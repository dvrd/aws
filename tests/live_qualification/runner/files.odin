package main

import "core:c"
import "core:crypto"
import "core:crypto/hash"
import "core:encoding/hex"
import "core:encoding/json"
import "core:os"
import "core:strings"
import "core:sys/posix"

foreign import libc "system:c"

foreign libc {
	@(link_name = "flock")
	file_lock :: proc(descriptor: posix.FD, operation: c.int) -> c.int ---
}

LOCK_EXCLUSIVE :: 2
LOCK_NONBLOCKING :: 4
LOCK_RELEASE :: 8
BINARY_BYTES_MAX :: 128 << 20
PRIVATE_FILE :: posix.mode_t{.IRUSR, .IWUSR}

permission_bits :: proc(mode: posix.mode_t) -> int {
	return int(transmute(posix._mode_t)mode) & 0o7777
}

// A regular file of this user, mode 0600, with one name.
private_file :: proc(descriptor: posix.FD) -> (info: posix.stat_t, failure: Failure) {
	if posix.fstat(descriptor, &info) != .OK {
		return info, .System
	}
	if !posix.S_ISREG(info.st_mode) ||
	   info.st_uid != posix.geteuid() ||
	   permission_bits(info.st_mode) != 0o600 ||
	   info.st_nlink != 1 {
		return info, .Private_File_Required
	}
	return info, .None
}

read_all :: proc(descriptor: posix.FD, limit: int) -> (data: []u8, failure: Failure) {
	buffer := make([]u8, limit + 1)
	used := 0
	for used < len(buffer) {
		space := len(buffer) - used
		count := posix.read(descriptor, raw_data(buffer[used:]), c.size_t(space))
		if count < 0 {
			return nil, .System
		}
		if count == 0 {
			break
		}
		used += int(count)
	}
	return buffer[:used], .None
}

// Reads one private metadata document without following a link.
read_private :: proc(path: string) -> (object: json.Object, failure: Failure) {
	descriptor := posix.open(strings.clone_to_cstring(path), {.NOFOLLOW, .NONBLOCK})
	if descriptor < 0 {
		return nil, .System
	}
	defer posix.close(descriptor)
	info := private_file(descriptor) or_return
	if info.st_size > MAX_BYTES {
		return nil, .Metadata_Too_Large
	}
	data := read_all(descriptor, MAX_BYTES) or_return
	if len(data) > MAX_BYTES {
		return nil, .Metadata_Too_Large
	}
	return decode_object(data)
}

write_all :: proc(descriptor: posix.FD, data: []u8) -> bool {
	written := 0
	for written < len(data) {
		rest := len(data) - written
		count := posix.write(descriptor, raw_data(data[written:]), c.size_t(rest))
		if count <= 0 {
			return false
		}
		written += int(count)
	}
	return true
}

// Replaces directory/name with value in one rename, synced before and after.
atomic :: proc(directory, name: string, value: json.Value) -> Failure {
	data := encode(value)
	if len(data) > MAX_BYTES {
		return .Metadata_Too_Large
	}
	random: [8]u8
	crypto.rand_bytes(random[:])
	temporary := strings.concatenate({directory, "/.qualification-", string(hex.encode(random[:]))})
	temporary_path := strings.clone_to_cstring(temporary)
	descriptor := posix.open(temporary_path, {.WRONLY, .CREAT, .EXCL, .NOFOLLOW}, PRIVATE_FILE)
	if descriptor < 0 {
		return .System
	}
	stored := write_all(descriptor, data) && posix.fsync(descriptor) == .OK
	posix.close(descriptor)
	target := strings.clone_to_cstring(strings.concatenate({directory, "/", name}))
	if !stored || posix.rename(temporary_path, target) != 0 {
		posix.unlink(temporary_path)
		return .System
	}
	owner := posix.open(strings.clone_to_cstring(directory), {.DIRECTORY})
	if owner < 0 {
		return .System
	}
	defer posix.close(owner)
	if posix.fsync(owner) != .OK {
		return .System
	}
	return .None
}

// Exclusive ownership of a state directory for one command. The directory must be
// absolute, private to this user and mode 0700; it is created when missing.
State_Lock :: struct {
	descriptor: posix.FD,
}

lock_acquire :: proc(path: string) -> (lock: State_Lock, failure: Failure) {
	if !os.is_absolute_path(path) {
		return {}, .Absolute_State_Required
	}
	directory := strings.clone_to_cstring(path)
	posix.mkdir(directory, posix.S_IRWXU)
	info: posix.stat_t
	if posix.lstat(directory, &info) != .OK {
		return {}, .System
	}
	if !posix.S_ISDIR(info.st_mode) || info.st_uid != posix.geteuid() || permission_bits(info.st_mode) != 0o700 {
		return {}, .Private_Directory_Required
	}
	owner := strings.clone_to_cstring(strings.concatenate({path, "/owner.lock"}))
	descriptor := posix.open(owner, {.RDWR, .CREAT, .NOFOLLOW, .CLOEXEC}, PRIVATE_FILE)
	if descriptor < 0 {
		return {}, .System
	}
	if _, private := private_file(descriptor); private != .None {
		posix.close(descriptor)
		return {}, private
	}
	if file_lock(descriptor, LOCK_EXCLUSIVE | LOCK_NONBLOCKING) != 0 {
		posix.close(descriptor)
		return {}, .Locked
	}
	return {descriptor}, .None
}

// Unlocks explicitly: a child forked while the lock was held shares the open file
// until it executes, and closing this descriptor alone would leave the lock held.
lock_release :: proc(lock: State_Lock) {
	file_lock(lock.descriptor, LOCK_RELEASE)
	posix.close(lock.descriptor)
}

sha256_hex :: proc(data: []u8) -> string {
	digest: [32]u8
	hash.hash(.SHA256, data, digest[:])
	return string(hex.encode(digest[:]))
}

file_sha256 :: proc(path: string) -> (digest: string, failure: Failure) {
	data, error := os.read_entire_file(path, context.allocator)
	if error != nil {
		return "", .System
	}
	return sha256_hex(data), .None
}

// Digest of the native probe: an absolute, regular, executable file that group and
// others cannot write.
binary_hash :: proc(path: string) -> (digest: string, failure: Failure) {
	if !os.is_absolute_path(path) {
		return "", .Absolute_Binary_Required
	}
	name := strings.clone_to_cstring(path)
	descriptor := posix.open(name, {.NOFOLLOW})
	if descriptor < 0 {
		return "", .System
	}
	defer posix.close(descriptor)
	info: posix.stat_t
	if posix.fstat(descriptor, &info) != .OK {
		return "", .System
	}
	if !posix.S_ISREG(info.st_mode) ||
	   info.st_size > BINARY_BYTES_MAX ||
	   permission_bits(info.st_mode) & 0o022 != 0 ||
	   posix.access(name, {.X_OK}) != .OK {
		return "", .Executable_Required
	}
	hasher: hash.Context
	hash.init(&hasher, .SHA256)
	buffer := make([]u8, 64 * 1024)
	for {
		count := posix.read(descriptor, raw_data(buffer), c.size_t(len(buffer)))
		if count < 0 {
			return "", .System
		}
		if count == 0 {
			break
		}
		hash.update(&hasher, buffer[:count])
	}
	sum: [32]u8
	hash.final(&hasher, sum[:])
	return string(hex.encode(sum[:])), .None
}

path_present :: proc(path: string) -> bool {
	info: posix.stat_t
	return posix.lstat(strings.clone_to_cstring(path), &info) == .OK
}
