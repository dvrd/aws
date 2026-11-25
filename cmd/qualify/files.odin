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

// Reads one private metadata document without following a link, and returns the
// bytes it parsed so callers can hash exactly what they read.
read_private_bytes :: proc(path: string) -> (object: json.Object, data: []u8, failure: Failure) {
	descriptor := posix.open(strings.clone_to_cstring(path), {.NOFOLLOW, .NONBLOCK})
	if descriptor < 0 {
		return nil, nil, .System
	}
	defer posix.close(descriptor)
	info := private_file(descriptor) or_return
	if info.st_size > MAX_BYTES {
		return nil, nil, .Metadata_Too_Large
	}
	data = read_all(descriptor, MAX_BYTES) or_return
	if len(data) > MAX_BYTES {
		return nil, nil, .Metadata_Too_Large
	}
	object = decode_object(data) or_return
	return object, data, .None
}

// Reads one private metadata document without following a link.
read_private :: proc(path: string) -> (object: json.Object, failure: Failure) {
	object, _ = read_private_bytes(path) or_return
	return object, .None
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

PROBE_NAME :: "probe"

// Opens the native probe without following a link and checks the open file: an
// absolute, regular, executable file owned by this user that group and others
// cannot write. binary_hash and probe_install share it so the checks cannot drift.
probe_open :: proc(path: string) -> (descriptor: posix.FD, failure: Failure) {
	if !os.is_absolute_path(path) {
		return -1, .Absolute_Binary_Required
	}
	descriptor = posix.open(strings.clone_to_cstring(path), {.NOFOLLOW, .NONBLOCK, .CLOEXEC})
	if descriptor < 0 {
		return -1, .System
	}
	info: posix.stat_t
	if posix.fstat(descriptor, &info) != .OK {
		posix.close(descriptor)
		return -1, .System
	}
	if !posix.S_ISREG(info.st_mode) ||
	   info.st_size > BINARY_BYTES_MAX ||
	   info.st_uid != posix.geteuid() ||
	   permission_bits(info.st_mode) & 0o022 != 0 ||
	   .IXUSR not_in info.st_mode {
		posix.close(descriptor)
		return -1, .Executable_Required
	}
	return descriptor, .None
}

// Digest of everything read from source, also written to copy unless copy is -1.
probe_digest :: proc(source: posix.FD, copy: posix.FD = -1) -> (digest: string, failure: Failure) {
	hasher: hash.Context
	hash.init(&hasher, .SHA256)
	buffer := make([]u8, 64 * 1024)
	defer delete(buffer)
	total := 0
	for {
		count := posix.read(source, raw_data(buffer), c.size_t(len(buffer)))
		if count < 0 {
			return "", .System
		}
		if count == 0 {
			break
		}
		total += int(count)
		if total > BINARY_BYTES_MAX {
			return "", .Executable_Required
		}
		hash.update(&hasher, buffer[:count])
		if copy >= 0 && !write_all(copy, buffer[:count]) {
			return "", .System
		}
	}
	sum: [32]u8
	hash.final(&hasher, sum[:])
	return string(hex.encode(sum[:])), .None
}

// Digest of the native probe: an absolute, regular, executable file owned by this
// user that group and others cannot write.
binary_hash :: proc(path: string) -> (digest: string, failure: Failure) {
	descriptor := probe_open(path) or_return
	defer posix.close(descriptor)
	return probe_digest(descriptor)
}

// Copies the probe at source into directory/PROBE_NAME (mode 0700, never
// following or replacing a link) and returns the digest of the bytes written,
// which are the bytes read from the descriptor the probe checks were made on.
probe_install :: proc(source, directory: string) -> (digest: string, failure: Failure) {
	descriptor := probe_open(source) or_return
	defer posix.close(descriptor)
	destination := strings.clone_to_cstring(strings.concatenate({directory, "/", PROBE_NAME}))
	mode := posix.mode_t{.IRUSR, .IWUSR, .IXUSR}
	copy := posix.open(destination, {.WRONLY, .CREAT, .EXCL, .NOFOLLOW, .CLOEXEC}, mode)
	if copy < 0 {
		info: posix.stat_t
		if posix.lstat(destination, &info) != .OK || !posix.S_ISREG(info.st_mode) || posix.unlink(destination) != .OK {
			return "", .System
		}
		copy = posix.open(destination, {.WRONLY, .CREAT, .EXCL, .NOFOLLOW, .CLOEXEC}, mode)
		if copy < 0 {
			return "", .System
		}
	}
	copied, copy_failure := probe_digest(descriptor, copy)
	if copy_failure == .None && posix.fsync(copy) != .OK {
		copy_failure = .System
	}
	posix.close(copy)
	if copy_failure != .None {
		posix.unlink(destination)
		return "", copy_failure
	}
	return copied, .None
}

path_present :: proc(path: string) -> bool {
	info: posix.stat_t
	return posix.lstat(strings.clone_to_cstring(path), &info) == .OK
}
