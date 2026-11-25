package main

import "core:c"
import "core:crypto/hash"
import "core:encoding/hex"
import "core:fmt"
import "core:os"
import "core:strings"
import "core:sys/posix"
import "core:time"

BUILD_TIMEOUT :: 120 * time.Second
// A program the tasks build and run: the native-errors driver, the consumer.
RUN_TIMEOUT :: 120 * time.Second

compiler :: proc() -> string {
	if value, found := os.lookup_env("ODIN", context.allocator); found && value != "" {
		return value
	}
	return "odin"
}

// The compiler as an absolute path, for digests and for children started elsewhere.
compiler_path :: proc() -> string {
	name := compiler()
	if strings.contains_rune(name, '/') {
		absolute, _ := os.get_absolute_path(name, context.allocator)
		return absolute
	}
	search, _ := os.lookup_env("PATH", context.allocator)
	for directory in strings.split(search, ":") {
		candidate := fmt.aprintf("%s/%s", directory, name)
		if directory != "" && os.is_file(candidate) {
			return candidate
		}
	}
	return name
}

// The collection the dependencies are installed in.
shared_source :: proc() -> string {
	if value, found := os.lookup_env("WEBTOOLS_SHARED", context.allocator); found && value != "" {
		return value
	}
	home, _ := os.lookup_env("HOME", context.allocator)
	return fmt.aprintf("%s/dev/oss/Odin/shared", home)
}

fail :: proc(format: string, arguments: ..any) -> int {
	fmt.eprintf("tasks: ")
	fmt.eprintf(format, ..arguments)
	fmt.eprintln()
	return 1
}

// A private scratch directory with a resolved path. Remove it with os.remove_all.
work_directory :: proc(name: string) -> (path: string, ok: bool) {
	created, error := os.make_directory_temp("", fmt.aprintf("aws-%s-*", name), context.allocator)
	if error != nil {
		return "", false
	}
	resolved := posix.realpath(strings.clone_to_cstring(created))
	if resolved == nil {
		return "", false
	}
	return strings.clone(string(resolved)), true
}

root_directory :: proc() -> string {
	directory, _ := os.get_working_directory(context.allocator)
	return directory
}

// A collection with aws from this checkout and the pinned dependencies.
stage_collection :: proc(work: string) -> (shared: string, ok: bool) {
	shared = fmt.aprintf("%s/shared", work)
	if os.make_directory(shared) != nil || os.symlink(fmt.aprintf("%s/src", root_directory()), fmt.aprintf("%s/aws", shared)) != nil {
		return "", false
	}
	source, _ := os.get_absolute_path(shared_source(), context.allocator)
	pins, parsed := pins_read(root_directory())
	if !parsed {
		fail("cannot read .krs/packages.json")
		return "", false
	}
	for pin in pins {
		path := fmt.aprintf("%s/%s", source, pin.name)
		if !os.is_directory(path) {
			fail("shared:%s is pinned but not in %s", pin.name, source)
			return "", false
		}
		if os.symlink(path, fmt.aprintf("%s/%s", shared, pin.name)) != nil {
			return "", false
		}
	}
	return shared, true
}

// Sanitized builds link the address sanitizer runtime of the clang that does the
// linking, which must match the LLVM Odin was built with. Unless ODIN_CLANG_PATH
// is already set, prefer a clang of that major version installed beside the
// system one.
sanitizer_clang_select :: proc() {
	if value, found := os.lookup_env("ODIN_CLANG_PATH", context.allocator); found && value != "" {
		return
	}
	report, code := output({compiler(), "report"})
	marker :: "Backend: LLVM "
	at := strings.index(report, marker)
	if code != 0 || at < 0 {
		return
	}
	major := report[at + len(marker):]
	if dot := strings.index_any(major, ".\n "); dot >= 0 {
		major = major[:dot]
	}
	for pattern in ([]string{"/opt/homebrew/opt/llvm@%s/bin/clang", "/usr/local/opt/llvm@%s/bin/clang", "/usr/lib/llvm-%s/bin/clang"}) {
		candidate := fmt.aprintf(pattern, major)
		if major != "" && os.is_file(candidate) {
			os.set_env("ODIN_CLANG_PATH", candidate)
			return
		}
	}
}

// One child process in its own session, so a deadline can end everything it
// started. Descriptors left at zero are inherited.
Spawn :: struct {
	command:     []string,
	directory:   string,
	// When exact is set the child receives only environment ("NAME=value").
	environment: []string,
	exact:       bool,
	output:      string, // file that receives stdout
	errors:      string, // file that receives stderr; "&output" shares stdout
}

Child :: struct {
	pid:    posix.pid_t,
	reaped: bool,
	status: c.int, // valid when reaped
}

spawn :: proc(options: Spawn) -> (child: Child, ok: bool) {
	arguments := make([]cstring, len(options.command) + 1)
	for argument, index in options.command {
		arguments[index] = strings.clone_to_cstring(argument)
	}
	variables := make([]cstring, len(options.environment) + 1)
	for variable, index in options.environment {
		variables[index] = strings.clone_to_cstring(variable)
	}
	directory := strings.clone_to_cstring(options.directory)
	null := posix.open("/dev/null", {.RDWR})
	stdout, stderr := posix.FD(-1), posix.FD(-1)
	if options.output != "" {
		stdout = posix.open(strings.clone_to_cstring(options.output), {.WRONLY, .CREAT, .TRUNC}, {.IRUSR, .IWUSR})
	}
	if options.errors != "" && options.errors != "&output" {
		stderr = posix.open(strings.clone_to_cstring(options.errors), {.WRONLY, .CREAT, .TRUNC}, {.IRUSR, .IWUSR})
	}
	pid := posix.fork()
	if pid == 0 {
		// Only system calls from here.
		posix.setsid()
		if options.directory != "" && posix.chdir(directory) != .OK {
			posix._exit(126)
		}
		posix.dup2(null, 0)
		if stdout >= 0 {
			posix.dup2(stdout, 1)
		}
		if options.errors == "&output" {
			posix.dup2(1, 2)
		} else if stderr >= 0 {
			posix.dup2(stderr, 2)
		}
		for descriptor in 3 ..< 1024 {
			posix.close(posix.FD(descriptor))
		}
		if options.exact {
			posix.execve(arguments[0], raw_data(arguments), raw_data(variables))
		} else {
			posix.execvp(arguments[0], raw_data(arguments))
		}
		posix._exit(127)
	}
	posix.close(null)
	if stdout >= 0 {
		posix.close(stdout)
	}
	if stderr >= 0 {
		posix.close(stderr)
	}
	if pid < 0 {
		return {}, false
	}
	return {pid = pid}, true
}

// The exit code of child, or finished == false after it outlived timeout and was
// killed with its whole session. A zero timeout waits without limit.
wait :: proc(child: ^Child, timeout: time.Duration = 0) -> (code: int, finished: bool) {
	started := time.tick_now()
	for !child.reaped {
		result := posix.waitpid(child.pid, &child.status, {.NOHANG} if timeout > 0 else {})
		if result == child.pid {
			child.reaped = true
			break
		}
		if result < 0 && posix.errno() != .EINTR {
			return -1, true
		}
		if timeout > 0 && time.tick_since(started) >= timeout {
			stop(child)
			return -1, false
		}
		time.sleep(5 * time.Millisecond)
	}
	if posix.WIFEXITED(child.status) {
		return int(posix.WEXITSTATUS(child.status)), true
	}
	return 128 + int(posix.WTERMSIG(child.status)), true
}

alive :: proc(child: ^Child) -> bool {
	for !child.reaped {
		result := posix.waitpid(child.pid, &child.status, {.NOHANG})
		if result < 0 && posix.errno() == .EINTR {
			continue
		}
		child.reaped = result == child.pid
		return result == 0
	}
	return false
}

// Ends the child and the session it started, and reaps it. The child is signalled
// first because it may not have called setsid yet.
stop :: proc(child: ^Child) {
	if child.reaped {
		return
	}
	posix.kill(child.pid, .SIGTERM)
	posix.killpg(child.pid, .SIGTERM)
	time.sleep(50 * time.Millisecond)
	posix.kill(child.pid, .SIGKILL)
	posix.killpg(child.pid, .SIGKILL)
	for {
		result := posix.waitpid(child.pid, &child.status, {})
		if result < 0 && posix.errno() == .EINTR {
			continue
		}
		child.reaped = result == child.pid
		break
	}
}

// Runs a command with this process's output and returns its exit code; 124 means
// it outlived timeout.
run :: proc(command: []string, directory := "", timeout: time.Duration = 0) -> int {
	child, started := spawn({command = command, directory = directory})
	if !started {
		return fail("cannot start %s", command[0])
	}
	code, finished := wait(&child, timeout)
	if !finished {
		fmt.eprintf("tasks: %s did not finish in %v\n", command[0], timeout)
		return 124
	}
	return code
}

// The standard output of a short command.
output :: proc(command: []string, directory := "") -> (text: string, code: int) {
	state, stdout, _, error := os.process_exec({command = command, working_dir = directory}, context.allocator)
	if error != nil {
		return "", 127
	}
	return string(stdout), state.exit_code
}

sha256_file :: proc(path: string) -> string {
	data, error := os.read_entire_file(path, context.allocator)
	if error != nil {
		return ""
	}
	digest: [32]u8
	hash.hash(.SHA256, data, digest[:])
	return string(hex.encode(digest[:]))
}

read_text :: proc(path: string) -> string {
	data, _ := os.read_entire_file(path, context.allocator)
	return string(data)
}

// Creates a directory and its parents; an existing directory is fine.
directory_ensure :: proc(path: string) -> bool {
	os.make_directory_all(path)
	return os.is_directory(path)
}

// Copies the non-hidden files of a directory tree.
copy_tree :: proc(source, target: string) -> bool {
	directory_ensure(target) or_return
	entries, error := os.read_all_directory_by_path(source, context.allocator)
	if error != nil {
		return false
	}
	for entry in entries {
		if strings.has_prefix(entry.name, ".") {
			continue
		}
		destination := fmt.aprintf("%s/%s", target, entry.name)
		if os.is_directory(entry.fullpath) {
			copy_tree(entry.fullpath, destination) or_return
		} else if os.copy_file(destination, entry.fullpath) != nil {
			return false
		}
	}
	return true
}

// Splits "--name value" options from the rest. Unknown options are an error.
option_value :: proc(arguments: []string, index: ^int) -> (value: string, ok: bool) {
	if index^ + 1 >= len(arguments) {
		return "", false
	}
	index^ += 1
	return arguments[index^], true
}
