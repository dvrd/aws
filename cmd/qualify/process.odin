package main

import "core:c"
import "core:mem"
import "core:strings"
import "core:sys/posix"
import "core:time"

// Zeroes the NAME=value strings built for a child; the parent no longer needs them.
variables_wipe :: proc(variables: []cstring) {
	for variable in variables {
		if variable != nil {
			mem.zero_explicit(rawptr(variable), len(string(variable)))
		}
	}
}

// Runs one child in its own session with only the given environment, no input and
// no error stream, and returns its exit code and at most limit bytes of output.
// deadline is on the runner's monotonic clock. A child that outlives the deadline
// or exceeds limit is killed with its process group and reaped before returning.
// Once the child has been reaped its process id is never signalled.
capture_child :: proc(
	runner: ^Runner,
	argv: []string,
	environment: map[string]string,
	deadline: time.Duration,
	limit: int,
) -> (
	code: int,
	output: []u8,
	failure: Failure,
) {
	if len(argv) == 0 {
		return 0, nil, .System
	}
	arguments := make([]cstring, len(argv) + 1)
	for argument, index in argv {
		arguments[index] = strings.clone_to_cstring(argument)
	}
	variables := make([dynamic]cstring, 0, len(environment) + 1)
	for name, value in environment {
		append(&variables, strings.clone_to_cstring(strings.concatenate({name, "=", value})))
	}
	append(&variables, nil)

	if deadline - runner.monotonic(runner) <= 0 {
		variables_wipe(variables[:])
		return 0, nil, .Child_Deadline
	}
	null := posix.open("/dev/null", {.RDWR})
	if null < 0 {
		variables_wipe(variables[:])
		return 0, nil, .System
	}
	channel: [2]posix.FD
	if posix.pipe(&channel) != .OK {
		variables_wipe(variables[:])
		posix.close(null)
		return 0, nil, .System
	}
	child := posix.fork()
	if child < 0 {
		variables_wipe(variables[:])
		posix.close(null)
		posix.close(channel[0])
		posix.close(channel[1])
		return 0, nil, .System
	}
	if child == 0 {
		// Only system calls from here: the parent may hold locks in other threads.
		posix.setsid()
		posix.dup2(null, 0)
		posix.dup2(channel[1], 1)
		posix.dup2(null, 2)
		for descriptor in 3 ..< 1024 {
			posix.close(posix.FD(descriptor))
		}
		posix.execve(arguments[0], raw_data(arguments), raw_data(variables))
		posix._exit(127)
	}
	// The child has its own copy of the environment.
	variables_wipe(variables[:])
	posix.close(null)
	posix.close(channel[1])
	reaped := false
	status: c.int
	defer {
		if !reaped {
			// The child may not have called setsid yet, so its group may not exist:
			// kill the child itself, then the group it may have started after exec.
			posix.kill(child, .SIGKILL)
			posix.killpg(child, .SIGKILL)
			child_wait(child, &status, 5 * time.Second)
		}
		posix.close(channel[0])
	}

	collected := make([dynamic]u8)
	buffer: [4096]u8
	for {
		remaining := deadline - runner.monotonic(runner)
		if remaining <= 0 {
			return 0, nil, .Child_Deadline
		}
		ready := posix.pollfd {
			fd     = channel[0],
			events = {.IN},
		}
		wait := min(remaining, time.Second)
		if posix.poll(&ready, 1, c.int(max(wait / time.Millisecond, 1))) <= 0 {
			continue
		}
		count := posix.read(channel[0], raw_data(buffer[:]), len(buffer))
		if count < 0 {
			if posix.errno() == .EINTR {
				continue
			}
			return 0, nil, .System
		}
		if count == 0 {
			break
		}
		append(&collected, ..buffer[:count])
		if len(collected) > limit {
			return 0, nil, .Child_Output_Limit
		}
	}
	patience := max(deadline - runner.monotonic(runner), 10 * time.Millisecond)
	switch child_wait(child, &status, patience) {
	case .Running:
		return 0, nil, .Child_Deadline
	case .Lost:
		// The kernel or someone else reaped it: never signal that pid again.
		reaped = true
		return 0, nil, .System
	case .Reaped:
	}
	reaped = true
	if posix.WIFEXITED(status) {
		code = int(posix.WEXITSTATUS(status))
	} else {
		code = -1
	}
	return code, collected[:], .None
}

Child_Wait :: enum {
	Reaped, // status holds the child's exit status
	Running, // patience ran out; the child was not reaped
	Lost, // waitpid failed: the status is unknown (for example SIGCHLD is ignored)
}

// Reaps child within patience of real time.
child_wait :: proc(child: posix.pid_t, status: ^c.int, patience: time.Duration) -> Child_Wait {
	started := time.tick_now()
	for {
		result := posix.waitpid(child, status, {.NOHANG})
		if result == child {
			return .Reaped
		}
		if result < 0 && posix.errno() != .EINTR {
			return .Lost
		}
		if time.tick_since(started) >= patience {
			return .Running
		}
		time.sleep(2 * time.Millisecond)
	}
}
