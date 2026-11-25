package main

import "core:strings"
import "core:sys/posix"
import "core:testing"
import "core:time"

// Unit tests of cmd/qualify/process.odin. Real owned children only: short shell
// fixtures, no CLI, probe or network.
child_fixture :: proc(test: ^Test, script: string) -> string {
	fixture(test)
	path := strings.concatenate({test.root, "/child"})
	write_file(path, script, posix.S_IRWXU)
	return path
}

@(test)
child_output_exit_code_and_exact_environment_are_captured :: proc(t: ^testing.T) {
	test: Test
	context.allocator = test_begin(&test, t)
	defer test_end(&test)
	path := child_fixture(&test, "#!/bin/sh\nprintf '%s:%s' \"${HOME-unset}\" \"$ONLY\"\necho hidden >&2\nexit 2\n")
	variables := make(map[string]string)
	variables["ONLY"] = "owned"
	deadline := test.runner.monotonic(&test.runner) + 10 * time.Second
	code, output, failure := capture_child(&test.runner, {path}, variables, deadline, 32)
	testing.expect_value(t, failure, Failure.None)
	testing.expect_value(t, code, 2)
	testing.expect_value(t, string(output), "unset:owned")
}

@(test)
child_past_its_deadline_is_killed_and_reaped :: proc(t: ^testing.T) {
	test: Test
	context.allocator = test_begin(&test, t)
	defer test_end(&test)
	// The sleeper inherits the pipe, so only killing the whole group ends the read.
	path := child_fixture(&test, "#!/bin/sh\nsleep 30 &\nsleep 30\n")
	started := time.tick_now()
	deadline := test.runner.monotonic(&test.runner) + 200 * time.Millisecond
	_, output, failure := capture_child(&test.runner, {path}, nil, deadline, 32)
	testing.expect_value(t, failure, Failure.Child_Deadline)
	testing.expect_value(t, len(output), 0)
	testing.expect(t, time.tick_since(started) < 5 * time.Second, "the child is not waited for")
}

@(test)
child_output_over_the_limit_is_discarded :: proc(t: ^testing.T) {
	test: Test
	context.allocator = test_begin(&test, t)
	defer test_end(&test)
	path := child_fixture(&test, "#!/bin/sh\nprintf '%s' 0123456789012345678901234567890123\nsleep 30\n")
	started := time.tick_now()
	deadline := test.runner.monotonic(&test.runner) + 10 * time.Second
	_, output, failure := capture_child(&test.runner, {path}, nil, deadline, 32)
	testing.expect_value(t, failure, Failure.Child_Output_Limit)
	testing.expect_value(t, len(output), 0)
	testing.expect(t, time.tick_since(started) < 5 * time.Second, "the child is not waited for")
}

@(test)
missing_child_is_a_failed_exit_not_a_result :: proc(t: ^testing.T) {
	test: Test
	context.allocator = test_begin(&test, t)
	defer test_end(&test)
	fixture(&test)
	deadline := test.runner.monotonic(&test.runner) + 10 * time.Second
	code, output, failure := capture_child(&test.runner, {strings.concatenate({test.root, "/absent"})}, nil, deadline, 32)
	testing.expect_value(t, failure, Failure.None)
	testing.expect_value(t, code, 127)
	testing.expect_value(t, len(output), 0)
}
