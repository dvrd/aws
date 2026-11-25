package main

import "core:fmt"
import "core:os"
import "core:testing"

// Unit tests of cmd/tasks/loopback.odin.

@(test)
loopback_options_are_checked_before_anything_is_built :: proc(t: ^testing.T) {
	context.allocator = context.temp_allocator
	testing.expect_value(t, loopback_command({"--mode", "fastest"}), 1)
	testing.expect_value(t, loopback_command({"--report", "report.json"}), 1, )
	testing.expect_value(t, loopback_command({"--verbose"}), 1)
}

@(test)
the_loopback_programs_are_where_the_task_builds_them :: proc(t: ^testing.T) {
	context.allocator = context.temp_allocator
	for directory in ([]string{LOOPBACK_PEER, LOOPBACK_DEFAULT_PROBE, LOOPBACK_OBSERVER_PROBE}) {
		testing.expectf(t, os.is_file(fmt.aprintf("%s/main.odin", directory)), "%s/main.odin", directory)
	}
	testing.expect(t, os.is_file(LOOPBACK_OBSERVATION))
}

@(test)
ready_port_requires_a_complete_line :: proc(t: ^testing.T) {
	context.allocator = context.temp_allocator
	testing.expect_value(t, ready_port("ready 12"), 0)
	testing.expect_value(t, ready_port("ready 12345\n"), 12345)
	testing.expect_value(t, ready_port("noise\n"), 0)
}
