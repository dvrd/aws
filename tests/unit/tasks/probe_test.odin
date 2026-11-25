package main

import "core:os"
import "core:testing"

// Unit tests of cmd/tasks/probe.odin.

@(test)
the_qualification_probe_is_where_the_task_builds_it :: proc(t: ^testing.T) {
	testing.expect(t, os.is_file(QUALIFICATION_PROBE + "/main.odin"))
}
