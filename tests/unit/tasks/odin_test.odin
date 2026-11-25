// Unit tests of cmd/tasks/odin.odin.
package main

import "core:os"
import "core:strings"
import "core:testing"

@(test)
odin_binary_sha_reads_the_version_suffix :: proc(t: ^testing.T) {
	testing.expect_value(t, odin_binary_sha("odin version dev-2026-11:74d53468b"), "74d53468b")
	testing.expect_value(t, odin_binary_sha("odin version dev"), "")
}

@(test)
odin_pin_problems_reports_a_missing_pin :: proc(t: ^testing.T) {
	context.allocator = context.temp_allocator
	root, created := work_directory("odin-pin")
	if !testing.expect(t, created) {
		return
	}
	defer os.remove_all(root)
	problems, _ := odin_pin_problems(root)
	if !testing.expect(t, len(problems) == 1) {
		return
	}
	testing.expect(t, strings.contains(problems[0], "ODIN_COMMIT"))
}
