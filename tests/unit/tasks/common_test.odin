package main

import "core:fmt"
import "core:os"
import "core:strings"
import "core:testing"
import "core:time"

// Unit tests of cmd/tasks/common.odin: options, files and child processes.

@(test)
option_values_are_bounded :: proc(t: ^testing.T) {
	arguments := []string{"--only", "imds", "--report"}
	index := 0
	value, ok := option_value(arguments, &index)
	testing.expect(t, ok && value == "imds" && index == 1)
	index = 2
	_, ok = option_value(arguments, &index)
	testing.expect(t, !ok && index == 2)
}

@(test)
trees_are_copied_without_hidden_files :: proc(t: ^testing.T) {
	context.allocator = context.temp_allocator
	work, created := work_directory("tasks-copy")
	testing.expect(t, created)
	defer os.remove_all(work)
	testing.expect(t, directory_ensure(fmt.aprintf("%s/source/nested/deeper", work)))
	testing.expect(t, directory_ensure(fmt.aprintf("%s/source/nested/deeper", work)), "an existing directory is fine")
	testing.expect(t, directory_ensure(fmt.aprintf("%s/source/.git", work)))
	for path in ([]string{"source/a.odin", "source/nested/deeper/b.txt", "source/.hidden", "source/.git/config"}) {
		testing.expect(t, os.write_entire_file(fmt.aprintf("%s/%s", work, path), path) == nil)
	}
	testing.expect(t, copy_tree(fmt.aprintf("%s/source", work), fmt.aprintf("%s/target", work)))
	testing.expect_value(t, read_text(fmt.aprintf("%s/target/nested/deeper/b.txt", work)), "source/nested/deeper/b.txt")
	testing.expect(t, os.is_file(fmt.aprintf("%s/target/a.odin", work)))
	testing.expect(t, !os.exists(fmt.aprintf("%s/target/.hidden", work)))
	testing.expect(t, !os.exists(fmt.aprintf("%s/target/.git", work)))
	// SHA-256 of "source/a.odin".
	testing.expect_value(t, sha256_file(fmt.aprintf("%s/target/a.odin", work)), SHA256_OF_SOURCE_A)
	testing.expect_value(t, sha256_file(fmt.aprintf("%s/absent", work)), "")
}

@(test)
children_report_their_exit_and_are_stopped_at_the_deadline :: proc(t: ^testing.T) {
	context.allocator = context.temp_allocator
	testing.expect_value(t, run({"/bin/sh", "-c", "exit 3"}), 3)
	testing.expect_value(t, run({"/bin/sh", "-c", "exit 0"}), 0)
	started := time.tick_now()
	// The sleeper's own child would keep a pipe open; the whole session is stopped.
	testing.expect_value(t, run({"/bin/sh", "-c", "sleep 30 & sleep 30"}, timeout = 200 * time.Millisecond), 124)
	testing.expect(t, time.tick_since(started) < 10 * time.Second)
	printed, code := output({"/bin/sh", "-c", "printf 'out'; printf 'err' >&2"})
	testing.expect(t, code == 0 && printed == "out")
	_, missing := output({"/nonexistent/program"})
	testing.expect(t, missing != 0)
}

@(test)
an_exact_environment_is_all_a_child_sees :: proc(t: ^testing.T) {
	context.allocator = context.temp_allocator
	work, created := work_directory("tasks-env")
	testing.expect(t, created)
	defer os.remove_all(work)
	file := fmt.aprintf("%s/env", work)
	child, started := spawn({command = {"/usr/bin/env"}, environment = {"ONLY=1"}, exact = true, output = file})
	testing.expect(t, started)
	code, finished := wait(child, 10 * time.Second)
	testing.expect(t, finished && code == 0)
	testing.expect_value(t, strings.trim_space(read_text(file)), "ONLY=1")
}

SHA256_OF_SOURCE_A :: "c5c36b8189a55ac1308879d5a730951fd75282a1e7175bdda77e1a2e8649f14a"
