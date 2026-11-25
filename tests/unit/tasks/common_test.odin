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
clang_majors_are_read_from_version_text :: proc(t: ^testing.T) {
	testing.expect_value(t, clang_major("Apple clang version 21.0.0 (clang-2100.4.1.1)\nTarget: ..."), "21")
	testing.expect_value(t, clang_major("Homebrew clang version 22.1.8\n"), "22")
	testing.expect_value(t, clang_major("gcc (GCC) 14"), "")
}

@(test)
the_sanitizer_clang_is_explicit_then_versioned_then_system :: proc(t: ^testing.T) {
	context.allocator = context.temp_allocator
	exists :: proc(path: string) -> bool {
		return path == "first" || path == "second"
	}
	installed := []string{"missing", "first", "second"}
	missing := []string{"missing"}
	for example in ([]struct {
		explicit, backend, system: string,
		candidates: []string,
		path: string,
		ok: bool,
		message: string,
	}{
		{"custom", "22", "21", installed, "custom", true, ""},
		{"", "", "21", installed, "", true, ""},
		{"", "22", "22", installed, "first", true, ""},
		{"", "22", "22", missing, "", true, ""},
		{"", "22", "21", missing, "", false, "need clang 22: install llvm@22 or set ODIN_CLANG_PATH"},
	}) {
		path, ok, message := sanitizer_clang_choose(example.explicit, example.backend, example.system, example.candidates, exists)
		testing.expect_value(t, path, example.path)
		testing.expect_value(t, ok, example.ok)
		testing.expect_value(t, message, example.message)
	}
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
children_stopped_at_the_deadline_never_finish :: proc(t: ^testing.T) {
	context.allocator = context.temp_allocator
	work, created := work_directory("tasks-stop")
	testing.expect(t, created)
	defer os.remove_all(work)
	for i in 0 ..< 10 {
		testing.expect_value(t, run({"/bin/sh", "-c", fmt.aprintf("sleep 1; touch %s/finished-%d", work, i)}, timeout = time.Millisecond), 124)
	}
	time.sleep(1500 * time.Millisecond)
	for i in 0 ..< 10 {
		testing.expectf(t, !os.exists(fmt.aprintf("%s/finished-%d", work, i)), "child %d finished after it was stopped", i)
	}
}

@(test)
an_exact_environment_is_all_a_child_sees :: proc(t: ^testing.T) {
	context.allocator = context.temp_allocator
	work, created := work_directory("tasks-env")
	testing.expect(t, created)
	defer os.remove_all(work)
	file := fmt.aprintf("%s/env", work)
	child, started := spawn({command = {"/usr/bin/env"}, environment = {"ONLY=1"}, exact = true, output = file})
	if !testing.expect(t, started) {
		return
	}
	code, finished := wait(&child, 10 * time.Second)
	testing.expect(t, finished && code == 0)
	testing.expect_value(t, strings.trim_space(read_text(file)), "ONLY=1")
}

SHA256_OF_SOURCE_A :: "c5c36b8189a55ac1308879d5a730951fd75282a1e7175bdda77e1a2e8649f14a"

@(test)
alive_is_false_once_the_child_exits :: proc(t: ^testing.T) {
	context.allocator = context.temp_allocator
	child, started := spawn({command = {"/bin/sh", "-c", "exit 4"}})
	if !testing.expect(t, started) {
		return
	}
	defer stop(&child)
	start := time.tick_now()
	for alive(&child) && time.tick_since(start) < 2 * time.Second {
		time.sleep(5 * time.Millisecond)
	}
	testing.expect(t, child.reaped)
	testing.expect(t, !alive(&child))
	code, finished := wait(&child, time.Second)
	testing.expect(t, finished && code == 4)
}
