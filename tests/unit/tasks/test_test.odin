package main

import "core:fmt"
import "core:os"
import "core:strings"
import "core:testing"

// Unit tests of cmd/tasks/test.odin: the unit-file rule, where a suite is
// compiled, which suites --package selects, and relative imports.

@(test)
relative_imports_are_recognised :: proc(t: ^testing.T) {
	path, found := import_relative(`import surf "../surf"`)
	testing.expect(t, found && path == "../surf")
	path, found = import_relative(`	import "./local"`)
	testing.expect(t, found && path == "./local")
	_, found = import_relative(`import aws "shared:aws"`)
	testing.expect(t, !found)
	_, found = import_relative(`text := "../not an import"`)
	testing.expect(t, !found)
}

// A throwaway checkout: each entry is a path and its contents.
checkout_make :: proc(t: ^testing.T, files: []struct {
		path, text: string,
	}) -> string {
	root, created := work_directory("tasks-layout")
	testing.expect(t, created)
	for file in files {
		path := fmt.aprintf("%s/%s", root, file.path)
		testing.expect(t, directory_ensure(path[:strings.last_index_byte(path, '/')]))
		testing.expect(t, os.write_entire_file(path, file.text) == nil)
	}
	return root
}

@(test)
every_source_file_needs_a_unit_test_file_of_the_same_name :: proc(t: ^testing.T) {
	context.allocator = context.temp_allocator
	root := checkout_make(
		t,
		{
			{"src/s3.odin", "package aws\n"},
			{"src/ses.odin", "package aws\n"},
			{"src/stray_test.odin", "package aws\n"},
			{"cmd/tool/main.odin", "package main\n"},
			{"tests/unit/s3_test.odin", "package aws\n"},
			{"tests/unit/gone_test.odin", "package aws\n"},
			{"tests/unit/helpers.odin", "package aws\n"},
			{"tests/unit/tool/main_test.odin", "package main\n"},
		},
	)
	defer os.remove_all(root)
	homes := homes_find(root)
	testing.expect_value(t, len(homes), 2)
	testing.expect_value(t, homes[0].package_, "aws")
	testing.expect_value(t, homes[1].unit, "tests/unit/tool")
	problems := strings.join(layout_problems(root, homes), "\n")
	testing.expect(t, strings.contains(problems, "src/ses.odin has no unit test file tests/unit/ses_test.odin"), problems)
	testing.expect(t, strings.contains(problems, "src/stray_test.odin: tests belong under tests/"), problems)
	testing.expect(t, strings.contains(problems, "tests/unit/gone_test.odin tests no file"), problems)
	testing.expect(t, strings.contains(problems, "tests/unit/helpers.odin: only unit test files belong here"), problems)
	testing.expect(t, !strings.contains(problems, "s3"), problems)
	testing.expect(t, !strings.contains(problems, "tool"), problems)
	testing.expect_value(t, len(layout_problems(root, homes)), 4)
}

@(test)
suites_compile_into_the_package_they_declare :: proc(t: ^testing.T) {
	context.allocator = context.temp_allocator
	root := checkout_make(
		t,
		{
			{"src/s3.odin", "package aws\n"},
			{"cmd/tool/main.odin", "package main\n"},
			{"tests/unit/s3_test.odin", "package aws\n"},
			{"tests/unit/tool/main_test.odin", "package main\n"},
			{"tests/fuzz/generator.odin", "package aws\n"},
			{"tests/fuzz/inputs_test.odin", "package aws\n"},
			{"tests/integration/tool/run_test.odin", "package main\n"},
			{"tests/qualification/probe/main.odin", "package main\n"},
			{"tests/qualification/probe/probe_test.odin", "package main\n"},
			{"tests/e2e/peer/main.odin", "package main\n"},
		},
	)
	defer os.remove_all(root)
	homes := homes_find(root)
	suites := suites_find(root, "all", homes)
	found := make(map[string]string)
	for suite in suites {
		found[suite.owner] = homes[suite.home].source if suite.home >= 0 else "itself"
	}
	expected := [][2]string {
		{"unit", "src"},
		{"unit/tool", "cmd/tool"},
		{"fuzz", "src"},
		{"integration/tool", "cmd/tool"},
		{"qualification/probe", "itself"},
	}
	testing.expect_value(t, len(found), len(expected))
	for item in expected {
		testing.expectf(t, found[item[0]] == item[1], "%s: %s", item[0], found[item[0]])
	}
	// --package selects a directory and everything below it, and nothing that
	// only shares a prefix.
	testing.expect_value(t, len(suites_find(root, "unit", homes)), 2)
	testing.expect_value(t, len(suites_find(root, "unit/tool", homes)), 1)
	testing.expect_value(t, len(suites_find(root, "qualification", homes)), 1)
	testing.expect_value(t, len(suites_find(root, "uni", homes)), 0)
	testing.expect_value(t, package_of(fmt.aprintf("%s/tests/e2e/peer", root)), "main")
	testing.expect_value(t, package_of(fmt.aprintf("%s/tests/none", root)), "")
}

@(test)
a_compiled_suite_holds_its_package_support_and_tests :: proc(t: ^testing.T) {
	context.allocator = context.temp_allocator
	root := checkout_make(
		t,
		{
			{"src/s3.odin", "package aws\n"},
			{"tests/support/aws/fixtures.odin", "package aws\n"},
			{"tests/unit/s3_test.odin", "package aws\n"},
			{"tests/clash/s3.odin", "package aws\n"},
			{"tests/clash/clash_test.odin", "package aws\n"},
		},
	)
	defer os.remove_all(root)
	homes := homes_find(root)
	target, staged := suite_stage(root, fmt.aprintf("%s/out/unit", root), homes[0], {relative = "tests/unit"})
	testing.expect(t, staged)
	testing.expect_value(t, strings.join(odin_files(target), ","), "fixtures.odin,s3.odin,s3_test.odin")
	_, clashing := suite_stage(root, fmt.aprintf("%s/out/clash", root), homes[0], {relative = "tests/clash"})
	testing.expect(t, !clashing, "a test file may not replace a source file")
}

@(test)
suites_fail_on_bad_memory_unless_the_user_decides :: proc(t: ^testing.T) {
	context.allocator = context.temp_allocator
	flags := strings.join(suite_flags({}, "/shared", "/out/tests"), " ")
	testing.expect(t, strings.contains(flags, SUITE_MEMORY_FLAG), flags)
	testing.expect(t, strings.contains(flags, "-out:/out/tests"), flags)
	mine := strings.join(suite_flags({"-define:ODIN_TEST_FAIL_ON_BAD_MEMORY=false", "-out:x"}, "/shared", "/out/tests"), " ")
	testing.expect(t, !strings.contains(mine, SUITE_MEMORY_FLAG), mine)
	testing.expect(t, !strings.contains(mine, "-out:/out/tests"), mine)
}

@(test)
ignored_files_are_neither_suites_nor_sources :: proc(t: ^testing.T) {
	context.allocator = context.temp_allocator
	root := checkout_make(
		t,
		{
			{".gitignore", "tests/ignored/\nsrc/scratch.odin\n"},
			{"src/s3.odin", "package aws\n"},
			{"tests/unit/s3_test.odin", "package aws\n"},
			{"tests/ignored/x_test.odin", "package aws\n"},
			{"src/scratch.odin", "package aws\n"},
		},
	)
	defer os.remove_all(root)
	testing.expect_value(t, run({"git", "-C", root, "init", "-q"}), 0)
	repository := fmt.aprintf("%s/repository", root)
	testing.expect(t, repository_stage(root, repository))
	homes := homes_find(repository)
	suites := suites_find(repository, "all", homes)
	if testing.expect_value(t, len(suites), 1) {
		testing.expect_value(t, suites[0].owner, "unit")
	}
	testing.expect_value(t, len(layout_problems(repository, homes)), 0)
}

@(test)
a_checkout_outside_git_is_staged_with_its_hidden_files :: proc(t: ^testing.T) {
	context.allocator = context.temp_allocator
	root := checkout_make(
		t,
		{
			{".krs/packages.json", "{}\n"},
			{".gitignore", "build/\n"},
			{".git/config", "not a repository\n"},
			{"src/s3.odin", "package aws\n"},
		},
	)
	defer os.remove_all(root)
	staged, created := work_directory("tasks-stage")
	testing.expect(t, created)
	defer os.remove_all(staged)
	repository := fmt.aprintf("%s/repository", staged)
	testing.expect(t, repository_stage(root, repository))
	testing.expect_value(t, read_text(fmt.aprintf("%s/.krs/packages.json", repository)), "{}\n")
	testing.expect(t, os.is_file(fmt.aprintf("%s/.gitignore", repository)))
	testing.expect(t, os.is_file(fmt.aprintf("%s/src/s3.odin", repository)))
	testing.expect(t, !os.exists(fmt.aprintf("%s/.git", repository)))
}
