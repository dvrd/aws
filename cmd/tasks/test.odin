package main

import "core:fmt"
import "core:os"
import "core:path/filepath"
import "core:slice"
import "core:strings"
import "core:time"

SUITE_TIMEOUT :: 300 * time.Second

Suite :: struct {
	relative: string, // tests/internal, tests/live_qualification, ...
	owner:    string, // "." for the library, otherwise the path under tests/
	private:  bool, // staged into the package it tests
}

// Runs the suites against a staged copy of the checkout, so nothing is written
// into it. A suite is any directory under tests/ that holds a *_test.odin file.
// tests/internal is compiled inside src/, and tests/<package>/internal inside
// src/<package>/, so those tests see the package's private names.
test_command :: proc(arguments: []string) -> int {
	selected := "all"
	internal_only := false
	dependencies := shared_source()
	flags := make([dynamic]string)
	index := 0
	options: for index < len(arguments) {
		switch arguments[index] {
		case "--shared":
			dependencies = option_value(arguments, &index) or_else ""
		case "--package":
			selected = option_value(arguments, &index) or_else ""
		case "--internal-only":
			internal_only = true
		case "--":
			index += 1
			break options
		case:
			break options
		}
		index += 1
	}
	has_output := false
	for flag in arguments[min(index, len(arguments)):] {
		if strings.has_prefix(flag, "-collection:shared=") {
			dependencies = flag[len("-collection:shared="):]
			continue
		}
		has_output ||= strings.has_prefix(flag, "-out:")
		append(&flags, flag)
	}
	if selected == "" || dependencies == "" || !os.is_directory(dependencies) {
		return fail("no shared collection at %q", dependencies)
	}
	root := root_directory()
	if !os.is_directory(fmt.aprintf("%s/src", root)) {
		return fail("no src/ in %s", root)
	}

	suites := suites_find(root, selected, internal_only)
	if len(suites) == 0 {
		return fail("no matching test suites")
	}
	work, created := work_directory("tests")
	if !created {
		return fail("cannot create a work directory")
	}
	defer os.remove_all(work)

	// The repository keeps its geometry (src/ beside tests/), so paths relative to
	// tests/<package>/ resolve as they do in the checkout.
	repository := fmt.aprintf("%s/repository", work)
	if !repository_stage(root, repository) {
		return fail("cannot stage the checkout")
	}
	if escapes := imports_escaping(repository); len(escapes) > 0 {
		fmt.eprintln("Relative imports leave the repository; use shared:<library> instead:")
		for escape in escapes {
			fmt.eprintln(escape)
		}
		return 2
	}
	os.set_env("WEBTOOLS_SHARED", dependencies)
	shared, staged := stage_collection(work)
	if !staged {
		return fail("cannot stage the shared collection")
	}
	// The library resolves to the staged copy, which also holds its private tests.
	os.remove(fmt.aprintf("%s/aws", shared))
	if os.symlink(fmt.aprintf("%s/src", repository), fmt.aprintf("%s/aws", shared)) != nil {
		return fail("cannot stage the library")
	}
	if !private_tests_stage(repository) {
		return 2
	}
	fmt.printf("Library aws from %s/src; dependencies from %s\n", root, dependencies)

	append(&flags, fmt.aprintf("-collection:shared=%s", shared))
	if !has_output {
		append(&flags, fmt.aprintf("-out:%s/tests", work))
	}
	for suite in suites {
		target := fmt.aprintf("%s/%s", repository, suite.relative)
		if suite.private {
			target = private_target(repository, suite.relative)
		}
		fmt.printf("Testing %s\n", suite.relative)
		command := make([dynamic]string)
		append(&command, compiler_path(), "test", target)
		append(&command, ..flags[:])
		if code := run(command[:], repository, SUITE_TIMEOUT); code != 0 {
			return code
		}
	}
	return 0
}

suites_find :: proc(root, selected: string, internal_only: bool) -> []Suite {
	directories := make(map[string]bool)
	walker := os.walker_create(fmt.aprintf("%s/tests", root))
	defer os.walker_destroy(&walker)
	for info in os.walker_walk(&walker) {
		if info.type == .Directory && strings.has_prefix(info.name, ".") {
			os.walker_skip_dir(&walker)
			continue
		}
		if info.type == .Regular && strings.has_suffix(info.name, "_test.odin") {
			directories[strings.clone(filepath.dir(info.fullpath))] = true
		}
	}
	suites := make([dynamic]Suite)
	for directory in directories {
		relative := strings.trim_prefix(directory, fmt.aprintf("%s/", root))
		suite := Suite {
			relative = relative,
		}
		switch {
		case relative == "tests/internal":
			suite.owner, suite.private = ".", true
		case strings.has_suffix(relative, "/internal"):
			suite.owner, suite.private = strings.trim_suffix(strings.trim_prefix(relative, "tests/"), "/internal"), true
		case relative == "tests":
			suite.owner = "."
		case:
			suite.owner = strings.trim_prefix(relative, "tests/")
		}
		if selected != "all" && selected != suite.owner || internal_only && !suite.private {
			continue
		}
		append(&suites, suite)
	}
	slice.sort_by(suites[:], proc(a, b: Suite) -> bool {return a.relative < b.relative})
	return suites[:]
}

// Tracked and untracked unignored files of a Git checkout, or every non-hidden
// file when this is not one.
repository_stage :: proc(root, repository: string) -> bool {
	listing, code := output({"git", "-C", root, "ls-files", "--cached", "--others", "--exclude-standard", "-z"})
	if code != 0 {
		return copy_tree(root, repository)
	}
	for relative in strings.split(listing, "\x00") {
		source := fmt.aprintf("%s/%s", root, relative)
		if relative == "" || !os.is_file(source) {
			continue
		}
		destination := fmt.aprintf("%s/%s", repository, relative)
		if !directory_ensure(filepath.dir(destination)) {
			return false
		}
		if error := os.copy_file(destination, source); error != nil {
			fmt.eprintf("tasks: %s: %v\n", relative, error)
			return false
		}
	}
	return true
}

// Where a private suite is compiled: tests/internal in src/, and
// tests/<package>/internal in src/<package>/.
private_target :: proc(repository, relative: string) -> string {
	location := strings.trim_prefix(strings.trim_suffix(strings.trim_prefix(relative, "tests"), "internal"), "/")
	location = strings.trim_suffix(location, "/")
	if location == "" {
		return fmt.aprintf("%s/src", repository)
	}
	return fmt.aprintf("%s/src/%s", repository, location)
}

private_tests_stage :: proc(repository: string) -> bool {
	walker := os.walker_create(fmt.aprintf("%s/tests", repository))
	defer os.walker_destroy(&walker)
	for info in os.walker_walk(&walker) {
		if info.type != .Directory || info.name != "internal" {
			continue
		}
		relative := strings.trim_prefix(info.fullpath, fmt.aprintf("%s/", repository))
		target := private_target(repository, relative)
		if !os.is_directory(target) {
			fmt.eprintf("Private tests %s have no package %s\n", relative, strings.trim_prefix(target, fmt.aprintf("%s/", repository)))
			return false
		}
		files, _ := os.read_all_directory_by_path(info.fullpath, context.allocator)
		for file in files {
			if strings.has_suffix(file.name, ".odin") && os.copy_file(fmt.aprintf("%s/%s", target, file.name), file.fullpath) != nil {
				return false
			}
		}
	}
	return true
}

// "file: import" for each relative import that leaves its tree: src/ for the
// library, the repository for the tests. Other libraries are reached through
// shared:<name>.
imports_escaping :: proc(repository: string) -> []string {
	escapes := make([dynamic]string)
	for tree in ([]struct {
			scan, limit: string,
		}{{"src", "src"}, {"tests", ""}}) {
		limit := repository if tree.limit == "" else fmt.aprintf("%s/%s", repository, tree.limit)
		walker := os.walker_create(fmt.aprintf("%s/%s", repository, tree.scan))
		defer os.walker_destroy(&walker)
		for info in os.walker_walk(&walker) {
			if info.type != .Regular || !strings.has_suffix(info.name, ".odin") {
				continue
			}
			for line in strings.split_lines(read_text(info.fullpath)) {
				path, found := import_relative(line)
				if !found {
					continue
				}
				resolved, _ := filepath.clean(fmt.aprintf("%s/%s", filepath.dir(info.fullpath), path))
				if resolved != limit && !strings.has_prefix(resolved, fmt.aprintf("%s/", limit)) {
					append(&escapes, fmt.aprintf("%s: %s", strings.trim_prefix(info.fullpath, fmt.aprintf("%s/", repository)), path))
				}
			}
		}
	}
	return escapes[:]
}

// The path of `import [name] "./x"` or `"../x"`.
import_relative :: proc(line: string) -> (path: string, found: bool) {
	text := strings.trim_space(line)
	if !strings.has_prefix(text, "import ") {
		return "", false
	}
	open := strings.index_byte(text, '"')
	close := strings.last_index_byte(text, '"')
	if open < 0 || close <= open {
		return "", false
	}
	path = text[open + 1:close]
	return path, strings.has_prefix(path, "./") || strings.has_prefix(path, "../")
}
