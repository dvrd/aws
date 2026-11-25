package main

import "core:fmt"
import "core:os"
import "core:path/filepath"
import "core:slice"
import "core:strings"
import "core:time"

SUITE_TIMEOUT :: 300 * time.Second

// Memory tracking is on in every test; with this a leak or a bad free fails the
// test instead of only printing a warning.
SUITE_MEMORY_FLAG :: "-define:ODIN_TEST_FAIL_ON_BAD_MEMORY=true"

// The packages whose source files each need a unit test file of the same name:
// the library in src/, and every program in cmd/<name>/. Their unit tests are in
// tests/unit/ and tests/unit/<name>/, one <file>_test.odin for each <file>.odin.
Home :: struct {
	name:      string, // "aws" for the library, the program's name otherwise
	source:    string, // src or cmd/<name>
	unit:      string, // tests/unit or tests/unit/<name>
	package_:  string, // the package its files declare
}

Suite :: struct {
	relative: string, // directory under the root: tests/unit, tests/fuzz, ...
	owner:    string, // the same path without "tests/"
	home:     int, // index of the package the suite is compiled into, -1 for none
}

homes_find :: proc(root: string) -> []Home {
	homes := make([dynamic]Home)
	append(&homes, Home{name = "aws", source = "src", unit = "tests/unit", package_ = package_of(fmt.aprintf("%s/src", root))})
	programs, _ := os.read_all_directory_by_path(fmt.aprintf("%s/cmd", root), context.allocator)
	slice.sort_by(programs, proc(a, b: os.File_Info) -> bool {return a.name < b.name})
	for program in programs {
		if program.type != .Directory || strings.has_prefix(program.name, ".") {
			continue
		}
		append(
			&homes,
			Home {
				name = strings.clone(program.name),
				source = fmt.aprintf("cmd/%s", program.name),
				unit = fmt.aprintf("tests/unit/%s", program.name),
				package_ = package_of(program.fullpath),
			},
		)
	}
	return homes[:]
}

// The package clause of the first .odin file in a directory, "" without one.
package_of :: proc(directory: string) -> string {
	files, _ := os.read_all_directory_by_path(directory, context.allocator)
	slice.sort_by(files, proc(a, b: os.File_Info) -> bool {return a.name < b.name})
	for file in files {
		if !strings.has_suffix(file.name, ".odin") {
			continue
		}
		for line in strings.split_lines(read_text(file.fullpath)) {
			text := strings.trim_space(line)
			if strings.has_prefix(text, "package ") {
				return strings.trim_space(text[len("package "):])
			}
		}
	}
	return ""
}

odin_files :: proc(directory: string) -> []string {
	files, _ := os.read_all_directory_by_path(directory, context.allocator)
	names := make([dynamic]string)
	for file in files {
		if file.type == .Regular && strings.has_suffix(file.name, ".odin") {
			append(&names, strings.clone(file.name))
		}
	}
	slice.sort(names[:])
	return names[:]
}

// Every source file has a unit test file of the same name, and every unit test
// file has its source file. Returns the problems found.
layout_problems :: proc(root: string, homes: []Home) -> []string {
	problems := make([dynamic]string)
	for home in homes {
		sources := odin_files(fmt.aprintf("%s/%s", root, home.source))
		tests := odin_files(fmt.aprintf("%s/%s", root, home.unit))
		for source in sources {
			if strings.has_suffix(source, "_test.odin") {
				append(&problems, fmt.aprintf("%s/%s: tests belong under tests/", home.source, source))
				continue
			}
			expected := fmt.aprintf("%s_test.odin", strings.trim_suffix(source, ".odin"))
			if !slice.contains(tests, expected) {
				append(&problems, fmt.aprintf("%s/%s has no unit test file %s/%s", home.source, source, home.unit, expected))
			}
		}
		for test in tests {
			source := fmt.aprintf("%s.odin", strings.trim_suffix(test, "_test.odin"))
			if !strings.has_suffix(test, "_test.odin") {
				append(&problems, fmt.aprintf("%s/%s: only unit test files belong here; shared helpers go in tests/support/%s/", home.unit, test, home.name))
			} else if !slice.contains(sources, source) {
				append(&problems, fmt.aprintf("%s/%s tests no file: %s/%s does not exist", home.unit, test, home.source, source))
			}
		}
	}
	return problems[:]
}

layout_command :: proc(arguments: []string) -> int {
	problems := layout_problems(root_directory(), homes_find(root_directory()))
	for problem in problems {
		fmt.eprintln(problem)
	}
	return 1 if len(problems) > 0 else 0
}

// Runs the suites against a staged copy of the checkout, so nothing is written
// into it. A suite is any directory under tests/ that holds a *_test.odin file.
//
// A suite that declares the package of src/ is compiled together with a copy of
// the library, and one under tests/.../<name>/ that declares the package of
// cmd/<name>/ together with a copy of that program, so its tests see private
// names; tests/support/<name>/ is added to both. Any other suite is a program
// of its own and compiled as it is.
test_command :: proc(arguments: []string) -> int {
	selected := "all"
	dependencies := shared_source()
	user := make([dynamic]string)
	index := 0
	options: for index < len(arguments) {
		switch arguments[index] {
		case "--shared":
			dependencies = option_value(arguments, &index) or_else ""
		case "--package":
			selected = option_value(arguments, &index) or_else ""
		case "--":
			index += 1
			break options
		case:
			break options
		}
		index += 1
	}
	for flag in arguments[min(index, len(arguments)):] {
		if strings.has_prefix(flag, "-collection:shared=") {
			dependencies = flag[len("-collection:shared="):]
			continue
		}
		append(&user, flag)
	}
	if selected == "" || dependencies == "" || !os.is_directory(dependencies) {
		return fail("no shared collection at %q", dependencies)
	}
	root := root_directory()
	if !os.is_directory(fmt.aprintf("%s/src", root)) {
		return fail("no src/ in %s", root)
	}
	homes := homes_find(root)
	if problems := layout_problems(root, homes); len(problems) > 0 {
		for problem in problems {
			fmt.eprintln(problem)
		}
		return 2
	}

	suites := suites_find(root, selected, homes)
	if len(suites) == 0 {
		return fail("no matching test suites")
	}
	work, created := work_directory("tests")
	if !created {
		return fail("cannot create a work directory")
	}
	defer os.remove_all(work)

	// The repository keeps its geometry (src/ beside tests/), so paths relative to
	// the root resolve as they do in the checkout.
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
	os.remove(fmt.aprintf("%s/aws", shared))
	if os.symlink(fmt.aprintf("%s/src", repository), fmt.aprintf("%s/aws", shared)) != nil {
		return fail("cannot stage the library")
	}
	fmt.printf("Library aws from %s/src; dependencies from %s\n", root, dependencies)

	flags := suite_flags(user[:], shared, fmt.aprintf("%s/tests", work))
	for suite, number in suites {
		target := fmt.aprintf("%s/%s", repository, suite.relative)
		if suite.home >= 0 {
			staged_target, ok := suite_stage(repository, fmt.aprintf("%s/compiled/%d", work, number), homes[suite.home], suite)
			if !ok {
				return fail("cannot stage %s", suite.relative)
			}
			target = staged_target
		}
		fmt.printf("Testing %s\n", suite.relative)
		command := make([dynamic]string)
		append(&command, compiler_path(), "test", target)
		append(&command, ..flags)
		if code := run(command[:], repository, SUITE_TIMEOUT); code != 0 {
			return code
		}
	}
	return 0
}

// The flags every suite gets after the user's: the memory check, unless the user
// set it, and an output path, unless the user gave one.
suite_flags :: proc(user: []string, shared, output: string) -> []string {
	flags := make([dynamic]string)
	has_output, has_memory_flag := false, false
	for flag in user {
		if strings.has_prefix(flag, "-collection:shared=") {
			continue
		}
		has_output ||= strings.has_prefix(flag, "-out:")
		has_memory_flag ||= strings.has_prefix(flag, "-define:ODIN_TEST_FAIL_ON_BAD_MEMORY=")
		append(&flags, flag)
	}
	append(&flags, fmt.aprintf("-collection:shared=%s", shared))
	if !has_memory_flag {
		append(&flags, SUITE_MEMORY_FLAG)
	}
	if !has_output {
		append(&flags, fmt.aprintf("-out:%s", output))
	}
	return flags[:]
}

// The package of home, its support files and the suite's files, in one directory.
suite_stage :: proc(repository, target: string, home: Home, suite: Suite) -> (directory: string, ok: bool) {
	directory_ensure(target) or_return
	for source in ([]string{home.source, fmt.aprintf("tests/support/%s", home.name), suite.relative}) {
		for name in odin_files(fmt.aprintf("%s/%s", repository, source)) {
			destination := fmt.aprintf("%s/%s", target, name)
			if os.exists(destination) {
				fmt.eprintf("tasks: %s/%s clashes with a file of the same name in %s\n", source, name, home.source)
				return "", false
			}
			if os.copy_file(destination, fmt.aprintf("%s/%s/%s", repository, source, name)) != nil {
				return "", false
			}
		}
	}
	return target, true
}

// The package a suite is compiled into: the library for its package, a program
// for a directory named after it that declares its package, none otherwise.
suite_home :: proc(root, relative: string, homes: []Home) -> int {
	suite_package := package_of(fmt.aprintf("%s/%s", root, relative))
	for home, index in homes {
		if suite_package == "" || suite_package != home.package_ {
			continue
		}
		if home.source == "src" || filepath.base(relative) == home.name {
			return index
		}
	}
	return -1
}

suites_find :: proc(root, selected: string, homes: []Home) -> []Suite {
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
		owner := strings.trim_prefix(relative, "tests/")
		// --package names a directory under tests/ and selects it with everything below.
		if selected != "all" && owner != selected && !strings.has_prefix(owner, fmt.aprintf("%s/", selected)) {
			continue
		}
		append(&suites, Suite{relative = relative, owner = owner, home = suite_home(root, relative, homes)})
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
