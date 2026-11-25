package main

import "core:fmt"
import "core:os"
import "core:strconv"
import "core:strings"

// Semantic versions from Conventional Commits. The version follows from the commit
// subjects since the last vX.Y.Z tag:
//
//   type!: or a "BREAKING CHANGE:" footer   major
//   feat: or feat(scope):                   minor
//   anything else                           patch
//
// Before v1 the API may still change, so a breaking change bumps the minor
// version and nothing is ever bumped to v1 by the commits. v1.0.0 is published
// only when asked for with --stable; after that the table above applies as is.
//
// The tag is annotated with those subjects. Consumers pin it with
// "krs update aws@<tag>". Releases are cut from a clean main only.
Version :: struct {
	major, minor, patch: int,
}

Bump :: enum {
	Patch,
	Minor,
	Major,
}

// vX.Y.Z with no leading zeros and nothing after.
version_parse :: proc(tag: string) -> (version: Version, ok: bool) {
	if !strings.has_prefix(tag, "v") {
		return {}, false
	}
	parts := strings.split(tag[1:], ".")
	if len(parts) != 3 {
		return {}, false
	}
	numbers: [3]int
	for part, index in parts {
		if part == "" || len(part) > 1 && part[0] == '0' {
			return {}, false
		}
		for character in part {
			if character < '0' || character > '9' {
				return {}, false
			}
		}
		numbers[index] = strconv.parse_int(part, 10) or_return
	}
	return {numbers[0], numbers[1], numbers[2]}, true
}

version_less :: proc(a, b: Version) -> bool {
	if a.major != b.major {
		return a.major < b.major
	}
	if a.minor != b.minor {
		return a.minor < b.minor
	}
	return a.patch < b.patch
}

// The type of a Conventional Commit subject, and whether it is marked breaking:
// "feat(scope)!: text" is ("feat", true).
subject_type :: proc(subject: string) -> (type: string, breaking: bool, ok: bool) {
	colon := strings.index_byte(subject, ':')
	if colon < 1 {
		return "", false, false
	}
	head := subject[:colon]
	if strings.has_suffix(head, "!") {
		breaking = true
		head = head[:len(head) - 1]
	}
	if open := strings.index_byte(head, '('); open >= 0 {
		scope := head[open:]
		if len(scope) < 3 || scope[len(scope) - 1] != ')' || strings.contains_any(scope[1:len(scope) - 1], "()") {
			return "", false, false
		}
		head = head[:open]
	}
	if head == "" {
		return "", false, false
	}
	for character, index in head {
		letter := character >= 'a' && character <= 'z' || character >= 'A' && character <= 'Z'
		if !letter && (index == 0 || !(character >= '0' && character <= '9') && character != '-') {
			return "", false, false
		}
	}
	return head, breaking, true
}

bump_of :: proc(subjects: []string, bodies: string) -> Bump {
	bump := Bump.Patch
	for subject in subjects {
		type, breaking, conventional := subject_type(subject)
		if !conventional {
			continue
		}
		if breaking {
			return .Major
		}
		if type == "feat" {
			bump = .Minor
		}
	}
	for line in strings.split_lines(bodies) {
		if strings.has_prefix(line, "BREAKING CHANGE:") || strings.has_prefix(line, "BREAKING-CHANGE:") {
			return .Major
		}
	}
	return bump
}

version_next :: proc(version: Version, bump: Bump) -> Version {
	switch bump {
	case .Major:
		return {version.major + 1, 0, 0}
	case .Minor:
		return {version.major, version.minor + 1, 0}
	case .Patch:
		return {version.major, version.minor, version.patch + 1}
	}
	return version
}

// The bump a release applies. Before v1 a breaking change is held to minor, and
// stable (the explicit decision to publish v1.0.0) is the only way to v1.
release_bump :: proc(latest: Version, bump: Bump, stable: bool) -> Bump {
	if latest.major > 0 {
		return bump
	}
	if stable {
		return .Major
	}
	return .Minor if bump == .Major else bump
}

Plan :: struct {
	previous: string, // "" before the first release
	next:     string,
	bump:     Bump, // what the commits ask for
	applied:  Bump, // what the release applies
	stable:   bool, // this release is the decision to publish v1.0.0
	latest:   Version,
	subjects: []string,
}

plan_valid :: proc(plan: Plan) -> bool {
	if plan.stable && plan.latest.major > 0 {
		fail("--stable publishes v1.0.0, and %s is already past it", plan.previous)
		return false
	}
	return true
}

Release_Options :: struct {
	stable, allow_drift: bool,
}

release_options :: proc(arguments: []string) -> (options: Release_Options, ok: bool) {
	for argument in arguments {
		switch argument {
		case "--stable":
			options.stable = true
		case "--allow-drift":
			options.allow_drift = true
		case:
			fail("unknown option: %s", argument)
			return {}, false
		}
	}
	return options, true
}

// --stable publishes v1.0.0. It is refused once the library is past v1.
stable_option :: proc(arguments: []string) -> (stable: bool, ok: bool) {
	for argument in arguments {
		if argument != "--stable" {
			fail("unknown option: %s", argument)
			return false, false
		}
		stable = true
	}
	return stable, true
}

release_plan :: proc(stable := false) -> (plan: Plan, ok: bool) {
	tags, code := output({"git", "tag", "--merged", "HEAD"})
	if code != 0 {
		return {}, false
	}
	latest: Version
	for tag in strings.split_lines(tags) {
		version, valid := version_parse(tag)
		if valid && (plan.previous == "" || version_less(latest, version)) {
			latest, plan.previous = version, tag
		}
	}
	range := "HEAD" if plan.previous == "" else fmt.aprintf("%s..HEAD", plan.previous)
	subjects, subjects_code := output({"git", "log", "--reverse", "--format=%s", range})
	bodies, bodies_code := output({"git", "log", "--format=%b", range})
	if subjects_code != 0 || bodies_code != 0 {
		return {}, false
	}
	listed := make([dynamic]string)
	for subject in strings.split_lines(subjects) {
		if subject != "" {
			append(&listed, subject)
		}
	}
	plan.subjects = listed[:]
	plan.bump = bump_of(plan.subjects, bodies)
	plan.stable = stable
	plan.latest = latest
	plan.applied = release_bump(latest, plan.bump, stable)
	next := version_next(latest, plan.applied)
	plan.next = fmt.aprintf("v%d.%d.%d", next.major, next.minor, next.patch)
	return plan, true
}

// Prints the plan. False when there is nothing to release.
plan_print :: proc(plan: Plan) -> bool {
	if len(plan.subjects) == 0 && !plan.stable {
		fmt.printf("%s is the current release; nothing has been committed since.\n", plan.previous)
		return false
	}
	names := [Bump]string {
		.Patch = "patch",
		.Minor = "minor",
		.Major = "major",
	}
	reason := names[plan.applied]
	if plan.stable {
		reason = "stable, published on request"
	} else if plan.applied != plan.bump {
		reason = "minor: breaking changes bump the minor version before v1"
	}
	fmt.printf(
		"Last release: %s\nNext release: %s (%s, %d commit(s))\n",
		plan.previous if plan.previous != "" else "none",
		plan.next,
		reason,
		len(plan.subjects),
	)
	for subject in plan.subjects {
		fmt.printf("  %s\n", subject)
	}
	return true
}

version_command :: proc(arguments: []string) -> int {
	stable, parsed := stable_option(arguments)
	if !parsed {
		return 64
	}
	plan, planned := release_plan(stable)
	if !planned {
		return fail("cannot read the Git history")
	}
	if !plan_valid(plan) {
		return 1
	}
	plan_print(plan)
	return 0
}

release_command :: proc(arguments: []string) -> int {
	options, parsed := release_options(arguments)
	if !parsed {
		return 64
	}
	branch, _ := output({"git", "branch", "--show-current"})
	if strings.trim_space(branch) != "main" {
		return fail("releases are tagged on main")
	}
	changes, _ := output({"git", "status", "--porcelain", "--untracked-files=all"})
	if strings.trim_space(changes) != "" {
		return fail("commit or stash every change before releasing")
	}
	plan, planned := release_plan(options.stable)
	if !planned {
		return fail("cannot read the Git history")
	}
	if !plan_valid(plan) {
		return 1
	}
	if len(plan.subjects) == 0 && !options.stable {
		plan_print(plan)
		return 0
	}
	if !options.allow_drift {
		if code := deps_command({"--strict"}); code != 0 {
			return fail("the shared collection differs from .krs/packages.json; release against the pins or pass --allow-drift")
		}
	}
	if code := check_command(nil); code != 0 {
		return code
	}
	plan_print(plan)
	work, created := work_directory("release")
	if !created {
		return fail("cannot create a work directory")
	}
	defer os.remove_all(work)
	message := strings.builder_make()
	fmt.sbprintf(&message, "aws %s\n\n", plan.next)
	for subject in plan.subjects {
		fmt.sbprintf(&message, "- %s\n", subject)
	}
	file := fmt.aprintf("%s/message", work)
	if os.write_entire_file(file, strings.to_string(message)) != nil {
		return fail("cannot write the tag message")
	}
	if code := run({"git", "tag", "-a", plan.next, "-F", file}); code != 0 {
		return code
	}
	head, _ := output({"git", "rev-parse", "--short", "HEAD"})
	fmt.printf("Tagged %s at %s. Consumers: krs update aws@%s\n", plan.next, strings.trim_space(head), plan.next)
	return 0
}
