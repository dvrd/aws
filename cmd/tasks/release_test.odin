package main

import "core:testing"

@(test)
versions_are_strict_and_ordered :: proc(t: ^testing.T) {
	context.allocator = context.temp_allocator
	version, ok := version_parse("v1.20.3")
	testing.expect(t, ok)
	testing.expect_value(t, version, Version{1, 20, 3})
	for tag in ([]string{"", "1.2.3", "v1.2", "v1.2.3.4", "v01.2.3", "v1.2.x", "v1.2.3-rc1", "v1..3", "protocol-watch-1"}) {
		context.allocator = context.temp_allocator
		_, valid := version_parse(tag)
		testing.expect(t, !valid, tag)
	}
	testing.expect(t, version_less({0, 9, 9}, {0, 10, 0}))
	testing.expect(t, version_less({0, 1, 1}, {1, 0, 0}))
	testing.expect(t, !version_less({1, 2, 3}, {1, 2, 3}))
}

@(test)
subjects_decide_the_bump :: proc(t: ^testing.T) {
	cases := []struct {
		subjects: []string,
		bodies:   string,
		expected: Bump,
	} {
		{{"fix: wipe signing keys", "chore: pins", "Merge branch"}, "", .Patch},
		{{"docs: notes", "feat: sign requests without sending"}, "", .Minor},
		{{"feat(s3): builders", "fix: later"}, "", .Minor},
		{{"feat: one", "refactor!: rename the executor"}, "", .Major},
		{{"fix(s3)!: change results"}, "", .Major},
		{{"fix: one"}, "details\nBREAKING CHANGE: the executor takes a struct\n", .Major},
		{{"fix: one"}, "BREAKING-CHANGE: also accepted", .Major},
		{{"feature: not the feat type", "feat without a colon"}, "mentions BREAKING CHANGE: mid-line", .Patch},
		{{"fix(a(b))!: malformed scope", "!: no type"}, "", .Patch},
	}
	for item in cases {
		context.allocator = context.temp_allocator
		testing.expect_value(t, bump_of(item.subjects, item.bodies), item.expected)
	}
	testing.expect_value(t, version_next({0, 1, 1}, .Patch), Version{0, 1, 2})
	testing.expect_value(t, version_next({0, 1, 1}, .Minor), Version{0, 2, 0})
	testing.expect_value(t, version_next({0, 1, 1}, .Major), Version{1, 0, 0})
}

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
