package main

import "core:testing"

// Unit tests of cmd/tasks/release.odin: versions, bumps and the pre-v1 rule.
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
nothing_reaches_v1_until_it_is_asked_for :: proc(t: ^testing.T) {
	// Before v1 a breaking change is held to minor; the rest is unchanged.
	testing.expect_value(t, release_bump({0, 2, 0}, .Major, false), Bump.Minor)
	testing.expect_value(t, release_bump({0, 2, 0}, .Minor, false), Bump.Minor)
	testing.expect_value(t, release_bump({0, 2, 0}, .Patch, false), Bump.Patch)
	testing.expect_value(t, version_next({0, 2, 0}, release_bump({0, 2, 0}, .Major, false)), Version{0, 3, 0})
	// Asking for it publishes v1.0.0 whatever the commits say.
	for bump in Bump {
		testing.expect_value(t, version_next({0, 9, 4}, release_bump({0, 9, 4}, bump, true)), Version{1, 0, 0})
	}
	// After v1 the commits decide, a breaking change included.
	testing.expect_value(t, release_bump({1, 4, 2}, .Major, false), Bump.Major)
	testing.expect_value(t, release_bump({1, 4, 2}, .Minor, false), Bump.Minor)
	testing.expect_value(t, release_bump({1, 4, 2}, .Patch, false), Bump.Patch)
	testing.expect(t, !plan_valid({stable = true, latest = {1, 0, 0}, previous = "v1.0.0"}))
	testing.expect(t, plan_valid({stable = true, latest = {0, 3, 0}, previous = "v0.3.0"}))
}

@(test)
release_accepts_stable_and_allow_drift :: proc(t: ^testing.T) {
	options, ok := release_options({"--stable", "--allow-drift"})
	testing.expect(t, ok && options.stable && options.allow_drift)
	_, valid := release_options({"--allow"})
	testing.expect(t, !valid)
}
