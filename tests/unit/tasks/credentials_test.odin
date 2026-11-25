package main

import "core:fmt"
import "core:os"
import "core:strings"
import "core:testing"

// Unit tests of cmd/tasks/credentials.odin.

@(test)
credential_options_are_checked_before_anything_is_built :: proc(t: ^testing.T) {
	context.allocator = context.temp_allocator
	testing.expect_value(t, credentials_command({"--only", "no-such-fixture"}), 1)
	testing.expect_value(t, credentials_command({"--only"}), 1)
	testing.expect_value(t, credentials_command({"--verbose"}), 1)
}

@(test)
every_credential_fixture_is_handled_by_the_fixture_program :: proc(t: ^testing.T) {
	context.allocator = context.temp_allocator
	source := read_text(fmt.aprintf("%s/main.odin", CREDENTIALS_FIXTURE))
	testing.expect(t, source != "", "run from the root of the checkout")
	seen := make(map[string]bool)
	for fixture in CREDENTIAL_FIXTURES {
		testing.expectf(t, fixture not_in seen, "%s is listed twice", fixture)
		seen[fixture] = true
		testing.expectf(t, strings.contains(source, fmt.aprintf("%q", fixture)), "the fixture program has no mode %s", fixture)
	}
	testing.expect(t, os.is_directory(CREDENTIALS_FIXTURE))
}
