package main

import "core:testing"

// Unit tests of cmd/tasks/main.odin.

@(test)
commands_are_unique_documented_and_cover_the_check :: proc(t: ^testing.T) {
	context.allocator = context.temp_allocator
	names := make(map[string]bool)
	for command in COMMANDS {
		testing.expectf(t, command.name not_in names, "%s is listed twice", command.name)
		names[command.name] = true
		testing.expectf(t, command.run != nil && command.usage != "" && command.description != "", "%s", command.name)
	}
	for step in CHECK_STEPS {
		_, found := command_find(step)
		testing.expectf(t, found, "check runs %s, which is not a command", step)
	}
	_, found := command_find("deploy")
	testing.expect(t, !found)
}
