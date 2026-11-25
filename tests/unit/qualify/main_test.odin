package main

import "core:testing"

// Unit tests of cmd/qualify/main.odin: the command line.

@(test)
command_lines_parse_into_arguments :: proc(t: ^testing.T) {
	context.allocator = context.temp_allocator
	arguments, ok := arguments_parse(
		{
			"plan",
			"--state-dir",
			"/state",
			"--resource-plan=/plan.json",
			"--binary",
			"/probe",
			"--aws-cli",
			"/aws",
			"--allow-write",
			"--ses-sender",
			"a@example.test",
			"--ses-identity-verified",
			"--live",
		},
	)
	testing.expect(t, ok)
	testing.expect_value(
		t,
		arguments,
		Arguments {
			command = "plan",
			state_dir = "/state",
			resource_plan = "/plan.json",
			binary = "/probe",
			aws_cli = "/aws",
			ses_sender = "a@example.test",
			allow_write = true,
			ses_identity_verified = true,
			live = true,
		},
	)
	for command in ([]string{"plan", "run", "reconcile", "cleanup", "send", "status"}) {
		_, valid := arguments_parse({command, "--state-dir", "/state"})
		testing.expect(t, valid, command)
	}
	refused := [][]string {
		{},
		{"--state-dir", "/state"},
		{"status"},
		{"deploy", "--state-dir", "/state"},
		{"run", "status", "--state-dir", "/state"},
		{"run", "--state-dir"},
		{"run", "--state-dir", "/state", "--live=yes"},
		{"run", "--state-dir", "/state", "--verbose"},
	}
	for line in refused {
		_, valid := arguments_parse(line)
		testing.expectf(t, !valid, "%v", line)
	}
}
