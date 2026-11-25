// The project's task runner. Taskfile.yml builds it to build/tasks and every task
// is one of its commands, run from the repository root.
//
// ODIN selects the compiler (default "odin"). WEBTOOLS_SHARED selects the shared
// collection that provides the dependencies (default ~/dev/oss/Odin/shared).
package main

import "core:fmt"
import "core:mem/virtual"
import "core:os"

Command :: struct {
	name:        string,
	run:         proc(arguments: []string) -> int,
	usage:       string,
	description: string,
}

COMMANDS := [?]Command {
	{"check", check_command, "check", "Type-check the library and run every offline test."},
	{"build", build_command, "build [Odin flags]", "Type-check the library with vet and warnings as errors."},
	{
		"test",
		test_command,
		"test [--shared DIR] [--package PATH] [--internal-only] [-- Odin flags]",
		"Stage the checkout and run the Odin test suites.",
	},
	{"signatures", signatures_command, "signatures", "Recalculate the SigV4 fixtures with OpenSSL."},
	{"consumer", consumer_command, "consumer", "Build and run a consumer that vendors the library."},
	{
		"credentials",
		credentials_command,
		"credentials [--only FIXTURE]",
		"Run the credential resolver fixtures under the address sanitizer.",
	},
	{
		"loopback",
		loopback_command,
		"loopback [--mode default|observer] [--report FILE]",
		"Observe the native S3 GET against an owned TLS loopback peer.",
	},
	{
		"native-errors",
		native_errors_command,
		"native-errors [--report FILE]",
		"Check S3 error handling against an owned TLS peer.",
	},
	{
		"version",
		version_command,
		"version [--stable]",
		"Show the last released version and the one the next release would get.",
	},
	{
		"release",
		release_command,
		"release [--stable]",
		"Check, then tag HEAD with the next semantic version. --stable publishes v1.0.0.",
	},
}

main :: proc() {
	arena: virtual.Arena
	if virtual.arena_init_growing(&arena) != nil {
		os.exit(70)
	}
	context.allocator = virtual.arena_allocator(&arena)
	if len(os.args) < 2 || os.args[1] == "--help" || os.args[1] == "-h" {
		fmt.println("usage: tasks <command> [options]")
		for command in COMMANDS {
			fmt.printf("  %-14s %s\n", command.name, command.description)
		}
		os.exit(0 if len(os.args) >= 2 else 64)
	}
	name := os.args[1]
	arguments := os.args[2:]
	for command in COMMANDS {
		if name != command.name {
			continue
		}
		if len(arguments) == 1 && (arguments[0] == "--help" || arguments[0] == "-h") {
			fmt.printf("usage: tasks %s\n\n%s\n", command.usage, command.description)
			return
		}
		os.exit(command.run(arguments))
	}
	fmt.eprintf("tasks: unknown command %q (see tasks --help)\n", name)
	os.exit(64)
}

// Everything offline, in the order a failure is cheapest to find.
check_command :: proc(arguments: []string) -> int {
	steps := []Command {
		{name = "build", run = build_command},
		{name = "test", run = test_command},
		{name = "signatures", run = signatures_command},
		{name = "consumer", run = consumer_command},
		{name = "credentials", run = credentials_command},
		{name = "loopback", run = loopback_command},
		{name = "native-errors", run = native_errors_command},
	}
	for step in steps {
		if code := step.run(nil); code != 0 {
			fmt.eprintf("tasks: %s failed\n", step.name)
			return code
		}
	}
	return 0
}

build_command :: proc(arguments: []string) -> int {
	command := make([dynamic]string)
	append(&command, compiler(), "check", "src", "-no-entry-point", "-vet", "-warnings-as-errors")
	append(&command, fmt.aprintf("-collection:shared=%s", shared_source()))
	append(&command, ..arguments)
	return run(command[:])
}
