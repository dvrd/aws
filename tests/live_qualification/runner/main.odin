package main

import "core:fmt"
import "core:mem/virtual"
import "core:os"
import "core:strings"

USAGE :: `usage: runner {plan,run,reconcile,cleanup,send,status} --state-dir DIR
              [--resource-plan FILE] [--binary FILE] [--aws-cli FILE]
              [--allow-write] [--ses-sender ADDRESS] [--ses-identity-verified] [--live]
`

arguments_parse :: proc(input: []string) -> (arguments: Arguments, ok: bool) {
	index := 0
	for index < len(input) {
		argument := input[index]
		index += 1
		if !strings.has_prefix(argument, "--") {
			if arguments.command != "" {
				return {}, false
			}
			arguments.command = argument
			continue
		}
		name, value := argument, ""
		inline := false
		if equals := strings.index_byte(argument, '='); equals >= 0 {
			name, value, inline = argument[:equals], argument[equals + 1:], true
		}
		switch name {
		case "--allow-write", "--ses-identity-verified", "--live":
			if inline {
				return {}, false
			}
			switch name {
			case "--allow-write":
				arguments.allow_write = true
			case "--ses-identity-verified":
				arguments.ses_identity_verified = true
			case "--live":
				arguments.live = true
			}
			continue
		}
		if !inline {
			if index >= len(input) {
				return {}, false
			}
			value = input[index]
			index += 1
		}
		switch name {
		case "--state-dir":
			arguments.state_dir = value
		case "--resource-plan":
			arguments.resource_plan = value
		case "--binary":
			arguments.binary = value
		case "--aws-cli":
			arguments.aws_cli = value
		case "--ses-sender":
			arguments.ses_sender = value
		case:
			return {}, false
		}
	}
	switch arguments.command {
	case "plan", "run", "reconcile", "cleanup", "send", "status":
		return arguments, arguments.state_dir != ""
	}
	return {}, false
}

main :: proc() {
	arena: virtual.Arena
	if virtual.arena_init_growing(&arena) != nil {
		os.exit(2)
	}
	context.allocator = virtual.arena_allocator(&arena)
	arguments, parsed := arguments_parse(os.args[1:])
	if !parsed {
		fmt.eprint(USAGE)
		os.exit(2)
	}
	runner := runner_make(arguments)
	result, failure := execute(&runner)
	if failure != .None {
		fmt.println(`{"schema":1,"phase":"FAILED","reason":"QUALIFICATION_GUARD_FAILED"}`)
		os.exit(2)
	}
	fmt.println(string(encode(result)))
	switch phase, _ := text_of(result, "phase"); phase {
	case "PREPARED", "READ_ONLY_CHECKED", "PUT_VERIFIED", "S3_COMPLETE", "COMPLETE":
		os.exit(0)
	}
	os.exit(2)
}
