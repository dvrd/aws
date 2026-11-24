package main

import "core:encoding/json"
import "core:mem"
import "core:mem/virtual"
import "core:os"
import "core:strings"
import "core:sys/posix"
import "core:testing"
import "core:time"

// Owned offline fixtures only: no AWS CLI, provider requests or real keys.
Test :: struct {
	t:           ^testing.T,
	arena:       virtual.Arena,
	root:        string,
	runner:      Runner,
	actions:     [dynamic]string,
	variables:   map[string]string,
	clock:       time.Duration,
	// Knobs read by the launchers of individual tests.
	verb:        string,
	status:      i64,
	kind:        string,
	captures:    int,
}

ACCOUNT :: "123456789012"
SECRET :: "fake-private-material"

// Everything a test allocates lives in its arena, released by test_end.
test_begin :: proc(test: ^Test, t: ^testing.T) -> mem.Allocator {
	test.t = t
	assert(virtual.arena_init_growing(&test.arena) == nil)
	return virtual.arena_allocator(&test.arena)
}

test_end :: proc(test: ^Test) {
	if test.root != "" {
		os.remove_all(test.root)
	}
	virtual.arena_destroy(&test.arena)
}

write_file :: proc(path, text: string, mode: posix.mode_t = PRIVATE_FILE) {
	assert(os.write_entire_file(path, text) == nil)
	assert(posix.chmod(strings.clone_to_cstring(path), mode) == .OK)
}

write_document :: proc(path: string, value: json.Value) {
	write_file(path, string(encode(value)))
}

read_text :: proc(path: string) -> string {
	data, error := os.read_entire_file(path, context.allocator)
	if error != nil {
		return ""
	}
	return string(data)
}

document :: proc(test: ^Test, name: string) -> json.Object {
	value, failure := read_private(state_file(&test.runner, name))
	testing.expect_value(test.t, failure, Failure.None)
	return value
}

phase_of :: proc(object: json.Object) -> string {
	phase, _ := text_of(object, "phase")
	return phase
}

same :: proc(a, b: json.Value) -> bool {
	return string(encode(a)) == string(encode(b))
}

resource_default :: proc() -> json.Object {
	resource := make(json.Object)
	resource["schema"] = json.Integer(1)
	resource["phase"] = "READY"
	resource["bucket"] = "webtools-qualification-fixture"
	resource["prefix"] = "qualification/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/"
	resource["profile"] = "fixture"
	resource["region"] = "us-east-1"
	resource["expected_account"] = ACCOUNT
	resource["public_access_block_verified"] = true
	resource["encryption"] = "AES256"
	return resource
}

// A state directory parent with a ready resource plan and a probe that exits 0.
fixture :: proc(test: ^Test, write := true, ses := false, script := "#!/bin/sh\nexit 0\n") {
	root, error := os.make_directory_temp("", "aws-qualification-*", context.allocator)
	assert(error == nil)
	// The runner refuses relative and linked paths, and TMPDIR is a link on macOS.
	resolved := posix.realpath(strings.clone_to_cstring(root))
	assert(resolved != nil)
	test.root = strings.clone(string(resolved))
	posix.free(rawptr(resolved))
	arguments := Arguments {
		command               = "run",
		state_dir             = strings.concatenate({test.root, "/state"}),
		resource_plan         = strings.concatenate({test.root, "/resources.json"}),
		binary                = strings.concatenate({test.root, "/probe"}),
		allow_write           = write,
		live                  = true,
		ses_sender            = "qualification@example.test" if ses else "",
		ses_identity_verified = ses,
	}
	write_document(arguments.resource_plan, resource_default())
	write_file(arguments.binary, script, posix.S_IRWXU)
	test.runner = runner_make(arguments)
	test.runner.user = test
	test.runner.credentials = fake_credentials
	test.runner.launch = launch_success
}

planned :: proc(test: ^Test) -> json.Object {
	value, failure := plan(&test.runner)
	testing.expect_value(test.t, failure, Failure.None)
	return value
}

command :: proc(test: ^Test, name: string) -> (json.Object, Failure) {
	test.runner.arguments.command = name
	return run(&test.runner)
}

// A native result as the probe prints it.
result :: proc(ok := true, object := "Absent", effect := "Response_Received", verb := "") -> json.Object {
	value := make(json.Object)
	value["schema"] = json.Integer(1)
	value["ok"] = ok
	value["reason"] = "None" if ok else "Read_Failed"
	value["object"] = object
	value["credential_kind"] = "None"
	value["s3_kind"] = "None"
	value["ses_kind"] = "None"
	value["put_effect"] = "Not_Sent"
	value["delete_effect"] = "Not_Sent"
	value["ses_effect"] = "Not_Sent"
	value["mutation_status"] = json.Integer(200 if ok else 0)
	if verb != "" {
		value[strings.concatenate({verb, "_effect"})] = effect
	}
	return value
}

is_mutation :: proc(verb: string) -> bool {
	return verb == "put" || verb == "delete" || verb == "ses"
}

fake_credentials :: proc(runner: ^Runner, scope: json.Object, deadline: time.Duration) -> (Environment, Failure) {
	variables := make(map[string]string)
	variables["AWS_ACCESS_KEY_ID"] = "fixture-access"
	variables["AWS_SECRET_ACCESS_KEY"] = SECRET
	return {variables = variables}, .None
}

// Succeeds at every action after checking that its intent is already durable.
launch_success :: proc(
	runner: ^Runner,
	state: json.Object,
	verb: string,
	environment: Environment,
	deadline: time.Duration,
) -> (
	json.Object,
	Failure,
) {
	test := cast(^Test)runner.user
	append(&test.actions, verb)
	expected := ""
	switch verb {
	case "read":
		expected = "READ_INTENT"
	case "put":
		expected = "PUT_INTENT"
	case "delete":
		expected = "DELETE_INTENT"
	case "ses":
		expected = "SES_INTENT"
	}
	testing.expect_value(test.t, phase_of(document(test, "state.json")), expected)
	return result(object = "Owned" if verb == "put" else "Absent", verb = verb if is_mutation(verb) else ""), .None
}

launch_absent :: proc(
	runner: ^Runner,
	state: json.Object,
	verb: string,
	environment: Environment,
	deadline: time.Duration,
) -> (
	json.Object,
	Failure,
) {
	return result(), .None
}

launch_forbidden :: proc(
	runner: ^Runner,
	state: json.Object,
	verb: string,
	environment: Environment,
	deadline: time.Duration,
) -> (
	json.Object,
	Failure,
) {
	test := cast(^Test)runner.user
	append(&test.actions, verb)
	testing.expect(test.t, false, "no native action is expected")
	return nil, .System
}

capture_forbidden :: proc(
	runner: ^Runner,
	argv: []string,
	environment: map[string]string,
	deadline: time.Duration,
	limit: int,
) -> (
	int,
	[]u8,
	Failure,
) {
	test := cast(^Test)runner.user
	test.captures += 1
	testing.expect(test.t, false, "no child is expected")
	return 0, nil, .System
}

variable_fixed :: proc(runner: ^Runner, name: string) -> (string, bool) {
	test := cast(^Test)runner.user
	value, found := test.variables[name]
	return value, found
}

count_of :: proc(actions: []string, verb: string) -> int {
	count := 0
	for action in actions {
		if action == verb {
			count += 1
		}
	}
	return count
}

actions_are :: proc(test: ^Test, expected: []string) -> bool {
	if len(test.actions) != len(expected) {
		return false
	}
	for action, index in expected {
		if test.actions[index] != action {
			return false
		}
	}
	return true
}
