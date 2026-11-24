package main

import "core:encoding/json"
import "core:strings"
import "core:sys/posix"
import "core:testing"
import "core:time"

@(test)
plan_is_private_and_does_not_launch_or_reissue_run :: proc(t: ^testing.T) {
	test: Test
	context.allocator = test_begin(&test, t)
	defer test_end(&test)
	fixture(&test)
	test.runner.capture = capture_forbidden
	value := planned(&test)
	testing.expect_value(t, phase_of(value), "PREPARED")
	testing.expect(t, !is_true(value, "qualified"))
	info: posix.stat_t
	testing.expect(t, posix.stat(strings.clone_to_cstring(state_file(&test.runner, "scope.json")), &info) == .OK)
	testing.expect_value(t, permission_bits(info.st_mode), 0o600)
	_, again := plan(&test.runner)
	testing.expect_value(t, again, Failure.Run_Already_Exists)
	testing.expect_value(t, test.captures, 0)
}

@(test)
scope_refuses_business_resource_paths_and_missing_guards :: proc(t: ^testing.T) {
	test: Test
	context.allocator = test_begin(&test, t)
	defer test_end(&test)
	fixture(&test)
	updates := []struct {
		name:     string,
		value:    json.Value,
		expected: Failure,
	} {
		{"bucket", "business-data", .Scope_Resource_Invalid},
		{"prefix", "qualification/../business/", .Scope_Resource_Invalid},
		{"expected_account", "wrong", .Scope_Resource_Invalid},
		{"public_access_block_verified", false, .Resources_Not_Ready},
		{"encryption", "none", .Resources_Not_Ready},
	}
	for update in updates {
		resource := resource_default()
		resource[update.name] = update.value
		write_document(test.runner.arguments.resource_plan, resource)
		_, failure := plan(&test.runner)
		testing.expect_value(t, failure, update.expected)
	}
}

@(test)
exact_roundtrip_intents_keep_secrets_out_of_state :: proc(t: ^testing.T) {
	test: Test
	context.allocator = test_begin(&test, t)
	defer test_end(&test)
	fixture(&test)
	planned(&test)
	value, failure := command(&test, "run")
	testing.expect_value(t, failure, Failure.None)
	testing.expect(t, actions_are(&test, {"read", "put", "delete"}))
	testing.expect(t, is_true(value, "qualified") && is_true(value, "s3_qualified"))
	put, _ := object_of(value, "put_result")
	removed, _ := object_of(value, "delete_result")
	testing.expect(t, text_is(put, "put_effect", "Response_Received"))
	testing.expect(t, text_is(removed, "delete_effect", "Response_Received"))
	for name in ([]string{"state.json", "receipt.json"}) {
		stored := read_text(state_file(&test.runner, name))
		testing.expect(t, stored != "" && !strings.contains(stored, SECRET))
	}
}

@(test)
readonly_miss_is_not_full_roundtrip_qualification :: proc(t: ^testing.T) {
	test: Test
	context.allocator = test_begin(&test, t)
	defer test_end(&test)
	fixture(&test, write = false)
	planned(&test)
	value, failure := command(&test, "run")
	testing.expect_value(t, failure, Failure.None)
	testing.expect(t, actions_are(&test, {"read"}))
	testing.expect_value(t, phase_of(value), "READ_ONLY_CHECKED")
	testing.expect(t, !is_true(value, "qualified"))
}

@(test)
unknown_put_requires_readonly_reconcile_and_never_resends :: proc(t: ^testing.T) {
	test: Test
	context.allocator = test_begin(&test, t)
	defer test_end(&test)
	fixture(&test)
	planned(&test)
	launch :: proc(
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
		if verb == "put" {
			return result(false, "Unverified", "Unknown", "put"), .None
		}
		return result(object = "Owned" if verb == "reconcile" else "Absent", verb = "delete" if verb == "delete" else ""), .None
	}
	test.runner.launch = launch
	value, failure := command(&test, "run")
	testing.expect_value(t, failure, Failure.None)
	testing.expect_value(t, phase_of(value), "PUT_INTENT")
	_, failure = command(&test, "run")
	testing.expect_value(t, failure, Failure.Run_Requires_Review)

	test.runner.launch = launch_absent
	value, failure = command(&test, "reconcile")
	testing.expect_value(t, failure, Failure.None)
	testing.expect_value(t, phase_of(value), "PUT_INTENT")
	test.runner.launch = launch
	value, failure = command(&test, "reconcile")
	testing.expect_value(t, failure, Failure.None)
	testing.expect_value(t, phase_of(value), "PUT_VERIFIED")
	value, failure = command(&test, "cleanup")
	testing.expect_value(t, failure, Failure.None)
	testing.expect(t, is_true(value, "qualified"))
	testing.expect_value(t, count_of(test.actions[:], "put"), 1)
}

@(test)
prior_put_evidence_survives_delete_verification_failure :: proc(t: ^testing.T) {
	test: Test
	context.allocator = test_begin(&test, t)
	defer test_end(&test)
	fixture(&test)
	planned(&test)
	test.runner.launch =
	proc(
		runner: ^Runner,
		state: json.Object,
		verb: string,
		environment: Environment,
		deadline: time.Duration,
	) -> (
		json.Object,
		Failure,
	) {
		if verb == "delete" {
			return result(false, "Unverified", "Response_Received", "delete"), .None
		}
		return result(object = "Owned" if verb == "put" else "Absent", verb = "put" if verb == "put" else ""), .None
	}
	value, failure := command(&test, "run")
	testing.expect_value(t, failure, Failure.None)
	testing.expect_value(t, phase_of(value), "DELETE_INTENT")
	put, _ := object_of(value, "put_result")
	removed, _ := object_of(value, "delete_result")
	testing.expect(t, text_is(put, "put_effect", "Response_Received"))
	testing.expect(t, text_is(removed, "delete_effect", "Response_Received"))
	testing.expect(t, !is_true(value, "qualified"))
	test.runner.launch = launch_absent
	value, failure = command(&test, "reconcile")
	testing.expect_value(t, failure, Failure.None)
	testing.expect(t, is_true(value, "qualified"))
}

@(test)
ses_needs_verified_sender_and_unknown_send_never_retries :: proc(t: ^testing.T) {
	test: Test
	context.allocator = test_begin(&test, t)
	defer test_end(&test)
	fixture(&test, ses = true)
	test.runner.arguments.ses_identity_verified = false
	_, failure := plan(&test.runner)
	testing.expect_value(t, failure, Failure.Verified_SES_Identity_Required)
	test.runner.arguments.ses_identity_verified = true
	planned(&test)
	test.runner.launch =
	proc(
		runner: ^Runner,
		state: json.Object,
		verb: string,
		environment: Environment,
		deadline: time.Duration,
	) -> (
		json.Object,
		Failure,
	) {
		if verb == "ses" {
			test := cast(^Test)runner.user
			append(&test.actions, verb)
			return result(false, "Unverified", "Unknown", "ses"), .None
		}
		return launch_success(runner, state, verb, environment, deadline)
	}
	value: json.Object
	value, failure = command(&test, "run")
	testing.expect_value(t, failure, Failure.None)
	testing.expect_value(t, phase_of(value), "SES_INTENT")
	testing.expect(t, is_true(value, "s3_qualified") && !is_true(value, "qualified"))
	_, failure = command(&test, "send")
	testing.expect_value(t, failure, Failure.Run_Requires_Review)
	testing.expect_value(t, count_of(test.actions[:], "ses"), 1)
}

@(test)
sts_checks_the_exported_triple_and_rejects_wrong_account :: proc(t: ^testing.T) {
	test: Test
	context.allocator = test_begin(&test, t)
	defer test_end(&test)
	fixture(&test)
	planned(&test)
	test.runner.arguments.aws_cli = "/fixture/aws"
	test.runner.variable = variable_fixed
	test.variables["PATH"] = "/usr/bin:/bin"
	test.variables["LINEAR_API"] = "fake-linear-secret"
	scope := document(&test, "scope.json")

	// kind selects the account the fake identity reports; status the export expiry.
	test.runner.capture =
	proc(
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
		exporting := false
		for argument in argv {
			exporting ||= argument == "export-credentials"
		}
		if exporting {
			testing.expect(test.t, "AWS_SECRET_ACCESS_KEY" not_in environment)
			expiration := `,"Expiration":"2000-01-01T00:00:00Z"` if test.status == 1 else ""
			text := strings.concatenate(
				{
					`{"Version":1,"AccessKeyId":"fixture-access","SecretAccessKey":"fake-private-material","SessionToken":null`,
					expiration,
					"}",
				},
			)
			return 0, transmute([]u8)text, .None
		}
		testing.expect_value(test.t, environment["AWS_SECRET_ACCESS_KEY"], SECRET)
		return 0, transmute([]u8)strings.concatenate({`{"Account":"`, test.kind, `"}`}), .None
	}
	deadline := test.runner.monotonic(&test.runner) + 10 * time.Second
	test.kind = ACCOUNT
	environment, failure := credentials(&test.runner, scope, deadline)
	testing.expect_value(t, failure, Failure.None)
	testing.expect(t, "LINEAR_API" not_in environment.variables)
	testing.expect(t, "AWS_SESSION_TOKEN" not_in environment.variables)
	testing.expect_value(t, test.captures, 2)

	test.kind = "000000000000"
	_, failure = credentials(&test.runner, scope, deadline)
	testing.expect_value(t, failure, Failure.Account_Not_Verified)
	test.kind = ACCOUNT
	test.status = 1
	_, failure = credentials(&test.runner, scope, deadline)
	testing.expect_value(t, failure, Failure.Credentials_Near_Expiry)
}

@(test)
live_binary_singleton_and_false_success_guards :: proc(t: ^testing.T) {
	test: Test
	context.allocator = test_begin(&test, t)
	defer test_end(&test)
	fixture(&test)
	planned(&test)
	test.runner.arguments.live = false
	_, failure := command(&test, "run")
	testing.expect_value(t, failure, Failure.Live_Opt_In_Required)
	test.runner.arguments.live = true
	{
		lock, locked := lock_acquire(test.runner.arguments.state_dir)
		testing.expect_value(t, locked, Failure.None)
		defer lock_release(lock)
		_, failure = command(&test, "run")
		testing.expect_value(t, failure, Failure.Locked)
	}
	// A put that answers without proving ownership is not a success.
	test.runner.launch =
	proc(
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
		return result(object = "Unverified" if verb == "put" else "Absent"), .None
	}
	value: json.Object
	value, failure = command(&test, "run")
	testing.expect_value(t, failure, Failure.None)
	testing.expect_value(t, phase_of(value), "PUT_INTENT")
	testing.expect(t, actions_are(&test, {"read", "put"}))
	write_file(test.runner.arguments.binary, "#!/bin/sh\nexit 1\n", posix.S_IRWXU)
	_, failure = command(&test, "run")
	testing.expect_value(t, failure, Failure.Run_Binding_Mismatch)
}

@(test)
real_child_output_limit_redacts_before_mutation :: proc(t: ^testing.T) {
	test: Test
	context.allocator = test_begin(&test, t)
	defer test_end(&test)
	fixture(
		&test,
		script = "#!/bin/sh\ni=0\nwhile [ $i -lt 2000 ]; do printf fake-private-material; i=$((i+1)); done\n",
	)
	planned(&test)
	test.runner.launch = native
	value, failure := command(&test, "run")
	testing.expect_value(t, failure, Failure.None)
	testing.expect_value(t, phase_of(value), "READ_INTENT")
	testing.expect(t, !is_true(value, "qualified"))
	testing.expect(t, text_is(value, "reason", "NATIVE_OUTCOME_UNKNOWN"))
	stored := read_text(state_file(&test.runner, "receipt.json"))
	testing.expect(t, stored != "" && !strings.contains(stored, SECRET))
}

@(test)
instants_need_an_explicit_zone_and_apply_it :: proc(t: ^testing.T) {
	base, base_ok := instant_parse("2030-01-02T03:04:05Z")
	testing.expect(t, base_ok)
	testing.expect_value(t, time.time_to_unix(base), 1893553445)
	for text in ([]string{"2030-01-02T03:04:05+00:00", "2030-01-02T03:04:05.123456+00:00", "2030-01-02T05:04:05.9+02:00", "2030-01-01T22:04:05-05:00"}) {
		instant, ok := instant_parse(text)
		testing.expect(t, ok && instant == base, text)
	}
	for text in ([]string{"", "invalid", "2030-01-02T03:04:05", "2030-01-02 03:04:05Z", "2030-13-02T03:04:05Z", "2030-01-02T03:04:05.Z", "2030-01-02T03:04:05+0000", "2030-01-02T03:04:05Zjunk"}) {
		_, ok := instant_parse(text)
		testing.expect(t, !ok, text)
	}
}

@(test)
documents_refuse_duplicate_members_and_non_finite_numbers :: proc(t: ^testing.T) {
	test: Test
	context.allocator = test_begin(&test, t)
	defer test_end(&test)
	cases := []struct {
		text:     string,
		expected: Failure,
	} {
		{`{"a":1,"b":{"a":2},"c":[{"a":3},{"a":4}]}`, .None},
		{`{"a":1,"a":2}`, .Duplicate_JSON},
		{`{"a":{"b":1,"b":2}}`, .Duplicate_JSON},
		{`{"a":1,"\u0061":2}`, .Duplicate_JSON},
		{`{"a":NaN}`, .Invalid_JSON},
		{`{"a":1} trailing`, .Invalid_JSON},
		{`{"a":1`, .Invalid_JSON},
	}
	for item in cases {
		text := item.text
		_, failure := decode(transmute([]u8)text)
		testing.expect_value(t, failure, item.expected)
	}
	value, failure := decode_object(transmute([]u8)string(`{"b":[true,null,"q\"\n"],"a":-3}`))
	testing.expect_value(t, failure, Failure.None)
	testing.expect_value(t, string(encode(value)), `{"a":-3,"b":[true,null,"q\"\u000a"]}`)
}
