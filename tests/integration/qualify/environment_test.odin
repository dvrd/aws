package main

import "core:encoding/json"
import "core:os"
import "core:strings"
import "core:sys/posix"
import "core:testing"
import "core:time"

// Environment-mode qualification with synthetic keys and an owned fake CLI only.
ROLE :: "arn:aws:iam::" + ACCOUNT + ":role/webtools-qualification-s3"
ASSUMED :: "arn:aws:sts::" + ACCOUNT + ":assumed-role/webtools-qualification-s3/owned-session"

// Plans against a role instead of a profile and installs a fake AWS CLI that
// accepts exactly one STS call with exactly the owned temporary credentials.
environment_fixture :: proc(test: ^Test, arn := ASSUMED, account := ACCOUNT, role := ROLE) {
	fixture(test)
	resource := resource_default()
	resource["credential_source"] = "environment"
	resource["expected_role_arn"] = role
	delete_key(&resource, "profile")
	write_document(test.runner.arguments.resource_plan, resource)
	identity := make(json.Object)
	identity["Account"] = account
	identity["Arn"] = arn
	script := strings.concatenate(
		{
			"#!/bin/sh\n",
			`[ "$*" = "sts get-caller-identity --region us-east-1 --output json --no-cli-pager" ] || exit 1` + "\n",
			`[ "$AWS_ACCESS_KEY_ID" = owned-access ] || exit 1` + "\n",
			`[ "$AWS_SECRET_ACCESS_KEY" = owned-secret ] || exit 1` + "\n",
			`[ "$AWS_SESSION_TOKEN" = owned-session-token ] || exit 1` + "\n",
			`[ -z "${AWS_PROFILE+set}" ] || exit 1` + "\n",
			`[ -z "${AWS_ENDPOINT_URL+set}" ] || exit 1` + "\n",
			`[ "$AWS_CONFIG_FILE" = /dev/null ] || exit 1` + "\n",
			`[ "$AWS_SHARED_CREDENTIALS_FILE" = /dev/null ] || exit 1` + "\n",
			`echo sts-only >> "$TMPDIR/cli-calls"` + "\n",
			"printf '%s\\n' '",
			string(encode(identity)),
			"'\n",
		},
	)
	test.runner.arguments.aws_cli = strings.concatenate({test.root, "/fake-aws"})
	write_file(test.runner.arguments.aws_cli, script, posix.S_IRWXU)
	test.runner.credentials = credentials
	test.runner.variable = variable_fixed
	test.variables["PATH"] = "/usr/bin:/bin"
	test.variables["TMPDIR"] = test.root
	test.variables["AWS_ACCESS_KEY_ID"] = "owned-access"
	test.variables["AWS_SECRET_ACCESS_KEY"] = "owned-secret"
	test.variables["AWS_SESSION_TOKEN"] = "owned-session-token"
	test.variables["AWS_CREDENTIAL_EXPIRATION"] = "2099-01-01T00:00:00Z"
	test.variables["AWS_PROFILE"] = "must-not-override"
	test.variables["AWS_ENDPOINT_URL"] = "https://must-not-use.invalid"
}

cli_calls :: proc(test: ^Test) -> string {
	return read_text(strings.concatenate({test.root, "/cli-calls"}))
}

@(test)
planning_binds_policy_without_keys_cli_or_native_scope_changes :: proc(t: ^testing.T) {
	test: Test
	context.allocator = test_begin(&test, t)
	defer test_end(&test)
	environment_fixture(&test)
	test.runner.capture = capture_forbidden
	prepared := planned(&test)
	scope := document(&test, "scope.json")
	state := document(&test, "state.json")
	testing.expect(t, members_are(scope, SCOPE_MEMBERS))
	testing.expect(t, text_is(scope, "profile", "environment"))
	_, policy, failure := read_private_bytes(state_file(&test.runner, "credential-policy.json"))
	testing.expect_value(t, failure, Failure.None)
	testing.expect(t, text_is(state, "credential_policy_sha256", sha256_hex(policy)))
	testing.expect(t, "credential_attestation" not_in prepared)
	testing.expect(t, !strings.contains(read_text(state_file(&test.runner, "state.json")), "owned-secret"))
	testing.expect_value(t, test.captures, 0)
}

@(test)
real_fake_cli_validates_exact_triple_role_before_native_and_redacts :: proc(t: ^testing.T) {
	test: Test
	context.allocator = test_begin(&test, t)
	defer test_end(&test)
	environment_fixture(&test)
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
		test := cast(^Test)runner.user
		testing.expect_value(test.t, cli_calls(test), "sts-only\n")
		testing.expect_value(test.t, environment.variables["AWS_SESSION_TOKEN"], "owned-session-token")
		attestation, _ := object_of(state, "credential_attestation")
		testing.expect(test.t, is_true(attestation, "role_match"))
		append(&test.actions, verb)
		return result(object = "Owned" if verb == "put" else "Absent", verb = verb if verb == "put" || verb == "delete" else ""), .None
	}
	value, failure := command(&test, "run")
	testing.expect_value(t, failure, Failure.None)
	testing.expect(t, actions_are(&test, {"read", "put", "delete"}))
	testing.expect(t, is_true(value, "qualified"))
	expected := make(json.Object)
	expected["principal_type"] = "AssumedRole"
	expected["role_match"] = true
	expected["session_present"] = true
	expected["expiry_guard"] = true
	expected["expected_role_arn_sha256"] = sha256_hex(transmute([]u8)string(ROLE))
	testing.expect(t, same(value["credential_attestation"], expected))
	for name in ([]string{"state.json", "receipt.json"}) {
		stored := read_text(state_file(&test.runner, name))
		testing.expect(t, stored != "")
		for forbidden in ([]string{"owned-access", "owned-secret", "owned-session-token", ASSUMED, ROLE}) {
			testing.expect(t, !strings.contains(stored, forbidden))
		}
	}
}

@(test)
wrong_role_iam_user_or_account_stops_before_any_native_action :: proc(t: ^testing.T) {
	wrong, _ := strings.replace_all(ASSUMED, "/webtools-", "/wrong-")
	defer delete(wrong)
	cases := []struct {
		arn, account: string,
		expected:     Failure,
	} {
		{wrong, ACCOUNT, .Expected_Role_Not_Verified},
		{"arn:aws:iam::" + ACCOUNT + ":user/owned-user", ACCOUNT, .Expected_Role_Not_Verified},
		{ASSUMED, "000000000000", .Account_Not_Verified},
	}
	for item in cases {
		test: Test
		context.allocator = test_begin(&test, t)
		defer test_end(&test)
		environment_fixture(&test, item.arn, item.account)
		planned(&test)
		test.runner.launch = launch_forbidden
		_, failure := command(&test, "run")
		testing.expect_value(t, failure, item.expected)
		testing.expect_value(t, len(test.actions), 0)
		testing.expect_value(t, phase_of(document(&test, "state.json")), "PREPARED")
		testing.expect_value(t, cli_calls(&test), "sts-only\n")
	}
}

@(test)
missing_token_or_near_expiry_never_invokes_cli_or_native :: proc(t: ^testing.T) {
	near, formatted := time.time_to_rfc3339(time.time_add(time.now(), 179 * time.Second))
	testing.expect(t, formatted)
	defer delete(near)
	cases := []struct {
		name, value: string,
		expected:    Failure,
	} {
		{"AWS_SESSION_TOKEN", "", .Temporary_Credentials_Required},
		{"AWS_CREDENTIAL_EXPIRATION", near, .Credentials_Near_Expiry},
		{"AWS_CREDENTIAL_EXPIRATION", "", .Temporary_Expiration_Required},
		{"AWS_CREDENTIAL_EXPIRATION", "invalid", .Temporary_Expiration_Required},
	}
	for item in cases {
		test: Test
		context.allocator = test_begin(&test, t)
		defer test_end(&test)
		environment_fixture(&test)
		planned(&test)
		test.variables[item.name] = item.value
		test.runner.launch = launch_forbidden
		_, failure := command(&test, "run")
		testing.expect_value(t, failure, item.expected)
		testing.expect_value(t, len(test.actions), 0)
		testing.expect(t, !os.exists(strings.concatenate({test.root, "/cli-calls"})))
		testing.expect_value(t, phase_of(document(&test, "state.json")), "PREPARED")
	}
}

@(test)
role_name_metacharacters_are_matched_literally :: proc(t: ^testing.T) {
	test: Test
	context.allocator = test_begin(&test, t)
	defer test_end(&test)
	arn, _ := strings.replace_all(ASSUMED, "webtools-qualification-s3", "qaXroleZ")
	environment_fixture(&test, arn = arn, role = "arn:aws:iam::" + ACCOUNT + ":role/qa.role+")
	planned(&test)
	test.runner.launch = launch_forbidden
	_, failure := command(&test, "run")
	testing.expect_value(t, failure, Failure.Expected_Role_Not_Verified)
	testing.expect_value(t, len(test.actions), 0)
}

@(test)
identity_returning_after_campaign_deadline_cannot_start_native :: proc(t: ^testing.T) {
	test: Test
	context.allocator = test_begin(&test, t)
	defer test_end(&test)
	environment_fixture(&test)
	planned(&test)
	test.runner.launch = launch_forbidden
	test.runner.monotonic = proc(runner: ^Runner) -> time.Duration {
		return (cast(^Test)runner.user).clock
	}
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
		test.clock = 181 * time.Second
		return 0, transmute([]u8)string(`{"Account":"` + ACCOUNT + `","Arn":"` + ASSUMED + `"}`), .None
	}
	_, failure := command(&test, "run")
	testing.expect_value(t, failure, Failure.Campaign_Deadline)
	testing.expect_value(t, len(test.actions), 0)
	testing.expect_value(t, phase_of(document(&test, "state.json")), "PREPARED")
}

@(test)
policy_change_or_cross_account_role_is_refused :: proc(t: ^testing.T) {
	other_account, _ := strings.replace_all(ROLE, ACCOUNT, "000000000000")
	defer delete(other_account)
	for role in ([]string{other_account, ROLE + "/path", "not-an-arn"}) {
		test: Test
		context.allocator = test_begin(&test, t)
		defer test_end(&test)
		environment_fixture(&test, role = role)
		_, failure := plan(&test.runner)
		testing.expect_value(t, failure, Failure.Credential_Policy_Invalid)
	}
	test: Test
	context.allocator = test_begin(&test, t)
	defer test_end(&test)
	environment_fixture(&test)
	planned(&test)
	policy := document(&test, "credential-policy.json")
	changed, _ := strings.replace_all(ROLE, "webtools-", "wrong-")
	policy["expected_role_arn"] = changed
	write_document(state_file(&test.runner, "credential-policy.json"), policy)
	test.runner.capture = capture_forbidden
	_, failure := command(&test, "run")
	testing.expect_value(t, failure, Failure.Credential_Policy_Changed)
	testing.expect_value(t, test.captures, 0)
}

@(test)
receipt_refuses_unapproved_attestation_fields :: proc(t: ^testing.T) {
	test: Test
	context.allocator = test_begin(&test, t)
	defer test_end(&test)
	environment_fixture(&test)
	planned(&test)
	state := document(&test, "state.json")
	unapproved := make(json.Object)
	unapproved["provider_body"] = "owned-secret"
	state["credential_attestation"] = unapproved
	_, failure := receipt(test.runner.arguments.state_dir, state)
	testing.expect_value(t, failure, Failure.Role_Attestation_Invalid)
	testing.expect(t, !strings.contains(read_text(state_file(&test.runner, "receipt.json")), "owned-secret"))
}

@(test)
completed_state_and_unknown_intent_do_not_load_credentials_or_replay :: proc(t: ^testing.T) {
	for phase in ([]string{"COMPLETE", "PUT_INTENT", "DELETE_INTENT", "SES_INTENT"}) {
		test: Test
		context.allocator = test_begin(&test, t)
		defer test_end(&test)
		environment_fixture(&test)
		planned(&test)
		state := document(&test, "state.json")
		state["phase"] = phase
		write_document(state_file(&test.runner, "state.json"), state)
		test.runner.capture = capture_forbidden
		_, failure := command(&test, "run")
		testing.expect_value(t, failure, Failure.Run_Requires_Review)
		testing.expect_value(t, test.captures, 0)
		testing.expect(t, !os.exists(strings.concatenate({test.root, "/cli-calls"})))
	}
}
