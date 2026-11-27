package main

import aws "shared:aws"
import surf "shared:surf"
import "core:mem"
import "core:strings"
import "core:testing"

TEST_RUN :: "0123456789abcdef0123456789abcdef"
TEST_SCOPE :: Scope {
	bucket           = "webtools-qualification-fixture",
	region           = "us-east-1",
	prefix           = "qualification/0123456789abcdef0123456789abcdef/",
	profile          = "fixture",
	expected_account = "123456789012",
	allow_write      = true,
}
Fixture :: struct {
	t:                                                              ^testing.T,
	object:                                                         Object,
	gets, puts, deletes, sends:                                     int,
	put_unknown, delete_unknown, ses_unknown:                       bool,
	put_readback_failure, delete_readback_failure, delete_mismatch: bool,
}

fixture_get :: proc(
	url: string,
	headers: []string,
	timeout_ms: i64,
	bytes_max: int,
	allocator: mem.Allocator,
) -> (
	[]u8,
	int,
	aws.S3_Get_Error,
) {
	fixture := cast(^Fixture)context.user_ptr
	fixture.gets += 1
	testing.expect(
		fixture.t,
		strings.has_prefix(url, "https://webtools-qualification-fixture.s3.us-east-1.amazonaws.com/qualification/"),
	)
	testing.expect(fixture.t, len(headers) >= 4 && timeout_ms == aws.S3_GET_TIMEOUT_MS)
	testing.expect_value(fixture.t, bytes_max, 1024)
	if fixture.put_readback_failure && fixture.puts > 0 || fixture.delete_readback_failure && fixture.deletes > 0 {
		return nil, 0, .Unavailable
	}
	if fixture.object == .Absent {
		return nil, 404, .Not_Found
	}
	text := "foreign-private-object"
	owned: string
	if fixture.object == .Owned {
		owned = strings.concatenate({PAYLOAD_PREFIX, TEST_RUN})
		text = owned
	}
	defer if owned != "" {
		delete(owned)
	}
	body := make([]u8, len(text), allocator)
	copy(body, transmute([]u8)text)
	return body, 200, .None
}

fixture_write :: proc(request: aws.HTTP_Request) -> ([]u8, aws.HTTP_Result) {
	fixture := cast(^Fixture)context.user_ptr
	testing.expect(fixture.t, request.ca_file == "" && !request.allow_http && request.timeout_ms <= 15000)
	testing.expect(fixture.t, request.upload_file == nil && request.upload_size == 0)
	signed := false
	for header in request.headers {
		if strings.has_prefix(header, "Authorization: AWS4-HMAC-SHA256 ") {
			signed = true
		}
	}
	testing.expect(fixture.t, signed)
	if request.method == "POST" {
		fixture.sends += 1
		testing.expect_value(fixture.t, request.url, "https://email.us-east-1.amazonaws.com/v2/email/outbound-emails")
		testing.expect(fixture.t, strings.contains(string(request.body), `"ToAddresses":["success@simulator.amazonses.com"]`))

		if fixture.ses_unknown {
			return nil, {error = {kind = .IO_Failed, write_effect = .Unknown}}
		}

		return transmute([]u8)string(`{"MessageId":"fixture-message"}`), {ok = true, status = 200}
	}
	testing.expect(
		fixture.t,
		strings.has_prefix(request.url, "https://webtools-qualification-fixture.s3.us-east-1.amazonaws.com/qualification/"),
	)
	if request.method == "PUT" {
		fixture.puts += 1
		fixture.object = .Owned
		expected := strings.concatenate({PAYLOAD_PREFIX, TEST_RUN})
		defer delete(expected)
		testing.expect_value(fixture.t, string(request.body), expected)

		if fixture.put_unknown {
			return nil, {error = {kind = .IO_Failed, write_effect = .Unknown}}
		}

		return nil, {ok = true, status = 200}
	}
	testing.expect_value(fixture.t, request.method, "DELETE")
	fixture.deletes += 1
	if !fixture.delete_mismatch {
		fixture.object = .Absent
	}
	if fixture.delete_unknown {
		return nil, {error = {kind = .IO_Failed, write_effect = .Unknown}}
	}
	return nil, {ok = true, status = 204}
}

fixture_probe :: proc(fixture: ^Fixture, action: Action, scope := TEST_SCOPE) -> Result {
	previous := context.user_ptr
	context.user_ptr = fixture
	defer context.user_ptr = previous
	credentials := aws.AWS_Credentials {
		access_key = "fixture-access",
		secret_key = "fixture-secret",
	}

	executors := Probe_Executors {
		write = fixture_write,
		get   = fixture_get,
	}

	return probe(scope, action, TEST_RUN, credentials, executors)
}

@(test)
scope_refuses_nonscratch_resources_and_implicit_ses :: proc(t: ^testing.T) {
	testing.expect(t, scope_valid(TEST_SCOPE))

	for mode in 0 ..< 5 {
		scope := TEST_SCOPE

		switch mode {
		case 0:
			scope.bucket = "application-data"
		case 1:
			scope.prefix = "qualification/../business/"
		case 2:
			scope.expected_account = "invalid"
		case 3:
			scope.profile = "unsafe\nprofile"
		case 4:
			scope.ses_sender = "configured-without-optin@example.test"
		}

		testing.expect(t, !scope_valid(scope))
	}

	for text in ([]string {
			`{"schema":1,"schema":1}`,
			`{} {}`,
			`{"x":[[[[]]]]}`,
			`{"schema":18446744073709551617}`,
			`{"x":1,}`,
		}) {
		_, _, valid := scope_decode(transmute([]u8)text)
		testing.expect(t, !valid)
	}
}

@(test)
owned_s3_roundtrip_hash_and_delete_use_one_exact_mutation_each :: proc(t: ^testing.T) {
	fixture := Fixture {
		t      = t,
		object = .Absent,
	}

	put := fixture_probe(&fixture, .Put)
	testing.expect(t, put.ok && put.object == .Owned && put.put_effect == .Response_Received)
	repeated := fixture_probe(&fixture, .Put)
	testing.expect(t, repeated.ok && repeated.object == .Owned)
	testing.expect_value(t, fixture.puts, 1)
	removed := fixture_probe(&fixture, .Delete)
	testing.expect(t, removed.ok && removed.object == .Absent && removed.delete_effect == .Response_Received)
	testing.expect_value(t, fixture.deletes, 1)
}

@(test)
foreign_object_cannot_be_put_over_or_deleted :: proc(t: ^testing.T) {
	fixture := Fixture {
		t      = t,
		object = .Foreign,
	}

	for action in ([]Action{.Put, .Delete}) {
		result := fixture_probe(&fixture, action)
		testing.expect(t, !result.ok && result.object == .Foreign)
	}

	testing.expect(t, fixture.puts == 0 && fixture.deletes == 0)
}

@(test)
unknown_put_is_not_replayed_and_reconciliation_only_reads :: proc(t: ^testing.T) {
	fixture := Fixture {
		t           = t,
		object      = .Absent,
		put_unknown = true,
	}

	result := fixture_probe(&fixture, .Put)
	testing.expect(t, !result.ok && result.put_effect == .Unknown)
	testing.expect_value(t, fixture.puts, 1)
	reconciled := fixture_probe(&fixture, .Reconcile)
	testing.expect(t, reconciled.ok && reconciled.object == .Owned)
	testing.expect_value(t, fixture.puts, 1)
	testing.expect_value(t, fixture.deletes, 0)
}

@(test)
acknowledged_put_and_delete_survive_later_default_get_diagnostics :: proc(t: ^testing.T) {
	fixture := Fixture {
		t                    = t,
		object               = .Absent,
		put_readback_failure = true,
	}

	result := fixture_probe(&fixture, .Put)
	testing.expect(t, !result.ok && result.object == .Unverified)
	testing.expect_value(t, result.put_effect, .Response_Received)
	fixture.put_readback_failure = false
	fixture.delete_readback_failure = true
	deleted := fixture_probe(&fixture, .Delete)
	testing.expect(t, !deleted.ok && deleted.object == .Unverified)
	testing.expect_value(t, deleted.delete_effect, .Response_Received)
}

@(test)
delete_readback_mismatch_and_readonly_scope_do_not_claim_cleanup :: proc(t: ^testing.T) {
	fixture := Fixture {
		t      = t,
		object = .Absent,
	}

	scope := TEST_SCOPE
	scope.allow_write = false
	blocked := fixture_probe(&fixture, .Put, scope)
	testing.expect(t, !blocked.ok && blocked.reason == .Put_Disabled)
	testing.expect_value(t, fixture.puts, 0)
	fixture.object = .Owned
	fixture.delete_mismatch = true
	result := fixture_probe(&fixture, .Delete)
	testing.expect(t, !result.ok && result.reason == .Response_Mismatch)
	testing.expect_value(t, result.delete_effect, .Response_Received)
}

@(test)
ses_is_disabled_by_default_and_only_sends_one_fixed_simulator_message :: proc(t: ^testing.T) {
	fixture := Fixture {
		t      = t,
		object = .Absent,
	}

	disabled := fixture_probe(&fixture, .SES)
	testing.expect(t, !disabled.ok && disabled.reason == .SES_Disabled)
	testing.expect_value(t, fixture.sends, 0)
	scope := TEST_SCOPE
	scope.allow_ses = true
	scope.ses_sender = "qualification@example.test"
	sent := fixture_probe(&fixture, .SES, scope)
	testing.expect(t, sent.ok && sent.ses_effect == .Response_Received)
	testing.expect_value(t, fixture.sends, 1)
}

@(test)
unknown_ses_response_remains_unknown_without_resending :: proc(t: ^testing.T) {
	fixture := Fixture {
		t           = t,
		object      = .Absent,
		ses_unknown = true,
	}

	scope := TEST_SCOPE
	scope.allow_ses = true
	scope.ses_sender = "qualification@example.test"
	result := fixture_probe(&fixture, .SES, scope)
	testing.expect(t, !result.ok && result.ses_kind == .Unavailable && result.ses_effect == .Unknown)
	testing.expect_value(t, fixture.sends, 1)
}
