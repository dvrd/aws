package main
import aws "shared:aws"
import "core:encoding/json"
import "core:mem"
import "core:strings"
import "core:testing"

Observed_Fixture :: struct {
	t:                    ^testing.T,
	status, gets, writes: int,
	body, token, url:     string,
	sequence:             bool,
}
observed_fixture_get :: proc(
	url: string,
	headers: []string,
	timeout: i64,
	bound: int,
	allocator: mem.Allocator,
) -> (
	[]u8,
	int,
	aws.S3_Get_Error,
) {
	s := cast(^Observed_Fixture)context.user_ptr
	s.gets += 1
	testing.expect_value(s.t, timeout, aws.S3_GET_TIMEOUT_MS)
	testing.expect_value(s.t, bound, 1024)
	if s.url == "" {
		s.url = strings.clone(url)
	} else {
		testing.expect_value(s.t, url, s.url)
	}
	if s.token != "" {
		found := false

		for header in headers {
			if strings.has_prefix(header, "x-amz-security-token: ") {
				found = header[len("x-amz-security-token: "):] == s.token
			}
		}

		testing.expect(s.t, found)
	}
	text := s.body
	status := s.status
	if s.sequence {
		status = s.gets == 1 ? 404 : 403
		text =
			s.gets == 1 \
				? "<Error><Code>NoSuchKey</Code></Error>" \
				: "<Error><Code>AccessDenied</Code><Message>private-fault</Message></Error>"
	}
	body := make([]u8, len(text), allocator)
	copy(body, transmute([]u8)text)
	return body, status, .None
}
observed_fixture_write :: proc(_: aws.HTTP_Request) -> ([]u8, aws.HTTP_Result) {
	s := cast(^Observed_Fixture)context.user_ptr
	s.writes += 1
	return nil, {}
}
observed_fixture_probe :: proc(s: ^Observed_Fixture, action: Action) -> Result {
	previous := context.user_ptr
	context.user_ptr = s
	defer context.user_ptr = previous

	return probe(
		TEST_SCOPE,
		action,
		TEST_RUN,
		{access_key = "fixture-access", secret_key = "fixture-secret", session_token = s.token},
		{get = observed_fixture_get, write = observed_fixture_write},
	)
}

@(test)
observed_s3_codes_are_strict_bounded_and_never_provider_strings :: proc(t: ^testing.T) {
	for item in ([]struct {
			text:     string,
			expected: S3_Observed_Code,
		} {
			{"<Error><Code>NoSuchBucket</Code></Error>", .NoSuchBucket},
			{"<?xml version=\"1.0\"?><Error><Code>NoSuchKey</Code></Error>", .NoSuchKey},
			{"<Error xmlns=\"urn:fixture\"><Code>ExpiredToken</Code></Error>", .ExpiredToken},
			{"<Error><Code>private-unrecognized-code</Code></Error>", .Unknown},
			{"<Error><Message><Code>NoSuchBucket</Code></Message></Error>", .Unknown},
			{"<Error><Code>NoSuchKey</Code><Code>NoSuchBucket</Code></Error>", .Unknown},
			{"<Error><Code>NoSuchBucket</Code></Error><Error></Error>", .Unknown},
			{"<Error><Code>NoSuchBucket</Code>", .Unknown},
			{"<!DOCTYPE Error><Error><Code>NoSuchBucket</Code></Error>", .Unknown},
			{"<Error><Code><![CDATA[NoSuchBucket]]></Code></Error>", .Unknown},
			{"<Error><Code>NoSuch&#66;ucket</Code></Error>", .Unknown},
			{"private-malformed-body", .Unknown},
		}) {testing.expect_value(t, observed_error_code(transmute([]u8)item.text), item.expected)}
	large := strings.repeat("x", 1025)
	defer delete(large)
	testing.expect_value(t, observed_error_code(transmute([]u8)large), .Unknown)
}

@(test)
missing_bucket_is_not_qualification_absence_or_permission_to_write :: proc(t: ^testing.T) {
	for action in ([]Action{.Read, .Put, .Delete}) {
		s := Observed_Fixture {
			t      = t,
			status = 404,
			body   = "<Error><Code>NoSuchBucket</Code></Error>",
		}

		defer delete(s.url)
		result := observed_fixture_probe(&s, action)
		testing.expect(t, !result.ok && result.object == .Unverified && result.reason == .Read_Failed)
		testing.expect_value(t, result.s3_kind, aws.S3_Get_Error.Not_Found)
		testing.expect_value(t, result.read_status, 404)
		testing.expect_value(t, result.read_error_code, S3_Observed_Code.NoSuchBucket)
		testing.expect(t, s.gets == 1 && s.writes == 0)
	}

	s := Observed_Fixture {
		t      = t,
		status = 404,
		body   = "<Error><Code>NoSuchKey</Code></Error>",
	}

	defer delete(s.url)
	result := observed_fixture_probe(&s, .Read)
	testing.expect(t, result.ok && result.object == .Absent && result.read_error_code == .NoSuchKey)
}

@(test)
observed_read_then_put_retains_status_token_and_no_extra_call :: proc(t: ^testing.T) {
	token := strings.repeat("fixture/token+value=", 96)
	defer delete(token)
	s := Observed_Fixture {
		t        = t,
		token    = token,
		sequence = true,
	}

	defer delete(s.url)
	first := observed_fixture_probe(&s, .Read)
	second := observed_fixture_probe(&s, .Put)
	testing.expect(t, first.ok && first.read_status == 404 && first.read_error_code == .NoSuchKey)
	testing.expect(t, !second.ok && second.read_status == 403 && second.read_error_code == .AccessDenied)
	testing.expect(t, second.put_effect == .Not_Sent && second.delete_effect == .Not_Sent)
	testing.expect(t, s.gets == 2 && s.writes == 0)
	data, error := json.marshal(second, {use_enum_names = true})
	assert(error == nil)
	defer delete(data)
	testing.expect(
		t,
		!strings.contains(string(data), "private-") &&
		!strings.contains(string(data), "fixture/") &&
		!strings.contains(string(data), "<Error>"),
	)
}

@(test)
unknown_provider_codes_are_redacted_without_reclassifying_sdk_errors :: proc(t: ^testing.T) {
	s := Observed_Fixture {
		t      = t,
		status = 403,
		body   = "<Error><Code>private-code</Code><Message>private-message</Message></Error>",
	}

	defer delete(s.url)
	result := observed_fixture_probe(&s, .Put)
	testing.expect(t, !result.ok && result.s3_kind == .Rejected && result.read_status == 403)
	testing.expect(t, result.read_error_code == .Unknown && s.gets == 1 && s.writes == 0)
	data, error := json.marshal(result, {use_enum_names = true})
	assert(error == nil)
	defer delete(data)
	testing.expect(t, !strings.contains(string(data), "private-") && !strings.contains(string(data), "<Error>"))
}

@(test)
production_observer_uses_native_default_guards_and_refuses_second_execution :: proc(t: ^testing.T) {
	capture: S3_Read_Observation
	previous := context.user_ptr
	context.user_ptr = &capture
	defer context.user_ptr = previous
	body, status, error := observed_get("invalid-url", nil, 0, 8, context.allocator)
	testing.expect(t, body == nil && status == 0 && error == .Invalid_Input)
	direct, direct_status, direct_error := aws.s3_get_native("invalid-url", nil, 0, 8, context.allocator)
	testing.expect(t, direct == nil && direct_status == status && direct_error == error)
	testing.expect(t, capture.calls == 1 && capture.status == 0 && capture.code == .None)
	_, _, repeated := observed_get("invalid-url", nil, 0, 8, context.allocator)
	testing.expect(t, repeated == .Invalid_Input && capture.calls == 1)
}
