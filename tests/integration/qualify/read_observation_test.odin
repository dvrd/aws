package main

import "core:encoding/json"
import "core:fmt"
import "core:strings"
import "core:testing"

// Safe per-read receipts using owned fake native children, never a provider.

// A probe that prints one result for the read action and another for the rest,
// exiting 0 or 2 the way the native probe does.
observation_fixture :: proc(test: ^Test, read: json.Object, put: json.Object = nil, write := true) {
	later := put if put != nil else read
	script := fmt.aprintf(
		"#!/bin/sh\nif [ \"$6\" = read ]; then printf '%%s\\n' '%s'; exit %d; fi\nprintf '%%s\\n' '%s'; exit %d\n",
		string(encode(read)),
		0 if is_true(read, "ok") else 2,
		string(encode(later)),
		0 if is_true(later, "ok") else 2,
	)
	fixture(test, write = write, script = script)
	test.runner.launch = native
	planned(test)
}

observed :: proc(base: json.Object, status: json.Value, code: json.Value) -> json.Object {
	base := base
	if status != nil {
		base["read_status"] = status
	}
	if code != nil {
		base["read_error_code"] = code
	}
	return base
}

denied_put :: proc() -> json.Object {
	put := observed(result(false, "Unverified", "Not_Sent", "put"), json.Integer(403), "AccessDenied")
	put["reason"] = "Read_Failed"
	put["s3_kind"] = "Rejected"
	return put
}

@(test)
initial_read_and_later_precondition_denial_remain_distinct :: proc(t: ^testing.T) {
	test: Test
	context.allocator = test_begin(&test, t)
	defer test_end(&test)
	read := observed(result(), json.Integer(404), "NoSuchKey")
	put := denied_put()
	observation_fixture(&test, read, put)
	value, failure := command(&test, "run")
	testing.expect_value(t, failure, Failure.None)
	testing.expect_value(t, phase_of(value), "PUT_INTENT")
	testing.expect(t, same(value["read_result"], read))
	testing.expect(t, same(value["put_result"], put))
	test.runner.capture = capture_forbidden
	_, failure = command(&test, "run")
	testing.expect_value(t, failure, Failure.Run_Requires_Review)
	testing.expect_value(t, test.captures, 0)
}

@(test)
reconciliation_observation_does_not_erase_original_read_or_put :: proc(t: ^testing.T) {
	test: Test
	context.allocator = test_begin(&test, t)
	defer test_end(&test)
	observation_fixture(&test, observed(result(), json.Integer(404), "NoSuchKey"), denied_put())
	first, failure := command(&test, "run")
	testing.expect_value(t, failure, Failure.None)
	later: json.Object
	later, failure = command(&test, "reconcile")
	testing.expect_value(t, failure, Failure.None)
	testing.expect_value(t, phase_of(later), "PUT_INTENT")
	testing.expect(t, same(later["read_result"], first["read_result"]))
	testing.expect(t, same(later["put_result"], first["put_result"]))
	reconciled, _ := object_of(later, "reconcile_result")
	testing.expect(t, integer_is(reconciled, "read_status", 403))
	testing.expect(t, text_is(reconciled, "read_error_code", "AccessDenied"))
}

@(test)
initial_read_survives_later_unparseable_child_output :: proc(t: ^testing.T) {
	test: Test
	context.allocator = test_begin(&test, t)
	defer test_end(&test)
	read := observed(result(), json.Integer(404), "NoSuchKey")
	put := observed(result(false, "Unverified", "Not_Sent", "put"), json.Integer(403), "private-untrusted-value")
	observation_fixture(&test, read, put)
	value, failure := command(&test, "run")
	testing.expect_value(t, failure, Failure.None)
	testing.expect(t, same(value["read_result"], read))
	testing.expect_value(t, phase_of(value), "PUT_INTENT")
	testing.expect(t, text_is(value, "reason", "NATIVE_OUTCOME_UNKNOWN"))
	testing.expect(t, !strings.contains(read_text(state_file(&test.runner, "receipt.json")), "private-"))
}

@(test)
unknown_allowlisted_code_is_safe_and_results_without_observation_remain_valid :: proc(t: ^testing.T) {
	for with_observation in ([]bool{false, true}) {
		test: Test
		context.allocator = test_begin(&test, t)
		defer test_end(&test)
		read := result()
		if with_observation {
			read = observed(read, json.Integer(404), "Unknown")
		}
		observation_fixture(&test, read, write = false)
		value, failure := command(&test, "run")
		testing.expect_value(t, failure, Failure.None)
		testing.expect_value(t, phase_of(value), "READ_ONLY_CHECKED")
		testing.expect(t, same(value["read_result"], read))
	}
}

@(test)
provider_text_partial_fields_and_invalid_status_never_enter_receipts :: proc(t: ^testing.T) {
	cases := []struct {
		status, code: json.Value,
		headers:      string,
	} {
		{json.Integer(403), "private-provider-code", ""},
		{true, "AccessDenied", ""},
		{json.Integer(-1), "Unknown", ""},
		{json.Integer(99), "Unknown", ""},
		{json.Integer(600), "Unknown", ""},
		{json.Integer(403), nil, ""},
		{nil, "AccessDenied", ""},
		{json.Integer(403), "Unknown", "private-token"},
	}
	for item in cases {
		test: Test
		context.allocator = test_begin(&test, t)
		defer test_end(&test)
		read := observed(result(), item.status, item.code)
		if item.headers != "" {
			read["headers"] = item.headers
		}
		observation_fixture(&test, read)
		value, failure := command(&test, "run")
		testing.expect_value(t, failure, Failure.None)
		testing.expect_value(t, phase_of(value), "READ_INTENT")
		testing.expect(t, text_is(value, "reason", "NATIVE_OUTCOME_UNKNOWN"))
		testing.expect(t, "read_result" not_in value)
		testing.expect(t, !strings.contains(read_text(state_file(&test.runner, "receipt.json")), "private-"))
	}
}

@(test)
explicit_missing_bucket_is_failed_and_false_absence_is_refused :: proc(t: ^testing.T) {
	for success in ([]bool{true, false}) {
		test: Test
		context.allocator = test_begin(&test, t)
		defer test_end(&test)
		response := observed(result(success, "Absent" if success else "Unverified"), json.Integer(404), "NoSuchBucket")
		response["reason"] = "None" if success else "Read_Failed"
		response["s3_kind"] = "Not_Found"
		observation_fixture(&test, response)
		value, failure := command(&test, "run")
		testing.expect_value(t, failure, Failure.None)
		testing.expect_value(t, phase_of(value), "READ_INTENT")
		testing.expect(t, !is_true(value, "qualified"))
		if success {
			testing.expect(t, "read_result" not_in value)
		} else {
			read, _ := object_of(value, "read_result")
			testing.expect(t, text_is(read, "read_error_code", "NoSuchBucket"))
		}
		testing.expect(t, "put_result" not_in value)
	}
}
