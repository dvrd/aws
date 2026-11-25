package main

import aws "shared:aws"
import "core:encoding/json"
import "core:strings"
import "core:testing"

@(test)
credential_denial_probe_accepts_only_scratch_namespace_and_explicit_live_opt_in :: proc(t: ^testing.T) {
	key :: "qualification/0123456789abcdef0123456789abcdef/0123456789abcdef0123456789abcdef.txt"
	testing.expect(t, scope_valid("webtools-qualification-fixture", "us-east-1", key))

	for rejected in ([]string{"business/key", "qualification/../business", "qualification/x/file.txt"}) {
		testing.expect(t, !scope_valid("webtools-qualification-fixture", "us-east-1", rejected))
	}

	testing.expect(t, !scope_valid("business-bucket", "us-east-1", key))
	testing.expect(t, !scope_valid("webtools-qualification-fixture", "bad/region", key))
	result := run({"probe", "private-input-marker"})
	testing.expect(t, !result.http_denied && result.reason == .Opt_In_Required)
}

@(test)
credential_denial_probe_never_confuses_failure_classes_or_echoes_resource_data :: proc(t: ^testing.T) {
	for fixture in ([]struct {
			status, calls: int,
			error:         aws.S3_Get_Error,
			denied:        bool,
		} {
			{403, 1, .Rejected, true},
			{400, 1, .Rejected, false},
			{404, 1, .Not_Found, false},
			{429, 1, .Unavailable, false},
			{0, 1, .Unavailable, false},
			{403, 2, .Rejected, false},
		}) {
		result := result_of({status = fixture.status, calls = fixture.calls}, fixture.error)
		testing.expect_value(t, result.http_denied, fixture.denied)
		data, error := json.marshal(result, {use_enum_names = true})
		assert(error == nil)
		defer delete(data)
		testing.expect(
			t,
			!strings.contains(string(data), "private-") &&
			!strings.contains(string(data), "access_key") &&
			!strings.contains(string(data), "bucket"),
		)
	}
}
