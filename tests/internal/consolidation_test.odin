package aws

import "core:fmt"
import "core:os"
import "core:strings"
import "core:sync"
import "core:testing"
import "core:time"

S3_Time_Fixture :: struct {
	t:                 ^testing.T,
	method, signature: string,
	file:              bool,
	calls:             int,
	result:            S3_Result,
}
s3_time_fixture: ^S3_Time_Fixture
s3_exact_http :: proc(request: HTTP_Request) -> ([]u8, S3_Result) {
	s := s3_time_fixture
	s.calls += 1
	testing.expect_value(s.t, request.method, s.method)
	testing.expect_value(s.t, request.url, "https://examplebucket.s3.us-east-1.amazonaws.com/a%20b/c%2Bd")
	testing.expect(s.t, !request.allow_http && request.ca_file == "fixture-ca.pem")
	testing.expect_value(s.t, request.timeout_ms, i64(120000) if s.file else i64(15000))
	payload := "payload" if request.method == "PUT" else ""
	if s.file {
		testing.expect(s.t, request.upload_file != nil && request.upload_size == 7 && len(request.body) == 0)
		buffer: [7]u8
		n, e := os.read(request.upload_file, buffer[:])
		testing.expect(s.t, e == nil && n == 7 && string(buffer[:]) == payload)
	} else {
		testing.expect(s.t, request.upload_file == nil && request.upload_size == 0 && string(request.body) == payload)
	}
	digest :=
		"239f59ed55e737c77147cf55ad0c1b030b6d7ee748a7426952f9b852d5a935e5" if \
			request.method == "PUT" else \
			"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
	expected := []string{fmt.tprintf("x-amz-content-sha256: %s", digest), "x-amz-date: 20130524T000000Z", "Expect:"}
	testing.expect(s.t, len(request.headers) == 6 if request.method == "PUT" else len(request.headers) == 5)
	for field, i in expected {
		testing.expect_value(s.t, request.headers[i], field)
	}
	offset := 3
	if request.method == "PUT" {
		testing.expect_value(s.t, request.headers[offset], "Content-Type: text/plain")
		offset += 1
	}
	testing.expect_value(s.t, request.headers[offset], "x-amz-security-token: fixture/token+value")
	testing.expect_value(
		s.t,
		request.headers[offset + 1],
		fmt.tprintf(
			"Authorization: AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/20130524/us-east-1/s3/aws4_request, SignedHeaders=host;x-amz-content-sha256;x-amz-date;x-amz-security-token, Signature=%s",
			s.signature,
		),
	)
	return nil, s.result
}

@(test)
s3_at_operations_emit_deterministic_signed_wire_and_preserve_outcomes :: proc(t: ^testing.T) {
	sync.mutex_lock(&aws_test_http_mutex)
	defer sync.mutex_unlock(&aws_test_http_mutex)
	config := S3_Config {
		bucket  = "examplebucket",
		region  = "us-east-1",
		ca_file = "fixture-ca.pem",
	}

	credentials := AWS_Credentials {
		"AKIAIOSFODNN7EXAMPLE",
		"wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
		"fixture/token+value",
	}

	now := time.unix(1369353600, 0)
	fixture := S3_Time_Fixture {
		t = t,
		method = "PUT",
		signature = "ed63c9a16fbbdfc2127f409b79ffce52deaaea62ab8d39048ca5fc8d256e5b26",
		result = {status = 503, error = {kind = .IO_Failed, phase = .Read, write_effect = .Unknown}},
	}

	s3_time_fixture = &fixture
	defer {
		s3_time_fixture = nil
	}

	result := s3_put(
		config,
		credentials,
		"a b/c+d",
		transmute([]u8)string("payload"),
		"text/plain",
		now,
		s3_exact_http,
	)
	testing.expect(
		t,
		!result.ok &&
		result.status == 503 &&
		result.error.phase == .Read &&
		result.error.write_effect == .Unknown &&
		fixture.calls == 1,
	)
	fixture.result = {
		status       = 204,
		ok           = true,
		transport_ok = true,
	}

	fixture.method = "DELETE"
	fixture.signature = "703c365c9e031e61271a08e36dc622e00f12493b12901d9cf725e8f7f01f942b"
	result = s3_delete(config, credentials, "a b/c+d", now, s3_exact_http)
	testing.expect(t, result.ok && result.status == 204 && fixture.calls == 2)
	// HEAD exercises the existing generic signing/request seam, not a new public
	// S3 HEAD API. The callback is the entire wire executor; no sockets are opened.
	fixture.method = "HEAD"
	fixture.signature = "fdd51dae18ee3b7b2f9a6fe56ccec529798be849c3d8f94093884fec89aaf4d2"
	result = s3_object_request_at(config, credentials, "HEAD", "a b/c+d", nil, "", now, http_execute = s3_exact_http)
	testing.expect(t, result.ok && fixture.calls == 3)
	directory, error := os.make_directory_temp("", "aws-at-*", context.allocator)
	assert(error == nil)
	defer delete(directory)
	defer os.remove(directory)
	path := fmt.aprintf("%s/body", directory)
	defer delete(path)
	defer os.remove(path)
	assert(os.write_entire_file(path, "payload") == nil)
	fixture.method = "PUT"
	fixture.signature = "ed63c9a16fbbdfc2127f409b79ffce52deaaea62ab8d39048ca5fc8d256e5b26"
	fixture.file = true
	result = s3_put_file(config, credentials, "a b/c+d", path, "text/plain", now, s3_exact_http)
	testing.expect(t, result.ok && fixture.calls == 4)
	result = s3_put(config, {}, "a b/c+d", nil, "", now, s3_exact_http)
	testing.expect(t, !result.ok && fixture.calls == 4)
	// Do not add parameters to any old function-value type.
	put: proc(_: S3_Config, _: AWS_Credentials, _: string, _: []u8, _: string, _: time.Time, _: HTTP_Execute) -> S3_Result =
		s3_put
	file: proc(_: S3_Config, _: AWS_Credentials, _: string, _: string, _: string, _: time.Time, _: HTTP_Execute) -> S3_Result =
		s3_put_file
	del: proc(_: S3_Config, _: AWS_Credentials, _: string, _: time.Time, _: HTTP_Execute) -> S3_Result = s3_delete
	resolve: proc() -> (AWS_Credentials, bool) = aws_credentials
	testing.expect(t, put != nil && file != nil && del != nil && resolve != nil)
}

@(test)
s3_exact_presign_time_and_global_endpoint_fixture :: proc(t: ^testing.T) {
	config := S3_Config {
		bucket   = "examplebucket",
		region   = "us-east-1",
		endpoint = "https://examplebucket.s3.amazonaws.com",
	}

	credentials := AWS_Credentials{"AKIAIOSFODNN7EXAMPLE", "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY", ""}
	now := time.unix(1369353600, 0)
	url, ok := s3_download_url(config, credentials, "test.txt", 86400, now)
	testing.expect(t, ok)
	testing.expect_value(
		t,
		url,
		"https://examplebucket.s3.amazonaws.com/test.txt?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=AKIAIOSFODNN7EXAMPLE%2F20130524%2Fus-east-1%2Fs3%2Faws4_request&X-Amz-Date=20130524T000000Z&X-Amz-Expires=86400&X-Amz-SignedHeaders=host&X-Amz-Signature=aeeed9bbccd4d02ee5c0109b86d86835f995330da4c265957d157751f604d404",
	)
	current, current_ok := s3_download_url(config, credentials, "test.txt", 1)
	testing.expect(
		t,
		current_ok && !strings.contains(current, "X-Amz-Date=19700101T000000Z"),
		"omitted time is the current time",
	)
	_, invalid := s3_download_url(config, credentials, "test.txt", 604801, now)
	testing.expect(t, !invalid)
}

@(test)
ses_keeps_the_same_shared_sigv4_owner_with_its_service_scope :: proc(t: ^testing.T) {
	credentials := AWS_Credentials{"AKIAIOSFODNN7EXAMPLE", "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY", ""}
	headers := ses_headers(
		"us-east-1",
		credentials,
		"email.us-east-1.amazonaws.com",
		"20130524T000000Z",
		transmute([]u8)string(`{"fixture":true}`),
	)
	testing.expect_value(t, len(headers), 3)
	testing.expect_value(
		t,
		headers[2],
		"Authorization: AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/20130524/us-east-1/ses/aws4_request, SignedHeaders=content-type;host;x-amz-date, Signature=e99a4c5a7187beeb1818b101c484bbee3869e6b24eac0d093e2111c1a4ce0153",
	)
}
