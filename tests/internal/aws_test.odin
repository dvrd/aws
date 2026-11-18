package aws

import network_client "shared:surf"
import "core:fmt"
import "core:os"
import "core:strings"
import "core:sync"
import "core:testing"
import "core:time"

@(test)
profile_reading_preserves_sections_and_bounds :: proc(t: ^testing.T) {
	directory, error := os.make_directory_temp("", "aws-profile-*", context.allocator)

	if !testing.expect(t, error == nil) {
		return
	}

	defer delete(directory)
	defer os.remove(directory)
	path := fmt.aprintf("%s/credentials", directory)
	defer delete(path)
	defer os.remove(path)
	fixture :=
		"# synthetic fixture\n[default]\naws_access_key_id = default-key\naws_secret_access_key = default-secret\n" +
		"[ selected ]\naws_access_key_id = fixture-key\naws_secret_access_key = fixture-secret\naws_session_token = fixture-token\n"
	testing.expect(t, os.write_entire_file(path, fixture) == nil)
	credentials, _, _, read_error := credential_profile_load(path, "selected", false)
	testing.expect_value(t, read_error.kind, .None)
	testing.expect(t, aws_credentials_valid(credentials))
	testing.expect_value(t, credentials.access_key, "fixture-key")
	testing.expect_value(t, credentials.secret_key, "fixture-secret")
	testing.expect_value(t, credentials.session_token, "fixture-token")
	missing, _, _, missing_error := credential_profile_load(path, "missing", false)
	testing.expect(t, missing_error.kind == .None && !aws_credentials_valid(missing))
	large := make([]u8, 65537)
	defer delete(large)
	testing.expect(t, os.write_entire_file(path, large) == nil)
	_, _, _, limit_error := credential_profile_load(path, "selected", false)
	testing.expect_value(t, limit_error.kind, Read_Error_Kind.Limit_Exceeded)
	testing.expect(t, !aws_credentials_valid({"fixture\nkey", "secret", ""}))
	testing.expect(t, !aws_credentials_valid({"fixture-key", "", ""}))
}

@(test)
sigv4_matches_independent_fixture :: proc(t: ^testing.T) {
	// Expected signature independently calculated with Python hashlib/hmac.
	empty :: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
	canonical :=
		"GET\n/test.txt\n\nhost:examplebucket.s3.amazonaws.com\nrange:bytes=0-9\n" +
		"x-amz-content-sha256:" +
		empty +
		"\nx-amz-date:20130524T000000Z\n\n" +
		"host;range;x-amz-content-sha256;x-amz-date\n" +
		empty
	actual := s3_signature(
		"wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
		"us-east-1",
		"20130524T000000Z",
		"20130524/us-east-1/s3/aws4_request",
		canonical,
	)
	testing.expect_value(t, actual, "f0e8bdb87c964420e857bd35b5d6ed310bd44f0170aba48dd91039c6036bdb41")
}

AWS_Test_HTTP :: struct {
	t:                 ^testing.T,
	calls:             int,
	method, url, body: string,
	file_body:         bool,
	status:            int,
	response:          string,
	ok:                bool,
}
// Serialize only the shared fake provider; unrelated tests can run in parallel.
aws_test_http_mutex: sync.Mutex
aws_test_http_state: ^AWS_Test_HTTP

aws_test_http :: proc(request: HTTP_Request) -> ([]u8, network_client.Buffered_HTTP_Result) {
	state := aws_test_http_state
	state.calls += 1
	testing.expect_value(state.t, request.method, state.method)
	testing.expect_value(state.t, request.url, state.url)
	testing.expect(state.t, !request.allow_http && request.ca_file == "", "fake peer receives HTTPS policy")
	if state.file_body {
		testing.expect(state.t, request.upload_file != nil && request.upload_size == 7 && request.timeout_ms == 120000)
		buffer: [7]u8
		n, error := os.read(request.upload_file, buffer[:])
		testing.expect(state.t, error == nil && n == 7 && string(buffer[:]) == "payload")
	} else {
		testing.expect(state.t, request.upload_file == nil && request.upload_size == 0 && request.timeout_ms == 15000)

		if state.body != "" {
			testing.expect_value(state.t, string(request.body), state.body)
		}
	}
	auth, date := false, false
	for header in request.headers {
		if strings.has_prefix(header, "Authorization: AWS4-HMAC-SHA256 Credential=fixture-key/") {
			auth = true
		}

		if strings.has_prefix(header, "x-amz-date: ") {
			date = true
		}
	}
	testing.expect(state.t, auth && date, "signed headers reach the injected provider")
	return transmute([]u8)state.response, {status = state.status, ok = state.ok}
}

@(test)
s3_operations_use_injected_http_without_network :: proc(t: ^testing.T) {
	sync.mutex_lock(&aws_test_http_mutex)
	defer sync.mutex_unlock(&aws_test_http_mutex)
	credentials := AWS_Credentials{"fixture-key", "fixture-secret", "fixture-token"}
	config := S3_Config {
		bucket = "examplebucket",
		region = "us-east-1",
	}

	state := AWS_Test_HTTP {
		t      = t,
		method = "PUT",
		url    = "https://examplebucket.s3.us-east-1.amazonaws.com/a%20b",
		body   = "payload",
		status = 200,
		ok     = true,
	}

	aws_test_http_state = &state
	defer {
		aws_test_http_state = nil
	}

	result := s3_put(config, credentials, "a b", transmute([]u8)state.body, "text/plain", http_execute = aws_test_http)
	testing.expect(t, result.ok && result.status == 200 && state.calls == 1)
	state.method = "DELETE"
	state.body = ""
	result = s3_delete(config, credentials, "a b", http_execute = aws_test_http)
	testing.expect(t, result.ok && state.calls == 2)
	result = s3_put(config, {}, "a b", nil, "text/plain", http_execute = aws_test_http)
	testing.expect(t, !result.ok && state.calls == 2, "invalid credentials never reach HTTP")

	directory, error := os.make_directory_temp("", "aws-upload-*", context.allocator)

	if !testing.expect(t, error == nil) {
		return
	}

	defer delete(directory)
	defer os.remove(directory)
	path := fmt.aprintf("%s/body", directory)
	defer delete(path)
	defer os.remove(path)
	testing.expect(t, os.write_entire_file(path, "payload") == nil)
	state.method = "PUT"
	state.file_body = true
	result = s3_put_file(config, credentials, "a b", path, "text/plain", http_execute = aws_test_http)
	testing.expect(t, result.ok && state.calls == 3)
}

@(test)
ses_operation_uses_injected_http_and_preserves_outcomes :: proc(t: ^testing.T) {
	sync.mutex_lock(&aws_test_http_mutex)
	defer sync.mutex_unlock(&aws_test_http_mutex)
	credentials := AWS_Credentials{"fixture-key", "fixture-secret", ""}
	config := SES_Config {
		region    = "us-east-1",
		sender    = "from@example.test",
		recipient = "to@example.test",
	}

	state := AWS_Test_HTTP {
		t        = t,
		method   = "POST",
		url      = "https://email.us-east-1.amazonaws.com/v2/email/outbound-emails",
		status   = 200,
		response = `{"MessageId":"fixture-message"}`,
		ok       = true,
	}

	aws_test_http_state = &state
	defer {
		aws_test_http_state = nil
	}

	testing.expect_value(t, ses_send(config, credentials, "subject", "body", time.Time{}, aws_test_http), .None)
	state.response = "{}"
	testing.expect_value(
		t,
		ses_send(config, credentials, "subject", "body", time.Time{}, aws_test_http),
		.Invalid_Response,
	)
	state.status = 403
	testing.expect_value(t, ses_send(config, credentials, "subject", "body", time.Time{}, aws_test_http), .Rejected)
	state.status = 0
	state.ok = false
	testing.expect_value(t, ses_send(config, credentials, "subject", "body", time.Time{}, aws_test_http), .Unavailable)
	testing.expect_value(t, state.calls, 4)
}
