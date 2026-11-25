package aws

import network_client "shared:surf"
import tls "shared:async/tls"
import "core:bytes"
import "core:crypto/hash"
import "core:encoding/hex"
import "core:fmt"
import "core:mem"
import "core:os"
import "core:strings"
import "core:sync"
import "core:testing"
import "core:time"
import x509 "core:crypto/x509"
// Unit tests of src/s3.odin: signing, the request builders, the blocking
// calls through injected executors, endpoints, keys and the observer.
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

S3_Time_Fixture :: struct {
	t:                 ^testing.T,
	method, signature: string,
	file:              bool,
	calls:             int,
	result:            network_client.Buffered_HTTP_Result,
}

s3_time_fixture: ^S3_Time_Fixture

s3_exact_http :: proc(request: HTTP_Request) -> ([]u8, network_client.Buffered_HTTP_Result) {
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
		result.error == .Unavailable &&
		result.effect == .Response_Received &&
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
	for expires in ([]int{0, -1}) {
		_, refused := s3_download_url(config, credentials, "test.txt", expires, now)
		testing.expectf(t, !refused, "%d", expires)
	}
	for expires in ([]int{1, 604800}) {
		_, accepted := s3_download_url(config, credentials, "test.txt", expires, now)
		testing.expectf(t, accepted, "%d", expires)
	}
}

// Expected signatures independently calculated with Python hashlib/hmac.
@(test)
s3_request_builders_sign_without_sending :: proc(t: ^testing.T) {
	credentials := AWS_Credentials{"fixture-key", "fixture-secret", "fixture-token"}
	config := S3_Config{bucket = "examplebucket", region = "us-east-1"}
	now := time.unix(1369353600, 0)
	body := "payload"

	put, put_ok := s3_put_request(config, credentials, "a b", transmute([]u8)body, "text/plain", now)
	testing.expect(t, put_ok)
	testing.expect_value(t, put.method, "PUT")
	testing.expect_value(t, put.url, "https://examplebucket.s3.us-east-1.amazonaws.com/a%20b")
	testing.expect_value(t, string(put.body), body)
	testing.expect_value(t, len(put.headers), 5)
	testing.expect_value(t, s3_request_header(put, "Content-Type"), "text/plain")
	testing.expect_value(t, s3_request_header(put, "x-amz-date"), "20130524T000000Z")
	testing.expect_value(t, s3_request_header(put, "x-amz-security-token"), "fixture-token")
	testing.expect_value(
		t,
		s3_request_header(put, "x-amz-content-sha256"),
		"239f59ed55e737c77147cf55ad0c1b030b6d7ee748a7426952f9b852d5a935e5",
	)
	testing.expect_value(
		t,
		s3_request_header(put, "Authorization"),
		"AWS4-HMAC-SHA256 Credential=fixture-key/20130524/us-east-1/s3/aws4_request, " +
		"SignedHeaders=host;x-amz-content-sha256;x-amz-date;x-amz-security-token, " +
		"Signature=98094a46331c84b1e9d319c36e2684662ed1b0cd9a95d8c9026ba821dc561a7b",
	)

	credentials.session_token = ""
	remove, remove_ok := s3_delete_request(config, credentials, "a b", now)
	testing.expect(t, remove_ok)
	testing.expect_value(t, remove.method, "DELETE")
	testing.expect_value(t, remove.url, put.url)
	testing.expect_value(t, len(remove.body), 0)
	testing.expect_value(t, len(remove.headers), 3)
	testing.expect_value(
		t,
		s3_request_header(remove, "Authorization"),
		"AWS4-HMAC-SHA256 Credential=fixture-key/20130524/us-east-1/s3/aws4_request, " +
		"SignedHeaders=host;x-amz-content-sha256;x-amz-date, " +
		"Signature=ad440d603284fb2ae964daaf457d3c38fd30cb6fb9730fcd1476a9e3434530b2",
	)
	for header in remove.headers {
		testing.expect(t, header.value != "", "the empty Expect line is not a request header")
	}
}

@(test)
s3_request_builders_reject_invalid_input :: proc(t: ^testing.T) {
	credentials := AWS_Credentials{"fixture-key", "fixture-secret", ""}
	config := S3_Config{bucket = "examplebucket", region = "us-east-1"}

	_, ok := s3_put_request(config, {}, "key", nil, "text/plain")
	testing.expect(t, !ok, "credentials are required")
	_, ok = s3_put_request(config, credentials, "", nil, "text/plain")
	testing.expect(t, !ok, "key is required")
	_, ok = s3_put_request(config, credentials, "key", nil, "text/plain\r\nx-injected: 1")
	testing.expect(t, !ok, "content type cannot carry a header")
	_, ok = s3_delete_request({region = "us-east-1"}, credentials, "key")
	testing.expect(t, !ok, "bucket is required")
	request, signed := s3_delete_request(config, credentials, "key")
	testing.expect(t, signed && strings.has_prefix(s3_request_header(request, "Authorization"), "AWS4-HMAC-SHA256 "))
}

@(test)
sigv4_long_secrets_match_independent_fixtures :: proc(t: ^testing.T) {
	scope :: "20130524/us-east-1/s3/aws4_request"
	stamp :: "20130524T000000Z"
	// 60 bytes fills one HMAC block with the AWS4 prefix; 61 is the first hashed key.
	block := strings.repeat("s", 61, context.temp_allocator)
	testing.expect_value(
		t,
		s3_signature(block[:60], "us-east-1", stamp, scope, "canonical"),
		"a159a2a81a2b1a563d1a8e0eef164195e37a5962a918481bbad27c213b638b4d",
	)
	testing.expect_value(
		t,
		s3_signature(block, "us-east-1", stamp, scope, "canonical"),
		"c44850f6e2ef2e3cd7b9f76dbc548ceb42fce4331bf67200b02e4bdc289f524e",
	)
	testing.expect_value(
		t,
		s3_signature(strings.repeat("long-secret-", 20, context.temp_allocator), "us-east-1", stamp, scope, "canonical"),
		"4822689f8f7a40d90b0299bacd19e1082c8d361e7576e476e1f422b08ea0de2d",
	)
}

@(test)
sigv4_leaves_no_secret_in_the_temporary_allocator :: proc(t: ^testing.T) {
	backing: [4096]u8
	arena: mem.Arena
	mem.arena_init(&arena, backing[:])
	short := "fixture-secret-never-copied"
	long := strings.repeat("fixture-long-secret-", 8)
	defer delete(long)
	{
		context.temp_allocator = mem.arena_allocator(&arena)
		for secret in ([]string{short, long}) {
			signature := s3_signature(secret, "us-east-1", "20130524T000000Z", "20130524/us-east-1/s3/aws4_request", "canonical")
			testing.expect_value(t, len(signature), 64)
		}
	}
	testing.expect(t, arena.offset > 0, "signing used the arena")
	testing.expect(t, !bytes.contains(backing[:], transmute([]u8)short))
	testing.expect(t, !bytes.contains(backing[:], transmute([]u8)long[:20]))
}

// The inputs of the OpenSSL fixtures in cmd/tasks/signatures.odin.
S3_REQUEST_FIXTURE_CREDENTIALS :: AWS_Credentials{"AKIAIOSFODNN7EXAMPLE", "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY", "fixture/token+value"}

S3_REQUEST_FIXTURE_CONFIG :: S3_Config {
	bucket = "examplebucket",
	region = "us-east-1",
}

S3_REQUEST_FIXTURE_KEY :: "a b/c+d"

// What a blocking call handed to its executor. Written under aws_test_http_mutex.
S3_Sent :: struct {
	method, url, authorization: string,
}

s3_sent: S3_Sent

s3_sent_record :: proc(method, url: string, headers: []string) {
	s3_sent = {
		method = method,
		url    = strings.clone(url),
	}
	for line in headers {
		if strings.has_prefix(line, "Authorization: ") {
			s3_sent.authorization = strings.clone(line[len("Authorization: "):])
		}
	}
}

s3_sent_http :: proc(request: HTTP_Request) -> ([]u8, network_client.Buffered_HTTP_Result) {
	s3_sent_record(request.method, request.url, request.headers)
	return nil, {status = 200, ok = true}
}

s3_sent_get :: proc(url: string, headers: []string, timeout_ms: i64, bytes_max: int, allocator: mem.Allocator) -> ([]u8, int, S3_Get_Error) {
	s3_sent_record("GET", url, headers)
	return nil, 200, .None
}

@(test)
s3_request_builders_sign_exactly_what_the_blocking_calls_send :: proc(t: ^testing.T) {
	// The blocking calls report to the process-wide observer, which other tests count.
	sync.mutex_lock(&aws_test_http_mutex)
	defer sync.mutex_unlock(&aws_test_http_mutex)
	context.allocator = context.temp_allocator
	now := time.unix(1369353600, 0)
	credentials := S3_REQUEST_FIXTURE_CREDENTIALS
	config := S3_REQUEST_FIXTURE_CONFIG
	payload := "payload"
	cases := []struct {
		method, fixture: string,
	} {
		{"PUT", "ed63c9a16fbbdfc2127f409b79ffce52deaaea62ab8d39048ca5fc8d256e5b26"},
		{"DELETE", "703c365c9e031e61271a08e36dc622e00f12493b12901d9cf725e8f7f01f942b"},
		{"GET", "a8460ec9b92745c9bc1fc7d2ef7a9e8cc186c3ab4079a824db9cdb6183315512"},
	}
	for item in cases {
		request: S3_Request
		built: bool
		s3_sent = {}
		switch item.method {
		case "PUT":
			request, built = s3_put_request(config, credentials, S3_REQUEST_FIXTURE_KEY, transmute([]u8)payload, "", now)
			sent := s3_put(config, credentials, S3_REQUEST_FIXTURE_KEY, transmute([]u8)payload, "", now, s3_sent_http)
			testing.expect(t, sent.ok)
		case "DELETE":
			request, built = s3_delete_request(config, credentials, S3_REQUEST_FIXTURE_KEY, now)
			sent := s3_delete(config, credentials, S3_REQUEST_FIXTURE_KEY, now, s3_sent_http)
			testing.expect(t, sent.ok)
		case "GET":
			request, built = s3_get_request(config, credentials, S3_REQUEST_FIXTURE_KEY, now)
			_, failure := s3_get(config, credentials, S3_REQUEST_FIXTURE_KEY, 8, now, execute = s3_sent_get)
			testing.expect_value(t, failure, S3_Get_Error.None)
		}
		testing.expect(t, built, item.method)
		testing.expect_value(t, request.method, item.method)
		testing.expect_value(t, s3_sent.method, item.method)
		testing.expect_value(t, request.url, s3_sent.url)
		testing.expect_value(t, request.url, "https://examplebucket.s3.us-east-1.amazonaws.com/a%20b/c%2Bd")
		testing.expect_value(t, s3_request_header(request, "Authorization"), s3_sent.authorization)
		testing.expect_value(t, s3_request_signature(s3_sent.authorization), item.fixture)
	}
}

@(test)
s3_head_request_matches_the_independent_fixture :: proc(t: ^testing.T) {
	// The library has no blocking HEAD, so the OpenSSL fixture is the reference.
	request, ok := s3_head_request(S3_REQUEST_FIXTURE_CONFIG, S3_REQUEST_FIXTURE_CREDENTIALS, S3_REQUEST_FIXTURE_KEY, time.unix(1369353600, 0))
	testing.expect(t, ok)
	testing.expect_value(t, request.method, "HEAD")
	testing.expect_value(t, request.url, "https://examplebucket.s3.us-east-1.amazonaws.com/a%20b/c%2Bd")
	testing.expect_value(t, len(request.body), 0)
	testing.expect_value(
		t,
		s3_request_signature(s3_request_header(request, "Authorization")),
		"fdd51dae18ee3b7b2f9a6fe56ccec529798be849c3d8f94093884fec89aaf4d2",
	)
	_, ok = s3_head_request(S3_REQUEST_FIXTURE_CONFIG, {}, S3_REQUEST_FIXTURE_KEY)
	testing.expect(t, !ok)
	_, ok = s3_get_request(S3_REQUEST_FIXTURE_CONFIG, S3_REQUEST_FIXTURE_CREDENTIALS, "")
	testing.expect(t, !ok)
}

@(test)
s3_requests_carry_only_signed_headers_and_authorization :: proc(t: ^testing.T) {
	now := time.unix(1369353600, 0)
	body := "payload"
	put, _ := s3_put_request(S3_REQUEST_FIXTURE_CONFIG, S3_REQUEST_FIXTURE_CREDENTIALS, S3_REQUEST_FIXTURE_KEY, transmute([]u8)body, "text/plain", now)
	get, _ := s3_get_request(S3_REQUEST_FIXTURE_CONFIG, S3_REQUEST_FIXTURE_CREDENTIALS, S3_REQUEST_FIXTURE_KEY, now)
	head, _ := s3_head_request(S3_REQUEST_FIXTURE_CONFIG, S3_REQUEST_FIXTURE_CREDENTIALS, S3_REQUEST_FIXTURE_KEY, now)
	remove, _ := s3_delete_request(S3_REQUEST_FIXTURE_CONFIG, S3_REQUEST_FIXTURE_CREDENTIALS, S3_REQUEST_FIXTURE_KEY, now)
	for request in ([]S3_Request{put, get, head, remove}) {
		testing.expect_value(t, len(request.headers), 5 if request.method == "PUT" else 4)
		for header in request.headers {
			switch header.name {
			case "x-amz-content-sha256", "x-amz-date", "x-amz-security-token", "Authorization":
			case "Content-Type":
				testing.expect_value(t, request.method, "PUT")
			case:
				testing.expectf(t, false, "%s carries %s", request.method, header.name)
			}
			testing.expect(t, header.value != "")
		}
	}
}

@(test)
s3_key_strict_refuses_traversal_and_control_characters :: proc(t: ^testing.T) {
	for key in ([]string{"a", "a/b.txt", "reports/2026/11/file name.pdf", "a..b/c", ".hidden/x", "a/...", "caf\u00e9/\u65e5\u672c"}) {
		testing.expect(t, s3_key_strict(key), key)
	}
	for key in ([]string{"", "/a", "a/", "a//b", ".", "..", "../a", "a/../b", "a/./b", "a/..", "a\nb", "a\x00b", "a\tb", "a\x7fb"}) {
		testing.expectf(t, !s3_key_strict(key), "%q", key)
	}
	longest := strings.repeat("k", S3_KEY_BYTES_MAX + 1)
	defer delete(longest)
	testing.expect(t, s3_key_strict(longest[:S3_KEY_BYTES_MAX]))
	testing.expect(t, !s3_key_strict(longest))
	// The request procs do not apply it: such keys are sent literally, percent-encoded.
	request, ok := s3_get_request(S3_REQUEST_FIXTURE_CONFIG, S3_REQUEST_FIXTURE_CREDENTIALS, "a/../b")
	testing.expect(t, ok)
	testing.expect_value(t, request.url, "https://examplebucket.s3.us-east-1.amazonaws.com/a/../b")
}

@(test)
sigv4_long_secret_path_matches_and_leaves_nothing_in_the_temporary_allocator :: proc(t: ^testing.T) {
	backing: [4096]u8
	arena: mem.Arena
	mem.arena_init(&arena, backing[:])
	secret := strings.repeat("long-secret-", 20)
	defer delete(secret)
	{
		context.temp_allocator = mem.arena_allocator(&arena)
		testing.expect_value(
			t,
			s3_signature(secret, "us-east-1", "20130524T000000Z", "20130524/us-east-1/s3/aws4_request", "canonical"),
			"4822689f8f7a40d90b0299bacd19e1082c8d361e7576e476e1f422b08ea0de2d",
		)
	}
	testing.expect(t, !bytes.contains(backing[:], transmute([]u8)secret[:24]))
}

@(private)
S3_Get_Fixture :: struct {
	t:                        ^testing.T,
	calls, status, body_size: int,
	limit:                    int,
	error:                    S3_Get_Error,
	signed:                   bool,
}

@(private)
s3_get_fixture: ^S3_Get_Fixture

@(private)
s3_get_fixture_execute :: proc(
	url: string,
	headers: []string,
	timeout_ms: i64,
	bytes_max: int,
	allocator: mem.Allocator,
) -> (
	[]u8,
	int,
	S3_Get_Error,
) {
	s := s3_get_fixture
	s.calls += 1
	testing.expect_value(s.t, url, "https://examplebucket.s3.us-east-1.amazonaws.com/a%20b/c%2Bd")
	testing.expect_value(s.t, timeout_ms, i64(S3_GET_TIMEOUT_MS))
	testing.expect_value(s.t, bytes_max, s.limit)
	testing.expect_value(s.t, len(headers), 5)
	expected :=
		"Authorization: AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/" +
		"20130524/us-east-1/s3/aws4_request, SignedHeaders=" +
		"host;x-amz-content-sha256;x-amz-date;x-amz-security-token, Signature=" +
		"a8460ec9b92745c9bc1fc7d2ef7a9e8cc186c3ab4079a824db9cdb6183315512"
	for field in headers {
		if field == expected {
			s.signed = true
		}
	}
	testing.expect(s.t, strings.has_prefix(headers[0], "x-amz-content-sha256: e3b0c442"))
	testing.expect_value(s.t, headers[1], "x-amz-date: 20130524T000000Z")
	testing.expect_value(s.t, headers[3], "x-amz-security-token: fixture/token+value")
	data := make([]u8, s.body_size, allocator)
	for &b in data {
		b = 42
	}
	return data, s.status, s.error
}

@(test)
s3_get_promotes_signed_bounded_owned_reads :: proc(t: ^testing.T) {
	sync.mutex_lock(&aws_test_http_mutex)
	defer sync.mutex_unlock(&aws_test_http_mutex)
	fixture := S3_Get_Fixture {
		t         = t,
		status    = 200,
		body_size = 7,
		limit     = 8,
	}; s3_get_fixture = &fixture
	defer {
		s3_get_fixture = nil
	}

	config := S3_Config {
		bucket = "examplebucket",
		region = "us-east-1",
	}

	credentials := AWS_Credentials {
		"AKIAIOSFODNN7EXAMPLE",
		"wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
		"fixture/token+value",
	}

	body, e := s3_get(
		config,
		credentials,
		"a b/c+d",
		8,
		time.unix(1369353600, 0),
		context.allocator,
		s3_get_fixture_execute,
	)
	defer delete(body)
	testing.expect(t, e == .None && fixture.signed && fixture.calls == 1)
	testing.expect_value(t, len(body), 7)
	testing.expect_value(t, body[0], u8(42))
}

@(test)
s3_get_maps_status_and_releases_every_failed_body :: proc(t: ^testing.T) {
	sync.mutex_lock(&aws_test_http_mutex)
	defer sync.mutex_unlock(&aws_test_http_mutex)
	fixture := S3_Get_Fixture {
		t         = t,
		body_size = 7,
		limit     = 8,
	}; s3_get_fixture = &fixture
	defer {
		s3_get_fixture = nil
	}

	config := S3_Config {
		bucket = "examplebucket",
		region = "us-east-1",
	}

	credentials := AWS_Credentials {
		"AKIAIOSFODNN7EXAMPLE",
		"wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
		"fixture/token+value",
	}

	cases := []struct {
		status: int,
		error:  S3_Get_Error,
	} {
		{0, .Unavailable},
		{301, .Rejected},
		{307, .Rejected},
		{403, .Rejected},
		{404, .Not_Found},
		{408, .Unavailable},
		{429, .Unavailable},
		{503, .Unavailable},
	}

	for item in cases {
		fixture.status = item.status
		body, e := s3_get(
			config,
			credentials,
			"a b/c+d",
			8,
			time.unix(1369353600, 0),
			context.allocator,
			s3_get_fixture_execute,
		)
		testing.expect_value(t, e, item.error)
		testing.expect(t, body == nil)
	}

	// The native executor stops reading an error body above bytes_max and reports
	// Too_Large with the status; the status decides.
	fixture.error = .Too_Large
	fixture.body_size = 0
	for item in cases {
		if item.status == 0 {
			continue
		}
		fixture.status = item.status
		body, e := s3_get(
			config,
			credentials,
			"a b/c+d",
			8,
			time.unix(1369353600, 0),
			context.allocator,
			s3_get_fixture_execute,
		)
		testing.expect_value(t, e, item.error)
		testing.expect(t, body == nil)
	}
	fixture.error = .None
	fixture.body_size = 7

	fixture.status = 200
	fixture.body_size = 9
	body, e := s3_get(
		config,
		credentials,
		"a b/c+d",
		8,
		time.unix(1369353600, 0),
		context.allocator,
		s3_get_fixture_execute,
	)
	testing.expect(t, body == nil && e == .Too_Large)
	fixture.body_size = 7
	fixture.error = .Unavailable
	body, e = s3_get(
		config,
		credentials,
		"a b/c+d",
		8,
		time.unix(1369353600, 0),
		context.allocator,
		s3_get_fixture_execute,
	)
	testing.expect(t, body == nil && e == .Unavailable)
	calls := fixture.calls

	for bound in ([]int{-1, S3_GET_BYTES_MAX + 1}) {
		body, e = s3_get(config, credentials, "a b/c+d", bound, execute = s3_get_fixture_execute)
		testing.expect(t, body == nil && e == .Invalid_Input)
	}

	_, e = s3_get(config, {}, "key", 8, execute = s3_get_fixture_execute)
	testing.expect_value(t, e, .Invalid_Input)
	_, e = s3_get(config, credentials, "", 8, execute = s3_get_fixture_execute)
	testing.expect_value(t, e, .Invalid_Input)
	testing.expect_value(t, fixture.calls, calls)
}

@(test)
s3_get_native_rejects_invalid_public_bounds_and_header_injection :: proc(t: ^testing.T) {
	for item in ([]struct {
			bound:   int,
			timeout: i64,
		}{{-1, 1000}, {S3_GET_BYTES_MAX + 1, 1000}, {1, 0}, {1, S3_GET_TIMEOUT_MS + 1}}) {
		body, status, e := s3_get_native("invalid-url", nil, item.timeout, item.bound, context.allocator)
		testing.expect(t, body == nil && status == 0 && e == .Invalid_Input)
	}

	for header in ([]string{"missing colon", ": empty-name", "x: value\r\nInjected: yes", "x: value\x00"}) {
		body, status, e := s3_get_native("invalid-url", {header}, 1000, 8, context.allocator)
		testing.expect(t, body == nil && status == 0 && e == .Invalid_Input)
	}

	headers: [S3_GET_HEADERS_MAX + 1]string
	body, status, e := s3_get_native("invalid-url", headers[:], 1000, 8, context.allocator)
	testing.expect(t, body == nil && status == 0 && e == .Invalid_Input)
	fmt.println("S3 GET failure bodies released by the caller allocator; native input rejected before I/O")
}

@(test)
s3_get_native_explicit_platform_trust_survives_config_preflight :: proc(t: ^testing.T) {
	anchor: [1]^x509.Certificate
	config := s3_get_native_config(1000, 0, anchor[:0])
	settings := config.tls
	settings.server_name = "s3.us-east-1.amazonaws.com"
	testing.expect_value(t, tls.config_validate(settings), nil)
	testing.expect(t, raw_data(config.tls.root_cas) != nil && len(config.tls.root_cas) == 0)
	testing.expect_value(t, config.max_body_size, 1)
	testing.expect(t, !config.allow_http && config.max_redirects == 0 && !config.http3)
}

S3_Observer_Record :: struct {
	calls, failures: int,
}

// Written only by tests that hold aws_test_http_mutex.
s3_observer_record: S3_Observer_Record

s3_observer_test_observe :: proc(started: time.Tick, ok: bool) {
	assert(time.tick_since(started) >= 0)
	s3_observer_record.calls += 1
	if !ok {
		s3_observer_record.failures += 1
	}
}

@(test)
s3_observer_reports_sent_requests_and_their_outcome :: proc(t: ^testing.T) {
	sync.mutex_lock(&aws_test_http_mutex)
	defer sync.mutex_unlock(&aws_test_http_mutex)
	s3_observer_record = {}
	s3_observer_set(s3_observer_test_observe)
	defer s3_observer_set(nil)

	credentials := AWS_Credentials{"fixture-key", "fixture-secret", "fixture-token"}
	config := S3_Config{bucket = "examplebucket", region = "us-east-1"}
	state := AWS_Test_HTTP {
		t      = t,
		method = "DELETE",
		url    = "https://examplebucket.s3.us-east-1.amazonaws.com/a%20b",
		status = 204,
		ok     = true,
	}
	aws_test_http_state = &state
	defer aws_test_http_state = nil
	result := s3_delete(config, credentials, "a b", http_execute = aws_test_http)
	testing.expect(t, result.ok)
	testing.expect_value(t, s3_observer_record, S3_Observer_Record{calls = 1})

	state.status = 503
	state.ok = false
	result = s3_delete(config, credentials, "a b", http_execute = aws_test_http)
	testing.expect(t, !result.ok)
	testing.expect_value(t, s3_observer_record, S3_Observer_Record{calls = 2, failures = 1})

	result = s3_delete(config, {}, "a b", http_execute = aws_test_http)
	testing.expect(t, !result.ok && state.calls == 2, "invalid credentials never reach HTTP")
	testing.expect_value(t, s3_observer_record.calls, 2)
}

@(test)
s3_observer_counts_a_missing_object_as_an_answer :: proc(t: ^testing.T) {
	sync.mutex_lock(&aws_test_http_mutex)
	defer sync.mutex_unlock(&aws_test_http_mutex)
	s3_observer_record = {}
	s3_observer_set(s3_observer_test_observe)
	defer s3_observer_set(nil)

	fixture := S3_Get_Fixture{t = t, body_size = 7, limit = 8}
	s3_get_fixture = &fixture
	defer s3_get_fixture = nil
	config := S3_Config{bucket = "examplebucket", region = "us-east-1"}
	credentials := AWS_Credentials {
		"AKIAIOSFODNN7EXAMPLE",
		"wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
		"fixture/token+value",
	}
	cases := []struct {
		status:   int,
		error:    S3_Get_Error,
		failures: int,
	}{{200, .None, 0}, {404, .Not_Found, 0}, {403, .Rejected, 1}, {503, .Unavailable, 2}}
	for item, index in cases {
		fixture.status = item.status
		body, e := s3_get(
			config,
			credentials,
			"a b/c+d",
			8,
			time.unix(1369353600, 0),
			context.allocator,
			s3_get_fixture_execute,
		)
		delete(body)
		testing.expect_value(t, e, item.error)
		testing.expect_value(t, s3_observer_record.calls, index + 1)
		testing.expect_value(t, s3_observer_record.failures, item.failures)
	}

	_, e := s3_get(config, credentials, "", 8, allocator = context.allocator, execute = s3_get_fixture_execute)
	testing.expect_value(t, e, S3_Get_Error.Invalid_Input)
	testing.expect_value(t, s3_observer_record.calls, len(cases))

	// A 404 whose body exceeded bytes_max is still an answer, not a failure.
	failures := s3_observer_record.failures
	fixture.error = .Too_Large
	fixture.status = 404
	body, e2 := s3_get(
		config,
		credentials,
		"a b/c+d",
		8,
		time.unix(1369353600, 0),
		context.allocator,
		s3_get_fixture_execute,
	)
	fixture.error = .None
	testing.expect(t, body == nil)
	testing.expect_value(t, e2, S3_Get_Error.Not_Found)
	testing.expect_value(t, s3_observer_record.calls, len(cases) + 1)
	testing.expect_value(t, s3_observer_record.failures, failures)
}

@(test)
s3_endpoint_is_a_host_and_port_only :: proc(t: ^testing.T) {
	for endpoint in ([]string{"https://example.com", "https://127.0.0.1:9000", "https://[::1]:9000", "https://s3.internal-zone.example"}) {
		testing.expect_value(t, s3_config_error({bucket = "examplebucket", region = "us-east-1", endpoint = endpoint}), "")
	}
	for endpoint in ([]string {
			"http://example.com",
			"https://",
			"https://example.com/path",
			"https://example.com?x",
			"https://user@example.com",
			"https://exa mple.com",
			"https://example.com\\evil",
			"https://example.com\t",
			"https://example.com\x00",
			"https://example.com#f",
			"https://exämple.com",
		}) {
		testing.expect(t, s3_config_error({bucket = "examplebucket", region = "us-east-1", endpoint = endpoint}) != "", endpoint)
	}
}

@(test)
s3_get_refuses_a_private_ca_on_the_native_executor :: proc(t: ^testing.T) {
	// The blocking calls report to the process-wide observer, which other tests count.
	sync.mutex_lock(&aws_test_http_mutex)
	defer sync.mutex_unlock(&aws_test_http_mutex)
	context.allocator = context.temp_allocator
	config := S3_REQUEST_FIXTURE_CONFIG
	config.ca_file = "private-ca.pem"
	// Refused before any connection: the native path would trust the system roots.
	_, native := s3_get(config, S3_REQUEST_FIXTURE_CREDENTIALS, "key", 8)
	testing.expect_value(t, native, S3_Get_Error.Invalid_Input)
	// An injected executor owns its own trust.
	s3_sent = {}
	_, injected := s3_get(config, S3_REQUEST_FIXTURE_CREDENTIALS, "key", 8, execute = s3_sent_get)
	testing.expect_value(t, injected, S3_Get_Error.None)
	testing.expect_value(t, s3_sent.method, "GET")
}

@(test)
signing_leaves_no_secret_in_the_temporary_allocator_for_any_operation :: proc(t: ^testing.T) {
	backing := make([]u8, 64 * 1024)
	defer delete(backing)
	arena: mem.Arena
	mem.arena_init(&arena, backing)
	secret := "fixture-secret-that-must-not-be-copied"
	credentials := AWS_Credentials{"fixture-key", secret, ""}
	{
		context.temp_allocator = mem.arena_allocator(&arena)
		body := "payload"
		now := time.unix(1369353600, 0)
		_, put := s3_put_request(S3_REQUEST_FIXTURE_CONFIG, credentials, "key", transmute([]u8)body, "text/plain", now)
		_, get := s3_get_request(S3_REQUEST_FIXTURE_CONFIG, credentials, "key", now)
		_, head := s3_head_request(S3_REQUEST_FIXTURE_CONFIG, credentials, "key", now)
		_, remove := s3_delete_request(S3_REQUEST_FIXTURE_CONFIG, credentials, "key", now)
		_, url := s3_download_url(S3_REQUEST_FIXTURE_CONFIG, credentials, "key", 60, now)
		headers := ses_headers("us-east-1", credentials, "email.us-east-1.amazonaws.com", "20130524T000000Z", transmute([]u8)body)
		testing.expect(t, put && get && head && remove && url && len(headers) == 3)
	}
	testing.expect(t, arena.offset > 0)
	testing.expect(t, !strings.contains(string(backing), secret))
	testing.expect(t, !strings.contains(string(backing), secret[:16]))
}

@(test)
s3_endpoint_is_signed_as_written_and_decides_the_bucket_position :: proc(t: ^testing.T) {
	for endpoint in ([]string {
			"https://example.com:443",
			"https://Example.com",
			"https://example.com:0",
			"https://example.com:65536",
			"https://example.com:",
			"https://example.com:08",
			"https://a:b:c",
			"https://:9000",
			"https://.example.com",
			"https://-example.com",
			"https://a..b",
			"https://[::1",
			"https://[]:9000",
			"https://[::1]9000",
			"https://[::1]:443",
		}) {
		testing.expect(t, s3_config_error({bucket = "examplebucket", region = "us-east-1", endpoint = endpoint}) != "", endpoint)
	}
	for endpoint in ([]string{"https://example.com:8443", "https://example.com:1", "https://example.com:65535", "https://[::1]", "https://[fe80::1]:9000"}) {
		testing.expect_value(t, s3_config_error({bucket = "examplebucket", region = "us-east-1", endpoint = endpoint}), "")
	}

	credentials := S3_REQUEST_FIXTURE_CREDENTIALS
	dotted := S3_Config {
		bucket = "assets.example.com",
		region = "us-east-1",
	}
	aws, _ := s3_get_request(dotted, credentials, "a.txt")
	testing.expect_value(t, aws.url, "https://s3.us-east-1.amazonaws.com/assets.example.com/a.txt")
	dotted.endpoint = "https://assets.example.com"
	own, _ := s3_get_request(dotted, credentials, "a.txt")
	testing.expect_value(t, own.url, "https://assets.example.com/a.txt")
	dotted.endpoint = "https://store.internal:9000"
	dotted.path_style = true
	store, _ := s3_get_request(dotted, credentials, "a.txt")
	testing.expect_value(t, store.url, "https://store.internal:9000/assets.example.com/a.txt")
}

@(test)
a_file_upload_without_its_digest_is_not_sent :: proc(t: ^testing.T) {
	sync.mutex_lock(&aws_test_http_mutex)
	defer sync.mutex_unlock(&aws_test_http_mutex)
	context.allocator = context.temp_allocator
	file, error := os.open("/dev/null")
	if !testing.expect(t, error == nil) {
		return
	}
	defer os.close(file)
	s3_sent = {}
	result := s3_object_request_at(
		S3_REQUEST_FIXTURE_CONFIG,
		S3_REQUEST_FIXTURE_CREDENTIALS,
		"PUT",
		"key",
		nil,
		"",
		time.unix(1369353600, 0),
		file,
		7,
		http_execute = s3_sent_http,
	)
	testing.expect(t, !result.ok)
	testing.expect_value(t, s3_sent.method, "")
}

S3_Validation_Count :: struct {
	calls:       int,
	upload_size: i64,
	digest:      string,
}

// Written only by tests that hold aws_test_http_mutex.
s3_validation_count: S3_Validation_Count

s3_validation_http :: proc(request: HTTP_Request) -> ([]u8, network_client.Buffered_HTTP_Result) {
	s3_validation_count.calls += 1
	s3_validation_count.upload_size = request.upload_size
	for header in request.headers {
		if strings.has_prefix(header, "x-amz-content-sha256: ") {
			s3_validation_count.digest = strings.clone(header[len("x-amz-content-sha256: "):], context.temp_allocator)
		}
	}
	return nil, {status = 200, ok = true, transport_ok = true}
}

@(test)
s3_config_refuses_buckets_and_regions_that_would_change_the_host :: proc(t: ^testing.T) {
	sync.mutex_lock(&aws_test_http_mutex)
	defer sync.mutex_unlock(&aws_test_http_mutex)
	context.allocator = context.temp_allocator
	long_ok := strings.repeat("a", 63)
	long_bad := strings.repeat("a", 64)
	required :: "S3 requires AWS_S3_BUCKET and AWS_REGION"
	for item in ([]struct {
			bucket, region, expected: string,
		} {
			{"", "us-east-1", ""},
			{"abc", "us-east-1", ""},
			{long_ok, "us-east-1", ""},
			{"my-bucket.v2", "us-east-1", ""},
			{"ab", "us-east-1", required},
			{long_bad, "us-east-1", required},
			{"abc", "", required},
			{"Abc", "us-east-1", "Invalid S3 bucket name"},
			{"my_bucket", "us-east-1", "Invalid S3 bucket name"},
			{"my/bucket", "us-east-1", "Invalid S3 bucket name"},
			{"my bucket", "us-east-1", "Invalid S3 bucket name"},
			{"abc", "US-EAST-1", "Invalid AWS region"},
			{"abc", "us.east.1", "Invalid AWS region"},
			{"abc", "us-east-1/", "Invalid AWS region"},
			{"abc", "eu_west_1", "Invalid AWS region"},
		}) {
		testing.expectf(
			t,
			s3_config_error({bucket = item.bucket, region = item.region}) == item.expected,
			"%q %q",
			item.bucket,
			item.region,
		)
	}

	s3_validation_count = {}
	result := s3_put(
		{bucket = "abc", region = "us-east-1/"},
		AWS_Credentials{"fixture-key", "fixture-secret", ""},
		"key",
		nil,
		"text/plain",
		http_execute = s3_validation_http,
	)
	testing.expect_value(t, result, S3_Result{error = .Invalid_Input, effect = .Not_Sent})
	testing.expect_value(t, s3_validation_count.calls, 0)
}

@(test)
s3_put_file_hashes_files_larger_than_its_buffer :: proc(t: ^testing.T) {
	sync.mutex_lock(&aws_test_http_mutex)
	defer sync.mutex_unlock(&aws_test_http_mutex)
	s3_observer_record = {}
	s3_observer_set(s3_observer_test_observe)
	defer s3_observer_set(nil)

	SIZE :: 200000
	data := make([]byte, SIZE)
	defer delete(data)
	for &item, index in data {
		item = byte(index % 251)
	}
	digest: [32]byte
	hash.hash(.SHA256, data, digest[:])
	expected := hex.encode(digest[:])
	defer delete(expected)

	directory, error := os.make_directory_temp("", "aws-upload-*", context.allocator)
	if !testing.expect(t, error == nil) {
		return
	}
	defer delete(directory)
	defer os.remove(directory)
	path := fmt.aprintf("%s/body", directory)
	defer delete(path)
	defer os.remove(path)
	testing.expect(t, os.write_entire_file(path, data) == nil)

	credentials := AWS_Credentials{"fixture-key", "fixture-secret", ""}
	config := S3_Config{bucket = "examplebucket", region = "us-east-1"}
	s3_validation_count = {}
	result := s3_put_file(config, credentials, "big", path, "text/plain", http_execute = s3_validation_http)
	testing.expect(t, result.ok)
	testing.expect_value(t, s3_validation_count.calls, 1)
	testing.expect_value(t, s3_validation_count.upload_size, i64(SIZE))
	testing.expect_value(t, s3_validation_count.digest, string(expected))
	testing.expect_value(t, s3_observer_record.calls, 1)

	s3_validation_count = {}
	result = s3_put_file(config, credentials, "big", "/nonexistent/file", "text/plain", http_execute = s3_validation_http)
	testing.expect_value(t, result, S3_Result{error = .Invalid_Input, effect = .Not_Sent})
	testing.expect_value(t, s3_validation_count.calls, 0)
	testing.expect_value(t, s3_observer_record.calls, 1)
}

@(test)
request_builders_refuse_a_token_with_a_space :: proc(t: ^testing.T) {
	config := S3_Config{bucket = "examplebucket", region = "us-east-1"}
	credentials := AWS_Credentials{"fixture-key", "fixture-secret", "fixture-token "}
	_, get_ok := s3_get_request(config, credentials, "key")
	testing.expect(t, !get_ok)
	_, put_ok := s3_put_request(config, credentials, "key", nil, "text/plain")
	testing.expect(t, !put_ok)
}

S3_Timeout_Probe :: struct {
	timeout_ms: i64,
	calls:      int,
}

s3_timeout_probe: S3_Timeout_Probe

s3_timeout_http :: proc(request: HTTP_Request) -> ([]u8, network_client.Buffered_HTTP_Result) {
	s3_timeout_probe.calls += 1
	s3_timeout_probe.timeout_ms = request.timeout_ms
	return nil, {status = 200, ok = true, transport_ok = true}
}

@(test)
put_timeout_follows_body_size :: proc(t: ^testing.T) {
	// The blocking calls report to the process-wide observer, which other tests count.
	sync.mutex_lock(&aws_test_http_mutex)
	defer sync.mutex_unlock(&aws_test_http_mutex)
	config := S3_Config {
		bucket = "examplebucket",
		region = "us-east-1",
	}
	credentials := AWS_Credentials{"fixture-key", "fixture-secret", ""}
	sizes := []struct {
		bytes:   int,
		timeout: i64,
	}{{7, 15000}, {1 << 20, 16000}, {64 << 20, 79000}, {200 << 20, 120000}}
	for size in sizes {
		body := make([]u8, size.bytes)
		s3_timeout_probe = {}
		result := s3_put(config, credentials, "key", body, "text/plain", http_execute = s3_timeout_http)
		delete(body)
		testing.expect(t, result.ok && s3_timeout_probe.calls == 1)
		testing.expect_value(t, s3_timeout_probe.timeout_ms, size.timeout)
	}

	s3_timeout_probe = {}
	result := s3_delete(config, credentials, "key", http_execute = s3_timeout_http)
	testing.expect(t, result.ok && s3_timeout_probe.calls == 1)
	testing.expect_value(t, s3_timeout_probe.timeout_ms, 15000)

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
	s3_timeout_probe = {}
	result = s3_put_file(config, credentials, "key", path, "text/plain", http_execute = s3_timeout_http)
	testing.expect(t, result.ok && s3_timeout_probe.calls == 1)
	testing.expect_value(t, s3_timeout_probe.timeout_ms, 120000)
}

S3_Outcome_Fixture :: struct {
	calls:  int,
	result: network_client.Buffered_HTTP_Result,
}

// Written only by tests that hold aws_test_http_mutex.
s3_outcome_fixture: ^S3_Outcome_Fixture

s3_outcome_http :: proc(request: HTTP_Request) -> ([]u8, network_client.Buffered_HTTP_Result) {
	s3_outcome_fixture.calls += 1
	return nil, s3_outcome_fixture.result
}

@(test)
put_and_delete_report_typed_outcomes :: proc(t: ^testing.T) {
	sync.mutex_lock(&aws_test_http_mutex)
	defer sync.mutex_unlock(&aws_test_http_mutex)
	credentials := AWS_Credentials{"fixture-key", "fixture-secret", ""}
	config := S3_Config{bucket = "examplebucket", region = "us-east-1"}
	fixture: S3_Outcome_Fixture
	s3_outcome_fixture = &fixture
	defer s3_outcome_fixture = nil

	Case :: struct {
		answer: network_client.Buffered_HTTP_Result,
		want:   S3_Result,
	}
	cases := []Case {
		{{status = 200, ok = true, transport_ok = true}, {200, true, .None, .Response_Received}},
		{{status = 403, transport_ok = true}, {403, false, .Rejected, .Response_Received}},
		{{status = 404, transport_ok = true}, {404, false, .Not_Found, .Response_Received}},
		{{status = 503, transport_ok = true}, {503, false, .Unavailable, .Response_Received}},
		{{status = 429, transport_ok = true}, {429, false, .Unavailable, .Response_Received}},
		{{status = 200, ok = false}, {200, false, .Unavailable, .Response_Received}},
		{{status = 0, error = {kind = .IO_Failed, write_effect = .Unknown}}, {0, false, .Unavailable, .Unknown}},
		{{status = 0, error = {kind = .Invalid_Config, write_effect = .Not_Sent}}, {0, false, .Unavailable, .Not_Sent}},
	}
	for c in cases {
		fixture.result = c.answer
		before := fixture.calls
		got := s3_put(config, credentials, "a b", nil, "text/plain", http_execute = s3_outcome_http)
		testing.expect_value(t, got, c.want)
		testing.expect_value(t, fixture.calls, before + 1)
		got = s3_delete(config, credentials, "a b", http_execute = s3_outcome_http)
		testing.expect_value(t, got, c.want)
	}

	calls := fixture.calls
	got := s3_put(config, credentials, "", nil, "", http_execute = s3_outcome_http)
	testing.expect_value(t, got, S3_Result{error = .Invalid_Input, effect = .Not_Sent})
	testing.expect_value(t, fixture.calls, calls)
}

@(test)
put_file_reports_a_missing_file_as_invalid_input :: proc(t: ^testing.T) {
	sync.mutex_lock(&aws_test_http_mutex)
	defer sync.mutex_unlock(&aws_test_http_mutex)
	s3_observer_record = {}
	s3_observer_set(s3_observer_test_observe)
	defer s3_observer_set(nil)
	credentials := AWS_Credentials{"fixture-key", "fixture-secret", ""}
	config := S3_Config{bucket = "examplebucket", region = "us-east-1"}
	fixture: S3_Outcome_Fixture
	s3_outcome_fixture = &fixture
	defer s3_outcome_fixture = nil

	got := s3_put_file(
		config,
		credentials,
		"a b",
		"/nonexistent-aws-test-directory/missing",
		"text/plain",
		http_execute = s3_outcome_http,
	)
	testing.expect_value(t, got, S3_Result{error = .Invalid_Input, effect = .Not_Sent})
	testing.expect_value(t, fixture.calls, 0)
	testing.expect_value(t, s3_observer_record.calls, 0)
}

@(test)
status_classifier_matches_the_documented_rule :: proc(t: ^testing.T) {
	Case :: struct {
		status: int,
		want:   S3_Error,
	}
	cases := []Case {
		{0, .Unavailable},
		{200, .None},
		{204, .None},
		{299, .None},
		{301, .Rejected},
		{400, .Rejected},
		{403, .Rejected},
		{404, .Not_Found},
		{408, .Unavailable},
		{409, .Rejected},
		{429, .Unavailable},
		{500, .Unavailable},
		{503, .Unavailable},
		{599, .Unavailable},
	}
	for c in cases {
		testing.expect_value(t, s3_status_error(c.status), c.want)
	}
}

// One signed request costs the header array, the line slice and one text buffer
// for the url and every header value; the canonical request is never built.
@(test)
signing_one_request_allocates_little :: proc(t: ^testing.T) {
	backing := make([]u8, 64 * 1024)
	defer delete(backing)
	arena: mem.Arena
	mem.arena_init(&arena, backing)
	tracking: mem.Tracking_Allocator
	mem.tracking_allocator_init(&tracking, mem.arena_allocator(&arena))
	defer mem.tracking_allocator_destroy(&tracking)
	credentials := AWS_Credentials{"fixture-key", "fixture-secret", strings.repeat("t", 1024, context.allocator)}
	defer delete(credentials.session_token)
	body := "payload"
	{
		context.temp_allocator = mem.tracking_allocator(&tracking)
		_, ok := s3_put_request({bucket = "examplebucket", region = "us-east-1"}, credentials, "a b/c", transmute([]u8)body, "text/plain", time.unix(1369353600, 0))
		testing.expect(t, ok)
	}
	testing.expectf(t, tracking.total_allocation_count <= 4, "%d allocations", tracking.total_allocation_count)
}

@(test)
signing_copies_the_session_token_once :: proc(t: ^testing.T) {
	backing := make([]u8, 64 * 1024)
	defer delete(backing)
	arena: mem.Arena
	mem.arena_init(&arena, backing)
	token := strings.repeat("Q", 300, context.allocator)
	defer delete(token)
	credentials := AWS_Credentials{"fixture-key", "fixture-secret", token}
	body := "payload"
	{
		context.temp_allocator = mem.arena_allocator(&arena)
		request, ok := s3_put_request(S3_REQUEST_FIXTURE_CONFIG, credentials, "key", transmute([]u8)body, "text/plain", time.unix(1369353600, 0))
		testing.expect(t, ok)
		testing.expect_value(t, s3_request_header(request, "x-amz-security-token"), token)
	}
	testing.expect_value(t, strings.count(string(backing[:arena.offset]), token), 1)
}
