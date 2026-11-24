package aws

import network_client "shared:surf"
import "core:bytes"
import "core:mem"
import "core:strings"
import "core:sync"
import "core:testing"
import "core:time"

s3_request_header :: proc(request: S3_Request, name: string) -> string {
	for header in request.headers {
		if header.name == name {
			return header.value
		}
	}
	return ""
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

s3_request_signature :: proc(authorization: string) -> string {
	marker :: "Signature="
	at := strings.index(authorization, marker)
	if at < 0 {
		return ""
	}
	return authorization[at + len(marker):]
}

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
