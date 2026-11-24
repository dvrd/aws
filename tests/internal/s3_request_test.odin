package aws

import "core:bytes"
import "core:mem"
import "core:strings"
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
