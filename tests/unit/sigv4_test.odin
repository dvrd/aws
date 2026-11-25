package aws

import "core:fmt"
import "core:testing"

// Unit tests of src/sigv4.odin: the streaming signer against the string signer
// and the botocore references it replaces.

@(test)
sigv4_streaming_matches_the_string_signer :: proc(t: ^testing.T) {
	stamp :: "20130524T000000Z"
	Case :: struct {
		secret, method, path, payload_hash, service, region: string,
		headers:                                             []Sigv4_Header,
		signature:                                           string, // from tests/conformance/botocore_test.odin
	}
	ses_payload := "{\"fixture\":true}"
	cases := []Case {
		{
			"secret/with+chars==",
			"POST",
			"/v2/email/outbound-emails",
			s3_sha256(transmute([]u8)ses_payload),
			"ses",
			"eu-west-3",
			{
				{"content-type", "application/json"},
				{"host", "email.eu-west-3.amazonaws.com"},
				{"x-amz-date", stamp},
				{"x-amz-security-token", "fixture/token+value=="},
			},
			"d9732a40afd3cd062394612eb73325dd6a2be4245b54634dfb98a8c13c90bb83",
		},
		{
			"LLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLL",
			"GET",
			"/a%20b/c%2Bd",
			EMPTY_PAYLOAD_SHA256,
			"s3",
			"us-east-1",
			{
				{"host", "examplebucket.s3.us-east-1.amazonaws.com"},
				{"x-amz-content-sha256", EMPTY_PAYLOAD_SHA256},
				{"x-amz-date", stamp},
				{"x-amz-security-token", "tok"},
			},
			"e86c8a119cef424b568b77322eaf533822b96fb18905b21f3fb39ff84a1b733a",
		},
		{
			"wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
			"PUT",
			"/examplebucket/a",
			s3_sha256(transmute([]u8)string("payload-a")),
			"s3",
			"eu-west-3",
			{
				{"host", "s3.eu-west-3.amazonaws.com"},
				{"x-amz-content-sha256", s3_sha256(transmute([]u8)string("payload-a"))},
				{"x-amz-date", stamp},
			},
			"b7f3777b5aa93936456e6fc2de35d3a91c8d51d48dc55b9989d6021729354e74",
		},
	}
	for c in cases {
		canonical_headers, signed: string
		for header, i in c.headers {
			canonical_headers = fmt.tprintf("%s%s:%s\n", canonical_headers, header.name, header.value)
			signed = fmt.tprintf("%s%s%s", signed, ";" if i > 0 else "", header.name)
		}
		canonical := fmt.tprintf("%s\n%s\n\n%s\n%s\n%s", c.method, c.path, canonical_headers, signed, c.payload_hash)
		scope := fmt.tprintf("%s/%s/%s/aws4_request", stamp[:8], c.region, c.service)
		expected := s3_signature(c.secret, c.region, stamp, scope, canonical, c.service)

		signature: [64]u8
		sigv4_sign(
			c.secret,
			{
				service = c.service,
				region = c.region,
				method = c.method,
				path = c.path,
				headers = c.headers,
				payload_hash = c.payload_hash,
				stamp = stamp,
			},
			&signature,
		)
		testing.expect_value(t, string(signature[:]), expected)
		testing.expect_value(t, expected, c.signature)
	}
}

@(test)
empty_payload_constant_is_the_sha256_of_nothing :: proc(t: ^testing.T) {
	testing.expect_value(t, s3_sha256(nil), EMPTY_PAYLOAD_SHA256)
}

@(test)
sigv4_refuses_a_stamp_without_a_date :: proc(t: ^testing.T) {
	signature: [64]u8
	signature[0] = 'x'
	sigv4_sign("secret", {service = "s3", region = "us-east-1", method = "GET", path = "/", stamp = "2013"}, &signature)
	testing.expect_value(t, signature, [64]u8{})
}
