package aws

import "core:fmt"
import "core:mem"
import "core:strings"
import "core:sync"
import "core:testing"
import "core:time"
import tls "shared:async/tls"
import x509 "core:crypto/x509"

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
