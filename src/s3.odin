package aws

import network_client "shared:surf"
import "core:crypto/hash"
import "core:crypto/hmac"
import "core:encoding/hex"
import "core:fmt"
import "core:io"
import "core:os"
import "core:strings"
import "core:sync"
import "core:time"
import x509 "core:crypto/x509"
import "core:mem"

S3_Config :: struct {
	bucket, region:    string,
	endpoint, ca_file: string, // Optional HTTPS endpoint/private CA for isolated peers.
	path_style:        bool,
}

AWS_Credentials :: struct {
	access_key, secret_key, session_token: string,
}

// Optional process-wide observer of S3 object requests (put, delete and get) for
// application metrics. started is the tick taken before the request was sent; ok
// is false when S3 gave no expected answer. A GET answered 404 is ok: a missing
// object is a valid answer, not a provider failure. Requests rejected before
// sending are not observed. It runs on the requesting thread and must not block.
S3_Observer :: #type proc(started: time.Tick, ok: bool)

s3_observer: S3_Observer

// Installs the S3 observer; nil removes it. Install it before requests start.
s3_observer_set :: proc(observer: S3_Observer) {
	sync.atomic_store(&s3_observer, observer)
}

s3_observe :: proc(started: time.Tick, ok: bool) {
	observer := sync.atomic_load(&s3_observer)
	if observer != nil {
		observer(started, ok)
	}
}

S3_Result :: network_client.Buffered_HTTP_Result

load_s3_config :: proc() -> S3_Config {
	config := S3_Config {
		bucket = os.get_env("AWS_S3_BUCKET", context.allocator),
		region = os.get_env("AWS_REGION", context.allocator),
	}

	if config.region == "" {
		config.region = os.get_env("AWS_DEFAULT_REGION", context.allocator)
	}

	return config
}

s3_config_error :: proc(config: S3_Config) -> string {
	if config.bucket == "" {
		return ""
	}

	if len(config.bucket) < 3 || len(config.bucket) > 63 || config.region == "" {
		return "S3 requires AWS_S3_BUCKET and AWS_REGION"
	}

	for ch in config.bucket {
		if !is_lower(ch) && !is_digit(ch) && ch != '-' && ch != '.' {
			return "Invalid S3 bucket name"
		}
	}

	for ch in config.region {
		if !region_char_valid(ch) {
			return "Invalid AWS region"
		}
	}

	if config.endpoint != "" {
		if !strings.has_prefix(config.endpoint, "https://") ||
		   strings.contains_any(config.endpoint[8:], "/?#@\r\n") ||
		   len(config.endpoint) <= 8 {
			return "S3 endpoint must be an HTTPS origin"
		}
	}

	return ""
}

signing_time :: proc(now: time.Time) -> time.Time {
	if now == (time.Time{}) {
		return time.now()
	}

	return now
}

region_char_valid :: proc(ch: rune) -> bool {
	return is_lower(ch) || is_digit(ch) || ch == '-'
}

// Keys are sent as given: "../" and other path segments reach S3 literally.
// Validating a key that comes from outside is the caller's job, and s3_key_strict
// is a check a caller can opt into.

// Blocks the calling thread until S3 answers or 15 seconds pass. Not for an
// event-loop thread: build the request with s3_put_request and send it through
// the server's own transport instead.
// now is the signing time; the zero time means time.now().
s3_put :: proc(
	config: S3_Config,
	credentials: AWS_Credentials,
	key: string,
	body: []byte,
	content_type: string,
	now: time.Time = {},
	http_execute: HTTP_Execute = http_execute_default,
) -> S3_Result {
	return s3_object_request_at(
		config,
		credentials,
		"PUT",
		key,
		body,
		content_type,
		signing_time(now),
		http_execute = http_execute,
	)
}

// Stream a file with a fixed buffer, avoiding an archive-sized allocation.
// Blocks the calling thread while it hashes the file and then for up to 120
// seconds of upload. Not for an event-loop thread, and it has no request builder:
// run it on a worker.
s3_put_file :: proc(
	config: S3_Config,
	credentials: AWS_Credentials,
	key, path, content_type: string,
	now: time.Time = {},
	http_execute: HTTP_Execute = http_execute_default,
) -> S3_Result {
	file, error := os.open(path)
	if error != nil {
		return {}
	}
	defer os.close(file)
	size, size_error := os.file_size(file)
	if size_error != nil {
		return {}
	}
	hasher: hash.Context
	hash.init(&hasher, .SHA256)
	buffer: [64 * 1024]byte
	for {
		n, read_error := os.read(file, buffer[:])
		if read_error != nil && read_error != io.Error.EOF {
			return {}
		}
		if n == 0 {
			break
		}
		hash.update(&hasher, buffer[:n])
	}
	digest: [32]byte
	hash.final(&hasher, digest[:])
	if _, seek_error := os.seek(file, 0, .Start); seek_error != nil {
		return {}
	}
	return s3_object_request_at(
		config,
		credentials,
		"PUT",
		key,
		nil,
		content_type,
		signing_time(now),
		file,
		size,
		string(hex.encode(digest[:], allocator = context.temp_allocator)),
		http_execute = http_execute,
	)
}

// Blocks the calling thread until S3 answers or 15 seconds pass. Not for an
// event-loop thread: use s3_delete_request there.
s3_delete :: proc(
	config: S3_Config,
	credentials: AWS_Credentials,
	key: string,
	now: time.Time = {},
	http_execute: HTTP_Execute = http_execute_default,
) -> S3_Result {
	return s3_object_request_at(config, credentials, "DELETE", key, nil, "", signing_time(now), http_execute = http_execute)
}

s3_object_request_at :: proc(
	config: S3_Config,
	credentials: AWS_Credentials,
	method, key: string,
	body: []byte,
	content_type: string,
	now: time.Time,
	file: ^os.File = nil,
	file_size: i64 = 0,
	file_digest: string = "",
	http_execute: HTTP_Execute = http_execute_default,
) -> S3_Result {
	if http_execute == nil {
		return {}
	}
	url, headers, signed := s3_object_sign(config, credentials, method, key, body, content_type, now, file_digest)
	if !signed {
		return {}
	}
	started := time.tick_now()
	_, result := http_execute(
		{
			method = method,
			url = url,
			body = body,
			headers = headers,
			ca_file = config.ca_file,
			timeout_ms = 120000 if file != nil else 15000,
			upload_file = file,
			upload_size = file_size,
		},
	)
	s3_observe(started, result.ok)
	return result
}

// Validates and signs one object request without sending it. digest is the hex
// SHA-256 of a payload that is not in body; empty means body is hashed here.
s3_object_sign :: proc(
	config: S3_Config,
	credentials: AWS_Credentials,
	method, key: string,
	body: []byte,
	content_type: string,
	now: time.Time,
	digest: string = "",
) -> (
	url: string,
	headers: []string,
	ok: bool,
) {
	if !aws_credentials_valid(credentials) ||
	   s3_config_error(config) != "" ||
	   config.bucket == "" ||
	   key == "" ||
	   strings.contains_any(content_type, "\r\n\x00") {
		return
	}
	origin, host, path := s3_location(config, key)
	payload_digest := digest if digest != "" else s3_sha256(body)
	headers = s3_object_headers(config, credentials, method, host, path, payload_digest, s3_timestamp(now), content_type)
	return fmt.tprintf("%s%s", origin, path), headers, true
}

// One signed request for a transport the caller owns, such as an async client.
// Building one does no I/O. headers holds only what was signed plus Authorization:
// no Host, Content-Length, Expect or anything else an HTTP client sets itself, so
// the client must send Host exactly as it appears in url.
//
// url and headers borrow context.temp_allocator and body borrows the caller's
// bytes: hand the request to a transport that copies it before either is
// released. The signature is bound to the signing time, so build a new request
// for a late retry instead of keeping this one. The caller's transport supplies
// the timeout and the trust for S3_Config.ca_file, and reports the outcome
// through s3_observe if the observer should see it.
S3_Request :: struct {
	method:  string, // "GET", "HEAD", "PUT" or "DELETE"
	url:     string,
	headers: []S3_Header,
	body:    []u8,
}

// Signs an upload of body without sending it. now is the signing time; the zero
// time means time.now(). Nothing is returned when the input is invalid.
s3_put_request :: proc(
	config: S3_Config,
	credentials: AWS_Credentials,
	key: string,
	body: []byte,
	content_type: string,
	now: time.Time = {},
) -> (
	S3_Request,
	bool,
) {
	return s3_request(config, credentials, "PUT", key, body, content_type, signing_time(now))
}

// Signs a delete without sending it; see s3_put_request.
s3_delete_request :: proc(
	config: S3_Config,
	credentials: AWS_Credentials,
	key: string,
	now: time.Time = {},
) -> (
	S3_Request,
	bool,
) {
	return s3_request(config, credentials, "DELETE", key, nil, "", signing_time(now))
}

// Signs a download without sending it; see s3_put_request. The transport bounds
// the response body: s3_get's bytes_max does not apply here.
s3_get_request :: proc(
	config: S3_Config,
	credentials: AWS_Credentials,
	key: string,
	now: time.Time = {},
) -> (
	S3_Request,
	bool,
) {
	return s3_request(config, credentials, "GET", key, nil, "", signing_time(now))
}

// Signs a metadata request (size, type, existence) without sending it; see
// s3_put_request. A HEAD answer has no body, so a failure carries no S3 error code.
s3_head_request :: proc(
	config: S3_Config,
	credentials: AWS_Credentials,
	key: string,
	now: time.Time = {},
) -> (
	S3_Request,
	bool,
) {
	return s3_request(config, credentials, "HEAD", key, nil, "", signing_time(now))
}

S3_KEY_BYTES_MAX :: 1024 // S3's own limit on a key

// A strict check for keys built from outside input, for callers that opt in: no
// empty key, nothing above S3's 1024 bytes, no control characters, and no empty,
// "." or ".." segment (so no leading, trailing or doubled slash). The request
// procs do not apply it, because S3 itself accepts such keys.
s3_key_strict :: proc(key: string) -> bool {
	if key == "" || len(key) > S3_KEY_BYTES_MAX {
		return false
	}
	for index in 0 ..< len(key) {
		if key[index] < 0x20 || key[index] == 0x7f {
			return false
		}
	}
	rest := key
	for segment in strings.split_iterator(&rest, "/") {
		if segment == "" || segment == "." || segment == ".." {
			return false
		}
	}
	return key[len(key) - 1] != '/'
}

s3_request :: proc(
	config: S3_Config,
	credentials: AWS_Credentials,
	method, key: string,
	body: []byte,
	content_type: string,
	now: time.Time,
) -> (
	request: S3_Request,
	ok: bool,
) {
	url, lines := s3_object_sign(config, credentials, method, key, body, content_type, now) or_return
	fields, allocation_error := make([]S3_Header, len(lines), context.temp_allocator)
	if allocation_error != nil {
		return
	}
	count := s3_header_fields(lines, fields) or_return
	return {method = method, url = url, headers = fields[:count], body = body}, true
}

// Splits "Name: value" lines into fields. A line with an empty value is dropped:
// "Expect:" only switches off a default of the buffered client.
s3_header_fields :: proc(lines: []string, fields: []S3_Header) -> (count: int, ok: bool) {
	for line in lines {
		colon := strings.index_byte(line, ':')
		if colon < 1 || strings.contains_any(line, "\r\n\x00") {
			return 0, false
		}
		value := strings.trim_space(line[colon + 1:])
		if value == "" {
			continue
		}
		if count == len(fields) {
			return 0, false
		}
		fields[count] = {
			name  = line[:colon],
			value = value,
		}
		count += 1
	}
	return count, true
}

s3_object_headers :: proc(
	config: S3_Config,
	credentials: AWS_Credentials,
	method, host, path, digest, stamp, content_type: string,
) -> []string {
	canonical_headers := fmt.tprintf("host:%s\nx-amz-content-sha256:%s\nx-amz-date:%s\n", host, digest, stamp)
	signed := "host;x-amz-content-sha256;x-amz-date"
	headers := make([dynamic]string, 0, 8, context.temp_allocator)
	append(&headers, fmt.tprintf("x-amz-content-sha256: %s", digest), fmt.tprintf("x-amz-date: %s", stamp), "Expect:")
	if content_type != "" {
		append(&headers, fmt.tprintf("Content-Type: %s", content_type))
	}
	if credentials.session_token != "" {
		canonical_headers = fmt.tprintf("%sx-amz-security-token:%s\n", canonical_headers, credentials.session_token)
		signed = fmt.tprintf("%s;x-amz-security-token", signed)
		append(&headers, fmt.tprintf("x-amz-security-token: %s", credentials.session_token))
	}
	canonical := fmt.tprintf("%s\n%s\n\n%s\n%s\n%s", method, path, canonical_headers, signed, digest)
	scope := fmt.tprintf("%s/%s/s3/aws4_request", stamp[:8], config.region)
	signature := s3_signature(credentials.secret_key, config.region, stamp, scope, canonical)
	append(
		&headers,
		fmt.tprintf(
			"Authorization: AWS4-HMAC-SHA256 Credential=%s/%s, SignedHeaders=%s, Signature=%s",
			credentials.access_key,
			scope,
			signed,
			signature,
		),
	)
	return headers[:]
}

// A presigned GET for a browser or another client to fetch directly. No I/O.
// Returned URL is a bearer credential. Never persist it or include it in logs.
s3_download_url :: proc(
	config: S3_Config,
	credentials: AWS_Credentials,
	key: string,
	expires_seconds := 300,
	now: time.Time = {},
) -> (
	url: string,
	ok: bool,
) {
	if !aws_credentials_valid(credentials) ||
	   s3_config_error(config) != "" ||
	   config.bucket == "" ||
	   key == "" ||
	   expires_seconds < 1 ||
	   expires_seconds > 604800 {
		return
	}
	origin, host, path := s3_location(config, key)
	stamp := s3_timestamp(signing_time(now))
	scope := fmt.tprintf("%s/%s/s3/aws4_request", stamp[:8], config.region)
	query := fmt.tprintf(
		"X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=%s&X-Amz-Date=%s&X-Amz-Expires=%d",
		s3_encode(fmt.tprintf("%s/%s", credentials.access_key, scope)),
		stamp,
		expires_seconds,
	)
	if credentials.session_token != "" {
		query = fmt.tprintf("%s&X-Amz-Security-Token=%s", query, s3_encode(credentials.session_token))
	}
	query = fmt.tprintf("%s&X-Amz-SignedHeaders=host", query)
	canonical := fmt.tprintf("GET\n%s\n%s\nhost:%s\n\nhost\nUNSIGNED-PAYLOAD", path, query, host)
	signature := s3_signature(credentials.secret_key, config.region, stamp, scope, canonical)
	return fmt.tprintf("%s%s?%s&X-Amz-Signature=%s", origin, path, query, signature), true
}

s3_location :: proc(config: S3_Config, key: string) -> (origin, host, path: string) {
	origin = config.endpoint
	suffix := "amazonaws.com.cn" if strings.has_prefix(config.region, "cn-") else "amazonaws.com"
	path_style := config.path_style || strings.contains(config.bucket, ".")

	if origin == "" {
		if path_style {
			origin = fmt.tprintf("https://s3.%s.%s", config.region, suffix)
		} else {
			origin = fmt.tprintf("https://%s.s3.%s.%s", config.bucket, config.region, suffix)
		}
	}

	host = origin[8:]
	path = fmt.tprintf("/%s", s3_encode(key, true))
	if path_style {
		path = fmt.tprintf("/%s%s", config.bucket, path)
	}

	return
}

s3_encode :: proc(text: string, keep_slashes := false) -> string {
	builder := strings.builder_make(allocator = context.temp_allocator)

	for ch in transmute([]byte)text {
		if is_alphanumeric(ch) || ch == '-' || ch == '_' || ch == '.' || ch == '~' || keep_slashes && ch == '/' {
			strings.write_byte(&builder, ch)
		} else {
			digits := "0123456789ABCDEF"
			strings.write_byte(&builder, '%')
			strings.write_byte(&builder, digits[ch >> 4])
			strings.write_byte(&builder, digits[ch & 15])
		}
	}

	return strings.to_string(builder)
}

s3_sha256 :: proc(data: []byte) -> string {
	digest: [32]byte
	hash.hash(.SHA256, data, digest[:])

	return string(hex.encode(digest[:], allocator = context.temp_allocator))
}

// The secret and the keys derived from it stay on the stack and are erased before
// returning, so no copy outlives the caller's credentials.
s3_signature :: proc(secret, region, stamp, scope, canonical: string, service: string = "s3") -> string {
	// "AWS4" + secret is the first HMAC key. HMAC replaces a key longer than one
	// SHA-256 block with its digest, so a long secret is hashed here, not copied.
	seed: [64]byte
	key, next: [32]byte
	defer {
		mem.zero_explicit(&seed, size_of(seed))
		mem.zero_explicit(&key, size_of(key))
		mem.zero_explicit(&next, size_of(next))
	}
	prefix := "AWS4"
	seed_size := len(prefix) + len(secret)
	if seed_size <= len(seed) {
		copy(seed[:], prefix)
		copy(seed[len(prefix):], secret)
	} else {
		hasher: hash.Context
		hash.init(&hasher, .SHA256)
		hash.update(&hasher, transmute([]byte)prefix)
		hash.update(&hasher, transmute([]byte)secret)
		hash.final(&hasher, seed[:32])
		mem.zero_explicit(&hasher, size_of(hasher))
		seed_size = 32
	}
	hmac.sum(.SHA256, key[:], transmute([]byte)stamp[:8], seed[:seed_size])

	for text in ([]string{region, service, "aws4_request"}) {
		hmac.sum(.SHA256, next[:], transmute([]byte)text, key[:])
		key = next
	}

	to_sign := fmt.tprintf("AWS4-HMAC-SHA256\n%s\n%s\n%s", stamp, scope, s3_sha256(transmute([]byte)canonical))
	signature: [32]byte
	hmac.sum(.SHA256, signature[:], transmute([]byte)to_sign, key[:])

	return string(hex.encode(signature[:], allocator = context.temp_allocator))
}

s3_timestamp :: proc(now: time.Time) -> string {
	year, month, day := time.date(now)
	hour, minute, second := time.clock(now)

	return fmt.tprintf("%04d%02d%02dT%02d%02d%02dZ", year, int(month), day, hour, minute, second)
}

S3_GET_BYTES_MAX :: 64 * 1024 * 1024 // Surf's response body ceiling
S3_GET_TIMEOUT_MS :: 120000
S3_GET_HEADERS_MAX :: 8

s3_get_native_config :: proc(timeout_ms: i64, bytes_max: int, roots: []^x509.Certificate) -> network_client.Config {
	return {
		max_body_size = max(bytes_max, 1),
		timeout = time.Duration(timeout_ms) * time.Millisecond,
		tls = {root_cas = roots},
	}
}

S3_Get_Error :: enum u8 {
	None,
	Invalid_Input, // bad config/credentials/key/bound; nothing was sent
	Not_Found, // 404: no object under the key
	Too_Large, // the object is above bytes_max; no bytes are returned
	Rejected, // nonretryable status, including redirects and other 4xx
	Unavailable, // transport failure, timeout, 408/429/5xx: retry later
}

// Per-operation executor for s3_get. It sends one signed GET ("Name: value" header
// lines), never follows redirects, and returns at most bytes_max body bytes in
// allocator (Too_Large otherwise). status is the HTTP status, 0 when none arrived.
S3_Get_Execute :: proc(
	url: string,
	headers: []string,
	timeout_ms: i64,
	bytes_max: int,
	allocator: mem.Allocator,
) -> (
	body: []u8,
	status: int,
	error: S3_Get_Error,
)

// Download one object, bounded by bytes_max (<= S3_GET_BYTES_MAX). The body uses
// allocator and belongs to the caller; nothing is returned on error.
// Blocks the calling thread for up to 120 seconds. Not for an event-loop thread:
// use s3_get_request there.
s3_get :: proc(
	config: S3_Config,
	credentials: AWS_Credentials,
	key: string,
	bytes_max: int,
	now: time.Time = {},
	allocator := context.allocator,
	execute: S3_Get_Execute = s3_get_native,
) -> (
	[]u8,
	S3_Get_Error,
) {
	if execute == nil ||
	   !aws_credentials_valid(credentials) ||
	   s3_config_error(config) != "" ||
	   config.bucket == "" ||
	   key == "" ||
	   bytes_max < 0 ||
	   bytes_max > S3_GET_BYTES_MAX {
		return nil, .Invalid_Input
	}
	origin, host, path := s3_location(config, key)
	stamp := s3_timestamp(signing_time(now))
	headers := s3_object_headers(config, credentials, "GET", host, path, s3_sha256(nil), stamp, "")
	url := fmt.tprintf("%s%s", origin, path)
	started := time.tick_now()
	body, status, error := execute(url, headers, S3_GET_TIMEOUT_MS, bytes_max, allocator)
	s3_observe(started, error == .None && (status == 404 || (status >= 200 && status <= 299)))
	if error == .None && (status < 200 || status > 299) {
		switch {
		case status == 404:
			error = .Not_Found
		case status == 0 || status == 408 || status == 429 || status >= 500:
			error = .Unavailable
		case:
			error = .Rejected
		}
	}
	if error == .None && len(body) > bytes_max {
		error = .Too_Large
	}
	if error != .None {
		if body != nil {
			delete(body, allocator)
		}

		return nil, error
	}
	return body, .None
}

// Surf executor: native TLS with system roots, no redirects or proxies. A private CA
// (S3_Config.ca_file) is not supported on this path.
s3_get_native :: proc(
	url: string,
	headers: []string,
	timeout_ms: i64,
	bytes_max: int,
	allocator: mem.Allocator,
) -> (
	body: []u8,
	status: int,
	error: S3_Get_Error,
) {
	if bytes_max < 0 ||
	   bytes_max > S3_GET_BYTES_MAX ||
	   timeout_ms <= 0 ||
	   timeout_ms > S3_GET_TIMEOUT_MS ||
	   len(headers) > S3_GET_HEADERS_MAX {
		return nil, 0, .Invalid_Input
	}
	fields: [S3_GET_HEADERS_MAX]S3_Header
	count, fields_ok := s3_header_fields(headers, fields[:])
	if !fields_ok {
		return nil, 0, .Invalid_Input
	}
	// A nil root slice means omitted trust and fails before dial. This non-nil
	// empty view explicitly requests platform anchors; Core owns their pool for
	// the connection. Keep the backing view alive until execute has returned.
	platform_anchor: [1]^x509.Certificate
	config := s3_get_native_config(timeout_ms, bytes_max, platform_anchor[:0])
	response, http_error := network_client.execute(
		{method = .GET, url = url, headers = fields[:count]},
		config,
		allocator,
	)
	defer network_client.response_destroy(&response)
	if http_error.kind == .Body_Oversized {
		return nil, http_error.status, .Too_Large
	}
	if http_error.kind != .None {
		return nil, http_error.status, .Unavailable
	}
	if len(response.body) > bytes_max {
		return nil, response.status, .Too_Large
	}
	copied, allocation_error := make([]u8, len(response.body), allocator)
	if allocation_error != nil {
		return nil, response.status, .Unavailable
	}
	copy(copied, response.body)
	return copied, response.status, .None
}

// Surf's request header type, named through its API so aws needs no http import.
S3_Header :: type_of(network_client.Response{}.headers[0])
