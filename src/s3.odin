package aws

import "core:crypto/hash"
import "core:crypto/x509"
import "core:encoding/hex"
import "core:fmt"
import "core:io"
import "core:mem"
import "core:os"
import "core:strings"
import "core:sync"
import "core:time"
import tls "shared:async/tls"
import "shared:surf"

// Without an endpoint the request goes to AWS: https://<bucket>.s3.<region>...,
// or path style (https://s3.<region>.../<bucket>/) when path_style is set or the
// bucket name contains a dot, which AWS's wildcard certificate cannot cover.
//
// endpoint replaces the AWS origin for an isolated peer, a compatible store or the
// bucket's own domain. It is "https://" and a lower-case host with an optional
// port other than 443, and is signed and sent exactly as written. The bucket is
// added to the path only when path_style is set; otherwise the endpoint is taken
// to be the bucket's own origin, dotted name or not. ca_file is a private CA for
// that endpoint.
S3_Config :: struct {
	bucket, region:    string,
	endpoint, ca_file: string,
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

@(private)
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

// Whether a PUT or DELETE may have changed the object: Not_Sent means it surely
// did not, Response_Received means S3 answered, Unknown means it may have.
S3_Write_Effect :: enum u8 {
	Unknown,
	Not_Sent,
	Response_Received,
}

// The outcome of a PUT or DELETE. status is S3's HTTP status, 0 when no answer
// arrived; ok is error == .None. A 2xx answer whose body could not be read or
// copied is Unavailable with effect Response_Received: S3 did store the object
// but the caller cannot know, and a retry is safe because PUT and DELETE are
// idempotent.
S3_Result :: struct {
	status: int,
	ok:     bool,
	error:  S3_Error,
	effect: S3_Write_Effect,
}

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
		if !strings.has_prefix(config.endpoint, "https://") || len(config.endpoint) <= 8 {
			return "S3 endpoint must be an HTTPS origin"
		}
		if !s3_endpoint_authority_valid(config.endpoint[8:]) {
			return "S3 endpoint must be an HTTPS origin"
		}
	}

	return ""
}

// A host and an optional port, nothing else: no path, query, user or space. The
// host is lower case and the port is not the default, so that the Host a client
// sends cannot differ from the one that was signed.
@(private)
s3_endpoint_authority_valid :: proc(authority: string) -> bool {
	host, port := authority, ""
	if strings.has_prefix(authority, "[") {
		closing := strings.index_byte(authority, ']')
		if closing < 2 {
			return false
		}
		for ch in transmute([]byte)authority[1:closing] {
			if !is_digit(ch) && !(ch >= 'a' && ch <= 'f') && ch != ':' && ch != '.' {
				return false
			}
		}
		host, port = "", authority[closing + 1:]
		if port != "" && port[0] != ':' {
			return false
		}
	} else if colon := strings.index_byte(authority, ':'); colon >= 0 {
		host, port = authority[:colon], authority[colon:]
	}
	if !strings.has_prefix(authority, "[") {
		if host == "" ||
		   len(host) > 253 ||
		   host[0] == '.' ||
		   host[0] == '-' ||
		   strings.contains(host, "..") {
			return false
		}
		for ch in transmute([]byte)host {
			if !is_lower(ch) && !is_digit(ch) && ch != '.' && ch != '-' {
				return false
			}
		}
	}
	if port == "" {
		return true
	}
	number := 0
	if len(port) < 2 || len(port) > 6 || port[1] == '0' {
		return false
	}
	for ch in transmute([]byte)port[1:] {
		if !is_digit(ch) {
			return false
		}
		number = number * 10 + int(ch - '0')
	}
	return number <= 65535 && number != 443
}

@(private)
signing_time :: proc(now: time.Time) -> time.Time {
	if now == (time.Time{}) {
		return time.now()
	}

	return now
}

@(private)
region_char_valid :: proc(ch: rune) -> bool {
	return is_lower(ch) || is_digit(ch) || ch == '-'
}

// Keys are sent as given: "../" and other path segments reach S3 literally.
// Validating a key that comes from outside is the caller's job, and s3_key_strict
// is a check a caller can opt into.

// The timeout of a PUT or DELETE: 15 s plus 1 s per whole MiB of body, at most
// Surf's 120 s. A file upload gets 120 s.
@(private)
S3_REQUEST_TIMEOUT_MS :: 15000
@(private)
S3_REQUEST_TIMEOUT_MAX_MS :: 120000

@(private)
s3_request_timeout :: proc(body_size: i64, file: bool) -> i64 {
	if file {
		return S3_REQUEST_TIMEOUT_MAX_MS
	}
	return min(S3_REQUEST_TIMEOUT_MS + (body_size / (1 << 20)) * 1000, S3_REQUEST_TIMEOUT_MAX_MS)
}

// The outcome is in S3_Result.error. Blocks the calling thread until S3 answers or its timeout passes: 15 seconds
// plus 1 second per MiB of body, at most 120 seconds. Not for an
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
// The outcome is in S3_Result.error; an unreadable file is Invalid_Input.
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
		return {error = .Invalid_Input, effect = .Not_Sent}
	}
	defer os.close(file)
	size, size_error := os.file_size(file)
	if size_error != nil {
		return {error = .Invalid_Input, effect = .Not_Sent}
	}
	hasher: hash.Context
	hash.init(&hasher, .SHA256)
	buffer: [64 * 1024]byte
	for {
		n, read_error := os.read(file, buffer[:])
		if read_error != nil && read_error != io.Error.EOF {
			return {error = .Invalid_Input, effect = .Not_Sent}
		}
		if n == 0 {
			break
		}
		hash.update(&hasher, buffer[:n])
	}
	digest: [32]byte
	hash.final(&hasher, digest[:])
	if _, seek_error := os.seek(file, 0, .Start); seek_error != nil {
		return {error = .Invalid_Input, effect = .Not_Sent}
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

// The outcome is in S3_Result.error. Blocks the calling thread until S3 answers or 15 seconds pass. Not for an
// event-loop thread: use s3_delete_request there.
s3_delete :: proc(
	config: S3_Config,
	credentials: AWS_Credentials,
	key: string,
	now: time.Time = {},
	http_execute: HTTP_Execute = http_execute_default,
) -> S3_Result {
	return s3_object_request_at(
		config,
		credentials,
		"DELETE",
		key,
		nil,
		"",
		signing_time(now),
		http_execute = http_execute,
	)
}

@(private)
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
	// A file is signed by the digest of its contents, never as an empty payload.
	if http_execute == nil || file != nil && file_digest == "" {
		return {error = .Invalid_Input, effect = .Not_Sent}
	}
	url, headers, signed := s3_object_sign(
		config,
		credentials,
		method,
		key,
		body,
		content_type,
		now,
		file_digest,
	)
	if !signed {
		return {error = .Invalid_Input, effect = .Not_Sent}
	}
	started := time.tick_now()
	_, result := http_execute(
		{
			method = method,
			url = url,
			body = body,
			headers = headers,
			ca_file = config.ca_file,
			timeout_ms = s3_request_timeout(i64(len(body)), file != nil),
			upload_file = file,
			upload_size = file_size,
		},
	)
	error := s3_status_error(result.status)
	if result.status == 0 {
		error = s3_transport_error(result.error)
	} else if error == .None && !result.ok {
		error = .Unavailable
	}
	effect := S3_Write_Effect.Response_Received
	if result.status == 0 {
		effect = .Not_Sent if result.error.write_effect == .Not_Sent else .Unknown
	}
	s3_observe(started, error == .None)
	return {status = result.status, ok = error == .None, error = error, effect = effect}
}

// Validates and signs one object request without sending it. digest is the hex
// SHA-256 of a payload that is not in body; empty means body is hashed here.
@(private)
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
	if !s3_input_valid(config, credentials, key) || strings.contains_any(content_type, "\r\n\x00") {
		return
	}
	// The empty payload's digest is a constant; any other body is hashed on the stack.
	payload_digest := digest
	digest_hex: [64]u8
	if payload_digest == "" && len(body) == 0 {
		payload_digest = EMPTY_PAYLOAD_SHA256
	} else if payload_digest == "" {
		sum: [32]u8
		hash.hash(.SHA256, body, sum[:])
		sigv4_hex(sum[:], digest_hex[:])
		payload_digest = string(digest_hex[:])
	}
	stamp_buffer: [S3_TIMESTAMP_BYTES_MAX]u8
	stamp := s3_timestamp_write(stamp_buffer[:], now)

	// The url and every header line share one buffer.
	size := s3_location_size(config, key) + s3_object_headers_size(config, credentials, payload_digest, stamp, content_type)
	builder, builder_error := strings.builder_make_len_cap(0, size, context.temp_allocator)
	if builder_error != nil {
		return
	}
	host_start, path_start := s3_location_write(&builder, config, key)
	path_end := strings.builder_len(builder)
	located := strings.to_string(builder)
	headers = s3_object_headers(
		&builder,
		config,
		credentials,
		method,
		located[host_start:path_start],
		located[path_start:path_end],
		payload_digest,
		stamp,
		content_type,
	) or_return
	return strings.to_string(builder)[:path_end], headers, true
}

// The checks every signed S3 request makes before anything is built.
@(private)
s3_input_valid :: proc(config: S3_Config, credentials: AWS_Credentials, key: string) -> bool {
	return aws_credentials_valid(credentials) && s3_config_error(config) == "" && config.bucket != "" && key != ""
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
	if !text_without_controls(key) {
		return false
	}
	rest := key
	for segment in strings.split_iterator(&rest, "/") {
		if segment == "" || segment == "." || segment == ".." {
			return false
		}
	}
	return key[len(key) - 1] != '/'
}

@(private)
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
	url, lines := s3_object_sign(
		config,
		credentials,
		method,
		key,
		body,
		content_type,
		now,
	) or_return
	fields, allocation_error := make([]S3_Header, len(lines), context.temp_allocator)
	if allocation_error != nil {
		return
	}
	count := s3_header_fields(lines, fields) or_return
	return {method = method, url = url, headers = fields[:count], body = body}, true
}

// Splits "Name: value" lines into fields. A line with an empty value is dropped:
// "Expect:" only switches off a default of the buffered client.
@(private)
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

// The signed header lines of one object request, in the order they are sent:
// x-amz-content-sha256, x-amz-date, Expect, an optional Content-Type, an optional
// x-amz-security-token and Authorization. Content-Type is sent but not signed.
// The line text is written into builder after the request is signed, so host and
// path may point into builder; the lines are cut from it once it is complete.
@(private)
s3_object_headers :: proc(
	builder: ^strings.Builder,
	config: S3_Config,
	credentials: AWS_Credentials,
	method, host, path, digest, stamp, content_type: string,
) -> (
	headers: []string,
	ok: bool,
) {
	token := credentials.session_token
	signed_headers := [4]Sigv4_Header {
		{"host", host},
		{"x-amz-content-sha256", digest},
		{"x-amz-date", stamp},
		{"x-amz-security-token", token},
	}
	signed := "host;x-amz-content-sha256;x-amz-date;x-amz-security-token"
	signed_count := 4
	if token == "" {
		signed = signed[:len("host;x-amz-content-sha256;x-amz-date")]
		signed_count = 3
	}
	signature: [64]u8
	sigv4_sign(
		credentials.secret_key,
		{
			service = "s3",
			region = config.region,
			method = method,
			path = path,
			headers = signed_headers[:signed_count],
			payload_hash = digest,
			stamp = stamp,
		},
		&signature,
	)

	count := 4 + int(content_type != "") + int(token != "")
	lines, allocation_error := make([]string, count, context.temp_allocator)
	if allocation_error != nil {
		return
	}
	// starts[i] and ends[i] bound line i in builder; Expect has no text there.
	starts, ends: [6]int
	line := 0
	write_line :: proc(builder: ^strings.Builder, starts, ends: ^[6]int, line: ^int, name, value: string) {
		starts[line^] = strings.builder_len(builder^)
		strings.write_string(builder, name)
		strings.write_string(builder, value)
		ends[line^] = strings.builder_len(builder^)
		line^ += 1
	}
	write_line(builder, &starts, &ends, &line, "x-amz-content-sha256: ", digest)
	write_line(builder, &starts, &ends, &line, "x-amz-date: ", stamp)
	expect := line
	line += 1
	if content_type != "" {
		write_line(builder, &starts, &ends, &line, "Content-Type: ", content_type)
	}
	if token != "" {
		write_line(builder, &starts, &ends, &line, "x-amz-security-token: ", token)
	}
	starts[line] = strings.builder_len(builder^)
	sigv4_authorization_write(builder, credentials.access_key, stamp, config.region, "s3", signed, &signature)
	ends[line] = strings.builder_len(builder^)

	text := strings.to_string(builder^)
	for i in 0 ..< count {
		lines[i] = "Expect:" if i == expect else text[starts[i]:ends[i]]
	}
	return lines, true
}

// The bytes s3_object_headers writes into its builder, at most.
@(private)
s3_object_headers_size :: proc(
	config: S3_Config,
	credentials: AWS_Credentials,
	digest, stamp, content_type: string,
) -> int {
	size := len("x-amz-content-sha256: ") + len(digest) + len("x-amz-date: ") + len(stamp)
	size += len("Content-Type: ") + len(content_type)
	size += len("x-amz-security-token: ") + len(credentials.session_token)
	signed := "host;x-amz-content-sha256;x-amz-date;x-amz-security-token"
	return size + sigv4_authorization_size(credentials.access_key, config.region, "s3", signed)
}

// A presigned GET for a browser or another client to fetch directly. No I/O.
// Returned URL is a bearer credential. Never persist it or include it in logs.
// It stops working when the credentials that signed it expire, even if
// expires_seconds has not passed.
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
	if !s3_input_valid(config, credentials, key) || expires_seconds < 1 || expires_seconds > 604800 {
		return
	}
	stamp_buffer: [S3_TIMESTAMP_BYTES_MAX]u8
	stamp := s3_timestamp_write(stamp_buffer[:], signing_time(now))
	token := credentials.session_token

	// The url is built once: origin, path, the query that is signed, then the
	// signature. Every encoded byte takes at most three.
	size := s3_location_size(config, key) + 1
	size += len("X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=")
	size += 3 * (len(credentials.access_key) + 1 + sigv4_scope_size(config.region, "s3"))
	size += len("&X-Amz-Date=") + len(stamp) + len("&X-Amz-Expires=") + 20
	size += len("&X-Amz-Security-Token=") + 3 * len(token) + len("&X-Amz-SignedHeaders=host")
	size += len("&X-Amz-Signature=") + 64
	builder, builder_error := strings.builder_make_len_cap(0, size, context.temp_allocator)
	if builder_error != nil {
		return
	}
	host_start, path_start := s3_location_write(&builder, config, key)
	path_end := strings.builder_len(builder)
	strings.write_byte(&builder, '?')
	query_start := strings.builder_len(builder)
	strings.write_string(&builder, "X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=")
	// Encoding is per byte, so the credential is encoded piece by piece.
	for piece in ([]string{credentials.access_key, "/", stamp[:8], "/", config.region, "/s3/aws4_request"}) {
		s3_encode_write(&builder, piece)
	}
	strings.write_string(&builder, "&X-Amz-Date=")
	strings.write_string(&builder, stamp)
	strings.write_string(&builder, "&X-Amz-Expires=")
	strings.write_int(&builder, expires_seconds)
	if token != "" {
		strings.write_string(&builder, "&X-Amz-Security-Token=")
		s3_encode_write(&builder, token)
	}
	strings.write_string(&builder, "&X-Amz-SignedHeaders=host")

	text := strings.to_string(builder)
	signed_headers := [1]Sigv4_Header{{"host", text[host_start:path_start]}}
	signature: [64]u8
	sigv4_sign(
		credentials.secret_key,
		{
			service = "s3",
			region = config.region,
			method = "GET",
			path = text[path_start:path_end],
			query = text[query_start:],
			headers = signed_headers[:],
			payload_hash = "UNSIGNED-PAYLOAD",
			stamp = stamp,
		},
		&signature,
	)
	strings.write_string(&builder, "&X-Amz-Signature=")
	strings.write_bytes(&builder, signature[:])
	return strings.to_string(builder), true
}

// Writes the origin and then the encoded path of key into builder, which together
// are the request URL. host_start and path_start are offsets into builder.
@(private)
s3_location_write :: proc(
	builder: ^strings.Builder,
	config: S3_Config,
	key: string,
) -> (
	host_start, path_start: int,
) {
	// A dotted bucket forces path style on AWS only; an endpoint is used as given.
	path_style := config.path_style || config.endpoint == "" && strings.contains(config.bucket, ".")
	host_start = strings.builder_len(builder^) + len("https://")
	if config.endpoint != "" {
		strings.write_string(builder, config.endpoint)
	} else {
		strings.write_string(builder, "https://")
		if !path_style {
			strings.write_string(builder, config.bucket)
			strings.write_byte(builder, '.')
		}
		strings.write_string(builder, "s3.")
		strings.write_string(builder, config.region)
		strings.write_byte(builder, '.')
		strings.write_string(builder, "amazonaws.com.cn" if strings.has_prefix(config.region, "cn-") else "amazonaws.com")
	}

	path_start = strings.builder_len(builder^)
	strings.write_byte(builder, '/')
	if path_style {
		strings.write_string(builder, config.bucket)
		strings.write_byte(builder, '/')
	}
	s3_encode_write(builder, key, true)
	return
}

// The bytes s3_location_write writes, at most.
@(private)
s3_location_size :: proc(config: S3_Config, key: string) -> int {
	origin := len(config.endpoint) + len("https://") + len(config.bucket) + len(".s3.") + len(config.region) + len(".amazonaws.com.cn")
	return origin + 2 + len(config.bucket) + 3 * len(key)
}

s3_encode :: proc(text: string, keep_slashes := false) -> string {
	builder := strings.builder_make(allocator = context.temp_allocator)
	s3_encode_write(&builder, text, keep_slashes)
	return strings.to_string(builder)
}

// Writes text into builder percent-encoded as SigV4 requires: unreserved bytes as
// they are, a slash too when keep_slashes is set, and every other byte as %XX.
@(private)
s3_encode_write :: proc(builder: ^strings.Builder, text: string, keep_slashes := false) {
	for ch in transmute([]byte)text {
		if is_alphanumeric(ch) ||
		   ch == '-' ||
		   ch == '_' ||
		   ch == '.' ||
		   ch == '~' ||
		   keep_slashes && ch == '/' {
			strings.write_byte(builder, ch)
		} else {
			digits := "0123456789ABCDEF"
			strings.write_byte(builder, '%')
			strings.write_byte(builder, digits[ch >> 4])
			strings.write_byte(builder, digits[ch & 15])
		}
	}
}

@(private)
s3_sha256 :: proc(data: []byte) -> string {
	digest: [32]byte
	hash.hash(.SHA256, data, digest[:])

	return string(hex.encode(digest[:], allocator = context.temp_allocator))
}

// Signs a canonical request given as a string, under the given scope. The secret
// and the keys derived from it stay on the stack and are erased before returning,
// so no copy outlives the caller's credentials. The signers stream their canonical
// requests through sigv4_sign instead; this form remains for fixtures.
@(private)
s3_signature :: proc(
	secret, region, stamp, scope, canonical: string,
	service: string = "s3",
) -> string {
	digest, signature: [32]u8
	hash.hash(.SHA256, transmute([]byte)canonical, digest[:])
	sigv4_signature_from_digest(secret, region, service, stamp, []string{scope}, &digest, &signature)

	return string(hex.encode(signature[:], allocator = context.temp_allocator))
}

@(private)
s3_timestamp :: proc(now: time.Time) -> string {
	buffer: [S3_TIMESTAMP_BYTES_MAX]u8
	return strings.clone(s3_timestamp_write(buffer[:], now), context.temp_allocator)
}

// A stamp is 16 bytes for years 1000 to 9999; the bound leaves room for others.
@(private)
S3_TIMESTAMP_BYTES_MAX :: 32

// Formats now as YYYYMMDDTHHMMSSZ into buffer and returns that part of it.
@(private)
s3_timestamp_write :: proc(buffer: []u8, now: time.Time) -> string {
	year, month, day := time.date(now)
	hour, minute, second := time.clock(now)

	return fmt.bprintf(buffer, "%04d%02d%02dT%02d%02d%02dZ", year, int(month), day, hour, minute, second)
}

S3_GET_BYTES_MAX :: 64 * 1024 * 1024 // Surf's response body ceiling
S3_GET_TIMEOUT_MS :: 120000
S3_GET_HEADERS_MAX :: 8

@(private)
s3_get_native_config :: proc(
	timeout_ms: i64,
	bytes_max: int,
	roots: []^x509.Certificate,
) -> surf.Config {
	return {
		max_body_size = max(bytes_max, 1),
		timeout = time.Duration(timeout_ms) * time.Millisecond,
		tls = {root_cas = roots},
	}
}

// The outcome of an S3 request. Async callers classify their own responses with
// s3_status_error.
S3_Error :: enum u8 {
	None,
	Invalid_Input, // bad config/credentials/key/bound, an unreadable local file, or a request the transport refused before sending; nothing was sent
	Not_Found, // 404: no object under the key (or no such bucket)
	Too_Large, // a 2xx object is above bytes_max; no bytes are returned
	Rejected, // nonretryable status, including redirects and other 4xx, or a server certificate or redirect the client refuses
	Unavailable, // no answer, a timeout, 408/429/5xx: retry later
}

// The name s3_get has always used.
S3_Get_Error :: S3_Error

// The error for an HTTP status S3 answered with; 0 means no answer arrived.
s3_status_error :: proc(status: int) -> S3_Error {
	switch {
	case status >= 200 && status <= 299:
		return .None
	case status == 404:
		return .Not_Found
	case status == 0 || status == 408 || status == 429 || status >= 500:
		return .Unavailable
	}
	return .Rejected
}

// The error for a request that got no usable HTTP answer. The switch is complete
// on purpose: a new Surf error kind fails to compile until it is classified.
@(private)
s3_transport_error :: proc(failure: surf.HTTP_Error) -> S3_Error {
	switch failure.kind {
	case .Invalid_URL,
	     .Insecure_URL,
	     .Invalid_Config,
	     .Invalid_Method,
	     .Invalid_Header,
	     .Reserved_Header,
	     .Address_Rejected:
		return .Invalid_Input
	case .Redirect_Limit, .Invalid_Redirect, .Unsafe_Redirect:
		return .Rejected
	case .Body_Oversized:
		return .Too_Large
	case .TLS_Failed:
		if general, is_general := failure.tls_error.(tls.General_Error); is_general {
			#partial switch general {
			case .Invalid_SNI_Hostname, .Invalid_Config, .Invalid_Trust_Roots, .Credential_Failed:
				return .Invalid_Input
			}
		}
		if protocol, is_protocol := failure.tls_error.(tls.Protocol_Error); is_protocol {
			#partial switch protocol {
			case .Bad_Certificate,
			     .Unsupported_Certificate,
			     .Certificate_Revoked,
			     .Certificate_Expired,
			     .Certificate_Unknown,
			     .Unknown_Ca,
			     .Protocol_Version,
			     .Insufficient_Security:
				return .Rejected
			}
		}
		return .Unavailable
	case .None,
	     .Header_Incomplete,
	     .Header_Oversized,
	     .Header_Limit,
	     .Invalid_Status,
	     .Conflicting_Framing,
	     .Unsupported_Transfer_Encoding,
	     .Invalid_Content_Length,
	     .Invalid_Chunk,
	     .Invalid_Trailer,
	     .Unexpected_EOF,
	     .No_Progress,
	     .Destination_Undersized,
	     .Overlapping_Buffers,
	     .Allocation_Failed,
	     .Dial_Failed,
	     .IO_Failed,
	     .Deadline_Failed,
	     .Too_Many_Informational,
	     .Unsupported_Content_Encoding,
	     .Content_Decoding_Failed:
		return .Unavailable
	}
	return .Unavailable
}

// Per-operation executor for s3_get. On an error status whose body exceeds
// bytes_max, return the status with Too_Large; s3_get classifies the status.
// It sends one signed GET ("Name: value" header
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
	   !s3_input_valid(config, credentials, key) ||
	   bytes_max < 0 ||
	   bytes_max > S3_GET_BYTES_MAX {
		return nil, .Invalid_Input
	}
	// The native executor trusts the system roots only. A configured private CA
	// must not be dropped silently in favour of them.
	if config.ca_file != "" && execute == s3_get_native {
		return nil, .Invalid_Input
	}
	url, headers, signed := s3_object_sign(config, credentials, "GET", key, nil, "", signing_time(now), EMPTY_PAYLOAD_SHA256)
	if !signed {
		return nil, .Invalid_Input
	}
	started := time.tick_now()
	body, status, error := execute(url, headers, S3_GET_TIMEOUT_MS, bytes_max, allocator)
	answered := status >= 200 && status <= 299
	// A status that is not 2xx decides the outcome, even when its body was cut
	// short for exceeding bytes_max: error answers are small XML documents that
	// a tight bound can still exceed.
	if status != 0 && !answered && (error == .None || error == .Too_Large) {
		error = s3_status_error(status)
	} else if error == .None && status == 0 {
		error = .Unavailable
	}
	s3_observe(started, error == .None || error == .Not_Found)
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
// (S3_Config.ca_file) is not supported on this path, and s3_get refuses the
// combination instead of ignoring the CA.
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
	response, http_error := surf.execute(
		{method = .GET, url = url, headers = fields[:count]},
		config,
		allocator,
	)
	defer surf.response_destroy(&response)
	if http_error.kind != .None {
		return nil, http_error.status, s3_transport_error(http_error)
	}
	if len(response.body) > bytes_max {
		return nil, response.status, .Too_Large
	}
	// Surf allocated the body with allocator (no budget scope is configured), so
	// the caller can own its storage outright. The slice starts at the
	// allocation, so delete(body, allocator) frees it. An empty body or one Surf
	// cannot hand over is copied instead.
	if len(response.body) > 0 {
		chunk, take_error := surf.response_take_body(&response)
		if take_error.kind == .None {
			return chunk.storage[:len(chunk.data)], response.status, .None
		}
	}
	copied, allocation_error := make([]u8, len(response.body), allocator)
	if allocation_error != nil {
		return nil, response.status, .Unavailable
	}
	copy(copied, response.body)
	return copied, response.status, .None
}

// Surf's request header type, named through its API so aws needs no http import.
S3_Header :: type_of(surf.Response{}.headers[0])
