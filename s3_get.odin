package aws

import network_client "../surf"
import "core:fmt"
import "core:mem"
import "core:strings"
import "core:time"

S3_GET_BYTES_MAX :: 64 * 1024 * 1024 // Surf's response body ceiling
S3_GET_TIMEOUT_MS :: 120000
S3_GET_HEADERS_MAX :: 8

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
s3_get :: proc(
	config: S3_Config,
	credentials: AWS_Credentials,
	key: string,
	bytes_max: int,
	allocator := context.allocator,
	execute: S3_Get_Execute = s3_get_native,
) -> (
	[]u8,
	S3_Get_Error,
) {
	return s3_get_at(config, credentials, key, bytes_max, time.now(), allocator, execute)
}

s3_get_at :: proc(
	config: S3_Config,
	credentials: AWS_Credentials,
	key: string,
	bytes_max: int,
	now: time.Time,
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
	stamp := s3_timestamp(now)
	headers := s3_object_headers(config, credentials, "GET", host, path, s3_sha256(nil), stamp, "")
	url := fmt.tprintf("%s%s", origin, path)
	body, status, error := execute(url, headers, S3_GET_TIMEOUT_MS, bytes_max, allocator)
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
	count := 0
	for line in headers {
		colon := strings.index_byte(line, ':')
		if colon < 1 || strings.contains_any(line, "\r\n\x00") {
			return nil, 0, .Invalid_Input
		}
		value := strings.trim_space(line[colon + 1:])
		// Empty "Expect:" needs no native header.
		if value == "" {
			continue
		}
		fields[count] = {
			name  = line[:colon],
			value = value,
		}
		count += 1
	}
	config := network_client.Config {
		max_body_size = max(bytes_max, 1), // zero would select Surf's 8 MiB default
		timeout       = time.Duration(timeout_ms) * time.Millisecond,
	}
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
@(private = "file")
S3_Header :: type_of(network_client.Response{}.headers[0])
