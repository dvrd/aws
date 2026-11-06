package aws

import network_client "../surf"
import files "../files"
import "core:crypto/hash"
import "core:crypto/hmac"
import "core:encoding/hex"
import "core:encoding/json"
import "core:fmt"
import "core:io"
import "core:os"
import "core:strings"
import "core:time"

S3_Config :: struct {
	bucket, region:    string,
	endpoint, ca_file: string, // Optional HTTPS endpoint/private CA for isolated peers.
	path_style:        bool,
}
AWS_Credentials :: struct {
	access_key, secret_key, session_token: string,
}
S3_Result :: network_client.Buffered_HTTP_Result

load_s3_config :: proc() -> S3_Config {
	config := S3_Config {
		bucket = os.get_env("AWS_S3_BUCKET", context.allocator),
		region = os.get_env("AWS_REGION", context.allocator),
	}
	if config.region == "" do config.region = os.get_env("AWS_DEFAULT_REGION", context.allocator)
	return config
}
s3_config_error :: proc(config: S3_Config) -> string {
	if config.bucket == "" do return ""
	if len(config.bucket) < 3 || len(config.bucket) > 63 || config.region == "" {
		return "S3 requires AWS_S3_BUCKET and AWS_REGION"
	}
	for ch in config.bucket {
		if !(ch >= 'a' && ch <= 'z') && !(ch >= '0' && ch <= '9') && ch != '-' && ch != '.' {
			return "Invalid S3 bucket name"
		}
	}
	for ch in config.region {
		if !(ch >= 'a' && ch <= 'z') && !(ch >= '0' && ch <= '9') && ch != '-' {
			return "Invalid AWS region"
		}
	}
	if config.endpoint != "" {
		if !strings.has_prefix(config.endpoint, "https://") ||
		   strings.contains_any(config.endpoint[8:], "/?#@\r\n") || len(config.endpoint) <= 8 {
			return "S3 endpoint must be an HTTPS origin"
		}
	}
	return ""
}

// Resolve at operation time so rotated role credentials are never retained indefinitely.
// A configured but incomplete credential source fails closed instead of falling through.
aws_credentials :: proc() -> (credentials: AWS_Credentials, ok: bool) {
	credentials = {
		access_key    = os.get_env("AWS_ACCESS_KEY_ID", context.temp_allocator),
		secret_key    = os.get_env("AWS_SECRET_ACCESS_KEY", context.temp_allocator),
		session_token = os.get_env("AWS_SESSION_TOKEN", context.temp_allocator),
	}
	if credentials.access_key != "" || credentials.secret_key != "" ||
	   credentials.session_token != "" {
		return credentials, aws_credentials_valid(credentials)
	}
	profile := os.get_env("AWS_PROFILE", context.temp_allocator)
	if profile == "" do profile = "default"
	path := os.get_env("AWS_SHARED_CREDENTIALS_FILE", context.temp_allocator)
	if path == "" {
		path = fmt.tprintf("%s/.aws/credentials", os.get_env("HOME", context.temp_allocator))
	}
	file_credentials, file_error := aws_credentials_read_profile(path, profile)
	if file_error.kind != .None && file_error.kind != .Open_Failed {return}
	if file_credentials.access_key != "" || file_credentials.secret_key != "" {
		return file_credentials, aws_credentials_valid(file_credentials)
	}

	relative := os.get_env("AWS_CONTAINER_CREDENTIALS_RELATIVE_URI", context.temp_allocator)
	url, token := "", ""
	if relative != "" {
		if !strings.has_prefix(relative, "/") || strings.contains_any(relative, "\r\n#") do return
		url = fmt.tprintf("http://169.254.170.2%s", relative)
	} else {
		if os.get_env("AWS_EC2_METADATA_DISABLED", context.temp_allocator) == "true" do return
		reply, result := network_client.buffered_http_execute(
			"PUT",
			"http://169.254.169.254/latest/api/token",
			nil,
			{"X-aws-ec2-metadata-token-ttl-seconds: 60"},
			"",
			allow_http = true, timeout_ms = 1500,
		)
		if !result.ok do return
		token = string(reply)
		if token == "" || strings.contains_any(token, "\r\n") do return
		role, role_result := network_client.buffered_http_execute(
			"GET",
			"http://169.254.169.254/latest/meta-data/iam/security-credentials/",
			nil,
			{fmt.tprintf("X-aws-ec2-metadata-token: %s", token)},
			"",
			allow_http = true, timeout_ms = 1500,
		)
		role_name := strings.trim_space(string(role))
		if !role_result.ok || role_name == "" || strings.contains_any(role_name, "/\r\n?#") {
			return
		}
		url = fmt.tprintf(
			"http://169.254.169.254/latest/meta-data/iam/security-credentials/%s",
			role_name,
		)
	}
	headers: []string
	if token != "" do headers = {fmt.tprintf("X-aws-ec2-metadata-token: %s", token)}
	data, result := network_client.buffered_http_execute(
		"GET", url, nil, headers, "", allow_http = true, timeout_ms = 1500,
	)
	if !result.ok do return
	document: struct {
		access: string `json:"AccessKeyId"`,
		secret: string `json:"SecretAccessKey"`,
		token:  string `json:"Token"`,
	}
	if json.unmarshal(data, &document, allocator = context.temp_allocator) != nil do return
	credentials = {document.access, document.secret, document.token}
	return credentials, aws_credentials_valid(credentials)
}
// Profile strings borrow bounded file storage in the operation's scratch arena.
aws_credentials_read_profile :: proc(
	path, profile: string,
) -> (credentials: AWS_Credentials, error: files.Read_Error) {
	data, read_error := files.read_limited(path, 64 * 1024, context.temp_allocator, erase_on_failure=true)
	if read_error.kind != .None {return {}, read_error}
	section := ""
	source := string(data)
	for raw_line in strings.split_iterator(&source, "\n") {
		line := strings.trim_space(raw_line)
		if line == "" || line[0] == '#' || line[0] == ';' {continue}
		if line[0] == '[' && line[len(line)-1] == ']' {
			section = strings.trim_space(line[1:len(line)-1]); continue
		}
		if section != profile {continue}
		equal := strings.index_byte(line, '=')
		if equal < 1 {continue}
		key := strings.trim_space(line[:equal])
		value := strings.trim_space(line[equal+1:])
		switch key {
		case "aws_access_key_id": credentials.access_key = value
		case "aws_secret_access_key": credentials.secret_key = value
		case "aws_session_token": credentials.session_token = value
		}
	}
	return credentials, {}
}

aws_credentials_valid :: proc(value: AWS_Credentials) -> bool {
	if value.access_key == "" || value.secret_key == "" do return false
	for text in ([]string{value.access_key, value.secret_key, value.session_token}) {
		if strings.contains_any(text, "\r\n\x00") do return false
	}
	return true
}

s3_put :: proc(
	config: S3_Config,
	credentials: AWS_Credentials,
	key: string,
	body: []byte,
	content_type: string,
	http_execute: HTTP_Execute = network_client.buffered_http_execute,
) -> S3_Result {
	return s3_object_request(config, credentials, "PUT", key, body, content_type, http_execute=http_execute)
}
// Stream a file with a fixed buffer, avoiding an archive-sized allocation.
s3_put_file :: proc(
	config: S3_Config,
	credentials: AWS_Credentials,
	key, path, content_type: string,
	http_execute: HTTP_Execute = network_client.buffered_http_execute,
) -> S3_Result {
	file, error := os.open(path)
	if error != nil do return {}
	defer os.close(file)
	size, size_error := os.file_size(file)
	if size_error != nil do return {}
	hasher: hash.Context
	hash.init(&hasher, .SHA256)
	buffer: [64 * 1024]byte
	for {
		n, read_error := os.read(file, buffer[:])
		if read_error != nil && read_error != io.Error.EOF do return {}
		if n == 0 do break
		hash.update(&hasher, buffer[:n])
	}
	digest: [32]byte
	hash.final(&hasher, digest[:])
	if _, seek_error := os.seek(file, 0, .Start); seek_error != nil do return {}
	return s3_object_request(
		config,
		credentials,
		"PUT",
		key,
		nil,
		content_type,
		file,
		size,
		string(hex.encode(digest[:], allocator = context.temp_allocator)),
		http_execute=http_execute,
	)
}
s3_delete :: proc(config: S3_Config, credentials: AWS_Credentials, key: string,
	http_execute: HTTP_Execute = network_client.buffered_http_execute,
) -> S3_Result {
	return s3_object_request(config, credentials, "DELETE", key, nil, "", http_execute=http_execute)
}
s3_object_request :: proc(
	config: S3_Config,
	credentials: AWS_Credentials,
	method, key: string,
	body: []byte,
	content_type: string,
	file: ^os.File = nil,
	file_size: i64 = 0,
	file_digest: string = "",
	http_execute: HTTP_Execute = network_client.buffered_http_execute,
) -> S3_Result {
	if http_execute == nil || !aws_credentials_valid(credentials) || s3_config_error(config) != "" ||
	   config.bucket == "" || key == "" || strings.contains_any(content_type, "\r\n\x00") {
		return {}
	}
	origin, host, path := s3_location(config, key)
	stamp := s3_timestamp(time.now())
	digest := file_digest if file != nil else s3_sha256(body)
	headers := s3_object_headers(
		config, credentials, method, host, path, digest, stamp, content_type,
	)
	_, result := http_execute(
		method,
		fmt.tprintf("%s%s", origin, path),
		body,
		headers,
		config.ca_file,
		false,
		120000 if file != nil else 15000,
		file,
		file_size,
	)
	return result
}

s3_object_headers :: proc(
	config: S3_Config, credentials: AWS_Credentials,
	method, host, path, digest, stamp, content_type: string,
) -> []string {
	canonical_headers := fmt.tprintf(
		"host:%s\nx-amz-content-sha256:%s\nx-amz-date:%s\n",
		host,
		digest,
		stamp,
	)
	signed := "host;x-amz-content-sha256;x-amz-date"
	headers := make([dynamic]string, 0, 8, context.temp_allocator)
	append(
		&headers,
		fmt.tprintf("x-amz-content-sha256: %s", digest),
		fmt.tprintf("x-amz-date: %s", stamp),
		"Expect:",
	)
	if content_type != "" do append(&headers, fmt.tprintf("Content-Type: %s", content_type))
	if credentials.session_token != "" {
		canonical_headers = fmt.tprintf(
			"%sx-amz-security-token:%s\n",
			canonical_headers,
			credentials.session_token,
		)
		signed = fmt.tprintf("%s;x-amz-security-token", signed)
		append(&headers, fmt.tprintf("x-amz-security-token: %s", credentials.session_token))
	}
	canonical := fmt.tprintf(
		"%s\n%s\n\n%s\n%s\n%s",
		method,
		path,
		canonical_headers,
		signed,
		digest,
	)
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
	if !aws_credentials_valid(credentials) || s3_config_error(config) != "" ||
	   config.bucket == "" || key == "" || expires_seconds < 1 || expires_seconds > 604800 {
		return
	}
	origin, host, path := s3_location(config, key)
	instant := now
	if instant == (time.Time{}) do instant = time.now()
	stamp := s3_timestamp(instant)
	scope := fmt.tprintf("%s/%s/s3/aws4_request", stamp[:8], config.region)
	query := fmt.tprintf(
		"X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=%s&X-Amz-Date=%s&X-Amz-Expires=%d",
		s3_encode(fmt.tprintf("%s/%s", credentials.access_key, scope)),
		stamp,
		expires_seconds,
	)
	if credentials.session_token != "" {
		query = fmt.tprintf(
			"%s&X-Amz-Security-Token=%s", query, s3_encode(credentials.session_token),
		)
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
		if path_style do origin = fmt.tprintf("https://s3.%s.%s", config.region, suffix)
		else do origin = fmt.tprintf("https://%s.s3.%s.%s", config.bucket, config.region, suffix)
	}
	host = origin[8:]
	path = fmt.tprintf("/%s", s3_encode(key, true))
	if path_style do path = fmt.tprintf("/%s%s", config.bucket, path)
	return
}
s3_encode :: proc(text: string, keep_slashes := false) -> string {
	builder := strings.builder_make(allocator = context.temp_allocator)
	for ch in transmute([]byte)text {
		if ch >= 'a' && ch <= 'z' ||
		   ch >= 'A' && ch <= 'Z' ||
		   ch >= '0' && ch <= '9' ||
		   ch == '-' ||
		   ch == '_' ||
		   ch == '.' ||
		   ch == '~' ||
		   keep_slashes && ch == '/' {
			strings.write_byte(&builder, ch)
		} else {
			digits := "0123456789ABCDEF"
			strings.write_byte(
				&builder,
				'%',
			)
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
s3_signature :: proc(
	secret, region, stamp, scope, canonical: string, service: string = "s3",
) -> string {
	key: [32]byte
	hmac.sum(
		.SHA256,
		key[:],
		transmute([]byte)stamp[:8],
		transmute([]byte)fmt.tprintf("AWS4%s", secret),
	)
	for text in ([]string{region, service, "aws4_request"}) {
		next: [32]byte
		hmac.sum(.SHA256, next[:], transmute([]byte)text, key[:])
		key = next
	}
	to_sign := fmt.tprintf(
		"AWS4-HMAC-SHA256\n%s\n%s\n%s",
		stamp,
		scope,
		s3_sha256(transmute([]byte)canonical),
	)
	signature: [32]byte
	hmac.sum(.SHA256, signature[:], transmute([]byte)to_sign, key[:])
	return string(hex.encode(signature[:], allocator = context.temp_allocator))
}
s3_timestamp :: proc(now: time.Time) -> string {
	year, month, day := time.date(now)
	hour, minute, second := time.clock(now)
	return fmt.tprintf("%04d%02d%02dT%02d%02d%02dZ", year, int(month), day, hour, minute, second)
}
