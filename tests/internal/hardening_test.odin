package aws

import network_client "shared:surf"
import "core:fmt"
import "core:mem"
import "core:os"
import "core:strings"
import "core:sync"
import "core:testing"
import "core:time"

@(test)
credential_expiry_instants_need_a_zone_and_may_carry_a_fraction :: proc(t: ^testing.T) {
	base, base_ok := credential_instant_parse("2030-01-02T03:04:05Z")
	testing.expect(t, base_ok)
	testing.expect_value(t, time.time_to_unix(base), 1893553445)
	for text in ([]string {
			"2030-01-02T03:04:05+00:00",
			"2030-01-02T03:04:05.1Z",
			"2030-01-02T03:04:05.123456789Z",
			"2030-01-02T05:04:05.25+02:00",
			"2030-01-01T22:04:05-05:00",
		}) {
		instant, ok := credential_instant_parse(text)
		testing.expect(t, ok && instant == base, text)
	}
	for text in ([]string {
			"",
			"invalid",
			"2030-01-02T03:04:05",
			"2030-01-02T03:04:05.12",
			"2030-01-02 03:04:05Z",
			"2030-13-02T03:04:05Z",
			"2030-02-30T03:04:05Z",
			"2030-01-02T03:04:05.Z",
			"2030-01-02T03:04:05+0000",
			"2030-01-02T03:04:05+24:00",
			"2030-01-02T03:04:05Zjunk",
		}) {
		_, ok := credential_instant_parse(text)
		testing.expect(t, !ok, text)
	}
}

@(test)
credential_documents_with_fractional_expiry_are_cached :: proc(t: ^testing.T) {
	saved := credential_test_env_push()
	defer credential_test_env_pop(saved)
	directory, directory_error := os.make_directory_temp("", "aws-cache-*", context.allocator)
	testing.expect(t, directory_error == nil)
	defer delete(directory)
	defer os.remove(directory)
	credential_test_absent(directory)
	testing.expect(t, os.set_env("AWS_CONTAINER_CREDENTIALS_RELATIVE_URI", "/v2/credentials/fixture") == nil)
	clock := Credential_Test_Clock {
		now = credential_test_instant("2024-01-01T00:00:00Z"),
	}
	http := Credential_Test_HTTP {
		body = `{"Code":"Success","AccessKeyId":"new-key","SecretAccessKey":"new-secret","Token":"new-token","Expiration":"2024-06-01T00:00:00.123456Z"}`,
	}
	credential_test_http_state = &http
	defer credential_test_http_state = nil
	cache: Credential_Cache
	testing.expect_value(t, credential_test_cache(&cache, &clock).kind, .None)
	defer credential_cache_destroy(&cache)
	testing.expect_value(t, credential_refresh(&cache).kind, Credential_Error_Kind.None)
	lease, failure := credential_lease_cached(&cache)
	defer credential_lease_release(&cache, &lease)
	testing.expect_value(t, failure.kind, Credential_Error_Kind.None)
	testing.expect(t, lease.has_expiry && lease.expires == credential_test_instant("2024-06-01T00:00:00Z"))
}

@(test)
credential_replies_of_the_default_executor_are_erased :: proc(t: ^testing.T) {
	other :: proc(request: HTTP_Request) -> ([]u8, network_client.Buffered_HTTP_Result) {
		return nil, {}
	}
	reply := [6]u8{'s', 'e', 'c', 'r', 'e', 't'}
	credential_reply_wipe(other, reply[:])
	testing.expect_value(t, string(reply[:]), "secret")
	credential_reply_wipe(http_execute_default, reply[:])
	testing.expect_value(t, reply, [6]u8{})
	credential_reply_wipe(http_execute_default, nil)
}

@(test)
credentials_with_control_characters_are_refused :: proc(t: ^testing.T) {
	testing.expect(t, aws_credentials_valid({"fixture-key", "fixture/secret+value", "token/with+base64=="}))
	testing.expect(t, aws_credentials_valid({"fixture-key", "fixture-secret", ""}))
	for value in ([]AWS_Credentials {
			{"key\tx", "secret", ""},
			{"key", "sec\x01ret", ""},
			{"key", "secret", "tok\x7fen"},
			{"key", "secret", "tok\ren"},
			{"key\x00", "secret", ""},
		}) {
		testing.expect(t, !aws_credentials_valid(value))
	}
}

@(test)
profile_option_names_are_case_insensitive :: proc(t: ^testing.T) {
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
		"[default]\nAWS_ACCESS_KEY_ID = fixture-key\nAws_Secret_Access_Key = fixture-secret\n" +
		"[role]\naws_access_key_id = other-key\naws_secret_access_key = other-secret\nRole_Arn = arn:aws:iam::123456789012:role/x\n"
	testing.expect(t, os.write_entire_file(path, fixture) == nil)
	credentials, unsupported, _, read_error := credential_profile_load(path, "default", true)
	testing.expect_value(t, read_error.kind, Read_Error_Kind.None)
	testing.expect_value(t, unsupported, Credential_Unsupported.None)
	testing.expect_value(t, credentials.access_key, "fixture-key")
	testing.expect_value(t, credentials.secret_key, "fixture-secret")
	role, role_unsupported, _, _ := credential_profile_load(path, "role", true)
	testing.expect_value(t, role_unsupported, Credential_Unsupported.Assumed_Role)
	testing.expect_value(t, role.access_key, "")
}

@(test)
uncached_resolution_applies_the_metadata_path_rule :: proc(t: ^testing.T) {
	saved := credential_test_env_push()
	defer credential_test_env_pop(saved)
	directory, directory_error := os.make_directory_temp("", "aws-cache-*", context.allocator)
	testing.expect(t, directory_error == nil)
	defer delete(directory)
	defer os.remove(directory)
	credential_test_absent(directory)
	http := Credential_Test_HTTP {
		body = CREDENTIAL_TEST_NEW,
	}
	credential_test_http_state = &http
	defer credential_test_http_state = nil
	for relative in ([]string {
			"//evil.example/path",
			"/v2/credentials?x=1",
			"/v2/@host",
			"http://evil.example/",
			"/v2/creden tials",
			"/v2/creden\ttials",
			"/v2/creden\x01tials",
			"/v2/cr\u00e9dentials",
		}) {
		testing.expect(t, os.set_env("AWS_CONTAINER_CREDENTIALS_RELATIVE_URI", relative) == nil)
		_, ok := aws_credentials_with_http(credential_test_http)
		testing.expect(t, !ok, relative)
	}
	testing.expect_value(t, http.calls, 0)
	testing.expect(t, os.set_env("AWS_CONTAINER_CREDENTIALS_RELATIVE_URI", "/v2/credentials/fixture") == nil)
	credentials, ok := aws_credentials_with_http(credential_test_http)
	testing.expect(t, ok && credentials.secret_key == "new-secret")
	testing.expect_value(t, http.calls, 1)
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

SES_Hardening :: struct {
	status: int,
	date:   string,
}
ses_hardening: SES_Hardening
ses_hardening_mutex: sync.Mutex

ses_hardening_http :: proc(request: HTTP_Request) -> ([]u8, network_client.Buffered_HTTP_Result) {
	for line in request.headers {
		if strings.has_prefix(line, "x-amz-date: ") {
			ses_hardening.date = strings.clone(line[len("x-amz-date: "):], context.temp_allocator)
		}
	}
	return transmute([]u8)string(`{"MessageId":"fixture-message"}`), {status = ses_hardening.status, ok = ses_hardening.status == 200, transport_ok = true}
}

@(test)
ses_signs_with_the_current_time_and_treats_every_answer_as_acknowledged :: proc(t: ^testing.T) {
	sync.mutex_lock(&ses_hardening_mutex)
	defer sync.mutex_unlock(&ses_hardening_mutex)
	credentials := AWS_Credentials{"fixture-key", "fixture-secret", ""}
	config := SES_Config {
		region    = "us-east-1",
		sender    = "from@example.test",
		recipient = "to@example.test",
	}
	before := s3_timestamp(time.now())
	ses_hardening = {
		status = 200,
	}
	testing.expect_value(t, ses_send(config, credentials, "subject", "body", time.Time{}, ses_hardening_http), SES_Error.None)
	after := s3_timestamp(time.now())
	testing.expect(t, ses_hardening.date >= before && ses_hardening.date <= after, "the zero time signs with the current time")

	fixed := time.unix(1369353600, 0)
	testing.expect_value(t, ses_send(config, credentials, "subject", "body", fixed, ses_hardening_http), SES_Error.None)
	testing.expect_value(t, ses_hardening.date, "20130524T000000Z")

	for item in ([]struct {
			status:   int,
			expected: SES_Error,
		} {
			{400, .Rejected},
			{403, .Rejected},
			{404, .Rejected},
			{301, .Rejected},
			// A throttle or a server error is still an acknowledged answer.
			{429, .Rejected},
			{503, .Rejected},
		}) {
		ses_hardening.status = item.status
		testing.expect_value(t, ses_send(config, credentials, "subject", "body", fixed, ses_hardening_http), item.expected)
	}
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
environment_credentials_honour_their_exported_expiry :: proc(t: ^testing.T) {
	saved := credential_test_env_push()
	defer credential_test_env_pop(saved)
	directory, directory_error := os.make_directory_temp("", "aws-cache-*", context.allocator)
	testing.expect(t, directory_error == nil)
	defer delete(directory)
	defer os.remove(directory)
	credential_test_absent(directory)
	testing.expect(t, os.set_env("AWS_ACCESS_KEY_ID", "fixture-key") == nil)
	testing.expect(t, os.set_env("AWS_SECRET_ACCESS_KEY", "fixture-secret") == nil)
	testing.expect(t, os.set_env("AWS_SESSION_TOKEN", "fixture-token") == nil)
	clock := Credential_Test_Clock {
		now = credential_test_instant("2024-01-01T00:00:00Z"),
	}
	http: Credential_Test_HTTP
	credential_test_http_state = &http
	defer credential_test_http_state = nil

	cases := []struct {
		expiration: string,
		expected:   Credential_Error_Kind,
	} {
		{"2024-01-01T01:00:00Z", .None},
		{"2024-01-01T01:00:00.5+00:00", .None},
		{"not-a-time", .Incomplete},
		{"2024-01-01T01:00:00", .Incomplete},
		{"2023-12-31T23:59:59Z", .Expired},
		{"2024-01-01T00:00:10Z", .Expired}, // inside the skew
	}
	for item in cases {
		testing.expect(t, os.set_env("AWS_CREDENTIAL_EXPIRATION", item.expiration) == nil)
		cache: Credential_Cache
		testing.expect_value(t, credential_test_cache(&cache, &clock).kind, .None)
		lease, failure := credential_lease(&cache)
		testing.expect_value(t, failure.kind, item.expected)
		if failure.kind == .None {
			testing.expect(t, lease.has_expiry && lease.expires == credential_test_instant("2024-01-01T01:00:00Z"))
			testing.expect_value(t, lease.source, Credential_Source.Environment)
		}
		credential_lease_release(&cache, &lease)
		testing.expect_value(t, credential_cache_destroy(&cache).kind, Credential_Error_Kind.None)
	}
	testing.expect_value(t, http.calls, 0)
}

@(test)
leases_stop_before_expiry_and_static_credentials_are_read_again :: proc(t: ^testing.T) {
	saved := credential_test_env_push()
	defer credential_test_env_pop(saved)
	directory, directory_error := os.make_directory_temp("", "aws-cache-*", context.allocator)
	testing.expect(t, directory_error == nil)
	defer delete(directory)
	defer os.remove(directory)
	credential_test_absent(directory)
	path := fmt.aprintf("%s/rotating", directory)
	defer delete(path)
	defer os.remove(path)
	testing.expect(t, os.write_entire_file(path, "[default]\naws_access_key_id = first-key\naws_secret_access_key = first-secret\n") == nil)
	testing.expect(t, os.set_env("AWS_SHARED_CREDENTIALS_FILE", path) == nil)
	start := credential_test_instant("2024-01-01T00:00:00Z")
	clock := Credential_Test_Clock {
		now = start,
	}
	http: Credential_Test_HTTP
	credential_test_http_state = &http
	defer credential_test_http_state = nil
	cache: Credential_Cache
	testing.expect_value(t, credential_test_cache(&cache, &clock).kind, .None)
	defer credential_cache_destroy(&cache)
	testing.expect_value(t, credential_refresh(&cache).kind, Credential_Error_Kind.None)
	held, held_error := credential_lease_cached(&cache)
	defer credential_lease_release(&cache, &held)
	testing.expect(t, held_error.kind == .None && !held.has_expiry && held.secret_key == "first-secret")

	// The file is rotated. Before the static interval the cache keeps what it has.
	testing.expect(t, os.write_entire_file(path, "[default]\naws_access_key_id = second-key\naws_secret_access_key = second-secret\n") == nil)
	clock.now = time.time_add(start, CREDENTIAL_STATIC_REFRESH - time.Second)
	testing.expect_value(t, credential_refresh(&cache).kind, Credential_Error_Kind.None)
	same, _ := credential_lease_cached(&cache)
	testing.expect_value(t, same.secret_key, "first-secret")
	credential_lease_release(&cache, &same)

	clock.now = time.time_add(start, CREDENTIAL_STATIC_REFRESH)
	testing.expect_value(t, credential_refresh(&cache).kind, Credential_Error_Kind.None)
	rotated, _ := credential_lease_cached(&cache)
	testing.expect_value(t, rotated.secret_key, "second-secret")
	credential_lease_release(&cache, &rotated)
	testing.expect_value(t, held.secret_key, "first-secret")

	// A file that disappears does not take usable static credentials with it.
	testing.expect(t, os.remove(path) == nil)
	clock.now = time.time_add(clock.now, CREDENTIAL_STATIC_REFRESH)
	testing.expect(t, credential_refresh(&cache).kind != .None)
	kept, kept_error := credential_lease_cached(&cache)
	testing.expect(t, kept_error.kind == .None && kept.secret_key == "second-secret")
	credential_lease_release(&cache, &kept)
	testing.expect_value(t, http.calls, 0)
}

@(test)
cached_leases_end_at_the_expiry_skew :: proc(t: ^testing.T) {
	saved := credential_test_env_push()
	defer credential_test_env_pop(saved)
	directory, directory_error := os.make_directory_temp("", "aws-cache-*", context.allocator)
	testing.expect(t, directory_error == nil)
	defer delete(directory)
	defer os.remove(directory)
	credential_test_absent(directory)
	testing.expect(t, os.set_env("AWS_CONTAINER_CREDENTIALS_RELATIVE_URI", "/v2/credentials/fixture") == nil)
	expires := credential_test_instant("2024-01-01T00:00:00Z")
	clock := Credential_Test_Clock {
		now = time.time_add(expires, -time.Hour),
	}
	http := Credential_Test_HTTP {
		body = CREDENTIAL_TEST_OLD,
	}
	credential_test_http_state = &http
	defer credential_test_http_state = nil
	cache: Credential_Cache
	testing.expect_value(t, credential_test_cache(&cache, &clock).kind, .None)
	defer credential_cache_destroy(&cache)
	testing.expect_value(t, credential_refresh(&cache).kind, Credential_Error_Kind.None)

	clock.now = time.time_add(expires, -CREDENTIAL_EXPIRY_SKEW - 1)
	last, last_error := credential_lease_cached(&cache)
	testing.expect_value(t, last_error.kind, Credential_Error_Kind.None)
	credential_lease_release(&cache, &last)
	clock.now = time.time_add(expires, -CREDENTIAL_EXPIRY_SKEW)
	_, ended := credential_lease_cached(&cache)
	testing.expect_value(t, ended.kind, Credential_Error_Kind.Expired)
	// The provider still serves the same nearly expired document: not cacheable.
	testing.expect_value(t, credential_refresh(&cache).kind, Credential_Error_Kind.Expired)
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
metadata_text_is_printable_before_it_reaches_a_url_or_header :: proc(t: ^testing.T) {
	testing.expect(t, credential_metadata_url_permitted("http://169.254.169.254/latest/meta-data/iam/security-credentials/fixture-role"))
	testing.expect(t, credential_metadata_url_permitted("http://169.254.170.2/v2/credentials/fixture"))
	for url in ([]string {
			"http://169.254.169.254/latest/meta-data/iam/security-credentials/role\tname",
			"http://169.254.169.254/latest/meta-data/iam/security-credentials/role\x01",
			"http://169.254.169.254/latest/meta-data/iam/security-credentials/r\u00f4le",
			"http://169.254.170.2/v2/creden tials",
			"http://169.254.170.2/v2/\x7f",
		}) {
		testing.expectf(t, !credential_metadata_url_permitted(url), "%q", url)
	}

	saved := credential_test_env_push()
	defer credential_test_env_pop(saved)
	directory, directory_error := os.make_directory_temp("", "aws-cache-*", context.allocator)
	testing.expect(t, directory_error == nil)
	defer delete(directory)
	defer os.remove(directory)
	credential_test_absent(directory)
	testing.expect(t, os.unset_env("AWS_EC2_METADATA_DISABLED"))
	// An IMDS token with a control character never becomes a header.
	bad_token :: proc(request: HTTP_Request) -> ([]u8, network_client.Buffered_HTTP_Result) {
		ses_hardening.status += 1
		return transmute([]u8)string("imds\ttoken"), {ok = true, status = 200}
	}
	sync.mutex_lock(&ses_hardening_mutex)
	defer sync.mutex_unlock(&ses_hardening_mutex)
	ses_hardening = {}
	_, ok := aws_credentials_with_http(bad_token)
	testing.expect(t, !ok)
	testing.expect_value(t, ses_hardening.status, 1)
	clock := Credential_Test_Clock {
		now = credential_test_instant("2024-01-01T00:00:00Z"),
	}
	cache: Credential_Cache
	testing.expect_value(t, credential_cache_init(&cache, bad_token, credential_test_clock, &clock).kind, Credential_Error_Kind.None)
	defer credential_cache_destroy(&cache)
	testing.expect_value(t, credential_refresh(&cache).kind, Credential_Error_Kind.Unavailable)
	testing.expect_value(t, ses_hardening.status, 2)
}

@(test)
profile_with_a_byte_order_mark_still_has_its_first_section :: proc(t: ^testing.T) {
	directory, error := os.make_directory_temp("", "aws-profile-*", context.allocator)
	if !testing.expect(t, error == nil) {
		return
	}
	defer delete(directory)
	defer os.remove(directory)
	path := fmt.aprintf("%s/credentials", directory)
	defer delete(path)
	defer os.remove(path)
	testing.expect(t, os.write_entire_file(path, "\xef\xbb\xbf[default]\r\naws_access_key_id = fixture-key\r\naws_secret_access_key = fixture-secret\r\n") == nil)
	credentials, _, _, read_error := credential_profile_load(path, "default", true)
	testing.expect_value(t, read_error.kind, Read_Error_Kind.None)
	testing.expect_value(t, credentials.access_key, "fixture-key")
	testing.expect_value(t, credentials.secret_key, "fixture-secret")
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

@(test)
profile_files_are_read_the_way_the_aws_cli_reads_them :: proc(t: ^testing.T) {
	directory, error := os.make_directory_temp("", "aws-profile-*", context.allocator)
	if !testing.expect(t, error == nil) {
		return
	}
	defer delete(directory)
	defer os.remove(directory)
	path := fmt.aprintf("%s/credentials", directory)
	defer delete(path)
	defer os.remove(path)
	// Each of these gives botocore 2.34.40 the access key "k1" and the secret "s1".
	accepted := []string {
		"[default]\naws_access_key_id = k1\naws_secret_access_key = s1\n",
		"[default]\naws_access_key_id: k1\naws_secret_access_key: s1\n",
		"[default]\naws_access_key_id=k1\naws_secret_access_key=s1\n",
		"[default]\r\naws_access_key_id = k1\r\naws_secret_access_key = s1\r\n",
		"[default]\nAWS_ACCESS_KEY_ID = k1\nAWS_SECRET_ACCESS_KEY = s1\n",
		"[default]\naws_access_key_id = k1\naws_secret_access_key = s1",
		"[default]\n  aws_access_key_id = k1\naws_secret_access_key = s1\n",
		"[default]\naws_access_key_id\t=\tk1\naws_secret_access_key\t=\ts1\n",
		"# c\n; c\n[default]\n# c\naws_access_key_id = k1\n; c\naws_secret_access_key = s1\n",
		"[other]\naws_access_key_id = o\naws_secret_access_key = os\n[default]\naws_access_key_id = k1\naws_secret_access_key = s1\n",
		"[default] # c\naws_access_key_id = k1\naws_secret_access_key = s1\n",
	}
	for text in accepted {
		testing.expect(t, os.write_entire_file(path, text) == nil)
		credentials, _, _, read_error := credential_profile_load(path, "default", true)
		testing.expect_value(t, read_error.kind, Read_Error_Kind.None)
		testing.expectf(t, credentials.access_key == "k1" && credentials.secret_key == "s1", "%q gave %q %q", text, credentials.access_key, credentials.secret_key)
	}
	// Delimiters inside a value belong to the value.
	testing.expect(t, os.write_entire_file(path, "[default]\naws_access_key_id = k1\naws_secret_access_key = s1==\naws_session_token = t=1:2\n") == nil)
	credentials, _, _, _ := credential_profile_load(path, "default", true)
	testing.expect_value(t, credentials.secret_key, "s1==")
	testing.expect_value(t, credentials.session_token, "t=1:2")
}
