package aws

import network_client "shared:surf"
import "core:fmt"
import "core:mem"
import "core:os"
import "core:strings"
import "core:sync"
import "core:testing"
import "core:thread"
import "core:time"
// Unit tests of src/credentials.odin: resolution, the cache and its leases,
// profile files, metadata rules and expiry.
@(test)
profile_reading_preserves_sections_and_bounds :: proc(t: ^testing.T) {
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
		"# synthetic fixture\n[default]\naws_access_key_id = default-key\naws_secret_access_key = default-secret\n" +
		"[ selected ]\naws_access_key_id = fixture-key\naws_secret_access_key = fixture-secret\naws_session_token = fixture-token\n"
	testing.expect(t, os.write_entire_file(path, fixture) == nil)
	credentials, _, _, read_error := credential_profile_load(path, "selected", false)
	testing.expect_value(t, read_error.kind, .None)
	testing.expect(t, aws_credentials_valid(credentials))
	testing.expect_value(t, credentials.access_key, "fixture-key")
	testing.expect_value(t, credentials.secret_key, "fixture-secret")
	testing.expect_value(t, credentials.session_token, "fixture-token")
	missing, _, _, missing_error := credential_profile_load(path, "missing", false)
	testing.expect(t, missing_error.kind == .None && !aws_credentials_valid(missing))
	large := make([]u8, 65537)
	defer delete(large)
	testing.expect(t, os.write_entire_file(path, large) == nil)
	_, _, _, limit_error := credential_profile_load(path, "selected", false)
	testing.expect_value(t, limit_error.kind, Read_Error_Kind.Limit_Exceeded)
	testing.expect(t, !aws_credentials_valid({"fixture\nkey", "secret", ""}))
	testing.expect(t, !aws_credentials_valid({"fixture-key", "", ""}))
}

CREDENTIAL_TEST_OLD :: `{"Code":"Success","AccessKeyId":"old-key","SecretAccessKey":"old-secret","Token":"old-token","Expiration":"2024-01-01T00:00:00Z"}`

CREDENTIAL_TEST_NEW :: `{"Code":"Success","AccessKeyId":"new-key","SecretAccessKey":"new-secret","Token":"new-token","Expiration":"2024-06-01T00:00:00Z"}`

CREDENTIAL_TEST_FAR :: `{"Code":"Success","AccessKeyId":"far-key","SecretAccessKey":"far-secret","Token":"far-token","Expiration":"2099-01-01T00:00:00Z"}`

Credential_Test_Clock :: struct {
	now: time.Time,
}

credential_test_clock :: proc(data: rawptr) -> time.Time {
	return (cast(^Credential_Test_Clock)data).now
}

credential_test_instant :: proc(text: string) -> time.Time {
	parsed, consumed := time.rfc3339_to_time_utc(text)
	assert(consumed == len(text))

	return parsed
}

Credential_Test_HTTP :: struct {
	calls:     int,
	entered:   int,
	fail:      bool,
	block:     bool,
	release:   bool,
	ec2:       bool,
	body:      string,
	role:      string,
	next_body: string,
	rejected:  string,
	mutex:     sync.Mutex,
	cond:      sync.Cond,
}

credential_test_http_state: ^Credential_Test_HTTP

credential_test_http :: proc(request: HTTP_Request) -> ([]u8, network_client.Buffered_HTTP_Result) {
	state := credential_test_http_state
	state.calls += 1
	if !request.allow_http ||
	   request.timeout_ms != 1500 ||
	   request.upload_file != nil ||
	   request.upload_size != 0 ||
	   request.ca_file != "" ||
	   len(request.body) != 0 ||
	   !credential_metadata_url_permitted(request.url) {
		state.rejected = request.url
		return nil, {ok = false, status = 400}
	}
	_ = request.headers
	if state.block {
		sync.mutex_lock(&state.mutex)
		state.entered += 1
		sync.cond_broadcast(&state.cond)

		for !state.release {
			sync.cond_wait(&state.cond, &state.mutex)
		}

		sync.mutex_unlock(&state.mutex)
	}
	if state.fail && state.calls > 1 {
		return nil, {ok = false, status = 503}
	}
	if state.ec2 {
		if request.method == "PUT" && request.url == "http://169.254.169.254/latest/api/token" {
			return transmute([]u8)string("imds-token"), {ok = true, status = 200}
		}

		if request.method == "GET" && request.url == "http://169.254.169.254/latest/meta-data/iam/security-credentials/" {
			role := state.role if state.role != "" else "fixture-role\n"
			return transmute([]u8)role, {ok = true, status = 200}
		}

		if request.method != "GET" || request.url != "http://169.254.169.254/latest/meta-data/iam/security-credentials/fixture-role" {
			state.rejected = request.url
			return nil, {ok = false}
		}
	} else if request.method != "GET" || request.url != "http://169.254.170.2/v2/credentials/fixture" {
		state.rejected = request.url
		return nil, {ok = false}
	}
	payload := state.body
	if state.next_body != "" && state.calls > 3 {
		payload = state.next_body
	} else if state.next_body != "" && !state.ec2 && state.calls > 1 {
		payload = state.next_body
	}
	return transmute([]u8)payload, {ok = true, status = 200}
}

credential_test_cache_state: ^Credential_Cache

credential_test_waiters_target: int

credential_test_provider_entered :: proc() -> bool {
	state := credential_test_http_state
	sync.mutex_lock(&state.mutex)
	entered := state.entered
	sync.mutex_unlock(&state.mutex)

	return entered >= 1
}

credential_test_waiters_reached :: proc() -> bool {
	cache := credential_test_cache_state
	sync.mutex_lock(&cache.mutex)
	count := cache.waiters
	sync.mutex_unlock(&cache.mutex)

	return count == credential_test_waiters_target
}

credential_test_cache :: proc(
	cache: ^Credential_Cache,
	clock: ^Credential_Test_Clock,
	allocator := context.allocator,
) -> Credential_Error {
	return credential_cache_init(cache, credential_test_http, credential_test_clock, clock, allocator = allocator)
}

Credential_Test_Call :: struct {
	cache:  ^Credential_Cache,
	cancel: ^Credential_Cancel,
	lease:  Credential_Lease,
	error:  Credential_Error,
}

credential_test_call :: proc(call: ^Credential_Test_Call) {
	call.lease, call.error = credential_lease(call.cache, call.cancel)
}

credential_test_wait_until :: proc(ready: proc() -> bool) -> bool {
	for _ in 0 ..< 2000 {
		if ready() {
			return true
		}

		time.sleep(time.Millisecond)
	}

	return false
}

Credential_Probe :: struct {
	backing:     mem.Allocator,
	visible:     bool,
	frees:       int,
	allocations: int,
	fail_at:     int,
}

credential_probe_contains :: proc(haystack: []byte, needle: string) -> bool {
	if len(needle) == 0 || len(haystack) < len(needle) {
		return false
	}

	for index in 0 ..= len(haystack) - len(needle) {
		if string(haystack[index:][:len(needle)]) == needle {
			return true
		}
	}

	return false
}

credential_probe_allocate :: proc(
	data: rawptr,
	mode: mem.Allocator_Mode,
	size, alignment: int,
	old_memory: rawptr,
	old_size: int,
	loc := #caller_location,
) -> (
	[]byte,
	mem.Allocator_Error,
) {
	probe := cast(^Credential_Probe)data
	if mode == .Alloc || mode == .Alloc_Non_Zeroed {
		probe.allocations += 1
		if probe.fail_at != 0 && probe.allocations == probe.fail_at {
			return nil, .Out_Of_Memory
		}
	}
	if mode == .Free && old_memory != nil && old_size > 0 {
		probe.frees += 1
		bytes := ([^]byte)(old_memory)[:old_size]

		if credential_probe_contains(bytes, "old-secret") || credential_probe_contains(bytes, "new-secret") {
			probe.visible = true
		}
	}
	return probe.backing.procedure(probe.backing.data, mode, size, alignment, old_memory, old_size, loc)
}

@(test)
credential_metadata_urls_reject_arbitrary_hosts :: proc(t: ^testing.T) {
	testing.expect(t, credential_metadata_url_permitted("http://169.254.170.2/v2/credentials/fixture"))
	testing.expect(t, credential_metadata_url_permitted("http://169.254.169.254/latest/api/token"))
	testing.expect(
		t,
		credential_metadata_url_permitted(
			"http://169.254.169.254/latest/meta-data/iam/security-credentials/fixture-role",
		),
	)
	refused_urls := [?]string {
		"http://127.0.0.1/creds",
		"http://169.254.170.2.example/creds",
		"https://169.254.170.2/v2/credentials/fixture",
		"http://169.254.170.2//v2/credentials/fixture",
		"http://example.com/latest/api/token",
	}

	for refused in refused_urls {
		testing.expect(t, !credential_metadata_url_permitted(refused))
	}

	testing.expect(t, !credential_ec2_probe_permitted({}))
}

@(test)
credential_expiry_uses_injected_clock_and_keeps_one_snapshot :: proc(t: ^testing.T) {
	saved := credential_test_env_push()
	defer credential_test_env_pop(saved)
	directory, directory_error := os.make_directory_temp("", "aws-cache-*", context.allocator)
	testing.expect(t, directory_error == nil)
	defer delete(directory)
	defer os.remove(directory)
	credential_test_absent(directory)
	testing.expect(t, os.set_env("AWS_CONTAINER_CREDENTIALS_RELATIVE_URI", "/v2/credentials/fixture") == nil)
	testing.expect(t, os.unset_env("AWS_EC2_METADATA_DISABLED"))
	expires := credential_test_instant("2024-01-01T00:00:00Z")
	clock := Credential_Test_Clock {
		// One nanosecond before the cache stops handing these credentials out.
		now = time.time_add(expires, -CREDENTIAL_EXPIRY_SKEW - 1),
	}

	http := Credential_Test_HTTP {
		body      = CREDENTIAL_TEST_OLD,
		next_body = CREDENTIAL_TEST_NEW,
	}

	credential_test_http_state = &http
	defer credential_test_http_state = nil
	cache: Credential_Cache
	testing.expect_value(t, credential_test_cache(&cache, &clock).kind, .None)
	defer credential_cache_destroy(&cache)
	first, first_error := credential_lease(&cache)
	defer credential_lease_release(&cache, &first)
	testing.expect_value(t, first_error.kind, .None)
	testing.expect_value(t, first.source, .ECS)
	testing.expect(t, first.has_expiry && first.access_key == "old-key")
	testing.expect(t, first.secret_key == "old-secret" && first.session_token == "old-token")
	second, second_error := credential_lease(&cache)
	testing.expect(t, second_error.kind == .None && second.secret_key == "old-secret")
	credential_lease_release(&cache, &second)
	testing.expect_value(t, http.calls, 1)
	clock.now = time.time_add(expires, -CREDENTIAL_EXPIRY_SKEW)
	third, third_error := credential_lease(&cache)
	defer credential_lease_release(&cache, &third)
	testing.expect_value(t, third_error.kind, .None)
	testing.expect_value(t, http.calls, 2)
	testing.expect(
		t,
		third.access_key == "new-key" && third.secret_key == "new-secret" && third.session_token == "new-token",
	)
	testing.expect(
		t,
		first.access_key == "old-key" && first.secret_key == "old-secret" && first.session_token == "old-token",
		"held snapshot stays a consistent triple across refresh",
	)
	testing.expect(t, first.secret_key != third.secret_key && first.access_key != third.access_key)
}

@(test)
credential_failed_refresh_does_not_publish_or_return_secrets :: proc(t: ^testing.T) {
	saved := credential_test_env_push()
	defer credential_test_env_pop(saved)
	directory, error := os.make_directory_temp("", "aws-cache-fail-*", context.allocator)
	testing.expect(t, error == nil)
	defer delete(directory)
	defer os.remove(directory)
	credential_test_absent(directory)
	testing.expect(t, os.set_env("AWS_CONTAINER_CREDENTIALS_RELATIVE_URI", "/v2/credentials/fixture") == nil)
	expires := credential_test_instant("2024-01-01T00:00:00Z")
	clock := Credential_Test_Clock {
		// One nanosecond before the cache stops handing these credentials out.
		now = time.time_add(expires, -CREDENTIAL_EXPIRY_SKEW - 1),
	}

	probe := Credential_Probe {
		backing = context.allocator,
	}

	http := Credential_Test_HTTP {
		body = CREDENTIAL_TEST_OLD,
		fail = true,
	}

	credential_test_http_state = &http
	defer credential_test_http_state = nil
	cache: Credential_Cache
	testing.expect_value(
		t,
		credential_test_cache(&cache, &clock, {procedure = credential_probe_allocate, data = &probe}).kind,
		.None,
	)
	held, held_error := credential_lease(&cache)
	testing.expect(t, held_error.kind == .None && held.secret_key == "old-secret")
	clock.now = time.time_add(expires, -CREDENTIAL_EXPIRY_SKEW)
	failed, failed_error := credential_lease(&cache)
	testing.expect_value(t, failed_error.kind, .Unavailable)
	testing.expect_value(t, failed_error.source, .ECS)
	testing.expect(
		t,
		failed.snapshot == nil && failed.access_key == "" && failed.secret_key == "" && failed.session_token == "",
	)
	testing.expect_value(t, http.calls, 2)
	testing.expect(
		t,
		held.access_key == "old-key" && held.secret_key == "old-secret" && held.session_token == "old-token",
	)
	testing.expect_value(t, credential_cache_destroy(&cache).kind, .Busy)
	testing.expect(t, !probe.visible && probe.frees == 0, "a live reader keeps the snapshot allocated")
	credential_lease_release(&cache, &held)
	testing.expect(t, !probe.visible, "retired secret bytes are wiped before free")
	testing.expect(t, probe.frees > 0)
	testing.expect_value(t, credential_cache_destroy(&cache).kind, .None)
}

@(test)
credential_cancelled_waiter_does_not_receive_the_snapshot :: proc(t: ^testing.T) {
	saved := credential_test_env_push()
	defer credential_test_env_pop(saved)
	directory, error := os.make_directory_temp("", "aws-cache-cancel-*", context.allocator)
	testing.expect(t, error == nil)
	defer delete(directory)
	defer os.remove(directory)
	credential_test_absent(directory)
	testing.expect(t, os.set_env("AWS_CONTAINER_CREDENTIALS_RELATIVE_URI", "/v2/credentials/fixture") == nil)
	clock := Credential_Test_Clock {
		now = credential_test_instant("2023-12-01T00:00:00Z"),
	}

	http := Credential_Test_HTTP {
		body  = CREDENTIAL_TEST_OLD,
		block = true,
	}

	credential_test_http_state = &http
	defer credential_test_http_state = nil
	cache: Credential_Cache
	testing.expect_value(t, credential_test_cache(&cache, &clock).kind, .None)
	defer {
		credential_cache_destroy(&cache)
	}

	leader := Credential_Test_Call {
		cache = &cache,
	}

	leader_thread := thread.create_and_start_with_poly_data(&leader, credential_test_call)
	testing.expect(t, leader_thread != nil)
	testing.expect(
		t,
		credential_test_wait_until(credential_test_provider_entered),
		"refresh entered the fake provider",
	)
	cancel := Credential_Cancel{}
	waiter := Credential_Test_Call {
		cache  = &cache,
		cancel = &cancel,
	}

	other := Credential_Test_Call {
		cache = &cache,
	}

	waiter_thread := thread.create_and_start_with_poly_data(&waiter, credential_test_call)
	other_thread := thread.create_and_start_with_poly_data(&other, credential_test_call)
	testing.expect(t, waiter_thread != nil && other_thread != nil)
	credential_test_cache_state = &cache
	credential_test_waiters_target = 2
	defer credential_test_cache_state = nil
	testing.expect(
		t,
		credential_test_wait_until(credential_test_waiters_reached),
		"both followers wait on the one refresh",
	)
	credential_cancel(&cache, &cancel)
	sync.mutex_lock(&http.mutex)
	http.release = true
	sync.cond_broadcast(&http.cond)
	sync.mutex_unlock(&http.mutex)
	thread.join(leader_thread)
	thread.destroy(leader_thread)
	thread.join(waiter_thread)
	thread.destroy(waiter_thread)
	thread.join(other_thread)
	thread.destroy(other_thread)
	testing.expect_value(t, http.calls, 1)
	testing.expect_value(t, waiter.error.kind, .Cancelled)
	testing.expect(
		t,
		waiter.lease.snapshot == nil &&
		waiter.lease.access_key == "" &&
		waiter.lease.secret_key == "" &&
		waiter.lease.session_token == "",
	)
	testing.expect(t, leader.error.kind == .None && other.error.kind == .None)
	testing.expect(t, leader.lease.secret_key == "old-secret" && other.lease.secret_key == "old-secret")
	testing.expect(t, leader.lease.access_key == "old-key" && other.lease.session_token == "old-token")
	sync.mutex_lock(&cache.mutex)
	readers := 0

	if cache.snapshot != nil {
		readers = cache.snapshot.readers
	}

	sync.mutex_unlock(&cache.mutex)
	testing.expect_value(t, readers, 2)
	credential_lease_release(&cache, &leader.lease)
	credential_lease_release(&cache, &other.lease)
}

@(test)
credential_waiter_limit_does_not_hand_out_credentials :: proc(t: ^testing.T) {
	saved := credential_test_env_push()
	defer credential_test_env_pop(saved)
	directory, error := os.make_directory_temp("", "aws-cache-bound-*", context.allocator)
	testing.expect(t, error == nil)
	defer delete(directory)
	defer os.remove(directory)
	credential_test_absent(directory)
	testing.expect(t, os.set_env("AWS_CONTAINER_CREDENTIALS_RELATIVE_URI", "/v2/credentials/fixture") == nil)
	clock := Credential_Test_Clock {
		now = credential_test_instant("2023-12-01T00:00:00Z"),
	}

	http := Credential_Test_HTTP {
		body  = CREDENTIAL_TEST_OLD,
		block = true,
	}

	credential_test_http_state = &http
	defer credential_test_http_state = nil
	cache: Credential_Cache
	testing.expect_value(t, credential_test_cache(&cache, &clock).kind, .None)
	leader := Credential_Test_Call {
		cache = &cache,
	}

	leader_thread := thread.create_and_start_with_poly_data(&leader, credential_test_call)
	testing.expect(t, leader_thread != nil)
	testing.expect(t, credential_test_wait_until(credential_test_provider_entered))
	waiters: [CREDENTIAL_WAITERS_MAX]Credential_Test_Call
	workers: [CREDENTIAL_WAITERS_MAX]^thread.Thread

	for index in 0 ..< CREDENTIAL_WAITERS_MAX {
		waiters[index].cache = &cache
		workers[index] = thread.create_and_start_with_poly_data(&waiters[index], credential_test_call)
		testing.expect(t, workers[index] != nil)
	}

	credential_test_cache_state = &cache
	credential_test_waiters_target = CREDENTIAL_WAITERS_MAX
	defer credential_test_cache_state = nil

	if testing.expect(t, credential_test_wait_until(credential_test_waiters_reached)) {
		limited, limit_error := credential_lease(&cache)
		testing.expect_value(t, limit_error.kind, .Waiter_Limit)
		testing.expect(
			t,
			limited.snapshot == nil &&
			limited.secret_key == "" &&
			limited.access_key == "" &&
			limited.session_token == "",
		)
		testing.expect_value(t, http.calls, 1)
	}

	sync.mutex_lock(&http.mutex)
	http.release = true
	sync.cond_broadcast(&http.cond)
	sync.mutex_unlock(&http.mutex)
	thread.join(leader_thread)
	thread.destroy(leader_thread)

	for worker in workers {
		thread.join(worker)
		thread.destroy(worker)
	}

	testing.expect(t, leader.error.kind == .None && leader.lease.secret_key == "old-secret")
	credential_lease_release(&cache, &leader.lease)

	for &waiter in waiters {
		testing.expect(t, waiter.error.kind == .None && waiter.lease.secret_key == "old-secret")
		credential_lease_release(&cache, &waiter.lease)
	}

	testing.expect_value(t, credential_cache_destroy(&cache).kind, .None)
	testing.expect_value(t, http.calls, 1)
}

@(test)
credential_static_sources_cache_and_fail_closed :: proc(t: ^testing.T) {
	saved := credential_test_env_push()
	defer credential_test_env_pop(saved)
	directory, error := os.make_directory_temp("", "aws-cache-static-*", context.allocator)
	testing.expect(t, error == nil)
	defer delete(directory)
	defer os.remove(directory)
	credential_test_absent(directory)
	testing.expect(t, os.set_env("AWS_ACCESS_KEY_ID", "env-key") == nil)
	testing.expect(t, os.set_env("AWS_SECRET_ACCESS_KEY", "env-secret") == nil)
	clock := Credential_Test_Clock {
		now = credential_test_instant("2024-01-01T00:00:00Z"),
	}

	http := Credential_Test_HTTP {
		body = CREDENTIAL_TEST_OLD,
	}

	credential_test_http_state = &http
	defer credential_test_http_state = nil
	cache: Credential_Cache
	testing.expect_value(t, credential_test_cache(&cache, &clock).kind, .None)
	defer credential_cache_destroy(&cache)
	lease, lease_error := credential_lease(&cache)
	defer credential_lease_release(&cache, &lease)
	testing.expect(t, lease_error.kind == .None && lease.source == .Environment && !lease.has_expiry)
	testing.expect(t, lease.access_key == "env-key" && lease.secret_key == "env-secret" && lease.session_token == "")
	testing.expect(t, os.set_env("AWS_ACCESS_KEY_ID", "rotated-key") == nil)
	again, again_error := credential_lease(&cache)
	testing.expect(t, again_error.kind == .None && again.access_key == "env-key")
	credential_lease_release(&cache, &again)
	rotated, rotated_ok := aws_credentials_with_http(credential_test_http)
	testing.expect(t, rotated_ok && rotated.access_key == "rotated-key")
	testing.expect_value(t, http.calls, 0)

	credential_lease_release(&cache, &lease)
	testing.expect_value(t, credential_cache_destroy(&cache).kind, .None)
	testing.expect(t, os.unset_env("AWS_ACCESS_KEY_ID"))
	testing.expect(t, os.unset_env("AWS_SECRET_ACCESS_KEY"))
	testing.expect(t, os.unset_env("AWS_SESSION_TOKEN"))
	testing.expect(t, os.set_env("AWS_ACCESS_KEY_ID", "partial-key") == nil)
	path := fmt.aprintf("%s/credentials", directory)
	defer delete(path)
	defer os.remove(path)
	profile := "[default]\naws_access_key_id=profile-key\naws_secret_access_key=profile-secret\n"
	testing.expect(t, os.write_entire_file(path, profile) == nil)
	testing.expect(t, os.set_env("AWS_SHARED_CREDENTIALS_FILE", path) == nil)
	testing.expect(t, os.set_env("AWS_CONTAINER_CREDENTIALS_RELATIVE_URI", "/v2/credentials/fixture") == nil)
	partial_cache: Credential_Cache
	testing.expect_value(t, credential_test_cache(&partial_cache, &clock).kind, .None)
	defer credential_cache_destroy(&partial_cache)
	partial, partial_error := credential_lease(&partial_cache)
	credential_lease_release(&partial_cache, &partial)
	testing.expect_value(t, partial_error.kind, .Incomplete)
	testing.expect_value(t, partial_error.source, .Environment)
	testing.expect(t, partial.secret_key == "" && http.calls == 0)

	testing.expect(t, os.unset_env("AWS_ACCESS_KEY_ID"))
	profile_cache: Credential_Cache
	testing.expect_value(t, credential_test_cache(&profile_cache, &clock).kind, .None)
	defer credential_cache_destroy(&profile_cache)
	loaded, loaded_error := credential_lease(&profile_cache)
	testing.expect(t, loaded_error.kind == .None && loaded.source == .Profile && loaded.access_key == "profile-key")
	testing.expect(
		t,
		os.write_entire_file(
			path,
			"[default]\naws_access_key_id=changed-key\naws_secret_access_key=changed-secret\n",
		) ==
		nil,
	)
	cached, cached_error := credential_lease(&profile_cache)
	testing.expect(t, cached_error.kind == .None && cached.access_key == "profile-key" && http.calls == 0)
	credential_lease_release(&profile_cache, &cached)
	credential_lease_release(&profile_cache, &loaded)
}

@(test)
credential_unsupported_modes_are_typed_and_not_fetched :: proc(t: ^testing.T) {
	saved := credential_test_env_push()
	defer credential_test_env_pop(saved)
	directory, error := os.make_directory_temp("", "aws-cache-refuse-*", context.allocator)
	testing.expect(t, error == nil)
	defer delete(directory)
	defer os.remove(directory)
	credential_test_absent(directory)
	clock := Credential_Test_Clock {
		now = credential_test_instant("2023-12-01T00:00:00Z"),
	}

	http := Credential_Test_HTTP {
		body = CREDENTIAL_TEST_OLD,
	}

	credential_test_http_state = &http
	defer credential_test_http_state = nil

	expect_refused :: proc(
		t: ^testing.T,
		clock: ^Credential_Test_Clock,
		http: ^Credential_Test_HTTP,
		unsupported: Credential_Unsupported,
		source: Credential_Source,
	) {
		cache: Credential_Cache
		testing.expect_value(t, credential_test_cache(&cache, clock).kind, .None)
		defer credential_cache_destroy(&cache)
		before := http.calls
		lease, lease_error := credential_lease(&cache)
		credential_lease_release(&cache, &lease)
		testing.expect_value(t, lease_error.kind, .Unsupported)
		testing.expect_value(t, lease_error.unsupported, unsupported)
		testing.expect_value(t, lease_error.source, source)
		testing.expect(t, lease.snapshot == nil && lease.secret_key == "")
		testing.expect_value(t, http.calls, before)
		testing.expect(t, http.rejected == "")
	}

	testing.expect(t, os.set_env("AWS_WEB_IDENTITY_TOKEN_FILE", "/tmp/not-read") == nil)
	testing.expect(t, os.set_env("AWS_ROLE_ARN", "arn:aws:iam::1:role/refused") == nil)
	expect_refused(t, &clock, &http, .Web_Identity, .Environment)
	os.unset_env("AWS_WEB_IDENTITY_TOKEN_FILE")
	os.unset_env("AWS_ROLE_ARN")

	path := fmt.aprintf("%s/credentials", directory)
	defer delete(path)
	defer os.remove(path)
	testing.expect(t, os.set_env("AWS_SHARED_CREDENTIALS_FILE", path) == nil)
	cases := []struct {
		text:        string,
		unsupported: Credential_Unsupported,
	} {
		{"[default]\nsso_start_url=https://example.awsapps.com/start\nsso_account_id=1\nsso_role_name=role\n", .SSO},
		{"[default]\ncredential_process=/usr/bin/false\n", .Credential_Process},
		{
			"[default]\nrole_arn=arn:aws:iam::1:role/refused\nsource_profile=default\naws_access_key_id=should-not-leak\naws_secret_access_key=should-not-leak\n",
			.Assumed_Role,
		},
	}

	for item in cases {
		testing.expect(t, os.write_entire_file(path, item.text) == nil)
		expect_refused(t, &clock, &http, item.unsupported, .Profile)
	}

	os.unset_env("AWS_SHARED_CREDENTIALS_FILE")
	credential_test_absent(directory)
	testing.expect(t, os.set_env("AWS_CONTAINER_CREDENTIALS_FULL_URI", "http://127.0.0.1/creds") == nil)
	testing.expect(t, os.set_env("AWS_CONTAINER_CREDENTIALS_RELATIVE_URI", "/v2/credentials/fixture") == nil)
	expect_refused(t, &clock, &http, .ECS_Full_URI, .ECS)
	testing.expect_value(t, http.calls, 0)
}

@(test)
credential_metadata_probe_is_explicit :: proc(t: ^testing.T) {
	saved := credential_test_env_push()
	defer credential_test_env_pop(saved)
	directory, error := os.make_directory_temp("", "aws-cache-probe-*", context.allocator)
	testing.expect(t, error == nil)
	defer delete(directory)
	defer os.remove(directory)
	credential_test_absent(directory)
	clock := Credential_Test_Clock {
		now = time.time_add(credential_test_instant("2024-01-01T00:00:00Z"), -CREDENTIAL_EXPIRY_SKEW - 1),
	}

	http := Credential_Test_HTTP {
		body = CREDENTIAL_TEST_OLD,
		ec2  = true,
	}

	credential_test_http_state = &http
	defer credential_test_http_state = nil

	without_ec2: Credential_Cache
	testing.expect_value(
		t,
		credential_cache_init(&without_ec2, credential_test_http, credential_test_clock, &clock, {.Environment, .Profile, .ECS}).kind,
		.None,
	)
	testing.expect(t, os.unset_env("AWS_EC2_METADATA_DISABLED"))
	testing.expect(t, !credential_ec2_probe_permitted({.Environment, .Profile, .ECS}))
	missing, missing_error := credential_lease(&without_ec2)
	credential_lease_release(&without_ec2, &missing)
	testing.expect_value(t, missing_error.kind, .Unavailable)
	testing.expect_value(t, http.calls, 0)
	testing.expect_value(t, credential_cache_destroy(&without_ec2).kind, .None)

	testing.expect(t, os.set_env("AWS_EC2_METADATA_DISABLED", "true") == nil)
	testing.expect(t, !credential_ec2_probe_permitted(CREDENTIAL_MODES_SUPPORTED))
	disabled: Credential_Cache
	testing.expect_value(t, credential_test_cache(&disabled, &clock).kind, .None)
	disabled_lease, disabled_error := credential_lease(&disabled)
	credential_lease_release(&disabled, &disabled_lease)
	testing.expect_value(t, disabled_error.kind, .Unavailable)
	testing.expect_value(t, http.calls, 0)
	credential_cache_destroy(&disabled)

	testing.expect(t, os.unset_env("AWS_EC2_METADATA_DISABLED"))
	testing.expect(t, credential_ec2_probe_permitted(CREDENTIAL_MODES_SUPPORTED))
	probed: Credential_Cache
	testing.expect_value(t, credential_test_cache(&probed, &clock).kind, .None)
	defer credential_cache_destroy(&probed)
	lease, lease_error := credential_lease(&probed)
	defer credential_lease_release(&probed, &lease)
	testing.expect(t, lease_error.kind == .None && lease.source == .EC2 && lease.secret_key == "old-secret")
	testing.expect_value(t, http.calls, 3)
	testing.expect(t, http.rejected == "")
	again, again_error := credential_lease(&probed)
	credential_lease_release(&probed, &again)
	testing.expect(t, again_error.kind == .None && http.calls == 3)
	clock.now = credential_test_instant("2024-01-01T00:00:00Z")
	http.next_body = CREDENTIAL_TEST_NEW
	refreshed, refresh_error := credential_lease(&probed)
	defer credential_lease_release(&probed, &refreshed)
	testing.expect(t, refresh_error.kind == .None && refreshed.secret_key == "new-secret" && http.calls == 6)
	testing.expect(
		t,
		lease.secret_key == "old-secret" && lease.access_key == "old-key" && lease.session_token == "old-token",
	)
}

@(test)
credential_expired_document_is_not_cached :: proc(t: ^testing.T) {
	saved := credential_test_env_push()
	defer credential_test_env_pop(saved)
	directory, error := os.make_directory_temp("", "aws-cache-expired-*", context.allocator)
	testing.expect(t, error == nil)
	defer delete(directory)
	defer os.remove(directory)
	credential_test_absent(directory)
	testing.expect(t, os.set_env("AWS_CONTAINER_CREDENTIALS_RELATIVE_URI", "/v2/credentials/fixture") == nil)
	clock := Credential_Test_Clock {
		now = credential_test_instant("2024-02-01T00:00:00Z"),
	}

	http := Credential_Test_HTTP {
		body = CREDENTIAL_TEST_OLD,
	}

	credential_test_http_state = &http
	defer credential_test_http_state = nil
	cache: Credential_Cache
	testing.expect_value(t, credential_test_cache(&cache, &clock).kind, .None)
	defer credential_cache_destroy(&cache)
	lease, lease_error := credential_lease(&cache)
	credential_lease_release(&cache, &lease)
	testing.expect_value(t, lease_error.kind, .Expired)
	testing.expect(t, lease.secret_key == "")
	again, again_error := credential_lease(&cache)
	credential_lease_release(&cache, &again)
	testing.expect_value(t, again_error.kind, .Expired)
	testing.expect_value(t, http.calls, 2)
	testing.expect(t, http.rejected == "")
}

@(test)
credential_refresh_replaces_ahead_of_expiry_and_cached_leases_never_fetch :: proc(t: ^testing.T) {
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
		body      = CREDENTIAL_TEST_OLD,
		next_body = CREDENTIAL_TEST_NEW,
	}
	credential_test_http_state = &http
	defer credential_test_http_state = nil
	cache: Credential_Cache
	testing.expect_value(t, credential_test_cache(&cache, &clock).kind, .None)
	defer credential_cache_destroy(&cache)

	// A cold cache gives a request handler nothing and contacts nobody.
	_, cold := credential_lease_cached(&cache)
	testing.expect_value(t, cold.kind, Credential_Error_Kind.Unavailable)
	testing.expect_value(t, http.calls, 0)

	testing.expect_value(t, credential_refresh(&cache).kind, Credential_Error_Kind.None)
	testing.expect_value(t, http.calls, 1)
	first, first_error := credential_lease_cached(&cache)
	defer credential_lease_release(&cache, &first)
	testing.expect(t, first_error.kind == .None && first.secret_key == "old-secret")

	// Outside the margin a refresh is a no-op.
	testing.expect_value(t, credential_refresh(&cache).kind, Credential_Error_Kind.None)
	testing.expect_value(t, http.calls, 1)

	// Inside the margin, a failing provider leaves the usable credentials in place.
	clock.now = time.time_add(expires, -time.Minute)
	http.fail = true
	testing.expect_value(t, credential_refresh(&cache).kind, Credential_Error_Kind.Unavailable)
	testing.expect_value(t, http.calls, 2)
	kept, kept_error := credential_lease_cached(&cache)
	testing.expect(t, kept_error.kind == .None && kept.secret_key == "old-secret")
	credential_lease_release(&cache, &kept)

	// The next attempt publishes new credentials before the old ones expire.
	http.fail = false
	testing.expect_value(t, credential_refresh(&cache).kind, Credential_Error_Kind.None)
	testing.expect_value(t, http.calls, 3)
	second, second_error := credential_lease_cached(&cache)
	defer credential_lease_release(&cache, &second)
	testing.expect(t, second_error.kind == .None && second.secret_key == "new-secret")
	testing.expect(t, first.secret_key == "old-secret", "a held lease keeps its own triple")
	testing.expect_value(t, http.calls, 3)

	// Past expiry with no refresh, a cached lease reports it and still does no I/O.
	clock.now = credential_test_instant("2024-06-01T00:00:00Z")
	_, expired := credential_lease_cached(&cache)
	testing.expect_value(t, expired.kind, Credential_Error_Kind.Expired)
	testing.expect_value(t, expired.source, Credential_Source.ECS)
	testing.expect_value(t, http.calls, 3)
	testing.expect_value(t, credential_refresh(&cache, -time.Second).kind, Credential_Error_Kind.Invalid_Argument)
}

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
credentials_must_be_visible_ascii :: proc(t: ^testing.T) {
	testing.expect(t, aws_credentials_valid({"fixture-key", "fixture/secret+value", "token/with+base64=="}))
	testing.expect(t, aws_credentials_valid({"fixture-key", "fixture-secret", ""}))
	for value in ([]AWS_Credentials {
			{"key\tx", "secret", ""},
			{"key", "sec\x01ret", ""},
			{"key", "secret", "tok\x7fen"},
			{"key", "secret", "tok\ren"},
			{"key\x00", "secret", ""},
			{"key ", "secret", ""},
			{"key", " secret", ""},
			{"key", "secret", "token "},
			{"key", "sec ret", ""},
			{"key", "secret", "tokén"},
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
	http.body = CREDENTIAL_TEST_FAR
	credentials, ok := aws_credentials_with_http(credential_test_http)
	testing.expect(t, ok && credentials.secret_key == "far-secret")
	testing.expect_value(t, http.calls, 1)
}

@(test)
uncached_resolution_applies_the_cache_rules :: proc(t: ^testing.T) {
	saved := credential_test_env_push()
	defer credential_test_env_pop(saved)
	directory, directory_error := os.make_directory_temp("", "aws-cache-*", context.allocator)
	testing.expect(t, directory_error == nil)
	defer delete(directory)
	defer os.remove(directory)
	credential_test_absent(directory)
	http: Credential_Test_HTTP
	credential_test_http_state = &http
	defer credential_test_http_state = nil
	testing.expect(t, os.set_env("AWS_CONTAINER_CREDENTIALS_RELATIVE_URI", "/v2/credentials/fixture") == nil)

	// Documents that are not a successful answer, or carry no future expiry.
	for body in ([]string {
			`{"Code":"Failure","AccessKeyId":"far-key","SecretAccessKey":"far-secret","Token":"far-token","Expiration":"2099-01-01T00:00:00Z"}`,
			`{"Code":"Success","AccessKeyId":"far-key","SecretAccessKey":"far-secret","Token":"far-token"}`,
			`{"Code":"Success","AccessKeyId":"far-key","SecretAccessKey":"far-secret","Token":"far-token","Expiration":"2020-01-01T00:00:00Z"}`,
		}) {
		http = {
			body = body,
		}
		_, ok := aws_credentials_with_http(credential_test_http)
		testing.expect(t, !ok, body)
		testing.expect_value(t, http.calls, 1)
	}

	// Unsupported mechanisms are refused, not skipped in favour of the metadata service.
	http = {
		body = CREDENTIAL_TEST_FAR,
	}
	testing.expect(t, os.set_env("AWS_WEB_IDENTITY_TOKEN_FILE", "/nonexistent/token") == nil)
	_, web_identity_ok := aws_credentials_with_http(credential_test_http)
	testing.expect(t, !web_identity_ok)
	testing.expect_value(t, http.calls, 0)
	testing.expect(t, os.unset_env("AWS_WEB_IDENTITY_TOKEN_FILE"))

	testing.expect(t, os.set_env("AWS_CONTAINER_CREDENTIALS_FULL_URI", "http://169.254.170.2/v2/credentials/fixture") == nil)
	_, full_uri_ok := aws_credentials_with_http(credential_test_http)
	testing.expect(t, !full_uri_ok)
	testing.expect_value(t, http.calls, 0)
	testing.expect(t, os.unset_env("AWS_CONTAINER_CREDENTIALS_FULL_URI"))

	path := fmt.aprintf("%s/credentials", directory)
	defer delete(path)
	defer os.remove(path)
	profile := "[default]\naws_access_key_id = role-key\naws_secret_access_key = role-secret\nrole_arn = arn:aws:iam::000000000000:role/example\n"
	testing.expect(t, os.write_entire_file(path, profile) == nil)
	testing.expect(t, os.set_env("AWS_SHARED_CREDENTIALS_FILE", path) == nil)
	_, role_ok := aws_credentials_with_http(credential_test_http)
	testing.expect(t, !role_ok)
	testing.expect_value(t, http.calls, 0)
	testing.expect(t, os.set_env("AWS_SHARED_CREDENTIALS_FILE", fmt.tprintf("%s/absent", directory)) == nil)

	// Environment credentials obey their exported expiry and the length bounds.
	testing.expect(t, os.set_env("AWS_ACCESS_KEY_ID", "env-key") == nil)
	testing.expect(t, os.set_env("AWS_SECRET_ACCESS_KEY", "env-secret") == nil)
	testing.expect(t, os.set_env("AWS_CREDENTIAL_EXPIRATION", "2020-01-01T00:00:00Z") == nil)
	_, expired_ok := aws_credentials_with_http(credential_test_http)
	testing.expect(t, !expired_ok)
	testing.expect(t, os.unset_env("AWS_CREDENTIAL_EXPIRATION"))

	long_secret := strings.repeat("s", CREDENTIAL_SECRET_MAX + 1)
	defer delete(long_secret)
	testing.expect(t, os.set_env("AWS_SECRET_ACCESS_KEY", long_secret) == nil)
	_, long_ok := aws_credentials_with_http(credential_test_http)
	testing.expect(t, !long_ok)
	testing.expect_value(t, http.calls, 0)
	testing.expect(t, os.unset_env("AWS_ACCESS_KEY_ID"))
	testing.expect(t, os.unset_env("AWS_SECRET_ACCESS_KEY"))

	// The caller's copies outlive the snapshot the call erased.
	credentials, ok := aws_credentials_with_http(credential_test_http)
	testing.expect(t, ok)
	testing.expect_value(t, http.calls, 1)
	testing.expect_value(t, credentials.access_key, "far-key")
	testing.expect_value(t, credentials.secret_key, "far-secret")
	testing.expect_value(t, credentials.session_token, "far-token")
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

@(test)
credential_rejected_documents_are_not_cached :: proc(t: ^testing.T) {
	saved := credential_test_env_push()
	defer credential_test_env_pop(saved)
	directory, error := os.make_directory_temp("", "aws-cache-reject-*", context.allocator)
	testing.expect(t, error == nil)
	defer delete(directory)
	defer os.remove(directory)
	credential_test_absent(directory)
	testing.expect(t, os.set_env("AWS_CONTAINER_CREDENTIALS_RELATIVE_URI", "/v2/credentials/fixture") == nil)
	long_access := strings.repeat("a", 129)
	defer delete(long_access)
	long_access_document := fmt.aprintf(
		`{{"Code":"Success","AccessKeyId":"%s","SecretAccessKey":"s","Token":"t","Expiration":"2024-01-01T00:00:00Z"}}`,
		long_access,
	)
	defer delete(long_access_document)
	documents := [?]string {
		`{"Code":"Failure","AccessKeyId":"k","SecretAccessKey":"s","Token":"t","Expiration":"2024-01-01T00:00:00Z"}`,
		`{bad`,
		long_access_document,
		`{"Code":"Success","AccessKeyId":"k","SecretAccessKey":"sec\u0001ret","Token":"t","Expiration":"2024-01-01T00:00:00Z"}`,
		`{"Code":"Success","AccessKeyId":"k","SecretAccessKey":"s","Token":"t"}`,
		`{"Code":"Success","AccessKeyId":"k","SecretAccessKey":"s","Token":"t","Expiration":"2024-01-01"}`,
	}

	for document, index in documents {
		clock := Credential_Test_Clock {
			now = credential_test_instant("2023-12-01T00:00:00Z"),
		}

		http := Credential_Test_HTTP {
			body = document,
		}

		credential_test_http_state = &http
		cache: Credential_Cache
		testing.expect_value(t, credential_test_cache(&cache, &clock).kind, .None)
		refresh_error := credential_refresh(&cache)
		testing.expectf(
			t,
			refresh_error == Credential_Error{kind = .Unavailable, source = .ECS},
			"document %d: refresh returned %v",
			index,
			refresh_error,
		)
		cached, cached_error := credential_lease_cached(&cache)
		testing.expectf(t, cached_error.kind == .Unavailable, "document %d: nothing is published", index)
		testing.expect(t, cached.snapshot == nil && cached.secret_key == "")
		testing.expect_value(t, http.calls, 1)
		testing.expect_value(t, http.rejected, "")
		testing.expect_value(t, credential_cache_destroy(&cache).kind, .None)
		credential_test_http_state = nil
	}
}

@(test)
credential_rejected_role_names_stop_before_the_document :: proc(t: ^testing.T) {
	saved := credential_test_env_push()
	defer credential_test_env_pop(saved)
	directory, error := os.make_directory_temp("", "aws-cache-role-*", context.allocator)
	testing.expect(t, error == nil)
	defer delete(directory)
	defer os.remove(directory)
	credential_test_absent(directory)
	testing.expect(t, os.unset_env("AWS_EC2_METADATA_DISABLED"))
	long_role := strings.repeat("r", 129)
	defer delete(long_role)
	// The fake answers its default role for an empty string, so an empty role
	// is a bare newline, which the resolver trims to nothing.
	roles := [?]string{"\n", "a/b", "a?b", "a#b", "a\\b", "a@b", "role\tname", long_role}

	for role, index in roles {
		clock := Credential_Test_Clock {
			now = credential_test_instant("2023-12-01T00:00:00Z"),
		}

		http := Credential_Test_HTTP {
			body = CREDENTIAL_TEST_OLD,
			ec2  = true,
			role = role,
		}

		credential_test_http_state = &http
		cache: Credential_Cache
		testing.expect_value(t, credential_test_cache(&cache, &clock).kind, .None)
		refresh_error := credential_refresh(&cache)
		testing.expectf(
			t,
			refresh_error == Credential_Error{kind = .Unavailable, source = .EC2},
			"role %d: refresh returned %v",
			index,
			refresh_error,
		)
		testing.expectf(t, http.calls == 2, "role %d: %d requests, want token and role list only", index, http.calls)
		testing.expect_value(t, http.rejected, "")
		testing.expect_value(t, credential_cache_destroy(&cache).kind, .None)
		credential_test_http_state = nil
	}
}

@(test)
credential_profile_read_errors_stop_resolution :: proc(t: ^testing.T) {
	saved := credential_test_env_push()
	defer credential_test_env_pop(saved)
	directory, error := os.make_directory_temp("", "aws-cache-profile-error-*", context.allocator)
	testing.expect(t, error == nil)
	defer delete(directory)
	defer os.remove(directory)
	credential_test_absent(directory)
	testing.expect(t, os.set_env("AWS_CONTAINER_CREDENTIALS_RELATIVE_URI", "/v2/credentials/fixture") == nil)
	path := fmt.aprintf("%s/credentials", directory)
	defer delete(path)
	defer os.remove(path)
	large := make([]u8, 64 * 1024 + 1)
	defer delete(large)
	testing.expect(t, os.write_entire_file(path, large) == nil)
	clock := Credential_Test_Clock {
		now = credential_test_instant("2023-12-01T00:00:00Z"),
	}

	http := Credential_Test_HTTP {
		body = CREDENTIAL_TEST_OLD,
	}

	credential_test_http_state = &http
	defer credential_test_http_state = nil
	expected := Credential_Error {
		kind   = .Unavailable,
		source = .Profile,
	}

	// A profile file over the size limit.
	testing.expect(t, os.set_env("AWS_SHARED_CREDENTIALS_FILE", path) == nil)
	oversized: Credential_Cache
	testing.expect_value(t, credential_test_cache(&oversized, &clock).kind, .None)
	testing.expect_value(t, credential_refresh(&oversized), expected)
	testing.expect_value(t, http.calls, 0)
	testing.expect_value(t, credential_cache_destroy(&oversized).kind, .None)

	// Plan 007 changes this case: a path that is not a regular file will be
	// skipped like a missing file, and ECS answers.
	testing.expect(t, os.set_env("AWS_SHARED_CREDENTIALS_FILE", directory) == nil)
	not_a_file: Credential_Cache
	testing.expect_value(t, credential_test_cache(&not_a_file, &clock).kind, .None)
	testing.expect_value(t, credential_refresh(&not_a_file), expected)
	testing.expect_value(t, http.calls, 0)
	testing.expect_value(t, credential_cache_destroy(&not_a_file).kind, .None)
}

@(test)
credential_waiter_receives_the_leaders_failure :: proc(t: ^testing.T) {
	saved := credential_test_env_push()
	defer credential_test_env_pop(saved)
	directory, error := os.make_directory_temp("", "aws-cache-leader-fail-*", context.allocator)
	testing.expect(t, error == nil)
	defer delete(directory)
	defer os.remove(directory)
	credential_test_absent(directory)
	testing.expect(t, os.set_env("AWS_CONTAINER_CREDENTIALS_RELATIVE_URI", "/v2/credentials/fixture") == nil)
	clock := Credential_Test_Clock {
		now = credential_test_instant("2023-12-01T00:00:00Z"),
	}

	http := Credential_Test_HTTP {
		body  = `{"Code":"Failure","AccessKeyId":"k","SecretAccessKey":"s","Token":"t","Expiration":"2024-01-01T00:00:00Z"}`,
		block = true,
	}

	credential_test_http_state = &http
	defer credential_test_http_state = nil
	cache: Credential_Cache
	testing.expect_value(t, credential_test_cache(&cache, &clock).kind, .None)
	defer credential_cache_destroy(&cache)
	leader := Credential_Test_Call {
		cache = &cache,
	}

	leader_thread := thread.create_and_start_with_poly_data(&leader, credential_test_call)
	testing.expect(t, leader_thread != nil)
	testing.expect(
		t,
		credential_test_wait_until(credential_test_provider_entered),
		"refresh entered the fake provider",
	)
	testing.expect_value(t, credential_refresh(&cache), Credential_Error{kind = .Busy})
	waiter := Credential_Test_Call {
		cache = &cache,
	}

	waiter_thread := thread.create_and_start_with_poly_data(&waiter, credential_test_call)
	testing.expect(t, waiter_thread != nil)
	credential_test_cache_state = &cache
	credential_test_waiters_target = 1
	defer credential_test_cache_state = nil
	testing.expect(
		t,
		credential_test_wait_until(credential_test_waiters_reached),
		"the waiter waits on the leader's refresh",
	)
	sync.mutex_lock(&http.mutex)
	http.release = true
	sync.cond_broadcast(&http.cond)
	sync.mutex_unlock(&http.mutex)
	thread.join(leader_thread)
	thread.destroy(leader_thread)
	thread.join(waiter_thread)
	thread.destroy(waiter_thread)
	testing.expect_value(t, http.calls, 1)
	expected := Credential_Error {
		kind   = .Unavailable,
		source = .ECS,
	}

	testing.expect_value(t, leader.error, expected)
	testing.expect_value(t, waiter.error, expected)
	testing.expect(t, leader.lease.snapshot == nil && leader.lease.access_key == "" && leader.lease.secret_key == "")
	testing.expect(t, waiter.lease.snapshot == nil && waiter.lease.access_key == "" && waiter.lease.secret_key == "")
	testing.expect(t, leader.lease.session_token == "" && waiter.lease.session_token == "")
	testing.expect_value(t, credential_cache_destroy(&cache).kind, .None)
}

@(test)
credential_cancelled_and_closed_calls_do_no_io :: proc(t: ^testing.T) {
	saved := credential_test_env_push()
	defer credential_test_env_pop(saved)
	directory, error := os.make_directory_temp("", "aws-cache-closed-*", context.allocator)
	testing.expect(t, error == nil)
	defer delete(directory)
	defer os.remove(directory)
	credential_test_absent(directory)
	testing.expect(t, os.set_env("AWS_CONTAINER_CREDENTIALS_RELATIVE_URI", "/v2/credentials/fixture") == nil)
	clock := Credential_Test_Clock {
		now = credential_test_instant("2023-12-01T00:00:00Z"),
	}

	http := Credential_Test_HTTP {
		body = CREDENTIAL_TEST_OLD,
	}

	credential_test_http_state = &http
	defer credential_test_http_state = nil
	cache: Credential_Cache
	testing.expect_value(t, credential_test_cache(&cache, &clock).kind, .None)
	cancel := Credential_Cancel{}
	credential_cancel(&cache, &cancel)
	cancelled, cancelled_error := credential_lease(&cache, &cancel)
	testing.expect_value(t, cancelled_error.kind, .Cancelled)
	testing.expect(t, cancelled.snapshot == nil && cancelled.secret_key == "")
	testing.expect_value(t, http.calls, 0)
	testing.expect_value(t, credential_cache_destroy(&cache).kind, .None)
	cached, cached_error := credential_lease_cached(&cache)
	testing.expect_value(t, cached_error.kind, .Closed)
	testing.expect(t, cached.snapshot == nil)
	testing.expect_value(t, credential_refresh(&cache).kind, .Closed)
	closed, closed_error := credential_lease(&cache)
	testing.expect_value(t, closed_error.kind, .Closed)
	testing.expect(t, closed.snapshot == nil)
	testing.expect_value(t, http.calls, 0)
}

@(test)
credential_cache_init_refuses_bad_arguments :: proc(t: ^testing.T) {
	saved := credential_test_env_push()
	defer credential_test_env_pop(saved)
	directory, error := os.make_directory_temp("", "aws-cache-init-*", context.allocator)
	testing.expect(t, error == nil)
	defer delete(directory)
	defer os.remove(directory)
	credential_test_absent(directory)
	testing.expect(t, os.set_env("AWS_CONTAINER_CREDENTIALS_RELATIVE_URI", "/v2/credentials/fixture") == nil)
	clock := Credential_Test_Clock {
		now = credential_test_instant("2023-12-01T00:00:00Z"),
	}

	http := Credential_Test_HTTP {
		body = CREDENTIAL_TEST_OLD,
	}

	credential_test_http_state = &http
	defer credential_test_http_state = nil
	testing.expect_value(
		t,
		credential_cache_init(nil, credential_test_http, credential_test_clock, &clock).kind,
		.Invalid_Argument,
	)
	blank: Credential_Cache
	testing.expect_value(t, credential_cache_init(&blank, nil, credential_test_clock, &clock).kind, .Invalid_Argument)
	testing.expect_value(t, credential_cache_init(&blank, credential_test_http, nil, &clock).kind, .Invalid_Argument)
	testing.expect_value(
		t,
		credential_cache_init(&blank, credential_test_http, credential_test_clock, &clock, allocator = mem.Allocator{}).kind,
		.Invalid_Argument,
	)
	cache: Credential_Cache
	testing.expect_value(t, credential_test_cache(&cache, &clock).kind, .None)
	testing.expect_value(t, credential_refresh(&cache).kind, .None)
	testing.expect_value(t, credential_test_cache(&cache, &clock).kind, .Invalid_Argument)
	held, held_error := credential_lease_cached(&cache)
	testing.expect_value(t, held_error.kind, .None)
	testing.expect_value(t, held.secret_key, "old-secret")
	credential_lease_release(&cache, &held)
	testing.expect_value(t, credential_cache_destroy(&cache).kind, .None)
}

@(test)
credential_snapshot_allocation_failures_leave_nothing_behind :: proc(t: ^testing.T) {
	probe := Credential_Probe {
		backing = context.allocator,
		fail_at = 1,
	}

	allocator := mem.Allocator {
		procedure = credential_probe_allocate,
		data      = &probe,
	}

	expected := Credential_Error {
		kind   = .Allocation_Failed,
		source = .ECS,
	}

	snap, failure := credential_snapshot_new(allocator, .ECS, "k", "old-secret", "t", {}, false)
	testing.expect(t, snap == nil)
	testing.expect_value(t, failure, expected)
	testing.expect_value(t, probe.frees, 0)

	probe = {
		backing = context.allocator,
		fail_at = 2,
	}

	snap, failure = credential_snapshot_new(allocator, .ECS, "k", "old-secret", "t", {}, false)
	testing.expect(t, snap == nil)
	testing.expect_value(t, failure, expected)
	testing.expect_value(t, probe.frees, 1)
	testing.expect(t, !probe.visible, "the released storage was wiped")

	probe = {
		backing = context.allocator,
	}

	snap, failure = credential_snapshot_new(allocator, .ECS, "k", "old-secret", "t", {}, false)
	testing.expect_value(t, failure.kind, .None)
	testing.expect(t, snap != nil)
	owner := Credential_Cache {
		allocator = allocator,
	}

	credential_snapshot_erase(&owner, snap)
	testing.expect(t, !probe.visible, "the erased snapshot was wiped")
	testing.expect(t, probe.frees > 0, "the storage was released")
}
