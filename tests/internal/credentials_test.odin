package aws

import network_client "../surf"
import "core:fmt"
import "core:mem"
import "core:os"
import "core:sync"
import "core:testing"
import "core:thread"
import "core:time"

CREDENTIAL_TEST_OLD :: `{"Code":"Success","AccessKeyId":"old-key","SecretAccessKey":"old-secret","Token":"old-token","Expiration":"2024-01-01T00:00:00Z"}`
CREDENTIAL_TEST_NEW :: `{"Code":"Success","AccessKeyId":"new-key","SecretAccessKey":"new-secret","Token":"new-token","Expiration":"2024-06-01T00:00:00Z"}`
CREDENTIAL_TEST_KEYS :: [?]string {
	"AWS_ACCESS_KEY_ID",
	"AWS_SECRET_ACCESS_KEY",
	"AWS_SESSION_TOKEN",
	"AWS_PROFILE",
	"AWS_SHARED_CREDENTIALS_FILE",
	"AWS_CONTAINER_CREDENTIALS_RELATIVE_URI",
	"AWS_CONTAINER_CREDENTIALS_FULL_URI",
	"AWS_EC2_METADATA_DISABLED",
	"AWS_WEB_IDENTITY_TOKEN_FILE",
	"AWS_ROLE_ARN",
	"HOME",
}

Credential_Env_Slot :: struct {
	key, value: string,
	found:      bool,
}

// Environment is process-wide. Hold this across every synthetic test and its
// workers until pop has restored all keys, so parallel tests cannot mix sources.
@(private)
credential_test_env_mutex: sync.Mutex

credential_test_env_push :: proc() -> []Credential_Env_Slot {
	sync.mutex_lock(&credential_test_env_mutex)
	saved := make([]Credential_Env_Slot, len(CREDENTIAL_TEST_KEYS))

	for key, index in CREDENTIAL_TEST_KEYS {
		value, found := os.lookup_env(key, context.allocator)
		saved[index] = {
			key   = key,
			value = value,
			found = found,
		}

		os.unset_env(key)
	}

	return saved
}

credential_test_env_pop :: proc(saved: []Credential_Env_Slot) {
	if saved == nil {
		return
	}

	defer sync.mutex_unlock(&credential_test_env_mutex)

	for slot in saved {
		if slot.found {
			os.set_env(slot.key, slot.value)
		} else {
			os.unset_env(slot.key)
		}

		if slot.value != "" {
			delete(slot.value)
		}
	}

	delete(saved)
}

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
	next_body: string,
	rejected:  string,
	mutex:     sync.Mutex,
	cond:      sync.Cond,
}

credential_test_http_state: ^Credential_Test_HTTP

credential_test_http :: proc(
	method, url: string,
	body: []u8,
	headers: []string,
	ca_file: string,
	allow_http: bool,
	timeout_ms: i64,
	upload_file: ^os.File,
	upload_size: i64,
) -> (
	[]u8,
	network_client.Buffered_HTTP_Result,
) {
	state := credential_test_http_state
	state.calls += 1
	if !allow_http ||
	   timeout_ms != 1500 ||
	   upload_file != nil ||
	   upload_size != 0 ||
	   ca_file != "" ||
	   len(body) != 0 ||
	   !credential_metadata_url_permitted(url) {
		state.rejected = url
		return nil, {ok = false, status = 400}
	}
	_ = headers
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
		if method == "PUT" && url == "http://169.254.169.254/latest/api/token" {
			return transmute([]u8)string("imds-token"), {ok = true, status = 200}
		}

		if method == "GET" && url == "http://169.254.169.254/latest/meta-data/iam/security-credentials/" {
			return transmute([]u8)string("fixture-role\n"), {ok = true, status = 200}
		}

		if method != "GET" || url != "http://169.254.169.254/latest/meta-data/iam/security-credentials/fixture-role" {
			state.rejected = url
			return nil, {ok = false}
		}
	} else if method != "GET" || url != "http://169.254.170.2/v2/credentials/fixture" {
		state.rejected = url
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

credential_test_absent :: proc(directory: string) {
	os.set_env("HOME", directory)
	os.set_env("AWS_SHARED_CREDENTIALS_FILE", fmt.tprintf("%s/absent", directory))
	os.set_env("AWS_EC2_METADATA_DISABLED", "true")
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
	backing: mem.Allocator,
	visible: bool,
	frees:   int,
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
		now = time.unix(0, time.time_to_unix_nano(expires) - 1),
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
	clock.now = expires
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
		now = time.unix(0, time.time_to_unix_nano(expires) - 1),
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
	clock.now = expires
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
		now = time.unix(0, time.time_to_unix_nano(credential_test_instant("2024-01-01T00:00:00Z")) - 1),
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
