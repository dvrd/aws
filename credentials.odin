package aws

import files "../files"
import network_client "../surf"
import "core:encoding/json"
import "core:fmt"
import "core:mem"
import "core:os"
import "core:strings"
import "core:sync"
import "core:time"

// Uncached resolution. Strings borrow context.temp_allocator. No expiry and no cache:
// a later call observes environment changes. Incomplete configured material fails closed.
aws_credentials :: proc() -> (credentials: AWS_Credentials, ok: bool) {
	return aws_credentials_with_http(network_client.buffered_http_execute)
}

aws_credentials_with_http :: proc(
	http_execute: HTTP_Execute,
) -> (
	credentials: AWS_Credentials,
	ok: bool,
) {
	if http_execute == nil {
		return
	}

	credentials = {
		access_key    = os.get_env("AWS_ACCESS_KEY_ID", context.temp_allocator),
		secret_key    = os.get_env("AWS_SECRET_ACCESS_KEY", context.temp_allocator),
		session_token = os.get_env("AWS_SESSION_TOKEN", context.temp_allocator),
	}
	if credentials.access_key != "" ||
	   credentials.secret_key != "" ||
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
	if file_error.kind != .None && file_error.kind != .Open_Failed {
		return
	}
	if file_credentials.access_key != "" ||
	   file_credentials.secret_key != "" ||
	   file_credentials.session_token != "" {
		return file_credentials, aws_credentials_valid(file_credentials)
	}

	relative := os.get_env("AWS_CONTAINER_CREDENTIALS_RELATIVE_URI", context.temp_allocator)
	url, token := "", ""
	if relative != "" {
		// Same acceptance rule as before caching: one slash-prefixed path, no line breaks.
		if !strings.has_prefix(relative, "/") || strings.contains_any(relative, "\r\n#") do return
		url = fmt.tprintf("http://169.254.170.2%s", relative)
	} else {
		if os.get_env("AWS_EC2_METADATA_DISABLED", context.temp_allocator) == "true" do return
		reply, result := http_execute(
			"PUT",
			"http://169.254.169.254/latest/api/token",
			nil,
			{"X-aws-ec2-metadata-token-ttl-seconds: 60"},
			"",
			true,
			1500,
			nil,
			0,
		)
		if !result.ok do return
		token = string(reply)
		if token == "" || strings.contains_any(token, "\r\n") do return
		role, role_result := http_execute(
			"GET",
			"http://169.254.169.254/latest/meta-data/iam/security-credentials/",
			nil,
			{fmt.tprintf("X-aws-ec2-metadata-token: %s", token)},
			"",
			true,
			1500,
			nil,
			0,
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
	data, result := http_execute("GET", url, nil, headers, "", true, 1500, nil, 0)
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
) -> (
	credentials: AWS_Credentials,
	error: files.Read_Error,
) {
	credentials, _, _, error = credential_profile_load(path, profile, false)
	return
}

aws_credentials_valid :: proc(value: AWS_Credentials) -> bool {
	if value.access_key == "" || value.secret_key == "" do return false
	for text in ([]string{value.access_key, value.secret_key, value.session_token}) {
		if strings.contains_any(text, "\r\n\x00") do return false
	}
	return true
}

Credential_Clock :: proc(data: rawptr) -> time.Time

credential_clock_wall :: proc(_: rawptr) -> time.Time {
	return time.now()
}

// Enabled sources. Unsupported mechanisms are not members; they return a typed error.
Credential_Mode :: enum {
	Environment,
	Profile,
	ECS,
	EC2,
}
Credential_Modes :: bit_set[Credential_Mode]
CREDENTIAL_MODES_SUPPORTED :: Credential_Modes{.Environment, .Profile, .ECS, .EC2}

Credential_Source :: enum {
	None,
	Environment,
	Profile,
	ECS,
	EC2,
}

Credential_Unsupported :: enum {
	None,
	Web_Identity,
	SSO,
	Credential_Process,
	Assumed_Role,
	ECS_Full_URI,
}

Credential_Error_Kind :: enum {
	None,
	Invalid_Argument,
	Unsupported,
	Incomplete,
	Unavailable,
	Expired,
	Cancelled,
	Waiter_Limit,
	Busy,
	Allocation_Failed,
	Closed,
}

Credential_Error :: struct {
	kind:         Credential_Error_Kind,
	source:       Credential_Source,
	unsupported:  Credential_Unsupported,
}

// One published triple. Fields are written only before the cache stores the pointer.
Credential_Snapshot :: struct {
	source:        Credential_Source,
	has_expiry:    bool,
	expires:       time.Time,
	access_key:    string,
	secret_key:    string,
	session_token: string,
	readers:       int,
	retired:       bool,
	storage:       []byte,
}

// Borrow of one snapshot. Strings alias snapshot storage until release.
Credential_Lease :: struct {
	snapshot:      ^Credential_Snapshot,
	source:        Credential_Source,
	has_expiry:    bool,
	expires:       time.Time,
	access_key:    string,
	secret_key:    string,
	session_token: string,
}

Credential_Cancel :: struct {
	cancelled: int,
}

// Waiters blocked on the single in-flight refresh. The caller that performs it is not a waiter.
CREDENTIAL_WAITERS_MAX :: 8

CREDENTIAL_ACCESS_MAX :: 128
CREDENTIAL_SECRET_MAX :: 256
CREDENTIAL_TOKEN_MAX :: 8192
CREDENTIAL_ROLE_MAX :: 128
CREDENTIAL_IMDS_TOKEN_MAX :: 4096
CREDENTIAL_RELATIVE_MAX :: 1024

Credential_Cache :: struct {
	execute:          HTTP_Execute,
	clock:            Credential_Clock,
	clock_data:       rawptr,
	modes:            Credential_Modes,
	allocator:        mem.Allocator,
	mutex:            sync.Mutex,
	cond:             sync.Cond,
	snapshot:         ^Credential_Snapshot,
	refresh_active:   bool,
	refresh_attempt:  u64,
	failed_attempt:   u64,
	refresh_error:    Credential_Error,
	waiters:          int,
	live_readers:     int,
	closed:           bool,
}

credential_cache_init :: proc(
	cache: ^Credential_Cache,
	execute: HTTP_Execute,
	clock: Credential_Clock,
	clock_data: rawptr = nil,
	modes: Credential_Modes = CREDENTIAL_MODES_SUPPORTED,
	allocator := context.allocator,
) -> Credential_Error {
	if cache == nil || execute == nil || clock == nil || allocator.procedure == nil ||
	   cache.snapshot != nil || cache.refresh_active {
		return {kind = .Invalid_Argument}
	}
	cache.execute = execute
	cache.clock = clock
	cache.clock_data = clock_data
	cache.modes = modes
	cache.allocator = allocator
	cache.refresh_attempt = 0
	cache.failed_attempt = 0
	cache.refresh_error = {}
	cache.waiters = 0
	cache.live_readers = 0
	cache.closed = false
	return {}
}

// Requires no lease and no refresh. Snapshot bytes are wiped before release.
credential_cache_destroy :: proc(cache: ^Credential_Cache) -> Credential_Error {
	if cache == nil {
		return {kind = .Invalid_Argument}
	}
	sync.mutex_lock(&cache.mutex)
	if cache.refresh_active || cache.waiters != 0 || cache.live_readers != 0 {
		sync.mutex_unlock(&cache.mutex)
		return {kind = .Busy}
	}
	snap := cache.snapshot
	cache.snapshot = nil
	cache.closed = true
	sync.mutex_unlock(&cache.mutex)
	credential_snapshot_erase(cache, snap)
	return {}
}

credential_cancel :: proc(cache: ^Credential_Cache, cancel: ^Credential_Cancel) {
	if cancel == nil {
		return
	}
	sync.atomic_store(&cancel.cancelled, 1)
	if cache == nil {
		return
	}
	sync.mutex_lock(&cache.mutex)
	sync.cond_broadcast(&cache.cond)
	sync.mutex_unlock(&cache.mutex)
}

// EC2 link-local is contacted only when that mode is enabled and the disable switch is not exactly "true".
credential_ec2_probe_permitted :: proc(modes: Credential_Modes) -> bool {
	if .EC2 not_in modes {
		return false
	}
	return os.get_env("AWS_EC2_METADATA_DISABLED", context.temp_allocator) != "true"
}

credential_lease :: proc(
	cache: ^Credential_Cache,
	cancel: ^Credential_Cancel = nil,
) -> (
	lease: Credential_Lease,
	error: Credential_Error,
) {
	if cache == nil || cache.execute == nil || cache.clock == nil {
		return {}, {kind = .Invalid_Argument}
	}
	sync.mutex_lock(&cache.mutex)
	for {
		if cache.closed {
			sync.mutex_unlock(&cache.mutex)
			return {}, {kind = .Closed}
		}
		if credential_cancelled(cancel) {
			sync.mutex_unlock(&cache.mutex)
			return {}, {kind = .Cancelled}
		}
		now := cache.clock(cache.clock_data)
		if credential_snapshot_usable(cache.snapshot, now) {
			lease = credential_snapshot_borrow(cache.snapshot)
			cache.live_readers += 1
			sync.mutex_unlock(&cache.mutex)
			return lease, {}
		}
		if cache.refresh_active {
			if cache.waiters >= CREDENTIAL_WAITERS_MAX {
				sync.mutex_unlock(&cache.mutex)
				return {}, {kind = .Waiter_Limit}
			}
			target := cache.refresh_attempt
			cache.waiters += 1
			for cache.refresh_active && cache.refresh_attempt == target && !credential_cancelled(cancel) {
				sync.cond_wait(&cache.cond, &cache.mutex)
			}
			cache.waiters -= 1
			if credential_cancelled(cancel) {
				sync.mutex_unlock(&cache.mutex)
				return {}, {kind = .Cancelled}
			}
			if cache.refresh_active {
				continue
			}
			now = cache.clock(cache.clock_data)
			if credential_snapshot_usable(cache.snapshot, now) {
				continue
			}
			if cache.failed_attempt == target && cache.refresh_error.kind != .None {
				error = cache.refresh_error
				sync.mutex_unlock(&cache.mutex)
				return {}, error
			}
			continue
		}

		cache.refresh_active = true
		cache.refresh_attempt += 1
		target := cache.refresh_attempt
		sync.mutex_unlock(&cache.mutex)

		snap, resolve_error := credential_resolve(cache)
		now = cache.clock(cache.clock_data)

		sync.mutex_lock(&cache.mutex)
		if resolve_error.kind == .None && snap != nil &&
		   credential_snapshot_usable(snap, now) && !cache.closed {
			credential_snapshot_retire(cache, cache.snapshot)
			cache.snapshot = snap
			snap = nil
			cache.failed_attempt = 0
			cache.refresh_error = {}
		} else {
			if resolve_error.kind == .None && snap != nil {
				resolve_error = {kind = .Expired, source = snap.source}
			}
			credential_snapshot_erase(cache, snap)
			snap = nil
			cache.refresh_error = resolve_error
			cache.failed_attempt = target
			if cache.snapshot != nil && !credential_snapshot_usable(cache.snapshot, now) {
				stale := cache.snapshot
				cache.snapshot = nil
				credential_snapshot_retire(cache, stale)
			}
		}
		cache.refresh_active = false
		sync.cond_broadcast(&cache.cond)
		if credential_cancelled(cancel) {
			sync.mutex_unlock(&cache.mutex)
			return {}, {kind = .Cancelled}
		}
		now = cache.clock(cache.clock_data)
		if credential_snapshot_usable(cache.snapshot, now) {
			lease = credential_snapshot_borrow(cache.snapshot)
			cache.live_readers += 1
			sync.mutex_unlock(&cache.mutex)
			return lease, {}
		}
		error = cache.refresh_error
		if error.kind == .None {
			error.kind = .Unavailable
		}
		sync.mutex_unlock(&cache.mutex)
		return {}, error
	}
}

// Drops the borrow. The lease is cleared. Storage is wiped once no reader remains on a retired snapshot.
credential_lease_release :: proc(cache: ^Credential_Cache, lease: ^Credential_Lease) {
	if cache == nil || lease == nil || lease.snapshot == nil {
		if lease != nil {
			lease^ = {}
		}
		return
	}
	snap := lease.snapshot
	lease^ = {}
	sync.mutex_lock(&cache.mutex)
	defer sync.mutex_unlock(&cache.mutex)
	if snap.readers <= 0 {
		return
	}
	snap.readers -= 1
	if cache.live_readers > 0 {
		cache.live_readers -= 1
	}
	if snap.retired && snap.readers == 0 {
		credential_snapshot_erase(cache, snap)
	}
}

@(private)
credential_cancelled :: proc(cancel: ^Credential_Cancel) -> bool {
	if cancel == nil {
		return false
	}
	return sync.atomic_load(&cancel.cancelled) != 0
}

@(private)
credential_snapshot_usable :: proc(snap: ^Credential_Snapshot, now: time.Time) -> bool {
	if snap == nil || snap.retired {
		return false
	}
	if !snap.has_expiry {
		return true
	}
	return time.diff(now, snap.expires) > 0
}

@(private)
credential_snapshot_borrow :: proc(snap: ^Credential_Snapshot) -> Credential_Lease {
	snap.readers += 1
	return {
		snapshot = snap,
		source = snap.source,
		has_expiry = snap.has_expiry,
		expires = snap.expires,
		access_key = snap.access_key,
		secret_key = snap.secret_key,
		session_token = snap.session_token,
	}
}

@(private)
credential_snapshot_retire :: proc(cache: ^Credential_Cache, snap: ^Credential_Snapshot) {
	if snap == nil {
		return
	}
	snap.retired = true
	if snap.readers == 0 {
		credential_snapshot_erase(cache, snap)
	}
}

@(private)
credential_snapshot_erase :: proc(cache: ^Credential_Cache, snap: ^Credential_Snapshot) {
	if snap == nil {
		return
	}
	allocator := context.allocator
	if cache != nil {
		allocator = cache.allocator
	}
	if snap.storage != nil {
		mem.zero_explicit(raw_data(snap.storage), len(snap.storage))
		delete(snap.storage, allocator)
	}
	snap.access_key = ""
	snap.secret_key = ""
	snap.session_token = ""
	snap.storage = nil
	free(snap, allocator)
}

@(private)
credential_snapshot_new :: proc(
	allocator: mem.Allocator,
	source: Credential_Source,
	access, secret, token: string,
	expires: time.Time,
	has_expiry: bool,
) -> (
	snap: ^Credential_Snapshot,
	error: Credential_Error,
) {
	if len(access) > CREDENTIAL_ACCESS_MAX ||
	   len(secret) > CREDENTIAL_SECRET_MAX ||
	   len(token) > CREDENTIAL_TOKEN_MAX ||
	   !aws_credentials_valid({access, secret, token}) {
		return nil, {kind = .Unavailable, source = source}
	}
	storage, alloc_error := make([]byte, len(access) + len(secret) + len(token), allocator)
	if alloc_error != nil {
		return nil, {kind = .Allocation_Failed, source = source}
	}
	snap, alloc_error = new(Credential_Snapshot, allocator)
	if alloc_error != nil {
		mem.zero_explicit(raw_data(storage), len(storage))
		delete(storage, allocator)
		return nil, {kind = .Allocation_Failed, source = source}
	}
	copy(storage[:len(access)], access)
	copy(storage[len(access):][:len(secret)], secret)
	copy(storage[len(access) + len(secret):], token)
	snap.storage = storage
	snap.source = source
	snap.has_expiry = has_expiry
	snap.expires = expires
	snap.access_key = string(storage[:len(access)])
	snap.secret_key = string(storage[len(access):][:len(secret)])
	snap.session_token = string(storage[len(access) + len(secret):])
	return snap, {}
}

@(private)
credential_resolve :: proc(
	cache: ^Credential_Cache,
) -> (
	snap: ^Credential_Snapshot,
	error: Credential_Error,
) {
	access_buf: [CREDENTIAL_ACCESS_MAX]byte
	secret_buf: [CREDENTIAL_SECRET_MAX]byte
	token_buf: [CREDENTIAL_TOKEN_MAX]byte
	defer mem.zero_explicit(&access_buf, size_of(access_buf))
	defer mem.zero_explicit(&secret_buf, size_of(secret_buf))
	defer mem.zero_explicit(&token_buf, size_of(token_buf))

	if .Environment in cache.modes {
		access := credential_env("AWS_ACCESS_KEY_ID")
		secret := credential_env("AWS_SECRET_ACCESS_KEY")
		token := credential_env("AWS_SESSION_TOKEN")
		defer credential_wipe_text(access)
		defer credential_wipe_text(secret)
		defer credential_wipe_text(token)
		if access != "" || secret != "" || token != "" {
			if !credential_store_bounded(&access_buf, &secret_buf, &token_buf, access, secret, token) ||
			   !aws_credentials_valid({
					   string(access_buf[:len(access)]),
					   string(secret_buf[:len(secret)]),
					   string(token_buf[:len(token)]),
				   }) {
				return nil, {kind = .Incomplete, source = .Environment}
			}
			return credential_snapshot_new(
				cache.allocator,
				.Environment,
				string(access_buf[:len(access)]),
				string(secret_buf[:len(secret)]),
				string(token_buf[:len(token)]),
				{},
				false,
			)
		}
	}
	web_identity := credential_env("AWS_WEB_IDENTITY_TOKEN_FILE")
	defer credential_wipe_text(web_identity)
	if web_identity != "" {
		return nil, {kind = .Unsupported, source = .Environment, unsupported = .Web_Identity}
	}

	if .Profile in cache.modes {
		// Keep env copies distinct from literals and formatted paths so wiping cannot touch them.
		profile_env := credential_env("AWS_PROFILE")
		defer credential_wipe_text(profile_env)
		profile := profile_env if profile_env != "" else "default"
		path_env := credential_env("AWS_SHARED_CREDENTIALS_FILE")
		defer credential_wipe_text(path_env)
		path := path_env
		if path == "" {
			home := credential_env("HOME")
			defer credential_wipe_text(home)
			path = fmt.tprintf("%s/.aws/credentials", home)
		}
		loaded, unsupported, data, read_error := credential_profile_load(path, profile, true)
		defer credential_wipe_bytes(data)
		if read_error.kind != .None && read_error.kind != .Open_Failed {
			return nil, {kind = .Unavailable, source = .Profile}
		}
		if unsupported != .None {
			return nil, {kind = .Unsupported, source = .Profile, unsupported = unsupported}
		}
		if loaded.access_key != "" || loaded.secret_key != "" || loaded.session_token != "" {
			if !credential_store_bounded(
				&access_buf,
				&secret_buf,
				&token_buf,
				loaded.access_key,
				loaded.secret_key,
				loaded.session_token,
			) || !aws_credentials_valid(loaded) {
				return nil, {kind = .Incomplete, source = .Profile}
			}
			return credential_snapshot_new(
				cache.allocator,
				.Profile,
				string(access_buf[:len(loaded.access_key)]),
				string(secret_buf[:len(loaded.secret_key)]),
				string(token_buf[:len(loaded.session_token)]),
				{},
				false,
			)
		}
	}

	full_uri := credential_env("AWS_CONTAINER_CREDENTIALS_FULL_URI")
	defer credential_wipe_text(full_uri)
	if full_uri != "" {
		return nil, {kind = .Unsupported, source = .ECS, unsupported = .ECS_Full_URI}
	}
	if .ECS in cache.modes {
		relative := credential_env("AWS_CONTAINER_CREDENTIALS_RELATIVE_URI")
		defer credential_wipe_text(relative)
		if relative != "" {
			if !credential_relative_uri_ok(relative) {
				return nil, {kind = .Incomplete, source = .ECS}
			}
			return credential_fetch_document(
				cache,
				.ECS,
				fmt.tprintf("http://169.254.170.2%s", relative),
				nil,
			)
		}
	}
	if credential_ec2_probe_permitted(cache.modes) {
		return credential_fetch_ec2(cache)
	}
	return nil, {kind = .Unavailable}
}

@(private)
credential_fetch_ec2 :: proc(
	cache: ^Credential_Cache,
) -> (
	snap: ^Credential_Snapshot,
	error: Credential_Error,
) {
	token_buf: [CREDENTIAL_IMDS_TOKEN_MAX]byte
	defer mem.zero_explicit(&token_buf, size_of(token_buf))
	reply, ok := credential_metadata_call(
		cache.execute,
		"PUT",
		"http://169.254.169.254/latest/api/token",
		{"X-aws-ec2-metadata-token-ttl-seconds: 60"},
	)
	if !ok || len(reply) == 0 || len(reply) > len(token_buf) {
		return nil, {kind = .Unavailable, source = .EC2}
	}
	token := string(reply)
	if strings.contains_any(token, "\r\n") {
		return nil, {kind = .Unavailable, source = .EC2}
	}
	copy(token_buf[:len(reply)], reply)
	role, role_ok := credential_metadata_call(
		cache.execute,
		"GET",
		"http://169.254.169.254/latest/meta-data/iam/security-credentials/",
		{fmt.tprintf("X-aws-ec2-metadata-token: %s", string(token_buf[:len(reply)]))},
	)
	role_name := strings.trim_space(string(role))
	if !role_ok || role_name == "" || len(role_name) > CREDENTIAL_ROLE_MAX ||
	   strings.contains_any(role_name, "/\r\n?#\\@") {
		return nil, {kind = .Unavailable, source = .EC2}
	}
	role_buf: [CREDENTIAL_ROLE_MAX]byte
	defer mem.zero_explicit(&role_buf, size_of(role_buf))
	copy(role_buf[:len(role_name)], role_name)
	return credential_fetch_document(
		cache,
		.EC2,
		fmt.tprintf(
			"http://169.254.169.254/latest/meta-data/iam/security-credentials/%s",
			string(role_buf[:len(role_name)]),
		),
		{fmt.tprintf("X-aws-ec2-metadata-token: %s", string(token_buf[:len(reply)]))},
	)
}

@(private)
credential_fetch_document :: proc(
	cache: ^Credential_Cache,
	source: Credential_Source,
	url: string,
	headers: []string,
) -> (
	snap: ^Credential_Snapshot,
	error: Credential_Error,
) {
	if !credential_metadata_url_permitted(url) {
		return nil, {kind = .Unavailable, source = source}
	}
	data, ok := credential_metadata_call(cache.execute, "GET", url, headers)
	document: struct {
		code:       string `json:"Code"`,
		access:     string `json:"AccessKeyId"`,
		secret:     string `json:"SecretAccessKey"`,
		token:      string `json:"Token"`,
		expiration: string `json:"Expiration"`,
	}
	parsed := false
	if ok {
		parsed = json.unmarshal(data, &document, allocator = context.temp_allocator) == nil
	}
	defer credential_wipe_text(document.code)
	defer credential_wipe_text(document.access)
	defer credential_wipe_text(document.secret)
	defer credential_wipe_text(document.token)
	defer credential_wipe_text(document.expiration)
	if !ok || !parsed {
		return nil, {kind = .Unavailable, source = source}
	}
	if document.code != "" && document.code != "Success" {
		return nil, {kind = .Unavailable, source = source}
	}
	access_buf: [CREDENTIAL_ACCESS_MAX]byte
	secret_buf: [CREDENTIAL_SECRET_MAX]byte
	token_buf: [CREDENTIAL_TOKEN_MAX]byte
	defer mem.zero_explicit(&access_buf, size_of(access_buf))
	defer mem.zero_explicit(&secret_buf, size_of(secret_buf))
	defer mem.zero_explicit(&token_buf, size_of(token_buf))
	if !credential_store_bounded(
		&access_buf,
		&secret_buf,
		&token_buf,
		document.access,
		document.secret,
		document.token,
	) || !aws_credentials_valid({document.access, document.secret, document.token}) {
		return nil, {kind = .Unavailable, source = source}
	}
	expires, expiry_ok := credential_expiration(document.expiration)
	if !expiry_ok {
		return nil, {kind = .Unavailable, source = source}
	}
	now := cache.clock(cache.clock_data)
	if time.diff(now, expires) <= 0 {
		return nil, {kind = .Expired, source = source}
	}
	return credential_snapshot_new(
		cache.allocator,
		source,
		string(access_buf[:len(document.access)]),
		string(secret_buf[:len(document.secret)]),
		string(token_buf[:len(document.token)]),
		expires,
		true,
	)
}

@(private)
credential_expiration :: proc(value: string) -> (expires: time.Time, ok: bool) {
	if value == "" {
		return {}, false
	}
	parsed, consumed := time.rfc3339_to_time_utc(value)
	if consumed != len(value) {
		return {}, false
	}
	return parsed, true
}

@(private)
credential_metadata_call :: proc(
	execute: HTTP_Execute,
	method, url: string,
	headers: []string,
) -> (
	[]byte,
	bool,
) {
	if execute == nil || !credential_metadata_url_permitted(url) {
		return nil, false
	}
	reply, result := execute(method, url, nil, headers, "", true, 1500, nil, 0)
	if !result.ok {
		return nil, false
	}
	return reply, true
}

// Fixed link-local metadata only. Full credential URIs and any other host are rejected.
@(private)
credential_metadata_url_permitted :: proc(url: string) -> bool {
	if strings.contains_any(url, "\r\n\\@ ") || !strings.contains(url, "://") {
		return false
	}
	ecs := "http://169.254.170.2/"
	if strings.has_prefix(url, ecs) {
		return credential_relative_uri_ok(url[len("http://169.254.170.2"):])
	}
	if url == "http://169.254.169.254/latest/api/token" ||
	   url == "http://169.254.169.254/latest/meta-data/iam/security-credentials/" {
		return true
	}
	prefix := "http://169.254.169.254/latest/meta-data/iam/security-credentials/"
	if strings.has_prefix(url, prefix) {
		role := url[len(prefix):]
		return role != "" && len(role) <= CREDENTIAL_ROLE_MAX && !strings.contains_any(role, "/?#\\\r\n@")
	}
	return false
}

@(private)
credential_relative_uri_ok :: proc(relative: string) -> bool {
	if relative == "" || len(relative) > CREDENTIAL_RELATIVE_MAX {
		return false
	}
	if !strings.has_prefix(relative, "/") || strings.has_prefix(relative, "//") {
		return false
	}
	if strings.contains(relative, "://") || strings.contains_any(relative, "\r\n#\\@?") {
		return false
	}
	return true
}

@(private)
credential_store_bounded :: proc(
	access_buf: ^[CREDENTIAL_ACCESS_MAX]byte,
	secret_buf: ^[CREDENTIAL_SECRET_MAX]byte,
	token_buf: ^[CREDENTIAL_TOKEN_MAX]byte,
	access, secret, token: string,
) -> bool {
	if len(access) > len(access_buf) || len(secret) > len(secret_buf) || len(token) > len(token_buf) {
		return false
	}
	copy(access_buf[:len(access)], access)
	copy(secret_buf[:len(secret)], secret)
	copy(token_buf[:len(token)], token)
	return true
}

@(private)
credential_env :: proc(key: string) -> string {
	return os.get_env(key, context.temp_allocator)
}

@(private)
credential_wipe_text :: proc(value: string) {
	if len(value) == 0 {
		return
	}
	mem.zero_explicit(raw_data(value), len(value))
}

@(private)
credential_wipe_bytes :: proc(value: []byte) {
	if len(value) == 0 {
		return
	}
	mem.zero_explicit(raw_data(value), len(value))
}

@(private)
credential_profile_load :: proc(
	path, profile: string,
	strict: bool,
) -> (
	credentials: AWS_Credentials,
	unsupported: Credential_Unsupported,
	data: []byte,
	error: files.Read_Error,
) {
	data, error = files.read_limited(path, 64 * 1024, context.temp_allocator, erase_on_failure = true)
	if error.kind != .None {
		return {}, {}, nil, error
	}
	section := ""
	source := string(data)
	for raw_line in strings.split_iterator(&source, "\n") {
		line := strings.trim_space(raw_line)
		if line == "" || line[0] == '#' || line[0] == ';' {
			continue
		}
		if line[0] == '[' && line[len(line) - 1] == ']' {
			section = strings.trim_space(line[1:len(line) - 1])
			continue
		}
		if section != profile {
			continue
		}
		equal := strings.index_byte(line, '=')
		if equal < 1 {
			continue
		}
		key := strings.trim_space(line[:equal])
		value := strings.trim_space(line[equal + 1:])
		switch key {
		case "aws_access_key_id":
			credentials.access_key = value
		case "aws_secret_access_key":
			credentials.secret_key = value
		case "aws_session_token":
			credentials.session_token = value
		case "credential_process":
			if strict && unsupported == .None {
				unsupported = .Credential_Process
			}
		case "web_identity_token_file":
			if strict && unsupported == .None {
				unsupported = .Web_Identity
			}
		case "sso_start_url", "sso_account_id", "sso_role_name", "sso_region", "sso_session":
			if strict && unsupported == .None {
				unsupported = .SSO
			}
		case "role_arn", "source_profile", "credential_source", "external_id":
			if strict && unsupported == .None {
				unsupported = .Assumed_Role
			}
		}
	}
	if unsupported != .None {
		credentials = {}
	}
	return
}

// Optional per-operation seam for isolated providers and offline tests. Defaults
// use Surf; implementations must preserve its bounded response/trust contract.
HTTP_Execute :: proc(
	method, url: string,
	body: []u8,
	headers: []string,
	ca_file: string,
	allow_http: bool,
	timeout_ms: i64,
	upload_file: ^os.File,
	upload_size: i64,
) -> ([]u8, network_client.Buffered_HTTP_Result)
