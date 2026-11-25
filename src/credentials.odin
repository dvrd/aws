package aws

import "core:encoding/json"
import "core:fmt"
import "core:mem"
import "core:os"
import "core:strings"
import "core:sync"
import "core:thread"
import "core:time"
import "shared:surf"

// Two ways to obtain credentials:
//
// aws_credentials is a convenience for scripts and one-shot tools. It resolves on
// every call, may block for up to three metadata calls of 1500 ms each, and
// returns the secret in strings that stay in context.temp_allocator, unwiped,
// until the caller resets it.
//
// A server uses a Credential_Cache: credential_cache_init once at startup with
// credential_clock_wall, a Credential_Refresher (credential_refresher_start) that
// calls credential_refresh from its own thread, and credential_lease_cached with
// credential_lease_release around each signing in a request handler, passing
// credential_lease_credentials(lease) to the signer. The cache keeps one copy of
// the secret, wipes it when it is replaced and no lease holds it, and hands out
// leases without I/O.
//
//   cache: aws.Credential_Cache
//   aws.credential_cache_init(&cache, aws.http_execute_default, aws.credential_clock_wall)
//   refresher: aws.Credential_Refresher
//   aws.credential_refresher_start(&refresher, &cache)
//
//   // in a request handler:
//   lease, error := aws.credential_lease_cached(&cache)
//   if error.kind != .None { /* 503: credentials not ready */ }
//   defer aws.credential_lease_release(&cache, &lease)
//   result := aws.s3_put(config, aws.credential_lease_credentials(lease), key, body, type)
//
//   // at shutdown, after handlers stop:
//   aws.credential_refresher_stop(&refresher)
//   aws.credential_cache_destroy(&cache)
//
//   credential_lease_cached   request handler: never blocks, never does I/O
//   credential_refresher_*    startup and shutdown: one thread runs credential_refresh
//   credential_refresh        maintenance only: blocks for the provider's calls
//   credential_lease          startup or a worker: blocks when a refresh is needed
//   aws_credentials           scripts only

// Uncached resolution for scripts; servers use a Credential_Cache (see above).
// Strings borrow context.temp_allocator and are not wiped. No cache: a later call
// observes environment changes. It applies the cache's rules (sources, bounds,
// expiry against the wall clock, unsupported mechanisms refused) through the same resolver.
// Blocks for up to three metadata calls of 1500 ms each.
aws_credentials :: proc() -> (credentials: AWS_Credentials, ok: bool) {
	return aws_credentials_with_http(http_execute_default)
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
	snap, failure := credential_resolve(
		{
			execute = http_execute,
			clock = credential_clock_wall,
			modes = CREDENTIAL_MODES_SUPPORTED,
			allocator = context.allocator,
		},
	)
	if failure.kind != .None || snap == nil {
		return
	}
	// The caller gets copies in the temp allocator; the snapshot is wiped now.
	defer credential_snapshot_erase(nil, snap)
	credentials = {
		access_key    = strings.clone(snap.access_key, context.temp_allocator),
		secret_key    = strings.clone(snap.secret_key, context.temp_allocator),
		session_token = strings.clone(snap.session_token, context.temp_allocator),
	}
	return credentials, true
}

aws_credentials_valid :: proc(value: AWS_Credentials) -> bool {
	if value.access_key == "" || value.secret_key == "" {
		return false
	}

	// The keys and the token go into header values as written: visible ASCII only,
	// so no side can trim or reject a byte the signature covers.
	for text in ([]string{value.access_key, value.secret_key, value.session_token}) {
		if !text_visible(text) {
			return false
		}
	}

	return true
}

Credential_Clock :: proc(data: rawptr) -> time.Time

// The real time, for a Credential_Cache outside tests: credential_cache_init(&cache,
// http_execute_default, credential_clock_wall).
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
	kind:        Credential_Error_Kind,
	source:      Credential_Source,
	unsupported: Credential_Unsupported,
}

// One published triple. Fields are written only before the cache stores the pointer.
Credential_Snapshot :: struct {
	source:        Credential_Source,
	has_expiry:    bool,
	expires:       time.Time,
	resolved:      time.Time, // when the cache published it
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
// Temp memory one resolution may use: a 64 KiB profile, three metadata replies
// of up to 64 KiB, and the decoded document, with room to spare. Zeroed in full
// and freed before the refresh returns.
CREDENTIAL_SCRATCH_BYTES :: 1 << 20
CREDENTIAL_IMDS_TOKEN_MAX :: 4096
CREDENTIAL_RELATIVE_MAX :: 1024

Credential_Cache :: struct {
	execute:         HTTP_Execute,
	clock:           Credential_Clock,
	clock_data:      rawptr,
	modes:           Credential_Modes,
	allocator:       mem.Allocator,
	mutex:           sync.Mutex,
	cond:            sync.Cond,
	snapshot:        ^Credential_Snapshot,
	refresh_active:  bool,
	refresh_attempt: u64,
	failed_attempt:  u64,
	refresh_error:   Credential_Error,
	expired_source:  Credential_Source, // source of credentials dropped for expiry; None once new ones are published
	waiters:         int,
	live_readers:    int,
	closed:          bool,
}

// What one resolution needs. The cache keeps one; aws_credentials builds one per call.
Credential_Resolver :: struct {
	execute:    HTTP_Execute,
	clock:      Credential_Clock,
	clock_data: rawptr,
	modes:      Credential_Modes,
	allocator:  mem.Allocator, // the snapshot's allocator
}

credential_resolver_of :: proc(cache: ^Credential_Cache) -> Credential_Resolver {
	return {cache.execute, cache.clock, cache.clock_data, cache.modes, cache.allocator}
}

credential_cache_init :: proc(
	cache: ^Credential_Cache,
	execute: HTTP_Execute,
	clock: Credential_Clock,
	clock_data: rawptr = nil,
	modes: Credential_Modes = CREDENTIAL_MODES_SUPPORTED,
	allocator := context.allocator,
) -> Credential_Error {
	if cache == nil ||
	   execute == nil ||
	   clock == nil ||
	   allocator.procedure == nil ||
	   cache.snapshot != nil ||
	   cache.refresh_active {
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
	cache.expired_source = .None
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

// Credentials that expire within this margin are replaced by credential_refresh.
CREDENTIAL_REFRESH_MARGIN :: 5 * time.Minute

// Credentials stop being handed out this long before they expire, so a request
// signed with a fresh lease is not refused for arriving after the expiry.
CREDENTIAL_EXPIRY_SKEW :: 15 * time.Second

// Credentials with no expiry (a profile, or an environment without
// AWS_CREDENTIAL_EXPIRATION) are read again by credential_refresh once they are
// this old, so a rotated file is noticed without a restart.
CREDENTIAL_STATIC_REFRESH :: 15 * time.Minute

// A lease from the cache as it is: no resolution, no I/O and no waiting, so a
// request handler may call it. Without usable cached credentials it returns
// Expired (the cached ones ran out) or Unavailable (none were ever resolved);
// credential_refresh, called elsewhere, is what fills the cache.
credential_lease_cached :: proc(
	cache: ^Credential_Cache,
) -> (
	lease: Credential_Lease,
	error: Credential_Error,
) {
	if cache == nil || cache.execute == nil || cache.clock == nil {
		return {}, {kind = .Invalid_Argument}
	}
	sync.mutex_lock(&cache.mutex)
	defer sync.mutex_unlock(&cache.mutex)
	if cache.closed {
		return {}, {kind = .Closed}
	}
	if credential_snapshot_usable(cache.snapshot, cache.clock(cache.clock_data)) {
		lease = credential_snapshot_borrow(cache.snapshot)
		cache.live_readers += 1
		return lease, {}
	}
	if cache.snapshot != nil {
		return {}, {kind = .Expired, source = cache.snapshot.source}
	}
	if cache.expired_source != .None {
		return {}, {kind = .Expired, source = cache.expired_source}
	}
	return {}, {kind = .Unavailable}
}

// Keeps the cache ahead of expiry. When there are no usable credentials, they
// expire within margin, or they have no expiry and are CREDENTIAL_STATIC_REFRESH
// old, it resolves new ones and publishes them; otherwise it returns at once.
// The credentials being replaced stay valid for the leases that hold them and for
// credential_lease_cached until the new ones are published, and a failed attempt
// leaves them in place while they are still usable.
//
// Blocks for the provider's calls (up to three of 1500 ms each): call it from a
// maintenance thread or timer, more often than margin, never from a request
// handler. Returns Busy when another refresh is already running.
credential_refresh :: proc(
	cache: ^Credential_Cache,
	margin: time.Duration = CREDENTIAL_REFRESH_MARGIN,
) -> Credential_Error {
	if cache == nil || cache.execute == nil || cache.clock == nil || margin < 0 {
		return {kind = .Invalid_Argument}
	}
	sync.mutex_lock(&cache.mutex)
	defer sync.mutex_unlock(&cache.mutex)
	if cache.closed {
		return {kind = .Closed}
	}
	now := cache.clock(cache.clock_data)
	if credential_snapshot_usable(cache.snapshot, now) {
		snap := cache.snapshot
		if snap.has_expiry && time.diff(now, snap.expires) > margin + CREDENTIAL_EXPIRY_SKEW {
			return {}
		}
		if !snap.has_expiry && time.diff(snap.resolved, now) < CREDENTIAL_STATIC_REFRESH {
			return {}
		}
	}
	if cache.refresh_active {
		return {kind = .Busy}
	}
	target := credential_refresh_run(cache)
	if cache.failed_attempt != target {
		return {}
	}
	if cache.refresh_error.kind == .None {
		return {kind = .Unavailable}
	}
	return cache.refresh_error
}

// Resolves once and publishes the result. The caller holds the mutex and has seen
// that no refresh is active; the mutex is released for the provider's calls and
// held again on return. Returns the attempt number, which equals
// cache.failed_attempt when the attempt failed.
credential_refresh_run :: proc(cache: ^Credential_Cache) -> (target: u64) {
	cache.refresh_active = true
	cache.refresh_attempt += 1
	target = cache.refresh_attempt
	resolver := credential_resolver_of(cache)
	sync.mutex_unlock(&cache.mutex)

	scratch, scratch_error := make([]byte, CREDENTIAL_SCRATCH_BYTES, resolver.allocator)
	snap: ^Credential_Snapshot
	resolve_error: Credential_Error
	if scratch_error != nil {
		resolve_error = {kind = .Allocation_Failed}
	} else {
		arena: mem.Arena
		mem.arena_init(&arena, scratch)
		{
			context.temp_allocator = mem.arena_allocator(&arena)
			snap, resolve_error = credential_resolve(resolver)
		}
		mem.zero_explicit(raw_data(scratch), len(scratch))
		delete(scratch, resolver.allocator)
	}
	now := cache.clock(cache.clock_data)

	sync.mutex_lock(&cache.mutex)

	if resolve_error.kind == .None &&
	   snap != nil &&
	   credential_snapshot_usable(snap, now) &&
	   !cache.closed {
		snap.resolved = now
		credential_snapshot_retire(cache, cache.snapshot)
		cache.snapshot = snap
		cache.expired_source = .None
		snap = nil
		cache.failed_attempt = 0
		cache.refresh_error = {}
	} else {
		if resolve_error.kind == .None && snap != nil {
			resolve_error = {
				kind   = .Expired,
				source = snap.source,
			}
		}

		credential_snapshot_erase(cache, snap)
		snap = nil
		cache.refresh_error = resolve_error
		cache.failed_attempt = target

		if cache.snapshot != nil && !credential_snapshot_usable(cache.snapshot, now) {
			stale := cache.snapshot
			cache.expired_source = stale.source
			cache.snapshot = nil
			credential_snapshot_retire(cache, stale)
		}
	}

	cache.refresh_active = false
	sync.cond_broadcast(&cache.cond)
	return target
}

// A lease, resolving credentials on this thread when the cache has none that are
// usable: it can block for the provider's calls, or behind another caller's
// refresh. For startup and worker threads. A request handler uses
// credential_lease_cached.
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

			for cache.refresh_active &&
			    cache.refresh_attempt == target &&
			    !credential_cancelled(cancel) {
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

		credential_refresh_run(cache)

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

// The lease's credentials in the shape every signer takes. They BORROW the
// lease: valid only until credential_lease_release(cache, &lease). Sign with
// them, then release; never store them, put them in a struct that outlives the
// release, or hand them to another thread. A zero lease gives zero credentials,
// which every signer refuses.
credential_lease_credentials :: proc(lease: Credential_Lease) -> AWS_Credentials {
	return {lease.access_key, lease.secret_key, lease.session_token}
}

// Keeps a Credential_Cache fresh from its own thread: credential_refresh at
// start, then every interval, until credential_refresher_stop. interval must be
// positive and shorter than margin, so credentials are replaced before they
// enter the skew. The cache must outlive the refresher; stop it before
// credential_cache_destroy (destroy returns Busy while a refresh runs).
Credential_Refresher :: struct {
	cache:    ^Credential_Cache,
	interval: time.Duration,
	margin:   time.Duration,
	thread:   ^thread.Thread,
	mutex:    sync.Mutex,
	cond:     sync.Cond,
	stopping: bool, // guarded by mutex
	attempts: int, // guarded by mutex
	last:     Credential_Error, // guarded by mutex; the latest refresh result
}

// How often a Credential_Refresher calls credential_refresh by default; well
// inside CREDENTIAL_REFRESH_MARGIN.
CREDENTIAL_REFRESH_INTERVAL :: time.Minute

// Starts the refresher's thread, which refreshes at once and then every
// interval. Does not block: the first refresh runs on the new thread, so a
// caller that needs credentials before serving polls credential_lease_cached or
// uses credential_lease. Call it from the thread that owns the refresher, once;
// it returns Invalid_Argument for a nil refresher or cache, a refresher already
// started, interval <= 0, margin < 0 or interval >= margin, and
// Allocation_Failed when the thread cannot be created.
credential_refresher_start :: proc(
	refresher: ^Credential_Refresher,
	cache: ^Credential_Cache,
	interval: time.Duration = CREDENTIAL_REFRESH_INTERVAL,
	margin: time.Duration = CREDENTIAL_REFRESH_MARGIN,
) -> Credential_Error {
	if refresher == nil ||
	   cache == nil ||
	   refresher.thread != nil ||
	   interval <= 0 ||
	   margin < 0 ||
	   interval >= margin {
		return {kind = .Invalid_Argument}
	}
	refresher.cache = cache
	refresher.interval = interval
	refresher.margin = margin
	refresher.stopping = false
	refresher.attempts = 0
	refresher.last = {}
	refresher.thread = thread.create_and_start_with_data(refresher, credential_refresher_run)
	if refresher.thread == nil {
		return {kind = .Allocation_Failed}
	}
	return {}
}

// The refresher's thread. It ends when stop is requested, or after the cache
// reports Closed (destroyed under it).
@(private)
credential_refresher_run :: proc(data: rawptr) {
	refresher := cast(^Credential_Refresher)data
	for {
		error := credential_refresh(refresher.cache, refresher.margin)
		// The refresh's temp allocations end here, so a long-lived thread does not grow its temp allocator.
		free_all(context.temp_allocator)

		sync.mutex_lock(&refresher.mutex)
		refresher.attempts += 1
		refresher.last = error
		if error.kind == .Closed {
			sync.mutex_unlock(&refresher.mutex)
			return
		}
		// Cond waits can wake early or spuriously; wait until the deadline or a stop.
		deadline := time.tick_add(time.tick_now(), refresher.interval)
		for !refresher.stopping {
			remaining := time.tick_diff(time.tick_now(), deadline)
			if remaining <= 0 {
				break
			}
			sync.cond_wait_with_timeout(&refresher.cond, &refresher.mutex, remaining)
		}
		stopping := refresher.stopping
		sync.mutex_unlock(&refresher.mutex)
		if stopping {
			return
		}
	}
}

// Stops and joins the thread. Waits at most for one refresh already in progress
// (the provider's calls, up to 4.5 s). Safe to call on a refresher never started.
// Call it from the thread that started the refresher, or from one other thread
// at a time; afterwards the refresher may be started again.
credential_refresher_stop :: proc(refresher: ^Credential_Refresher) {
	if refresher == nil || refresher.thread == nil {
		return
	}
	sync.mutex_lock(&refresher.mutex)
	refresher.stopping = true
	sync.cond_broadcast(&refresher.cond)
	sync.mutex_unlock(&refresher.mutex)
	thread.join(refresher.thread)
	thread.destroy(refresher.thread)
	refresher.thread = nil
}

// The number of refreshes run and the latest result, for health checks. Does
// not block beyond the refresher's mutex; any thread may call it.
credential_refresher_status :: proc(
	refresher: ^Credential_Refresher,
) -> (
	attempts: int,
	last: Credential_Error,
) {
	if refresher == nil {
		return 0, {kind = .Invalid_Argument}
	}
	sync.mutex_lock(&refresher.mutex)
	defer sync.mutex_unlock(&refresher.mutex)
	return refresher.attempts, refresher.last
}

credential_cancelled :: proc(cancel: ^Credential_Cancel) -> bool {
	if cancel == nil {
		return false
	}

	return sync.atomic_load(&cancel.cancelled) != 0
}

credential_snapshot_usable :: proc(snap: ^Credential_Snapshot, now: time.Time) -> bool {
	if snap == nil || snap.retired {
		return false
	}

	if !snap.has_expiry {
		return true
	}

	return time.diff(now, snap.expires) > CREDENTIAL_EXPIRY_SKEW
}

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

credential_snapshot_retire :: proc(cache: ^Credential_Cache, snap: ^Credential_Snapshot) {
	if snap == nil {
		return
	}

	snap.retired = true

	if snap.readers == 0 {
		credential_snapshot_erase(cache, snap)
	}
}

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
	if !credential_bounded_valid({access, secret, token}) {
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

credential_resolve :: proc(
	resolver: Credential_Resolver,
) -> (
	snap: ^Credential_Snapshot,
	error: Credential_Error,
) {
	if .Environment in resolver.modes {
		access := credential_env("AWS_ACCESS_KEY_ID")
		secret := credential_env("AWS_SECRET_ACCESS_KEY")
		token := credential_env("AWS_SESSION_TOKEN")
		defer credential_wipe_text(access)
		defer credential_wipe_text(secret)
		defer credential_wipe_text(token)

		if access != "" || secret != "" || token != "" {
			if !credential_bounded_valid({access, secret, token}) {
				return nil, {kind = .Incomplete, source = .Environment}
			}

			// AWS_CREDENTIAL_EXPIRATION, as exported with temporary credentials, bounds
			// them here too. Without it they are static.
			expiration := credential_env("AWS_CREDENTIAL_EXPIRATION")
			expires: time.Time
			if expiration != "" {
				parsed: bool
				expires, parsed = credential_instant_parse(expiration)
				if !parsed {
					return nil, {kind = .Incomplete, source = .Environment}
				}
				if time.diff(resolver.clock(resolver.clock_data), expires) <= CREDENTIAL_EXPIRY_SKEW {
					return nil, {kind = .Expired, source = .Environment}
				}
			}

			// The snapshot copies the triple before the deferred wipes run.
			return credential_snapshot_new(
				resolver.allocator,
				.Environment,
				access,
				secret,
				token,
				expires,
				expiration != "",
			)
		}
	}

	web_identity := credential_env("AWS_WEB_IDENTITY_TOKEN_FILE")
	defer credential_wipe_text(web_identity)

	if web_identity != "" {
		return nil, {kind = .Unsupported, source = .Environment, unsupported = .Web_Identity}
	}

	if .Profile in resolver.modes {
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
		defer credential_wipe_text(string(data))

		// A missing path, or one that is not a regular file (/dev/null is a common
		// way to turn the file off), means no profile; anything else fails closed.
		if read_error.kind != .None && read_error.kind != .Open_Failed && read_error.kind != .Not_Regular {
			return nil, {kind = .Unavailable, source = .Profile}
		}

		if unsupported != .None {
			return nil, {kind = .Unsupported, source = .Profile, unsupported = unsupported}
		}

		if loaded.access_key != "" || loaded.secret_key != "" || loaded.session_token != "" {
			if !credential_bounded_valid(loaded) {
				return nil, {kind = .Incomplete, source = .Profile}
			}

			return credential_snapshot_new(
				resolver.allocator,
				.Profile,
				loaded.access_key,
				loaded.secret_key,
				loaded.session_token,
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

	if .ECS in resolver.modes {
		relative := credential_env("AWS_CONTAINER_CREDENTIALS_RELATIVE_URI")
		defer credential_wipe_text(relative)

		if relative != "" {
			if !credential_relative_uri_ok(relative) {
				return nil, {kind = .Incomplete, source = .ECS}
			}

			return credential_fetch_document(
				resolver,
				.ECS,
				fmt.tprintf("http://169.254.170.2%s", relative),
				nil,
			)
		}
	}

	if credential_ec2_probe_permitted(resolver.modes) {
		return credential_fetch_ec2(resolver)
	}

	return nil, {kind = .Unavailable}
}

credential_fetch_ec2 :: proc(
	resolver: Credential_Resolver,
) -> (
	snap: ^Credential_Snapshot,
	error: Credential_Error,
) {
	reply, ok := credential_metadata_call(
		resolver.execute,
		"PUT",
		"http://169.254.169.254/latest/api/token",
		{"X-aws-ec2-metadata-token-ttl-seconds: 60"},
	)
	token := string(reply)
	defer credential_reply_wipe(resolver.execute, reply)

	if !ok ||
	   token == "" ||
	   len(token) > CREDENTIAL_IMDS_TOKEN_MAX ||
	   !credential_text_printable(token) {
		return nil, {kind = .Unavailable, source = .EC2}
	}

	token_header := fmt.tprintf("X-aws-ec2-metadata-token: %s", token)
	defer credential_wipe_text(token_header)
	role, role_ok := credential_metadata_call(
		resolver.execute,
		"GET",
		"http://169.254.169.254/latest/meta-data/iam/security-credentials/",
		{token_header},
	)
	role_name := strings.trim_space(string(role))
	if !role_ok ||
	   role_name == "" ||
	   len(role_name) > CREDENTIAL_ROLE_MAX ||
	   strings.contains_any(role_name, "/\r\n?#\\@") {
		return nil, {kind = .Unavailable, source = .EC2}
	}

	return credential_fetch_document(
		resolver,
		.EC2,
		fmt.tprintf(
			"http://169.254.169.254/latest/meta-data/iam/security-credentials/%s",
			role_name,
		),
		{token_header},
	)
}

credential_fetch_document :: proc(
	resolver: Credential_Resolver,
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
	data, ok := credential_metadata_call(resolver.execute, "GET", url, headers)
	// The reply is the document that carries the secret, not only its decoded copy.
	defer credential_reply_wipe(resolver.execute, data)
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
	if !credential_bounded_valid({document.access, document.secret, document.token}) {
		return nil, {kind = .Unavailable, source = source}
	}
	expires, expires_ok := credential_instant_parse(document.expiration)
	if !expires_ok {
		return nil, {kind = .Unavailable, source = source}
	}
	now := resolver.clock(resolver.clock_data)
	if time.diff(now, expires) <= CREDENTIAL_EXPIRY_SKEW {
		return nil, {kind = .Expired, source = source}
	}
	return credential_snapshot_new(
		resolver.allocator,
		source,
		document.access,
		document.secret,
		document.token,
		expires,
		true,
	)
}

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

	reply, result := execute(
		{method = method, url = url, headers = headers, allow_http = true, timeout_ms = 1500},
	)

	if !result.ok {
		return nil, false
	}

	return reply, true
}

// Fixed link-local metadata only. Full credential URIs and any other host are rejected.
credential_metadata_url_permitted :: proc(url: string) -> bool {
	if strings.contains_any(url, "\\@") ||
	   !strings.contains(url, "://") ||
	   !credential_text_printable(url) {
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
		return(
			role != "" &&
			len(role) <= CREDENTIAL_ROLE_MAX &&
			!strings.contains_any(role, "/?#\\\r\n@") \
		)
	}

	return false
}

credential_relative_uri_ok :: proc(relative: string) -> bool {
	if relative == "" || len(relative) > CREDENTIAL_RELATIVE_MAX {
		return false
	}

	if !strings.has_prefix(relative, "/") || strings.has_prefix(relative, "//") {
		return false
	}

	if strings.contains(relative, "://") || strings.contains_any(relative, "#\\@?") {
		return false
	}

	return credential_text_printable(relative)
}

// Printable ASCII only: no space, control character or byte above 0x7e. What the
// metadata service returns is put into URLs and header values.
credential_text_printable :: proc(text: string) -> bool {
	return text_visible(text)
}

credential_bounded_valid :: proc(value: AWS_Credentials) -> bool {
	return(
		len(value.access_key) <= CREDENTIAL_ACCESS_MAX &&
		len(value.secret_key) <= CREDENTIAL_SECRET_MAX &&
		len(value.session_token) <= CREDENTIAL_TOKEN_MAX &&
		aws_credentials_valid(value) \
	)
}

// Erases a metadata reply. Only the default executor's replies are known to be
// writable memory of the temporary allocator; an injected executor may return
// memory this package must not write to, and owns the lifetime of its replies.
credential_reply_wipe :: proc(execute: HTTP_Execute, reply: []byte) {
	if execute == http_execute_default && len(reply) > 0 {
		mem.zero_explicit(raw_data(reply), len(reply))
	}
}

// An expiry instant with an explicit zone:
// YYYY-MM-DDTHH:MM:SS[.fraction](Z|+HH:MM|-HH:MM). The fraction is dropped, which
// can only make credentials look as if they expire earlier. core:time's RFC 3339
// parser is not used: it stops inside a fraction longer than two digits.
credential_instant_parse :: proc(text: string) -> (instant: time.Time, ok: bool) {
	number :: proc(text: string) -> (value: int, ok: bool) {
		for index in 0 ..< len(text) {
			if text[index] < '0' || text[index] > '9' {
				return 0, false
			}
			value = value * 10 + int(text[index] - '0')
		}
		return value, len(text) > 0
	}
	if len(text) < 20 ||
	   len(text) > 64 ||
	   text[4] != '-' ||
	   text[7] != '-' ||
	   text[10] != 'T' ||
	   text[13] != ':' ||
	   text[16] != ':' {
		return {}, false
	}
	year := number(text[0:4]) or_return
	month := number(text[5:7]) or_return
	day := number(text[8:10]) or_return
	hour := number(text[11:13]) or_return
	minute := number(text[14:16]) or_return
	second := number(text[17:19]) or_return
	rest := text[19:]
	if rest[0] == '.' {
		digits := 1
		for digits < len(rest) && rest[digits] >= '0' && rest[digits] <= '9' {
			digits += 1
		}
		if digits == 1 {
			return {}, false
		}
		rest = rest[digits:]
	}
	offset: time.Duration
	switch {
	case rest == "Z":
	case len(rest) == 6 && (rest[0] == '+' || rest[0] == '-') && rest[3] == ':':
		hours := number(rest[1:3]) or_return
		minutes := number(rest[4:6]) or_return
		if hours > 23 || minutes > 59 {
			return {}, false
		}
		offset = time.Duration(hours) * time.Hour + time.Duration(minutes) * time.Minute
		if rest[0] == '-' {
			offset = -offset
		}
	case:
		return {}, false
	}
	instant = time.datetime_to_time(year, month, day, hour, minute, second) or_return
	return time.time_add(instant, -offset), true
}

credential_env :: proc(key: string) -> string {
	return os.get_env(key, context.temp_allocator)
}

credential_wipe_text :: proc(value: string) {
	if len(value) == 0 {
		return
	}

	mem.zero_explicit(raw_data(value), len(value))
}

credential_profile_load :: proc(
	path, profile: string,
	strict: bool,
) -> (
	credentials: AWS_Credentials,
	unsupported: Credential_Unsupported,
	data: []byte,
	error: Read_Error,
) {
	data, error = read_limited(path, 64 * 1024, context.temp_allocator, erase_on_failure = true)
	if error.kind != .None {
		return {}, {}, nil, error
	}
	section := ""
	source := string(data)
	// An editor's UTF-8 byte order mark is not part of the first section header.
	source = strings.trim_prefix(source, "\xef\xbb\xbf")
	for raw_line in strings.split_iterator(&source, "\n") {
		line := strings.trim_space(raw_line)

		if line == "" || line[0] == '#' || line[0] == ';' {
			continue
		}

		// A header may be followed by a comment: "[default] # note".
		if line[0] == '[' {
			if closing := strings.last_index_byte(line, ']'); closing > 0 {
				section = strings.trim_space(line[1:closing])
				continue
			}
		}

		if section != profile {
			continue
		}

		// "name = value" or "name: value", whichever delimiter comes first.
		equal := strings.index_any(line, "=:")

		if equal < 1 {
			continue
		}

		key := strings.trim_space(line[:equal])
		value := strings.trim_space(line[equal + 1:])

		// Option names are case-insensitive, as in the AWS CLI.
		is_one_of :: proc(key: string, names: ..string) -> bool {
			for name in names {
				if strings.equal_fold(key, name) {
					return true
				}
			}
			return false
		}
		found: Credential_Unsupported
		switch {
		case is_one_of(key, "aws_access_key_id"):
			credentials.access_key = value
		case is_one_of(key, "aws_secret_access_key"):
			credentials.secret_key = value
		case is_one_of(key, "aws_session_token"):
			credentials.session_token = value
		case is_one_of(key, "credential_process"):
			found = .Credential_Process
		case is_one_of(key, "web_identity_token_file"):
			found = .Web_Identity
		case is_one_of(
			     key,
			     "sso_start_url",
			     "sso_account_id",
			     "sso_role_name",
			     "sso_region",
			     "sso_session",
		     ):
			found = .SSO
		case is_one_of(key, "role_arn", "source_profile", "credential_source", "external_id"):
			found = .Assumed_Role
		}
		if strict && unsupported == .None {
			unsupported = found
		}
	}
	if unsupported != .None {
		credentials = {}
	}
	return
}

// Optional per-operation seam for isolated providers and offline tests. Defaults
// use Surf; implementations must preserve its bounded response/trust contract.
HTTP_Execute :: proc(request: HTTP_Request) -> ([]u8, surf.Buffered_HTTP_Result)

// One buffered request. Optional upload_file streams upload_size bytes instead of body.
HTTP_Request :: struct {
	method, url: string,
	body:        []u8,
	headers:     []string,
	ca_file:     string,
	allow_http:  bool,
	timeout_ms:  i64,
	upload_file: ^os.File,
	upload_size: i64,
}

// Default HTTP_Execute: Surf's buffered client.
http_execute_default :: proc(
	request: HTTP_Request,
) -> (
	[]u8,
	surf.Buffered_HTTP_Result,
) {
	return surf.buffered_http_execute(
		request.method,
		request.url,
		request.body,
		request.headers,
		request.ca_file,
		request.allow_http,
		request.timeout_ms,
		request.upload_file,
		request.upload_size,
	)
}
