package aws

import network_client "shared:surf"
import "core:fmt"
import "core:os"
import "core:strings"
import "core:sync"
import "core:testing"
import "core:thread"
import "core:time"

// Concurrency stress of the credential cache.
// Many readers against one refresher. Each generation is a distinct triple, so a
// lease that mixed two generations, or outlived its storage, shows as a mismatch.
Credential_Stress :: struct {
	cache:      Credential_Cache,
	now:        i64, // unix seconds, atomic
	generation: i64, // atomic
	stop:       i64, // atomic
	leases:     i64, // atomic
	mismatches: i64, // atomic
	unexpected: i64, // atomic
}

credential_stress: ^Credential_Stress

credential_stress_clock :: proc(data: rawptr) -> time.Time {
	return time.unix(sync.atomic_load(&(cast(^Credential_Stress)data).now), 0)
}

credential_stress_http :: proc(request: HTTP_Request) -> ([]u8, HTTP_Result) {
	state := credential_stress
	generation := sync.atomic_add(&state.generation, 1)
	// Every document expires one hour after the moment it was fetched.
	year, month, day := time.date(time.unix(sync.atomic_load(&state.now) + 3600, 0))
	hour, minute, second := time.clock(time.unix(sync.atomic_load(&state.now) + 3600, 0))
	body := fmt.tprintf(
		`{{"Code":"Success","AccessKeyId":"key-%d","SecretAccessKey":"secret-%d","Token":"token-%d","Expiration":"%04d-%02d-%02dT%02d:%02d:%02dZ"}}`,
		generation,
		generation,
		generation,
		year,
		int(month),
		day,
		hour,
		minute,
		second,
	)
	return transmute([]u8)body, {ok = true, status = 200, transport_ok = true}
}

credential_stress_reader :: proc(data: rawptr) {
	state := cast(^Credential_Stress)data
	turn := 0
	for sync.atomic_load(&state.stop) == 0 {
		lease: Credential_Lease
		failure: Credential_Error
		// Both kinds of lease share the snapshots.
		if turn % 2 == 0 {
			lease, failure = credential_lease_cached(&state.cache)
		} else {
			lease, failure = credential_lease(&state.cache)
		}
		turn += 1
		if failure.kind != .None {
			// Only Expired can happen: the provider always succeeds and readers stay below the waiter cap.
			if failure.kind != .Expired {
				sync.atomic_add(&state.unexpected, 1)
			}
			continue
		}
		access, secret, token := lease.access_key, lease.secret_key, lease.session_token
		consistent :=
			strings.has_prefix(access, "key-") &&
			strings.has_prefix(secret, "secret-") &&
			strings.has_prefix(token, "token-") &&
			access[len("key-"):] == secret[len("secret-"):] &&
			access[len("key-"):] == token[len("token-"):]
		if !consistent {
			sync.atomic_add(&state.mismatches, 1)
		}
		sync.atomic_add(&state.leases, 1)
		credential_lease_release(&state.cache, &lease)
		free_all(context.temp_allocator)
	}
}

@(test)
credential_cache_serves_consistent_triples_under_concurrent_refresh :: proc(t: ^testing.T) {
	saved := credential_test_env_push()
	defer credential_test_env_pop(saved)
	directory, directory_error := os.make_directory_temp("", "aws-cache-*", context.allocator)
	testing.expect(t, directory_error == nil)
	defer delete(directory)
	defer os.remove(directory)
	credential_test_absent(directory)
	testing.expect(t, os.set_env("AWS_CONTAINER_CREDENTIALS_RELATIVE_URI", "/v2/credentials/fixture") == nil)

	state := new(Credential_Stress)
	defer free(state)
	state.now = 1704067200
	credential_stress = state
	defer credential_stress = nil
	testing.expect_value(
		t,
		credential_cache_init(&state.cache, credential_stress_http, credential_stress_clock, state).kind,
		Credential_Error_Kind.None,
	)
	testing.expect_value(t, credential_refresh(&state.cache).kind, Credential_Error_Kind.None)

	readers: [6]^thread.Thread
	for &reader in readers {
		reader = thread.create_and_start_with_data(state, credential_stress_reader)
	}
	// Each step moves the clock into the margin of the current credentials, so
	// every refresh publishes a new generation while leases are being taken.
	refreshes := 0
	for step in 0 ..< 400 {
		sync.atomic_add(&state.now, 3600 - 60)
		failure := credential_refresh(&state.cache)
		if failure.kind == .None {
			refreshes += 1
		} else {
			// A reader's own refresh can be running: that is the only other outcome.
			testing.expect_value(t, failure.kind, Credential_Error_Kind.Busy)
		}
		if step % 16 == 0 {
			time.sleep(time.Millisecond)
		}
		free_all(context.temp_allocator)
	}
	sync.atomic_store(&state.stop, 1)
	for reader in readers {
		thread.join(reader)
		thread.destroy(reader)
	}
	testing.expect(t, refreshes > 0)
	testing.expect(t, sync.atomic_load(&state.leases) > 0)
	testing.expect_value(t, sync.atomic_load(&state.mismatches), 0)
	testing.expect_value(t, sync.atomic_load(&state.unexpected), 0)
	// No reader is left on any snapshot, so the cache can be destroyed.
	testing.expect_value(t, credential_cache_destroy(&state.cache).kind, Credential_Error_Kind.None)
}
