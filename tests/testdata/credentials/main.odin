package main

import "core:fmt"
import "core:mem"
import "core:os"
import "core:strings"
import aws "shared:aws"
import surf "shared:surf"

mode: string
calls: int
metadata :: proc(
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
	surf.Buffered_HTTP_Result,
) {
	assert(
		allow_http && timeout_ms == 1500 && ca_file == "" && len(body) == 0 && upload_file == nil && upload_size == 0,
	)
	step := calls
	calls += 1
	if mode == "imds" {
		switch step {
		case 0:
			assert(method == "PUT" && url == "http://169.254.169.254/latest/api/token")
			assert(len(headers) == 1 && headers[0] == "X-aws-ec2-metadata-token-ttl-seconds: 60")
			return transmute([]u8)string("fixture-token"), {status = 200, ok = true, transport_ok = true}
		case 1:
			assert(method == "GET" && url == "http://169.254.169.254/latest/meta-data/iam/security-credentials/")
			assert(len(headers) == 1 && headers[0] == "X-aws-ec2-metadata-token: fixture-token")
			return transmute([]u8)string("fixture-role\n"), {status = 200, ok = true, transport_ok = true}
		case 2:
			assert(
				method == "GET" &&
				url == "http://169.254.169.254/latest/meta-data/iam/security-credentials/fixture-role",
			)
			assert(len(headers) == 1 && headers[0] == "X-aws-ec2-metadata-token: fixture-token")
		case:
			panic("unexpected metadata request")
		}
	} else {
		assert(method == "GET" && url == "http://169.254.170.2/v2/credentials/fixture" && len(headers) == 0)
	}
	if mode == "transport-failure" {
		return nil, {status = 503, error = {kind = .IO_Failed, phase = .Read, write_effect = .Unknown}}
	}
	if mode == "malformed" {
		return transmute([]u8)string("{bad"), {status = 200, ok = true, transport_ok = true}
	}
	if mode == "invalid-credentials" {
		return transmute([]u8)string(`{"AccessKeyId":"bad\nkey","SecretAccessKey":"secret","Token":"token"}`), {
			status = 200,
			ok = true,
			transport_ok = true,
		}
	}
	return transmute([]u8)string(
		`{"AccessKeyId":"fixture-key","SecretAccessKey":"fixture-secret","Token":"fixture-session"}`,
	), {status = 200, ok = true, transport_ok = true}
}

main :: proc() {
	assert(len(os.args) == 2)
	mode = os.args[1]
	tracker: mem.Tracking_Allocator
	mem.tracking_allocator_init(&tracker, context.allocator)
	defer mem.tracking_allocator_destroy(&tracker)
	arena: mem.Dynamic_Arena
	mem.dynamic_arena_init(
		&arena,
		block_allocator = mem.tracking_allocator(&tracker),
		array_allocator = mem.tracking_allocator(&tracker),
		block_size = 4096,
	)
	context.temp_allocator = mem.dynamic_arena_allocator(&arena)
	credentials, ok := aws.aws_credentials_with_http(metadata)

	switch mode {
	case "environment", "profile":
		assert(
			ok &&
			credentials.access_key == "fixture-key" &&
			credentials.secret_key == "fixture-secret" &&
			credentials.session_token == "fixture-session" &&
			calls == 0,
		)
	case "ecs":
		assert(ok && credentials.access_key == "fixture-key" && calls == 1)
	case "imds":
		assert(ok && credentials.access_key == "fixture-key" && calls == 3)
	case "partial-env", "partial-profile", "token-only-profile", "oversize", "disabled", "invalid-relative":
		assert(!ok && calls == 0)
	case "transport-failure", "malformed", "invalid-credentials":
		assert(!ok && calls == 1)
	case:
		panic("unknown fixture")
	}

	if mode == "oversize" {
		assert(tracker.total_memory_allocated < 65536, "oversize credential bytes allocated before rejection")
	}

	// Synthetic process-only environment changes prove per-operation rotation;
	// metadata's provider is still fake and no real configuration is consulted.
	if mode == "environment" {
		assert(os.set_env("AWS_ACCESS_KEY_ID", "rotated-key") == nil)
		next, good := aws.aws_credentials_with_http(metadata)
		assert(good && next.access_key == "rotated-key" && calls == 0)
	}

	_, nil_ok := aws.aws_credentials_with_http(nil)
	assert(!nil_ok && calls <= 3)
	mem.dynamic_arena_destroy(&arena)
	assert(tracker.current_memory_allocated == 0)
	fmt.println(mode, "calls", calls, "retained", tracker.current_memory_allocated)
}
