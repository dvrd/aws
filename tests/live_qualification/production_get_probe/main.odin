package main

import aws "shared:aws"
import "core:fmt"
import "core:os"
import "core:strconv"
import "core:strings"
import "core:time"

main :: proc() {
	if len(os.args) != 2 || !strings.has_prefix(os.args[1], "https://127.0.0.1:") {
		os.exit(2)
	}

	port, valid := strconv.parse_uint(os.args[1][18:], 10)

	if !valid || port < 1 || port > 65535 {
		os.exit(2)
	}

	config := aws.S3_Config {
		bucket     = "fixturebucket",
		region     = "us-east-1",
		endpoint   = os.args[1],
		path_style = true,
	}

	// This intentionally uses the public SIGNED operation and its DEFAULT native
	// executor, not an injected HTTP callback. The owned peer closes during TLS.
	body, error := aws.s3_get_at(
		config,
		{access_key = "fixture-access", secret_key = "fixture-secret"},
		"qualification/fixture.txt",
		64,
		time.now(),
	)
	defer delete(body)

	if error != .Unavailable || len(body) != 0 {
		os.exit(2)
	}

	fmt.println(`{"native_default_get":true,"peer_closed_during_tls":true,"body_bytes":0}`)
}
