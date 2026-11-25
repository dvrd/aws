package main

import aws "shared:aws"
import "core:encoding/json"
import "core:fmt"
import "core:os"
import "core:strconv"
import "core:strings"
import "core:time"

main :: proc() {
	if len(os.args) != 6 || !strings.has_prefix(os.args[1], "https://127.0.0.1:") {
		os.exit(2)
	}

	port, valid := strconv.parse_uint(os.args[1][18:], 10)

	if !valid || port == 0 || port > 65535 {
		os.exit(2)
	}

	status, status_valid := strconv.parse_uint(os.args[4], 10)

	if !status_valid || status > 599 {
		os.exit(2)
	}

	config := aws.S3_Config {
		bucket     = "fixturebucket",
		region     = "us-east-1",
		endpoint   = os.args[1],
		ca_file    = os.args[2],
		path_style = true,
	}

	credentials := aws.AWS_Credentials {
		access_key    = "public-fixture-key",
		secret_key    = "public-fixture-secret",
		session_token = "public-fixture-session",
	}

	result: aws.S3_Result
	body := "public-fixture-body"
	// Public signed APIs and their unchanged DEFAULT native Surf executor.
	switch os.args[3] {
	case "PUT":
		result = aws.s3_put(
			config,
			credentials,
			"qualification/owned.txt",
			transmute([]u8)body,
			"text/plain",
			time.now(),
		)
	case "DELETE":
		result = aws.s3_delete(config, credentials, "qualification/owned.txt", time.now())
	case:
		os.exit(2)
	}

	expected_ok := status >= 200 && status < 300
	passed := result.status == int(status) && result.ok == expected_ok

	if os.args[5] == "response" {
		passed = passed && result.status != 0 && result.error == aws.s3_status_error(int(status))
	} else if os.args[5] == "trust-failure" {
		passed =
			passed &&
			status == 0 &&
			result.status == 0 &&
			result.error == .Rejected &&
			result.effect == .Not_Sent
	} else {
		os.exit(2)
	}

	// No credentials, headers, resource identifiers or provider body in the result.
	observation := struct {
		passed, ok, transport_ok: bool,
		status:                   int,
	}{passed, result.ok, result.status != 0, result.status}
	data, error := json.marshal(observation)
	assert(error == nil)
	defer delete(data)
	fmt.println(string(data))

	if !passed {
		os.exit(1)
	}
}
