package main

import "core:encoding/hex"
import "core:fmt"
import "core:os"
import "core:strings"

// Recalculates the SigV4 fixtures with OpenSSL, independently of the library and
// of Odin's own HMAC, using public synthetic AWS example credentials.
SIGNATURE_SECRET :: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
SIGNATURE_STAMP :: "20130524T000000Z"
SIGNATURE_REGION :: "us-east-1"
SIGNATURE_HOST :: "examplebucket.s3.us-east-1.amazonaws.com"

Signatures :: struct {
	work: string,
	ok:   bool,
}

// `openssl dgst -sha256 [-mac HMAC -macopt hexkey:KEY]` over text.
openssl_digest :: proc(state: ^Signatures, text: string, key := "") -> string {
	input := fmt.aprintf("%s/input", state.work)
	if os.write_entire_file(input, text) != nil {
		state.ok = false
		return ""
	}
	command := make([dynamic]string)
	append(&command, "openssl", "dgst", "-sha256")
	if key != "" {
		append(&command, "-mac", "HMAC", "-macopt", fmt.aprintf("hexkey:%s", key))
	}
	append(&command, input)
	printed, code := output(command[:])
	fields := strings.fields(printed)
	if code != 0 || len(fields) == 0 {
		state.ok = false
		return ""
	}
	return fields[len(fields) - 1]
}

signature :: proc(state: ^Signatures, canonical: string, service := "s3") -> string {
	key := string(hex.encode(transmute([]u8)fmt.aprintf("AWS4%s", SIGNATURE_SECRET)))
	for part in ([]string{SIGNATURE_STAMP[:8], SIGNATURE_REGION, service, "aws4_request"}) {
		key = openssl_digest(state, part, key)
	}
	to_sign := fmt.aprintf(
		"AWS4-HMAC-SHA256\n%s\n%s/%s/%s/aws4_request\n%s",
		SIGNATURE_STAMP,
		SIGNATURE_STAMP[:8],
		SIGNATURE_REGION,
		service,
		openssl_digest(state, canonical),
	)
	return openssl_digest(state, to_sign, key)
}

signatures_command :: proc(arguments: []string) -> int {
	work, created := work_directory("signatures")
	if !created {
		return fail("cannot create a work directory")
	}
	defer os.remove_all(work)
	state := Signatures{work, true}
	requests := []struct {
		method, payload, expected: string,
	} {
		{"PUT", "payload", "ed63c9a16fbbdfc2127f409b79ffce52deaaea62ab8d39048ca5fc8d256e5b26"},
		{"DELETE", "", "703c365c9e031e61271a08e36dc622e00f12493b12901d9cf725e8f7f01f942b"},
		{"HEAD", "", "fdd51dae18ee3b7b2f9a6fe56ccec529798be849c3d8f94093884fec89aaf4d2"},
	}
	for request in requests {
		digest := openssl_digest(&state, request.payload)
		canonical := fmt.aprintf(
			"%s\n/a%%20b/c%%2Bd\n\nhost:%s\nx-amz-content-sha256:%s\nx-amz-date:%s\nx-amz-security-token:fixture/token+value\n\nhost;x-amz-content-sha256;x-amz-date;x-amz-security-token\n%s",
			request.method,
			SIGNATURE_HOST,
			digest,
			SIGNATURE_STAMP,
			digest,
		)
		actual := signature(&state, canonical)
		if !state.ok || actual != request.expected {
			return fail("signature mismatch: %s", request.method)
		}
		fmt.printf("%s %s\n", request.method, actual)
	}
	query :: "X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=AKIAIOSFODNN7EXAMPLE%2F20130524%2Fus-east-1%2Fs3%2Faws4_request&X-Amz-Date=20130524T000000Z&X-Amz-Expires=86400&X-Amz-SignedHeaders=host"
	presign := signature(
		&state,
		fmt.aprintf("GET\n/test.txt\n%s\nhost:examplebucket.s3.amazonaws.com\n\nhost\nUNSIGNED-PAYLOAD", query),
	)
	if !state.ok || presign != "aeeed9bbccd4d02ee5c0109b86d86835f995330da4c265957d157751f604d404" {
		return fail("presign mismatch")
	}
	fmt.printf("GET presign %s\n", presign)
	ses := signature(
		&state,
		fmt.aprintf(
			"POST\n/v2/email/outbound-emails\n\ncontent-type:application/json\nhost:email.us-east-1.amazonaws.com\nx-amz-date:%s\n\ncontent-type;host;x-amz-date\n%s",
			SIGNATURE_STAMP,
			openssl_digest(&state, `{"fixture":true}`),
		),
		"ses",
	)
	if !state.ok {
		return fail("openssl failed")
	}
	fmt.printf("SES POST %s\n", ses)
	return 0
}
