package main

import "core:fmt"
import "core:os"
import "core:testing"

// Unit tests of cmd/tasks/signatures.odin. They need openssl, as the task does.

@(test)
openssl_digests_and_the_aws_example_signature :: proc(t: ^testing.T) {
	context.allocator = context.temp_allocator
	work, created := work_directory("tasks-signatures")
	testing.expect(t, created)
	defer os.remove_all(work)
	state := Signatures{work, true}
	testing.expect_value(t, openssl_digest(&state, "abc"), "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")
	// RFC 4231 test case 2: key "Jefe", data "what do ya want for nothing?".
	testing.expect_value(
		t,
		openssl_digest(&state, "what do ya want for nothing?", "4a656665"),
		"5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843",
	)
	// The presigned GET of the AWS documentation, as signatures_command checks it.
	query :: "X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=AKIAIOSFODNN7EXAMPLE%2F20130524%2Fus-east-1%2Fs3%2Faws4_request&X-Amz-Date=20130524T000000Z&X-Amz-Expires=86400&X-Amz-SignedHeaders=host"
	testing.expect_value(
		t,
		signature(&state, "GET\n/test.txt\n" + query + "\nhost:examplebucket.s3.amazonaws.com\n\nhost\nUNSIGNED-PAYLOAD"),
		"aeeed9bbccd4d02ee5c0109b86d86835f995330da4c265957d157751f604d404",
	)
	testing.expect(t, state.ok)
	ses_canonical := fmt.aprintf(
		"POST\n/v2/email/outbound-emails\n\ncontent-type:application/json\nhost:email.us-east-1.amazonaws.com\nx-amz-date:%s\n\ncontent-type;host;x-amz-date\n%s",
		SIGNATURE_STAMP,
		openssl_digest(&state, `{"fixture":true}`),
	)
	testing.expect_value(
		t,
		signature(&state, ses_canonical, "ses"),
		"e99a4c5a7187beeb1818b101c484bbee3869e6b24eac0d093e2111c1a4ce0153",
	)
}
