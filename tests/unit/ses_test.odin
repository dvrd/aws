package aws

import network_client "shared:surf"
import "core:strings"
import "core:sync"
import "core:testing"
import "core:time"

// Unit tests of src/ses.odin.
@(test)
ses_operation_uses_injected_http_and_preserves_outcomes :: proc(t: ^testing.T) {
	sync.mutex_lock(&aws_test_http_mutex)
	defer sync.mutex_unlock(&aws_test_http_mutex)
	credentials := AWS_Credentials{"fixture-key", "fixture-secret", ""}
	config := SES_Config {
		region    = "us-east-1",
		sender    = "from@example.test",
		recipient = "to@example.test",
	}

	state := AWS_Test_HTTP {
		t        = t,
		method   = "POST",
		url      = "https://email.us-east-1.amazonaws.com/v2/email/outbound-emails",
		status   = 200,
		response = `{"MessageId":"fixture-message"}`,
		ok       = true,
	}

	aws_test_http_state = &state
	defer {
		aws_test_http_state = nil
	}

	testing.expect_value(t, ses_send(config, credentials, "subject", "body", time.Time{}, aws_test_http), .None)
	state.response = "{}"
	testing.expect_value(
		t,
		ses_send(config, credentials, "subject", "body", time.Time{}, aws_test_http),
		.Invalid_Response,
	)
	state.status = 403
	testing.expect_value(t, ses_send(config, credentials, "subject", "body", time.Time{}, aws_test_http), .Rejected)
	state.status = 0
	state.ok = false
	testing.expect_value(t, ses_send(config, credentials, "subject", "body", time.Time{}, aws_test_http), .Unavailable)
	// SES answered 200 but the body was lost: the message was accepted, so this
	// must never be reported as Unavailable (which invites a resend).
	state.status = 200
	state.ok = false
	testing.expect_value(t, ses_send(config, credentials, "subject", "body", time.Time{}, aws_test_http), .Invalid_Response)
	testing.expect_value(t, state.calls, 5)
}

@(test)
ses_keeps_the_same_shared_sigv4_owner_with_its_service_scope :: proc(t: ^testing.T) {
	credentials := AWS_Credentials{"AKIAIOSFODNN7EXAMPLE", "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY", ""}
	headers := ses_headers(
		"us-east-1",
		credentials,
		"email.us-east-1.amazonaws.com",
		"20130524T000000Z",
		transmute([]u8)string(`{"fixture":true}`),
	)
	testing.expect_value(t, len(headers), 3)
	testing.expect_value(
		t,
		headers[2],
		"Authorization: AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/20130524/us-east-1/ses/aws4_request, SignedHeaders=content-type;host;x-amz-date, Signature=e99a4c5a7187beeb1818b101c484bbee3869e6b24eac0d093e2111c1a4ce0153",
	)
}

SES_Hardening :: struct {
	status: int,
	date:   string,
}

ses_hardening: SES_Hardening

ses_hardening_mutex: sync.Mutex

ses_hardening_http :: proc(request: HTTP_Request) -> ([]u8, network_client.Buffered_HTTP_Result) {
	for line in request.headers {
		if strings.has_prefix(line, "x-amz-date: ") {
			ses_hardening.date = strings.clone(line[len("x-amz-date: "):], context.temp_allocator)
		}
	}
	return transmute([]u8)string(`{"MessageId":"fixture-message"}`), {status = ses_hardening.status, ok = ses_hardening.status == 200, transport_ok = true}
}

@(test)
ses_signs_with_the_current_time_and_treats_every_answer_as_acknowledged :: proc(t: ^testing.T) {
	sync.mutex_lock(&ses_hardening_mutex)
	defer sync.mutex_unlock(&ses_hardening_mutex)
	credentials := AWS_Credentials{"fixture-key", "fixture-secret", ""}
	config := SES_Config {
		region    = "us-east-1",
		sender    = "from@example.test",
		recipient = "to@example.test",
	}
	before := s3_timestamp(time.now())
	ses_hardening = {
		status = 200,
	}
	testing.expect_value(t, ses_send(config, credentials, "subject", "body", time.Time{}, ses_hardening_http), SES_Error.None)
	after := s3_timestamp(time.now())
	testing.expect(t, ses_hardening.date >= before && ses_hardening.date <= after, "the zero time signs with the current time")

	fixed := time.unix(1369353600, 0)
	testing.expect_value(t, ses_send(config, credentials, "subject", "body", fixed, ses_hardening_http), SES_Error.None)
	testing.expect_value(t, ses_hardening.date, "20130524T000000Z")

	for item in ([]struct {
			status:   int,
			expected: SES_Error,
		} {
			{400, .Rejected},
			{403, .Rejected},
			{404, .Rejected},
			{301, .Rejected},
			// A throttle or a server error is still an acknowledged answer.
			{429, .Rejected},
			{503, .Rejected},
		}) {
		ses_hardening.status = item.status
		testing.expect_value(t, ses_send(config, credentials, "subject", "body", fixed, ses_hardening_http), item.expected)
	}
}
