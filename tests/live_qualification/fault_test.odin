package main

import aws "shared:aws"
import surf "shared:surf"
import "core:encoding/json"
import "core:mem"
import "core:strings"
import "core:testing"

// These are deterministic SDK/qualification boundary faults, not live providers.
AWS_Qualification_Fault :: struct {
	t:                     ^testing.T,
	status, reads, writes: int,
	object:                Object,
	read_failure:          bool,
}
aws_fault_get :: proc(
	_: string,
	headers: []string,
	_: i64,
	_: int,
	allocator: mem.Allocator,
) -> (
	[]u8,
	int,
	aws.S3_Get_Error,
) {
	fault := cast(^AWS_Qualification_Fault)context.user_ptr
	fault.reads += 1
	signed := false
	for header in headers {
		if strings.has_prefix(header, "Authorization: AWS4-HMAC-SHA256 ") {
			signed = true
		}
	}
	testing.expect(fault.t, signed)
	if fault.read_failure {
		raw := "<Error><Code>ExpiredToken</Code><Message>private-fault-body</Message></Error>"
		body := make([]u8, len(raw), allocator)
		copy(body, transmute([]u8)raw)
		// Let the actual public SDK classify the status and dispose of this body.
		return body, fault.status, .None
	}
	if fault.object == .Absent {
		return nil, 404, .None
	}
	owned := strings.concatenate({PAYLOAD_PREFIX, TEST_RUN})
	defer delete(owned)
	body := make([]u8, len(owned), allocator)
	copy(body, transmute([]u8)owned)
	return body, 200, .None
}
aws_fault_write :: proc(request: aws.HTTP_Request) -> ([]u8, surf.Buffered_HTTP_Result) {
	fault := cast(^AWS_Qualification_Fault)context.user_ptr
	fault.writes += 1
	testing.expect(fault.t, !request.allow_http && request.timeout_ms <= 15000)
	testing.expect(fault.t, request.method == "PUT" || request.method == "DELETE" || request.method == "POST")
	return nil, {status = fault.status}
}
aws_fault_probe :: proc(fault: ^AWS_Qualification_Fault, action: Action, scope := TEST_SCOPE) -> Result {
	previous := context.user_ptr
	context.user_ptr = fault
	defer context.user_ptr = previous

	return probe(
		scope,
		action,
		TEST_RUN,
		{access_key = "fixture", secret_key = "fixture"},
		{get = aws_fault_get, write = aws_fault_write},
	)
}
aws_fault_redacted :: proc(t: ^testing.T, result: Result) {
	data, error := json.marshal(result, {use_enum_names = true})
	assert(error == nil)
	defer delete(data)
	testing.expect(t, !strings.contains(string(data), "private-") && !strings.contains(string(data), "<Error>"))
}

@(test)
aws_qualification_read_denial_credential_style_and_throttle_stop_before_any_write :: proc(t: ^testing.T) {
	for status in ([]int{400, 403, 429, 503}) {
		for action in ([]Action{.Read, .Put, .Delete}) {
			fault := AWS_Qualification_Fault {
				t            = t,
				status       = status,
				read_failure = true,
			}

			result := aws_fault_probe(&fault, action)
			testing.expect(t, !result.ok && result.reason == .Read_Failed && result.object == .Unverified)
			testing.expect_value(t, result.s3_kind, status >= 429 ? aws.S3_Get_Error.Unavailable : .Rejected)
			testing.expect_value(t, fault.reads, 1)
			testing.expect_value(t, fault.writes, 0)
			testing.expect_value(t, result.put_effect, .Not_Sent)
			testing.expect_value(t, result.delete_effect, .Not_Sent)
			aws_fault_redacted(t, result)
		}
	}
}

@(test)
aws_qualification_write_failures_preserve_response_evidence_without_internal_replay :: proc(t: ^testing.T) {
	for status in ([]int{400, 403, 429, 503}) {
		for action in ([]Action{.Put, .Delete}) {
			fault := AWS_Qualification_Fault {
				t      = t,
				status = status,
				object = action == .Put ? Object.Absent : .Owned,
			}

			result := aws_fault_probe(&fault, action)
			testing.expect(t, !result.ok && result.object == .Unverified)
			testing.expect_value(t, result.mutation_status, status)
			effect := result.put_effect if action == .Put else result.delete_effect
			testing.expect_value(t, effect, .Response_Received)
			testing.expect_value(t, fault.reads, 1)
			testing.expect_value(t, fault.writes, 1)
			// A caller's explicit reconciliation reads once; it must not repeat mutation.
			reconciled := aws_fault_probe(&fault, .Reconcile)
			testing.expect(t, reconciled.ok && reconciled.object == fault.object)
			testing.expect_value(t, fault.reads, 2)
			testing.expect_value(t, fault.writes, 1)
			aws_fault_redacted(t, result)
		}
	}
}

@(test)
aws_qualification_ses_denial_and_throttle_remain_acknowledged_failures_without_replay :: proc(t: ^testing.T) {
	scope := TEST_SCOPE
	scope.allow_ses = true
	scope.ses_sender = "fixture@example.test"

	for status in ([]int{403, 429, 503}) {
		fault := AWS_Qualification_Fault {
			t      = t,
			status = status,
		}

		result := aws_fault_probe(&fault, .SES, scope)
		testing.expect(t, !result.ok && result.reason == .SES_Failed && result.ses_kind == .Rejected)
		testing.expect_value(t, result.ses_effect, .Response_Received)
		testing.expect_value(t, result.mutation_status, status)
		testing.expect_value(t, fault.writes, 1)
		testing.expect_value(t, fault.reads, 0)
	}
}
