package main

import "core:encoding/json"
import "core:strings"
import "core:testing"
import "core:time"

// Offline campaign failures; no AWS CLI, provider requests or real credentials.
@(test)
credential_rejection_stops_before_any_native_action :: proc(t: ^testing.T) {
	test: Test
	context.allocator = test_begin(&test, t)
	defer test_end(&test)
	fixture(&test)
	planned(&test)
	initial, _ := text_of(document(&test, "state.json"), "run_id")
	test.runner.launch = launch_forbidden
	test.runner.credentials = proc(runner: ^Runner, scope: json.Object, deadline: time.Duration) -> (Environment, Failure) {
		return {}, .Account_Not_Verified
	}
	_, failure := command(&test, "run")
	testing.expect_value(t, failure, Failure.Account_Not_Verified)
	state := document(&test, "state.json")
	testing.expect_value(t, phase_of(state), "PREPARED")
	testing.expect(t, text_is(state, "run_id", initial))
	testing.expect_value(t, len(test.actions), 0)
}

@(test)
read_denial_or_throttle_is_not_absence_and_cannot_start_put :: proc(t: ^testing.T) {
	for kind in ([]string{"Rejected", "Unavailable"}) {
		test: Test
		context.allocator = test_begin(&test, t)
		defer test_end(&test)
		fixture(&test)
		planned(&test)
		test.kind = kind
		test.runner.launch =
		proc(
			runner: ^Runner,
			state: json.Object,
			verb: string,
			environment: Environment,
			deadline: time.Duration,
		) -> (
			json.Object,
			Failure,
		) {
			test := cast(^Test)runner.user
			append(&test.actions, verb)
			value := result(false, "Unverified", "Not_Sent")
			value["s3_kind"] = test.kind
			return value, .None
		}
		value, failure := command(&test, "run")
		testing.expect_value(t, failure, Failure.None)
		testing.expect(t, actions_are(&test, {"read"}))
		testing.expect_value(t, phase_of(value), "READ_INTENT")
		testing.expect(t, !is_true(value, "qualified"))
		_, failure = command(&test, "run")
		testing.expect_value(t, failure, Failure.Run_Requires_Review)
		testing.expect(t, actions_are(&test, {"read"}))
	}
}

@(test)
http_mutation_failures_retain_status_and_intent_without_resending :: proc(t: ^testing.T) {
	cases := []struct {
		verb, phase, reason: string,
	}{{"put", "PUT_INTENT", "Put_Failed"}, {"delete", "DELETE_INTENT", "Delete_Failed"}, {"ses", "SES_INTENT", "SES_Failed"}}
	for item in cases {
		for status in ([]i64{403, 429, 503}) {
			test: Test
			context.allocator = test_begin(&test, t)
			defer test_end(&test)
			fixture(&test, ses = item.verb == "ses")
			planned(&test)
			initial, _ := text_of(document(&test, "state.json"), "run_id")
			test.verb = item.verb
			test.kind = item.reason
			test.status = status
			test.runner.launch =
			proc(
				runner: ^Runner,
				state: json.Object,
				verb: string,
				environment: Environment,
				deadline: time.Duration,
			) -> (
				json.Object,
				Failure,
			) {
				test := cast(^Test)runner.user
				append(&test.actions, verb)
				if verb == test.verb {
					value := result(false, "Unverified", verb = verb)
					value["reason"] = test.kind
					value["mutation_status"] = test.status
					value["ses_kind"] = "Rejected" if verb == "ses" else "None"
					return value, .None
				}
				return result(object = "Owned" if verb == "put" else "Absent", verb = verb if is_mutation(verb) else ""), .None
			}
			value, failure := command(&test, "run")
			testing.expect_value(t, failure, Failure.None)
			testing.expect_value(t, phase_of(value), item.phase)
			testing.expect(t, !is_true(value, "qualified"))
			outcome, _ := object_of(value, strings.concatenate({item.verb, "_result"}))
			testing.expect(t, integer_is(outcome, "mutation_status", status))
			testing.expect(t, text_is(outcome, strings.concatenate({item.verb, "_effect"}), "Response_Received"))
			before := len(test.actions)
			_, failure = command(&test, "run")
			testing.expect_value(t, failure, Failure.Run_Requires_Review)
			testing.expect_value(t, len(test.actions), before)
			testing.expect(t, text_is(document(&test, "state.json"), "run_id", initial))
			testing.expect(t, !strings.contains(read_text(state_file(&test.runner, "state.json")), SECRET))
		}
	}
}
