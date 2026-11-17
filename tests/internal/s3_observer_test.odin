package aws

import "core:sync"
import "core:testing"
import "core:time"

S3_Observer_Record :: struct {
	calls, failures: int,
}

// Written only by tests that hold aws_test_http_mutex.
s3_observer_record: S3_Observer_Record

s3_observer_test_observe :: proc(started: time.Tick, ok: bool) {
	assert(time.tick_since(started) >= 0)
	s3_observer_record.calls += 1
	if !ok {
		s3_observer_record.failures += 1
	}
}

@(test)
s3_observer_reports_sent_requests_and_their_outcome :: proc(t: ^testing.T) {
	sync.mutex_lock(&aws_test_http_mutex)
	defer sync.mutex_unlock(&aws_test_http_mutex)
	s3_observer_record = {}
	s3_observer_set(s3_observer_test_observe)
	defer s3_observer_set(nil)

	credentials := AWS_Credentials{"fixture-key", "fixture-secret", "fixture-token"}
	config := S3_Config{bucket = "examplebucket", region = "us-east-1"}
	state := AWS_Test_HTTP {
		t      = t,
		method = "DELETE",
		url    = "https://examplebucket.s3.us-east-1.amazonaws.com/a%20b",
		status = 204,
		ok     = true,
	}
	aws_test_http_state = &state
	defer aws_test_http_state = nil
	result := s3_delete(config, credentials, "a b", http_execute = aws_test_http)
	testing.expect(t, result.ok)
	testing.expect_value(t, s3_observer_record, S3_Observer_Record{calls = 1})

	state.status = 503
	state.ok = false
	result = s3_delete(config, credentials, "a b", http_execute = aws_test_http)
	testing.expect(t, !result.ok)
	testing.expect_value(t, s3_observer_record, S3_Observer_Record{calls = 2, failures = 1})

	result = s3_delete(config, {}, "a b", http_execute = aws_test_http)
	testing.expect(t, !result.ok && state.calls == 2, "invalid credentials never reach HTTP")
	testing.expect_value(t, s3_observer_record.calls, 2)
}

@(test)
s3_observer_counts_a_missing_object_as_an_answer :: proc(t: ^testing.T) {
	sync.mutex_lock(&aws_test_http_mutex)
	defer sync.mutex_unlock(&aws_test_http_mutex)
	s3_observer_record = {}
	s3_observer_set(s3_observer_test_observe)
	defer s3_observer_set(nil)

	fixture := S3_Get_Fixture{t = t, body_size = 7, limit = 8}
	s3_get_fixture = &fixture
	defer s3_get_fixture = nil
	config := S3_Config{bucket = "examplebucket", region = "us-east-1"}
	credentials := AWS_Credentials {
		"AKIAIOSFODNN7EXAMPLE",
		"wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
		"fixture/token+value",
	}
	cases := []struct {
		status:   int,
		error:    S3_Get_Error,
		failures: int,
	}{{200, .None, 0}, {404, .Not_Found, 0}, {403, .Rejected, 1}, {503, .Unavailable, 2}}
	for item, index in cases {
		fixture.status = item.status
		body, e := s3_get(
			config,
			credentials,
			"a b/c+d",
			8,
			time.unix(1369353600, 0),
			context.allocator,
			s3_get_fixture_execute,
		)
		delete(body)
		testing.expect_value(t, e, item.error)
		testing.expect_value(t, s3_observer_record.calls, index + 1)
		testing.expect_value(t, s3_observer_record.failures, item.failures)
	}

	_, e := s3_get(config, credentials, "", 8, allocator = context.allocator, execute = s3_get_fixture_execute)
	testing.expect_value(t, e, S3_Get_Error.Invalid_Input)
	testing.expect_value(t, s3_observer_record.calls, len(cases))
}
