package aws

import network_client "shared:surf"
import "core:os"
import "core:strings"
import "core:sync"
import "core:testing"

AWS_Test_HTTP :: struct {
	t:                 ^testing.T,
	calls:             int,
	method, url, body: string,
	file_body:         bool,
	status:            int,
	response:          string,
	ok:                bool,
}

// Serialize only the shared fake provider; unrelated tests can run in parallel.
aws_test_http_mutex: sync.Mutex

aws_test_http_state: ^AWS_Test_HTTP

aws_test_http :: proc(request: HTTP_Request) -> ([]u8, network_client.Buffered_HTTP_Result) {
	state := aws_test_http_state
	state.calls += 1
	testing.expect_value(state.t, request.method, state.method)
	testing.expect_value(state.t, request.url, state.url)
	testing.expect(state.t, !request.allow_http && request.ca_file == "", "fake peer receives HTTPS policy")
	if state.file_body {
		testing.expect(state.t, request.upload_file != nil && request.upload_size == 7 && request.timeout_ms == 120000)
		buffer: [7]u8
		n, error := os.read(request.upload_file, buffer[:])
		testing.expect(state.t, error == nil && n == 7 && string(buffer[:]) == "payload")
	} else {
		testing.expect(state.t, request.upload_file == nil && request.upload_size == 0 && request.timeout_ms == 15000)

		if state.body != "" {
			testing.expect_value(state.t, string(request.body), state.body)
		}
	}
	auth, date := false, false
	for header in request.headers {
		if strings.has_prefix(header, "Authorization: AWS4-HMAC-SHA256 Credential=fixture-key/") {
			auth = true
		}

		if strings.has_prefix(header, "x-amz-date: ") {
			date = true
		}
	}
	testing.expect(state.t, auth && date, "signed headers reach the injected provider")
	return transmute([]u8)state.response, {status = state.status, ok = state.ok}
}
