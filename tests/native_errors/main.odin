// Public S3 default native TLS error boundary; owned loopback and public fixtures only.
//
// Usage: <driver> --probe <probe-binary> [--report <path>], run from the repository
// root. Each case serves one TLS 1.3 connection to the probe built from
// tests/testdata/native_error_loopback and checks what both sides observed.
package main

import "core:bytes"
import tls "core:crypto/tls"
import credentials "core:crypto/tls/credentials"
import store "core:crypto/tls/credentials/store"
import "core:encoding/json"
import "core:fmt"
import "core:nbio"
import "core:net"
import "core:os"
import "core:strconv"
import "core:strings"
import "core:time"

MARKER :: "private-native-loopback-marker"
KEY :: "public-fixture-key"
TOKEN :: "public-fixture-session"
BODY :: "public-fixture-body"
TARGET :: "/fixturebucket/qualification/owned.txt"
CERTIFICATE :: "tests/testdata/tls/localhost.pem"
PRIVATE_KEY :: "tests/testdata/tls/rsa2048.pem"
WRONG_ROOT :: "tests/testdata/tls/root.pem"
ERROR_SOURCE :: "https://docs.aws.amazon.com/AmazonS3/latest/API/API_Error.html"

HEAD_MAX :: 16384
BODY_MAX :: 1024
OUTPUT_MAX :: 65536
PEER_TIMEOUT :: 3 * time.Second
CHILD_TIMEOUT :: 22 * time.Second
RETRY_WINDOW :: 150 * time.Millisecond

Observed :: struct {
	connections:            int,
	requests:               int,
	signed_session_request: bool,
	tls_rejected:           bool,
	response_error_code:    string,
	failure:                string,
}

Observation :: struct {
	passed, ok, transport_ok: bool,
	status:                   int,
}

Case :: struct {
	method:                string,
	response_status:       int,
	trust_negative:        bool,
	wrong_status_negative: bool,
	native_exit:           int,
	observation:           Observation,
	// The peer's side, flattened as in the report.
	connections:            int,
	requests:               int,
	signed_session_request: bool,
	tls_rejected:           bool,
	response_error_code:    string,
}

Report :: struct {
	passed:                                                           bool,
	owned_loopback_only:                                              bool,
	provider_calls:                                                   bool,
	credentials:                                                      string,
	cases:                                                            []Case,
	error_mapping_source:                                             string,
	error_mapping:                                                    Error_Mapping,
	error_code_labels_are_peer_responses_not_sdk_xml_classification: bool,
	limits:                                                           []string,
}

Error_Mapping :: struct {
	expired_token:  string `json:"400"`,
	access_denied:  string `json:"403"`,
	slow_down:      string `json:"503"`,
	synthetic_http: string `json:"429"`,
}

Session :: struct {
	server:      tls.Server_Async_Conn,
	tcp:         nbio.TCP_Async_Connection,
	handshake:   tls.Server_Async_Handshake_Operation,
	read:        net.Async_Operation,
	write:       net.Async_Operation,
	close:       net.Async_Operation,
	input:       [HEAD_MAX + BODY_MAX]u8,
	output:      [512]u8,
	output_size: int,
	used:        int,
	head_found:  bool,
	body_start:  int,
	body_size:   int,
	method:      string,
	status:      int,
	observed:    ^Observed,
	closing:     bool,
	closed:      bool,
}

// The child that is still running, so a failed check never leaves it behind.
owned_child: os.Process
owned_child_running: bool

fail :: proc(format: string, args: ..any) -> ! {
	if owned_child_running {
		_ = os.process_kill(owned_child)
		_, _ = os.process_wait(owned_child, 5 * time.Second)
	}
	fmt.eprintf(format, ..args)
	fmt.eprintln()
	os.exit(1)
}

error_code :: proc(status: int) -> string {
	switch status {
	case 400:
		return "ExpiredToken"
	case 403:
		return "AccessDenied"
	case 503:
		return "SlowDown"
	case 429:
		return "SyntheticHTTP429"
	}
	return "None"
}

peer_fail :: proc(s: ^Session, reason: string) {
	if s.observed.failure == "" {
		s.observed.failure = reason
	}
	session_close(s)
}

session_closed :: proc(op: ^net.Async_Operation) {
	s := cast(^Session)op.user_data
	s.closed = true
}

session_close :: proc(s: ^Session) {
	if s.closing {
		return
	}
	s.closing = true
	s.close = {
		callback  = session_closed,
		user_data = s,
	}
	if net.async_close(tls.server_async_connection(&s.server), &s.close).kind != .None {
		s.closed = true
		if s.observed.failure == "" {
			s.observed.failure = "close rejected"
		}
	}
}

session_read :: proc(s: ^Session) {
	// Mirrors the Python peer: 4096-byte reads for the head, then exactly the missing body.
	size := min(4096, len(s.input) - s.used)
	if s.head_found {
		size = s.body_size - (s.used - s.body_start)
	}
	if size <= 0 {
		peer_fail(s, "request exceeds the owned bound")
		return
	}
	deadline := time.time_add(time.now(), PEER_TIMEOUT)
	connection := tls.server_async_connection(&s.server)
	if net.async_read(connection, &s.read, s.input[s.used:s.used + size], deadline).kind != .None {
		peer_fail(s, "read rejected")
	}
}

handshake_done :: proc(op: ^tls.Server_Async_Handshake_Operation) {
	s := cast(^Session)op.user_data
	if op.err.kind != .None {
		// The probe refused the certificate (or left) before any request.
		s.observed.tls_rejected = true
		session_close(s)
		return
	}
	s.read = {
		callback  = read_done,
		user_data = s,
	}
	session_read(s)
}

read_done :: proc(op: ^net.Async_Operation) {
	s := cast(^Session)op.user_data
	if op.result.err.kind != .None || op.result.count <= 0 {
		peer_fail(s, "incomplete body" if s.head_found else "incomplete request")
		return
	}
	s.used += op.result.count
	if !s.head_found {
		if s.used > HEAD_MAX {
			peer_fail(s, "request head exceeds 16384 bytes")
			return
		}
		terminator := "\r\n\r\n"
		end := bytes.index(s.input[:s.used], transmute([]u8)terminator)
		if end < 0 {
			session_read(s)
			return
		}
		if reason := request_head_check(s, string(s.input[:end])); reason != "" {
			peer_fail(s, reason)
			return
		}
		s.head_found = true
		s.body_start = end + len(terminator)
	}
	if s.used - s.body_start < s.body_size {
		session_read(s)
		return
	}
	expected := BODY if s.method == "PUT" else ""
	if string(s.input[s.body_start:s.used]) != expected {
		peer_fail(s, "unexpected request body")
		return
	}
	s.observed.requests += 1
	s.observed.signed_session_request = true
	code := error_code(s.status)
	s.observed.response_error_code = code
	response := ""
	if s.status != 200 && s.status != 204 {
		response = fmt.tprintf("<Error><Code>%s</Code><Message>%s</Message></Error>", code, MARKER)
	}
	message := fmt.bprintf(
		s.output[:],
		"HTTP/1.1 %d Owned\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s",
		s.status,
		len(response),
		response,
	)
	s.output_size = len(message)
	s.write = {
		callback  = write_done,
		user_data = s,
	}
	deadline := time.time_add(time.now(), PEER_TIMEOUT)
	connection := tls.server_async_connection(&s.server)
	if net.async_write(connection, &s.write, s.output[:s.output_size], deadline).kind != .None {
		peer_fail(s, "write rejected")
	}
}

write_done :: proc(op: ^net.Async_Operation) {
	s := cast(^Session)op.user_data
	if op.result.err.kind != .None || op.result.count != s.output_size {
		peer_fail(s, "incomplete response")
		return
	}
	session_close(s)
}

// Returns the reason the request head is not the expected signed request, or "".
request_head_check :: proc(s: ^Session, head: string) -> string {
	lines := strings.split(head, "\r\n", context.temp_allocator)
	if lines[0] != fmt.tprintf("%s %s HTTP/1.1", s.method, TARGET) {
		return "unexpected request line"
	}
	names := make([dynamic]string, 0, len(lines), context.temp_allocator)
	length, token, authorization := "0", "", ""
	has_token, has_authorization := false, false
	for line in lines[1:] {
		colon := strings.index_byte(line, ':')
		if colon < 0 {
			return "header without a colon"
		}
		name := strings.to_lower(line[:colon], context.temp_allocator)
		value := strings.trim_space(line[colon + 1:])
		for seen in names {
			if seen == name {
				return "duplicate request header"
			}
		}
		append(&names, name)
		switch name {
		case "content-length":
			length = value
		case "x-amz-security-token":
			token, has_token = value, true
		case "authorization":
			authorization, has_authorization = value, true
		}
	}
	size, size_valid := strconv.parse_int(length, 10)
	if !size_valid || size < 0 || size > BODY_MAX {
		return "content length outside the owned bound"
	}
	s.body_size = size
	if !has_token || token != TOKEN {
		return "session token header missing or changed"
	}
	if !has_authorization ||
	   !strings.has_prefix(authorization, "AWS4-HMAC-SHA256 Credential=" + KEY + "/") ||
	   !strings.contains(authorization, "x-amz-security-token") {
		return "request is not signed with the session token"
	}
	return ""
}

// Polls the non-blocking listener for one connection until the window closes.
accept_within :: proc(listener: net.TCP_Socket, window: time.Duration) -> (socket: net.TCP_Socket, accepted: bool) {
	started := time.tick_now()
	for {
		connection, _, failure := net.accept_tcp(listener)
		if failure == nil {
			return connection, true
		}
		if failure != net.Accept_Error.Would_Block {
			fail("owned listener failed: %v", failure)
		}
		if time.tick_since(started) >= window {
			return
		}
		time.sleep(time.Millisecond)
	}
}

child_environment :: proc() -> []string {
	environment := make([dynamic]string, 0, 8, context.temp_allocator)
	for key in ([]string{"PATH", "TMPDIR", "LANG", "LC_ALL"}) {
		if value, found := os.lookup_env(key, context.temp_allocator); found {
			append(&environment, fmt.tprintf("%s=%s", key, value))
		}
	}
	append(
		&environment,
		"AWS_EC2_METADATA_DISABLED=true",
		"AWS_CONFIG_FILE=/dev/null",
		"AWS_SHARED_CREDENTIALS_FILE=/dev/null",
	)
	return environment[:]
}

serve :: proc(socket: net.TCP_Socket, credential_store: ^store.Store, method: string, status: int, observed: ^Observed) {
	s := new(Session)
	defer free(s)
	s.method = method
	s.status = status
	s.observed = observed
	if nbio.tcp_async_connection_init(&s.tcp, socket) != nil {
		net.close(socket)
		observed.failure = "owned connection not associated"
		return
	}
	config := tls.Server_Async_Config {
		store             = credential_store,
		handshake_timeout = PEER_TIMEOUT,
	}
	transport := nbio.tcp_async_connection(&s.tcp)
	if tls.server_async_server(&s.server, transport, nbio.async_executor(), config, context.allocator) != .None {
		fail("owned TLS server rejected its configuration")
	}
	s.handshake = {
		callback  = handshake_done,
		user_data = s,
	}
	if tls.server_async_handshake(&s.server, &s.handshake).kind != .None {
		fail("owned TLS handshake not accepted")
	}
	if nbio.run() != nil || !s.closed {
		fail("owned peer did not retire")
	}
	if tls.server_async_stats(&s.server).live_bytes != 0 && observed.failure == "" {
		observed.failure = "owned TLS memory retained"
	}
}

run_case :: proc(
	probe: string,
	credential_store: ^store.Store,
	method: string,
	status: int,
	trust := false,
	wrong_status := false,
) -> Case {
	observed := Observed {
		response_error_code = "NotSent",
	}
	listener, listen_error := net.listen_tcp({net.IP4_Loopback, 0}, 4)
	if listen_error != nil {
		fail("owned listener not available: %v", listen_error)
	}
	defer net.close(listener)
	endpoint, bound_error := net.bound_endpoint(listener)
	if bound_error != nil || net.set_blocking(listener, false) != nil {
		fail("owned listener not configured")
	}

	expected := 403 if wrong_status else 0 if trust else status
	reader, writer, pipe_error := os.pipe()
	if pipe_error != nil {
		fail("owned pipe not available: %v", pipe_error)
	}
	defer os.close(reader)
	started := time.tick_now()
	child, start_error := os.process_start(
		{
			command = {
				probe,
				fmt.tprintf("https://127.0.0.1:%d", endpoint.port),
				WRONG_ROOT if trust else CERTIFICATE,
				method,
				fmt.tprintf("%d", expected),
				"trust-failure" if trust else "response",
			},
			env = child_environment(),
			stdout = writer,
			stderr = writer,
		},
	)
	os.close(writer)
	if start_error != nil {
		fail("probe not started: %v", start_error)
	}
	owned_child, owned_child_running = child, true

	if socket, accepted := accept_within(listener, PEER_TIMEOUT); accepted {
		observed.connections += 1
		serve(socket, credential_store, method, status, &observed)
	} else {
		observed.failure = "no connection from the probe"
	}

	remaining := max(CHILD_TIMEOUT - time.tick_since(started), 10 * time.Millisecond)
	state, wait_error := os.process_wait(child, remaining)
	if wait_error != nil || !state.exited {
		fail("owned child deadline (%s %d): %v", method, status, wait_error)
	}
	owned_child_running = false

	// The child has exited, so the pipe holds everything it wrote.
	output := make([dynamic]u8, 0, 4096, context.temp_allocator)
	chunk: [4096]u8
	for {
		n, read_error := os.read(reader, chunk[:])
		if n > 0 {
			append(&output, ..chunk[:n])
		}
		if len(output) > OUTPUT_MAX {
			fail("owned output bound")
		}
		if n <= 0 || read_error != nil {
			break
		}
	}

	if extra, retried := accept_within(listener, RETRY_WINDOW); retried {
		net.close(extra)
		fail("native request retried (%s %d)", method, status)
	}
	if observed.failure != "" {
		fail("owned peer failed (%s %d): %s; probe output: %s", method, status, observed.failure, string(output[:]))
	}
	for secret in ([]string{MARKER, KEY, TOKEN}) {
		if bytes.contains(output[:], transmute([]u8)secret) {
			fail("probe output discloses a fixture secret (%s %d)", method, status)
		}
	}

	// The native child emits a fixed numeric/bool observation only; no response body.
	observation := observation_decode(output[:], method, status)
	exit_expected := 1 if wrong_status else 0
	if state.exit_code != exit_expected {
		fail("probe exit %d, expected %d (%s %d): %s", state.exit_code, exit_expected, method, status, string(output[:]))
	}
	if observation.passed == wrong_status {
		fail("probe passed=%v (%s %d)", observation.passed, method, status)
	}
	if observed.connections != 1 {
		fail("%d connections, expected 1 (%s %d)", observed.connections, method, status)
	}
	if observed.requests != (0 if trust else 1) {
		fail("%d requests (%s %d trust=%v)", observed.requests, method, status, trust)
	}
	if observed.tls_rejected != trust {
		fail("tls_rejected=%v (%s %d trust=%v)", observed.tls_rejected, method, status, trust)
	}
	if observed.response_error_code != ("NotSent" if trust else error_code(status)) {
		fail("response code %s (%s %d trust=%v)", observed.response_error_code, method, status, trust)
	}
	return {
		method = method,
		response_status = status,
		trust_negative = trust,
		wrong_status_negative = wrong_status,
		native_exit = state.exit_code,
		observation = observation,
		connections = observed.connections,
		requests = observed.requests,
		signed_session_request = observed.signed_session_request,
		tls_rejected = observed.tls_rejected,
		response_error_code = observed.response_error_code,
	}
}

// The probe prints one JSON object with exactly passed, ok, transport_ok and status.
observation_decode :: proc(output: []u8, method: string, status: int) -> (observation: Observation) {
	value, parse_error := json.parse(output, .JSON, false, context.temp_allocator)
	object, is_object := value.(json.Object)
	if parse_error != nil || !is_object || len(object) != 4 {
		fail("probe output is not the fixed observation (%s %d): %s", method, status, string(output))
	}
	valid := true
	flags := [3]^bool{&observation.passed, &observation.ok, &observation.transport_ok}
	for name, index in ([3]string{"passed", "ok", "transport_ok"}) {
		flag, is_flag := object[name].(json.Boolean)
		flags[index]^ = flag
		valid &&= is_flag
	}
	#partial switch number in object["status"] {
	case json.Integer:
		observation.status = int(number)
	case json.Float:
		observation.status = int(number)
		valid &&= f64(observation.status) == number
	case:
		valid = false
	}
	if !valid {
		fail("probe output is not the fixed observation (%s %d): %s", method, status, string(output))
	}
	return
}

credential_store_load :: proc() -> ^store.Store {
	chain, chain_error := os.read_entire_file(CERTIFICATE, context.allocator)
	key, key_error := os.read_entire_file(PRIVATE_KEY, context.allocator)
	if chain_error != nil || key_error != nil {
		fail("TLS fixtures not readable; run from the repository root")
	}
	defer delete(chain)
	defer delete(key)
	credential, credential_error := credentials.create(chain, key, {}, context.allocator)
	if credential_error != .None {
		fail("TLS fixture credential rejected: %v", credential_error)
	}
	credential_store, store_error := store.create({}, context.allocator)
	if store_error.kind != .None || store.replace(credential_store, &credential).kind != .None {
		fail("TLS fixture credential not stored")
	}
	return credential_store
}

main :: proc() {
	probe, report := "", ""
	arguments := os.args[1:]
	for len(arguments) >= 2 {
		switch arguments[0] {
		case "--probe":
			probe = arguments[1]
		case "--report":
			report = arguments[1]
		case:
			fail("Usage: %s --probe <probe-binary> [--report <path>]", os.args[0])
		}
		arguments = arguments[2:]
	}
	if probe == "" || len(arguments) != 0 {
		fail("Usage: %s --probe <probe-binary> [--report <path>]", os.args[0])
	}

	if nbio.acquire_thread_event_loop() != nil {
		fail("event loop not available")
	}
	defer nbio.release_thread_event_loop()
	credential_store := credential_store_load()

	cases := make([dynamic]Case, 0, 13)
	defer delete(cases)
	for method in ([]string{"PUT", "DELETE"}) {
		for status in ([]int{400, 403, 503, 429, 200 if method == "PUT" else 204}) {
			append(&cases, run_case(probe, credential_store, method, status))
			free_all(context.temp_allocator)
		}
		append(&cases, run_case(probe, credential_store, method, 403, trust = true))
		free_all(context.temp_allocator)
	}
	append(&cases, run_case(probe, credential_store, "PUT", 200, wrong_status = true))
	free_all(context.temp_allocator)

	if store.close(credential_store).kind != .None {
		fail("TLS fixture credential still leased")
	}
	_ = store.destroy(&credential_store)

	if report != "" {
		document := Report {
			passed = true,
			owned_loopback_only = true,
			provider_calls = false,
			credentials = "public synthetic strings only",
			cases = cases[:],
			error_mapping_source = ERROR_SOURCE,
			error_mapping = {"ExpiredToken", "AccessDenied", "SlowDown", "SyntheticHTTP429"},
			error_code_labels_are_peer_responses_not_sdk_xml_classification = true,
			limits = {
				"Simulated400ExpiredToken/403AccessDenied/503SlowDown;429SyntheticHTTP429 is generic robustness only, not an AWS S3 error mapping.",
				"No production SDK/Surf/API/trust/deadline change.",
			},
		}
		data, marshal_error := json.marshal(document, {pretty = true, use_spaces = true, spaces = 2})
		if marshal_error != nil {
			fail("report not encoded: %v", marshal_error)
		}
		defer delete(data)
		if os.write_entire_file(report, data) != nil {
			fail("report not written: %s", report)
		}
	}
	fmt.printf("{{\"passed\":true,\"cases\":%d}}\n", len(cases))
}
