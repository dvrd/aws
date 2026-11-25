package main

import "core:encoding/json"
import "core:fmt"
import "core:os"
import "core:strconv"
import "core:strings"
import "core:time"

SANITIZED_FLAGS :: []string{"-thread-count:1", "-vet", "-warnings-as-errors", "-sanitize:address"}

LOOPBACK_PEER :: "tests/e2e/loopback/peer"
LOOPBACK_DEFAULT_PROBE :: "tests/e2e/loopback/production_get_probe"
LOOPBACK_OBSERVER_PROBE :: "tests/e2e/loopback/observer_probe"
// The observer probe is compiled together with the observation the live
// qualification probe reports.
LOOPBACK_OBSERVATION :: "tests/qualification/probe/get_observation.odin"

// Observes the native S3 GET against an owned loopback peer that accepts one
// connection and reads the TLS ClientHello. No provider, no credentials. With no
// --mode both probes run; a report is written only on request.
loopback_command :: proc(arguments: []string) -> int {
	mode, report := "", ""
	for index := 0; index < len(arguments); index += 1 {
		switch arguments[index] {
		case "--mode":
			mode = option_value(arguments, &index) or_else "invalid"
		case "--report":
			report = option_value(arguments, &index) or_else ""
		case:
			return fail("unknown option: %s", arguments[index])
		}
	}
	if mode != "" && mode != "default" && mode != "observer" {
		return fail("--mode is default or observer")
	}
	if mode == "" && report != "" {
		return fail("--report needs --mode")
	}
	sanitizer_clang_select()
	for candidate in ([]string{"default", "observer"}) {
		if mode != "" && mode != candidate {
			continue
		}
		if code := loopback_run(candidate, report); code != 0 {
			return code
		}
	}
	return 0
}

ready_port :: proc(text: string) -> int {
	first, separator, _ := strings.partition(text, "\n")
	if separator == "" || !strings.has_prefix(first, "ready ") {
		return 0
	}
	port, ok := strconv.parse_int(first[len("ready "):], 10)
	return port if ok else 0
}

loopback_run :: proc(mode, report: string) -> int {
	work, created := work_directory("tls-observation")
	if !created {
		return fail("cannot create a work directory")
	}
	defer os.remove_all(work)
	shared, staged := stage_collection(work)
	if !staged {
		return fail("cannot stage the shared collection")
	}
	odin := compiler_path()
	observation := LOOPBACK_OBSERVATION
	source := LOOPBACK_DEFAULT_PROBE
	if mode == "observer" {
		// The observer probe is compiled together with the observation it reports.
		source = fmt.aprintf("%s/source", work)
		if os.make_directory(source) != nil ||
		   os.copy_file(fmt.aprintf("%s/get_observation.odin", source), observation) != nil ||
		   os.copy_file(fmt.aprintf("%s/main.odin", source), fmt.aprintf("%s/main.odin", LOOPBACK_OBSERVER_PROBE)) != nil {
			return fail("cannot stage the observer probe")
		}
	}
	source_digest := sha256_file(observation)
	probe := fmt.aprintf("%s/probe", work)
	peer := fmt.aprintf("%s/peer", work)
	compile := make([dynamic]string)
	append(&compile, odin, "build", source, fmt.aprintf("-collection:shared=%s", shared))
	append(&compile, ..SANITIZED_FLAGS)
	append(&compile, fmt.aprintf("-out:%s", probe))
	peer_compile := make([dynamic]string)
	append(&peer_compile, odin, "build", LOOPBACK_PEER)
	append(&peer_compile, ..SANITIZED_FLAGS)
	append(&peer_compile, fmt.aprintf("-out:%s", peer))
	for build in ([][]string{compile[:], peer_compile[:]}) {
		log := fmt.aprintf("%s/build.log", work)
		child, started := spawn({command = build, output = log, errors = "&output"})
		if !started {
			return fail("cannot start %s", build[0])
		}
		code, finished := wait(&child, BUILD_TIMEOUT)
		if !finished {
			return fail("building %s did not finish in %v", build[2], BUILD_TIMEOUT)
		}
		if code != 0 {
			fmt.eprint(read_text(log))
			return fail("cannot build %s", build[2])
		}
	}

	peer_output := fmt.aprintf("%s/peer.out", work)
	peer_errors := fmt.aprintf("%s/peer.err", work)
	listener, listening := spawn({command = {peer}, output = peer_output, errors = peer_errors})
	if !listening {
		return fail("cannot start the peer")
	}
	defer stop(&listener)
	port := 0
	for attempt := 0; attempt < 250 && port == 0; attempt += 1 {
		port = ready_port(read_text(peer_output))
		if port != 0 {
			break
		}
		if !alive(&listener) {
			fmt.eprint(read_text(peer_errors))
			return fail("the peer exited before it was ready")
		}
		time.sleep(20 * time.Millisecond)
	}
	if port <= 0 || port > 65535 {
		return fail("the peer did not report a port")
	}
	url := fmt.aprintf("https://127.0.0.1:%d", port)
	if mode == "observer" {
		url = fmt.aprintf("%s/", url)
	}
	native_output := fmt.aprintf("%s/native.out", work)
	native_errors := fmt.aprintf("%s/native.err", work)
	native, started := spawn({command = {probe, url}, output = native_output, errors = native_errors})
	if !started {
		return fail("cannot start the probe")
	}
	native_code, native_finished := wait(&native, 10 * time.Second)
	peer_code, peer_finished := wait(&listener, 12 * time.Second)
	if !native_finished {
		return fail("the %s probe did not finish in 10s", mode)
	}
	if native_code != 0 || read_text(native_errors) != "" {
		fmt.eprint(read_text(native_errors))
		return fail("the %s probe failed", mode)
	}
	if !peer_finished || peer_code != 0 || read_text(peer_errors) != "" {
		fmt.eprint(read_text(peer_errors))
		return fail("the peer failed")
	}

	observed, parsed := json.parse(transmute([]u8)read_text(native_output), .JSON, true)
	if parsed != .None {
		return fail("the probe printed no observation")
	}
	if mode == "observer" {
		if count, is_integer := observed.(json.Integer); !is_integer || count != 1 {
			return fail("the observer was not called exactly once")
		}
	} else {
		object, _ := observed.(json.Object)
		native_get, _ := object["native_default_get"].(json.Boolean)
		closed, _ := object["peer_closed_during_tls"].(json.Boolean)
		bytes, is_integer := object["body_bytes"].(json.Integer)
		if !native_get || !closed || !is_integer || bytes != 0 {
			return fail("the default probe observed something else")
		}
	}
	lines := strings.split_lines(strings.trim_space(read_text(peer_output)))
	peer_observed, peer_parsed := json.parse(transmute([]u8)lines[len(lines) - 1], .JSON, true)
	peer_object, _ := peer_observed.(json.Object)
	connections, _ := peer_object["accepted_connections"].(json.Integer)
	hello, _ := peer_object["tls_client_hello_seen"].(json.Boolean)
	if peer_parsed != .None || connections != 1 || !hello {
		return fail("the peer did not see exactly one TLS ClientHello")
	}
	if sha256_file(observation) != source_digest {
		return fail("get_observation.odin changed during the run")
	}

	builder := strings.builder_make()
	if mode == "observer" {
		fmt.sbprintf(
			&builder,
			`{{"passed":true,"source_sha256":%q,"source_unchanged":true,"provider_calls":false,"credentials_used":false,"native_executor_calls":1,"owned_connections":1,"tls_client_hello":true,"stderr_empty":true,"child_reaped":true,"binary_sha256":%q,"build_command":[`,
			source_digest,
			sha256_file(probe),
		)
		for argument, index in compile {
			fmt.sbprintf(&builder, "%s%q", "," if index > 0 else "", argument)
		}
		strings.write_string(&builder, `],"limits":"ClientHello and input/trust path only; no successful TLS handshake."}`)
	} else {
		fmt.sbprintf(
			&builder,
			`{{"owned_loopback_only":true,"provider_calls":false,"credentials":"public synthetic strings only","native_exit":0,"accepted_connections":1,"tls_client_hello_seen":true,"compiler_sha256":%q,"probe_sha256":%q,"passed":true}}`,
			sha256_file(odin),
			sha256_file(probe),
		)
	}
	summary := strings.to_string(builder)
	if report != "" && os.write_entire_file(report, fmt.aprintf("%s\n", summary)) != nil {
		return fail("cannot write %s", report)
	}
	fmt.println(summary)
	return 0
}
