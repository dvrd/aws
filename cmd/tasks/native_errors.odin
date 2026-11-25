package main

import "core:fmt"
import "core:os"

NATIVE_ERRORS_PROBE :: "tests/e2e/native_errors/probe"
NATIVE_ERRORS_PEER :: "tests/e2e/native_errors/peer"

// Builds the S3 error probe and its TLS 1.3 peer (tests/e2e/native_errors), then runs
// the peer's 13 response, trust and wrong-status cases over loopback.
native_errors_command :: proc(arguments: []string) -> int {
	work, created := work_directory("native-errors")
	if !created {
		return fail("cannot create a work directory")
	}
	defer os.remove_all(work)
	shared, staged := stage_collection(work)
	if !staged {
		return fail("cannot stage the shared collection")
	}
	sanitizer_clang_select()
	probe := fmt.aprintf("%s/probe", work)
	driver := fmt.aprintf("%s/driver", work)
	builds := [][]string {
		{NATIVE_ERRORS_PROBE, fmt.aprintf("-collection:shared=%s", shared), fmt.aprintf("-out:%s", probe)},
		{NATIVE_ERRORS_PEER, fmt.aprintf("-collection:shared=%s", shared), fmt.aprintf("-out:%s", driver)},
	}
	for build in builds {
		command := make([dynamic]string)
		append(&command, compiler(), "build")
		append(&command, ..build)
		append(&command, ..SANITIZED_FLAGS)
		if code := run(command[:]); code != 0 {
			return code
		}
	}
	command := make([dynamic]string)
	append(&command, driver, "--probe", probe)
	append(&command, ..arguments)
	return run(command[:])
}
