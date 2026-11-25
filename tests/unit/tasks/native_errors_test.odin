package main

import "core:fmt"
import "core:os"
import "core:testing"

// Unit tests of cmd/tasks/native_errors.odin.

@(test)
the_native_error_programs_are_where_the_task_builds_them :: proc(t: ^testing.T) {
	context.allocator = context.temp_allocator
	for directory in ([]string{NATIVE_ERRORS_PROBE, NATIVE_ERRORS_PEER}) {
		testing.expectf(t, os.is_file(fmt.aprintf("%s/main.odin", directory)), "%s/main.odin", directory)
	}
	// The peer reads its certificates from beside it.
	for certificate in ([]string{"localhost.pem", "rsa2048.pem", "root.pem"}) {
		testing.expectf(t, os.is_file(fmt.aprintf("tests/e2e/native_errors/tls/%s", certificate)), "%s", certificate)
	}
}
