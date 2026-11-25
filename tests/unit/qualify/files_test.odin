package main

import "core:encoding/json"
import "core:os"
import "core:strings"
import "core:sys/posix"
import "core:testing"

// Unit tests of cmd/qualify/files.odin: private files, atomic replacement, the
// state lock and the probe digest.

@(test)
private_documents_must_be_owner_only_regular_and_small :: proc(t: ^testing.T) {
	test: Test
	context.allocator = test_begin(&test, t)
	defer test_end(&test)
	fixture(&test)
	path := strings.concatenate({test.root, "/document.json"})
	write_file(path, `{"a":1}`)
	value, failure := read_private(path)
	testing.expect_value(t, failure, Failure.None)
	testing.expect(t, integer_is(value, "a", 1))

	write_file(path, `{"a":1}`, {.IRUSR, .IWUSR, .IRGRP})
	_, failure = read_private(path)
	testing.expect_value(t, failure, Failure.Private_File_Required)

	write_file(path, strings.repeat(" ", MAX_BYTES + 1))
	_, failure = read_private(path)
	testing.expect_value(t, failure, Failure.Metadata_Too_Large)

	// A link is not followed, and a second name makes a file not private.
	write_file(path, `{"a":1}`)
	link := strings.concatenate({test.root, "/link.json"})
	testing.expect(t, os.symlink(path, link) == nil)
	_, failure = read_private(link)
	testing.expect_value(t, failure, Failure.System)
	hard := strings.concatenate({test.root, "/hard.json"})
	testing.expect(t, posix.link(strings.clone_to_cstring(path), strings.clone_to_cstring(hard)) == .OK)
	_, failure = read_private(path)
	testing.expect_value(t, failure, Failure.Private_File_Required)
}

@(test)
atomic_replaces_a_document_with_a_private_file :: proc(t: ^testing.T) {
	test: Test
	context.allocator = test_begin(&test, t)
	defer test_end(&test)
	fixture(&test)
	value := make(json.Object)
	value["phase"] = "PREPARED"
	testing.expect_value(t, atomic(test.root, "state.json", value), Failure.None)
	value["phase"] = "COMPLETE"
	testing.expect_value(t, atomic(test.root, "state.json", value), Failure.None)
	stored, failure := read_private(strings.concatenate({test.root, "/state.json"}))
	testing.expect_value(t, failure, Failure.None)
	testing.expect(t, text_is(stored, "phase", "COMPLETE"))
	// No temporary file is left behind.
	entries, _ := os.read_all_directory_by_path(test.root, context.allocator)
	for entry in entries {
		testing.expectf(t, !strings.has_prefix(entry.name, ".qualification-"), "%s", entry.name)
	}
	value["padding"] = strings.repeat("x", MAX_BYTES)
	testing.expect_value(t, atomic(test.root, "state.json", value), Failure.Metadata_Too_Large)
}

@(test)
state_directory_lock_is_exclusive_and_private :: proc(t: ^testing.T) {
	test: Test
	context.allocator = test_begin(&test, t)
	defer test_end(&test)
	fixture(&test)
	_, relative := lock_acquire("state")
	testing.expect_value(t, relative, Failure.Absolute_State_Required)
	directory := strings.concatenate({test.root, "/state"})
	lock, failure := lock_acquire(directory)
	testing.expect_value(t, failure, Failure.None)
	_, second := lock_acquire(directory)
	testing.expect_value(t, second, Failure.Locked)
	lock_release(lock)
	again, after := lock_acquire(directory)
	testing.expect_value(t, after, Failure.None)
	lock_release(again)

	open_directory := strings.concatenate({test.root, "/open"})
	testing.expect(t, posix.mkdir(strings.clone_to_cstring(open_directory), {.IRUSR, .IWUSR, .IXUSR, .IRGRP, .IXGRP}) == .OK)
	_, shared := lock_acquire(open_directory)
	testing.expect_value(t, shared, Failure.Private_Directory_Required)
}

@(test)
probe_digest_needs_an_absolute_executable_nobody_else_can_write :: proc(t: ^testing.T) {
	test: Test
	context.allocator = test_begin(&test, t)
	defer test_end(&test)
	fixture(&test)
	binary := test.runner.arguments.binary
	digest, failure := binary_hash(binary)
	testing.expect_value(t, failure, Failure.None)
	testing.expect_value(t, digest, sha256_hex(transmute([]u8)read_text(binary)))
	_, relative := binary_hash("probe")
	testing.expect_value(t, relative, Failure.Absolute_Binary_Required)
	write_file(binary, "#!/bin/sh\n", {.IRUSR, .IWUSR})
	_, not_executable := binary_hash(binary)
	testing.expect_value(t, not_executable, Failure.Executable_Required)
	write_file(binary, "#!/bin/sh\n", {.IRUSR, .IWUSR, .IXUSR, .IWGRP})
	_, writable := binary_hash(binary)
	testing.expect_value(t, writable, Failure.Executable_Required)
	testing.expect_value(t, len(sha256_hex(nil)), 64)
}
