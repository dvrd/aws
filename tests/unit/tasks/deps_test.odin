package main

import "core:crypto/hash"
import "core:encoding/endian"
import "core:encoding/hex"
import "core:fmt"
import "core:os"
import "core:path/filepath"
import "core:strings"
import "core:testing"

Dep_Test_File :: struct {
	path, text: string,
}

dep_test_tree :: proc(t: ^testing.T, files: []Dep_Test_File) -> string {
	root, created := work_directory("tasks-deps")
	testing.expect(t, created)
	for file in files {
		path := fmt.aprintf("%s/%s", root, file.path)
		testing.expect(t, directory_ensure(filepath.dir(path)))
		testing.expect(t, os.write_entire_file(path, file.text) == nil)
	}
	return root
}

// The caller supplies the expected install paths in digest order.
dep_test_digest :: proc(files: []Dep_Test_File) -> string {
	ctx: hash.Context
	hash.init(&ctx, .SHA256)
	for file in files {
		length: [8]u8
		endian.put_u64(length[:], .Little, u64(len(file.text)))
		hash.update(&ctx, transmute([]byte)file.path)
		hash.update(&ctx, []byte{0})
		hash.update(&ctx, length[:])
		hash.update(&ctx, transmute([]byte)file.text)
	}
	sum: [32]byte
	hash.final(&ctx, sum[:])
	return string(hex.encode(sum[:]))
}

@(test)
installed_hash_uses_sorted_paths_and_ignores_metadata :: proc(t: ^testing.T) {
	context.allocator = context.temp_allocator
	files := []Dep_Test_File{{"a.odin", "package x\n"}, {"sub/b.odin", "package b\n"}, {".DS_Store", "metadata"}}
	root := dep_test_tree(t, files)
	defer os.remove_all(root)
	actual, ok := hash_installed(root)
	testing.expect(t, ok)
	testing.expect_value(t, actual, dep_test_digest(files[:2]))
}

@(test)
checkout_hash_selects_source_loaded_data_and_licence :: proc(t: ^testing.T) {
	context.allocator = context.temp_allocator
	source :: `package x
data :: #load("data.bin")
`
	root := dep_test_tree(t, {
		{".git/HEAD", "ref"}, {"src/a.odin", source}, {"src/tests/t_test.odin", "package x"},
		{"src/examples/e.odin", "package x"}, {"src/notes.md", "notes"}, {"src/data.bin", "\x00\x01"},
		{"LICENSE", "terms"}, {"README.md", "readme"},
	})
	defer os.remove_all(root)
	actual, ok := hash_checkout(root)
	testing.expect(t, ok)
	testing.expect_value(t, actual, dep_test_digest({{"LICENSE", "terms"}, {"a.odin", source}, {"data.bin", "\x00\x01"}}))
}

@(test)
recorded_pins_have_names_and_sha256_hashes :: proc(t: ^testing.T) {
	context.allocator = context.temp_allocator
	pins, ok := pins_read(".")
	names := []string{"async", "surf", "websocket"}
	if !testing.expect(t, ok && len(pins) == len(names)) {
		return
	}
	for pin, i in pins {
		testing.expect_value(t, pin.name, names[i])
		testing.expect_value(t, len(pin.hash), 64)
		for c in pin.hash {
			testing.expect(t, strings.contains_rune("0123456789abcdef", c))
		}
	}
}

@(test)
comparison_reports_only_the_differing_package :: proc(t: ^testing.T) {
	context.allocator = context.temp_allocator
	root := dep_test_tree(t, {{"one/a.odin", "package one"}, {"two/a.odin", "package two"}})
	defer os.remove_all(root)
	digest, ok := hash_installed(fmt.aprintf("%s/one", root))
	testing.expect(t, ok)
	problems := deps_compare({{name = "one", hash = digest}, {name = "two", hash = strings.repeat("0", 64)}}, root)
	if testing.expect_value(t, len(problems), 1) {
		testing.expect(t, strings.has_prefix(problems[0], "two:"))
	}
}
