package main

import "core:crypto/hash"
import "core:encoding/endian"
import "core:encoding/hex"
import lexer "core:odin/tokenizer"
import "core:path/filepath"
import "core:slice"
import "core:strings"
import "core:sys/posix"
import "core:encoding/json"
import "core:fmt"
import "core:os"

Pin :: struct {
	name, source, tag, commit, hash: string,
}

// The packages recorded in .krs/packages.json under root.
pins_read :: proc(root: string) -> (pins: []Pin, ok: bool) {
	data, err := os.read_entire_file(fmt.aprintf("%s/.krs/packages.json", root), context.allocator)
	if err != nil {
		return nil, false
	}
	record: struct {
		format: int,
		packages: []Pin,
	}
	if json.unmarshal(data, &record) != nil {
		return nil, false
	}
	for pin in record.packages {
		if pin.name == "" || pin.hash == "" {
			return nil, false
		}
	}
	return record.packages, true
}

dep_list :: proc(root, directory: string, checkout: bool, files: ^[dynamic]string) -> bool {
	entries, err := os.read_all_directory_by_path(fmt.aprintf("%s/%s", root, directory), context.allocator)
	if err != nil {
		return false
	}
	for entry in entries {
		switch entry.name {
		case ".DS_Store", "Thumbs.db", "ehthumbs.db", "desktop.ini":
			continue
		}
		if strings.has_prefix(entry.name, "._") {
			continue
		}
		path := entry.name
		if directory != "" {
			path = fmt.aprintf("%s/%s", directory, entry.name)
		}
		#partial switch entry.type {
		case .Directory:
			if checkout && entry.name == ".git" {
				continue
			}
			dep_list(root, path, checkout, files) or_return
		case .Regular:
			append(files, path)
		case:
			if !checkout {
				return false
			}
		}
	}
	return true
}

// The map keys are install paths. Values are paths relative to the source root.
dep_digest :: proc(root: string, files: map[string]string) -> (digest: string, ok: bool) {
	paths := make([dynamic]string, 0, len(files))
	for path in files {
		append(&paths, path)
	}
	slice.sort(paths[:])
	ctx: hash.Context
	hash.init(&ctx, .SHA256)
	for path in paths {
		data, err := os.read_entire_file(fmt.aprintf("%s/%s", root, files[path]), context.allocator)
		if err != nil {
			return "", false
		}
		length: [8]u8
		endian.put_u64(length[:], .Little, u64(len(data)))
		hash.update(&ctx, transmute([]byte)path)
		hash.update(&ctx, []byte{0})
		hash.update(&ctx, length[:])
		hash.update(&ctx, data)
		delete(data)
	}
	sum: [32]byte
	hash.final(&ctx, sum[:])
	return string(hex.encode(sum[:])), true
}

// Content hash of an installed copy under krs's hash_directory rule.
hash_installed :: proc(directory: string) -> (digest: string, ok: bool) {
	list: [dynamic]string
	dep_list(directory, "", false, &list) or_return
	files: map[string]string
	for path in list {
		files[path] = path
	}
	return dep_digest(directory, files)
}

dep_next :: proc(scanner: ^lexer.Tokenizer) -> lexer.Token {
	for {
		token := lexer.scan(scanner)
		if token.kind != .Comment {
			return token
		}
	}
}

dep_references :: proc(source, path, prefix: string, known: map[string]bool, selected: ^map[string]string) {
	scanner: lexer.Tokenizer
	lexer.init(&scanner, source, path, nil)
	for {
		token := dep_next(&scanner)
		directory, foreign_path, group: bool
		#partial switch token.kind {
		case .EOF:
			return
		case .Hash:
			name := dep_next(&scanner).text
			directory = name == "load_directory"
			if (!directory && name != "load" && name != "load_hash") || dep_next(&scanner).kind != .Open_Paren {
				continue
			}
			token = dep_next(&scanner)
		case .Foreign:
			if dep_next(&scanner).kind != .Import {
				continue
			}
			foreign_path = true
			token = dep_next(&scanner)
			if token.kind == .Ident {
				token = dep_next(&scanner)
			}
			group = token.kind == .Open_Brace
			if group {
				token = dep_next(&scanner)
			}
		case:
			continue
		}
		for token.kind == .String {
			ref := token.text[1:len(token.text)-1]
			if !strings.has_prefix(ref, "/") && !(foreign_path && strings.contains(ref, ":")) {
				target, _ := filepath.join({filepath.dir(path), ref})
				if directory {
					for candidate in known {
						if strings.has_prefix(candidate, prefix) && (filepath.dir(candidate) == target || (filepath.dir(candidate) == "" && target == ".")) {
							selected[candidate[len(prefix):]] = candidate
						}
					}
				} else if target in known && strings.has_prefix(target, prefix) {
					selected[target[len(prefix):]] = target
				}
			}
			if !group || dep_next(&scanner).kind != .Comma {
				break
			}
			token = dep_next(&scanner)
		}
	}
}

// Content hash of a checkout's working tree under krs's release selection rule.
hash_checkout :: proc(checkout: string) -> (digest: string, ok: bool) {
	list: [dynamic]string
	dep_list(checkout, "", true, &list) or_return
	known: map[string]bool
	prefix := ""
	for path in list {
		known[path] = true
		if strings.has_prefix(path, "src/") {
			prefix = "src/"
		}
	}
	selected: map[string]string
	for path in list {
		base := filepath.base(path)
		if path == base || path == fmt.aprintf("src/%s", base) {
			lower := strings.to_lower(base)
			for start in ([]string{"license", "licence", "notice", "copying"}) {
				if strings.has_prefix(lower, start) && (path != base || base not_in selected) {
					selected[base] = path
				}
			}
		}
		if !strings.has_prefix(path, prefix) || !strings.has_suffix(path, ".odin") {
			continue
		}
		name := path[len(prefix):]
		parts := strings.split(name, "/")
		excluded := false
		for part in parts[:len(parts)-1] {
			if part == "tests" || part == "examples" || part == "testdata" {
				excluded = true
				break
			}
		}
		if excluded {
			continue
		}
		selected[name] = path
		data, err := os.read_entire_file(fmt.aprintf("%s/%s", checkout, path), context.allocator)
		if err != nil {
			return "", false
		}
		dep_references(string(data), path, prefix, known, &selected)
		delete(data)
	}
	return dep_digest(checkout, selected)
}

// Matches are reported immediately. The caller chooses how to report problems.
deps_compare :: proc(pins: []Pin, shared: string) -> (problems: []string) {
	found: [dynamic]string
	for pin in pins {
		entry := fmt.aprintf("%s/%s", shared, pin.name)
		if !os.exists(entry) {
			append(&found, fmt.aprintf("%s: not in the shared collection %s", pin.name, shared))
			continue
		}
		resolved := posix.realpath(strings.clone_to_cstring(entry))
		if resolved == nil {
			append(&found, fmt.aprintf("%s: cannot resolve %s", pin.name, entry))
			continue
		}
		path := string(resolved)
		checkout := filepath.dir(path)
		digest: string
		ok: bool
		if filepath.base(path) == "src" && os.exists(fmt.aprintf("%s/.git", checkout)) {
			digest, ok = hash_checkout(checkout)
		} else {
			digest, ok = hash_installed(path)
		}
		if !ok {
			append(&found, fmt.aprintf("%s: cannot hash %s", pin.name, path))
		} else if digest == pin.hash {
			fmt.printf("deps: %s %s matches the pin\n", pin.name, pin.tag)
		} else {
			commit := pin.commit[:min(9, len(pin.commit))]
			append(&found, fmt.aprintf("%s: %s differs from the pinned %s (%s)", pin.name, path, pin.tag, commit))
		}
	}
	return found[:]
}

// Compares the collection with the recorded pins. With --strict, drift fails.
deps_command :: proc(arguments: []string) -> int {
	strict := false
	for argument in arguments {
		if argument != "--strict" {
			fail("unknown option: %s", argument)
			return 64
		}
		strict = true
	}
	pins, ok := pins_read(root_directory())
	if !ok {
		return fail("cannot read .krs/packages.json")
	}
	problems := deps_compare(pins, shared_source())
	for problem in problems {
		if strict {
			fail("%s", problem)
		} else {
			fmt.printf("deps: warning: %s\n", problem)
		}
	}
	return 1 if strict && len(problems) > 0 else 0
}
