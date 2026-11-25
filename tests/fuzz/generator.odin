package aws

// Deterministic input generators shared by the fuzz tests.
// Deterministic random inputs for everything that parses text from outside. The
// properties are that nothing indexes out of range and that an accepted value
// has the shape its check promises.
Fuzz :: struct {
	state: u64,
}

fuzz_next :: proc(fuzz: ^Fuzz) -> u64 {
	fuzz.state ~= fuzz.state << 13
	fuzz.state ~= fuzz.state >> 7
	fuzz.state ~= fuzz.state << 17
	return fuzz.state
}

// Text biased towards the characters the parsers give meaning to.
fuzz_text :: proc(fuzz: ^Fuzz, limit: int, alphabet: string) -> string {
	size := int(fuzz_next(fuzz) % u64(limit + 1))
	buffer := make([]u8, size, context.temp_allocator)
	for &character in buffer {
		choice := fuzz_next(fuzz)
		if choice % 4 == 0 {
			character = u8(choice >> 8)
		} else {
			character = alphabet[int(choice >> 8) % len(alphabet)]
		}
	}
	return string(buffer)
}

// A valid sample with up to two random edits, so that both sides of a check are
// reached often.
fuzz_mutate :: proc(fuzz: ^Fuzz, seed: string, alphabet: string) -> string {
	buffer := make([dynamic]u8, context.temp_allocator)
	append(&buffer, seed)
	for _ in 0 ..< int(fuzz_next(fuzz) % 3) {
		choice := fuzz_next(fuzz)
		at := int(choice >> 8) % (len(buffer) + 1)
		character := alphabet[int(choice >> 24) % len(alphabet)]
		if choice % 8 == 0 {
			character = u8(choice >> 40)
		}
		switch choice % 3 {
		case 0:
			if at < len(buffer) {
				buffer[at] = character
			}
		case 1:
			inject_at(&buffer, at, character)
		case 2:
			if at < len(buffer) {
				ordered_remove(&buffer, at)
			}
		}
	}
	return string(buffer[:])
}
