package aws

import "core:unicode"

// Accept bytes and string-loop runes without narrowing non-ASCII code points
// into bytes.
is_alpha :: proc(c: $T) -> bool where T == u8 || T == rune {
	r := cast(rune)c

	return r >= 0 && r < 128 && unicode.is_alpha(r)
}

is_lower :: proc(c: $T) -> bool where T == u8 || T == rune {
	return c >= 'a' && c <= 'z'
}

is_digit :: proc(c: $T) -> bool where T == u8 || T == rune {
	r := cast(rune)c

	return r >= 0 && r < 128 && unicode.is_digit(r)
}

is_alphanumeric :: proc(c: $T) -> bool where T == u8 || T == rune {
	return is_alpha(c) || is_digit(c)
}

// Every byte is visible ASCII, 0x21 to 0x7e: no space, control character or
// non-ASCII byte. For credentials and metadata text that go into URLs and header
// values unquoted, where a space would be trimmed by one side and not the other.
text_visible :: proc(text: string) -> bool {
	for index in 0 ..< len(text) {
		if text[index] < 0x21 || text[index] > 0x7e {
			return false
		}
	}
	return true
}

// No control character (below 0x20, or 0x7f). Spaces and non-ASCII bytes are
// allowed: for text such as object keys that is encoded before it is sent.
text_without_controls :: proc(text: string) -> bool {
	for index in 0 ..< len(text) {
		if text[index] < 0x20 || text[index] == 0x7f {
			return false
		}
	}
	return true
}
