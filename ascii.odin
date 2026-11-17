package aws

import "core:unicode"

// Accept bytes and string-loop runes without narrowing non-ASCII code points
// into bytes.
@(private)
is_alpha :: proc(c: $T) -> bool where T == u8 || T == rune {
	r := cast(rune)c

	return r >= 0 && r < 128 && unicode.is_alpha(r)
}

@(private)
is_lower :: proc(c: $T) -> bool where T == u8 || T == rune {
	return c >= 'a' && c <= 'z'
}

@(private)
is_digit :: proc(c: $T) -> bool where T == u8 || T == rune {
	r := cast(rune)c

	return r >= 0 && r < 128 && unicode.is_digit(r)
}

@(private)
is_alphanumeric :: proc(c: $T) -> bool where T == u8 || T == rune {
	return is_alpha(c) || is_digit(c)
}
