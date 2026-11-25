package aws

import "core:testing"

// Unit tests of src/ascii.odin: ASCII classes that never accept other scripts.

@(test)
ascii_classes_accept_ascii_only :: proc(t: ^testing.T) {
	for character in u8(0) ..< 128 {
		letter := character >= 'a' && character <= 'z' || character >= 'A' && character <= 'Z'
		digit := character >= '0' && character <= '9'
		testing.expect_value(t, is_alpha(character), letter)
		testing.expect_value(t, is_digit(character), digit)
		testing.expect_value(t, is_lower(character), character >= 'a' && character <= 'z')
		testing.expect_value(t, is_alphanumeric(character), letter || digit)
		// The rune forms agree with the byte forms.
		testing.expect_value(t, is_alpha(rune(character)), letter)
		testing.expect_value(t, is_alphanumeric(rune(character)), letter || digit)
	}
	for character in u8(128) ..= 255 {
		testing.expect(t, !is_alpha(character) && !is_digit(character) && !is_lower(character))
	}
	// Letters and digits of other scripts are not ASCII.
	for character in ([]rune{'é', 'ß', 'Ж', '日', '٣', '१', '５', -1, 0x10ffff}) {
		testing.expectf(t, !is_alphanumeric(character) && !is_lower(character), "%v", character)
	}
}

@(test)
text_predicates_draw_the_documented_lines :: proc(t: ^testing.T) {
	for value in 0 ..< 256 {
		bytes := [1]u8{u8(value)}
		text := string(bytes[:])
		testing.expect_value(t, text_visible(text), value >= 0x21 && value <= 0x7e)
		testing.expect_value(t, text_without_controls(text), value >= 0x20 && value != 0x7f)
	}
	testing.expect(t, text_visible(""))
	testing.expect(t, text_without_controls(""))
}
