package aws

import "core:fmt"
import "core:strings"
import "core:testing"
import "core:time"

// Fuzzing of request building: any key and configuration yields a well-formed
// request, and key encoding round-trips.
@(test)
fuzz_requests_are_well_formed_for_any_key_and_configuration :: proc(t: ^testing.T) {
	context.allocator = context.temp_allocator
	fuzz := Fuzz{0x243f6a8885a308d3}
	credentials := AWS_Credentials{"fixture-key", "fixture-secret", "fixture-token"}
	now := time.unix(1369353600, 0)
	built := 0
	for round in 0 ..< 5000 {
		// Invalid characters are only offered to one configuration in eight, so
		// that enough requests are still built.
		noisy := fuzz_next(&fuzz) % 8 == 0
		config := S3_Config {
			bucket     = fuzz_text(&fuzz, 12, "abc.-xyz019A_/" if noisy else "abc.-xyz019"),
			region     = fuzz_text(&fuzz, 10, "us-east-1cn.A/" if noisy else "us-east-1cn"),
			path_style = fuzz_next(&fuzz) % 2 == 0,
		}
		if fuzz_next(&fuzz) % 3 == 0 {
			config.endpoint = fmt.tprintf("https://%s", fuzz_text(&fuzz, 14, "store.internal:9000[]"))
		}
		key := fuzz_text(&fuzz, 24, "a b/c+d%?#é\x00\n")
		request, ok := s3_get_request(config, credentials, key, now)
		url, presigned := s3_download_url(config, credentials, key, 60, now)
		testing.expect_value(t, presigned, ok)
		if !ok {
			continue
		}
		built += 1
		testing.expect(t, config.bucket != "" && key != "")
		// The accepted-configuration rule, stated independently of s3_config_error.
		testing.expectf(t, len(config.bucket) >= 3 && len(config.bucket) <= 63, "%q", config.bucket)
		for character in transmute([]u8)config.bucket {
			valid := (character >= 'a' && character <= 'z') || (character >= '0' && character <= '9') || character == '-' || character == '.'
			testing.expectf(t, valid, "%q", config.bucket)
		}
		testing.expectf(t, config.region != "", "%q", config.region)
		for character in transmute([]u8)config.region {
			valid := (character >= 'a' && character <= 'z') || (character >= '0' && character <= '9') || character == '-'
			testing.expectf(t, valid, "%q", config.region)
		}
		for text in ([]string{request.url, url}) {
			testing.expectf(t, strings.has_prefix(text, "https://"), "%q", text)
			for character in transmute([]u8)text {
				// Only URL characters reach the wire: the key is percent-encoded.
				testing.expectf(t, character > 0x20 && character < 0x7f, "%q", text)
			}
		}
		rest := request.url[len("https://"):]
		slash := strings.index_byte(rest, '/')
		testing.expectf(t, slash > 0 && !strings.contains_any(rest[slash:], "?#"), "%q", request.url)
		if round % 256 == 0 {
			free_all(context.temp_allocator)
		}
	}
	testing.expect(t, built > 100)
}

@(test)
fuzz_key_encoding_round_trips :: proc(t: ^testing.T) {
	context.allocator = context.temp_allocator
	fuzz := Fuzz{0x13198a2e03707344}
	for _ in 0 ..< 5000 {
		key := fuzz_text(&fuzz, 32, "aZ09-_.~/ %+é")
		for keep_slashes in ([]bool{true, false}) {
			encoded := s3_encode(key, keep_slashes)
			decoded := strings.builder_make()
			for index := 0; index < len(encoded); index += 1 {
				character := encoded[index]
				if character == '%' {
					testing.expect(t, index + 2 < len(encoded))
					high := strings.index_byte("0123456789ABCDEF", encoded[index + 1])
					low := strings.index_byte("0123456789ABCDEF", encoded[index + 2])
					testing.expectf(t, high >= 0 && low >= 0, "%q", encoded)
					strings.write_byte(&decoded, u8(high * 16 + low))
					index += 2
					continue
				}
				unreserved := is_alphanumeric(character) || strings.contains_rune("-_.~", rune(character)) || keep_slashes && character == '/'
				testing.expectf(t, unreserved, "%q", encoded)
				strings.write_byte(&decoded, character)
			}
			testing.expect_value(t, strings.to_string(decoded), key)
		}
	}
}
