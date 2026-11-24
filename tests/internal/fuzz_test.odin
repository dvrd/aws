package aws

import "core:fmt"
import "core:os"
import "core:strings"
import "core:testing"
import "core:time"

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

@(test)
fuzz_text_checks_accept_only_what_they_promise :: proc(t: ^testing.T) {
	context.allocator = context.temp_allocator
	fuzz := Fuzz{0x9e3779b97f4a7c15}
	accepted: [6]int
	for round in 0 ..< 20000 {
		instant_seeds := []string{"2030-01-02T03:04:05Z", "2030-01-02T03:04:05.123+02:00", "2030-12-31T23:59:59-11:30"}
		instant := fuzz_mutate(&fuzz, instant_seeds[round % len(instant_seeds)], "0123456789-T:.Z+ ")
		if _, ok := credential_instant_parse(instant); ok {
			accepted[0] += 1
			testing.expect(t, len(instant) >= 20 && instant[10] == 'T', instant)
			last := instant[len(instant) - 1]
			testing.expect(t, last == 'Z' || instant[len(instant) - 6] == '+' || instant[len(instant) - 6] == '-', instant)
		}

		authority := fuzz_text(&fuzz, 24, "abcz019.-:[]443")
		if s3_endpoint_authority_valid(authority) {
			accepted[1] += 1
			for character in transmute([]u8)authority {
				allowed := is_lower(character) || is_digit(character) || strings.contains_rune(".-:[]", rune(character))
				testing.expectf(t, allowed, "%q", authority)
			}
			testing.expectf(t, !strings.has_suffix(authority, ":443") && !strings.has_suffix(authority, ":"), "%q", authority)
		}

		key := fuzz_text(&fuzz, 40, "ab/..\x00\n\x7f ")
		if s3_key_strict(key) {
			accepted[2] += 1
			padded := fmt.tprintf("/%s/", key)
			unsafe := strings.contains(padded, "//") || strings.contains(padded, "/./") || strings.contains(padded, "/../")
			testing.expectf(t, !unsafe, "%q", key)
		}

		relative := fuzz_text(&fuzz, 30, "/v2credentials:@?#\\\r\n.")
		if credential_relative_uri_ok(relative) {
			accepted[3] += 1
			url := fmt.tprintf("http://169.254.170.2%s", relative)
			testing.expectf(t, credential_metadata_url_permitted(url), "%q", relative)
			testing.expectf(t, relative[0] == '/' && !strings.contains_any(relative, "@?#\\\r\n"), "%q", relative)
		}
		url_seeds := []string {
			"http://169.254.170.2/v2/credentials/fixture",
			"http://169.254.169.254/latest/api/token",
			"http://169.254.169.254/latest/meta-data/iam/security-credentials/",
			"http://169.254.169.254/latest/meta-data/iam/security-credentials/fixture-role",
		}
		url := fuzz_mutate(&fuzz, url_seeds[round % len(url_seeds)], "/.:@?#\\ 0129evil")
		if credential_metadata_url_permitted(url) {
			accepted[4] += 1
			testing.expectf(t, strings.has_prefix(url, "http://169.254.170.2/") || strings.has_prefix(url, "http://169.254.169.254/latest/"), "%q", url)
		}

		// Whatever a header line holds, splitting it neither fails nor invents text.
		line := fuzz_text(&fuzz, 24, "Name: value\r\n\x00:")
		fields: [2]S3_Header
		count, split := s3_header_fields({line, "Expect:"}, fields[:])
		if split && count == 1 {
			accepted[5] += 1
			testing.expectf(t, fields[0].name != "" && fields[0].value != "" && strings.contains(line, fields[0].value), "%q", line)
		}

		credentials := AWS_Credentials{fuzz_text(&fuzz, 12, "AKIA\t\x7f"), fuzz_text(&fuzz, 12, "secret\x01"), fuzz_text(&fuzz, 12, "token\r")}
		if aws_credentials_valid(credentials) {
			joined := strings.concatenate({credentials.access_key, credentials.secret_key, credentials.session_token})
			for character in transmute([]u8)joined {
				testing.expect(t, character >= 0x20 && character != 0x7f)
			}
		}
		if round % 256 == 0 {
			free_all(context.temp_allocator)
		}
	}
	// The generators do reach the accepting paths, so the properties were exercised.
	for count, index in accepted {
		testing.expectf(t, count > 0, "check %d never accepted an input", index)
	}
}

@(test)
fuzz_requests_are_well_formed_for_any_key_and_configuration :: proc(t: ^testing.T) {
	context.allocator = context.temp_allocator
	fuzz := Fuzz{0x243f6a8885a308d3}
	credentials := AWS_Credentials{"fixture-key", "fixture-secret", "fixture-token"}
	now := time.unix(1369353600, 0)
	built := 0
	for round in 0 ..< 5000 {
		config := S3_Config {
			bucket     = fuzz_text(&fuzz, 12, "abc.-xyz019"),
			region     = fuzz_text(&fuzz, 10, "us-east-1cn"),
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
		testing.expect(t, s3_config_error(config) == "" && config.bucket != "" && key != "")
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

@(test)
fuzz_profile_files_never_break_the_reader :: proc(t: ^testing.T) {
	directory, error := os.make_directory_temp("", "aws-profile-fuzz-*", context.allocator)
	if !testing.expect(t, error == nil) {
		return
	}
	defer delete(directory)
	defer os.remove(directory)
	path := fmt.aprintf("%s/credentials", directory)
	defer delete(path)
	defer os.remove(path)
	fuzz := Fuzz{0xa4093822299f31d0}
	loaded := 0
	for _ in 0 ..< 300 {
		text := fuzz_mutate(
			&fuzz,
			"# fixture\n[other]\naws_access_key_id = other\n[default]\naws_access_key_id = fixture-key\r\naws_secret_access_key=fixture-secret\n; note\n",
			"[]=\n\r#; \x00role_arn",
		)
		testing.expect(t, os.write_entire_file(path, text) == nil)
		for strict in ([]bool{true, false}) {
			credentials, unsupported, _, read_error := credential_profile_load(path, "default", strict)
			if read_error.kind != .None {
				continue
			}
			if unsupported != .None {
				testing.expect_value(t, credentials, AWS_Credentials{})
			}
			if credentials.access_key != "" {
				loaded += 1
				testing.expectf(t, strings.contains(text, credentials.access_key), "%q", text)
			}
		}
		free_all(context.temp_allocator)
	}
	testing.expect(t, loaded > 0)
}
