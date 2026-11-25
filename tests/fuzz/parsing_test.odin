package aws

import "core:fmt"
import "core:os"
import "core:strings"
import "core:testing"

// Fuzzing of every check that reads text from outside: expiry instants,
// endpoints, keys, metadata paths and URLs, header lines, credentials and
// credentials files.
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
