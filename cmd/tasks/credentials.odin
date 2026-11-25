package main

import "core:fmt"
import "core:os"
import "core:time"

CREDENTIALS_FIXTURE :: "tests/e2e/credentials/fixture"

CREDENTIAL_FIXTURES :: []string {
	"environment",
	"profile",
	"partial-env",
	"partial-profile",
	"token-only-profile",
	"oversize",
	"ecs",
	"imds",
	"disabled",
	"invalid-relative",
	"transport-failure",
	"malformed",
	"invalid-credentials",
}

// Runs the credential resolver fixture once per source, each time with nothing in
// the environment but that source. Synthetic files, environment and fake HTTP only.
credentials_command :: proc(arguments: []string) -> int {
	only := ""
	for index := 0; index < len(arguments); index += 1 {
		if arguments[index] != "--only" {
			return fail("unknown option: %s", arguments[index])
		}
		only = option_value(arguments, &index) or_else ""
		known := false
		for fixture in CREDENTIAL_FIXTURES {
			known ||= fixture == only
		}
		if !known {
			return fail("unknown credential fixture")
		}
	}
	work, created := work_directory("credentials")
	if !created {
		return fail("cannot create a work directory")
	}
	defer os.remove_all(work)
	shared, staged := stage_collection(work)
	if !staged {
		return fail("cannot stage the shared collection")
	}
	if !sanitizer_clang_select() {
		return 1
	}
	fixture := fmt.aprintf("%s/fixture", work)
	if code := run(
		{
			compiler(),
			"build",
			CREDENTIALS_FIXTURE,
			fmt.aprintf("-collection:shared=%s", shared),
			"-sanitize:address",
			"-warnings-as-errors",
			fmt.aprintf("-out:%s", fixture),
		},
		timeout = BUILD_TIMEOUT,
	); code != 0 {
		return code
	}
	files := []struct {
		name, text: string,
	} {
		{"profile", "[default]\naws_access_key_id=fixture-key\naws_secret_access_key=fixture-secret\naws_session_token=fixture-session\n"},
		{"partial-profile", "[default]\naws_access_key_id=fixture-key\n"},
		{"token-only-profile", "[default]\naws_session_token=fixture-session\n"},
	}
	for file in files {
		if os.write_entire_file(fmt.aprintf("%s/%s", work, file.name), file.text) != nil {
			return fail("cannot write %s", file.name)
		}
	}
	if os.write_entire_file(fmt.aprintf("%s/oversize", work), make([]u8, 1024 * 1024)) != nil {
		return fail("cannot write oversize")
	}
	search, _ := os.lookup_env("PATH", context.allocator)
	if search == "" {
		search = "/usr/bin:/bin"
	}
	for mode in CREDENTIAL_FIXTURES {
		if only != "" && only != mode {
			continue
		}
		environment := make([dynamic]string)
		append(
			&environment,
			fmt.aprintf("PATH=%s", search),
			fmt.aprintf("HOME=%s", work),
			fmt.aprintf("TMPDIR=%s", work),
			fmt.aprintf("AWS_SHARED_CREDENTIALS_FILE=%s/absent", work),
			"AWS_EC2_METADATA_DISABLED=false",
		)
		// A later assignment of the same name wins in the fixture's environment.
		switch mode {
		case "environment":
			append(&environment, "AWS_ACCESS_KEY_ID=fixture-key", "AWS_SECRET_ACCESS_KEY=fixture-secret", "AWS_SESSION_TOKEN=fixture-session")
		case "partial-env":
			append(&environment, "AWS_ACCESS_KEY_ID=fixture-key")
		case "profile", "partial-profile", "token-only-profile", "oversize":
			environment[3] = fmt.aprintf("AWS_SHARED_CREDENTIALS_FILE=%s/%s", work, mode)
		}
		switch mode {
		case "imds":
		case "disabled":
			environment[4] = "AWS_EC2_METADATA_DISABLED=true"
		case "invalid-relative":
			append(&environment, "AWS_CONTAINER_CREDENTIALS_RELATIVE_URI=//invalid\npath")
		case:
			append(&environment, "AWS_CONTAINER_CREDENTIALS_RELATIVE_URI=/v2/credentials/fixture")
		}
		child, started := spawn({command = {fixture, mode}, environment = environment[:], exact = true})
		if !started {
			return fail("cannot start the fixture")
		}
		code, finished := wait(&child, 5 * time.Second)
		if !finished {
			return fail("credential fixture %s did not finish", mode)
		}
		if code != 0 {
			return code
		}
	}
	fmt.println("Credential resolver fixtures passed; synthetic files/environment and fake HTTP only")
	return 0
}
