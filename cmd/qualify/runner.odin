// Finite native AWS qualification with explicit scratch resources and durable intent.
//
// Credentials come from the selected profile or an explicitly planned temporary
// environment; S3 and SES operations run in the native probe. No keys, provider
// bodies or URLs are logged.
package main

import "core:crypto"
import "core:encoding/hex"
import "core:encoding/json"
import "core:os"
import "core:strings"
import "core:sys/posix"
import "core:time"
import "core:unicode"
import "core:unicode/utf8"

TOTAL_TIME :: 180 * time.Second

SCOPE_MEMBERS :: []string {
	"schema",
	"bucket",
	"region",
	"prefix",
	"profile",
	"expected_account",
	"allow_write",
	"allow_ses",
	"ses_sender",
}
RESULT_MEMBERS :: []string {
	"schema",
	"ok",
	"reason",
	"object",
	"credential_kind",
	"s3_kind",
	"ses_kind",
	"put_effect",
	"delete_effect",
	"ses_effect",
	"mutation_status",
}
READ_ERROR_CODES :: []string {
	"None",
	"Unknown",
	"NoSuchKey",
	"NoSuchBucket",
	"AccessDenied",
	"InvalidAccessKeyId",
	"SignatureDoesNotMatch",
	"ExpiredToken",
	"InvalidToken",
	"RequestTimeTooSkewed",
	"AuthorizationHeaderMalformed",
	"SlowDown",
	"RequestTimeout",
	"PermanentRedirect",
	"TemporaryRedirect",
	"RequestExpired",
}
REASONS :: []string {
	"None",
	"Invalid_Arguments",
	"Invalid_Scope",
	"Credential_Error",
	"Read_Failed",
	"Foreign_Object",
	"Put_Disabled",
	"Put_Failed",
	"Delete_Failed",
	"Response_Mismatch",
	"SES_Disabled",
	"SES_Failed",
}
OBJECTS :: []string{"Unverified", "Absent", "Owned", "Foreign"}
CREDENTIAL_KINDS :: []string {
	"None",
	"Invalid_Argument",
	"Unsupported",
	"Incomplete",
	"Unavailable",
	"Expired",
	"Cancelled",
	"Waiter_Limit",
	"Busy",
	"Allocation_Failed",
	"Closed",
}
S3_KINDS :: []string{"None", "Invalid_Input", "Not_Found", "Too_Large", "Rejected", "Unavailable"}
SES_KINDS :: []string {
	"None",
	"Invalid_Config",
	"Invalid_Message",
	"Allocation_Failed",
	"Unavailable",
	"Rejected",
	"Invalid_Response",
}
EFFECTS :: []string{"Unknown", "Not_Sent", "Response_Received"}
ATTESTATION_MEMBERS :: []string {
	"principal_type",
	"role_match",
	"session_present",
	"expiry_guard",
	"expected_role_arn_sha256",
}

Arguments :: struct {
	command:                                    string,
	state_dir, resource_plan, binary, aws_cli:  string,
	ses_sender:                                 string,
	allow_write, ses_identity_verified, live:   bool,
}

// The environment handed to the native probe. attestation is set only when the
// credentials were checked against the planned role.
Environment :: struct {
	variables:   map[string]string,
	attestation: json.Object,
	verified:    bool,
}

Launch :: #type proc(
	runner: ^Runner,
	state: json.Object,
	verb: string,
	environment: Environment,
	deadline: time.Duration,
) -> (
	json.Object,
	Failure,
)
Credential_Loader :: #type proc(runner: ^Runner, scope: json.Object, deadline: time.Duration) -> (Environment, Failure)
Capture :: #type proc(
	runner: ^Runner,
	argv: []string,
	environment: map[string]string,
	deadline: time.Duration,
	limit: int,
) -> (
	int,
	[]u8,
	Failure,
)

// One command and the seams it reaches the outside world through. Deadlines are
// durations on monotonic, which only ever moves forward.
Runner :: struct {
	arguments:   Arguments,
	launch:      Launch,
	credentials: Credential_Loader,
	capture:     Capture,
	monotonic:   proc(runner: ^Runner) -> time.Duration,
	variable:    proc(runner: ^Runner, name: string) -> (string, bool),
	started:     time.Tick,
	user:        rawptr,
}

runner_make :: proc(arguments: Arguments) -> Runner {
	return {
		arguments = arguments,
		launch = native,
		credentials = credentials,
		capture = capture_child,
		monotonic = proc(runner: ^Runner) -> time.Duration {
			return time.tick_since(runner.started)
		},
		variable = proc(runner: ^Runner, name: string) -> (string, bool) {
			value := posix.getenv(strings.clone_to_cstring(name))
			if value == nil {
				return "", false
			}
			return strings.clone(string(value)), true
		},
		started = time.tick_now(),
	}
}

state_file :: proc(runner: ^Runner, name: string) -> string {
	return strings.concatenate({runner.arguments.state_dir, "/", name})
}

characters_valid :: proc(text: string, low, high: int, allowed: proc(character: u8) -> bool) -> bool {
	if len(text) < low || len(text) > high {
		return false
	}
	for index in 0 ..< len(text) {
		if !allowed(text[index]) {
			return false
		}
	}
	return true
}

is_lower :: proc(character: u8) -> bool {
	return character >= 'a' && character <= 'z'
}

is_digit :: proc(character: u8) -> bool {
	return character >= '0' && character <= '9'
}

is_hex :: proc(character: u8) -> bool {
	return is_digit(character) || character >= 'a' && character <= 'f'
}

is_bucket_character :: proc(character: u8) -> bool {
	return is_lower(character) || is_digit(character) || character == '-'
}

is_profile_character :: proc(character: u8) -> bool {
	return is_lower(character) || is_digit(character) || character >= 'A' && character <= 'Z' || character == '_' || character == '-'
}

is_role_character :: proc(character: u8) -> bool {
	return is_profile_character(character) || strings.contains_rune("+=,.@", rune(character))
}

is_printable :: proc(character: u8) -> bool {
	return character >= 33 && character <= 126
}

hex_valid :: proc(text: string, size: int) -> bool {
	return characters_valid(text, size, size, is_hex)
}

// webtools-qualification-<3..40 of a-z 0-9 ->
bucket_valid :: proc(text: string) -> bool {
	prefix :: "webtools-qualification-"
	return strings.has_prefix(text, prefix) && characters_valid(text[len(prefix):], 3, 40, is_bucket_character)
}

// Two letters, letters, one digit: us-east-1.
region_valid :: proc(text: string) -> bool {
	size := len(text)
	return(
		size >= 6 &&
		characters_valid(text[:2], 2, 2, is_lower) &&
		text[2] == '-' &&
		characters_valid(text[3:size - 2], 1, size, is_lower) &&
		text[size - 2] == '-' &&
		is_digit(text[size - 1]) \
	)
}

// qualification/<32 hex>/
prefix_valid :: proc(text: string) -> bool {
	prefix :: "qualification/"
	return(
		len(text) == len(prefix) + 33 &&
		strings.has_prefix(text, prefix) &&
		hex_valid(text[len(prefix):len(text) - 1], 32) &&
		text[len(text) - 1] == '/' \
	)
}

sender_part_valid :: proc(text: string) -> bool {
	count := utf8.rune_count_in_string(text)
	if count < 1 || count > 120 {
		return false
	}
	for character in text {
		if unicode.is_space(character) || character == '<' || character == '>' || character == '@' {
			return false
		}
	}
	return true
}

sender_valid :: proc(text: string) -> bool {
	at := strings.index_byte(text, '@')
	return at >= 0 && sender_part_valid(text[:at]) && sender_part_valid(text[at + 1:])
}

// arn:aws:iam::<account>:role/<1..64 role characters>
role_valid :: proc(role, account: string) -> bool {
	prefix := strings.concatenate({"arn:aws:iam::", account, ":role/"})
	return strings.has_prefix(role, prefix) && characters_valid(role[len(prefix):], 1, 64, is_role_character)
}

scope_valid :: proc(scope: json.Object) -> Failure {
	if !members_are(scope, SCOPE_MEMBERS) || !integer_is(scope, "schema", 1) {
		return .Scope_Schema_Invalid
	}
	for check in ([]struct {
			name:  string,
			valid: proc(text: string) -> bool,
		} {
			{"bucket", bucket_valid},
			{"region", region_valid},
			{"prefix", prefix_valid},
			{"profile", proc(text: string) -> bool {return characters_valid(text, 1, 64, is_profile_character)}},
			{"expected_account", proc(text: string) -> bool {return characters_valid(text, 12, 12, is_digit)}},
		}) {
		text, found := text_of(scope, check.name)
		if !found || !check.valid(text) {
			return .Scope_Resource_Invalid
		}
	}
	allow_write, write_set := boolean_of(scope, "allow_write")
	allow_ses, ses_set := boolean_of(scope, "allow_ses")
	if !write_set || !ses_set {
		return .Scope_Policy_Invalid
	}
	sender, sender_set := text_of(scope, "ses_sender")
	if !sender_set || allow_ses && !sender_valid(sender) || !allow_ses && sender != "" {
		return .SES_Policy_Invalid
	}
	// SES is sent only after the S3 round trip, which needs write access.
	if allow_ses && !allow_write {
		return .SES_Policy_Invalid
	}
	return .None
}

// The role a temporary environment must hold. bound is false for a plain profile.
credential_policy :: proc(resource: json.Object, account: string) -> (policy: json.Object, bound: bool, failure: Failure) {
	source := "profile"
	source_is_text := true
	if "credential_source" in resource {
		source, source_is_text = text_of(resource, "credential_source")
	}
	if source_is_text && source == "profile" && "expected_role_arn" not_in resource {
		return nil, false, .None
	}
	role, role_is_text := text_of(resource, "expected_role_arn")
	if !source_is_text || source != "environment" || !role_is_text || !role_valid(role, account) {
		return nil, false, .Credential_Policy_Invalid
	}
	policy = make(json.Object)
	policy["schema"] = json.Integer(1)
	policy["credential_source"] = source
	policy["expected_role_arn"] = role
	return policy, true, .None
}

// scope with the planned credential policy merged in, after checking that the
// policy file is still the one the plan bound.
bound_credential_scope :: proc(runner: ^Runner, state, scope: json.Object) -> (bound: json.Object, failure: Failure) {
	path := state_file(runner, "credential-policy.json")
	expected, planned := state["credential_policy_sha256"]
	if _, null := expected.(json.Null); !planned || null || expected == nil {
		if path_present(path) {
			return nil, .Unbound_Credential_Policy
		}
		return scope, .None
	}
	policy, policy_bytes := read_private_bytes(path) or_return
	digest := sha256_hex(policy_bytes)
	if expected_text, is_text := expected.(json.String); !is_text || digest != expected_text {
		return nil, .Credential_Policy_Changed
	}
	if !members_are(policy, {"schema", "credential_source", "expected_role_arn"}) || !integer_is(policy, "schema", 1) {
		return nil, .Credential_Policy_Invalid
	}
	account, account_set := text_of(scope, "expected_account")
	if !account_set {
		return nil, .Invalid_Document
	}
	_, validated := credential_policy(policy, account) or_return
	if !validated {
		return nil, .Credential_Policy_Invalid
	}
	bound = make(json.Object)
	for name, value in scope {
		bound[name] = value
	}
	bound["credential_source"] = policy["credential_source"]
	bound["expected_role_arn"] = policy["expected_role_arn"]
	return bound, .None
}

// The only shape of role evidence that may be stored or printed.
safe_attestation :: proc(value: json.Value) -> (safe: json.Object, failure: Failure) {
	object, is_object := value.(json.Object)
	digest, _ := text_of(object, "expected_role_arn_sha256")
	if !is_object ||
	   !members_are(object, ATTESTATION_MEMBERS) ||
	   !text_is(object, "principal_type", "AssumedRole") ||
	   !is_true(object, "role_match") ||
	   !is_true(object, "session_present") ||
	   !is_true(object, "expiry_guard") ||
	   !hex_valid(digest, 64) {
		return nil, .Role_Attestation_Invalid
	}
	return object, .None
}

// Writes and returns the public summary of a run.
receipt :: proc(directory: string, state: json.Object, reason := "") -> (result: json.Object, failure: Failure) {
	result = make(json.Object)
	for name in ([]string{"run_id", "scope_sha256", "binary_sha256", "phase"}) {
		if name not_in state {
			return nil, .Invalid_Document
		}
		result[name] = state[name]
	}
	if "allow_ses" not_in state {
		return nil, .Invalid_Document
	}
	result["schema"] = json.Integer(1)
	result["qualified"] = text_is(state, "phase", "COMPLETE")
	result["s3_qualified"] = state["s3_qualified"] if "s3_qualified" in state else json.Value(false)
	result["secrets_logged"] = false
	result["ses_selected"] = state["allow_ses"]
	if reason != "" {
		result["reason"] = reason
	}
	for name in ([]string{"last_result", "read_result", "reconcile_result", "put_result", "delete_result", "ses_result"}) {
		if name in state {
			result[name] = state[name]
		}
	}
	if "credential_attestation" in state {
		result["credential_attestation"] = safe_attestation(state["credential_attestation"]) or_return
	}
	atomic(directory, "receipt.json", result) or_return
	return result, .None
}

// Binds a run to its scratch resources, policy and probe binary. Starts nothing.
plan :: proc(runner: ^Runner) -> (result: json.Object, failure: Failure) {
	arguments := runner.arguments
	resource := read_private(arguments.resource_plan) or_return
	if !integer_is(resource, "schema", 1) ||
	   !text_is(resource, "phase", "READY") ||
	   !is_true(resource, "public_access_block_verified") ||
	   !text_is(resource, "encryption", "AES256") {
		return nil, .Resources_Not_Ready
	}
	account, account_set := text_of(resource, "expected_account")
	if !account_set {
		return nil, .Invalid_Document
	}
	policy, bound := credential_policy(resource, account) or_return
	scope := make(json.Object)
	scope["schema"] = json.Integer(1)
	for name in ([]string{"bucket", "region", "prefix", "expected_account"}) {
		if name not_in resource {
			return nil, .Invalid_Document
		}
		scope[name] = resource[name]
	}
	if bound {
		scope["profile"] = "environment"
	} else {
		if "profile" not_in resource {
			return nil, .Invalid_Document
		}
		scope["profile"] = resource["profile"]
	}
	scope["allow_write"] = arguments.allow_write
	scope["allow_ses"] = arguments.ses_sender != ""
	scope["ses_sender"] = arguments.ses_sender
	if arguments.ses_sender != "" && !arguments.ses_identity_verified {
		return nil, .Verified_SES_Identity_Required
	}
	scope_valid(scope) or_return
	lock := lock_acquire(arguments.state_dir) or_return
	defer lock_release(lock)
	// state.json is written last and only ever replaced, never removed: without it
	// no run started, and leftovers of an interrupted plan are replaced below.
	if path_present(state_file(runner, "state.json")) {
		return nil, .Run_Already_Exists
	}
	// Only this private copy, made from the bytes that were hashed, is ever run.
	digest := probe_install(arguments.binary, arguments.state_dir) or_return
	atomic(arguments.state_dir, "scope.json", scope) or_return
	_, scope_bytes := read_private_bytes(state_file(runner, "scope.json")) or_return
	identifier: [16]u8
	crypto.rand_bytes(identifier[:])
	state := make(json.Object)
	state["schema"] = json.Integer(1)
	state["run_id"] = string(hex.encode(identifier[:]))
	state["phase"] = "PREPARED"
	state["scope_sha256"] = sha256_hex(scope_bytes)
	state["binary"] = state_file(runner, PROBE_NAME)
	state["binary_source"] = arguments.binary
	state["binary_sha256"] = digest
	state["allow_ses"] = scope["allow_ses"]
	state["s3_qualified"] = false
	if bound {
		atomic(arguments.state_dir, "credential-policy.json", policy) or_return
		_, policy_bytes := read_private_bytes(state_file(runner, "credential-policy.json")) or_return
		state["credential_policy_sha256"] = sha256_hex(policy_bytes)
	}
	if !bound {
		policy_path := strings.clone_to_cstring(state_file(runner, "credential-policy.json"))
		if posix.unlink(policy_path) != .OK && posix.errno() != .ENOENT {
			return nil, .System
		}
	}
	atomic(arguments.state_dir, "state.json", state) or_return
	return receipt(arguments.state_dir, state)
}

// An instant with an explicit zone: YYYY-MM-DDTHH:MM:SS[.fraction](Z|+HH:MM|-HH:MM).
// The fraction is dropped, which can only make an expiry look earlier.
// Mirrors credential_instant_parse in src/credentials.odin (private there) and
// must stay in step with it.
instant_parse :: proc(text: string) -> (instant: time.Time, ok: bool) {
	number :: proc(text: string) -> (value: int, ok: bool) {
		for index in 0 ..< len(text) {
			if !is_digit(text[index]) {
				return 0, false
			}
			value = value * 10 + int(text[index] - '0')
		}
		return value, len(text) > 0
	}
	if len(text) < 20 || len(text) > 64 || text[4] != '-' || text[7] != '-' || text[10] != 'T' || text[13] != ':' || text[16] != ':' {
		return {}, false
	}
	year := number(text[0:4]) or_return
	month := number(text[5:7]) or_return
	day := number(text[8:10]) or_return
	hour := number(text[11:13]) or_return
	minute := number(text[14:16]) or_return
	second := number(text[17:19]) or_return
	rest := text[19:]
	if rest[0] == '.' {
		digits := 1
		for digits < len(rest) && is_digit(rest[digits]) {
			digits += 1
		}
		if digits == 1 {
			return {}, false
		}
		rest = rest[digits:]
	}
	offset: time.Duration
	switch {
	case rest == "Z":
	case len(rest) == 6 && (rest[0] == '+' || rest[0] == '-') && rest[3] == ':':
		hours := number(rest[1:3]) or_return
		minutes := number(rest[4:6]) or_return
		if hours > 23 || minutes > 59 {
			return {}, false
		}
		offset = time.Duration(hours) * time.Hour + time.Duration(minutes) * time.Minute
		if rest[0] == '-' {
			offset = -offset
		}
	case:
		return {}, false
	}
	instant = time.datetime_to_time(year, month, day, hour, minute, second) or_return
	return time.time_add(instant, -offset), true
}

expires_within :: proc(expiry: time.Time, margin: time.Duration) -> bool {
	return time.diff(time.now(), expiry) <= margin
}

environment_copy :: proc(base: map[string]string, names: []string) -> map[string]string {
	result := make(map[string]string)
	for name in names {
		if value, found := base[name]; found {
			result[name] = value
		}
	}
	return result
}

// The temporary credentials of this process, bounded and printable, with an
// expiry that outlasts the whole campaign.
temporary_environment :: proc(
	runner: ^Runner,
	base: map[string]string,
) -> (
	variables: map[string]string,
	expiry: time.Time,
	failure: Failure,
) {
	variables = environment_copy(base, {"PATH", "LANG", "LC_ALL", "TMPDIR"})
	for item in ([]struct {
			name:  string,
			bound: int,
		}{{"AWS_ACCESS_KEY_ID", 128}, {"AWS_SECRET_ACCESS_KEY", 256}, {"AWS_SESSION_TOKEN", 8192}}) {
		value, _ := runner.variable(runner, item.name)
		if !characters_valid(value, 1, item.bound, is_printable) {
			return nil, {}, .Temporary_Credentials_Required
		}
		variables[item.name] = value
	}
	expiration, expiration_set := runner.variable(runner, "AWS_CREDENTIAL_EXPIRATION")
	parsed := false
	if expiration_set {
		expiry, parsed = instant_parse(expiration)
	}
	if !parsed {
		return nil, {}, .Temporary_Expiration_Required
	}
	if expires_within(expiry, TOTAL_TIME) {
		return nil, {}, .Credentials_Near_Expiry
	}
	variables["AWS_EC2_METADATA_DISABLED"] = "true"
	variables["AWS_CONFIG_FILE"] = "/dev/null"
	variables["AWS_SHARED_CREDENTIALS_FILE"] = "/dev/null"
	return variables, expiry, .None
}

caller_identity :: proc(
	runner: ^Runner,
	executable, region: string,
	variables: map[string]string,
	deadline: time.Duration,
) -> (
	identity: json.Object,
	failure: Failure,
) {
	code, data := runner.capture(
		runner,
		{executable, "sts", "get-caller-identity", "--region", region, "--output", "json", "--no-cli-pager"},
		variables,
		min(deadline, runner.monotonic(runner) + 30 * time.Second),
		MAX_BYTES,
	) or_return
	if code != 0 {
		return nil, .None
	}
	value := decode(data) or_return
	identity, _ = value.(json.Object)
	return identity, .None
}

// Credentials from the environment, accepted only as a session of the planned role.
environment_credentials :: proc(
	runner: ^Runner,
	executable: string,
	scope: json.Object,
	base: map[string]string,
	deadline: time.Duration,
) -> (
	environment: Environment,
	failure: Failure,
) {
	variables, expiry := temporary_environment(runner, base) or_return
	region, _ := text_of(scope, "region")
	account, _ := text_of(scope, "expected_account")
	role, role_set := text_of(scope, "expected_role_arn")
	if !role_set {
		return {}, .Invalid_Document
	}
	variables["AWS_REGION"] = region
	identity := caller_identity(runner, executable, region, variables, deadline) or_return
	if identity == nil || !text_is(identity, "Account", account) {
		return {}, .Account_Not_Verified
	}
	// The role name is compared literally; only the session name is a pattern.
	name := role[strings.last_index_byte(role, '/') + 1:]
	assumed := strings.concatenate({"arn:aws:sts::", account, ":assumed-role/", name, "/"})
	arn, arn_set := text_of(identity, "Arn")
	if !arn_set || !strings.has_prefix(arn, assumed) || !characters_valid(arn[len(assumed):], 2, 64, is_role_character) {
		return {}, .Expected_Role_Not_Verified
	}
	remaining := deadline - runner.monotonic(runner)
	if remaining <= 0 {
		return {}, .Campaign_Deadline
	}
	if expires_within(expiry, remaining) {
		return {}, .Credentials_Near_Expiry
	}
	safe := make(json.Object)
	safe["principal_type"] = "AssumedRole"
	safe["role_match"] = true
	safe["session_present"] = true
	safe["expiry_guard"] = true
	safe["expected_role_arn_sha256"] = sha256_hex(transmute([]u8)role)
	return {variables = variables, attestation = safe, verified = true}, .None
}

executable_find :: proc(runner: ^Runner, name: string) -> string {
	search, _ := runner.variable(runner, "PATH")
	for directory in strings.split(search, ":") {
		if directory == "" || !os.is_absolute_path(directory) {
			continue
		}
		candidate := strings.concatenate({directory, "/", name})
		path := strings.clone_to_cstring(candidate)
		info: posix.stat_t
		if posix.stat(path, &info) == .OK && posix.S_ISREG(info.st_mode) && posix.access(path, {.X_OK}) == .OK {
			return candidate
		}
	}
	return ""
}

// The real path of the AWS CLI, which receives live credentials: an absolute path
// to a regular, executable file owned by this user or by root that group and
// others cannot write. A link (such as Homebrew's) is resolved first, and only the
// resolved file is checked and executed.
aws_cli_trusted :: proc(path: string) -> (resolved: string, failure: Failure) {
	if !os.is_absolute_path(path) {
		return "", .AWS_CLI_Required
	}
	real := posix.realpath(strings.clone_to_cstring(path))
	if real == nil {
		return "", .AWS_CLI_Required
	}
	resolved = strings.clone_from_cstring(real)
	posix.free(real)
	name := strings.clone_to_cstring(resolved)
	info: posix.stat_t
	if posix.stat(name, &info) != .OK ||
	   !posix.S_ISREG(info.st_mode) ||
	   (info.st_uid != posix.geteuid() && info.st_uid != 0) ||
	   permission_bits(info.st_mode) & 0o022 != 0 ||
	   posix.access(name, {.X_OK}) != .OK {
		return "", .AWS_CLI_Required
	}
	return resolved, .None
}

// Default Credential_Loader: asks the AWS CLI for the credentials and checks the
// account they belong to before anything native starts.
credentials :: proc(runner: ^Runner, scope: json.Object, deadline: time.Duration) -> (environment: Environment, failure: Failure) {
	executable := runner.arguments.aws_cli
	if executable == "" {
		executable = executable_find(runner, "aws")
	}
	if executable == "" {
		return {}, .AWS_CLI_Required
	}
	executable = aws_cli_trusted(executable) or_return
	base := make(map[string]string)
	for name in ([]string{"PATH", "HOME", "USER", "LOGNAME", "LANG", "LC_ALL", "TMPDIR"}) {
		if value, found := runner.variable(runner, name); found {
			base[name] = value
		}
	}
	base["AWS_EC2_METADATA_DISABLED"] = "true"
	if text_is(scope, "credential_source", "environment") {
		return environment_credentials(runner, executable, scope, base, deadline)
	}
	profile, profile_set := text_of(scope, "profile")
	region, region_set := text_of(scope, "region")
	account, account_set := text_of(scope, "expected_account")
	if !profile_set || !region_set || !account_set {
		return {}, .Invalid_Document
	}
	code, data := runner.capture(
		runner,
		{executable, "configure", "export-credentials", "--format", "process", "--profile", profile},
		base,
		min(deadline, runner.monotonic(runner) + 30 * time.Second),
		MAX_BYTES,
	) or_return
	if code != 0 {
		return {}, .Credential_Export_Failed
	}
	exported := decode(data) or_return
	value, is_object := exported.(json.Object)
	if !is_object || !integer_is(value, "Version", 1) {
		return {}, .Credential_Export_Invalid
	}
	variables := environment_copy(base, {"PATH", "LANG", "LC_ALL", "TMPDIR"})
	for item in ([]struct {
			name, source: string,
			bound:        int,
		} {
			{"AWS_ACCESS_KEY_ID", "AccessKeyId", 128},
			{"AWS_SECRET_ACCESS_KEY", "SecretAccessKey", 256},
			{"AWS_SESSION_TOKEN", "SessionToken", 8192},
		}) {
		text := ""
		if raw, present := value[item.source]; present {
			_, null := raw.(json.Null)
			if !(item.source == "SessionToken" && (null || raw == nil)) {
				is_text: bool
				text, is_text = raw.(json.String)
				if !is_text {
					return {}, .Credential_Export_Invalid
				}
			}
		}
		if len(text) > item.bound {
			return {}, .Credential_Export_Invalid
		}
		for index in 0 ..< len(text) {
			if text[index] < 33 {
				return {}, .Credential_Export_Invalid
			}
		}
		if text != "" {
			variables[item.name] = text
		}
	}
	if "AWS_ACCESS_KEY_ID" not_in variables || "AWS_SECRET_ACCESS_KEY" not_in variables {
		return {}, .Credential_Export_Invalid
	}
	if raw, present := value["Expiration"]; present {
		_, null := raw.(json.Null)
		text, is_text := raw.(json.String)
		if !null && raw != nil && !is_text {
			return {}, .Credential_Export_Invalid
		}
		if text != "" {
			expiry, parsed := instant_parse(text)
			if !parsed {
				return {}, .Credential_Export_Invalid
			}
			if expires_within(expiry, TOTAL_TIME) {
				return {}, .Credentials_Near_Expiry
			}
		}
	}
	variables["AWS_EC2_METADATA_DISABLED"] = "true"
	variables["AWS_REGION"] = region
	identity := caller_identity(runner, executable, region, variables, deadline) or_return
	if identity == nil || !text_is(identity, "Account", account) {
		return {}, .Account_Not_Verified
	}
	return {variables = variables}, .None
}

member_allowed :: proc(object: json.Object, name: string, allowed: []string) -> bool {
	text, found := text_of(object, name)
	if !found {
		return false
	}
	for candidate in allowed {
		if candidate == text {
			return true
		}
	}
	return false
}

// Default Launch: runs the bound native probe for one action and accepts only a
// result made of known members and allowlisted values.
native :: proc(
	runner: ^Runner,
	state: json.Object,
	verb: string,
	environment: Environment,
	deadline: time.Duration,
) -> (
	value: json.Object,
	failure: Failure,
) {
	scope_path := state_file(runner, "scope.json")
	binary, binary_set := text_of(state, "binary")
	run_id, run_set := text_of(state, "run_id")
	scope_digest, scope_set := text_of(state, "scope_sha256")
	if !binary_set || !run_set || !scope_set {
		return nil, .Invalid_Document
	}
	if binary != state_file(runner, PROBE_NAME) {
		return nil, .Run_Binding_Mismatch
	}
	_, scope_bytes := read_private_bytes(scope_path) or_return
	if sha256_hex(scope_bytes) != scope_digest {
		return nil, .Scope_Changed
	}
	if !text_is(state, "binary_sha256", binary_hash(binary) or_return) {
		return nil, .Binary_Changed
	}
	code, data := runner.capture(
		runner,
		{binary, "--scope", scope_path, "--run-id", run_id, "--action", verb, "--scope-sha256", scope_digest},
		environment.variables,
		min(deadline, runner.monotonic(runner) + 90 * time.Second),
		8192,
	) or_return
	value = decode_object(data) or_return
	observed := "read_status" in value || "read_error_code" in value
	if len(value) != len(RESULT_MEMBERS) + (2 if observed else 0) {
		return nil, .Native_Result_Invalid
	}
	for name in RESULT_MEMBERS {
		if name not_in value {
			return nil, .Native_Result_Invalid
		}
	}
	ok, ok_set := boolean_of(value, "ok")
	if observed {
		status, status_set := integer_of(value, "read_status")
		if !status_set || status != 0 && (status < 100 || status > 599) || !member_allowed(value, "read_error_code", READ_ERROR_CODES) {
			return nil, .Native_Result_Invalid
		}
		if text_is(value, "read_error_code", "NoSuchBucket") && (ok || text_is(value, "object", "Absent")) {
			return nil, .Native_Result_Invalid
		}
	}
	if !ok_set || code != 0 && code != 2 || ok != (code == 0) || !integer_is(value, "schema", 1) {
		return nil, .Native_Result_Invalid
	}
	for check in ([]struct {
			name:    string,
			allowed: []string,
		} {
			{"reason", REASONS},
			{"object", OBJECTS},
			{"credential_kind", CREDENTIAL_KINDS},
			{"s3_kind", S3_KINDS},
			{"ses_kind", SES_KINDS},
			{"put_effect", EFFECTS},
			{"delete_effect", EFFECTS},
			{"ses_effect", EFFECTS},
		}) {
		if !member_allowed(value, check.name, check.allowed) {
			return nil, .Native_Result_Invalid
		}
	}
	status, status_set := integer_of(value, "mutation_status")
	if !status_set || status < 0 || status > 599 {
		return nil, .Native_Result_Invalid
	}
	return value, .None
}

// Records the phase durably. An intent starts without the previous result.
save :: proc(runner: ^Runner, state: ^json.Object, phase: string, result: json.Object = nil) -> Failure {
	state["phase"] = phase
	if result != nil {
		state["last_result"] = result
	} else if strings.has_suffix(phase, "_INTENT") {
		delete_key(state, "last_result")
	}
	return atomic(runner.arguments.state_dir, "state.json", state^)
}

// One native action between a durable intent and its verified phase. stopped is
// true when the run must end here with the returned receipt.
action :: proc(
	runner: ^Runner,
	state: ^json.Object,
	verb, phase, success: string,
	environment: Environment,
	deadline: time.Duration,
	qualifies_s3 := false,
) -> (
	stopped_with: json.Object,
	stopped: bool,
	failure: Failure,
) {
	directory := runner.arguments.state_dir
	save(runner, state, phase) or_return
	result, launch_failure := runner.launch(runner, state^, verb, environment, deadline)
	if launch_failure != .None {
		stopped_with = receipt(directory, state^, "NATIVE_OUTCOME_UNKNOWN") or_return
		return stopped_with, true, .None
	}
	state[strings.concatenate({verb, "_result"})] = result
	expected := ""
	switch verb {
	case "put":
		expected = "Owned"
	case "delete":
		expected = "Absent"
	}
	if !is_true(result, "ok") || expected != "" && !text_is(result, "object", expected) {
		save(runner, state, phase, result) or_return
		stopped_with = receipt(directory, state^, "NATIVE_ACTION_NOT_VERIFIED") or_return
		return stopped_with, true, .None
	}
	if qualifies_s3 {
		state["s3_qualified"] = true
	}
	save(runner, state, success, result) or_return
	return nil, false, .None
}

s3_complete :: proc(runner: ^Runner, state: ^json.Object) -> Failure {
	state["s3_qualified"] = true
	return save(runner, state, "S3_COMPLETE" if is_true(state^, "allow_ses") else "COMPLETE")
}

phase_permitted :: proc(command, phase: string) -> bool {
	switch command {
	case "run":
		return phase == "PREPARED"
	case "reconcile":
		return phase == "PUT_INTENT" || phase == "PUT_VERIFIED" || phase == "DELETE_INTENT"
	case "cleanup":
		return phase == "PUT_VERIFIED"
	case "send":
		return phase == "S3_COMPLETE"
	}
	return false
}

// run, reconcile, cleanup and send: the commands that may reach AWS. Each one
// continues only from the phases it is permitted to and never repeats a mutation
// whose outcome is unknown.
run :: proc(runner: ^Runner) -> (result: json.Object, failure: Failure) {
	arguments := runner.arguments
	if !arguments.live {
		return nil, .Live_Opt_In_Required
	}
	lock := lock_acquire(arguments.state_dir) or_return
	defer lock_release(lock)
	scope, scope_bytes := read_private_bytes(state_file(runner, "scope.json")) or_return
	scope_valid(scope) or_return
	state := read_private(state_file(runner, "state.json")) or_return
	binary, binary_set := text_of(state, "binary")
	run_id, run_set := text_of(state, "run_id")
	phase, phase_set := text_of(state, "phase")
	allow_ses, ses_set := boolean_of(state, "allow_ses")
	if !binary_set || !run_set || !phase_set || !ses_set || "scope_sha256" not_in state || "binary_sha256" not_in state {
		return nil, .Invalid_Document
	}
	if binary != state_file(runner, PROBE_NAME) {
		return nil, .Run_Binding_Mismatch
	}
	if !text_is(state, "scope_sha256", sha256_hex(scope_bytes)) ||
	   !text_is(state, "binary_sha256", binary_hash(binary) or_return) ||
	   !hex_valid(run_id, 32) ||
	   allow_ses != is_true(scope, "allow_ses") {
		return nil, .Run_Binding_Mismatch
	}
	if !phase_permitted(arguments.command, phase) {
		return nil, .Run_Requires_Review
	}
	deadline := runner.monotonic(runner) + TOTAL_TIME
	credential_scope := bound_credential_scope(runner, state, scope) or_return
	environment := runner.credentials(runner, credential_scope, deadline) or_return
	if text_is(credential_scope, "credential_source", "environment") {
		if !environment.verified {
			return nil, .Role_Attestation_Required
		}
		safe := safe_attestation(environment.attestation) or_return
		role, _ := text_of(credential_scope, "expected_role_arn")
		if !text_is(safe, "expected_role_arn_sha256", sha256_hex(transmute([]u8)role)) {
			return nil, .Role_Attestation_Invalid
		}
		state["credential_attestation"] = safe
		atomic(arguments.state_dir, "state.json", state) or_return
	}
	if arguments.command == "reconcile" {
		value := runner.launch(runner, state, "reconcile", environment, deadline) or_return
		state["reconcile_result"] = value
		atomic(arguments.state_dir, "state.json", state) or_return
		if is_true(value, "ok") && text_is(value, "object", "Owned") && phase != "DELETE_INTENT" {
			save(runner, &state, "PUT_VERIFIED", value) or_return
		} else if is_true(value, "ok") && text_is(value, "object", "Absent") && phase == "DELETE_INTENT" {
			s3_complete(runner, &state) or_return
		}
		return receipt(arguments.state_dir, state, "READ_ONLY_RECONCILIATION")
	}
	if arguments.command == "run" {
		if stopped_with, stopped := action(runner, &state, "read", "READ_INTENT", "READ_CHECKED", environment, deadline) or_return; stopped {
			return stopped_with, .None
		}
		if !is_true(scope, "allow_write") {
			save(runner, &state, "READ_ONLY_CHECKED") or_return
			return receipt(arguments.state_dir, state)
		}
		if stopped_with, stopped := action(runner, &state, "put", "PUT_INTENT", "PUT_VERIFIED", environment, deadline) or_return; stopped {
			return stopped_with, .None
		}
	}
	if arguments.command != "send" {
		final := "S3_COMPLETE" if allow_ses else "COMPLETE"
		if stopped_with, stopped := action(runner, &state, "delete", "DELETE_INTENT", final, environment, deadline, qualifies_s3 = true) or_return; stopped {
			return stopped_with, .None
		}
	}
	if allow_ses && arguments.command != "cleanup" {
		if stopped_with, stopped := action(runner, &state, "ses", "SES_INTENT", "COMPLETE", environment, deadline) or_return; stopped {
			return stopped_with, .None
		}
	}
	return receipt(arguments.state_dir, state)
}

// status: the receipt of the current state, without starting anything.
status :: proc(runner: ^Runner) -> (result: json.Object, failure: Failure) {
	lock := lock_acquire(runner.arguments.state_dir) or_return
	defer lock_release(lock)
	state := read_private(state_file(runner, "state.json")) or_return
	return receipt(runner.arguments.state_dir, state)
}

execute :: proc(runner: ^Runner) -> (result: json.Object, failure: Failure) {
	switch runner.arguments.command {
	case "plan":
		if runner.arguments.resource_plan == "" || runner.arguments.binary == "" {
			return nil, .Plan_Input_Required
		}
		return plan(runner)
	case "status":
		return status(runner)
	}
	return run(runner)
}
