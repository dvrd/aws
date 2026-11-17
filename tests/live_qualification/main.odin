package main

import aws "shared:aws"
import surf "shared:surf"
import "core:crypto/sha2"
import "core:encoding/hex"
import "core:encoding/json"
import "core:fmt"
import "core:os"
import "core:strconv"
import "core:strings"
import "core:time"

Scope :: struct {
 bucket, region, prefix, profile, expected_account, ses_sender: string,
 allow_write, allow_ses: bool,
}
Action :: enum {Read, Put, Reconcile, Delete, SES}
Object :: enum {Unverified, Absent, Owned, Foreign}
Reason :: enum {
 None, Invalid_Arguments, Invalid_Scope, Credential_Error, Read_Failed,
 Foreign_Object, Put_Disabled, Put_Failed, Delete_Failed, Response_Mismatch,
 SES_Disabled, SES_Failed,
}
Result :: struct {
 schema: int,
 ok: bool,
 reason: Reason,
 object: Object,
 credential_kind: aws.Credential_Error_Kind,
 s3_kind: aws.S3_Get_Error,
 ses_kind: aws.SES_Error,
 put_effect, delete_effect, ses_effect: surf.HTTP_Write_Effect,
 mutation_status, read_status: int,
 read_error_code: S3_Observed_Code,
}

run_id_valid :: proc(value: string) -> bool {
 if len(value) != 32 {return false}
 for c in value {if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {return false}}
 return true
}

scope_decode :: proc(data: []u8) -> (Scope, json.Value, bool) {
 tokens := json.make_tokenizer(string(data), .JSON, true)
 previous: json.Token_Kind
 depth := 0
 for {
  token, error := json.get_token(&tokens)
  if token.kind == .EOF && (error == .None || error == .EOF) {break}
  if error != .None {return {}, {}, false}
  #partial switch token.kind {
  case .Open_Brace: depth += 1; if depth > 1 {return {}, {}, false}
  case .Close_Brace: if previous == .Comma {return {}, {}, false}; depth -= 1
  case .Open_Bracket, .Float, .NaN, .Infinity: return {}, {}, false
  case .Integer: if _, valid := strconv.parse_i64(token.text); !valid {return {}, {}, false}
  }
  previous = token.kind
 }
 if !json.is_valid(data, .JSON, true) {return {}, {}, false}
 parser := json.make_parser(data, .JSON, true)
 value, error := json.parse_value(&parser)
 if error != .None {json.destroy_value(value); return {}, {}, false}
 success := false
 defer if !success {json.destroy_value(value)}
 object, object_ok := value.(json.Object)
 if !object_ok || len(object) != 9 || parser.curr_token.kind != .EOF {return {}, {}, false}
 schema, schema_ok := object["schema"].(json.Integer)
 scope: Scope
 for pair in ([]struct {name: string, destination: ^string}{
  {"bucket", &scope.bucket}, {"region", &scope.region}, {"prefix", &scope.prefix},
  {"profile", &scope.profile}, {"expected_account", &scope.expected_account},
  {"ses_sender", &scope.ses_sender}}) {
  text, valid := object[pair.name].(json.String)
  if !valid {return {}, {}, false}
  pair.destination^ = text
 }
 allow_write, write_ok := object["allow_write"].(json.Boolean)
 allow_ses, ses_ok := object["allow_ses"].(json.Boolean)
 scope.allow_write, scope.allow_ses = allow_write, allow_ses
 if !schema_ok || schema != 1 || !write_ok || !ses_ok || !scope_valid(scope) {return {}, {}, false}
 success = true
 return scope, value, true
}

scope_valid :: proc(scope: Scope) -> bool {
 if !strings.has_prefix(scope.bucket, "webtools-qualification-") ||
    aws.s3_config_error({bucket = scope.bucket, region = scope.region}) != "" ||
    len(scope.profile) == 0 || len(scope.profile) > 64 || len(scope.expected_account) != 12 ||
    len(scope.prefix) != len("qualification/")+32+1 ||
    !strings.has_prefix(scope.prefix, "qualification/") ||
    !strings.has_suffix(scope.prefix, "/") {return false}
 if !run_id_valid(scope.prefix[len("qualification/"):len(scope.prefix)-1]) {return false}
 for c in scope.expected_account {if c < '0' || c > '9' {return false}}
 for c in scope.profile {
  if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' ||
   c == '-' || c == '_') {return false}
 }
 if scope.allow_ses {return aws.ses_config_valid({region = scope.region,
  sender = scope.ses_sender, recipient = "success@simulator.amazonses.com"})}
 return scope.ses_sender == ""
}

credential_clock :: proc(_: rawptr) -> time.Time {return time.now()}

probe_live :: proc(scope: Scope, action: Action, run_id: string) -> Result {
 cache: aws.Credential_Cache
 initialized := aws.credential_cache_init(&cache, surf.buffered_http_execute,
  credential_clock, modes = {.Environment})
 if initialized.kind != .None {
  return {reason = .Credential_Error, credential_kind = initialized.kind}
 }
 defer {
  destroyed := aws.credential_cache_destroy(&cache)
  assert(destroyed.kind == .None)
 }
 lease, error := aws.credential_lease(&cache)
 if error.kind != .None {return {reason = .Credential_Error, credential_kind = error.kind}}
 defer aws.credential_lease_release(&cache, &lease)
 credentials := aws.AWS_Credentials{lease.access_key, lease.secret_key, lease.session_token}
 return probe(scope, action, run_id, credentials, {})
}

main_run :: proc() -> Result {
 if len(os.args) != 9 || os.args[1] != "--scope" || os.args[3] != "--run-id" ||
    os.args[5] != "--action" || os.args[7] != "--scope-sha256" || !run_id_valid(os.args[4]) {
  return {reason = .Invalid_Arguments}
 }
 action: Action
 switch os.args[6] {
 case "read": action = .Read
 case "put": action = .Put
 case "reconcile": action = .Reconcile
 case "delete": action = .Delete
 case "ses": action = .SES
 case: return {reason = .Invalid_Arguments}
 }
 bytes, read_error := aws.read_limited(os.args[2], 16384)
 if read_error.kind != .None {return {reason = .Invalid_Scope}}
 defer delete(bytes)
 hash: sha2.Context_256
 sha2.init_256(&hash); sha2.update(&hash, bytes)
 sum: [32]u8; sha2.final(&hash, sum[:])
 encoded, encode_error := hex.encode(sum[:])
 if encode_error != nil {return {reason = .Invalid_Scope}}
 defer delete(encoded)
 if string(encoded) != os.args[8] {return {reason = .Invalid_Scope}}
 scope, document, valid := scope_decode(bytes)
 if !valid {return {reason = .Invalid_Scope}}
 defer json.destroy_value(document)
 return probe_live(scope, action, os.args[4])
}

main :: proc() {
 result := main_run(); result.schema = 1
 data, error := json.marshal(result, {use_enum_names = true})
 if error != nil {fmt.println(`{"schema":1,"ok":false}`); os.exit(2)}
 fmt.println(string(data)); delete(data)
 if !result.ok {os.exit(2)}
}
