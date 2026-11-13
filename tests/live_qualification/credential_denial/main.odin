package main

import aws "shared:aws"
import "core:encoding/json"
import "core:fmt"
import "core:mem"
import "core:os"
import "core:strings"
import "core:time"

Reason :: enum {None, Opt_In_Required, Invalid_Scope, Transport_Failed, Unexpected_Response}
Result :: struct {
 schema: int,
 http_denied: bool,
 reason: Reason,
 http_status, native_executor_calls: int,
 s3_kind: aws.S3_Get_Error,
}
Capture :: struct {status, calls: int}

hex_id :: proc(value: string) -> bool {
 if len(value) != 32 {return false}
 for c in value {if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {return false}}
 return true
}
scope_valid :: proc(bucket, region, key: string) -> bool {
 if !strings.has_prefix(bucket, "webtools-qualification-") ||
  aws.s3_config_error({bucket = bucket, region = region}) != "" ||
  len(region) > 32 || len(region) == 0 {return false}
 for c in region {if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {return false}}
 parts := strings.split(key, "/"); defer delete(parts)
 if len(parts) != 3 || parts[0] != "qualification" || !hex_id(parts[1]) ||
  len(parts[2]) != 36 || !strings.has_suffix(parts[2], ".txt") {return false}
 return hex_id(parts[2][:32])
}

// This wrapper observes only status/count. It delegates to the actual SDK native
// executor, preserving verified TLS, no redirects and no replay. No XML is kept.
capture_get :: proc(url: string, headers: []string, timeout_ms: i64, bytes_max: int,
 allocator: mem.Allocator) -> ([]u8, int, aws.S3_Get_Error) {
 capture := cast(^Capture)context.user_ptr
 assert(capture != nil)
 if capture.calls != 0 {return nil, 0, .Invalid_Input}
 capture.calls += 1
 body, status, error := aws.s3_get_native(
  url, headers, min(timeout_ms, 10000), bytes_max, allocator)
 capture.status = status
 return body, status, error
}
result_of :: proc(capture: Capture, error: aws.S3_Get_Error) -> Result {
 result := Result{schema = 1, http_status = capture.status,
  native_executor_calls = capture.calls, s3_kind = error}
 if capture.status == 403 && capture.calls == 1 && error == .Rejected {
  result.http_denied = true
 } else {result.reason = .Transport_Failed if capture.status == 0 else .Unexpected_Response}
 return result
}
run :: proc(args: []string) -> Result {
 if len(args) != 8 || args[1] != "--bucket" || args[3] != "--region" ||
  args[5] != "--key" || args[7] != "--live" {return {schema = 1, reason = .Opt_In_Required}}
 if !scope_valid(args[2], args[4], args[6]) {return {schema = 1, reason = .Invalid_Scope}}
 capture: Capture
 previous := context.user_ptr; context.user_ptr = &capture
 defer context.user_ptr = previous
 // Public synthetic values only. Ambient environment/profile keys are never read.
 body, error := aws.s3_get_at({bucket = args[2], region = args[4]},
  {access_key = "invalid-synthetic-access", secret_key = "public-fixture-not-a-secret"},
  args[6], 1024, time.now(), execute = capture_get)
 defer delete(body)
 return result_of(capture, error)
}
main :: proc() {
 result := run(os.args)
 data, error := json.marshal(result, {use_enum_names = true})
 if error != nil {os.exit(2)}
 fmt.println(string(data)); delete(data)
 if !result.http_denied {os.exit(2)}
}
