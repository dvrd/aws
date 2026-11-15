package main

import aws "shared:aws"
import surf "shared:surf"
import "core:crypto/sha2"
import "core:fmt"
import "core:os"
import "core:strings"
import "core:time"

PAYLOAD_PREFIX :: "odin-aws-qualification:"
Probe_Executors :: struct {
 write: aws.HTTP_Execute,
 get: aws.S3_Get_Execute,
}

SES_Capture :: struct {
 region: string,
 execute: aws.HTTP_Execute,
 data: rawptr,
 result: surf.Buffered_HTTP_Result,
 called: bool,
}

ses_capture :: proc(method, url: string, body: []u8, headers: []string, ca_file: string,
 allow_http: bool, timeout_ms: i64, upload_file: ^os.File, upload_size: i64) ->
 ([]u8, surf.Buffered_HTTP_Result) {
 capture := cast(^SES_Capture)context.user_ptr
 endpoint := fmt.aprintf("https://email.%s.amazonaws.com/v2/email/outbound-emails", capture.region)
 defer delete(endpoint)
 if capture.called || method != "POST" || url != endpoint || ca_file != "" ||
    allow_http || upload_file != nil || upload_size != 0 || len(body) > 4096 {
  return nil, {error = {kind = .Invalid_Config, write_effect = .Not_Sent}}
 }
 capture.called = true
 data: []u8
 if capture.execute == nil {
  data, capture.result = surf.buffered_http_execute(method, url, body, headers, "", false,
   min(timeout_ms, 15000), nil, 0)
 } else {
  previous := context.user_ptr; context.user_ptr = capture.data
  defer context.user_ptr = previous
  data, capture.result = capture.execute(method, url, body, headers, "", false,
   min(timeout_ms, 15000), nil, 0)
 }
 return data, capture.result
}

ses_probe :: proc(scope: Scope, credentials: aws.AWS_Credentials, run_id: string,
 executors: Probe_Executors) -> Result {
 result := result_start()
 if !scope.allow_ses {result.reason = .SES_Disabled; return result}
 capture := SES_Capture{region = scope.region, execute = executors.write, data = context.user_ptr}
 previous := context.user_ptr; context.user_ptr = &capture
 defer context.user_ptr = previous
 text := strings.concatenate({"Synthetic transport qualification: ", run_id})
 defer delete(text)
 result.ses_kind = aws.ses_send({region = scope.region, sender = scope.ses_sender,
  recipient = "success@simulator.amazonses.com"}, credentials,
  "Webtools native qualification", text,
  time.now(), ses_capture)
 if capture.called {result.ses_effect = effect_of(capture.result)}
 result.mutation_status = capture.result.status
 result.ok = result.ses_kind == .None
 if !result.ok {result.reason = .SES_Failed}
 return result
}

result_start :: proc() -> Result {
 return {put_effect = .Not_Sent, delete_effect = .Not_Sent, ses_effect = .Not_Sent}
}

object_read :: proc(config: aws.S3_Config, credentials: aws.AWS_Credentials,
 key, expected: string, executors: Probe_Executors) -> Result {
 result := result_start()
 body: []u8
 error: aws.S3_Get_Error
 capture := S3_Read_Observation{execute = executors.get, data = context.user_ptr}
 previous := context.user_ptr; context.user_ptr = &capture
 defer context.user_ptr = previous
 body, error = aws.s3_get(config, credentials, key, 1024, execute = observed_get)
 defer delete(body)
 result.s3_kind = error
 result.read_status, result.read_error_code = capture.status, capture.code
 // A missing bucket is not evidence that the selected owned object is absent.
 if capture.code == .NoSuchBucket {result.reason = .Read_Failed; return result}
 if error == .Not_Found {result.ok = true; result.object = .Absent; return result}
 if error != .None {result.reason = .Read_Failed; return result}
 actual, wanted: [32]u8
 hash: sha2.Context_256
 sha2.init_256(&hash); sha2.update(&hash, body); sha2.final(&hash, actual[:])
 sha2.init_256(&hash); sha2.update(&hash, transmute([]u8)expected); sha2.final(&hash, wanted[:])
 if actual == wanted && string(body) == expected {result.ok = true; result.object = .Owned}
 else {result.reason = .Foreign_Object; result.object = .Foreign}
 return result
}

effect_of :: proc(value: aws.S3_Result) -> surf.HTTP_Write_Effect {
 if value.status != 0 {return .Response_Received}
 return value.error.write_effect
}

object_put :: proc(scope: Scope, config: aws.S3_Config, credentials: aws.AWS_Credentials,
 key, expected: string, executors: Probe_Executors) -> Result {
 before := object_read(config, credentials, key, expected, executors)
 if !before.ok || before.object == .Owned {return before}
 if !scope.allow_write {before.ok = false; before.reason = .Put_Disabled; return before}
 outcome: aws.S3_Result
 if executors.write == nil {
  outcome = aws.s3_put(config, credentials, key, transmute([]u8)expected, "text/plain")
 } else {
  outcome = aws.s3_put(config, credentials, key, transmute([]u8)expected,
   "text/plain", executors.write)
 }
 effect := effect_of(outcome)
 if !outcome.ok || outcome.status < 200 || outcome.status > 299 {
  return {reason = .Put_Failed, put_effect = effect, mutation_status = outcome.status,
   delete_effect = .Not_Sent, ses_effect = .Not_Sent}
 }
 after := object_read(config, credentials, key, expected, executors)
 after.put_effect = .Response_Received; after.mutation_status = outcome.status
 if after.ok && after.object != .Owned {after.ok = false; after.reason = .Response_Mismatch}
 return after
}

object_delete :: proc(scope: Scope, config: aws.S3_Config, credentials: aws.AWS_Credentials,
 key, expected: string, executors: Probe_Executors) -> Result {
 before := object_read(config, credentials, key, expected, executors)
 if !before.ok || before.object == .Absent {return before}
 if !scope.allow_write {before.ok = false; before.reason = .Put_Disabled; return before}
 outcome: aws.S3_Result
 if executors.write == nil {outcome = aws.s3_delete(config, credentials, key)}
 else {outcome = aws.s3_delete(config, credentials, key, executors.write)}
 effect := effect_of(outcome)
 if !outcome.ok || outcome.status < 200 || outcome.status > 299 {
  return {reason = .Delete_Failed, delete_effect = effect, mutation_status = outcome.status,
   put_effect = .Not_Sent, ses_effect = .Not_Sent}
 }
 after := object_read(config, credentials, key, expected, executors)
 after.delete_effect = .Response_Received; after.mutation_status = outcome.status
 if after.ok && after.object != .Absent {after.ok = false; after.reason = .Response_Mismatch}
 return after
}

probe :: proc(scope: Scope, action: Action, run_id: string,
 credentials: aws.AWS_Credentials, executors: Probe_Executors) -> Result {
 if !scope_valid(scope) || !run_id_valid(run_id) {return {reason = .Invalid_Scope}}
 if action == .SES {return ses_probe(scope, credentials, run_id, executors)}
 config := aws.S3_Config{bucket = scope.bucket, region = scope.region}
 key := fmt.aprintf("%s%s.txt", scope.prefix, run_id)
 defer delete(key)
 expected := strings.concatenate({PAYLOAD_PREFIX, run_id})
 defer delete(expected)
 if action == .Put {return object_put(scope, config, credentials, key, expected, executors)}
 if action == .Delete {return object_delete(scope, config, credentials, key, expected, executors)}
 return object_read(config, credentials, key, expected, executors)
}
