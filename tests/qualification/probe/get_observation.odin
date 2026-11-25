package main

import aws "shared:aws"
import "core:encoding/xml"
import "core:mem"
import "core:strings"

// Receipt values are enum names, never provider-controlled strings.
S3_Observed_Code :: enum {
	None,
	Unknown,
	NoSuchKey,
	NoSuchBucket,
	AccessDenied,
	InvalidAccessKeyId,
	SignatureDoesNotMatch,
	ExpiredToken,
	InvalidToken,
	RequestTimeTooSkewed,
	AuthorizationHeaderMalformed,
	SlowDown,
	RequestTimeout,
	PermanentRedirect,
	TemporaryRedirect,
	RequestExpired,
}
S3_Read_Observation :: struct {
	execute:       aws.S3_Get_Execute,
	data:          rawptr,
	calls, status: int,
	code:          S3_Observed_Code,
}

silent_xml_error :: proc(_: xml.Pos, _: string, _: ..any) {}

observed_error_code :: proc(body: []u8) -> S3_Observed_Code {
	if len(body) == 0 || len(body) > 1024 {
		return .Unknown
	}

	text := strings.trim_space(string(body))

	if strings.has_prefix(text, "<?xml ") {
		end := strings.index(text, "?>")

		if end < 0 || end > 128 {
			return .Unknown
		}

		text = strings.trim_space(text[end + 2:])
	}

	if !strings.has_prefix(text, "<Error") ||
	   !strings.has_suffix(text, "</Error>") ||
	   strings.count(text, "<Error") != 1 ||
	   strings.contains(text, "<!") ||
	   strings.contains(text, "&") {
		// The parser decodes references and unwraps CDATA; a code spelled through either is not strict.
		return .Unknown
	}

	document, error := xml.parse(text, {flags = {.Error_on_Unsupported}}, error_handler = silent_xml_error)
	defer xml.destroy(document)

	if error != .None || document == nil || document.element_count == 0 || document.elements[0].ident != "Error" {
		return .Unknown
	}

	code, found := xml.find_child_by_ident(document, 0, "Code")
	_, duplicate := xml.find_child_by_ident(document, 0, "Code", 1)

	if !found || duplicate {
		return .Unknown
	}

	node := document.elements[code]

	if len(node.attribs) != 0 || len(node.value) != 1 {
		return .Unknown
	}

	value, is_text := node.value[0].(string)

	if !is_text {
		return .Unknown
	}

	switch strings.trim_space(value) {
	case "NoSuchKey":
		return .NoSuchKey
	case "NoSuchBucket":
		return .NoSuchBucket
	case "AccessDenied":
		return .AccessDenied
	case "InvalidAccessKeyId":
		return .InvalidAccessKeyId
	case "SignatureDoesNotMatch":
		return .SignatureDoesNotMatch
	case "ExpiredToken":
		return .ExpiredToken
	case "InvalidToken":
		return .InvalidToken
	case "RequestTimeTooSkewed":
		return .RequestTimeTooSkewed
	case "AuthorizationHeaderMalformed":
		return .AuthorizationHeaderMalformed
	case "SlowDown":
		return .SlowDown
	case "RequestTimeout":
		return .RequestTimeout
	case "PermanentRedirect":
		return .PermanentRedirect
	case "TemporaryRedirect":
		return .TemporaryRedirect
	case "RequestExpired":
		return .RequestExpired
	}

	return .Unknown
}

// The live branch calls the production executor once, with the original arguments.
// Observation precedes the public SDK's error-body disposal; no body is retained.
observed_get :: proc(
	url: string,
	headers: []string,
	timeout_ms: i64,
	bytes_max: int,
	allocator: mem.Allocator,
) -> (
	[]u8,
	int,
	aws.S3_Get_Error,
) {
	capture := cast(^S3_Read_Observation)context.user_ptr
	if capture.calls != 0 {
		return nil, 0, .Invalid_Input
	}
	capture.calls = 1
	previous := context.user_ptr
	context.user_ptr = capture.data
	defer context.user_ptr = previous
	body: []u8
	status: int
	error: aws.S3_Get_Error
	if capture.execute == nil {
		body, status, error = aws.s3_get_native(url, headers, timeout_ms, bytes_max, allocator)
	} else {
		body, status, error = capture.execute(url, headers, timeout_ms, bytes_max, allocator)
	}
	capture.status = status
	if status != 0 && (status < 200 || status > 299) {
		capture.code = observed_error_code(body)
	}
	return body, status, error
}
