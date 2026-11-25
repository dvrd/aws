package aws

import "core:crypto/hash"
import "core:encoding/json"
import "core:fmt"
import "core:strings"
import "core:time"

SES_Config :: struct {
	region, sender, recipient: string,
}
SES_Error :: enum {
	None,
	Invalid_Config,
	Invalid_Message,
	Allocation_Failed,
	Unavailable,
	Rejected,
	Invalid_Response,
}
@(private)
SES_Text :: struct {
	Data, Charset: string,
}
@(private)
SES_Message :: struct {
	FromEmailAddress: string,
	Destination:      struct {
		ToAddresses: [1]string,
	},
	Content:          struct {
		Simple: struct {
			Subject: SES_Text,
			Body:    struct {
				Text: SES_Text,
			},
		},
	},
}

ses_config_valid :: proc(config: SES_Config) -> bool {
	if len(config.region) == 0 || len(config.region) > 32 {
		return false
	}

	for ch in config.region {
		if !region_char_valid(ch) {
			return false
		}
	}

	for address in ([]string{config.sender, config.recipient}) {
		if len(address) < 3 ||
		   len(address) > 254 ||
		   !strings.contains(address, "@") ||
		   strings.contains_any(address, "\r\n\x00 <>\t") {
			return false
		}
	}

	return true
}

// This request owns no persistent data. Caller bounds its temporary allocator.
// SES has no idempotency token: ambiguous transport failures can duplicate alerts.
// Blocks the calling thread for up to 15 seconds. now is the signing time; the
// zero time means time.now(). Rejected is any answer from SES other than 200,
// throttles and 5xx included: SES acknowledged the request and it is not replayed
// here. A 200 whose body is lost or unreadable is Invalid_Response, for the same
// reason. Unavailable means no answer arrived, so only Unavailable is safe to retry.
ses_send :: proc(
	config: SES_Config,
	credentials: AWS_Credentials,
	subject, text: string,
	now: time.Time,
	http_execute: HTTP_Execute = http_execute_default,
) -> SES_Error {
	if http_execute == nil || !ses_config_valid(config) || !aws_credentials_valid(credentials) {
		return .Invalid_Config
	}
	if subject == "" ||
	   len(subject) > 200 ||
	   len(text) == 0 ||
	   len(text) > 8192 ||
	   strings.contains_any(subject, "\r\n\x00") {
		return .Invalid_Message
	}
	message: SES_Message
	message.FromEmailAddress = config.sender
	message.Destination.ToAddresses = {config.recipient}
	message.Content.Simple.Subject = {subject, "UTF-8"}
	message.Content.Simple.Body.Text = {text, "UTF-8"}
	payload, error := json.marshal(message, allocator = context.temp_allocator)
	if error != nil {
		return .Allocation_Failed
	}
	host := fmt.tprintf("email.%s.amazonaws.com", config.region)
	path := "/v2/email/outbound-emails"
	headers := ses_headers(config.region, credentials, host, s3_timestamp(signing_time(now)), payload)
	if headers == nil {
		return .Allocation_Failed
	}
	data, result := http_execute(
		{method = "POST", url = fmt.tprintf("https://%s%s", host, path), body = payload, headers = headers, timeout_ms = 15000},
	)
	// A status means SES answered: only its absence makes a retry safe.
	if result.status == 0 {
		return .Unavailable
	}
	if result.status != 200 {
		return .Rejected
	}
	if !result.ok {
		return .Invalid_Response
	}
	response: struct {
		MessageId: string,
	}
	if json.unmarshal(data, &response, allocator = context.temp_allocator) != nil || response.MessageId == "" {
		return .Invalid_Response
	}
	return .None
}

// The signed header lines of one SES send, in the order they are sent:
// Content-Type, x-amz-date, an optional x-amz-security-token and Authorization.
// The lines share one buffer in context.temp_allocator; nil when it cannot be had.
ses_headers :: proc(region: string, credentials: AWS_Credentials, host, stamp: string, payload: []u8) -> []string {
	token := credentials.session_token
	digest: [32]u8
	hash.hash(.SHA256, payload, digest[:])
	payload_hash: [64]u8
	sigv4_hex(digest[:], payload_hash[:])
	signed_headers := [4]Sigv4_Header {
		{"content-type", "application/json"},
		{"host", host},
		{"x-amz-date", stamp},
		{"x-amz-security-token", token},
	}
	signed := "content-type;host;x-amz-date;x-amz-security-token"
	count := 4
	if token == "" {
		signed = signed[:len("content-type;host;x-amz-date")]
		count = 3
	}
	signature: [64]u8
	sigv4_sign(
		credentials.secret_key,
		{
			service = "ses",
			region = region,
			method = "POST",
			path = "/v2/email/outbound-emails",
			headers = signed_headers[:count],
			payload_hash = string(payload_hash[:]),
			stamp = stamp,
		},
		&signature,
	)

	size := len("x-amz-date: ") + len(stamp) + sigv4_authorization_size(credentials.access_key, region, "ses", signed)
	if token != "" {
		size += len("x-amz-security-token: ") + len(token)
	}
	builder, builder_error := strings.builder_make_len_cap(0, size, context.temp_allocator)
	if builder_error != nil {
		return nil
	}
	headers, headers_error := make([]string, count, context.temp_allocator)
	if headers_error != nil {
		return nil
	}
	// Lines are cut from the buffer once it is complete, so growth cannot move them.
	ends: [4]int
	strings.write_string(&builder, "x-amz-date: ")
	strings.write_string(&builder, stamp)
	ends[1] = strings.builder_len(builder)
	if token != "" {
		strings.write_string(&builder, "x-amz-security-token: ")
		strings.write_string(&builder, token)
		ends[2] = strings.builder_len(builder)
	}
	sigv4_authorization_write(&builder, credentials.access_key, stamp, region, "ses", signed, &signature)
	ends[count - 1] = strings.builder_len(builder)

	text := strings.to_string(builder)
	headers[0] = "Content-Type: application/json"
	for i in 1 ..< count {
		headers[i] = text[ends[i - 1] if i > 1 else 0:ends[i]]
	}

	return headers
}
