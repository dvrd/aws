package aws

import network_client "../surf"
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
SES_Text :: struct {
	Data, Charset: string,
}
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
ses_send :: proc(
	config: SES_Config,
	credentials: AWS_Credentials,
	subject, text: string,
	now: time.Time,
	http_execute: HTTP_Execute = network_client.buffered_http_execute,
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
	headers := ses_headers(config.region, credentials, host, s3_timestamp(now), payload)
	data, result := http_execute(
		"POST",
		fmt.tprintf("https://%s%s", host, path),
		payload,
		headers,
		"",
		false,
		15000,
		nil,
		0,
	)
	if result.status != 0 && result.status != 200 {
		return .Rejected
	}
	if !result.ok {
		return .Unavailable
	}
	response: struct {
		MessageId: string,
	}
	if json.unmarshal(data, &response, allocator = context.temp_allocator) != nil || response.MessageId == "" {
		return .Invalid_Response
	}
	return .None
}

ses_headers :: proc(region: string, credentials: AWS_Credentials, host, stamp: string, payload: []u8) -> []string {
	canonical_headers := fmt.tprintf("content-type:application/json\nhost:%s\nx-amz-date:%s\n", host, stamp)
	signed := "content-type;host;x-amz-date"
	headers := make([dynamic]string, 0, 5, context.temp_allocator)
	append(&headers, "Content-Type: application/json", fmt.tprintf("x-amz-date: %s", stamp))

	if credentials.session_token != "" {
		canonical_headers = fmt.tprintf("%sx-amz-security-token:%s\n", canonical_headers, credentials.session_token)
		signed = fmt.tprintf("%s;x-amz-security-token", signed)
		append(&headers, fmt.tprintf("x-amz-security-token: %s", credentials.session_token))
	}

	canonical := fmt.tprintf(
		"POST\n/v2/email/outbound-emails\n\n%s\n%s\n%s",
		canonical_headers,
		signed,
		s3_sha256(payload),
	)
	scope := fmt.tprintf("%s/%s/ses/aws4_request", stamp[:8], region)
	signature := s3_signature(credentials.secret_key, region, stamp, scope, canonical, "ses")
	append(
		&headers,
		fmt.tprintf(
			"Authorization: AWS4-HMAC-SHA256 Credential=%s/%s, SignedHeaders=%s, Signature=%s",
			credentials.access_key,
			scope,
			signed,
			signature,
		),
	)

	return headers[:]
}
