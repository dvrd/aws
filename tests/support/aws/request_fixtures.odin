package aws

import "core:strings"
s3_request_signature :: proc(authorization: string) -> string {
	marker :: "Signature="
	at := strings.index(authorization, marker)
	if at < 0 {
		return ""
	}
	return authorization[at + len(marker):]
}

// Test support shared by every suite compiled into package aws: request
// fixtures and an executor that records what a blocking call sent.
s3_request_header :: proc(request: S3_Request, name: string) -> string {
	for header in request.headers {
		if header.name == name {
			return header.value
		}
	}
	return ""
}
