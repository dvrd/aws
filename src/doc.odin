/*
Package aws signs and sends AWS requests for S3 and SES, and resolves the
credentials they need. Import it as shared:aws.

Three ways in

	script or one-shot tool   aws_credentials, then s3_put, s3_get, s3_delete,
	                          s3_put_file, s3_download_url or ses_send
	server                    a Credential_Cache: credential_cache_init once,
	                          a Credential_Refresher (credential_refresher_start)
	                          that calls credential_refresh from its own thread,
	                          and credential_lease_cached with
	                          credential_lease_release around each signing
	own transport (async)     s3_put_request, s3_delete_request, s3_get_request
	                          and s3_head_request sign without any I/O and return
	                          an S3_Request for a client the caller owns

Credentials

	credential_lease_cached   request handler: never blocks, never does I/O
	credential_refresher_*    startup and shutdown: one thread runs credential_refresh
	credential_refresh        maintenance only: blocks for the provider's calls
	credential_lease          startup or a worker: blocks when a refresh is needed
	aws_credentials           scripts only

Sources: environment, shared credentials file (profile), ECS relative URI and
EC2 instance metadata (IMDSv2; AWS_EC2_METADATA_DISABLED=true turns it off).
Web identity, SSO, credential_process, assumed roles and the ECS full URI are
refused with an Unsupported Credential_Error.

Blocking calls

	call              longest wait                           on an event loop
	s3_put            15 s plus 1 s per MiB, at most 120 s   s3_put_request
	s3_put_file       hashes the file, then up to 120 s      none: run it on a worker
	s3_delete         15 s                                   s3_delete_request
	s3_get            120 s, body at most 64 MiB             s3_get_request
	ses_send          15 s                                   none
	aws_credentials   three metadata calls of 1500 ms        see Credentials
	credential_refresh  three metadata calls of 1500 ms      a maintenance thread

Allocators and lifetimes

  - aws_credentials returns strings in context.temp_allocator. They are not
    wiped and live until the caller resets the allocator.
  - The builders return an S3_Request whose url and headers borrow
    context.temp_allocator and whose body borrows the caller's bytes. Hand it to
    a transport that copies it before either is released. The signature is
    bound to the signing time: build a new request for a late retry.
  - s3_get's body uses the allocator it is given and belongs to the caller.
  - A Credential_Lease borrows the cache's storage until credential_lease_release.
    The cache keeps one copy of the secret and wipes it when it is replaced and
    no lease holds it.
  - s3_download_url returns a bearer credential: never log or persist it. It
    stops working when the credentials that signed it expire. expires_seconds
    is 1 to 604800 (default 300).

Keys are sent literally ("../" reaches S3 as written). s3_key_strict is a check
a caller can opt into for keys that come from outside input.

Threading

s3_observer_set installs one process-wide observer of object requests (put,
delete, get). Install it before requests start. It runs on the requesting
thread and must not block.

Limits

	CREDENTIAL_REFRESH_MARGIN   5 minutes   credentials closer to expiry than this are replaced
	CREDENTIAL_EXPIRY_SKEW      15 seconds  leases stop being handed out this long before expiry
	CREDENTIAL_STATIC_REFRESH   15 minutes  credentials without an expiry are read again after this
	S3_GET_BYTES_MAX            64 MiB      largest body s3_get accepts
	S3_GET_TIMEOUT_MS           120000      s3_get timeout
*/
package aws
