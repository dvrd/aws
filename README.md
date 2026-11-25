# aws

An Odin library that signs and sends AWS requests (S3 and SES) and resolves the credentials they need. Other projects import it as `shared:aws`. It uses SigV4 and the `shared:surf` HTTP client, and also signs requests for a transport the caller owns, such as an async client.

The package documentation is in `src/doc.odin` (`odin doc src`). To build, test or release the library, read `AGENTS.md`.

## Operations

| Operation | Blocking call | Signing-only builder | Notes |
|---|---|---|---|
| PUT | `s3_put` | `s3_put_request` | 15 s plus 1 s per MiB of body, at most 120 s |
| PUT from file | `s3_put_file` | none | hashes the file, then up to 120 s; run it on a worker |
| DELETE | `s3_delete` | `s3_delete_request` | 15 s |
| GET | `s3_get` | `s3_get_request` | body at most 64 MiB, 120 s; the body belongs to the caller |
| HEAD | none | `s3_head_request` | a HEAD answer has no body, so a failure carries no S3 error code |
| Presigned GET | `s3_download_url` | (no I/O) | bearer credential, never log or persist it; 1 to 604800 seconds, default 300 |
| SES send | `ses_send` | none | 15 s; `Rejected` is any answer other than 200 and is never replayed; only `Unavailable` is safe to retry |

A blocking call must not run on an event-loop thread or in a request handler. Build the request with a builder and send it through the server's own transport. A builder does no I/O and returns an `S3_Request` whose `url` and `headers` borrow `context.temp_allocator`; the transport must copy them before they are released, and a late retry needs a new request.

Keys are sent literally. `s3_key_strict` is an opt-in check for keys built from outside input.

## Credentials

| Call | Use |
|---|---|
| `credential_lease_cached` | request handler: never blocks, never does I/O |
| `credential_refresh` | maintenance only: blocks for the provider's calls (`credential_refresher_start` runs it on its own thread) |
| `credential_lease` | startup or a worker: blocks when a refresh is needed |
| `aws_credentials` | scripts only: resolves on every call, strings stay in `context.temp_allocator`, unwiped |

A server creates a `Credential_Cache` once with `credential_cache_init`, starts a `Credential_Refresher`, and wraps each signing in `credential_lease_cached` and `credential_lease_release`. Pass `credential_lease_credentials(lease)` to the signer.

Supported sources: environment variables, the shared credentials file and profile, the ECS relative URI, and EC2 instance metadata (IMDSv2).

Refused with a typed `Unsupported` error: web identity, SSO, `credential_process`, assumed roles and the ECS full URI.

## Non-goals

No multipart upload, no ListObjects or CopyObject, GET bounded at 64 MiB, presigned GET only.
