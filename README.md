# S3 object storage

This AWS package provides S3 object uploads, deletions, and temporary download URLs. The application owns image processing, authorization, and database relationships. No AWS SDK, external command, or relay is needed at runtime.

## Configure AWS

Create a **general-purpose S3 bucket** in your chosen region. Keep Block Public Access enabled and Object Ownership set to Bucket owner enforced. The app does not create buckets or change their policies. Separate buckets are recommended for development and production.

Set `AWS_S3_BUCKET` and `AWS_REGION` in the application environment. Call
`load_s3_config` and check `s3_config_error` before using storage.

`aws_credentials` resolves credentials for each call, with no cache and no expiry:

1. `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, and optional `AWS_SESSION_TOKEN`.
2. A static profile in `~/.aws/credentials`; select it with `AWS_PROFILE` or override the file with `AWS_SHARED_CREDENTIALS_FILE`.
3. An ECS task role through `AWS_CONTAINER_CREDENTIALS_RELATIVE_URI` on `169.254.170.2` only.
4. An EC2 instance role through IMDSv2 on `169.254.169.254` only. Set `AWS_EC2_METADATA_DISABLED=true` outside EC2 to avoid probing metadata when credentials are missing.

`Credential_Cache` is the expiration-aware path. Inject `HTTP_Execute` and a `Credential_Clock`. Enable sources with `Credential_Modes`; the supported set is environment, profile, ECS, and EC2 (`CREDENTIAL_MODES_SUPPORTED`). A snapshot is one immutable key, secret, and token. Environment and profile snapshots do not expire. ECS and EC2 snapshots stay cached only while the clock is strictly before the document `Expiration`. One refresh runs at a time. Further callers wait, at most `CREDENTIAL_WAITERS_MAX`. A cancelled waiter gets `Cancelled` and not another caller's snapshot. Partial configured keys fail closed.

These modes are refused with `Credential_Error_Kind.Unsupported` and are not fetched or executed: web identity (`AWS_WEB_IDENTITY_TOKEN_FILE`), SSO profile keys, `credential_process`, assumed-role profile keys (`role_arn`, `source_profile`, `credential_source`, `external_id`), and `AWS_CONTAINER_CREDENTIALS_FULL_URI`. The cache never requests an arbitrary credential URL. EC2 is probed only when that mode is enabled, no earlier source succeeded, and `AWS_EC2_METADATA_DISABLED` is not exactly `true`.

The uncached call does not return those typed errors: unknown profile keys are ignored, a full URI is not requested, and role documents are fetched again on every call. Locally, temporary credentials exported by an AWS tool can be placed in the process environment. Credentials remain on the server.

Grant the runtime identity only the object actions the application needs:
`s3:GetObject`, `s3:PutObject`, and `s3:DeleteObject`, scoped to
`arn:aws:s3:::YOUR_BUCKET/YOUR_PREFIX/*`. Bucket creation and policy management
belong to an administrative identity. Default S3 encryption needs no additional
permissions; customer-managed KMS keys require separate KMS permissions.

Buckets stay private. Download URLs are bearer credentials: anyone holding one
can use it until expiration. Applications own authorization, image processing,
object naming, database relationships, cleanup, and URL refresh behavior.

## AWS integration API

`load_s3_config`, `s3_config_error`, `aws_credentials`, `credential_cache_init`, `credential_lease`, `credential_lease_release`, `s3_put`, `s3_put_file`, `s3_delete`, and `s3_download_url` are independent of application handlers. The caller owns returned temporary allocations from the uncached resolver. A lease borrows cache-owned snapshot bytes until release. AWS requests use Signature Version 4 with payload hashes, verified HTTPS, no redirects or ambient proxies, bounded replies, and connection/transfer deadlines. `s3_put_file` hashes and uploads a file using fixed-size buffers, with a 120-second transfer limit for backup archives.

`S3_Config.endpoint`, `ca_file`, and `path_style` support isolated HTTPS test peers and compatible endpoints; production configuration uses regional AWS endpoints automatically. Dotted bucket names use path-style URLs to preserve TLS hostname validation.

Signing references: [AWS SigV4 query authentication](https://docs.aws.amazon.com/AmazonS3/latest/developerguide/sigv4-query-string-auth.html), [signed requests](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_sigv-create-signed-request.html).

## Package dependencies and validation

This package is reusable outside Saba. Vendor `aws`, `files`, `surf`, `http`
(including `http/v1`), `ascii`, and `websocket` under one shared collection.
Outbound HTTP is Surf's native buffered client and does not link libcurl. Signing
stays in this package. Facade extraction and async client integration are not
part of this client. No private Mesa helper directories, AWS SDK or application
imports are required.

Profile reads use the shared `files.read_limited` implementation: regular files,
64 KiB maximum, checked before allocation with concurrent-size-change rejection.
Returned credential strings borrow the operation's scratch allocator storage.

`S3` put/file/delete operations and `ses_send` accept an optional final
`http_execute: HTTP_Execute` callback. Existing calls retain their default Surf
execution. Injection permits offline providers while keeping request signing in
AWS. Configuration struct layouts are unchanged; code storing these operations
in an explicitly declared procedure type must account for the added parameter.

Run offline tests and an isolated vendored consumer with a supported compiler:

```sh
odin test shared/aws -thread-count:1 -warnings-as-errors
ODIN_BIN=/path/to/odin python3 shared/aws/tests/check_consumer.py
```

Tests use synthetic profiles and an injected HTTP provider; they do not inspect
real credential files, contact metadata services, send email or write S3 objects.

## Single owner and deterministic signing

AWS is the sole implementation of credential resolution, SigV4, S3 file hashing,
object requests, presigned URLs and SES signing. `shared:saba/s3` is an optional
compatibility adapter that delegates here; AWS has no dependency on Saba or its
server core. Saba core imports no AWS package.

Existing callable signatures are preserved. New `s3_put_at`, `s3_put_file_at`,
`s3_delete_at` and `s3_download_url_at` take an explicit `time.Time`; they never
interpret zero as the current time. The existing `s3_download_url(..., now={})`
retains its zero-means-current-time behavior. Existing file uploads choose their
signing timestamp after hashing; `_at` file uploads use the caller's exact time.
All data and configuration passed to signing remain caller-owned. Results and
generated headers/URLs retain their existing scratch-allocation lifetime. Signing
does not retry. Credential caching exists only on `Credential_Cache`.

`aws_credentials_with_http(execute)` applies the same per-call environment,
64 KiB profile and ECS/IMDSv2 chain with an explicit `HTTP_Execute` provider.
`aws_credentials()` retains its exact zero-argument signature and uses Surf.
The injected provider must preserve the normal bounded response, no-redirect,
trust and timeout contract; metadata requests are explicitly HTTP with a 1500 ms
budget and no upload. Incomplete environment or selected profile credentials,
including a session token without keys, fail closed rather than falling through
to another provider. Profile open failures retain the prior metadata fallback.
Returned strings borrow `context.temp_allocator` and must not outlive its storage.

`credential_cache_init` stores the provider, clock, enabled modes, and allocator.
The clock and provider must not call back into the cache. `credential_lease`
copies a consistent triple into cache memory before the pointer is published, so
a reader cannot observe a new key with an old secret or token. Release clears
the caller's lease. Retired storage is wiped with `mem.zero_explicit` only when
its reader count is zero. `credential_cache_destroy` does that for an unleased
snapshot and returns `.Busy` while a refresh or lease is outstanding. Scratch
env, profile, and JSON copies use `context.temp_allocator` and are wiped before
the resolve returns. Static snapshots are not reread until the cache is replaced.
ECS and EC2 documents without a full RFC3339 `Expiration` are not cached.

The executor is Surf's native buffered client. It does not link libcurl. Signing,
trust, timeouts, redirects and replay policy are unchanged: metadata and object
calls are single attempts, and an unknown write is not replayed. This does not
add an async client.

Additional offline verification:

```sh
odin test shared/aws -sanitize:address -define:ODIN_TEST_FAIL_ON_BAD_MEMORY=true
python3 shared/aws/tests/credentials_offline.py --odin /path/to/odin
```

The credential script starts isolated synthetic environments and files, and calls
fake ECS/IMDS providers only. The signing fixtures compare public PUT/file PUT,
DELETE and GET presigning with independently computed Python hashlib/HMAC values;
HEAD covers the internal generic signing/request seam, not a new public S3 HEAD
operation. Existing canonical SigV4 and SES regressions remain in the suite.
