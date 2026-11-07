# S3 object storage

This AWS package provides S3 object uploads, deletions, and temporary download URLs. The application owns image processing, authorization, and database relationships. No AWS SDK, external command, or relay is needed at runtime.

## Configure AWS

Create a **general-purpose S3 bucket** in your chosen region. Keep Block Public Access enabled and Object Ownership set to Bucket owner enforced. The app does not create buckets or change their policies. Separate buckets are recommended for development and production.

Set `AWS_S3_BUCKET` and `AWS_REGION` in the application environment. Call
`load_s3_config` and check `s3_config_error` before using storage.

Credentials are resolved for each operation, in this order:

1. `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, and optional `AWS_SESSION_TOKEN`.
2. A static profile in `~/.aws/credentials`; select it with `AWS_PROFILE` or override the file with `AWS_SHARED_CREDENTIALS_FILE`.
3. An ECS task role through `AWS_CONTAINER_CREDENTIALS_RELATIVE_URI`.
4. An EC2 instance role through IMDSv2. Set `AWS_EC2_METADATA_DISABLED=true` outside EC2 to avoid probing metadata when credentials are missing.

SSO, web identity, credential_process, assumed-role profiles, and ECS full-URI credential providers are not implemented. Locally, temporary credentials exported by an AWS tool can be placed in the process environment. Credentials remain on the server. Role credentials are fetched again on subsequent operations so rotation is honored.

Grant the runtime identity only the object actions the application needs:
`s3:GetObject`, `s3:PutObject`, and `s3:DeleteObject`, scoped to
`arn:aws:s3:::YOUR_BUCKET/YOUR_PREFIX/*`. Bucket creation and policy management
belong to an administrative identity. Default S3 encryption needs no additional
permissions; customer-managed KMS keys require separate KMS permissions.

Buckets stay private. Download URLs are bearer credentials: anyone holding one
can use it until expiration. Applications own authorization, image processing,
object naming, database relationships, cleanup, and URL refresh behavior.

## AWS integration API

`load_s3_config`, `s3_config_error`, `aws_credentials`, `s3_put`, `s3_put_file`, `s3_delete`, and `s3_download_url` are independent of application handlers. The caller owns returned temporary allocations. AWS requests use Signature Version 4 with payload hashes, verified HTTPS, no redirects or ambient proxies, bounded replies, and connection/transfer deadlines. `s3_put_file` hashes and uploads a file using fixed-size buffers, with a 120-second transfer limit for backup archives.

`S3_Config.endpoint`, `ca_file`, and `path_style` support isolated HTTPS test peers and compatible endpoints; production configuration uses regional AWS endpoints automatically. Dotted bucket names use path-style URLs to preserve TLS hostname validation.

Signing references: [AWS SigV4 query authentication](https://docs.aws.amazon.com/AmazonS3/latest/developerguide/sigv4-query-string-auth.html), [signed requests](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_sigv-create-signed-request.html).

## Package dependencies and validation

This package is reusable outside Saba. Vendor `aws`, `files`, `surf`, `http`
(including `http/v1`), `ascii`, and `websocket` under one shared collection.
The current Surf package also imports its legacy curl-backed bounded adapter;
full native method/upload migration is separate work (OKAMI-124). No private
Mesa helper directories, AWS SDK or application imports are required.

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
All data/configuration/credentials remain caller-owned. Results and generated
headers/URLs retain their existing scratch-allocation lifetime; this does not add
credential caching or automatic retries.

`aws_credentials_with_http(execute)` applies the same per-call environment,
64 KiB profile and ECS/IMDSv2 chain with an explicit `HTTP_Execute` provider.
`aws_credentials()` retains its exact zero-argument signature and uses Surf.
The injected provider must preserve the normal bounded response, no-redirect,
trust and timeout contract; metadata requests are explicitly HTTP with a 1500 ms
budget and no upload. Incomplete environment or selected profile credentials,
including a session token without keys, fail closed rather than falling through
to another provider. Profile open failures retain the prior metadata fallback.
Returned strings borrow `context.temp_allocator` and must not outlive its storage.

The current executor remains Surf's bounded compatibility adapter, including its
existing curl dependency. This consolidation does not complete the native-client
migration or change transport/trust/retry policy.

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
