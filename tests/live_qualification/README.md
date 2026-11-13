# Native AWS scratch qualification

This finite manual tool calls the actual Odin AWS bindings for a dedicated
private S3 bucket/prefix. It does not create infrastructure, change bucket
policies, discover application objects or deploy anything. Bootstrap test
resources separately and review their exact plan before any live call.

The private0600 resource-plan JSON must declare schema1, phase `READY`, an exact
`webtools-qualification-...` bucket, region, profile,12-digit expected account,
`qualification/<32hex>/` prefix, `public_access_block_verified=true` and
`encryption="AES256"`. These assertions are bootstrap evidence, not permission to
reuse a production bucket. One new persisted run ID selects one exact `.txt` key
under that prefix. Use one state owner per resource pair; do not clone manifests
or race different hosts against the same run.

From the parent shared directory:

```sh
../odin build aws/tests/live_qualification -collection:shared="$PWD" \
  -thread-count:1 -vet -warnings-as-errors -out:/tmp/aws-live-qualification
python3 aws/tests/live_qualification/run.py plan \
  --resource-plan "$PRIVATE_RESOURCE_PLAN" --binary /tmp/aws-live-qualification \
  --state-dir "$PRIVATE_STATE" --allow-write
```

Planning is local only: it validates the resource selection and pins the binary,
private scope JSON and run ID. It does not export credentials or contact AWS.
Private state is0700 and records0600. Existing state is never silently replaced.
Review the concrete scope and then explicitly run:

```sh
python3 aws/tests/live_qualification/run.py run --state-dir "$PRIVATE_STATE" --live
```

The runner exports the selected AWS CLI profile into process memory, then verifies
**that exact exported triple** with read-only STS against the expected account.
No key material is written to files or command arguments. Known expiring exports
must remain valid beyond the180-second campaign budget. Native children receive
only those explicit keys and minimal process settings; the Odin credential cache
uses Environment mode only, with no profile/metadata fallback. This qualifies
that environment-cache path, not native SSO, assumed-role, ECS/IMDS or long-lived
credential-expiration behavior.

The native sequence performs signed GET, one PUT of fixed synthetic bytes, GET
plus SHA256/exact-byte verification, one owned DELETE and GET absence checking.
Live GET uses `aws.s3_get` with its **default native executor**, not an injected
test replacement. TLS verification stays enabled, redirects/HTTP stay disabled,
and private-CA behavior is unchanged. The preserved GET callable still has no
`ca_file` parameter. No presigned URL, header, credential, response body, resource
identifier or sender is written to receipts. A read-only missing-object check
without `--allow-write` is reported as `READ_ONLY_CHECKED`, not full qualification.

The durable PUT intent is written before the mutation call. Unknown/failed
effects stop, retain the original run ID/key and never automatically replay.
An observed foreign body blocks both overwrite and deletion. Only exact owned
synthetic bytes are removed. PUT/DELETE effects are separate; successful mutation
evidence survives a later GET failure. The dedicated unique namespace is the
ownership boundary; this is not a distributed locking service.

After reviewing an unresolved outcome, use read-only reconciliation:

```sh
python3 aws/tests/live_qualification/run.py reconcile --state-dir "$PRIVATE_STATE" --live
```

An absent object after ambiguous PUT remains unknown, not proof the write never
happened. Owned bytes permit the explicit `cleanup` command. An absent object
after ambiguous DELETE verifies cleanup. These reads never repeat a mutation or
mint a new ID. Separate `put_result`, `delete_result` and optional `ses_result`
records preserve the operation evidence. No implicit retry or state reset exists.

## Optional SES simulator only

SES is disabled by default. Do not enable it until an operator verifies a sender
identity in the selected region. Add `--ses-sender VERIFIED_SENDER
--ses-identity-verified` during planning to authorize **one** fixed synthetic
message to `success@simulator.amazonses.com`, after the S3 cleanup succeeds.
There is no configurable recipient, bounce/complaint exercise, real inbox test,
SNS configuration change or automatic resend. A successful response proves SES
API acceptance, not actual recipient delivery. Unknown SES effects retain
`SES_INTENT`; even the `send` command cannot retry an unresolved send.

AWS documents the simulator, its required verified identity and normal billing
in [Sending test emails with the simulator](https://docs.aws.amazon.com/ses/latest/dg/send-an-email-from-console.html).
After read-only S3 reconciliation or manual cleanup reaches `S3_COMPLETE`, SES
requires an explicit `send --live` call. It is not triggered by reconciliation.

Each campaign is bounded to180 seconds, credential export/STS calls to30 seconds
each and each native child to90 seconds. Native S3 PUT/DELETE use the SDK15-second
request budget; GET preserves its120-second API contract, bounded externally by
the child/campaign watchdog. Output is capped and stderr discarded. A killed
mutation remains unknown. No continuous job or resource-creation loop is installed.

## Offline validation

```sh
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover \
  -s aws/tests/live_qualification -p 'test_*.py' -v
../odin test aws/tests/live_qualification -collection:shared="$PWD" \
  -thread-count:1 -vet -warnings-as-errors -sanitize:address \
  -define:ODIN_TEST_THREADS=1 -define:ODIN_TEST_FAIL_ON_BAD_MEMORY=true \
  -out:/tmp/aws-qualification-tests
python3 aws/tests/live_qualification/default_get_loopback.py --odin "$PWD/../odin" \
  --shared-root "$PWD" --report /tmp/aws-default-get-loopback.json
ODIN_BIN="$PWD/../odin" python3 aws/tests/check_consumer.py
```

The owned loopback probe exercises a signed public GET through the default
executor, reaches native TLS ClientHello and expects the owned peer to close.
It uses public synthetic credentials and no provider endpoints. It is evidence
of the trust-configuration regression/fix, not provider interoperability or a
successful TLS handshake. Other tests use injected SDK fakes and do not contact
AWS. Real expiry, restricted-role denial and service throttling need their own
scoped evidence; synthetic coverage must not be relabelled as live proof.

The deterministic qualification fault matrix injects S3 HTTP400/403 credential-style
rejections and429/503 availability failures through the public signed SDK API.
It proves failed reads stay unverified instead of becoming404 absence; no PUT or
DELETE follows a failed read. Failed PUT/DELETE/SES responses retain HTTP status
and acknowledged response evidence without internal replay. Runner controls keep
the original run ID and durable intent, block resending and stop before native
calls on credential rejection/expiry. SES faults use only an injected executor;
no simulator message is sent by these tests.

These controls do not prove actual restricted-role authorization, natural session
expiry or provider throttling. The default GET API intentionally exposes a typed
error rather than retaining provider XML/error-code bodies; fixture XML must not
be relabelled as observed AWS `ExpiredToken` evidence. Live S3/SES success receipts
remain separate. Deliberate throttling load, IAM grants and new infrastructure are
outside this campaign.
