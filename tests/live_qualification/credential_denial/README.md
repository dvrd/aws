# One-request synthetic-credential denial probe

This optional manual probe makes exactly one signed GET to one pre-reviewed
scratch key. It never reads environment/profile credentials, exports keys,
sends SES, mutates S3, creates infrastructure or changes IAM. Authentication uses
fixed public synthetic strings. Scope accepts only a `webtools-qualification-...`
bucket and `qualification/<32hex>/<32hex>.txt` key, with no configurable endpoint.
Explicit `--live` is required. The SDK native executor retains strict TLS and no
redirect/replay policy, with a ten-second request budget and1024-byte body cap.

Build locally, then review the exact resource plan before executing:

```sh
../odin build aws/tests/live_qualification/credential_denial -thread-count:1 \
  -vet -warnings-as-errors -out:/tmp/aws-credential-denial
/tmp/aws-credential-denial --bucket "$REVIEWED_SCRATCH_BUCKET" \
  --region "$REVIEWED_REGION" --key "$REVIEWED_PREVIOUSLY_CLEANED_KEY" --live
```

The wrapper delegates to `aws.s3_get_native` and captures only status/count;
the public signed S3 API classifies the response and discards the body. A passing
receipt means one actual HTTP403 was rejected with a typed S3 error. It does not
claim a specific XML error code, restricted-role policy, or natural expiry. No
request IDs, body XML, resources, headers or credential fields enter output.
AWS lists `InvalidAccessKeyId` among
[S3 error responses](https://docs.aws.amazon.com/AmazonS3/latest/API/API_Error.html).
Only a real execution can supply provider evidence; its two offline tests verify
scope/opt-in, fixed classification and redaction without making any request.
