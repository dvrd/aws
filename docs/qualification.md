# Live qualification

## What it does

The qualification runner (`cmd/qualify`) makes a finite live check of S3 GET, PUT and DELETE, and optionally of an SES send, using the native probe in `tests/qualification/probe/`. It is the only part of this repository that reaches AWS, and it does so only when you pass `--live`. Everything else, including its unit tests, is offline.

## Before you start

- A scratch bucket named `webtools-qualification-<suffix>` with Block Public Access turned on and default encryption set to SSE-S3 (`AES256`).
- A profile, or a temporary role session, limited to that bucket's prefix. If you check SES, it also needs `ses:SendEmail` for an identity you have verified. The exact policy is yours to write; this document does not prescribe one.
- The AWS CLI v2 at an absolute path that you own, passed with `--aws-cli`. Without that option the runner looks for `aws` on `PATH`. Either way the runner refuses a CLI it does not trust, and uses it to obtain the credentials.
- Credentials that stay valid for at least 180 seconds (`TOTAL_TIME` in `cmd/qualify/runner.odin`). The runner refuses credentials that expire sooner.

## The resource plan

The resource plan is a JSON file that names what the runner may touch. `docs/qualification.example.json` is a copy with placeholder values, and a unit test proves the runner accepts its shape. The fields are:

- `schema`: `1`.
- `phase`: `"READY"`.
- `bucket`: `webtools-qualification-` followed by 3 to 40 characters of `a-z`, `0-9` and `-`.
- `region`: the bucket's region.
- `prefix`: `qualification/` followed by 32 lowercase hex digits and a trailing `/`.
- `expected_account`: the 12-digit account id.
- `profile`: a profile name of 1 to 64 characters of `A-Z`, `a-z`, `0-9`, `_` and `-`. Use this or `credential_source`, not both.
- `public_access_block_verified`: `true`, once you have checked it.
- `encryption`: `"AES256"`.

Copy the example outside the repository, fill in your values, and run `chmod 600` on it; the runner refuses a plan that other users can read. Real account ids, ARNs and bucket names never go into the repository.

## Procedure

Build the probe. This writes `build/probe`:

```
task qualify:probe
```

Plan the run. `--binary` must be an absolute path to a file you own; the runner copies it into the state directory. `--allow-write` enables PUT and DELETE. `--ses-sender` needs `--allow-write` and `--ses-identity-verified`.

```
task qualify -- plan --state-dir DIR --resource-plan FILE --binary "$PWD/build/probe" \
    [--aws-cli /absolute/path/to/aws] [--allow-write] \
    [--ses-sender qualification@example.com --ses-identity-verified]
```

Run it. Nothing reaches AWS without `--live`:

```
task qualify -- run --state-dir DIR --live
task qualify -- status --state-dir DIR
```

If a run stops with an interrupted or unknown outcome, first reconcile, which only reads, and then clean up:

```
task qualify -- reconcile --state-dir DIR --live
task qualify -- cleanup --state-dir DIR --live
```

When the plan includes SES, `task qualify -- send --state-dir DIR --live` sends the message after the S3 part is complete.

The runner never replays a mutation whose outcome is unknown. Each command continues only from the phases it is permitted to (`phase_permitted` in `cmd/qualify/runner.odin`), and otherwise stops and asks for review.

## Environment credentials

Instead of `profile`, a plan may set `"credential_source": "environment"` and `"expected_role_arn"` to `arn:aws:iam::123456789012:role/qualification`, where the account matches `expected_account`. The environment must then hold `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, `AWS_SESSION_TOKEN` and `AWS_CREDENTIAL_EXPIRATION`, and the session must be a session of that role. The runner checks this before it starts anything and stops if it cannot.
