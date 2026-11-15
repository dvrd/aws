# Offline diagnosis of the retained Unknown STS attempt

The live cause cannot be recovered from the retained metadata. Keep issuance
`Unknown`. The controller's `session_count: 0` means no session was accepted as
verified Issued; it does not prove that AWS issued no session. The 0.697-second
observation does not identify which branch ran. Parent-reported zero CloudTrail
matches are not treated as proof of no issuance.

The saved campaign stopped on the first Unknown and the controller did not reach
CLI/native S3 readiness or the maintained campaign. Saved result metadata reports
owned role/policy cleanup confirmed absent. This offline review made no AWS call,
CLI invocation, role/session/provider operation or native application execution.

## Concrete information loss

Frozen `live_adapter.py` lines 96–123 maps all of these to the same operation row:

- Capture exception, including spawn/read/deadline/output-bound/wait/cleanup error.
- Nonzero CLI exit without exactly one matching legacy AccessDenied envelope.
- Zero CLI exit with JSON decoding, response shape, expected-session ARN or
  required credential-field validation failure.

It retains neither CLI return code nor safe branch/failure metadata. Eighteen
synthetic failure paths reproduced the identical Unknown row. A normal valid
synthetic response was accepted as Issued; no failure of that normal success
contract was demonstrated. Conservative Unknown for incomplete or conflicting
issuance evidence is appropriate and must not authorize a retry.

The `held_child_reaped: true` row is also unconditional. The actual frozen capture
method can receive a cleanup PermissionError before its wait call. A mock-only
control reproduced that path, with zero wait calls while the adapter recorded
`held_child_reaped: true`. This demonstrates an invalid attestation path, not that
it occurred in the live attempt. The live row alone cannot establish reap state.

## Installed CLI formatter result

Local installed CLI source is version **2.34.40**. Its local parser supports
`cli-error-format`; its default is enhanced. However, ClientErrorHandler overrides
its formatted message with `str(ClientError)`, preserving the legacy operation
line. Enhanced appends modeled details rather than replacing that line.

Actual installed formatter fixtures, passed into the actual frozen adapter:

| Error format | Synthetic AssumeRole AccessDenied | IAM NoSuchEntity legacy-code regex |
| --- | --- | --- |
| Default with no session/config | Denied | Matches |
| enhanced | Denied | Matches |
| legacy | Denied | Matches |
| json | Unknown | Does not match |

Thus enhanced by itself is not a demonstrated explanation for the live Unknown.
The observed IAM legacy-envelope match is compatible with enhanced and does not
establish a configured legacy format. A configured structured format is a possible
compatibility branch, but this review did not read user AWS configuration or
establish what format the live call used. No operation-specific formatting
mismatch was demonstrated for the synthetic standard ClientError cases.

## Safe diagnostic design for a separately reviewed successor

Do not change the frozen packet or replay this campaign. Add a bounded typed
capture result and a small allowlisted diagnostic envelope before collapsing an
outcome to Unknown. It should carry only:

- Phase: Spawn, Read, Wait, Cleanup, CLIExit, JSONDecode, ResponseShape,
  SessionIdentity, CredentialSchema, Completed.
- Return code: bounded integer or null when not verified.
- Failure type: Deadline, OutputLimit, PermissionDenied, OSFailure, WaitFailure,
  ServiceError, DecodeFailure, ValidationFailure, Other, or None.
- Error code: allowlisted official-envelope code (for example the tested
  AccessDenied, ExpiredToken, ValidationError, InvalidClientTokenId), or Other /
  Unknown. Never copy an arbitrary captured string into this field.
- Actual child state: NotSpawned, VerifiedReaped, or Unverified. Only capture's
  completed wait can establish VerifiedReaped. Cleanup failure must not set it.

Keep issuance Unknown for failed/incomplete capture or uncertain validation.
Retain the one-session guard, bounded retries only after confirmed denial, and
stop immediately on Unknown. A session-count field should explicitly describe
verified accepted sessions rather than total possible cloud issuance.

Never persist stdout/stderr, exception text, arbitrary JSON fields, credentials,
credential hashes or lengths, token prefixes, expiration values, or response
body hashes/lengths. An error summary must use fixed local labels, not remote
messages. Write the safe envelope atomically and durably within a strict small
bound; diagnostic failure must not permit another issuance attempt.

For stable CLI error parsing, a successor could explicitly pin a supported error
format rather than inherit profile settings; that is a new reviewed input, not a
claim about the previous call. Explicit legacy formatting preserves this installed
adapter's denial contract, while JSON would require a separately tested parser.
Neither format selection nor richer telemetry resolves the already discarded
live response.

## Offline controls and preservation

`test_actual_classifier.py` passed 7 tests / 21 synthetic response and exception
cases. It imports frozen methods but refuses real subprocess creation. One case
uses only fake Popen/selector/killpg objects to exercise actual capture cleanup;
no real signal or child is created. `test_installed_formatter.py` passed 8 actual
installed-formatter fixtures, with session=None and synthetic ClientError objects.
It constructs no AWS client and reads no user AWS config.

`receipt.json` records before/after hashes of the frozen controller, adapter,
lifecycle and approved manifest; they are identical. `formatter-receipt.json`
pins the installed CLI source files used. The campaign's result/readiness/ownership
metadata is hashed separately without opening state credential/session files.
All original frozen files and campaign evidence remain unchanged.
