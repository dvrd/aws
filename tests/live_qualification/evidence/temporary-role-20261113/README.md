# Approved temporary-role campaign: stopped before mutation

This is retained failure evidence, not AWS416 completion. The operator approved
the concrete temporary-role plan before execution. Preflight matched the selected
profile exactly to the trust principal/account and observed NoSuchEntity for the
unique role. Only that new ownership-tagged role and exact inline policy were
created. One ordinary900-second session was issued; credentials remained in
process memory/environment. There was no natural-expiry experiment.

The environment guard verified the exact exported triple's assumed-role identity,
account, expected role and remaining lifetime before native calls. The unchanged
previously qualified binary `0e9e5d03…` matched its retained binary/compiler/native
source evidence, including2770 standard-source files. No SDK change or rebuild
was substituted into this campaign.

The native runner advanced through READ_CHECKED, then stopped at PUT_INTENT.
The PUT operation's own precondition GET returned Read_Failed/Rejected/Unverified.
Its PUT and DELETE effects are Not_Sent; SES was disabled. No object mutation was
attempted, no foreign object was removed, and no uncertain intent was replayed or
reset. The original private campaign state remains unchanged. The public receipt
contains no credentials, raw principal ARN, resource IDs or response bodies.

The initial successful read is source-bound to the actual default S3 executor;
there is no cache/lazy-success path. Absent on that path comes from HTTP404.
The retained receipt does **not** distinguish XML NoSuchKey from NoSuchBucket.
The later Rejected category includes redirects and other4xx; it does **not**
establish a live403, AccessDenied, ExpiredToken or SignatureDoesNotMatch result.
Those raw status/body details are discarded by the current public GET API.

Cleanup verified the exact role identity, ownership tag and unchanged approved
trust/policy before deleting only the newly created inline policy and role.
Subsequent reads confirmed both NoSuchEntity. All held children were reaped;
no process-wide host census is claimed. There were no additional provider calls,
new sessions or role creations after this failure and cleanup.

## Offline diagnosis

The approved bucket/region/prefix match the fresh scope, and its exact derived key
is inside the approved object-resource ARN. ListBucket covers the same bucket
without a prefix condition; it permits S3's missing-object404 distinction but is
not itself a GetObject grant. Get/Put/Delete cover the exact selected prefix.
No policy/key spelling mismatch was found.

The source copies environment credentials into owned snapshot storage before
wiping temporary buffers; the lease remains alive through the probe. Temporary
security-token headers participate in the canonical signature. Existing synthetic
SigV4 vectors cover that header. No ownership/signing defect was established.

The new retained offline fixture uses unchanged main/probe sources and actual SDK
calls with injected HTTP outcomes: first404, then403, identical URL and a1824-byte
public synthetic token. ASan passes: two GETs, exact token header preserved, zero
write calls, and the second result matches Rejected/Not_Sent. A separate runner
reproduction reaches PUT_INTENT, refuses replay, and leaves the actual private
campaign state hash unchanged. The injected AccessDenied XML is deliberately
synthetic and is **not** relabeled as a live provider error code.

To reproduce the native control without providers or credentials, copy the
unchanged `main.odin` and `probe.odin` beside
`offline-rejection-test.odin.txt` renamed to `rejection_test.odin`, then run the
matching compiler's `odin test` with the existing shared collection, strict vet,
ASan, one test thread and fail-on-bad-memory enabled. The one-case retained log
and source hashes are bound by `provenance.json`.

## Required next scope

No production runtime fix is justified by this result. Before requesting another
live check, the narrow diagnostic change is a qualification-only GET observer
that delegates to actual `aws.s3_get_native` exactly once with unchanged arguments,
TLS and bounds, retaining only HTTP status plus a strict bounded allowlisted error
class. It must not log bodies/headers/keys or make an extra diagnostic retry.
Retain initial read evidence separately so later failures cannot erase it, and
cover the capture/no-extra-call contract deterministically. Any future role or
session/provider operation requires a separate root-authorized plan; this evidence
neither authorizes one nor completes the temporary-role S3 criterion.
