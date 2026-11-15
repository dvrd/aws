# Fresh diagnostic readiness proposal — NOT AUTHORIZED / NOT EXECUTED

Root must review this exact packet before any future explicit user approval.
The hash argument is an input-integrity guard, never authorization. No cloud,
provider, role/session, native application, S3 or SES operation was performed
preparing this packet. Local Python stubs and fixed process metadata controls
were executed only as offline tests. The proposed campaign path does not exist.

The consumed readiness attempt remains issuance Unknown. Its verified-accepted
session counter0 does not establish zero actual cloud sessions. Cleanup confirmed
its exact role/policy absent; a bounded CloudTrail search found no matching event,
which is not proof of no issuance. The old result, state and approved packet stay
untouched. A retry-clause parser bug is reproduced offline, not diagnosed as the
live cause. Forcing legacy format alone does not fix that variant.

This proposal uses exactly the fresh resources.json role/session/tag and32hex
prefix in the same dedicated us-east-1 bucket. Only that exact dvrd IAM user is
trusted. Get/Put/Delete are limited to the new prefix; the existing ListBucket
metadata grant is unchanged. No IAM grant, user, bucket, ingress or provider scope
is added. Fresh identifiers are prepared values, not claims of cloud absence.

Before any mutation, future preflight verifies the manifest, pinned installed
CLI2.34.40 entry/source files, binary/compiler/Core/diagnostic sources, clean AWS
owner8010f8cd2b5f9e8a144fb85ef90ff7dff8fd9bc1, exact caller/account and new role
NoSuchEntity. Refuse preexisting campaign/ownership/state or ambiguous guards.
Create only the new ownership-tagged role and exact trust/inline policy; recheck
RoleId/tag/ARN/trust/policy. Persist every mutation intent before dispatch.

The original readiness/state-machine bounds remain:

1. At most6 STS attempts within one absolute45s window, each duration900 and same
   role/session name. AWS_MAX_ATTEMPTS=1; only a complete confirmed AccessDenied
   allows a5s-delayed outer retry. Stop after the first verified Issued session;
   never renew. Any Unknown stops without retry. A complete late success counts
   as accepted Issued but cannot reach S3. Counters mean verified accepted only.
2. The same literal credential triple remains in memory only. Maintained guards
   verify exact assumed-role/account/expiry and225s remaining before proceeding.
   No credential values, hashes, lengths, prefixes or expiration persist.
3. At most6 CLI GET Range0-0 attempts, one45s window, five-second delay only after
   confirmed AccessDenied. Exact new prefix/run_id.txt, destination/dev/null,
   no profile/config/credential/endpoint/proxy fallback. Only explicit NoSuchKey
   permits one native read, which must establish Absent/HTTP404/NoSuchKey with no
   mutation effects. Existing object, malformed/unknown/nonzero-retry metadata,
   other error, timeout, divergence or deadline stops without PUT.
4. Only after both absence proofs, run the unchanged maintained180s campaign with
   the same triple: one synthetic PUT, owned readback, owned DELETE and final
   absence under its existing intent/effect/no-replay rules. No SES or expiry
   experiment. Keep overall360s admin/native and120s owned-cleanup deadlines.
5. On any created-role intent, use the original exact tag/RoleId/trust/policy
   ownership checks and confirm both owned policy/role absences. No mutation
   retry after an uncertain outcome, foreign deletion or old state replay.

This v3 preserves the rejected-but-unexecuted v1 packet byte-for-byte. It keeps
the same proposed fresh resource identifiers, grants, owner and bounds; it changes
only selected review corrections and the fresh local campaign output path.

One narrow shared error-envelope decoder serves STS and GetObject. Only pinned
ClientError exit254 can authorize service-error classification; killed children
or rc1/252/253/255 with error-looking text remain Unknown. It counts ALL
service-error prefixes, requires one correct-operation official envelope, and
accepts only absent retry metadata or exactly `(reached max retries: 0)`.
Retry1+, malformed annotations, duplicates, mixed operations, conflicting output
or unknown shape stay Unknown. IAM NoSuchEntity ownership cleanup keeps its
existing general error-code semantics. Every plan-local CLI request explicitly
pins legacy error format, coloroff, autopromptoff, outputJSON and one attempt.
The same settings cover maintained CLI requests through a local tuple-compatible
transport shim; common AWS runner/API/source files are unchanged.

Plan-local capture retains at most16KiB combined CLI output privately in memory
(maintained calls retain their existing explicit bound). Typed safe diagnostics
contain only fixed phase/failure/retry enums, bounded returncode, allowlisted
provider error, actual PID and actual wait state. No output, remote message,
exception text, credential data/hash/length or response-body hash/length is logged.
Result reports are atomic0600/fsynced and capped64KiB; readiness journal remains
append-only0600/fsynced. Capture/output/diagnostic uncertainty never permits retry.

Capture holds the child PID using WNOWAIT until retirement. Fixed bounded local
ps metadata verifies actual live same-UID members of the new held process group;
zombie-only groups are not signalled. Signal only before reap. Always attempt
actual waitpid even after signal/metadata/close failure, while the waitable-child
reservation is proven. ECHILD/lost reservation means no further group lookup,
signal or wait; PID stays explicitly unverified and no prior/fabricated Popen
status becomes a verified exit. A non-ECHILD observation failure instead suppresses
lookup/signals while retaining the owned bounded wait and failed diagnostic; it
does not disown a still-reserved child. A private sentinel only suppresses destructor
auto-poll after loss and is never reported as an exitcode. Both metadata-helper
close faults are contained until its protected owner retirement attempt. Reaped
attestation requires an actual successful waitpid result. The existing5s local retirement allowance includes bounded metadata/wait.
Unverified child state remains explicit with its PID; no blind signal retry or
foreign-process signal is permitted. No generic production process API is added.

Offline controls cover controller bounds/same triple/late success/no replay,
strict Case0 vs Case1 STS and S3, duplicate/malformed/wrong-operation envelopes,
actual installed CLI models/arguments/JSON output and36 formatted error variants,
private diagnostics, atomic bounded reports, owned role-cleanup refusal, real
owned Python stubs (including a live same-group descendant after leader exit),
mocked permission/wait failure, unknown/foreign ownership and no post-reap signal.
The predecessor's12 retry-metadata proofs are preserved separately. See the
source/hash-bound offline receipt and logs for actual counts and limitations.

Future root-reviewed invocation, only after separate explicit approval:
`python3 -B /tmp/aws416-readiness-plan-20261115-diagnostics-v3-7a1fc78b/live_adapter.py --execute-approved-plan-sha256 <SHA256 of SHA256SUMS.json>`

No result here establishes readiness, effective authorization, production/public
health or completion of AWS416. No future execution is authorized by this file.
