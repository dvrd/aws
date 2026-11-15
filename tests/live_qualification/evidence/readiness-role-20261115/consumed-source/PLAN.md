# Proposed bounded authorization readiness — NOT AUTHORIZED / NOT EXECUTED

This is a new proposal, not replay of any of the three consumed campaigns. The
latest actual campaign failed STS AssumeRole before issuance and was cleaned;
older S3 denials and their states remain immutable. A current principal simulation
returned allowed with no missing context; a bounded CloudTrail search found no
matching event. Neither diagnoses the historical denial. Propagation is only a
hypothesis. This proposal deliberately broadens the previous first-denial-stop
scope and needs a separate explicit user approval after root review.

Review resources.json/trust.json/permissions.json: one fresh uniquely named role,
one new32hex prefix in the existing dedicated bucket/region, only the current
exact IAM user trusted, one fixed session name, no new grants. Get/Put/Delete are
limited to that fresh prefix; the existing ListBucket metadata grant is unchanged.
The native binary7a0d114f… and all SDK/compiler/source bytes stay pinned; canonical
AWS808c15944760a70963c08509a351767f77f4a969 HEAD is required clean. No rebuild or SDK changes.

The prepared live_adapter.py reuses the verified earlier owned lifecycle and
maintained qualification runner. Its future separately approved execution will:

1. Verify every frozen input/source/binary/SDK/compiler hash and exact default
   profile principal/account. GetRole must return NoSuchEntity. Refuse existing
   role, ambiguous preflight, prior ownership/readiness/campaign directory. Create
   only the tagged role and exact trust/inline policy, verifying documents and
   role identity before readiness. Persist all write intentions before dispatch.
2. After verification, allow at most6 total AssumeRole API attempts within one
   absolute45s monotonic window, each requesting the same ordinary900s session
   duration/name/role. The first attempt is immediate; wait5s only after a fully
   received official AccessDenied envelope for the AssumeRole operation. CLI
   internal attempts remain1. Preserve every intent, attempt outcome and timing.
   Five confirmed denials may therefore precede one successful issuance. Stop
   immediately after success: at mostONE issued session, never renewal.
3. A timeout, cancellation, output bound, malformed/unexpected successful reply,
   different error, incomplete CLI error envelope or any ambiguous outcome stops
   with issuance=Unknown. No second attempt follows uncertainty. A late complete
   success is recorded Issued/session_count1 but stops without S3. Confirmed
   denial exhaustion is NotIssued, never mislabeled issuanceUnknown. The code
   does not promise API idempotency; its only issuance-retry predicate is a known
   denied request. Never retry create/policy/delete/unknown STS mutations.
4. Keep the one issued literal credential triple only in process memory/env.
   Verify exact assumed-role identity/account/expiry using maintained guard;
   require225s remaining for the combined45s readiness+180s campaign. Same triple
   everywhere; no hashes, values, lengths, expiration or exports in receipts.
5. Permit at most6 CLI GET attempts of the exact new prefix+run_id.txt key during
   one absolute45s window. Only an exact AccessDenied/GetObject error response
   permits a5s-delayed next read; no credential refresh. GET Range0-0 to/dev/null
   bounds an unexpected existing object's response to1byte. No profile/config/
   endpoint/proxy fallback. Per-child20s or remaining window, connect5/read10;
   all CLI transports one attempt. Every safe allowlisted denial/layer and timing
   is journaled. Existing object, NoSuchBucket, expired token, throttle, unknown
   error, timeout, exhaustion or any other result stops without native/PUT.
6. Only explicit CLI NoSuchKey permits ONE unchanged native Read, with same
   scope/runID/triple and remaining45s readiness budget. Require native successful
   Absent+HTTP404+explicitNoSuchKey. Native denial/divergence/unknown is never
   retried. Its typed numeric/code observation is preserved; no raw body/headers.
   Readiness uses its separate append-only0600 journal; maintained state remains
   PREPARED, with no reset/reconciliation of any old state.
7. Only after both implementations establish absence, call the unchanged
   maintained180s no-replay S3 campaign with the same triple and another readonly
   identity guard, never another AssumeRole session. One synthetic PUT,
   readback/hash, owned DELETE, final absence; existing intent/effect preservation
   governs uncertain writes. No SES, provider scope expansion or object cleanup
   outside maintained ownership rules. Up to6CLI readiness reads+1native
   readiness read, plus normal5nativeGET/1PUT/1DELETE if all phases succeed.
8. Always perform existing ownership/tag/RoleId/trust/policy checked cleanup after
   create intent, even on ambiguous creation/issuance. Delete only the exact new
   inline policy and role, confirm both absences; preserve unknown cleanup rather
   than retrying/deleting foreign state. Each deletion intent precedes dispatch.
   Existing360s absolute admin/native bound plus120s cleanup bound and held child
   reaping remain. Guard refuses starting campaign without remaining225s budget.
   Every held process group is killed/reaped on cancellation/error/timeout; no
   raw CLI stderr/stdout, identity document or credentials persist.

Safe receipts distinguish phase, Issued/NotIssued/Unknown, all attempts, fixed
codes/layers, exact-match attestation and owned cleanup. CLI numeric HTTP status
remains unknown rather than inferred from its code. Unknown/multiple deny-layer
phrases remain Unknown. Native AccessDenied has no retained message/layer.

CLI Range GET and native GET differ in headers and transport implementation.
A successful sequence may show readiness changed during one window, not prove
propagation was the cause. A denied sequence cannot identify the effective
policy without separate evidence. No expiry experiment, renewed session,
permission expansion, retry after ambiguous outcome, old state replay, host or
SES operation is included. No result here closes AWS416.

Predecessor preparation evidence:21 focused offline controls passed, including six-denial
bounds, unknown/timeout no-retry, late issued result, same immutable triple,
native denial no-retry, strict key/profile/triple adapter, actual held local child
bounds/reaping, exact owned cleanup/refusal, and real maintained PREPARED→COMPLETE
state transitions with fake transport. No IAM/provider/STS/credential operations
were performed preparing the predecessor or this successor directory. The three original state hashes and
previous frozen plan hash are preserved in offline-receipt.json.

Future root-reviewed invocation (not an approval):
`python3 -B /tmp/aws416-readiness-plan-20261115-held-child/live_adapter.py --execute-approved-plan-sha256 <SHA256 of SHA256SUMS.json>`

Root must review frozen files and obtain new explicit approval first. Do not run
preflight/execute now. This directory is only locally prepared, not published.


## Held-child correction successor

This successor preserves the frozen predecessor directory untouched. The exact
role name/ARN, prefix, trust, grants, session name, all readiness/campaign bounds
and unexecuted state are unchanged. Only the qualification capture ownership
correction is added: after successful wait/reap, no killpg signal may target the
released PID/group. On failure, signal only while the exclusively held child's
returncode is still unknown, then reap; always close pipes. Fixed AWS CLI commands
have no intended persistent descendants; no process-tree framework is added.

The owning maintained runner correction is clean808c15944760a70963c08509a351767f77f4a969,
now canonical following root review and34 qualification controls. The controller
and its new mocked test have their own RED→GREEN5 controls. Together with the14
readiness controls,19 successor controls pass without launching a subprocess,
CLI, native binary or provider operation. New pin files change only the owner
revision and maintained run.py hash; the native probe/compiler/Core hashes are
unchanged. Updated manifest hashes transparently bind this source-only correction.
The old21-control evidence remains in the frozen predecessor. No approval or
execution is inferred from this correction; root must review this successor.
