# Approved readiness campaign stopped with unknown issuance

Root executed the separately approved frozen readiness packet once after a fresh
login and exact source/principal review. It created the one ownership-tagged role
and exact inline policy. The first STS attempt returned the adapter's Unknown
classification after 0.6978 seconds. The controller stopped without another STS
attempt and before CLI/native S3 readiness or the maintained native campaign.
No S3 operation or SES send occurred in this campaign.

The accepted-session counter stayed zero; this is not proof AWS issued no
session. The retained metadata omits STS return code and classification-failure
phase, and no live output or credentials were retained. Its unconditional
held_child_reaped field cannot independently establish actual reap state on an
exception path. Ownership cleanup checked exact tag/RoleId/trust/policy, deleted
only the owned inline policy/role, and confirmed both NoSuchEntity responses.

Root performed one bounded read-only CloudTrail lookup for the exact target and
window, max50, no pagination/next token. It returned no matching event. This does
not prove no issuance or identify a denying policy. No extra provider operation
was performed preparing this evidence commit.

Offline controls of the consumed actual code passed 7 tests / 21 response and
exception cases. Normal success is accepted. Distinct nonzero CLI errors,
zero-exit JSON/identity/schema failures and capture exceptions collapse to the
same Unknown metadata. A mock-only actual capture test also proves a cleanup
PermissionError can bypass wait while the adapter unconditionally claims reaped.

The installed CLI2.34.40 default/enhanced preserves the usual legacy error line;
initial eight fixtures without retry metadata were accepted. The later twelve
actual-formatter fixtures added MaxAttemptsReached/RetryAttempts. The inserted
` (reached max retries: 0)` defeats the strict STS immediate-colon regex while
IAM's general error-code regex still matches. This proves a parser bug offline,
not the live cause. Forcing legacy alone would not repair that variant. All
original/narrower observations and the follow-up remain separately recorded.

Live issuance remains Unknown. AWS416 temporary-role qualification is incomplete.
A new nonexecuted diagnostic plan is separate; this commit neither authorizes
nor implements a retry, new session, role, permission, provider operation or
common production API change. The consumed source snapshot's preparation-time
NOT_AUTHORIZED / NOT_EXECUTED labels stay unchanged; later user approval and
actual execution were external to those original bytes.

The evidence includes only sanitized campaign metadata, the bounded CloudTrail
receipt/source, consumed plan-local code/configuration for review, and offline
controls/results. It excludes the native binary, SDK archive, credential/session
files and live output. Large compiler/source-pin maps remain in the original
frozen /tmp packet, bound by its approved manifest. Offline scripts retain their
original /tmp source paths; they are review/reproduction artifacts, not a cloud
entry point. All consumed files remain in place, unchanged.
