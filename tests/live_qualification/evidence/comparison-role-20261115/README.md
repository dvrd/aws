# Approved comparison stopped before session issuance

The user separately approved the frozen one-session comparison plan. Root ran
its exact adapter once after verifying the current default-profile identity,
source/binary bindings and plan manifest. It created one new ownership-tagged
role with the exact reviewed trust and S3 inline policy. The actual official CLI
STS AssumeRole request returned AccessDenied (exit254) before any session result
was returned. The safe outcome reports zero issued sessions. The controller's
coarse phase remains PREFLIGHT; the ordered operation record and durable
ASSUME_ROLE_INTENT establish the actual later boundary, rather than a failed
initial identity check.

The fresh maintained native state remains PREPARED. No CLI/native comparison GET,
native binary invocation, S3 call, PUT, DELETE or SES send occurred. Its prepared
receipt is not a successful native campaign. This consumed approval is not
replayable, even though native mutation intent was never reached. Both previous
campaign states retain their exact frozen hashes. No credentials, session
material, raw provider messages, headers or body are retained here.

Cleanup rechecked exact ownership/tag/RoleId/trust and inline policy, deleted only
the newly created policy and role, then confirmed both NoSuchEntity responses.
All14 held CLI children were reaped. Cleanup was performed by root's consumed
controller; this evidence preparation issued no provider calls.

Offline comparison finds no session-name mismatch: the frozen trust condition
and AssumeRole argument read the same session_name; its syntax is valid and the
requested duration is900s. The preflight principal hash matches the exact trust
principal. GetRole/GetRolePolicy verified the intended documents before STS and
again during ownership cleanup. These observations do not establish effective
STS authorization at issuance time. The role's S3-only inline permissions concern
later object operations; neither those operations nor the native SDK/signing
path were reached. The earlier S3 policy simulation and absent bucket policy
cannot explain this earlier STS denial. No denying policy statement/layer is
retained. Fresh IAM propagation is only a hypothesis, not a diagnosed cause.

The frozen resources file still has its preparation-time NOT_AUTHORIZED label;
the user's later explicit approval was external to those immutable bytes. This
label is not used to reclassify the authorized consumed execution or to authorize
another run. No approval request, new session/role, retry, policy expansion or
source/test logic change accompanies this evidence-only commit. AWS416 temporary
role qualification remains incomplete; previous historical S3/SES successes
retain their separate validity.
