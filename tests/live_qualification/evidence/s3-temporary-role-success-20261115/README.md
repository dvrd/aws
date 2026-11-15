# One approved temporary-role S3 campaign completed

Root ran the exact separately approved final packet once, bound to manifest
cb119a4c5f3b743f50c03e1dd205a81e4984b13bcc15f01863c5eae545ac1797 and clean
AWS owner d3f8a7164d0a5ead428deccc2235c71c1cb59c8a. It created only the fresh tagged
role and exact reviewed trust/S3 policy in the existing dedicated bucket/prefix.
The first two STS attempts were confirmed AccessDenied/exit254/retryZero. After
only the permitted five-second delays, the third issued one accepted session requested for900s.
There was no renewal or further issuance attempt. This observed sequence does
not diagnose propagation or explain any historical denial/Unknown result.

The role/account/expiry guards completed, and the original guard and maintained
campaign attestations match the same approved role. The readiness journal proves
one official CLI GetObject NoSuchKey response followed by native HTTP404 with
explicit NoSuchKey, using the same literal credential triple in memory. No
credential value, credential hash/length or expiration is retained.

The actual maintained native campaign then passed:

| Action | Recorded observation |
| --- | --- |
| Initial native read | HTTP404 / NoSuchKey / Absent |
| Synthetic PUT | HTTP200 / Response_Received |
| PUT readback | HTTP200 / Owned |
| Owned DELETE | HTTP204 / Response_Received |
| Final read | HTTP404 / NoSuchKey / Absent |

Result, maintained state and receipt all agree on COMPLETE, qualified=true and
s3_qualified=true. SES was disabled/not selected and no send occurred. The key is
bound to the approved fresh prefix and recorded run_id, and scope/binary/policy
hash bindings match across the retained files.

Owned is a source-bound verification, not an inferred HTTP200 label. The exact
approved native binary SHA is7a0d114f74db48769f176febc60a51be17de51519fd42251a8474739c40775e3;
its current bytes match the approved hash. The thirteen diagnostic source pins
and ten native-owner Odin source pins also match. In pinned probe.odin90–93,
object_read requires BOTH SHA256(body)==SHA256(expected) and exact byte equality.
object_put requires that owned readback; object_delete checks ownership before
its mutation and absence afterward. The retained delete effect/status establish
that its owned-object deletion path ran. The independent reviewer only read
files/hashes/source and did not rebuild, execute native code or query AWS.

Root independently rechecked the finalized receipts and pinned source guard after
execution, before any owner revision advance; root-postexecution-review.json
records that read-only check.

All23 recorded capture diagnostics report actual VerifiedReaped/Reaped with no
cleanup fault. Exact RoleId/tag/trust/policy ownership checks preceded cleanup;
only the new inline policy/role were deleted and both NoSuchEntity absences were
confirmed. Role deletion is not claimed to revoke already issued credentials.
The completed object absence comes from this campaign's final native observation,
not a new cleanup or audit request by the evidence preparer.

The prior v3 session was issued but stopped at a local tuple-contract bug; that
failed outcome and its immutable PREPARED state remain intact. The still earlier
separate Unknown issuance remains Unknown; its accepted counter0 is not proof of
zero cloud sessions. This later success does not rewrite any earlier result or
justify replay of old state. The corrected packet's offline full-flow/no-replay
controls and prior preparation labels remain separate from actual live results.

This is the positive temporary-role S3 gate for this exact native binary, role,
region and prefix. It does NOT complete all AWS416 scope: previously documented
restricted-role native S3 denial, natural expiry and throttling remain
unqualified. No SES simulator/send/delivery, renewal, general AWS service,
application deployment or production-readiness claim is made. Historical
credential/fault/SES-simulator evidence retains its own separate validity.

The evidence is limited to sanitized result/journal/ownership/scope/state/receipt,
the consumed plan-local source and review receipts, and the pinned native source
needed to assess ownership. Original SDK/compiler source maps and the binary
remain in the immutable /tmp preparation; approved manifests still bind those
full packets. Copied preparation-time NOT_AUTHORIZED/NOT_EXECUTED labels are
preserved original bytes; later user approval and execution were external.
No provider call, retry, cleanup operation, native application execution, source
fix or push accompanied this evidence-only commit. Do not rerun the consumed
adapter or replay the COMPLETE state.
