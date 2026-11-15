# Retry-metadata formatter follow-up

The initial eight formatter fixtures omitted ResponseMetadata retry fields. A
later twelve-case actual installed CLI 2.34.40 experiment added
`MaxAttemptsReached=True` with RetryAttempts 0 or 1, for AssumeRole AccessDenied
and IAM GetRole NoSuchEntity under default, enhanced and legacy formatting.

Botocore ClientError inserts ` (reached max retries: 0)` between `operation` and
its colon. The consumed STS regex requires an immediate colon, so this complete
synthetic denial becomes Unknown in all three formats. The general IAM code regex
still matches NoSuchEntity. This reproduces a concrete parser compatibility bug
and reconciles the two operation classifiers offline. Force-legacy alone is not
a sufficient correction. The original eight fixtures and their narrower results
are retained unchanged.

This does not establish the discarded live response or actual cause. Live
issuance remains Unknown, including after the bounded no-event CloudTrail result.
A reviewed successor must count all service-error envelopes, accept only an
absent or exactly-zero documented retry annotation, reject duplicate/mixed
operation envelopes, and stop Unknown on nonzero/malformed retry metadata.
AWS_MAX_ATTEMPTS=1 remains mandatory, with at most six confirmed-denial outer
attempts and at most one verified issued session.

No provider, CLI, session, native application, real subprocess or signal was used
in this follow-up. `retry-formatter-receipt.json` contains only synthetic error
fixtures; no live response or credentials were reconstructed.
