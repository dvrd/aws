# Offline native S3 error boundary and OKAMI-416 acceptance map

Owning baseline: `134f07247c6107f57932ccb65ada0184cd075c5a`. This batch changes only
owner-local test/harness/document/evidence files. No production AWS, Surf, facade,
API, trust or timeout source changed. All 16 AWS paths currently selected by
Mesa's utility manifest are unchanged by this batch relative to the owning baseline;
none of the new paths is selected. Twelve currently match Mesa byte-for-byte. Four
preexisting documentation/test/helper differences are recorded in the receipt; no
production runtime differs. This batch adds no new Mesa consumer source delta and
does not restamp those historical differences.

The new fixture runs the public signed `s3_put_at` and `s3_delete_at` with their
default native Surf executor against an explicitly trusted owned TLS peer. Public
synthetic credentials/session token and a small fixed payload are the only inputs.
The existing localhost test identity and private test key are selected explicitly.
A seven-package physical copy binds the isolated AWS checkout and shared dependencies.

ASan wire results on unchanged runtime code:

| Control | Cases | Actual boundary |
| --- | ---: | --- |
| PUT/DELETE403/429/503 | 6 | One signed HTTP request each; exact status, ok=false, transport_ok=true |
| PUT200/DELETE204 | 2 | Successful completed-response controls |
| Wrong CA, both methods | 2 | TLS rejected; zero HTTP requests; no write sent |
| Wrong expected status | 1 | Completed HTTP200 deliberately expected403; child exits1 |

All 11 cases passed, with 11 owned TLS connections and nine HTTP requests, no
second accepted connection per invocation, bounded children/output and source
snapshots unchanged. Native output contains only fixed numeric/bool observations;
provider body markers, credentials and headers are absent. The peer checks method,
path, body and signed session-token headers, but is not a second HMAC oracle.
Existing deterministic signature fixtures own that independent proof.

The first fixture compile rejected an untyped string transmute; its diagnostic is
retained. An initial capture discarded compiler stderr, so the fixture now retains
bounded combined diagnostics. Both failures were fixture setup, not runtime defects.
An old-runtime ASan baseline and the final exact-source ASan run each pass11 cases.
Existing AWS package ASan also passed20 tests with memory tracking and bad-memory
failure enabled, including fake-clock expiry, failed-refresh refusal, retained
snapshot consistency and secret wiping. No natural session-expiry experiment ran.
The postrun package report was corrected to bind Odin's aggregate20-test output to
the copied test registrations; package execution was not repeated.

Matching compiler is dev-2026-11:c826157de, rooted at the recorded local Odin tree.
Compiler hash and all2,770 previously authenticated standard-source files match.
Full raw source snapshots, temporary package copies and binaries remain under
`/tmp/aws416-native-error-loopback-20261115`; the compact receipts bind their hashes.

Current literal OKAMI-416 criteria map to existing accepted evidence:

| Listed criterion | Verified evidence |
| --- | --- |
| Exact isolated bucket/prefix/region/temporary role | Approved native S3 temporary-role success evidence |
| PUT/GET/hash/DELETE; clean only owned resources | COMPLETE receipt, owned-byte/hash checks, final404 and role/policy cleanup |
| Credential failure controls | Deterministic expiry/failed refresh/wiping; guards/no replay; new native TLS error controls |
| SES only simulator or approved test recipient | Historical approved actual SES simulator200/Response_Received receipt |
| No uncertain-write replay or logged keys | Durable intents/refused replay; source-bound diagnostic/privacy controls |

The retained live success is in `../s3-temporary-role-success-20261115`; historical
SES/fault/denial receipts are copied here unchanged with their original hashes.
The real success closes scoped temporary-role S3, not general service availability.
The new403/429/503 and ExpiredToken/SlowDown bodies are simulated responses, not
observed AWS natural expiry, provider throttling or out-of-prefix IAM denial.
Those unperformed extended observations are not additional literal issue criteria.
No literal listed criterion remains without evidence in this map; root must review
and accept the map before changing issue state. This batch makes no Done mutation.

Reproduce only the offline test using the documented harness invocation in
`../../../testdata/native_error_loopback/README.md`. `receipt.json` records full
commands, hashes and limits; `SHA256SUMS.json` authenticates this evidence bundle.
No AWS CLI/API, role/session, provider write, SES send, existing campaign replay,
production account/host change or push accompanied this batch.
