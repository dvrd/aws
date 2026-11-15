# Corrected S3 error-response fixture labels

This fixture-only successor preserves `9381a75a8c9ba73940c21dde08feeaa55f4b4906`.
Root review found that its 403/ExpiredToken and 429/SlowDown bodies were not the
published S3 status pairings. The original transport observations remain retained;
this receipt supersedes their interpretation as realistic S3 error labels.

The [official S3 error reference](https://docs.aws.amazon.com/AmazonS3/latest/API/API_Error.html)
pairs ExpiredToken with400, AccessDenied with403 and SlowDown with503. The owned
peer now sends those exact pairs for both public signed PUT and DELETE. The429
case remains generic HTTP robustness with the explicitly synthetic code
SyntheticHTTP429; it is not presented as an official S3 pairing.

The changed cases and negative controls passed one ASan wire run:

| Control | Cases | Result |
| --- | ---: | --- |
| 400/ExpiredToken,403/AccessDenied,503/SlowDown | 6 | Exact status, one signed request, ok=false/transport_ok=true |
| Generic429/SyntheticHTTP429 | 2 | Same HTTP robustness assertions; no AWS error claim |
| Wrong CA, both methods | 2 | TLS rejection and no HTTP request/response |
| Wrong expected status | 1 | Actual200 deliberately expected403; child exits1 |

All11 cases passed: 11 owned TLS connections, nine HTTP requests, zero retries or
provider calls. The report's allowlisted response_error_code is the Python peer's
sent response label, not a native SDK XML-classification result. TLS-negative
cases say NotSent. Native output remains fixed booleans/numbers; no credentials,
headers, response messages or raw body bytes enter it.

The driver and production SDK/Surf/API/trust/deadline paths are unchanged. The
prior20 package ASan tests and standalone PUT200/DELETE204 positive controls are
reused unchanged and were not rerun. Only the eight changed response cases and
three negative controls ran. Both old and new evidence hashes remain verifiable.
No new path is selected by Mesa's utility manifest, and no consumer restamp follows.

This models expired-token, access-denial and slowdown responses; it does not observe
natural live-session expiry, provider throttling/quota exhaustion or IAM boundary
behavior. The existing literal acceptance map retains its scope, with realistic
synthetic response labels established by this successor. No AWS/API/role/session,
SES send, cloud observation, push or issue mutation accompanied the correction.
