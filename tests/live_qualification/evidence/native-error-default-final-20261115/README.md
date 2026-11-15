# Default native AWS error harness: complete final control set

Root restored positive PUT200 and DELETE204 cases to the permanent default
harness after the mapping correction. One independent complete ASan run passed
all 13 cases: six documented S3 error pairings, two generic HTTP429 responses,
two successful operations, two wrong-CA rejections and one deliberately wrong
expected-status negative control. All 13 owned TLS connections retired; the peer
observed exactly one HTTP request for each of the 11 cases that passed TLS, and
no HTTP request in either wrong-CA case. Native observations contain no response
body, headers or credential values. No runtime/API/trust/deadline changes.

Mappings follow [the official S3 errors](https://docs.aws.amazon.com/AmazonS3/latest/API/API_Error.html):
400/ExpiredToken, 403/AccessDenied and 503/SlowDown. HTTP429 remains explicitly
generic. The peer reports which fixed error code it sent; it does not imply the
public buffered result parses AWS XML. No real provider was called.

The earlier 11-case runs remain historical. This final source keeps both positive
branches for future default invocations. Current 20 package ASan controls, real
scoped temporary-role S3 success and historical approved SES simulator acceptance
retain their separate source-bound evidence. Natural live expiry, provider quota
exhaustion and out-of-prefix IAM requests remain unperformed observations, not
results inferred from simulated errors. See the earlier acceptance map and the
root Linear acceptance decision. No test binaries or full source maps are in Git.
