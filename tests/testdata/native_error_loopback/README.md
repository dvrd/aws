# Native public S3 response boundary

Run from a clean owning AWS checkout using its matching Odin/compiler source and
an explicit canonical shared dependency tree:

```sh
python3 -B tests/native_error_loopback.py --odin /path/to/Odin/odin \
  --shared-root /path/to/Odin/shared --report /tmp/aws-native-errors.json
```

The harness copies the documented seven-package physical closure, using this AWS
checkout and the explicitly selected shared dependencies. It builds one ASan driver
and calls public `s3_put_at` / `s3_delete_at` with their default native Surf executor.
Only explicit `https://127.0.0.1:<owned-port>` endpoints are accepted. Credentials
are public synthetic literals; ambient credentials/config files are never read.
The existing test-only localhost certificate/key is selected explicitly using the
public `S3_Config.ca_file` option. No system trust, SDK API or deadline is changed.

The peer returns fixed 403/429/503 errors, including synthetic ExpiredToken and
SlowDown bodies. Public write results preserve the HTTP status with `ok=false`
and `transport_ok=true`: that is a completed non-success HTTP response, not a
transport failure. One signed request is observed for each operation; no retry or
redirect follows. Successful PUT200/DELETE204 controls protect the opposite branch.
Wrong-CA controls reject TLS before any HTTP request. A deliberately wrong expected
status proves the driver returns nonzero instead of accepting any completed reply.
All reported fields are fixed booleans/numbers; neither response messages nor
credentials, request headers or raw response bytes enter the native result/report.

The loopback peer checks the exact method/path/body, SigV4 and session-token header
presence. This is not an independent HMAC/signature oracle; existing deterministic
signing fixtures own that proof. It does not classify XML in the SDK write API,
prove provider authorization/throttling, simulate credential-cache expiry, or renew
any session. Natural live expiry remains untested and is outside this fixture.
The real restricted-role native S3 success and historical SES simulator receipt
retain their separate validity. No real provider or email request is made here.

The finite peer, child/output bounds and cleanup belong only to this fixture.
It reuses no consumed campaign state and cannot invoke the live qualification
runner. Source snapshots bind all selected inputs before/after, and the report
records the compiler and temporary driver hashes. Binaries remain outside Git.
