# Signed PUT options and a blocking HEAD

Status: design, not implemented. Nothing in `src/` changes with this document.

Goal: let a caller upload with a SHA-256 checksum, write-once (`If-None-Match: *`),
a storage class and user metadata, and read an object's size, checksum, storage
class and metadata back with a blocking HEAD, so that bot-mesa's log archiver
can stop shelling out to the AWS CLI and the Drive mirror can choose whether to
keep its sidecar objects.

Non-goal: multipart upload. A single PUT carries at most 5 GiB and this
library bounds a file upload to 120 s (`S3_REQUEST_TIMEOUT_MAX_MS`,
`src/s3.odin:193`); anything larger needs multipart upload, which is a separate,
larger design (part checksums, `x-amz-checksum-type: COMPOSITE`, abort and
cleanup) and is not covered here.

## 0. Base this design describes

Written against `develop` at `4d6a5c8`. Of the plans the spike was told to
account for:

- **Plan 019 (one SigV4 core) has landed** (`9acb9cf`). Every signer goes through
  `sigv4_sign` (`src/sigv4.odin:31`), which takes a `[]Sigv4_Header` that must be
  sorted by lower-case name (`src/sigv4.odin:11-24`, debug assert at `:36-40`) and
  streams the canonical request into SHA-256 without building it. S3 object
  requests build that list in one place, `s3_object_headers`
  (`src/s3.odin:571-642`), as a fixed `[4]Sigv4_Header` of `host`,
  `x-amz-content-sha256`, `x-amz-date` and an optional `x-amz-security-token`.
- **Plan 023 (typed results) has landed** (`99566cc`). `S3_Result` is the
  library's own struct `{status, ok, error: S3_Error, effect: S3_Write_Effect}`
  (`src/s3.odin:58-74`), and `S3_Error` is
  `{None, Invalid_Input, Not_Found, Too_Large, Rejected, Unavailable}`
  (`src/s3.odin:855-862`) with `s3_status_error` mapping a status
  (`src/s3.odin:868-878`).
- **Plan 022** touched neither file in a way that matters here.

Facts about the live code this design relies on:

- `s3_put` (`src/s3.odin:207-226`), `s3_put_file` (`:233-280`) and `s3_delete`
  (`:284-301`) all go through `s3_object_request_at` (`:303-355`) and the shared
  signer `s3_object_sign` (`:359-410`).
- Their procedure types are pinned by `tests/unit/s3_test.odin:266-273` ("Do not
  add parameters to any old function-value type"), and Saba re-exports
  `s3_put_request`, `s3_get_request` and `s3_head_request` as constant aliases
  (`saba/src/s3/s3.odin:84-87`). Options therefore need new procedures.
- `Content-Type` is sent but not signed (`src/s3.odin:566-568`, `:627-629`).
- `s3_head_request` (`src/s3.odin:480-490`) signs a HEAD for async transports;
  there is no blocking HEAD.
- `HTTP_Execute :: proc(request: HTTP_Request) -> ([]u8, surf.Buffered_HTTP_Result)`
  (`src/credentials.odin:1335`) returns a body and a status but no response
  headers. `s3_get_native` (`src/s3.odin:956-1005`) instead calls
  `surf.execute`, whose `surf.Response` carries `headers: []http.Header`
  (`shared/surf/http.odin:85-95`), and Surf already reads a HEAD answer without a
  body (`shared/surf/http.odin:778-779`, `http1.response_apply_method`).
- `s3_header_fields` (`src/s3.odin:544-564`) turns header lines into
  `S3_Header` fields for `S3_Request` and **drops a line whose value is empty**
  (`:550-553`). Any header that is signed must therefore have a non-empty value,
  or the async request would be missing a header its signature covers.

## 1. Signing rules

### 1.1 Which headers are signed

The SigV4 rules (AWS IAM user guide, "Create a signed AWS API request"):
`host` and every `x-amz-*` header that is sent must be signed; other standard
headers "can optionally" be signed. botocore signs every request header except a
blocklist of hop-by-hop headers (`SIGNED_HEADERS_BLACKLIST`, `botocore/auth.py:59`;
`headers_to_sign`, `:242`), so it signs `Content-Type` and `If-None-Match` when
they are present.

Decision for this library, PUT with options:

| Header | Signed | Sent value |
|---|---|---|
| `host` | yes | from the URL, as today |
| `x-amz-content-sha256` | yes | hex SHA-256 of the payload, as today |
| `x-amz-date` | yes | as today |
| `x-amz-security-token` | yes, when the credentials have one | as today |
| `x-amz-checksum-sha256` | yes | base64 of the payload's SHA-256 (1.3) |
| `x-amz-storage-class` | yes | the option value |
| `x-amz-meta-<name>` | yes, each one | the option value |
| `if-none-match` | yes | `*` |
| `content-type` | **no** (unchanged) | the `content_type` argument |
| `Expect` | no | empty (`Expect:` switches off curl's `100-continue`, `:625-639`) |

`If-None-Match` is not an `x-amz-*` header, so signing it is a choice, not a
requirement. It is signed because it changes what the request does (an
overwrite becomes a refusal), and an unsigned copy could be stripped by anything
between the caller and S3 without breaking the signature.

**`Content-Type` stays unsigned.** Reasons:

1. Every existing vector (38 rows in `REFERENCE_REQUESTS`, the unit fixtures at
   `tests/unit/s3_test.odin:325-339`) was produced without it; signing it would
   change every PUT signature with a content type and invalidate the fixtures for
   no new capability.
2. `s3_put_request` hands `Content-Type` to async transports as a header field
   (`src/s3.odin:417-433`). Signed, the transport would have to send exactly that
   byte string; HTTP clients commonly add or rewrite `Content-Type` (charset
   parameters, defaults for a body), which would turn into a
   `SignatureDoesNotMatch` that is hard to diagnose.
3. S3 accepts it unsigned: the library has always sent it that way and the
   qualification probe uploads with `text/plain` (`tests/qualification/probe/probe.odin:188-190`).

The cost is that something on the path could change the stored content type
without breaking the signature. Over TLS that is the same exposure as today. The
AWS guide's own wording conflicts ("If the Content-Type header is present in the
request, you must add it" versus "You can optionally include other standard
headers ... such as content-type"), so this stays an open question (4.1); row 8
of the vectors below is the signed variant so the decision can be reversed
without generating vectors again.

HEAD: `host`, `x-amz-content-sha256` (the empty payload's digest),
`x-amz-date`, the optional token, and `x-amz-checksum-mode: ENABLED` when the
caller asks for the checksum (2.2). Without that header S3 does not return
`x-amz-checksum-sha256` (HeadObject API reference, `x-amz-checksum-mode`: "To
retrieve the checksum, this parameter must be enabled").

### 1.2 Canonical form, and what the library rejects

Ordering. `canonical_headers` (`botocore/auth.py:300`) lower-cases names, sorts
them, and joins repeated values with `,`; `signed_headers` (`:324`) is the same
sorted list joined by `;`. The library's `sigv4_sign` requires the list already
sorted by byte-wise comparison of lower-case names. All names here are
lower-case ASCII, so byte order equals botocore's `sorted()` order. Note that
`if-none-match` sorts between `host` and the `x-amz-*` block, and `content-type`
(if it were ever signed) before `host`, so options cannot simply be appended:
the build step merges them into the fixed headers (3.5).

Repeated names. The library never sends a header twice: a metadata name given
twice is rejected, so the "join with `,`" rule never applies.

Value trimming. botocore's `_header_value` (`:316`) is `' '.join(value.split())`:
it trims and collapses runs of whitespace (spaces, and also tabs and other
whitespace) into one space. The AWS guide says "trim any leading or trailing
spaces" and "convert sequential spaces to a single space". S3 recomputes the
canonical form from the header it receives, so a value the library sends with
doubled spaces would still verify. Vector 5 confirms botocore's behaviour: the
value `"  two  spaces  here "` signs exactly like `"two spaces here"` (the
generator checks this, `collapsed_same: true`).

**Decision: reject, do not rewrite.** An option value must already be in
canonical form: no leading or trailing space and no two spaces in a row. Then
the bytes sent, the bytes signed and the bytes S3 stores are the same, and no
transport or proxy whitespace handling can matter. Rewriting silently would
store a value different from the one the caller passed (metadata values are
returned by HEAD and compared by consumers). The HeadObject reference even warns
"You must URL encode any signed header values that contain spaces"; with single
interior spaces allowed and everything else rejected, values stay safe and a
caller that needs arbitrary text encodes it itself.

Characters. Every option value must be printable US-ASCII: bytes `0x21-0x7E`
plus single interior spaces (`0x20`). That excludes CR, LF, NUL, tab and every
other control byte (header injection; the existing check for `content_type` is
`strings.contains_any(content_type, "\r\n\x00")`, `src/s3.odin:372`), and every
byte above `0x7E`.

Non-ASCII. S3 "allows arbitrary Unicode characters" in metadata values, but asks
REST callers to use US-ASCII and stores and returns non-ASCII values RFC 2047
encoded (S3 user guide, "Working with object metadata"). So a UTF-8 value would
not come back from HEAD as it was sent, and the library would have to sign raw
UTF-8 bytes that HTTP/1.1 header handling does not guarantee to pass through
unchanged. **Decision: reject non-ASCII.** A caller that needs Unicode encodes
it (percent-encoding or base64) before passing it, and decodes after HEAD.

Empty values. Rejected for metadata, because `s3_header_fields` drops an empty
header from `S3_Request` (`src/s3.odin:550-553`) while the signature would still
cover it. `storage_class == ""` means "no header".

Metadata names. The caller gives the part after `x-amz-meta-`; the library adds
the prefix. The suffix must be 1 or more bytes of `[a-z0-9-]` (lower case
because S3 stores metadata names lower case and the signer needs lower-case
names; no `_`, because some proxies drop headers with underscores). Taking only
the suffix means a metadata entry can never inject another `x-amz-*` header
such as `x-amz-acl` or `x-amz-website-redirect-location`.

Size. "Within the PUT request header, the user-defined metadata is limited to
2 KB in size. The size of user-defined metadata is measured by taking the sum of
the number of bytes in the UTF-8 encoding of each key and value" (S3 user guide).
Whether "key" includes the `x-amz-meta-` prefix is not stated; the library
counts it, the stricter reading: `S3_METADATA_BYTES_MAX :: 2048`, with
`sum(len("x-amz-meta-") + len(name) + len(value)) <= 2048`. That also bounds the
number of entries (at most 170 one-byte names), so the signer can size its
header list from the input. The whole PUT header is limited to 8 KB, which the
library's own headers (well under 1 KB without a very long session token) and
2 KiB of metadata fit in.

Storage class. Upper-case `[A-Z_]`, 1 to 64 bytes. The library does not keep a
list of valid classes (the list grows: the PutObject reference now lists 15,
including `FSX_*` and `AWS_BACKUP_*`); S3 answers 400 (`Rejected`) for an
unknown one.

### 1.3 One hash, two encodings

`x-amz-content-sha256` is the lower-case hex of the 32-byte SHA-256 of the
payload. `x-amz-checksum-sha256` is the base64 (standard alphabet, with padding,
always 44 characters ending in `=`) of the **same 32 bytes** (PutObject
reference: "the Base64 encoded, 256-bit SHA256 digest of the object"). Both come
from one hash:

```odin
sum: [32]u8
hash.hash(.SHA256, body, sum[:])          // s3_object_sign, src/s3.odin:381-383
digest_hex: [64]u8
sigv4_hex(sum[:], digest_hex[:])          // x-amz-content-sha256
checksum: [44]u8
base64_write(sum[:], checksum[:])         // x-amz-checksum-sha256, no allocation
```

For the vectors' body `payload` that is
`239f59ed55e737c77147cf55ad0c1b030b6d7ee748a7426952f9b852d5a935e5` and
`I59Z7VXnN8dxR89VrQwbAwttfudIp0JpUvm4UtWpNeU=`.

Today `s3_object_sign` hashes the body itself but takes a file's digest as a
hex **string** (`digest` parameter, `src/s3.odin:366`), which `s3_put_file`
builds with `hex.encode` into the temp allocator (`:262-263`, `:277`). The build
should pass the raw `[32]u8` instead (`digest: ^[32]u8 = nil`) so that both
encodings are written from the bytes on the stack, and the hex string allocation
disappears as a side effect. (`s3_get` passes `EMPTY_PAYLOAD_SHA256` as a
string, `:924`; it can pass nil and let the empty-body branch at `:378-379` apply.)

The library does **not** send `x-amz-sdk-checksum-algorithm`. The PutObject
reference says it only matters to SDKs and that sending it requires a matching
`x-amz-checksum-<algorithm>` or `x-amz-trailer`; `x-amz-checksum-sha256` alone
is enough for S3 to verify and store the checksum.

## 2. Reference vectors

### 2.1 How they were produced

Offline, with the AWS CLI's own interpreter
(`/opt/homebrew/Cellar/awscli/2.34.40/libexec/bin/python`, botocore 2.34.40),
by a script kept outside the repository. For each case it builds
`AWSRequest(method, url, headers, data=body)` with `host`,
`x-amz-content-sha256`, `x-amz-date`, the token when there is one, and the
option headers; sets `context['timestamp'] = '20130524T000000Z'` and
`context['payload_signing_enabled'] = True`; and computes
`auth.signature(auth.string_to_sign(req, auth.canonical_request(req)), req)` with
`S3SigV4Auth(credentials, 's3', 'us-east-1')`. Because `x-amz-content-sha256` is
set, `canonical_request` uses it as the payload hash (`botocore/auth.py:377`).

Credentials are read by the script from `tests/conformance/botocore_test.odin`,
never typed: "the conformance credentials" are those of
`REFERENCE_REQUESTS[0]` (plain) and, for the session-token case, those of
`REFERENCE_PRESIGNS[1]` (access key, secret and token). No key material appears
in this document.

Before generating anything, the script re-derived **all 38 existing
`REFERENCE_REQUESTS` signatures** with the same method and they all matched.
Six keys (`a/../b`, `dou//ble`, `/leading`) need botocore's
`_normalize_url_path` (`:384`) switched off, because S3 does not normalise
object keys and the library signs the path as sent; the other 32 match with
stock `S3SigV4Auth`.

Fixed inputs for every row: bucket `examplebucket`, region `us-east-1`,
virtual-hosted URL
`https://examplebucket.s3.us-east-1.amazonaws.com/staging/bot-mesa/app.log-20130524-1.gz`,
signing time 2013-05-24T00:00:00Z, PUT body `payload` (HEAD: empty).

### 2.2 The table

| # | Case | SignedHeaders | botocore signature |
|---|---|---|---|
| 1 | checksum only | `host;x-amz-checksum-sha256;x-amz-content-sha256;x-amz-date` | `8e71a99cbb4cea33167b4acefe8d5ba876aa0ade8aef8a916d11df16447f85d7` |
| 2 | `if-none-match: *` only | `host;if-none-match;x-amz-content-sha256;x-amz-date` | `093bae046b5505c5916f4f65ea55718a7ac6c975ac86a94705f9adbf3b870074` |
| 3 | storage class `STANDARD_IA` only | `host;x-amz-content-sha256;x-amz-date;x-amz-storage-class` | `e688d2aa02b6ef25a9fc840b171ac7407d9ced029958ee3b5072f5893e25f5e8` |
| 4 | two metadata headers given out of order (`modified-time`, then `drive-id`) | `host;x-amz-content-sha256;x-amz-date;x-amz-meta-drive-id;x-amz-meta-modified-time` | `3aa116b2a35292d7c9889d868be1298cd6d23d0e0df5b2b6c5842216285221f8` |
| 5 | metadata value `"  two  spaces  here "` (botocore canonicalises; the library would reject it, 1.2) | `host;x-amz-content-sha256;x-amz-date;x-amz-meta-note` | `e4bde2cd2beb6bb4f042f980e146cbbb39f676683889a1bf25c3a36521656baf` |
| 6 | all options (1 to 4 together) | `host;if-none-match;x-amz-checksum-sha256;x-amz-content-sha256;x-amz-date;x-amz-meta-drive-id;x-amz-meta-modified-time;x-amz-storage-class` | `9ed4f96d49abde0e5d4d08a4a53f9b49eb786884579dc7cf36cde353cab09a2c` |
| 7 | all options and a session token | `host;if-none-match;x-amz-checksum-sha256;x-amz-content-sha256;x-amz-date;x-amz-meta-drive-id;x-amz-meta-modified-time;x-amz-security-token;x-amz-storage-class` | `bf2c36962cc48a1be68cda80e30bc3b8c3c5e72cf57182bf5983c2b359562d5b` |
| 8 | all options, `content-type: application/gzip` **signed** (botocore's default) | `content-type;host;if-none-match;x-amz-checksum-sha256;x-amz-content-sha256;x-amz-date;x-amz-meta-drive-id;x-amz-meta-modified-time;x-amz-storage-class` | `b53b097eee16d69d2325b0c7be71d366dceae5b52bca11dd7ad8d280527b7961` |
| 9 | all options, `content-type: application/gzip` **sent unsigned** (this library's rule) | same as row 6 | `9ed4f96d49abde0e5d4d08a4a53f9b49eb786884579dc7cf36cde353cab09a2c` (equal to row 6) |
| 10 | HEAD, no options | `host;x-amz-content-sha256;x-amz-date` | `c5760ce280d86aa754f1cf8e5e432392f049b640239b70c22003a9416e630610` |
| 11 | HEAD, `x-amz-checksum-mode: ENABLED` | `host;x-amz-checksum-mode;x-amz-content-sha256;x-amz-date` | `de1a1031324d7fe9847a2e1ce47242a3613e704529cb5dd011d4772875ca8ba8` |

Rows 8 and 9 show the content-type decision in numbers: an unsigned
`Content-Type` leaves the signature exactly as if it were absent; signing it
changes both `SignedHeaders` and the signature.

### 2.3 Canonical requests

Row 4 (metadata given out of order; the canonical form sorts them):

```text
PUT
/staging/bot-mesa/app.log-20130524-1.gz

host:examplebucket.s3.us-east-1.amazonaws.com
x-amz-content-sha256:239f59ed55e737c77147cf55ad0c1b030b6d7ee748a7426952f9b852d5a935e5
x-amz-date:20130524T000000Z
x-amz-meta-drive-id:1AbC
x-amz-meta-modified-time:2013-05-24T00:00:00Z

host;x-amz-content-sha256;x-amz-date;x-amz-meta-drive-id;x-amz-meta-modified-time
239f59ed55e737c77147cf55ad0c1b030b6d7ee748a7426952f9b852d5a935e5
```

Row 6 (all options; `if-none-match` sorts before the `x-amz-*` block):

```text
PUT
/staging/bot-mesa/app.log-20130524-1.gz

host:examplebucket.s3.us-east-1.amazonaws.com
if-none-match:*
x-amz-checksum-sha256:I59Z7VXnN8dxR89VrQwbAwttfudIp0JpUvm4UtWpNeU=
x-amz-content-sha256:239f59ed55e737c77147cf55ad0c1b030b6d7ee748a7426952f9b852d5a935e5
x-amz-date:20130524T000000Z
x-amz-meta-drive-id:1AbC
x-amz-meta-modified-time:2013-05-24T00:00:00Z
x-amz-storage-class:STANDARD_IA

host;if-none-match;x-amz-checksum-sha256;x-amz-content-sha256;x-amz-date;x-amz-meta-drive-id;x-amz-meta-modified-time;x-amz-storage-class
239f59ed55e737c77147cf55ad0c1b030b6d7ee748a7426952f9b852d5a935e5
```

Row 8 differs from row 6 only by a first canonical header line
`content-type:application/gzip` and `content-type;` at the front of the signed
list.

### 2.4 Rows ready for `tests/conformance/botocore_test.odin`

These compiled and passed as a throwaway test in the `conformance` package
(Step 4, 2.5). In the build plan, `metadata` holds suffixes once
`S3_Put_Options` exists (`{"modified-time", ...}`); here it holds full header
names because the prototype fed `sigv4_sign` directly. Row 5 belongs in a
"rejected input" test once the library rejects such values; it stays here as the
botocore reference.

```odin
// PUT options and HEAD, botocore 2.34.40, signing time 2013-05-24T00:00:00Z,
// bucket examplebucket in us-east-1, virtual-hosted. Credentials: those of
// REFERENCE_REQUESTS[0], or of REFERENCE_PRESIGNS[1] when token is set.
Reference_Put_Options :: struct {
	method:            string, // "PUT" (body REFERENCE_PUT_OPTIONS_BODY) or "HEAD"
	token:             bool,
	content_type:      string, // sent; signed only when sign_content_type is set
	sign_content_type: bool,
	checksum_sha256:   bool,
	if_none_match:     bool,
	storage_class:     string,
	metadata:          [2]Sigv4_Header, // an empty name is no entry
	checksum_mode:     bool, // HEAD: x-amz-checksum-mode: ENABLED
	signed, signature: string,
}

REFERENCE_PUT_OPTIONS_KEY :: "staging/bot-mesa/app.log-20130524-1.gz"
REFERENCE_PUT_OPTIONS_BODY :: "payload"

REFERENCE_PUT_OPTIONS :: []Reference_Put_Options {
	{method = "PUT", checksum_sha256 = true, signed = "host;x-amz-checksum-sha256;x-amz-content-sha256;x-amz-date", signature = "8e71a99cbb4cea33167b4acefe8d5ba876aa0ade8aef8a916d11df16447f85d7"},
	{method = "PUT", if_none_match = true, signed = "host;if-none-match;x-amz-content-sha256;x-amz-date", signature = "093bae046b5505c5916f4f65ea55718a7ac6c975ac86a94705f9adbf3b870074"},
	{method = "PUT", storage_class = "STANDARD_IA", signed = "host;x-amz-content-sha256;x-amz-date;x-amz-storage-class", signature = "e688d2aa02b6ef25a9fc840b171ac7407d9ced029958ee3b5072f5893e25f5e8"},
	{method = "PUT", metadata = {{"x-amz-meta-modified-time", "2013-05-24T00:00:00Z"}, {"x-amz-meta-drive-id", "1AbC"}}, signed = "host;x-amz-content-sha256;x-amz-date;x-amz-meta-drive-id;x-amz-meta-modified-time", signature = "3aa116b2a35292d7c9889d868be1298cd6d23d0e0df5b2b6c5842216285221f8"},
	{method = "PUT", metadata = {{"x-amz-meta-note", "  two  spaces  here "}, {}}, signed = "host;x-amz-content-sha256;x-amz-date;x-amz-meta-note", signature = "e4bde2cd2beb6bb4f042f980e146cbbb39f676683889a1bf25c3a36521656baf"},
	{method = "PUT", checksum_sha256 = true, if_none_match = true, storage_class = "STANDARD_IA", metadata = {{"x-amz-meta-modified-time", "2013-05-24T00:00:00Z"}, {"x-amz-meta-drive-id", "1AbC"}}, signed = "host;if-none-match;x-amz-checksum-sha256;x-amz-content-sha256;x-amz-date;x-amz-meta-drive-id;x-amz-meta-modified-time;x-amz-storage-class", signature = "9ed4f96d49abde0e5d4d08a4a53f9b49eb786884579dc7cf36cde353cab09a2c"},
	{method = "PUT", token = true, checksum_sha256 = true, if_none_match = true, storage_class = "STANDARD_IA", metadata = {{"x-amz-meta-modified-time", "2013-05-24T00:00:00Z"}, {"x-amz-meta-drive-id", "1AbC"}}, signed = "host;if-none-match;x-amz-checksum-sha256;x-amz-content-sha256;x-amz-date;x-amz-meta-drive-id;x-amz-meta-modified-time;x-amz-security-token;x-amz-storage-class", signature = "bf2c36962cc48a1be68cda80e30bc3b8c3c5e72cf57182bf5983c2b359562d5b"},
	{method = "PUT", content_type = "application/gzip", sign_content_type = true, checksum_sha256 = true, if_none_match = true, storage_class = "STANDARD_IA", metadata = {{"x-amz-meta-modified-time", "2013-05-24T00:00:00Z"}, {"x-amz-meta-drive-id", "1AbC"}}, signed = "content-type;host;if-none-match;x-amz-checksum-sha256;x-amz-content-sha256;x-amz-date;x-amz-meta-drive-id;x-amz-meta-modified-time;x-amz-storage-class", signature = "b53b097eee16d69d2325b0c7be71d366dceae5b52bca11dd7ad8d280527b7961"},
	{method = "PUT", content_type = "application/gzip", checksum_sha256 = true, if_none_match = true, storage_class = "STANDARD_IA", metadata = {{"x-amz-meta-modified-time", "2013-05-24T00:00:00Z"}, {"x-amz-meta-drive-id", "1AbC"}}, signed = "host;if-none-match;x-amz-checksum-sha256;x-amz-content-sha256;x-amz-date;x-amz-meta-drive-id;x-amz-meta-modified-time;x-amz-storage-class", signature = "9ed4f96d49abde0e5d4d08a4a53f9b49eb786884579dc7cf36cde353cab09a2c"},
	{method = "HEAD", signed = "host;x-amz-content-sha256;x-amz-date", signature = "c5760ce280d86aa754f1cf8e5e432392f049b640239b70c22003a9416e630610"},
	{method = "HEAD", checksum_mode = true, signed = "host;x-amz-checksum-mode;x-amz-content-sha256;x-amz-date", signature = "de1a1031324d7fe9847a2e1ce47242a3613e704529cb5dd011d4772875ca8ba8"},
}
```

Once the API in section 3 exists, the test drives `s3_put_request_with` and
`s3_head_request_with` (not `sigv4_sign`), reads `Authorization` with the
existing `s3_request_header` and `s3_request_signature` helpers, as
`signed_requests_match_the_reference_implementation` does
(`tests/conformance/botocore_test.odin:86-113`), and also checks that every
signed name appears as a header field of the returned `S3_Request` with the
exact value that was signed.

### 2.5 Prototype result (Step 4)

The open question on paper was whether `sigv4_sign` and a merged, sorted header
list reproduce botocore for the option headers (including `if-none-match`
sorting ahead of `x-amz-*`, the token in the middle of the block, and the
base64 checksum from the same digest). A throwaway test in
`tests/conformance` built each row's header list (base headers, then options,
then a byte-wise insertion sort by name), computed the checksum with
`base64.encode` of the payload's `[32]u8` digest, collapsed whitespace the way
botocore does for row 5, and called `sigv4_sign`. All 11 rows matched both
`SignedHeaders` and the signature (`task test -- --package conformance`: "4
tests ... All tests were successful"). The test file was then deleted; `src/`
and `tests/` are unchanged on this branch.

## 3. API

### 3.1 Options

```odin
// Optional headers of a signed upload. The zero value sends the same request
// as s3_put.
S3_Put_Options :: struct {
	checksum_sha256: bool,        // x-amz-checksum-sha256 from the payload's hash
	if_none_match:   bool,        // If-None-Match: *, store only if the key is free
	storage_class:   string,      // "" is the bucket default (STANDARD)
	metadata:        []S3_Header, // name is the part after "x-amz-meta-"
}

S3_METADATA_BYTES_MAX :: 2048 // S3's limit, counted with the x-amz-meta- prefix

// "" when options can be signed, else what is wrong with them, in the style of
// s3_config_error. The request procedures refuse invalid options with
// Invalid_Input and effect Not_Sent.
s3_put_options_error :: proc(options: S3_Put_Options) -> string
```

`s3_put_options_error` checks the rules of 1.2: storage class `[A-Z_]{1,64}`;
each metadata name `[a-z0-9-]+`, unique; each value non-empty, printable
US-ASCII, no leading, trailing or doubled space; total size at most
`S3_METADATA_BYTES_MAX`. It returns a string, like `s3_config_error`
(`src/s3.odin:89`), because the only consumer of the reason is a log line;
request procedures fold any failure into `S3_Error.Invalid_Input`, as they do
for a bad config or key.

`S3_Header` (`src/s3.odin:1008`) is reused for metadata, so no new
name/value type enters the API.

### 3.2 New procedures (the pinned ones do not change)

```odin
s3_put_with :: proc(
	config: S3_Config,
	credentials: AWS_Credentials,
	key: string,
	body: []byte,
	content_type: string,
	options: S3_Put_Options,
	now: time.Time = {},
	http_execute: HTTP_Execute = http_execute_default,
) -> S3_Result

s3_put_file_with :: proc(
	config: S3_Config,
	credentials: AWS_Credentials,
	key, path, content_type: string,
	options: S3_Put_Options,
	now: time.Time = {},
	http_execute: HTTP_Execute = http_execute_default,
) -> S3_Result

s3_put_request_with :: proc(
	config: S3_Config,
	credentials: AWS_Credentials,
	key: string,
	body: []byte,
	content_type: string,
	options: S3_Put_Options,
	now: time.Time = {},
) -> (S3_Request, bool)

s3_head_request_with :: proc(
	config: S3_Config,
	credentials: AWS_Credentials,
	key: string,
	checksum: bool, // x-amz-checksum-mode: ENABLED
	now: time.Time = {},
) -> (S3_Request, bool)
```

`s3_put`, `s3_put_file`, `s3_put_request` and `s3_head_request` become one-line
calls with `S3_Put_Options{}` / `checksum = false`, and must produce
byte-identical requests: the 38 existing conformance rows and the unit fixtures
are the gate.

`s3_put_file_with` already hashes the file before sending
(`src/s3.odin:249-263`); the same `digest: [32]byte` gives both the hex payload
hash and, when `checksum_sha256` is set, the base64 checksum, so the checksum
costs no second read of the file. `s3_put_file` has no request builder today and
`s3_put_file_with` adds none.

### 3.3 Blocking HEAD

```odin
// What a HEAD answer says about an object. Strings borrow storage, which is in
// the allocator s3_head was given; free both with s3_object_info_destroy.
S3_Object_Info :: struct {
	size:            i64,         // Content-Length
	etag:            string,      // ETag as sent, quotes included
	checksum_sha256: string,      // base64; "" unless asked for and uploaded with one
	storage_class:   string,      // "STANDARD" when S3 sends no x-amz-storage-class
	content_type:    string,
	last_modified:   string,      // the HTTP date as sent; not parsed
	metadata:        []S3_Header, // names without "x-amz-meta-", lower case
	storage:         []u8,
}

s3_object_info_destroy :: proc(info: ^S3_Object_Info, allocator := context.allocator)

// Per-operation executor for s3_head, modeled on S3_Get_Execute. It sends one
// signed HEAD ("Name: value" header lines), never follows redirects, and copies
// the response header names and values into one block of storage in allocator;
// headers point into storage. status is the HTTP status, 0 when none arrived.
S3_Head_Execute :: proc(
	url: string,
	headers: []string,
	timeout_ms: i64,
	allocator: mem.Allocator,
) -> (
	response_headers: []S3_Header,
	storage: []u8,
	status: int,
	error: S3_Error,
)

// Blocks for up to 15 seconds. Not for an event-loop thread: use
// s3_head_request_with there and parse the answer with s3_object_info_parse.
s3_head :: proc(
	config: S3_Config,
	credentials: AWS_Credentials,
	key: string,
	checksum := false,
	now: time.Time = {},
	allocator := context.allocator,
	execute: S3_Head_Execute = s3_head_native,
) -> (S3_Object_Info, S3_Error)

// Parses the headers of a 2xx HEAD answer (exported so async callers with their
// own transport get the same rules).
s3_object_info_parse :: proc(headers: []S3_Header, storage: []u8) -> (S3_Object_Info, bool)
```

Why a new executor type: `HTTP_Execute` returns no response headers
(`src/credentials.odin:1335`) and changing it would touch every credential and
SES path. `s3_head_native` is `s3_get_native` (`src/s3.odin:956-1005`) with
`method = .HEAD`, `max_body_size = 1`, timeout `S3_REQUEST_TIMEOUT_MS`, the same
platform-roots trust, the same `S3_GET_HEADERS_MAX` bound on request lines (a
HEAD sends at most six: content hash, date, `Expect:`, token, checksum mode,
Authorization), and the same refusal of `config.ca_file` with the native
executor (`src/s3.odin:921-923`). It copies `response.headers` before
`surf.response_destroy`, which frees Surf's header storage.

Response headers parsed (names compared case-insensitively; HTTP/2 delivers
them lower case):

| Header | Field | When absent |
|---|---|---|
| `Content-Length` | `size` | answer is malformed: `Unavailable` |
| `ETag` | `etag` | `""` |
| `x-amz-checksum-sha256` | `checksum_sha256` | `""` (S3 sends it only with checksum mode and only if the object was uploaded with one) |
| `x-amz-storage-class` | `storage_class` | `"STANDARD"`: "Amazon S3 returns this header for all objects except for S3 Standard storage class objects" (HeadObject reference) |
| `Content-Type` | `content_type` | `""` |
| `Last-Modified` | `last_modified` | `""` |
| `x-amz-meta-*` | `metadata` | empty slice |

A repeated `x-amz-meta-*` name, which S3 itself joins with `,`, is kept as the
one entry S3 sent. A non-ASCII value comes back RFC 2047 encoded and is
returned as is; `x-amz-missing-meta` (entries S3 could not return) is ignored
(open question 4.6).

Allocator: one block (`storage`) holds every string, plus one `metadata`
slice; `s3_object_info_destroy` frees both. On any error nothing is returned and
nothing stays allocated, as with `s3_get` (`src/s3.odin:943-949`).

Errors (HEAD has no body, so no S3 error code is ever available): 2xx is
`None`; 404 is `Not_Found`; 403 is `Rejected` (S3 answers 403 instead of 404 when
the caller lacks `s3:ListBucket`, so a consumer that treats "missing" specially
must know which permissions it has); 0, 408, 429, 5xx are `Unavailable`. The
observer sees HEAD like GET: a 404 is an expected answer.

### 3.4 Reporting the write-once refusal

PutObject with `If-None-Match: *` answers **412 Precondition Failed** when the
key exists, and **409 ConditionalRequestConflict** when a conflicting write
raced it ("On a 409 failure you should retry the upload", PutObject reference).

**Decision: add `S3_Error.Precondition_Failed`** and map 412 to it in
`s3_status_error`. Mapping to `Rejected` with `status == 412` would make every
caller compare a raw status to tell "already stored, go verify" from "this
request is wrong", which is exactly what `S3_Error` exists to avoid. No request
the library sends today carries a precondition, so the new mapping changes no
existing outcome. The name follows HTTP rather than this use (`Exists`), because
later `If-Match` support would answer 412 for a different reason.

- 409 is `Unavailable` (retry) **for a PUT that carried `If-None-Match`**, and
  stays `Rejected` in `s3_status_error` otherwise, because a generic 409 is not
  known to be retryable.
- `effect` is `Response_Received` for both: S3 answered and did not store.
- The observer counts a 412 on a write-once PUT as ok (an expected answer, like
  a 404 on GET).

Compatibility: adding an enum member breaks an exhaustive `switch` on `S3_Error`
in a consumer, so the change ships as `feat!`. bot-mesa switches with
`#partial switch` (`bot-mesa/src/drive/drive.odin:595`); Saba only re-exports.

### 3.5 Fit with the SigV4 core (plan 019)

Options become extra entries in the sorted `[]Sigv4_Header` that
`s3_object_headers` passes to `sigv4_sign`; `sigv4_sign` itself does not
change. Concretely:

1. `s3_object_sign` gains `options: ^S3_Put_Options = nil` (nil for GET, DELETE
   and the zero-option PUT) and a `checksum_mode: bool` for HEAD, validates
   options with `s3_put_options_error`, and takes the payload digest as
   `^[32]u8` (1.3).
2. `s3_object_headers` replaces the fixed `[4]Sigv4_Header` with a list sized
   `4 + 4 + len(options.metadata)` in the temp allocator (it already allocates
   its line slice there, `src/s3.odin:609`). It fills the fixed headers, appends
   the options (metadata names written as `x-amz-meta-` + suffix into the
   builder), and insertion-sorts by name; the debug assert in `sigv4_sign`
   (`src/sigv4.odin:36-40`) catches a sort mistake, and rejecting duplicate
   metadata names makes the strict `<` hold.
3. The `SignedHeaders` string is written from the sorted list instead of the two
   constants at `src/s3.odin:587-591`, and `s3_object_headers_size` /
   `sigv4_authorization_size` take the list's names into account.
4. Header lines gain `If-None-Match: *`, `x-amz-checksum-sha256: ...`,
   `x-amz-storage-class: ...`, `x-amz-checksum-mode: ENABLED` and one
   `x-amz-meta-<name>: <value>` per entry, written into the same builder; the
   fixed `[6]int` `starts`/`ends` arrays become slices of the line count.

Presigned URLs (`s3_download_url`) and SES are untouched.

## 4. Open questions

Decisions this document makes but the maintainer should confirm:

1. **Sign `Content-Type`?** Proposed: no (1.1). Reversing it changes every
   existing PUT signature that has a content type, and requires async transports
   to send the exact signed bytes. Row 8 is ready if the answer changes.
2. **`Precondition_Failed` as a new `S3_Error` member** (breaking for exhaustive
   switches), versus `Rejected` with `status == 412` (not breaking, but callers
   compare raw statuses). Proposed: the new member. Also confirm 409-after-
   `If-None-Match` as `Unavailable`.
3. **Metadata size policy.** Proposed: count the `x-amz-meta-` prefix in the
   2 KiB (stricter than S3 may be). Alternative: count only suffix and value and
   let S3 reject the edge. Also: should the library cap the entry count
   separately (for example 32) to keep the signed list small?
4. **Reject or rewrite non-canonical values.** Proposed: reject leading,
   trailing and doubled spaces and all non-ASCII. Alternative: collapse spaces
   the way botocore does and send the collapsed value.
5. **Expose the checksum to callers.** The archiver needs the base64 digest to
   compare with HEAD. Today it would hash the file a second time. Options: an
   `s3_file_sha256(path) -> ([32]u8, bool)` helper, or a `checksum_sha256` field
   on `S3_Result` (adds bytes to every result), or let `S3_Put_Options` carry a
   precomputed checksum that the library compares to its own hash before
   sending.
6. **`x-amz-missing-meta`**: ignore (proposed) or surface as a count on
   `S3_Object_Info`.
7. **HEAD with conditions** (`If-Match`, `If-None-Match` on HEAD, answering 304
   or 412): not proposed; nothing needs it yet.
8. **Multipart upload** is a separate question (see the non-goal at the top):
   objects above one PUT's limits, part checksums and the `COMPOSITE` checksum
   type are out of scope here.

## 5. Consumers

### 5.1 bot-mesa log archiver

Today (`bot-mesa/deploy/log-archive/bot-mesa-log-archive.sh:76-86`): `aws s3api
put-object --storage-class "$STORAGE_CLASS" --checksum-algorithm SHA256
--checksum-sha256 "$digest" --if-none-match '*'`, ignoring its outcome, then
`aws s3api head-object --checksum-mode ENABLED --query
'[ContentLength,ChecksumSHA256,StorageClass]'` and a comparison with
`size<TAB>digest<TAB>STORAGE_CLASS`; the local file is deleted only on an exact
match.

With the library (a small Odin command in bot-mesa, run by the same timer):

```odin
result := aws.s3_put_file_with(config, credentials, key, path, "application/gzip",
	{checksum_sha256 = true, if_none_match = true, storage_class = storage_class})
#partial switch result.error {
case .None, .Precondition_Failed: // stored now, or already there: verify below
case: return .Kept                // anything else: keep the file, retry next run
}
info, error := aws.s3_head(config, credentials, key, checksum = true)
if error != .None {return .Kept}
defer aws.s3_object_info_destroy(&info)
if info.size != size || info.checksum_sha256 != digest_base64 ||
   info.storage_class != storage_class {return .Kept}
// delete the local file
```

What replaces what:

- `--checksum-algorithm SHA256 --checksum-sha256` becomes
  `checksum_sha256 = true`; S3 verifies the body against it and refuses the PUT
  (a 400, `Rejected`) on a mismatch.
- `--if-none-match '*'` becomes `if_none_match = true`; the 412 the script
  currently logs as "upload refused or failed" becomes the distinct
  `Precondition_Failed`.
- `head-object --checksum-mode ENABLED` becomes
  `s3_head(..., checksum = true)`, and the three `--query` fields become
  `info.size`, `info.checksum_sha256` and `info.storage_class`.
- `openssl dgst -sha256 -binary | base64` becomes the digest the library already
  computes, once open question 5 is settled.

Observation for bot-mesa (not acted on): with `STORAGE_CLASS=STANDARD` the
current script would not match, because S3 omits `x-amz-storage-class` for
STANDARD objects and the CLI text output then shows `None` (not verified against S3 in this spike). `s3_head` reporting
`"STANDARD"` for an absent header avoids that.

### 5.2 bot-mesa Drive mirror

Today the "unchanged" test (`bot-mesa/src/drive/drive.odin:510-514`) compares
the stored record's `modified_time`, `deleted_at`, `status`, `key` and `md5`,
loaded by `mirror_meta_load` (`:590-606`, an `s3_get` of
`<meta_prefix>/<id>.json`) and written by `mirror_meta_save` (`:609-617`, an
`s3_put`).

Moving the record into object metadata would replace that GET with a HEAD of the
mirrored object and drop the sidecar PUT. Trade-offs:

- For: one object per file instead of two; the record cannot drift from the
  object it describes; a HEAD is cheaper than a GET plus JSON parse.
- Against: user metadata is capped at 2 KiB and is only changed by rewriting the
  object (S3 user guide: "After you upload the object, you can't modify this
  user-defined metadata"). The mirror records state that changes without new
  bytes: `deleted_at` when an item is trashed (`drive.odin:448-452`), a folder that moves or is renamed
  (`:460-461`), `previous_key` when the key moves (`:515`). With metadata each of
  those would mean re-uploading or copying the object.
- Against: records with `status` `not_exportable` or `too_large` have **no
  mirrored object** (`drive.odin:505-509`, `:516-520`), so they need a sidecar
  anyway, and the mirror would have two lookup paths.
- Names and values would have to fit 1.2's rules (Drive names are Unicode, so
  `name` would need encoding).

Recommendation: keep the sidecar as the source of truth. If the extra request
matters, a cheaper step is to also write `md5` and `modified-time` as metadata
on the mirrored object, so a HEAD can confirm an object matches its record
during audits, without changing the unchanged test. This is the maintainer's
call (open question 3 bounds what fits).

### 5.3 Saba

Saba re-exports the request builders as constant aliases
(`saba/src/s3/s3.odin:84-87`). Since the existing builders keep their types it
needs no change; it can add aliases for `s3_put_request_with` and
`s3_head_request_with` when it wants them, and must send every returned header
field unchanged (the signed metadata and checksum values included).
