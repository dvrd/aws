package aws

import "core:crypto/hash"
import "core:crypto/hmac"
import "core:mem"
import "core:strings"

// The SHA-256 of an empty payload, as SigV4 writes it.
@(private)
EMPTY_PAYLOAD_SHA256 :: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

// One header that is signed, with a lower-case name and its value as sent.
@(private)
Sigv4_Header :: struct {
	name, value: string,
}

// What SigV4 signs. headers must be sorted by name; path and query are already
// URI-encoded the way they are sent. payload_hash is the hex SHA-256 of the
// payload, or "UNSIGNED-PAYLOAD".
@(private)
Sigv4_Input :: struct {
	service, region, method, path, query: string,
	headers:                              []Sigv4_Header,
	payload_hash:                         string,
	stamp:                                string, // YYYYMMDDTHHMMSSZ
}

// Writes the 64-character lower-case hex signature into signature; the caller
// formats the Authorization header or the X-Amz-Signature parameter. The
// canonical request is fed into a SHA-256 context piece by piece and never built
// as a string. The secret and the keys derived from it stay on the stack and are
// erased before returning. A stamp shorter than its date leaves signature zeroed.
@(private)
sigv4_sign :: proc(secret: string, input: Sigv4_Input, signature: ^[64]u8) {
	signature^ = {}
	if len(input.stamp) < 8 {
		return
	}
	when ODIN_DEBUG {
		for i in 1 ..< len(input.headers) {
			assert(input.headers[i - 1].name < input.headers[i].name, "SigV4 headers must be sorted by name")
		}
	}

	hasher: hash.Context
	hash.init(&hasher, .SHA256)
	sigv4_update(&hasher, input.method, "\n", input.path, "\n", input.query, "\n")
	for header in input.headers {
		sigv4_update(&hasher, header.name, ":", header.value, "\n")
	}
	sigv4_update(&hasher, "\n")
	for header, i in input.headers {
		if i > 0 {
			sigv4_update(&hasher, ";")
		}
		sigv4_update(&hasher, header.name)
	}
	sigv4_update(&hasher, "\n", input.payload_hash)
	canonical_digest: [32]u8
	hash.final(&hasher, canonical_digest[:])

	scope := [?]string{input.stamp[:8], "/", input.region, "/", input.service, "/aws4_request"}
	tag: [32]u8
	sigv4_signature_from_digest(secret, input.region, input.service, input.stamp, scope[:], &canonical_digest, &tag)
	sigv4_hex(tag[:], signature[:])
}

// Writes the credential scope, YYYYMMDD/region/service/aws4_request, into builder.
@(private)
sigv4_scope_write :: proc(builder: ^strings.Builder, stamp, region, service: string) {
	strings.write_string(builder, stamp[:8])
	strings.write_byte(builder, '/')
	strings.write_string(builder, region)
	strings.write_byte(builder, '/')
	strings.write_string(builder, service)
	strings.write_string(builder, "/aws4_request")
}

// The bytes the credential scope takes; see sigv4_scope_write.
@(private)
sigv4_scope_size :: proc(region, service: string) -> int {
	return 8 + 1 + len(region) + 1 + len(service) + len("/aws4_request")
}

// Writes "Authorization: AWS4-HMAC-SHA256 Credential=<access key>/<scope>,
// SignedHeaders=<signed>, Signature=<signature>" into builder.
@(private)
sigv4_authorization_write :: proc(
	builder: ^strings.Builder,
	access_key, stamp, region, service, signed: string,
	signature: ^[64]u8,
) {
	strings.write_string(builder, "Authorization: AWS4-HMAC-SHA256 Credential=")
	strings.write_string(builder, access_key)
	strings.write_byte(builder, '/')
	sigv4_scope_write(builder, stamp, region, service)
	strings.write_string(builder, ", SignedHeaders=")
	strings.write_string(builder, signed)
	strings.write_string(builder, ", Signature=")
	strings.write_bytes(builder, signature[:])
}

// The bytes sigv4_authorization_write takes.
@(private)
sigv4_authorization_size :: proc(access_key, region, service, signed: string) -> int {
	size := len("Authorization: AWS4-HMAC-SHA256 Credential=") + len(access_key) + 1
	size += sigv4_scope_size(region, service) + len(", SignedHeaders=") + len(signed)
	return size + len(", Signature=") + 64
}

// Writes the lower-case hex of bytes into out, which holds twice as many bytes.
@(private)
sigv4_hex :: proc(bytes: []u8, out: []u8) {
	digits := "0123456789abcdef"
	for b, i in bytes {
		out[2 * i] = digits[b >> 4]
		out[2 * i + 1] = digits[b & 15]
	}
}

@(private = "file")
sigv4_update :: proc(hasher: ^hash.Context, parts: ..string) {
	for part in parts {
		hash.update(hasher, transmute([]u8)part)
	}
}

// The shared tail of every signer: derives the signing key from secret, then
// HMACs the string to sign, "AWS4-HMAC-SHA256\n" stamp "\n" scope "\n" and the hex
// of canonical_digest, into tag. scope is given in pieces that are signed in
// order. The secret and every derived key stay on the stack and are erased before
// returning, so no copy outlives the caller's credentials.
@(private)
sigv4_signature_from_digest :: proc(
	secret, region, service, stamp: string,
	scope: []string,
	canonical_digest: ^[32]u8,
	tag: ^[32]u8,
) {
	// "AWS4" + secret is the first HMAC key. HMAC replaces a key longer than one
	// SHA-256 block with its digest, so a long secret is hashed here, not copied.
	seed: [64]byte
	key, next: [32]byte
	mac: hmac.Context
	defer {
		mem.zero_explicit(&seed, size_of(seed))
		mem.zero_explicit(&key, size_of(key))
		mem.zero_explicit(&next, size_of(next))
		mem.zero_explicit(&mac, size_of(mac))
	}
	prefix := "AWS4"
	seed_size := len(prefix) + len(secret)
	if seed_size <= len(seed) {
		copy(seed[:], prefix)
		copy(seed[len(prefix):], secret)
	} else {
		hasher: hash.Context
		hash.init(&hasher, .SHA256)
		hash.update(&hasher, transmute([]byte)prefix)
		hash.update(&hasher, transmute([]byte)secret)
		hash.final(&hasher, seed[:32])
		mem.zero_explicit(&hasher, size_of(hasher))
		seed_size = 32
	}
	hmac.sum(.SHA256, key[:], transmute([]byte)stamp[:8], seed[:seed_size])

	for text in ([]string{region, service, "aws4_request"}) {
		hmac.sum(.SHA256, next[:], transmute([]byte)text, key[:])
		key = next
	}

	digest_hex: [64]u8
	sigv4_hex(canonical_digest[:], digest_hex[:])
	hmac.init(&mac, .SHA256, key[:])
	hmac.update(&mac, transmute([]byte)string("AWS4-HMAC-SHA256\n"))
	hmac.update(&mac, transmute([]byte)stamp)
	hmac.update(&mac, transmute([]byte)string("\n"))
	for piece in scope {
		hmac.update(&mac, transmute([]byte)piece)
	}
	hmac.update(&mac, transmute([]byte)string("\n"))
	hmac.update(&mac, digest_hex[:])
	hmac.final(&mac, tag[:])
}
