#!/usr/bin/env bash
# Independent OpenSSL calculation using public synthetic AWS example credentials.
set -euo pipefail
work=$(mktemp -d "${TMPDIR:-/tmp}/aws-signatures.XXXXXX")
trap 'rm -rf -- "$work"' EXIT
trap 'exit 130' INT
trap 'exit 143' TERM HUP
secret='wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY'
stamp=20130524T000000Z
region=us-east-1
host=examplebucket.s3.us-east-1.amazonaws.com
hash_file() { openssl dgst -sha256 "$1" | awk '{print $NF}'; }
hmac_hex() { printf '%s' "$2" | openssl dgst -sha256 -mac HMAC -macopt "hexkey:$1" | awk '{print $NF}'; }
signature() {
    local service=${1:-s3} key part
    key=$(printf 'AWS4%s' "$secret" | od -An -v -tx1 | tr -d ' \n')
    for part in 20130524 "$region" "$service" aws4_request; do
        key=$(hmac_hex "$key" "$part")
    done
    printf 'AWS4-HMAC-SHA256\n%s\n20130524/%s/%s/aws4_request\n%s' \
        "$stamp" "$region" "$service" "$(hash_file "$work/canonical")" > "$work/to-sign"
    openssl dgst -sha256 -mac HMAC -macopt "hexkey:$key" "$work/to-sign" | awk '{print $NF}'
}
for method in PUT DELETE HEAD; do
    case $method in
        PUT) payload=payload; expected=ed63c9a16fbbdfc2127f409b79ffce52deaaea62ab8d39048ca5fc8d256e5b26 ;;
        DELETE) payload=; expected=703c365c9e031e61271a08e36dc622e00f12493b12901d9cf725e8f7f01f942b ;;
        HEAD) payload=; expected=fdd51dae18ee3b7b2f9a6fe56ccec529798be849c3d8f94093884fec89aaf4d2 ;;
    esac
    printf '%s' "$payload" > "$work/payload"
    digest=$(hash_file "$work/payload")
    printf '%s\n/a%%20b/c%%2Bd\n\nhost:%s\nx-amz-content-sha256:%s\nx-amz-date:%s\nx-amz-security-token:fixture/token+value\n\nhost;x-amz-content-sha256;x-amz-date;x-amz-security-token\n%s' \
        "$method" "$host" "$digest" "$stamp" "$digest" > "$work/canonical"
    actual=$(signature)
    [[ $actual == "$expected" ]] || { printf 'Signature mismatch: %s\n' "$method" >&2; exit 1; }
    printf '%s %s\n' "$method" "$actual"
done
query='X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=AKIAIOSFODNN7EXAMPLE%2F20130524%2Fus-east-1%2Fs3%2Faws4_request&X-Amz-Date=20130524T000000Z&X-Amz-Expires=86400&X-Amz-SignedHeaders=host'
printf 'GET\n/test.txt\n%s\nhost:examplebucket.s3.amazonaws.com\n\nhost\nUNSIGNED-PAYLOAD' "$query" > "$work/canonical"
actual=$(signature)
[[ $actual == aeeed9bbccd4d02ee5c0109b86d86835f995330da4c265957d157751f604d404 ]] || { printf '%s\n' 'Presign mismatch' >&2; exit 1; }
printf 'GET presign %s\n' "$actual"
printf '%s' '{"fixture":true}' > "$work/payload"
printf 'POST\n/v2/email/outbound-emails\n\ncontent-type:application/json\nhost:email.us-east-1.amazonaws.com\nx-amz-date:%s\n\ncontent-type;host;x-amz-date\n%s' \
    "$stamp" "$(hash_file "$work/payload")" > "$work/canonical"
printf 'SES POST %s\n' "$(signature ses)"
