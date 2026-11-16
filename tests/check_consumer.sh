#!/usr/bin/env bash
set -euo pipefail
root=$(CDPATH='' cd -- "$(dirname -- "$0")/../.." && pwd)
compiler=${ODIN_BIN:-${ODIN:-odin}}
command -v "$compiler" >/dev/null || { printf '%s\n' 'Set ODIN_BIN to a matching Odin compiler' >&2; exit 2; }
work=$(mktemp -d "${TMPDIR:-/tmp}/aws-consumer.XXXXXX")
trap 'rm -rf -- "$work"' EXIT
trap 'exit 130' INT
trap 'exit 143' TERM HUP
mkdir "$work/shared" "$work/consumer"
for package in aws files surf http ascii websocket async; do
    mkdir "$work/shared/$package"
    tar -C "$root/$package" --exclude=.git --exclude=__pycache__ --exclude='*.pyc' -cf - . |
        tar -C "$work/shared/$package" -xf -
done
cat > "$work/consumer/main.odin" <<'ODIN'
package main
import aws "shared:aws"
import files "shared:files"
main :: proc() {
    assert(aws.s3_config_error({bucket="examplebucket", region="us-east-1"}) == "")
    assert(aws.ses_config_valid({region="us-east-1", sender="from@example.test", recipient="to@example.test"}))
    _, error := files.read_limited("", 65536)
    assert(error.kind == .Invalid_Input)
}
ODIN
"$compiler" build "$work/consumer" -thread-count:1 -warnings-as-errors \
    "-collection:shared=$work/shared" -out:"$work/consumer.bin"
"$work/consumer.bin"
printf '%s\n' 'AWS isolated vendored consumer: build and execution passed (offline)'
