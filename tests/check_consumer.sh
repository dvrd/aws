#!/usr/bin/env bash
set -euo pipefail
root=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
dependencies=${WEBTOOLS_SHARED:-$HOME/dev/oss/Odin/shared}
compiler=${ODIN_BIN:-${ODIN:-odin}}
command -v "$compiler" >/dev/null || { printf '%s\n' 'Set ODIN_BIN to a matching Odin compiler' >&2; exit 2; }
work=$(mktemp -d "${TMPDIR:-/tmp}/aws-consumer.XXXXXX")
trap 'rm -rf -- "$work"' EXIT
trap 'exit 130' INT
trap 'exit 143' TERM HUP
mkdir "$work/shared" "$work/consumer"
for package in aws surf http websocket async; do
    source=$dependencies/$package
    [[ "$package" != aws ]] || source=$root/src
    mkdir "$work/shared/$package"
    tar -C "$source" --exclude=.git --exclude=__pycache__ --exclude='*.pyc' -cf - . |
        tar -C "$work/shared/$package" -xf -
done
cat > "$work/consumer/main.odin" <<'ODIN'
package main
import aws "shared:aws"
main :: proc() {
    assert(aws.s3_config_error({bucket="examplebucket", region="us-east-1"}) == "")
    assert(aws.ses_config_valid({region="us-east-1", sender="from@example.test", recipient="to@example.test"}))
    _, error := aws.read_limited("", 65536)
    assert(error.kind == .Invalid_Input)
}
ODIN
"$compiler" build "$work/consumer" -thread-count:1 -warnings-as-errors \
    "-collection:shared=$work/shared" -out:"$work/consumer.bin"
"$work/consumer.bin"
printf '%s\n' 'AWS isolated vendored consumer: build and execution passed (offline)'
