#!/bin/bash
set -euo pipefail
here=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd -P)
shared=$(CDPATH='' cd -- "$here/../.." && pwd -P)
odin=
only=
while (($#)); do
    case $1 in
        --odin|--only) (($# >= 2)) || exit 2
            if [[ $1 == --odin ]]; then odin=$2; else only=$2; fi
            shift 2 ;;
        *) printf 'Unknown option: %s\n' "$1" >&2; exit 2 ;;
    esac
done
[[ -n $odin ]] || { printf '%s\n' '--odin is required' >&2; exit 2; }
modes=(environment profile partial-env partial-profile token-only-profile oversize ecs imds disabled invalid-relative transport-failure malformed invalid-credentials)
if [[ -n $only ]]; then
    found=false
    for mode in "${modes[@]}"; do [[ $mode != "$only" ]] || found=true; done
    $found || { printf '%s\n' 'Unknown credential fixture' >&2; exit 2; }
fi
work=$(mktemp -d "${TMPDIR:-/tmp}/aws-credentials-offline.XXXXXX")
child=
timer=
cleanup() {
    [[ -z $timer ]] || { kill "$timer" 2>/dev/null || :; wait "$timer" 2>/dev/null || :; }
    [[ -z $child ]] || { kill "$child" 2>/dev/null || :; wait "$child" 2>/dev/null || :; }
    rm -rf -- "$work"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM HUP
"$odin" build "$here/testdata/credentials" "-collection:shared=$shared" -sanitize:address -warnings-as-errors "-out:$work/fixture"
printf '[default]\naws_access_key_id=fixture-key\naws_secret_access_key=fixture-secret\naws_session_token=fixture-session\n' > "$work/profile"
printf '[default]\naws_access_key_id=fixture-key\n' > "$work/partial-profile"
printf '[default]\naws_session_token=fixture-session\n' > "$work/token-only-profile"
dd if=/dev/zero of="$work/oversize" bs=1024 count=1024 2>/dev/null
for mode in "${modes[@]}"; do
    [[ -z $only || $only == "$mode" ]] || continue
    fixture_env=("PATH=${PATH:-/usr/bin:/bin}" "HOME=$work" "TMPDIR=$work" "AWS_SHARED_CREDENTIALS_FILE=$work/absent" AWS_EC2_METADATA_DISABLED=false)
    case $mode in
        environment) fixture_env+=(AWS_ACCESS_KEY_ID=fixture-key AWS_SECRET_ACCESS_KEY=fixture-secret AWS_SESSION_TOKEN=fixture-session) ;;
        partial-env) fixture_env+=(AWS_ACCESS_KEY_ID=fixture-key) ;;
        profile|partial-profile|token-only-profile|oversize) fixture_env+=("AWS_SHARED_CREDENTIALS_FILE=$work/$mode") ;;
    esac
    case $mode in
        imds) ;;
        disabled) fixture_env+=(AWS_EC2_METADATA_DISABLED=true) ;;
        invalid-relative) fixture_env+=($'AWS_CONTAINER_CREDENTIALS_RELATIVE_URI=//invalid\npath') ;;
        *) fixture_env+=(AWS_CONTAINER_CREDENTIALS_RELATIVE_URI=/v2/credentials/fixture) ;;
    esac
    env -i "${fixture_env[@]}" "$work/fixture" "$mode" & child=$!
    (
        sleeper=
        trap '[[ -z $sleeper ]] || { kill "$sleeper" 2>/dev/null || :; wait "$sleeper" 2>/dev/null || :; }; exit' TERM INT HUP
        sleep 5 & sleeper=$!
        wait "$sleeper"
        sleeper=
        kill -KILL "$child" 2>/dev/null || :
    ) & timer=$!
    code=0
    wait "$child" || code=$?
    child=
    kill "$timer" 2>/dev/null || :
    wait "$timer" 2>/dev/null || :
    timer=
    ((code == 0)) || exit "$code"
done
printf '%s\n' 'Credential resolver fixtures passed; synthetic files/environment and fake HTTP only'
