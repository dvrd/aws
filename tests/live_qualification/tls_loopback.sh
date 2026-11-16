#!/bin/bash
set -euo pipefail
umask 077
here=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd -P)
odin='' shared='' report='' mode=''
while (($#)); do
    (($#>=2)) || exit 2
    case $1 in --odin) odin=$2;; --shared|--shared-root) shared=$2;; --report) report=$2;; --mode) mode=$2;; *) exit 2;; esac
    shift 2
done
[[ -n $odin && -n $shared && -n $report && ( $mode == observer || $mode == default ) ]] || exit 2
work=$(mktemp -d "${TMPDIR:-/tmp}/aws-tls-observation.XXXXXX")
child='' timer='' peer='' peer_timer=''
stop_job() { [[ -z $1 ]] || { kill -TERM -- "-$1" 2>/dev/null || :; kill -KILL -- "-$1" 2>/dev/null || :; wait "$1" 2>/dev/null || :; }; }
cleanup() { trap - EXIT; for pid in "$child" "$timer" "$peer" "$peer_timer"; do stop_job "$pid"; done; rm -rf -- "$work"; }
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' HUP TERM
set -m
bounded() {
    local seconds=$1 code=0
    shift
    "$@" & child=$!
    (sleep "$seconds"; kill -TERM -- "-$child" 2>/dev/null || :; sleep 1; kill -KILL -- "-$child" 2>/dev/null || :) & timer=$!
    wait "$child" || code=$?
    child=''
    stop_job "$timer"; timer=''
    return "$code"
}
source="$here/production_get_probe"
if [[ $mode == observer ]]; then
    source="$work/source"; mkdir "$source"
    cp "$here/get_observation.odin" "$source/get_observation.odin"
    cp "$here/observer_probe/main.odin" "$source/main.odin"
fi
source_hash=$(shasum -a 256 "$here/get_observation.odin"); source_hash=${source_hash%% *}
compile=("$odin" build "$source" "-collection:shared=$shared" -thread-count:1 -vet -warnings-as-errors -sanitize:address "-out:$work/probe")
bounded 120 "${compile[@]}" > "$work/build.log" 2>&1
bounded 120 "$odin" build "$here/../testdata/tls_observer" -thread-count:1 -vet -warnings-as-errors -sanitize:address "-out:$work/peer" > "$work/peer-build.log" 2>&1
"$work/peer" > "$work/peer.out" 2> "$work/peer.err" & peer=$!
(sleep 12; kill -KILL -- "-$peer" 2>/dev/null || :) & peer_timer=$!
port=''
for ((ready=0;ready<250;ready++)); do
    if IFS= read -r line < "$work/peer.out" && [[ $line == 'ready '* ]]; then port=${line#ready }; break; fi
    kill -0 "$peer" 2>/dev/null || { cat "$work/peer.err" >&2; exit 1; }
    sleep .02
done
[[ $port =~ ^[0-9]+$ ]]
url="https://127.0.0.1:$port"; [[ $mode != observer ]] || url+=/
code=0
bounded 10 "$work/probe" "$url" > "$work/native.out" 2> "$work/native.err" || code=$?
wait "$peer"; peer=''
stop_job "$peer_timer"; peer_timer=''
[[ $code == 0 && ! -s $work/native.err && ! -s $work/peer.err ]]
if [[ $mode == observer ]]; then jq -e '.==1' "$work/native.out" > /dev/null
else jq -e '.native_default_get==true and .peer_closed_during_tls==true and .body_bytes==0' "$work/native.out" > /dev/null; fi
tail -n 1 "$work/peer.out" | jq -e '.accepted_connections==1 and .tls_client_hello_seen==true' > /dev/null
current_hash=$(shasum -a 256 "$here/get_observation.odin"); [[ ${current_hash%% *} == "$source_hash" ]]
compiler_sha=$(shasum -a 256 "$odin"); binary_sha=$(shasum -a 256 "$work/probe")
command_json=$(printf '%s\n' "${compile[@]}" | jq -R -s 'split("\n")[:-1]')
if [[ $mode == observer ]]; then
    jq -n --arg source "$source_hash" --arg binary "${binary_sha%% *}" --argjson command "$command_json" '{passed:true,source_sha256:$source,source_unchanged:true,provider_calls:false,credentials_used:false,native_executor_calls:1,owned_connections:1,tls_client_hello:true,stderr_empty:true,child_reaped:true,binary_sha256:$binary,build_command:$command,limits:"ClientHello and input/trust path only; no successful TLS handshake."}' > "$report"
else
    jq -n --arg compiler "${compiler_sha%% *}" --arg binary "${binary_sha%% *}" '{owned_loopback_only:true,provider_calls:false,credentials:"public synthetic strings only",native_exit:0,accepted_connections:1,tls_client_hello_seen:true,compiler_sha256:$compiler,probe_sha256:$binary,passed:true}' > "$report"
fi
jq -c . "$report"
