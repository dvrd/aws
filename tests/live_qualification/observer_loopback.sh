#!/bin/sh
set -eu
here=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd -P)
exec "$here/tls_loopback.sh" --mode observer "$@"
