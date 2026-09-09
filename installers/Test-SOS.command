#!/bin/sh
set -eu
PROJECT="${1:-$(pwd)}"
if [ "$#" -gt 0 ]; then shift; fi
SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)
# Same verified route as maintenance; never discover an executable through PATH
# or assume that a shared predecessor environment still exists.
exec "$SCRIPT_DIR/Install-SOS.command" test "$PROJECT" "$@"
