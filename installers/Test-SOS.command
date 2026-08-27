#!/bin/sh
set -eu
PROJECT="${1:-$(pwd)}"
exec python3 "$(dirname "$0")/native-smoke" "$PROJECT"
