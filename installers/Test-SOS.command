#!/bin/sh
set -eu
PROJECT="${1:-$(pwd)}"
if ! UV="$(command -v uv)"; then
  echo "SOS_ALPHA_UV_MISSING: install uv from its official distribution." >&2
  exit 2
fi
exec python3 "$(dirname "$0")/native-smoke" --uv "$UV" "$PROJECT"
