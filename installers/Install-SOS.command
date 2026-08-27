#!/bin/sh
set -eu

MODE="${1:-install}"
PROJECT="${2:-$(pwd)}"
case "$MODE" in
  install|update|remove) ;;
  *)
    echo "SOS_ALPHA_MODE_INVALID: use install, update, or remove." >&2
    exit 2
    ;;
esac

if ! command -v python3 >/dev/null 2>&1; then
  echo "SOS_ALPHA_PYTHON_MISSING: install Python 3.11 or 3.12 from python.org." >&2
  exit 2
fi

exec python3 "$(dirname "$0")/start-sos-alpha" --mode "$MODE" "$PROJECT"
