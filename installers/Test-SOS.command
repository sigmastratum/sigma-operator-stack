#!/bin/sh
set -eu
PROJECT="${1:-$(pwd)}"
RUNTIME_ROOT="$HOME/.local/share/sigma-operator-stack/runtime"
UV="$RUNTIME_ROOT/bootstrap/uv-0.12.6"
if [ ! -x "$UV" ]; then
  echo "SOS_ALPHA_RUNTIME_MISSING: run Install-SOS.command install first." >&2
  exit 2
fi
export UV_PYTHON_INSTALL_DIR="$RUNTIME_ROOT/python"
export UV_TOOL_DIR="$RUNTIME_ROOT/tools"
export UV_TOOL_BIN_DIR="$RUNTIME_ROOT/bin"
export UV_NO_CONFIG=1
PYTHON=$(
  "$UV" python find --offline --no-config --managed-python --no-python-downloads 3.12.14
)
exec "$PYTHON" "$(dirname "$0")/native-smoke" --uv "$UV" "$PROJECT"
