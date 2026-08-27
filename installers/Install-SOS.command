#!/bin/sh
set -eu

MODE="${1:-install}"
PROJECT="${2:-$(pwd)}"
SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)
UV_SOURCE="$SCRIPT_DIR/uv"
case "$(uname -s)" in
  Darwin) UV_SHA256="e8929237934c8679686428f5a7736c7ae7a5fe7a33b0504d1b03446cdbc43c94" ;;
  Linux) UV_SHA256="d381f11517c66523211b0876552ff7dea5c1b4b0f13800571b35225761302fba" ;;
  *) echo "SOS_PLATFORM_UNSUPPORTED: this installer supports Linux and macOS only." >&2; exit 2 ;;
esac
RUNTIME_ROOT="$HOME/.local/share/sigma-operator-stack/runtime"
UV="$RUNTIME_ROOT/bootstrap/uv-0.12.6"
PYTHON_ROOT="$RUNTIME_ROOT/python"
case "$MODE" in
  install|update|remove) ;;
  *)
    echo "SOS_ALPHA_MODE_INVALID: use install, update, or remove." >&2
    exit 2
    ;;
esac

if [ ! -f "$UV_SOURCE" ] || [ -L "$UV_SOURCE" ]; then
  echo "SOS_ALPHA_UV_BUNDLE_INVALID: the checked uv bootstrap binary is missing." >&2
  exit 2
fi
OBSERVED_SHA=$(/usr/bin/shasum -a 256 "$UV_SOURCE" | /usr/bin/awk '{print $1}')
if [ "$OBSERVED_SHA" != "$UV_SHA256" ]; then
  echo "SOS_ALPHA_UV_CHECKSUM_MISMATCH: do not continue with this bundle." >&2
  exit 2
fi

if [ -L "$RUNTIME_ROOT" ]; then
  echo "SOS_ALPHA_RUNTIME_COLLISION: the managed runtime root must not be a symlink." >&2
  exit 2
fi
/bin/mkdir -p "$RUNTIME_ROOT/bootstrap" "$PYTHON_ROOT" "$RUNTIME_ROOT/tools" "$RUNTIME_ROOT/bin"
/bin/cp "$UV_SOURCE" "$UV.tmp"
/bin/chmod 700 "$UV.tmp"
/bin/mv -f "$UV.tmp" "$UV"

export UV_PYTHON_INSTALL_DIR="$PYTHON_ROOT"
export UV_TOOL_DIR="$RUNTIME_ROOT/tools"
export UV_TOOL_BIN_DIR="$RUNTIME_ROOT/bin"
export UV_NO_CONFIG=1

set +e
PYTHON=$("$UV" python find --no-config --managed-python --no-python-downloads 3.12.14 2>/dev/null)
PYTHON_STATUS=$?
set -e
if [ "$PYTHON_STATUS" -ne 0 ]; then
  if [ "$MODE" = "remove" ]; then
    echo "SOS_ALPHA_MANAGED_PYTHON_MISSING: removal cannot acquire a runtime from the network." >&2
    exit 2
  fi
  echo "SOS acquisition: installing the pinned managed Python 3.12.14 runtime."
  "$UV" python install --no-config --no-progress --install-dir "$PYTHON_ROOT" 3.12.14
  PYTHON=$("$UV" python find --no-config --managed-python --no-python-downloads 3.12.14)
fi

set +e
"$PYTHON" "$SCRIPT_DIR/start-sos-alpha" --uv "$UV" --mode "$MODE" "$PROJECT"
STATUS=$?
set -e

if [ "$STATUS" -eq 0 ] && [ "$MODE" = "remove" ]; then
  case "$RUNTIME_ROOT" in
    "$HOME/.local/share/sigma-operator-stack/runtime") /bin/rm -rf "$RUNTIME_ROOT" ;;
    *) echo "SOS_ALPHA_RUNTIME_REMOVE_REFUSED: managed runtime root is not exact." >&2; exit 2 ;;
  esac
fi

exit "$STATUS"
