#!/bin/sh
set -eu

MODE="${1:-install}"
PROJECT="${2:-$(pwd)}"
PRIMARY_AUTHORITY=""
MAINTENANCE_BINDING=""
RESUME_CONFIRMATION_SEED=""
EXPECTED_PLAN_DIGEST=""
CLIENT="codex"
CLIENT_SEEN=""
CONTROLLER_PYTHON=""
CONTROLLER_PYTHON_SHA256=""
if [ "$#" -ge 2 ]; then shift 2; else shift "$#"; fi
while [ "$#" -gt 0 ]; do
  case "$1" in
    --controller-python)
      [ "$#" -ge 2 ] && [ -z "$CONTROLLER_PYTHON" ] && [ -n "$2" ] || exit 2
      CONTROLLER_PYTHON="$2"
      shift 2
      ;;
    --controller-python-sha256)
      [ "$#" -ge 2 ] && [ -z "$CONTROLLER_PYTHON_SHA256" ] && [ -n "$2" ] || exit 2
      CONTROLLER_PYTHON_SHA256="$2"
      shift 2
      ;;
    --primary-authority)
      [ "$#" -ge 2 ] && [ -z "$PRIMARY_AUTHORITY" ] && [ -n "$2" ] || {
        echo "SOS_ALPHA_ARGUMENTS_INVALID: invalid --primary-authority." >&2
        exit 2
      }
      PRIMARY_AUTHORITY="$2"
      shift 2
      ;;
    --maintenance-release-binding-json)
      [ "$#" -ge 2 ] && [ -z "$MAINTENANCE_BINDING" ] && [ -n "$2" ] || {
        echo "SOS_ALPHA_ARGUMENTS_INVALID: invalid --maintenance-release-binding-json." >&2
        exit 2
      }
      MAINTENANCE_BINDING="$2"
      shift 2
      ;;
    --resume-confirmation-seed)
      [ "$#" -ge 2 ] && [ -z "$RESUME_CONFIRMATION_SEED" ] && [ -n "$2" ] || {
        echo "SOS_ALPHA_ARGUMENTS_INVALID: invalid --resume-confirmation-seed." >&2
        exit 2
      }
      RESUME_CONFIRMATION_SEED="$2"
      shift 2
      ;;
    --expected-plan-digest)
      [ "$#" -ge 2 ] && [ -z "$EXPECTED_PLAN_DIGEST" ] && [ -n "$2" ] || {
        echo "SOS_ALPHA_ARGUMENTS_INVALID: invalid --expected-plan-digest." >&2
        exit 2
      }
      EXPECTED_PLAN_DIGEST="$2"
      shift 2
      ;;
    --client)
      [ "$#" -ge 2 ] && [ -z "$CLIENT_SEEN" ] || {
        echo "SOS_ALPHA_ARGUMENTS_INVALID: invalid or duplicate --client." >&2
        exit 2
      }
      case "$2" in
        codex|claude-code) CLIENT="$2" ;;
        *) echo "SOS_ALPHA_ARGUMENTS_INVALID: --client must be codex or claude-code." >&2; exit 2 ;;
      esac
      CLIENT_SEEN="yes"
      shift 2
      ;;
    *)
      echo "SOS_ALPHA_ARGUMENTS_INVALID: use the exact arguments from the verified public release route." >&2
      exit 2
      ;;
  esac
done
SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)
UV_SOURCE="$SCRIPT_DIR/uv"
case "$(uname -s)" in
  Darwin) UV_SHA256="e8929237934c8679686428f5a7736c7ae7a5fe7a33b0504d1b03446cdbc43c94" ;;
  Linux) UV_SHA256="d381f11517c66523211b0876552ff7dea5c1b4b0f13800571b35225761302fba" ;;
  *) echo "SOS_PLATFORM_UNSUPPORTED: this installer supports Linux and macOS only." >&2; exit 2 ;;
esac
CONTROLLER_ROOT=""
CONTROLLER_RUNNING=0
CONTROLLER_PID=""
stop_controller() {
  trap '' INT HUP TERM
  if [ -n "$CONTROLLER_PID" ]; then
    kill -TERM "$CONTROLLER_PID" 2>/dev/null || true
    set +e
    wait "$CONTROLLER_PID"
    STOP_STATUS=$?
    set -e
    if [ "$STOP_STATUS" -ne 3 ] && [ "$STOP_STATUS" -lt 128 ]; then
      CONTROLLER_RUNNING=0
    fi
  fi
  exit "$1"
}
cleanup_controller() {
  if [ "$CONTROLLER_RUNNING" -ne 0 ]; then
    echo "SOS_ALPHA_CONTROLLER_RETAINED: process termination is not confirmed." >&2
    return
  fi
  case "$CONTROLLER_ROOT" in
    /tmp/sos-controller.*|/private/tmp/sos-controller.*) /bin/rm -rf -- "$CONTROLLER_ROOT" ;;
  esac
}
case "$MODE" in
  install|detach|update|remove|recover|test) ;;
  *)
    echo "SOS_ALPHA_MODE_INVALID: use install, detach, update, remove, recover, or test." >&2
    exit 2
    ;;
esac
if [ -n "$PRIMARY_AUTHORITY" ] && [ "$MODE" != "install" ]; then
  echo "SOS_ALPHA_ARGUMENTS_INVALID: --primary-authority is valid only with install." >&2
  exit 2
fi
if { [ -n "$RESUME_CONFIRMATION_SEED" ] && [ -z "$EXPECTED_PLAN_DIGEST" ]; } ||
   { [ -z "$RESUME_CONFIRMATION_SEED" ] && [ -n "$EXPECTED_PLAN_DIGEST" ]; }; then
  echo "SOS_ALPHA_CONFIRMATION_HANDOFF_INVALID: use the seed and plan digest from the same preview." >&2
  exit 2
fi
if [ -n "$RESUME_CONFIRMATION_SEED" ] && [ "$MODE" != "install" ]; then
  echo "SOS_ALPHA_CONFIRMATION_HANDOFF_INVALID: confirmation resume is valid only for install." >&2
  exit 2
fi

if [ ! -f "$UV_SOURCE" ] || [ -L "$UV_SOURCE" ]; then
  echo "SOS_ALPHA_UV_BUNDLE_INVALID: the checked uv bootstrap binary is missing." >&2
  exit 2
fi
OBSERVED_SHA=$(/usr/bin/shasum -a 256 "$UV_SOURCE" | /usr/bin/awk '{print $1}')
if [ "$OBSERVED_SHA" != "$UV_SHA256" ]; then
  echo "SOS_ALPHA_UV_CHECKSUM_MISMATCH: do not continue with this bundle." >&2
  exit 2
fi

# Every mode bootstraps outside both shared and project-owned runtimes. A fresh
# a6 installation must remain serviceable when no shared a5 runtime exists.
case "$(uname -s)" in Darwin) CONTROLLER_BASE="/private/tmp" ;; *) CONTROLLER_BASE="/tmp" ;; esac
CONTROLLER_ROOT=$(/usr/bin/mktemp -d "$CONTROLLER_BASE/sos-controller.XXXXXX")
trap cleanup_controller EXIT
trap 'stop_controller 130' INT
trap 'stop_controller 143' HUP TERM
# Conservatively retain bootstrap on interruption during acquisition as well.
CONTROLLER_RUNNING=1
RUNTIME_ROOT="$CONTROLLER_ROOT/runtime"
UV="$RUNTIME_ROOT/bootstrap/uv-0.12.6"
PYTHON_ROOT="$RUNTIME_ROOT/python"
echo "SOS preparation: disposable checked controller outside project and installed runtimes."
/bin/mkdir -p "$RUNTIME_ROOT/bootstrap" "$PYTHON_ROOT" "$RUNTIME_ROOT/tools" "$RUNTIME_ROOT/bin"
/bin/cp "$UV_SOURCE" "$UV"
/bin/chmod 700 "$UV"
export UV_NO_CACHE=1
export PYTHONDONTWRITEBYTECODE=1

export UV_PYTHON_INSTALL_DIR="$PYTHON_ROOT"
export UV_TOOL_DIR="$RUNTIME_ROOT/tools"
export UV_TOOL_BIN_DIR="$RUNTIME_ROOT/bin"
export UV_PYTHON_BIN_DIR="$RUNTIME_ROOT/bin"
export UV_CACHE_DIR="$CONTROLLER_ROOT/cache"
export UV_NO_CONFIG=1

if [ -n "$CONTROLLER_PYTHON" ] || [ -n "$CONTROLLER_PYTHON_SHA256" ]; then
  # Explicit offline controller: caller verifies provenance independently. The
  # supplied digest binds consistency; it is not an authenticity certificate.
  case "$MODE" in remove|detach|recover|test) ;; *) exit 2 ;; esac
  case "$CONTROLLER_PYTHON" in /*) ;; *) exit 2 ;; esac
  [ -f "$CONTROLLER_PYTHON" ] && [ ! -L "$CONTROLLER_PYTHON" ] || exit 2
  [ "${#CONTROLLER_PYTHON_SHA256}" -eq 64 ] || exit 2
  case "$CONTROLLER_PYTHON_SHA256" in *[!0-9a-f]*) exit 2 ;; esac
  PYTHON=$(CDPATH= cd -- "$(dirname -- "$CONTROLLER_PYTHON")" && printf '%s/%s\n' "$(pwd -P)" "$(basename -- "$CONTROLLER_PYTHON")")
  case "$PYTHON" in */project-runtimes/*) echo "SOS_ALPHA_CONTROLLER_PYTHON_INVALID" >&2; exit 2 ;; esac
  [ "$(/usr/bin/shasum -a 256 "$PYTHON" | /usr/bin/awk '{print $1}')" = "$CONTROLLER_PYTHON_SHA256" ] || {
    echo "SOS_ALPHA_CONTROLLER_PYTHON_INVALID" >&2; exit 2;
  }
  [ "$("$PYTHON" -I -S -B --version)" = "Python 3.12.14" ] || exit 2
  "$PYTHON" -I -S -B -c 'import os,sys; paths=[sys.prefix,sys.base_prefix,*sys.path]; sys.exit(2 if any("project-runtimes" in os.path.realpath(p).split(os.sep) for p in paths if p) else 0)' || exit 2
  echo "SOS preparation: explicitly checked offline controller; no Python acquisition."
else
  set +e
  PYTHON=$("$UV" python find --no-config --managed-python --no-python-downloads 3.12.14 2>/dev/null)
  PYTHON_STATUS=$?
  set -e
  if [ "$PYTHON_STATUS" -ne 0 ]; then
    echo "SOS acquisition: installing the pinned managed Python 3.12.14 runtime."
    "$UV" python install --no-config --no-progress --no-bin --no-registry --install-dir "$PYTHON_ROOT" 3.12.14
    PYTHON=$("$UV" python find --no-config --managed-python --no-python-downloads 3.12.14)
  fi
fi

set -- "$PYTHON" "$SCRIPT_DIR/start-sos-alpha" --uv "$UV" --mode "$MODE" --client "$CLIENT"
if [ -n "$MAINTENANCE_BINDING" ]; then
  set -- "$@" --maintenance-release-binding-json "$MAINTENANCE_BINDING"
fi
if [ -n "$PRIMARY_AUTHORITY" ]; then
  set -- "$@" --primary-authority "$PRIMARY_AUTHORITY"
fi
if [ -n "$RESUME_CONFIRMATION_SEED" ]; then
  set -- "$@" --resume-confirmation-seed "$RESUME_CONFIRMATION_SEED"
fi
if [ -n "$EXPECTED_PLAN_DIGEST" ]; then
  set -- "$@" --expected-plan-digest "$EXPECTED_PLAN_DIGEST"
fi
set -- "$@" "$PROJECT"

set +e
CONTROLLER_RUNNING=1
exec 3<&0
"$@" <&3 &
CONTROLLER_PID=$!
wait "$CONTROLLER_PID"
STATUS=$?
CONTROLLER_PID=""
exec 3<&-
if [ "$STATUS" -ne 3 ] && [ "$STATUS" -lt 128 ]; then
  CONTROLLER_RUNNING=0
fi
if [ "$STATUS" -eq 3 ]; then STATUS=2; fi
set -e

exit "$STATUS"
