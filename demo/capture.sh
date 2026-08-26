#!/usr/bin/env bash
set -euo pipefail

if [[ ! -t 0 || ! -t 1 ]]; then
  echo 'SOS_DEMO_TTY_REQUIRED' >&2
  exit 2
fi

: "${SOS_FRESH_CODEX_TASK_FILE:?set to an external public-safe operator instruction}"
: "${SOS_FRESH_CODEX_PROVIDER_APPROVED:?set to 1 only under explicit provider approval}"
: "${SOS_CAPTURE_CANDIDATE:?set exact 40-character candidate SHA}"
: "${SOS_CAPTURE_TREE:?set exact 40-character candidate tree}"
: "${SOS_CAPTURE_WHEEL_SHA256:?set exact wheel SHA-256}"
: "${SOS_CODEX_MODEL:?set the exact admitted Codex model}"

source_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
codex_executable="${SOS_CODEX_EXECUTABLE:-$(command -v codex)}"

demo_root="${TMPDIR:-/tmp}/sos-fresh-agent-capture"
python3 tools/reset_fresh_agent_demo.py "$demo_root"
cd "$demo_root"

echo '$ sos compatibility . --json'
sos compatibility . --json || test "$?" -eq 2
echo '$ sos init --with-codex --primary-authority agents:AGENTS.md .'
sos init --with-codex --primary-authority agents:AGENTS.md .
echo '$ sos preflight . --json'
sos preflight . --json || test "$?" -eq 2
echo '$ sos qualify . --family python.stdlib-unittest'
sos qualify . --family python.stdlib-unittest
echo '$ sos status . --json'
sos status . --json
echo '$ codex exec --ephemeral [public recovery contract]'
python3 "$source_root/demo/capture_fresh_codex.py" \
  --project "$demo_root" \
  --task-file "$SOS_FRESH_CODEX_TASK_FILE" \
  --codex "$codex_executable" \
  --model "$SOS_CODEX_MODEL" \
  --candidate "$SOS_CAPTURE_CANDIDATE" \
  --tree "$SOS_CAPTURE_TREE" \
  --wheel-sha256 "$SOS_CAPTURE_WHEEL_SHA256" \
  --output "$source_root/demo/fresh-codex-receipt.json"
printf '\n# synthetic source change\n' >> src/demo_app.py
echo '$ sos status . --json'
sos status . --json || test "$?" -eq 2
echo '$ sos next-action . --json'
sos next-action . --json || test "$?" -eq 2
