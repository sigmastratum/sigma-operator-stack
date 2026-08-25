#!/usr/bin/env bash
set -euo pipefail

if [[ ! -t 0 || ! -t 1 ]]; then
  echo 'SOS_DEMO_TTY_REQUIRED' >&2
  exit 2
fi

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
printf '\n# synthetic source change\n' >> src/demo_app.py
echo '$ sos status . --json'
sos status . --json || test "$?" -eq 2
echo '$ sos next-action . --json'
sos next-action . --json || test "$?" -eq 2
