#!/usr/bin/env bash
set -euo pipefail

if [[ ! -t 0 || ! -t 1 ]]; then
  echo 'SOS_DEMO_TTY_REQUIRED' >&2
  exit 2
fi

: "${SOS_CAPTURE_PROJECT:?set to an already URL-only-installed synthetic project}"
: "${SOS_FRESH_CODEX_TASK_FILE:?set to an external public-safe recovery instruction}"
: "${SOS_FRESH_CODEX_PROVIDER_APPROVED:?set to 1 only under explicit provider approval}"
: "${SOS_CAPTURE_CANDIDATE:?set exact 40-character candidate SHA}"
: "${SOS_CAPTURE_TREE:?set exact 40-character candidate tree}"
: "${SOS_CAPTURE_WHEEL_SHA256:?set exact wheel SHA-256}"
: "${SOS_CODEX_MODEL:?set the exact admitted Codex model}"
: "${SOS_CAPTURE_RECOVERY_OUTPUT:?set an external path for the content-safe recovery receipt}"

source_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
codex_executable="${SOS_CODEX_EXECUTABLE:-$(command -v codex)}"

demo_root="$(cd "$SOS_CAPTURE_PROJECT" && pwd -P)"
echo '$ codex exec --ephemeral [fresh read-only SOS recovery]'
python3 "$source_root/demo/capture_fresh_codex.py" \
  --project "$demo_root" \
  --task-file "$SOS_FRESH_CODEX_TASK_FILE" \
  --codex "$codex_executable" \
  --model "$SOS_CODEX_MODEL" \
  --candidate "$SOS_CAPTURE_CANDIDATE" \
  --tree "$SOS_CAPTURE_TREE" \
  --wheel-sha256 "$SOS_CAPTURE_WHEEL_SHA256" \
  --output "$SOS_CAPTURE_RECOVERY_OUTPUT"
