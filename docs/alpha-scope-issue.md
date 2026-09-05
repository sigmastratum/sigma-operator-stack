# Community alpha scope and known limitations — 0.1.0a2

This is the canonical draft for the issue that will be pinned after the
repository becomes public. Do not create it remotely from a source-preview
commit without separate approval.

SOS records accepted project state for fresh coding-agent sessions, detects
stale or unverified work and returns one safe next action. The alpha is
Codex-first, local-first and has no telemetry.

## Supported and pending surfaces

- Native Linux x86_64 is the executable-qualification target only when the
  named Landlock/seccomp profile is admitted.
- macOS 14+ Apple Silicon is a control-plane target; executable project
  qualification remains unsupported.
- Windows 11 x86_64 remains pending Microsoft Store certification and a
  Store-signed clean-user lifecycle.
- Other agents, platforms and check families are unverified or unsupported as
  described in the README support matrix.

No public installation authority exists until an immutable release pointer is
published. `not_configured`, `not_verified`, ambiguous and unsupported states
are never green.

## Reporting useful alpha evidence

Use the typed issue forms and a synthetic reproducer. Include the SOS version,
OS profile, command, exit code and reason code. Do not include credentials,
private source, prompts, raw `.sigma`, host paths or customer data. Security
reports go through private vulnerability reporting.

Launch observations are reviewed at D+2, D+7, D+14 and D+30 under
[`launch-operations.md`](launch-operations.md). Stars, clones, views, forks and
downloads are reach metrics, not adoption.
