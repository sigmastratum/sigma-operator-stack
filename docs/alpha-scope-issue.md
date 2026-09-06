# Community alpha scope and known limitations — 0.1.0a5

This is the canonical source for the issue that will be created, assigned to
`@sigmastratum` and pinned before promotion. Remote creation and pinning remain
separately approved actions.

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

The only public installation authority is the immutable `v0.1.0a5` release
selected by `main:release/current.json`. `not_configured`, `not_verified`,
ambiguous and unsupported states are never green.

## Exact test requested

Give the repository URL to a fresh Codex task and ask it to install SOS in the
current project while showing the preview before mutation. After installation,
open a genuinely fresh task and verify recovery, a same-version update, the
public smoke test and a removal preview. Confirm removal only after reviewing
the exact managed targets; `.sigma` and unrelated user files must remain.

## Reporting useful alpha evidence

Use the typed issue forms and a synthetic reproducer. Include the SOS version,
OS profile, command, exit code and reason code. Do not include credentials,
private source, prompts, raw `.sigma`, host paths or customer data. Security
reports go through private vulnerability reporting.

Launch observations are reviewed at D+2, D+7, D+14 and D+30 under
[`launch-operations.md`](launch-operations.md). Stars, clones, views, forks and
downloads are reach metrics, not adoption.
