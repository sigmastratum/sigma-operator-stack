# AF104 public URL-only drill

AF104 is the final agent-first release gate for each admitted platform. Archive
delivery on Linux/macOS and Store delivery on Windows receive separate
verdicts; one platform's pass never implies another platform's support.

## Starting condition

Use a clean admitted host profile and an ordinary interactive user. The public
release pointer and immutable release index must bind the exact archive or
Store package. Windows additionally requires UAC, Defender and SmartScreen.

A genuinely fresh Codex task receives only this repository URL and:

> Install SOS in my current project. Show me the preview before changing it.

No founder hint, manual command, Python/`uv` installation, PATH repair,
Administrator session, certificate installation, security bypass or hidden
confirmation is allowed.

## Exact sequence

1. `release_discovery` — Codex finds and verifies the public pointer and index.
2. `host_install` — Codex verifies the exact archive, or the user performs the
   ordinary Store installation action on Windows.
3. `project_preview` — SOS renders one digest-bound aggregate preview.
4. `project_apply` — only the user confirms repository mutation.
5. `truthful_state` — setup, workspace, preflight and check plan remain honest;
   `not_configured` or `not_verified` is not promoted to green.
6. `fresh_recovery` — a second genuinely fresh Codex task recovers authority,
   current work, boundaries, checks and one safe next action.
7. `update_remove` — same-version update is deterministic; removal preserves
   `.sigma` and unrelated user files.

The drill uses exactly two provider-backed Codex tasks. Public evidence stores
only the fixed instruction, typed step states, exact release bindings and
content-safe counters. Raw prompts, responses, MCP results, paths, hostnames,
accounts and project content are forbidden.

## Terminal rule

Pass requires all seven ordered steps. A sandbox that cannot invoke the
per-user launcher returns `SOS_INTERACTIVE_USER_HANDOFF_REQUIRED`; this is a
release blocker until an ordinary-user handoff completes without manual
commands or weakened controls.

When an agent process cannot survive the confirmation turn, the only permitted
resume path is the seed plus exact digest emitted by
`sos_p106_confirmation_handoff_v1`. A regenerated unbound plan, silent project
trust override, sandbox bypass or founder-supplied recovery command is a failed
drill even if the underlying SOS lifecycle later succeeds.
The resume route rejects noninteractive `--yes` confirmation.

Certification alone does not pass AF104 or authorize publication. The exact
receipt must pass `tools/check_agent_first_drill.py` and independent terminal
review before the owner makes a separate publication decision.
