# Claude Code adapter discovery and architecture

Status: I1 implementation candidate; actual-client qualification and release are not authorized

Source baseline: `068b5936deec4fcb5674f2612a6be12b41ecc987`

Source tree: `946c05d78bebbe15a921156d2ecb8244f7ca78b0`
Research date: 2026-09-07

## Objective

Add a Claude Code client adapter over the existing repository-owned SOS state
without creating a Claude-specific authority, ledger, qualification result, or
mutation-capable MCP tool.

The acceptance path is:

```text
Codex records accepted work
  -> fresh Claude Code reads the same eight SOS projections
  -> Claude Code recovers the same work, boundaries, and checks
  -> a source change makes the earlier qualification stale
  -> both clients return the same typed refusal and next action
```

This document records discovery, architecture, and the bounded I1 implementation
candidate. It does not claim actual-client qualification, modify `v0.1.0a5`, or
authorize release, provider, publication, commit, or push work.

## Evidence boundary

Three evidence classes remain separate:

1. `documented`: dated first-party Claude Code documentation;
2. `offline`: SOS source inspection and future synthetic fixtures;
3. `actual_client`: an installed, authenticated Claude Code binary exercised
   against a synthetic project.

Only the first two classes are available here. No `claude` executable is
installed in the discovery environment, no Claude login was attempted, and no
provider turn was made.

## Claude Code capability baseline

The documentation baseline is Claude Code `2.1.263`, the latest public release
observed on 2026-09-07. It is a research pin, not a compatibility claim. Q1 must
pin and record the exact installed version again because the native installation
can auto-update.

Initial qualification profile:

- native Linux x86_64 on an SOS-admitted local filesystem;
- Claude Code installed for the ordinary interactive user;
- an authenticated Pro, Max, Team, Enterprise, or Console account;
- a pre-approved provider-turn budget;
- a synthetic Git repository and isolated user configuration directory;
- no existing user, project, managed, plugin, skill, or hook configuration
  except fixtures named by the scenario.

First-party findings:

| Surface | Documented behavior | Adapter consequence |
| --- | --- | --- |
| MCP transport | Claude Code supports local stdio servers. | Reuse `python -m sos mcp --root PATH`; do not add another server implementation. |
| MCP project scope | Project servers are stored in root `.mcp.json`. Ordinary interactive sessions require project-server approval; print/SDK/cloud sessions and explicitly configured bypass modes can skip that prompt. | Manage one exact `sigma_operator_stack` object. Q1 uses an ordinary interactive TTY, treats Claude's approval as a separate handoff, and does not infer that behavior for non-interactive clients. |
| MCP precedence | Duplicate names resolve local, project, user, plugin, then connector. | A local or user server named `sigma_operator_stack` is a collision, not evidence that the SOS project server loaded. |
| Instructions | Managed, user, project, and local `CLAUDE.md` files can all load. Root `CLAUDE.md` and `.claude/CLAUDE.md` are project surfaces; project rules and nested files can load later as files are accessed. | Existing instruction files and rules are untrusted inputs. Discovery observes type, size, and digest only and never launches Claude, follows instruction symlinks, or evaluates imports. |
| Settings | Precedence is managed, command line, local project, shared project, then user; arrays such as permissions merge. | Project settings cannot prove effective permissions. The adapter does not modify settings or claim enforcement. |
| Hooks | Hooks may run commands, HTTP requests, MCP calls, prompts, or agents from several scopes. | Discovery never starts Claude. Q1 uses a controlled configuration and reports any loaded hook scope; ordinary repositories retain their hooks unchanged. |
| Skills | Skills can be model-invoked and are discovered from user and project `.claude/skills` locations. | Preserve them. SOS does not install a skill because MCP plus a bounded instruction block is sufficient. |
| Authentication | Claude Code requires an eligible account or supported provider configuration. | D1/A1 remains zero-provider. Q1 records login class and turn budget without recording credentials. |

First-party references, all accessed 2026-09-07:

- <https://code.claude.com/docs/en/mcp>
- <https://code.claude.com/docs/en/memory>
- <https://code.claude.com/docs/en/settings>
- <https://code.claude.com/docs/en/permissions>
- <https://code.claude.com/docs/en/hooks>
- <https://code.claude.com/docs/en/slash-commands>
- <https://code.claude.com/docs/en/setup>
- <https://code.claude.com/docs/en/authentication>
- <https://github.com/anthropics/claude-code/releases/tag/v2.1.263>

## Current SOS seam map

| Source seam | Current truth at the baseline | Required change |
| --- | --- | --- |
| `src/sos/mcp.py` | Provider-neutral stdio server with exactly eight read/proposal tools. | No tool or transport change. Add parity tests only. |
| `src/sos/agent_api.py` | Shared projections, except `sos_propose_update` delegates to a Codex-named helper. | Make update projection enumerate installed client bindings while preserving the tool name and response semantics. |
| `src/sos/client_integration.py` | One large Codex-specific lifecycle for `AGENTS.md` and `.codex/config.toml`. | Keep Codex behavior stable; extract only small shared constants/helpers and add a separate Claude adapter module. |
| `src/sos/managed_files.py` | Published v1 plan/batch journals accept only `create_file` and `append_suffix`. | Preserve v1 replay unchanged. Add separately versioned v2 plan/batch contracts with a reversible `insert_bytes` operation. |
| `src/sos/lifecycle.py` | P106 aggregate bootstrap embeds one `CodexBootstrapSetup`. | Add client selection to a successor aggregate contract; do not reinterpret existing P106 receipts. |
| `src/sos/compatibility.py` | Detects AGENTS, `.codex`, `.sigma`, nested AGENTS and known governance roots. | Add bounded Claude project surfaces and typed collision results without reading user-level files into evidence. |
| `src/sos/maintenance_binding.py` | Correctly separates MCP executable identity from public maintenance launcher identity. | Reuse unchanged; client manifests point to the same MCP launcher binding. |
| `src/sos/transaction.py` | Stages and commits bounded repository files atomically. | Reuse; the selected client plans participate in one aggregate preview. |
| `src/sos/platform_services.py` | Repository-root, no-follow observation and publication. | Reuse; do not mutate `~/.claude.json` or credentials. |
| `src/sos/cli.py` | Parser and dispatch restrict setup/client choices to `codex`. | Add explicit `claude-code` selection and multi-client status/update dispatch. |
| `tools/start_sos_alpha.py` | Install/update/remove always targets Codex; removal then uninstalls the shared package. | Successor-only routing must distinguish adapter detach from application removal and protect other installed adapters. |

The current state model in `.sigma` remains the sole accepted project-state
model. Both clients call the same `project_tool` path and receive the same
`current`, `stale`, `not_configured`, `not_verified`, `owner_required`,
`unsupported`, `blocked`, or `invalid` decisions. Client setup manifests and
managed-file journals are integration evidence, not project authority.

## Adapter identity and targets

The canonical client ID is `claude-code`. User-facing prose may say “Claude
Code”; schemas, CLI arguments, filenames, and reason codes use `claude-code` or
`CLAUDE_CODE` consistently.

The adapter manages exactly two repository targets:

1. `CLAUDE.md`: create or append one bounded SOS recovery block;
2. `.mcp.json`: create a valid JSON object or structurally insert one
   `mcpServers.sigma_operator_stack` entry.

It writes one client manifest:

```text
.sigma/integrations/claude-code.json
```

and separate journals:

```text
claude-code-instructions-v1
claude-code-mcp-v1
```

The manifest contract records client ID, repository ID, state, ordered batch,
plan digests, package version, MCP launcher digest, target modes, and content-
safety booleans. It does not serialize original files, absolute paths,
credentials, settings, hooks, skills, or Claude trust choices.

Its contract ID is `sos_claude_code_setup_manifest_v1`. The successor aggregate
uses `sos_multi_client_lifecycle_plan_v1` and never rewrites or reinterprets a
P106 receipt.

The `.mcp.json` entry uses the already observed SOS managed Python executable
as `command`, with these arguments:

```json
{
  "mcpServers": {
    "sigma_operator_stack": {
      "type": "stdio",
      "command": "<observed-managed-python>",
      "args": ["-m", "sos", "mcp", "--root", "<project-root>"]
    }
  }
}
```

Paths above are shown only in the human preview and written to the local target.
Receipts retain their digests, never the path bytes. Environment variables and
secrets are not added. SOS does not write Claude's local or user MCP scopes and
does not mark the project server trusted.

## Core decision P107-CORE-01: reversible byte insertion

Decision candidate: leave the published v1 managed-file grammar closed and add
`sos_managed_file_plan_v2` plus `sos_managed_file_batch_v2`. V2 adds a required
`patch_offset` and `patch_kind=insert_bytes`; it also admits `create_file` and
`append_suffix` so one Claude setup batch contains only v2 plans. Existing Codex
manifests, plan files, batches, and journals remain v1 and replay byte-for-byte
through the unchanged v1 validation path.

Rationale: `.mcp.json` is one JSON document. Appending bytes cannot safely add an
object, while whole-file canonical replacement cannot reconstruct the user's
original formatting after fresh-process recovery without storing raw content.
Using `claude mcp add` would mutate user state, depend on the client binary, hide
the exact write from SOS, and weaken rollback evidence.

Required invariants:

- v2 binds before/after existence, byte count, mode, SHA-256, patch offset,
  inserted byte count, and inserted byte digest;
- apply is exactly `before[:patch_offset] + patch + before[patch_offset:]`;
  rollback verifies the after-image and inserted slice, removes only that slice,
  and verifies the reconstructed before digest before publication;
- fresh-process rollback needs only the v2 plan, deterministic adapter renderer,
  current after-image, and exact launcher binding; no original bytes are stored;
- the input and resulting document are parsed as strict UTF-8 JSON before
  publication;
- the root value and `mcpServers` must be objects;
- an existing `sigma_operator_stack` key is a typed collision;
- the insertion offset is immediately before the closing brace of the existing
  `mcpServers` object, or immediately before the root closing brace when the
  adapter inserts a new `mcpServers` member; the patch carries any required
  comma plus the exact new member bytes;
- every pre-existing byte, including whitespace, key order, line endings, and
  number spelling, remains at the same relative position;
- JSON parsing rejects duplicate members, non-finite numbers, invalid UTF-8,
  more than 64 nesting levels, more than 4,096 total members, and files above
  the existing 1 MiB managed-file ceiling with typed reasons;
- the inserted server member is deterministic compact UTF-8 JSON with sorted
  keys and no environment or secret fields; preview binds the exact patch and
  full after-image before confirmation;
- refusal or missing confirmation writes nothing;
- rollback restores the exact original bytes, including after process restart;
- symlinks, non-regular files, oversized files, duplicate JSON keys, parse
  failures, mode drift, byte drift, and preview drift fail closed;
- v2 `create_file` uses offset zero; v2 `append_suffix` uses the before byte
  count; all v1 validation remains unchanged;
- v2 batch steps include `plan_contract` as well as plan digest. V1 batch and
  journal replay never accepts a v2 plan. V2 replay accepts only v2 plans;
- `sos_managed_file_event_v1` and
  `sos_managed_file_batch_projection_v1` remain valid because they bind opaque
  plan digests and unchanged lifecycle states. The successor multi-client
  compatibility output advances to `sos_compatibility_projection_v2` so the
  new `insert` action is not added silently to the v1 projection.

This core change is a prerequisite for I1 and requires independent architecture
acceptance. It must land as its own patch family before Claude adapter code.

Typed parser/insertion refusals are frozen as
`SOS_CLAUDE_CODE_MCP_JSON_INVALID`,
`SOS_CLAUDE_CODE_MCP_JSON_LIMIT_EXCEEDED`,
`SOS_CLAUDE_CODE_MCP_SERVER_COLLISION`,
`SOS_CLAUDE_CODE_MCP_INSERTION_INVALID`, and the existing managed-file target,
drift, preview, and recovery reasons. Duplicate members, invalid numbers and
invalid UTF-8 map to `...JSON_INVALID`; member/depth/byte ceilings map to
`...JSON_LIMIT_EXCEEDED`.

## Instruction and configuration policy

Discovery is non-executing and bounded:

- observe root `CLAUDE.md`, `.claude/CLAUDE.md`, `CLAUDE.local.md`, `.mcp.json`,
  `.claude/settings.json`, `.claude/settings.local.json`, `.claude/rules`,
  `.claude/skills`, `.claude/commands`, and `.claude/agents` by type/presence;
- hash only bounded regular repository files already allowed by the public
  content boundary;
- never resolve or follow a symlink during integration;
- never import a CLAUDE.md reference, load a skill, parse a hook command for
  execution, start Claude, or inspect credential content;
- report user/managed scopes as `not_observed` during repository-only preview;
  Q1 records their effective presence from a controlled client status check.

Root `CLAUDE.md` is the only managed instruction target. Existing
`.claude/CLAUDE.md`, local instructions, rules, skills, commands, agents,
plugins, hooks, and settings are preserved and never edited.

For a repository without accepted SOS state, an existing project CLAUDE.md is
an authority candidate. Multiple recognized candidates still require one owner
choice. For an already initialized repository, installing the adapter cannot
change or reopen accepted authority; it only binds the new integration to the
existing repository ID and current control-plane integrity.

The managed instruction block states that SOS is the project-state authority,
the eight MCP tools are read/proposal only, typed non-success results stop
project work, and maintenance uses the separately verified launcher. It does
not claim to override managed/user/local Claude instructions or enforce model
behavior.

## Preview, confirmation, trust, and recovery

One aggregate adapter plan contains the instruction and MCP JSON targets in
that order, their rollback order, manifest digest, package binding, compatibility
digest, and resulting application fingerprint.

State transitions remain:

```text
install_prepared -> installed -> remove_prepared -> removed
```

The operation requires one live controlling-terminal confirmation. Refusal,
EOF, non-TTY execution, or a changed digest makes no project-target change.
After installation, Claude's project MCP approval is a separate client trust
decision for the qualified ordinary interactive flow. Adapter installation and
client readiness are projected separately:

| Manifest/integrity | Client readiness | Result | Maintenance |
| --- | --- | --- | --- |
| absent or `removed` | not applicable | `success / SOS_CLAUDE_CODE_SETUP_NOT_INSTALLED` | install allowed |
| `installed`, exact targets and launcher | `not_observed` | `owner_required / SOS_INTERACTIVE_USER_HANDOFF_REQUIRED` | confirmed update/detach allowed |
| `installed`, called through all eight tools in a fresh interactive session | current-session proof only | each tool returns the shared project status; readiness is not persisted as authority | confirmed update/detach allowed |
| prepared/interrupted | unknown | `blocked / SOS_CLAUDE_CODE_SETUP_RECOVERY_REQUIRED` | recover only |
| installed with target, manifest, or launcher drift | unknown | `stale` or `blocked` with the exact integrity reason | update/detach refused until official recovery |

The install command may complete its writes while returning the non-success
handoff result with `integration_state=installed`, `client_readiness=not_observed`,
and `maintenance_eligible=true`. A successor launcher recognizes that exact
typed result as an interactive handoff, not as installation failure or recovery
success. SOS does not persist Claude trust because the external choice can
change independently. Print mode, Agent SDK, cloud sessions,
`bypassPermissions`, and `--strict-mcp-config` are outside the initial Q1 profile
because their approval behavior differs. SOS does not edit `~/.claude.json`,
suppress the trust prompt, grant tool permissions, or use a bypass flag.

Interrupted apply uses the existing batch recovery algorithm and reverses exact
completed steps. A modified managed target returns `stale`; it is never repaired
by deleting user files or regenerating `.sigma`.

## Coexistence and shared environment lifetime

Client setup is independent; accepted project state and MCP executable are
shared:

| Installed clients | Remove Claude | Remove Codex | Package removal |
| --- | --- | --- | --- |
| Claude only | Restore Claude targets; preserve `.sigma`; keep package. | Already absent. | Blocked without a global inventory. |
| Codex only | Already absent. | Restore Codex targets; preserve `.sigma`; keep package. | Blocked without a global inventory. |
| Both | Restore only Claude targets and manifest state; Codex remains usable. | Restore only Codex targets and manifest state; Claude remains usable. | Refused while either setup is installed or indeterminate. |
| Neither | Idempotent success. | Idempotent success. | Blocked without a global inventory. |

`sos setup remove <client> PATH` is adapter detach only and never invokes `uv
tool uninstall` or removes the shared runtime. The verified platform launcher
must expose adapter detach separately from application removal. Application
removal cannot be admitted from a project-scoped successor: there is no global
cross-project inventory, so even a project whose known adapters are all removed
cannot prove that another repository does not use the same per-user package.
The successor returns
`blocked / SOS_SHARED_ENVIRONMENT_INVENTORY_REQUIRED` before invoking package
uninstall. A global inventory/refcount or a project-private runtime is a
separately approved architecture increment; only that increment may re-enable
application removal.

Version-changing package update cannot be admitted from a selected project for
the same reason as uninstall: the per-user package is shared and repositories
outside the selected root cannot be inventoried or rebound atomically. The
successor returns `blocked / SOS_SHARED_ENVIRONMENT_INVENTORY_REQUIRED` before
any package-manager call when the verified candidate differs from the installed
package binding.

Exact same-version adapter repair remains available. `setup update-all PATH`
previews one batch that rebinds every installed adapter in the selected project
to the already installed exact package, applies it atomically, and requires an
agent restart. It makes zero package-manager calls. Updating only one adapter
while another remains bound to a different manifest is refused. Historical
qualification remains stale until separately rerun.

## CLI and public launcher contract

Proposed successor CLI grammar:

```text
sos setup status codex PATH
sos setup status claude-code PATH
sos setup install claude-code PATH
sos setup recover claude-code PATH
sos setup remove claude-code PATH
sos setup update-all PATH
sos integrations PATH
```

The public launcher gains an explicit client selection for install and detach.
Existing `v0.1.0a5` bytes and grammar remain immutable. A successor release must
distinguish these operations:

- `install --client claude-code`: acquire the application, initialize shared
  SOS state if absent, and install the Claude adapter in one aggregate preview;
- `detach --client claude-code`: remove only the Claude adapter;
- `update`: permit only exact same-version adapter repair with zero package-
  manager calls; refuse a version change with
  `SOS_SHARED_ENVIRONMENT_INVENTORY_REQUIRED`;
- `remove`: return `SOS_SHARED_ENVIRONMENT_INVENTORY_REQUIRED`; package removal
  is unavailable in P107.

No MCP mutation tool is added. CLI mutation remains behind the existing TTY and
preview contract.

## Implementation file scope

P107-CORE-01 patch family:

- `src/sos/managed_files.py`;
- new `src/sos/schemas/sos-managed-file-plan-v2.schema.json`;
- new `src/sos/schemas/sos-managed-file-batch-v2.schema.json`;
- `tests/test_managed_files.py`;
- `tests/test_managed_file_batches.py`;
- `docs/managed-file-journal.md`.

The v1 plan and batch schemas are explicit non-targets. Core acceptance requires
v1 replay regression tests plus v2 create, append, insert, interruption, and
fresh-process byte-exact rollback tests.

Claude adapter patch family after core acceptance:

- new `src/sos/claude_integration.py`;
- narrow shared constants/helper extraction from `src/sos/client_integration.py`;
- `src/sos/compatibility.py`;
- `src/sos/lifecycle.py`;
- new `src/sos/multi_client_lifecycle.py` for successor-only aggregate plans;
- `src/sos/agent_api.py`;
- `src/sos/cli.py`;
- `tools/start_sos_alpha.py` for successor routing and pre-package-manager
  inventory refusal;
- `installers/Install-SOS.command` for exact `--client` pass-through, `detach`
  mode, and zero-runtime-deletion handling of typed package removal/update
  refusals;
- new `tests/test_claude_setup.py`;
- new `tests/test_multi_client_lifecycle.py`;
- `tests/test_client_integration.py` for Codex regression;
- `tests/test_existing_stack_compatibility.py` for Claude observations and v2
  compatibility projection;
- `tests/test_p106_lifecycle.py` for unchanged P106 receipt/recovery replay;
- `tests/test_alpha_onboarding.py` for exact successor launcher routing and
  package-removal refusal;
- `tests/test_native_alpha_bundles.py` for `Install-SOS.command` argument,
  pinned-runtime, detach, and zero-deletion regression coverage;
- new `docs/install-with-claude-code.md` after source behavior exists;
- `docs/version-update.md` for multi-client update and detach semantics.

I1 does not modify `installers/Install-SOS.ps1`, any `installers/windows-*`
path, release artifacts, release metadata, CI workflows, or `v0.1.0a5`
documentation. `Install-SOS.command` remains the pinned-runtime carrier on its
existing Linux/macOS code path, but P107 qualifies only native Linux x86_64;
macOS replay, Windows/MSIX, release integration, publication, and promotion
remain separate approvals.

Do not refactor the platform service, transaction, workspace, acceptance,
qualification, or MCP cores unless a failing invariant demonstrates the need.

## Frozen qualification scenarios

Offline tests must cover:

1. clean CLAUDE.md and `.mcp.json` creation;
2. exact preservation and restoration of existing files, including
   fresh-process recovery of irregularly formatted `.mcp.json` bytes;
3. existing CLAUDE.md, settings, skills, commands, hooks, nested instructions,
   symlinks, invalid JSON, duplicate keys, oversized files, and server collision;
4. conflicting authority requiring one exact owner selection only during
   initial SOS bootstrap;
5. all eight MCP projections and all typed status classes matching Codex;
6. one preview, refusal/no-TTY/no-confirmation causing zero target writes;
7. preview drift, interrupted first/second target, recovery, modified managed
   bytes, same-version update, version change, and failed update rollback;
8. Claude-only, Codex-only, and coexistence install/update/remove;
9. remove-Claude-preserves-Codex, remove-Codex-preserves-Claude, and package-
   removal refusal both while an integration remains and after all known local
   integrations are detached;
10. final application-removal attempt preserves `.sigma`, sentinel files, Git
    HEAD, accepted records, and unrelated files; in P107 this is a refusal proof
    with zero package-manager calls;
11. installed-but-untrusted readiness is non-success while separately confirmed
    update and detach remain available from exact integration state.

Actual-client Q1 must additionally prove:

1. a fresh Claude Code session requires and completes the normal project MCP
   approval without an SOS trust bypass;
2. exactly eight SOS tools are visible and read/proposal only;
3. Claude recovers an explicitly recorded synthetic task and boundaries;
4. Codex records -> Claude recovers -> source changes -> Claude refuses the
   stale receipt with one bounded next action;
5. the reverse Claude-to-Codex direction, or an explicit limitation if Claude
   cannot participate in the same owner-confirmed recording route;
6. detach/update/remove behavior with both clients installed;
7. exact SOS version, Claude Code version/channel, OS, architecture, source and
   artifact digests, login class, provider turn count, and residual limits.

No real repository content, prompts, transcripts, credentials, user paths, or
provider responses enter evidence.

## Risks and stop conditions

| Risk | Decision or stop condition |
| --- | --- |
| Shared runtime deleted while another project still depends on it | P107 never invokes package uninstall; return `SOS_SHARED_ENVIRONMENT_INVENTORY_REQUIRED`. |
| CLAUDE.md treated as accepted authority | It remains an untrusted instruction surface; accepted `.sigma` records remain authoritative. |
| Hooks or skills execute during discovery | Never start Claude during discovery; Q1 uses controlled synthetic scopes. |
| Local/user MCP shadows project SOS | Treat duplicate server identity as a Q1 blocker until `/mcp` shows the exact project binding. |
| Project JSON is overwritten or normalized invisibly | P107-CORE-01 inserts one digest-bound byte slice and preserves every original byte; fresh-process rollback removes only that slice. |
| Core refactor hidden in adapter patch | Land and review P107-CORE-01 separately; stop I1 if further core changes are needed. |
| Trust prompt mistaken for SOS confirmation | Record them as separate steps; SOS never grants Claude trust. |
| Platform support expands from docs | Q1 target is native Linux x86_64 only. |
| Provider access inferred | Stop Q1 until exact login authority and turn budget are supplied. |
| Claude release drift | Re-run D1 deltas and pin the exact binary before Q1. |

## Evidence and unknowns disposition

| Question | Disposition |
| --- | --- |
| Can Claude use the existing SOS MCP server? | Feasible by documented stdio MCP support; offline protocol core is already provider-neutral. |
| Can project configuration be installed without touching user credentials? | Yes, through project `.mcp.json`; normal Claude approval remains external. |
| Can existing managed-file grammar safely update `.mcp.json`? | No. P107-CORE-01 is required. |
| Can SOS prove effective Claude permission/hook precedence from repository files alone? | No. Repository preview reports it as unobserved; Q1 uses `/status`, `/doctor`, and `/mcp` in a controlled profile. |
| Is an actual Claude client presently available? | No; `claude --version` was unavailable in D1. |
| Is reverse-direction task recording supported? | Unknown until the owner-confirmed recording interface is mapped in I1/Q1; it cannot be added as an MCP mutation. |
| Can package removal prove no other project uses the user runtime? | No. P107 blocks package uninstall until a global inventory/refcount or project-private runtime is separately accepted. |

## Terminal readiness verdict

`changes_required`

D1 is complete. The second and final independent review returned
`changes_required` on the verified launcher path and cross-project package
update lifetime. This revision incorporates both corrections by including the
pinned-runtime `Install-SOS.command` handoff and refusing version-changing
package update as well as uninstall without global inventory.

The two-pass stop rule prevents this corrected revision from promoting itself
to `pass`. The remaining decision is independent acceptance of that narrowed
launcher/package-lifetime contract and exact I1 scope. I1 must not start without
that acceptance and separate implementation authorization. Q1 additionally
requires an exact Claude Code binary/login profile and an approved provider-turn
budget.
