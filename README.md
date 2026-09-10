# SOS

**Project state for coding agents.**

A new coding-agent session should not have to guess where you left off.
SOS records the project state you explicitly accept: current work, instructions,
and checks. The next session recovers that state and sees when a source change
has made an earlier check stale.

## Install with Codex

Give Codex this repository URL and instruction:

> https://github.com/sigmastratum/sigma-operator-stack
>
> **Install SOS in my current project. Show me the preview before changing it.**

Codex verifies the release and prepares the installation. You see one project
preview and confirm before project files change. The installer manages Python,
`uv`, and dependencies; you do not need to install them or repair PATH.

**Current installable Community alpha: `0.1.0a7`. Linux is the primary
supported path.** Also available: unsigned experimental macOS 14+ Apple Silicon
control plane; an explicit **Open Anyway** approval may be needed.
Windows 11 x86_64 pending Store lifecycle — no Windows install claim yet.

**For agents:** start at [`INSTALL.md`](INSTALL.md) and follow the
[canonical installation route](docs/install-with-codex.md), using the checked-in release
[pointer on main](https://raw.githubusercontent.com/sigmastratum/sigma-operator-stack/main/release/current.json).

[Limitations](#support-matrix) · [Security](SECURITY.md) ·
[Uninstall and preservation](docs/version-update.md#removal)

## See the recovery loop

![SOS installation and fresh-session recovery with unconfigured work and unverified checks](demo/recovery-terminal.png)

The [current narrated demo](demo/recovery-demo.mp4) and
[text transcript](demo/transcript.md) show the predecessor `0.1.0a5` Linux installation:
URL-only discovery, release verification, one preview, human confirmation,
and genuinely fresh-session recovery.

This recording starts with an unconfigured project. It correctly reports
`not_configured` work and `not_verified` checks; it does **not** demonstrate
recovery of an existing task or refusal of a stale check.
[Capture details and artifact bindings](demo/README.md).

### What recovery looks like with a recorded task

The separate [synthetic recovery example](examples/fresh-agent-recovery/README.md)
walks through a configured project:

1. The recorded task is to keep `demo_app.answer()` equal to `42` and preserve
   existing project controls.
2. A separately confirmed Python unittest check passes for that source state.
3. Recovery reads the accepted project state instead of relying on chat history.
4. A source change makes the previous state `stale`; SOS returns
   `SOS_SOURCE_STATUS_CHANGED` instead of treating the earlier pass as current.

This is a reproducible, zero-provider tutorial, not another recorded Codex
session. Executable qualification in the example requires the admitted native
Linux profile. The video above proves the installation route separately.

SOS only recovers work that has been explicitly recorded.
Installation and qualification are deliberately different operations:
setup does not invent a task or run registered project checks. Missing and
unverified state stays visible.

Sigma Operator Stack is the formal project name. SOS works alongside your
repository, issue tracker, existing `AGENTS.md`, and governance framework.
It previews its managed changes and asks you to resolve conflicting authority.
It is local-first and has no telemetry.

<details>
<summary>For agents and release reviewers: release verification</summary>

**Release activation is fail closed.** `release/current.json` is the only
current installation authority. Its immutable tag, index, artifact size,
digest, inner manifest and checksums must all be available and agree.
Otherwise stop; do not substitute a historical release, branch archive,
GitHub source archive, issue command, raw installer or private test bundle.
Full discovery and maintenance instructions are in [`INSTALL.md`](INSTALL.md)
and the [canonical route](docs/install-with-codex.md).

</details>

## Three failures SOS prevents

### A fresh agent guesses the project state

SOS binds accepted authority, policy, source observation, and current work to
append-only records. The next session reads those records instead of guessing
from chat history.

Limit: SOS recovers only state that was explicitly accepted and recorded; it
does not infer missing project truth from source code or chat history.

### Changed source is treated as already verified

Every authoritative read re-observes the application fingerprint. A changed
tracked, staged, unstaged, untracked, deleted, symlink, or bounded submodule
state becomes stale and returns an exact next action.

Qualification is also bound to the exact installed SOS package identity. An
upgrade or downgrade preserves historical receipts but makes their green state
stale until each project is rebound, Codex is restarted, and qualification is
run separately. See [version update and downgrade](docs/version-update.md).

Limit: the alpha qualifies only registered check families and cannot certify
model quality, production behavior, or checks outside the declared profile.

### Installation overwrites an existing stack

`sos compatibility` discovers known agent and governance surfaces and marks
each relevant object `preserve`, `append`, `create`, or `block`. Competing
authority systems require an explicit primary choice. Foreign managed bytes,
collisions, filesystem uncertainty, and changed previews stop without
overwrite.

Limit: recognized surfaces are classified; unknown frameworks are preserved
but remain outside the compatibility claim.

## Support matrix

`Observed` means an exact artifact ran in that environment. `Release claim`
is the smaller compatibility promise that may become active only after a
candidate-bound public release pointer exists. Observation never silently
expands the claim.

| Environment | Observed | Release claim | Current result |
| --- | --- | --- | --- |
| Native Linux x86_64 on a local filesystem, Python 3.11/3.12, Landlock ABI >= 3 and required seccomp | Independent native lifecycle and qualification controls passed | Control plane plus registered Python qualification | Admitted only through the exact tagged archive selected by the release pointer |
| macOS 14+ Apple Silicon on local APFS | Native install, smoke, same-version update, and removal passed; `.sigma` preserved | Unsigned/not-notarized control-plane alpha; one `Open Anyway` approval may be required | Admitted only through the exact tagged archive; executable qualification remains unsupported |
| Windows 11 x86_64 on local NTFS, UAC enabled, ordinary Medium Integrity user | Exact MSIX content built and accepted into Microsoft Store certification | Pending | Store-signed install/update/remove and clean-user lifecycle are not yet proven |
| Windows with UAC disabled, elevated execution, non-owner profile storage, shared/network filesystem, or sandbox identity targeting another profile | Typed refusals observed | Unsupported | SOS stops before project mutation |
| Docker Desktop on a WSL2 kernel exposing Landlock ABI 1 | Capability diagnostic recorded | Control plane only | Executable unittest is unsupported and fails closed |
| Native Ubuntu WSL2 | No complete native evidence | Unverified | Not a release target |
| Agents other than Codex | Not qualified | Unverified | Control plane is agent-neutral; the alpha adapter is Codex-first |
| Languages/check families beyond registered Python syntax and unittest | Not qualified | Unsupported | Future families require an explicit registry and isolation contract |
| Package network and telemetry | Launcher acquisition is bounded; SOS entrypoint counters remained `0/0/0` in qualified runs | No network or telemetry after verified handoff | Release evidence must bind the exact platform launcher |
| Existing agent/governance files | Preserve/append/create/block and collision fixtures passed | No silent overwrite | Semantic ambiguity requires an owner choice |

The public Community Alpha archives pin managed Python `3.12.14` and `uv 0.12.6`.
Exact Git and Codex versions are artifact-specific and must be frozen in the
public release index before any broad compatibility claim. The Codex adapter
exposes exactly eight read/proposal MCP tools.

On Linux, `sos capabilities --json` reports the exact local qualification
profile decision. Exit `0` means the complete named profile is available; exit
`2` gives a typed unsupported reason. Windows and macOS control-plane support
does not imply executable qualification support.

## Coexistence with an existing project

SOS preserves existing files by default. It recognizes root and nested
`AGENTS.md`, `.codex`, `.sigma`, OpenSpec, BMAD, spec-kit, and known governance
roots. It does not merge competing policies or print existing file contents.

```bash
sos compatibility PATH
sos init --with-codex --primary-authority '<discovered-id>' PATH
```

The primary-authority option is accepted only when the compatibility result
requires it. Unknown frameworks are preserved but remain outside the alpha
compatibility claim.

## Trust boundary

- Reads bounded repository metadata, Git state, SOS records, and recognized
  agent/governance surfaces; it does not serialize their raw contents.
- Writes only previewed SOS records and exact managed integration targets after
  the user's confirmation.
- Local and offline after package acquisition; no telemetry.
- Exact eight-tool MCP surface with no shell, accept, qualify, commit, push,
  deploy, or production mutation tool.
- One observed-terminal confirmation for managed writes.
- Digest-bound previews, receipts, successor lineage, and stale detection.
- Package-bound qualification currentness across upgrade and downgrade; setup
  rebind alone cannot manufacture green.
- Qualification runs only through a registered fixed command and a named
  fail-closed isolation profile.
- User files are restored byte-for-byte on safe setup removal; `.sigma`
  project records are preserved.
- Cannot prevent a user, another process, or an unrestricted coding agent from
  changing files outside SOS; it detects relevant drift on the next observed
  operation and fails closed.

Read the public [architecture overview](docs/architecture.md),
[threat model](docs/threat-model.md), and
[contracts and integrity](docs/contracts-and-integrity.md). The
[factual comparison](docs/comparison.md) explains what SOS complements rather
than replaces. Expected refusals
are indexed in [troubleshooting](docs/troubleshooting.md).

## Current capabilities and next milestones

The [public roadmap](docs/roadmap.md) tracks Community capability maturity
only. It intentionally excludes private planning and commercial commitments.

## Contributing and support

- Try the supported journey and tell us where it became unclear or stopped.
  Share only typed reason codes and a synthetic reproducer—never private
  source, prompts, raw `.sigma`, credentials, customer data, or host paths.
- Reproducible bugs and bounded proposals: GitHub Issues.
- Alpha feedback: [`docs/alpha-feedback.md`](docs/alpha-feedback.md).
- Security reports: GitHub private vulnerability reporting only.
- Contribution rules: [`CONTRIBUTING.md`](CONTRIBUTING.md).
- Support boundary: [`SUPPORT.md`](SUPPORT.md).

Licensed under the [Apache License 2.0](LICENSE).
