# SOS

**Project state for coding agents.**

Give this repository to Codex and say:

> **Install SOS in my current project. Show me the preview before changing it.**

Codex follows the [canonical installation route](docs/install-with-codex.md),
verifies one exact platform release, and prepares the setup. You review the
single SOS preview and remain the only person who can approve repository
mutation or choose project authority.

SOS is a local-first Community alpha with no telemetry. It helps a genuinely
fresh coding-agent session recover accepted project state, detect stale or
unverified work, and receive one safe next action without relying on the
previous chat. Unsupported, ambiguous, `not_configured` and `not_verified`
states are never presented as green.

> **Release gate:** no public release pointer is published yet. The URL-only
> installation claim is therefore not active. Until `release/current.json`
> exists in a tagged public release and passes the exact-candidate drill, do
> not install from a branch tip, source archive, issue command or private test
> bundle. Current platform evidence is summarized in the support matrix below.

Sigma Operator Stack is the formal project name. SOS does not replace your
repository, issue tracker, existing `AGENTS.md`, or governance framework. It
discovers them, previews the exact managed change, and fails closed when
authority is ambiguous.

## See the recovery loop

The reproducible demo in [`examples/fresh-agent-recovery/`](examples/fresh-agent-recovery/README.md)
shows the whole product outcome:

1. SOS discovers an existing project and preserves unrelated agent settings.
2. One preview and one confirmation install the local control plane and Codex
   adapter.
3. Qualification is a separate, explicit step.
4. A fresh session recovers accepted state and the next allowed action.
5. A later source change is detected as stale instead of silently trusted.

The exact-candidate terminal recording is available as
[`WebM`](demo/recovery-demo.webm) or [`MP4`](demo/recovery-demo.mp4). Its
canonical text equivalent is [`demo/transcript.md`](demo/transcript.md). It
combines the offline local lifecycle with one explicitly approved,
receipt-verified ephemeral Codex recovery. No raw task, response, tool result,
session identifier, account data or host path is retained.

## Install with Codex

There is one public installation route:
[`docs/install-with-codex.md`](docs/install-with-codex.md). The released
platform launcher owns its declared Python, `uv`, and package dependencies;
the developer does not repair PATH or install them manually.

Installation and qualification are deliberately different operations. Setup
may finish with `not_configured` or `not_verified`. Project checks run only
after a separate human-reviewed qualification proposal.

Invited private-alpha testing is not public installation authority. The
historical tester note at [`docs/alpha-quickstart.md`](docs/alpha-quickstart.md)
contains no alternative public command sequence.

## Three failures SOS prevents

### A fresh agent guesses the project state

SOS binds accepted authority, policy, source observation, and current work to
append-only records. The next session reads those records instead of guessing
from chat history.

### Changed source is treated as already verified

Every authoritative read re-observes the application fingerprint. A changed
tracked, staged, unstaged, untracked, deleted, symlink, or bounded submodule
state becomes stale and returns an exact next action.

Qualification is also bound to the exact installed SOS package identity. An
upgrade or downgrade preserves historical receipts but makes their green state
stale until each project is rebound, Codex is restarted, and qualification is
run separately. See [version update and downgrade](docs/version-update.md).

### Installation overwrites an existing stack

`sos compatibility` discovers known agent and governance surfaces and marks
each relevant object `preserve`, `append`, `create`, or `block`. Competing
authority systems require an explicit primary choice. Foreign managed bytes,
collisions, filesystem uncertainty, and changed previews stop without
overwrite.

## Support matrix

`Observed` means an exact artifact ran in that environment. `Claimed` is the
smaller public compatibility promise. Observation never silently expands the
claim.

| Environment | Observed | Claimed in 0.1 alpha | Result |
| --- | --- | --- | --- |
| Native Linux x86_64, Python 3.11/3.12, Landlock ABI >= 3 and required seccomp | Two independent positive controls | Supported | Control plane and registered Python qualification profile admitted |
| Docker Desktop on a WSL2 kernel exposing Landlock ABI 1 | Capability diagnostic recorded | Control plane only | Executable unittest is unsupported and fails closed |
| Native Ubuntu WSL2 | Pending diagnostic evidence | Unverified | Not the default Windows onboarding path |
| Direct Windows or Windows-backed mounts | Typed refusal observed | Unsupported in `0.1.0a1` | A native non-admin control-plane preview is planned; executable checks require later, separate isolation evidence |
| Direct macOS or VM shared folders | Not qualified | Unsupported | Demand-gated; no current installer or VM compatibility promise |
| Agents other than Codex | Not qualified | Unverified | Control plane is agent-neutral; the alpha adapter is Codex-first |
| Languages/check families beyond registered Python syntax and unittest | Not qualified | Unsupported | Future families require an explicit registry and isolation contract |

Run `sos capabilities --json` outside or inside a project for the exact local
kernel decision. Exit `0` means the complete named profile is available; exit
`2` gives a typed unsupported reason.

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

- Reproducible bugs and bounded proposals: GitHub Issues.
- Alpha feedback: [`docs/alpha-feedback.md`](docs/alpha-feedback.md).
- Security reports: GitHub private vulnerability reporting only.
- Contribution rules: [`CONTRIBUTING.md`](CONTRIBUTING.md).
- Support boundary: [`SUPPORT.md`](SUPPORT.md).

Licensed under the [Apache License 2.0](LICENSE).
