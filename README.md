# Sigma Operator Stack

Sigma Operator Stack (`sos`) lets a fresh coding-agent session enter an
existing Git repository, recover the accepted project state, detect stale or
unverified work, and receive one safe next action without relying on the
previous chat.

It is a local-first continuity and qualification layer for AI-native software
development. SOS does not replace your repository, issue tracker, existing
`AGENTS.md`, or governance framework. It discovers them, previews the exact
managed change, and fails closed when authority is ambiguous.

> **Community alpha:** the control plane is useful today on supported native
> Linux. Executable qualification has a deliberately narrow kernel boundary.
> Direct Windows remains unsupported in `0.1.0a1`; the next platform increment
> is a native, non-admin Windows control plane rather than a required
> WSL/Docker setup. Public release readiness is not claimed by this source
> candidate.

## See the recovery loop

The reproducible demo in [`examples/fresh-agent-recovery/`](examples/fresh-agent-recovery/README.md)
shows the whole product outcome:

1. SOS discovers an existing project and preserves unrelated agent settings.
2. One preview and one confirmation install the local control plane and Codex
   adapter.
3. Qualification is a separate, explicit step.
4. A fresh session recovers accepted state and the next allowed action.
5. A later source change is detected as stale instead of silently trusted.

The canonical text transcript is available even when video is not:
[`demo/transcript.md`](demo/transcript.md).

## Quickstart

Prerequisites: Linux x86_64, Python 3.11 or 3.12, Git, a preinstalled `uv`,
and a conventional Git repository.

```bash
uv tool install --no-config --no-sources --no-build --no-python-downloads \
  'sigma-operator-stack==0.1.0a1'

sos capabilities --json
sos compatibility PATH
sos init --with-codex PATH
sos qualify PATH
```

`sos init --with-codex` displays one aggregate preview and asks once before it
writes. It never runs project tests. Package acquisition ends before SOS
starts; SOS itself performs no network request, telemetry, or update check.

Before publication, the same path is qualified from an exact local wheel. If
you received a checked alpha bundle, verify it and run its `start-sos-alpha`
launcher as described in [`docs/alpha-quickstart.md`](docs/alpha-quickstart.md).

## Three failures SOS prevents

### A fresh agent guesses the project state

SOS binds accepted authority, policy, source observation, and current work to
append-only records. The next session reads those records instead of guessing
from chat history.

### Changed source is treated as already verified

Every authoritative read re-observes the application fingerprint. A changed
tracked, staged, unstaged, untracked, deleted, symlink, or bounded submodule
state becomes stale and returns an exact next action.

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
- Qualification runs only through a registered fixed command and a named
  fail-closed isolation profile.
- User files are restored byte-for-byte on safe setup removal; `.sigma`
  project records are preserved.

Read the public [architecture overview](docs/architecture.md),
[threat model](docs/threat-model.md), and
[contracts and integrity](docs/contracts-and-integrity.md). Expected refusals
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
