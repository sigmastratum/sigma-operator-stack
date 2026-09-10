# Changelog

All notable changes are recorded here. The format follows Keep a Changelog and
the project uses semantic versioning after the pre-1.0 stability boundary.

## 0.1.0a7 — 2026-09-10

### Fixed

- Keep the qualification worker's private, unlinked output sink outside the
  writable directory observed by the parent process. This removes a race that
  could falsely report `SOS_QUALIFICATION_WRITABLE_LIMIT_EXCEEDED` while
  preserving fail-closed handling of genuine observation errors.
- Report managed-Python acquisition failures before controller startup with a
  typed reason, without falsely claiming an unresolved controller process.
- Recovery and preflight report current check discovery after source changes,
  accepted regeneration and separate requalification. Source mismatches refuse
  a ready state; immutable bootstrap evidence and receipt history are preserved.
- Project-isolated runtime generations keep an updated project independent from
  projects still using the shared predecessor runtime. Adapter transitions and
  removal are journaled, recoverable and separately confirmed.
- Interactive owner confirmation does not consume a controller execution
  deadline. Runtime cache verification accepts equivalent pinned-CPython code
  graphs while continuing to reject instruction, constant and metadata drift.

## 0.1.0a6 — Unpublished candidate

### Fixed

- Recovery and preflight report current check discovery after source changes,
  accepted regeneration and separate requalification. Source mismatches refuse
  a ready state; immutable bootstrap evidence and receipt history are preserved.
- Project-isolated runtime generations keep an updated project independent from
  projects still using the shared predecessor runtime. Adapter transitions and
  removal are journaled, recoverable and separately confirmed.
- Interactive owner confirmation no longer consumes a controller execution
  deadline. Operation-specific subprocess timeouts and truthful recovery states
  remain bounded.
- Runtime cache verification accepts equivalent pinned-CPython marshal graphs
  while detecting instruction, constant and metadata drift without executing
  cached code or relying on platform address-space limits.

## 0.1.0a5 — 2026-09-06

### Fixed

- Bind a resumed agent-first installation confirmation to the exact plan shown
  before a Codex process boundary. Any seed, digest, repository state or
  launcher drift now fails before the mutation prompt.
- Treat project trust and sandbox execution failures as explicit interactive
  handoffs instead of silently overriding Codex security state.

## 0.1.0a4 — 2026-09-06

### Fixed

- Separate the project-local MCP Python binding from the public maintenance
  archive/launcher binding. Fresh sessions rediscover and verify a new exact
  release extraction before same-version update, smoke, or removal.

## 0.1.0a3 — 2026-09-05

### Fixed

- Separate owner-requested SOS maintenance from project qualification gates.
  A fresh Codex session may now perform an exact-release same-version update,
  public smoke test, and removal preview when qualification is `not_verified`;
  project work, qualification claims, and external actions remain fail closed.

### Changed

- Linux and macOS release artifacts, release metadata, and the next Windows
  Store payload are rebound to product version `0.1.0a3`.

## 0.1.0a2 — 2026-09-04

### Added

- Local-first repository authority, current-work and recovery records.
- Exact stale detection and append-only successor acceptance.
- Linux x86_64 Landlock/seccomp qualification for Python `unittest`.
- Digest-bound local qualification receipts with replay protection.
- Codex-first eight-tool read/proposal MCP surface.
- Reversible `sos init --with-codex` lifecycle with one aggregate preview.
- Reproducible wheel, content-safety, SBOM and release-manifest tooling.
- Typed host and filesystem admission for the Linux execution substrate.
- Deterministic zero-provider WebM/MP4 demo media and a factual coexistence
  comparison.
- Exact package/executor binding for qualification currentness and a qualified
  manual `N -> N+1 -> N` update/downgrade path across shared tool environments.
- Shared decision core with native Linux, Windows, and macOS filesystem
  adapters.
- Self-contained native private-alpha launchers with SOS-owned Python, `uv`,
  and wheel dependencies.
- Native macOS Apple Silicon install, smoke, same-version update, and removal
  lifecycle with repository-owned `.sigma` preservation.
- Per-user Windows 11 x86_64 MSIX packaging, exact Microsoft Store identity,
  offline payload, and semantic content reproducibility gates.
- Agent-first release pointer and index contracts with exact Linux and macOS
  archive bindings. Availability still requires the immutable tag and all
  declared GitHub Release assets.

### Security

- Fail-closed handling for foreign, forged, replayed, stale and incomplete
  authority, qualification and managed-file state.
- Unsupported hosts, filesystems, execution identities, and qualification
  profiles fail before preview, confirmation, or canonical bootstrap mutation.
- Release/build dependencies are pinned above their known-vulnerability floors
  and audited in CI and the publication workflow.
- Package replacement preserves immutable receipt history but fails stale until
  setup rebind, agent restart, and separate per-project qualification complete.

[0.1.0a7](https://github.com/sigmastratum/sigma-operator-stack/releases/tag/v0.1.0a7)
is the current installable Community Alpha. The public
[0.1.0a5](https://github.com/sigmastratum/sigma-operator-stack/releases/tag/v0.1.0a5),
[0.1.0a3](https://github.com/sigmastratum/sigma-operator-stack/releases/tag/v0.1.0a3)
and [0.1.0a4](https://github.com/sigmastratum/sigma-operator-stack/releases/tag/v0.1.0a4)
releases are immutable predecessors, not current installation authority.
`0.1.0a2` and `0.1.0a6` remain unpublished historical candidates and have no
public release permalink.
