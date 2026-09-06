# Changelog

All notable changes are recorded here. The format follows Keep a Changelog and
the project uses semantic versioning after the pre-1.0 stability boundary.

## 0.1.0a5 — Unreleased

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

[0.1.0a2](https://github.com/sigmastratum/sigma-operator-stack/releases/tag/v0.1.0a2)
and [0.1.0a3](https://github.com/sigmastratum/sigma-operator-stack/releases/tag/v0.1.0a3)
are immutable predecessor releases. The `0.1.0a4` release link is added only
after its exact candidate is tagged and its assets are public.
