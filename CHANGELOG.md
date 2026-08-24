# Changelog

All notable changes are recorded here. The format follows Keep a Changelog and
the project uses semantic versioning after the pre-1.0 stability boundary.

## [0.1.0a1] - Unreleased

### Added

- Local-first repository authority, current-work and recovery records.
- Exact stale detection and append-only successor acceptance.
- Linux x86_64 Landlock/seccomp qualification for Python `unittest`.
- Digest-bound local qualification receipts with replay protection.
- Codex-first eight-tool read/proposal MCP surface.
- Reversible `sos init --with-codex` lifecycle with one aggregate preview.
- Reproducible wheel, content-safety, SBOM and release-manifest tooling.
- Typed host and filesystem admission for the Linux execution substrate.

### Security

- Fail-closed handling for foreign, forged, replayed, stale and incomplete
  authority, qualification and managed-file state.
- Unsupported native hosts and Windows-backed/shared mounts fail before
  preview, confirmation or canonical bootstrap mutation.

[0.1.0a1]: https://github.com/sigmastratum/sigma-operator-stack/releases/tag/v0.1.0a1
