# One-command Codex lifecycle

Community v0.1 supports one client path:

```text
sos init --with-codex PATH
```

The command computes an overlay-aware post-managed application fingerprint,
shows one aggregate preview, and asks once. That confirmation binds the
canonical bootstrap subplan, exact two-target Codex setup, launcher/package
binding and reverse rollback plan. Qualification is excluded and remains the
separate `sos qualify` action.

Before canonical commit, SOS creates one sibling `.sigma.init.<transaction>`
journal. Managed targets are applied in order, their actual fingerprint must
equal the preview, and the fully bound control plane is then admitted through
a no-replace atomic rename. A crash before commit is recovered by exact probe
and reverse rollback; incomplete state is never projected as installed.

Re-running the command is idempotent. Foreign managed markers, incompatible
`.sigma`, symlinks, changed preview input and target drift fail closed without
overwrite. Package update is local and proposal-first; it rebinds the package
version and launcher digest without changing accepted records. Setup removal
must succeed before package uninstall and never removes `.sigma`.

The convenience installer claim is version-pinned, not a signed or
high-assurance installer claim. `uv` and package acquisition are prerequisites
outside the SOS entrypoint. SOS itself has no network, telemetry or automatic
update phase.

This candidate has not been qualified on an external or second server.
Cross-server compatibility, public availability and release readiness remain
unclaimed until the separately gated packet is executed successfully.
