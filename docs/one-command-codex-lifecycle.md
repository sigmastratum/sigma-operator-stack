# One-command Codex lifecycle

Community v0.1 supports one client path:

```text
sos init --with-codex PATH
```

For an existing mature repository, inspect the zero-write compatibility
projection first:

```text
sos compatibility PATH
```

The projection reports `preserve`, `append`, `create` or `block` for existing
agent instructions, Codex/SOS state and the bounded OpenSpec, BMAD, spec-kit
and governance-root grammar. Multiple recognized authority systems return
`owner_required`. Continue only with one exact ID from that projection:

```text
sos init --with-codex --primary-authority '<discovered-id>' PATH
```

The selection and discovery digest are bound into the aggregate plan and the
canonical authority record. A changed directory, file, selection or managed
target makes the preview stale before any write.

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
high-assurance installer claim. The released platform launcher verifies its
exact manifest and owns bounded acquisition of pinned managed Python, `uv` and
package dependencies. The developer does not install those dependencies or
repair `PATH` manually. Acquisition is the only declared network phase; after
the verified launcher handoff, the SOS entrypoint has no network, telemetry or
automatic update phase.

The transferable wheel is built from an exact committed tree with one
repository-owned offline entrypoint:

```text
python3 tools/build_release_wheel.py \
  --candidate <exact-40-character-commit> \
  --output-dir <repository-external-directory>
```

The builder archives only the exact commit, derives `SOURCE_DATE_EPOCH` from
that commit, disables indexes, dependency resolution, build isolation and pip
configuration, and emits the candidate, tree, epoch, filename and SHA-256 as
canonical JSON. Two builds in independent directories must produce identical
wheel bytes before the digest enters a transfer or qualification packet.

Cross-server qualification is specific to the exact release artifact. Local
green alone does not establish broad compatibility. Release evidence binds the
candidate, wheel digest and exact observed environment; publication and release
readiness remain separately gated.
