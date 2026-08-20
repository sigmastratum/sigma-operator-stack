# Managed external-file journal

SOS keeps repository-owned application files outside the canonical `.sigma/`
bootstrap transaction. A managed write therefore uses a separate, reversible
and non-authoritative journal. The journal does not accept governance records,
grant tool authority or make an application change current.

## Closed contract

Each journal owns one stable integration ID and one exact project-relative
target. A sealed plan records only:

- repository identity and relative target;
- `create_file` or `append_suffix` patch kind;
- before, patch and after byte counts and SHA-256 digests;
- explicit declarations that raw content and absolute paths are absent.

Arbitrary replacement, fuzzy patching, wildcard paths and writes under
`.sigma/` are unsupported. Existing content can only receive an exact suffix;
rollback removes that suffix only while all expected bytes and digests match.
New files can only be removed while their complete digest still matches.

The two Draft 2020-12 contracts are:

- `sos-managed-file-plan-v1.schema.json`;
- `sos-managed-file-event-v1.schema.json`.

## Append-only lifecycle

Plans are immutable and addressed by digest. Events are immutable ordinal
files linked by the predecessor event digest:

```text
apply_prepared -> applied -> rollback_prepared -> rolled_back
```

The next cycle may start only after `rolled_back`. Missing ordinals, duplicate
ordinals, invalid transitions, changed bytes, repository mismatch, a foreign
plan or a broken predecessor hash fail closed. A consumer manifest binds its
expected terminal journal state, so deletion of the latest event cannot turn
an installed or removed integration green.

The prepared event is durable before a target mutation. The applied or
rolled-back event is durable before the consumer manifest advances. Recovery
compares the exact target state with the plan and either completes the same
transition or returns typed stale/blocked state. It never guesses new patch
bytes.

## Multi-target composition

An immutable batch binds up to 32 unique journal IDs and exact relative
targets in one fixed order. It contains only repository identity, stable IDs,
plan digests, patch kinds and target names; raw bytes and absolute paths remain
absent. Its two additional Draft 2020-12 contracts are:

- `sos-managed-file-batch-v1.schema.json`;
- `sos-managed-file-batch-projection-v1.schema.json`.

Forward coordination prepares and applies one target at a time. Explicit or
failure-driven rollback visits completed targets in strict reverse order. A
prepared target is never falsely marked applied or rolled back. When a crash,
drift or consumer failure prevents completion, the read-only batch projection
returns exactly `integration_incomplete` with `recovery_required=true`.

Recovery probes each target against the sealed before/after digests. It may
complete one already-prepared exact operation only so the frozen four-state
journal can immediately traverse reverse rollback. Foreign or ambiguous bytes
stop recovery unchanged. Consumer callbacks are internal seams and are not
available through CLI or MCP.

## Current consumer and residuals

The Codex MCP lifecycle is the first consumer. Its config installation and
removal use the general journal plus atomic exchange/move-aside target
operations. Crash recovery is covered before target mutation, after target
mutation and after rollback.

The one-target journal and bounded multi-target coordinator are reusable
primitives. Codex remains the first concrete client consumer. Wiring the batch
into the complete bootstrap/update/uninstall journey, broader qualification,
Claude parity, cross-server verification, push, publication and release are
not claimed here.
