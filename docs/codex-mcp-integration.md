# Codex MCP integration

SOS supports one bounded local Codex profile. Codex officially supports
project-scoped `.codex/config.toml` files for trusted projects and STDIO MCP
servers with `command`, `args` and `cwd`; its desktop app, CLI and IDE extension
share that configuration on the same host. See the official
[Codex MCP documentation](https://learn.chatgpt.com/docs/extend/mcp).

## First consumer setup

Install SOS from a non-editable package in the Python environment that should
serve MCP, initialize the repository, then run:

```text
sos setup install codex PATH
```

SOS first returns a content-safe preview. Installation requires an observed
controlling terminal and one aggregate confirmation. `--yes` suppresses the
prompt but does not bypass the terminal boundary. The setup coordinates exactly
two managed targets in this order:

1. one bounded, public-safe project recovery block in `AGENTS.md`;
2. one project-scoped read-only SOS MCP block in `.codex/config.toml`.

The targets are projected as one batch. A second-target failure cannot become
installed: SOS records the incomplete batch, and `sos setup recover codex`
rolls back in exact reverse order from the append-only journals. No wildcard,
arbitrary replacement or write beneath `.sigma/` is admitted.

Codex loads project-scoped MCP configuration only for a project the user has
trusted. SOS never grants that trust on the user's behalf. Restart the relevant
Codex desktop or IDE client after installation; a new CLI invocation reads the
new configuration.

The managed Codex block freezes:

- the absolute Python executable used by the installed package;
- `python -m sos mcp` with an exact expected package version;
- the exact repository root and working directory;
- only `sos_status`, `sos_doctor`, `sos_recover` and `sos_check`;
- `default_tools_approval_mode = "writes"`, so a future tool not marked
  read-only does not inherit silent approval.

The integration exposes no acceptance, regeneration, qualification,
arbitrary-shell, commit, push, deploy, provider or production tool. The MCP
tool declarations carry explicit read-only, non-destructive annotations.

Adding either managed target changes application state. An already initialized
SOS workspace therefore becomes stale until the normal successor proposal and
human acceptance sequence binds that project change. Exact removal or recovery
also does not silently rebind accepted state: a stale workspace must use
`sos regenerate` and accept the exact successors before another install. This
is deliberate; consumer wiring is never hidden from source currentness.

## Status and removal

```text
sos setup status codex PATH
sos setup recover codex PATH
sos setup remove codex PATH
```

SOS keeps one content-safe consumer manifest under `.sigma/`; it stores
digests, relative target identifiers and package metadata, never raw target
content or absolute paths. The manifest is bound to the append-only
[managed-file journals](managed-file-journal.md) and their reviewed batch
projection. Each target records `apply_prepared` before mutation and `applied`
after it. Only an `integrated` two-target projection may finalize as installed.
Status fails closed on repository, package, launcher, manifest, journal, batch
or target drift.

Removal requires a controlling terminal and one aggregate confirmation. It
restores the exact original targets in reverse order only when the complete
current bytes and managed digests match. A target created solely by SOS is
removed; `.codex/` is removed only when SOS created it and it is empty.
`.sigma/` and accepted records are always retained. User edits block automatic
removal and require manual resolution. Exact managed cleanup remains available
after a package upgrade because it does not execute the old launcher. Removal
records every `rollback_prepared` before mutation and every `rolled_back`
before advancing the consumer manifest.

The older `sos client install|status|remove codex` commands remain for bounded
compatibility. A new aggregate install is owned by `sos setup`; client status
and removal detect that manifest and route through the same two-target
lifecycle.

## Current boundary

This is the first Codex consumer slice, not a broad compatibility claim.
Claude, other clients, update semantics and cross-server qualification remain
separate gates.
