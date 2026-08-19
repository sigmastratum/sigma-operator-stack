# Codex MCP integration

SOS supports one bounded local Codex profile. Codex officially supports
project-scoped `.codex/config.toml` files for trusted projects and STDIO MCP
servers with `command`, `args` and `cwd`; its desktop app, CLI and IDE extension
share that configuration on the same host. See the official
[Codex MCP documentation](https://learn.chatgpt.com/docs/extend/mcp).

## Install

Install SOS from a non-editable package in the Python environment that should
serve MCP, initialize the repository, then run:

```text
sos client install codex PATH
```

SOS first returns a content-safe preview. Installation requires an observed
controlling terminal and one confirmation. `--yes` suppresses the prompt but
does not bypass the terminal boundary.

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

Adding `.codex/config.toml` changes application state. An already initialized
SOS workspace therefore becomes stale until the normal successor proposal and
human acceptance sequence binds that project change. This is deliberate: the
client adapter is not hidden from source currentness.

## Status and removal

```text
sos client status codex PATH
sos client remove codex PATH
```

SOS keeps a content-safe integration manifest under `.sigma/`; it stores
digests and package metadata, never raw config or absolute paths. The manifest
is bound to the general append-only
[managed-file journal](managed-file-journal.md). Installation persists an
immutable plan and `apply_prepared` event, updates the client file, appends the
`applied` event and only then marks the integration installed. Status fails
closed on repository, package, launcher, manifest, journal or config drift.

Removal requires a controlling terminal and confirmation. It removes only the
exact marked suffix whose complete config, original prefix and managed block
digests still match. An existing config is restored byte for byte. A config
created solely by SOS is removed, and its directory is removed only when SOS
created it and it is empty. `.sigma/` and accepted records are always retained.
User edits block automatic removal and require manual resolution. Exact managed
cleanup remains available after a package upgrade because it does not execute
the old launcher. Removal records `rollback_prepared` before mutation and
`rolled_back` before advancing the manifest. Removal restores Git-visible
content but does not claim to advance or rewrite accepted SOS source
observations; a prior accepted adapter change still follows the normal
successor lifecycle.

## Current boundary

This is the first Codex adapter slice, not a broad compatibility claim. Claude,
other clients, multi-target update/uninstall composition and cross-server
qualification remain separate gates.
