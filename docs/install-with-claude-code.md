# Install SOS with Claude Code

Use the same verified public SOS release route as the Codex installation, but
select the repository-scoped Claude Code adapter:

```text
Install-SOS.command install PATH --client claude-code \
  --maintenance-release-binding-json '<verified-binding>'
```

The launcher verifies the exact bundle, installs the pinned SOS application,
shows one aggregate project preview, and waits for the human confirmation. It
then manages only:

- one bounded recovery block in root `CLAUDE.md`;
- one `sigma_operator_stack` project server entry in `.mcp.json`;
- adapter evidence under `.sigma/integrations` and managed-file journals.

Existing bytes, formatting, instructions, rules, settings, hooks, skills,
commands and agents are preserved. SOS never writes Claude user configuration,
credentials, trust state, permissions, or hooks. A server-name collision,
invalid/duplicate-key JSON, symlink, drift, or unverifiable rollback stops with
a typed result.

After installation, restart or reopen Claude Code in the project and complete
Claude Code's ordinary project-server approval. Until that independent action
is observed, the truthful result is
`SOS_INTERACTIVE_USER_HANDOFF_REQUIRED`; it is an installed adapter state, not
an SOS failure and not evidence that Claude accepted the server.

Then inspect and qualify separately:

```text
sos integrations PATH
sos setup status claude-code PATH
sos qualify PATH
```

To detach only this adapter while preserving `.sigma`, Codex, other clients,
and the shared SOS application:

```text
Install-SOS.command detach PATH --client claude-code \
  --maintenance-release-binding-json '<verified-binding>'
```

Version-changing update and application removal are refused while SOS lacks a
global inventory of every project using the shared environment. Exact
same-version repair uses `sos setup update-all PATH` and never calls a package
manager.

No actual Claude Code process or provider turn is part of this implementation
claim. That recovery and stale-state scenario remains the independent Q1 gate.
