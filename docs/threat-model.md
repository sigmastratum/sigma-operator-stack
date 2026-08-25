# Threat model

## Protected outcomes

SOS is designed to keep a coding agent from silently:

- inventing authoritative project state;
- treating stale source as verified;
- overwriting foreign project or agent configuration;
- converting missing, skipped, unsupported, or forged checks into green;
- using its MCP surface as a shell or deployment channel;
- serializing protected project content into receipts or diagnostics.

## Adversarial and failure conditions

- competing or malformed governance roots;
- staged, unstaged, untracked, deleted, symlink, submodule, or ignored state;
- changed bytes after preview, path races, collisions, and partial writes;
- forged, replayed, rolled-back, expired, or source-mismatched receipts;
- hostile project tests attempting network, process, mount, namespace, or
  out-of-root filesystem access;
- unavailable or downgraded Landlock, `no_new_privs`, or seccomp capability;
- oversized inputs, outputs, file sets, environment, or process activity;
- interruption during bootstrap, setup, qualification, update, or removal.
- a shared user-level tool replacement leaving one or more projects falsely
  green under executable bytes they did not qualify;
- setup rebind being mistaken for successful successor qualification.

## Controls

- fail-closed typed states and deterministic reason precedence;
- immutable digest-linked lineages and monotonic tips;
- fresh observation before authoritative reads and before execution;
- one-use nonce and expiry for qualification admission;
- fixed command arguments, closed environment, bounded output and timeout;
- read-only source projection plus bounded writable output root;
- exact managed-file journal with reverse-order rollback;
- package-version and executable-resource identity in qualification bindings;
- per-project stale projection after upgrade or downgrade, with explicit agent
  restart and separate qualification required;
- content-safe outputs that omit raw project bytes and environment values.

## Explicit non-goals

The alpha is not an authentication system, a general hostile-code sandbox, a
remote policy service, or permission to deploy. It does not prove every future
kernel, Python, Git, `uv`, Codex, language, or framework compatible. It does
not protect against an already-compromised operating system or repository
owner.

The alpha update contract is deliberately manual. It does not provide a global
project inventory, side-by-side executable slots, automatic binary rollback,
state-schema migration, or capability activation. The predecessor artifact
must be retained until the successor has qualified.
