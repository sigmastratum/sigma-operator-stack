# Version update and downgrade

SOS Community alpha uses an explicit, pinned and local-first update contract.
SOS never checks for updates, downloads a package, runs qualification or
activates a capability automatically.

Installation maintenance remains available when current work is absent or
qualification is `not_configured` or `not_verified`. Those states block green
qualification claims and project work; they are not prerequisites for an
owner-requested status check, same-version update, public smoke test or removal
preview. Maintenance must use the exact release-bound platform launcher and
must preserve its human confirmation boundary. Invalid control-plane
integrity, required recovery, managed-file drift or an unverified launcher
continues to fail closed.

The lifecycle receipt names two different identities. The MCP binding covers
the managed Python executable used for project-local MCP. The maintenance
binding covers the archive and platform launcher. Their digests are never
compared. A fresh session rediscovers the canonical pointer, downloads and
verifies a new extraction of the exact archive, and compares only the
maintenance binding before update, smoke or removal.

## Alpha contract

Before updating, retain the exact predecessor release identity and its
published digest. The platform launcher or package manager acquires and
verifies the successor application payload; users do not install Python,
`uv`, wheels, or repair `PATH` manually.

For a project at `PATH`:

```text
sos status PATH
sos setup status codex PATH
sos propose-update PATH
sos setup update codex PATH
sos setup update claude-code PATH
sos setup update-all PATH
```

The proposal must report that the agent must be restarted, the prior
qualification is no longer sufficient and the predecessor artifact must remain
available. Close the existing Codex session, open a new session for `PATH`, then
run qualification separately:

```text
sos status PATH
sos setup status codex PATH
sos qualify PATH
sos preflight PATH
```

An update changes no accepted records, user-owned files or capability state.
The prior immutable qualification receipts remain valid history, but their
executor binding is stale until the new package performs a new qualification.

## Downgrade

If setup rebind or qualification fails, preserve the failure receipt and use
the platform's verified rollback route to restore the retained predecessor
application payload. Then rebind the project:

```text
sos propose-update PATH
sos setup update codex PATH
```

Restart Codex and run `sos qualify PATH` separately. Do not delete `.sigma` or
run regeneration to hide an update failure.

## Project-isolated native runtime (a6 candidate)

This section describes the unpublished a6 candidate, not an activated release
pointer. Release admission and native platform replay remain separate gates.

The checked native launcher prepares a disposable controller without replacing
shared a5. A version-changing update shows one plan for the successor generation,
all installed supported adapters and preserved data. Exact confirmation precedes
permanent provisioning. Verified adapters switch through the shared P107 journal.
Another project still bound to a5 continues using its unchanged environment.

Fresh a6 installs also use project-isolated generations. Same-version maintenance
verifies the active generation; it does not reinstall it. An identical adapter
binding requires no mutation journal. Smoke uses the active verified interpreter,
not PATH, and preserves truthful stale/not_verified qualification states.

Interrupted mutation blocks ordinary maintenance. Use `recover` on the freshly
verified exact bundle, with its release binding and a separate confirmation.
Recovery reconstructs disk records; it does not depend on a previous extraction
or Python process. Incomplete provisioning may remain recovery-required with its
owned files retained. It must not be repaired by overwriting markers or manually
changing adapter configuration.

## Historical shared tool environment

One user-level SOS installation may serve more than one project. SOS does not
keep a global project inventory in this alpha. Qualification is bound to the
exact executable package identity. After replacement, every project opened by
the new package independently reports its previous qualification as stale and
requires its own setup rebind and qualification. No receipt, accepted record
or currentness state is shared between projects.

Because that global inventory is absent, shared-environment maintenance refuses a
version-changing package update and any package removal with
`SOS_SHARED_ENVIRONMENT_INVENTORY_REQUIRED`. An exact same-version maintenance
run may repair every adapter recorded in the selected repository through
`sos setup update-all PATH`; it makes no package-manager call.

Already-running agent processes are not evidence of the new package. Update
completion requires closing them and starting a fresh process after setup
rebind.

## Removal

Detach a project integration through the verified launcher before considering
application removal. Select the exact client (`codex` or `claude-code`); detach
never removes the shared application or managed tool environment. Application
removal from that shared environment remains blocked without a global project
inventory. The a6 candidate's project-isolated `remove` instead shows one aggregate
preview, detaches all supported adapters after confirmation and deletes only the
selected owned generation. It preserves shared a5 and all predecessor generations.
Partial deletion is recovery-required, not rollback.

Detach deletes only exact SOS-managed client integration bytes after a
preview and confirmation. It preserves `.sigma`, accepted records,
qualification history, user-owned files, and unrelated agent configuration.

Never delete `.sigma` to hide an update or removal failure. A collision,
foreign managed bytes, or an unverifiable target stops without overwrite.

## Deferred

Automatic update discovery, background network calls, automatic predecessor
pruning, automatic binary rollback, schema migration, vector-memory activation
and fleet rollout are outside this alpha contract.
