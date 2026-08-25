# Version update and downgrade

SOS Community alpha uses an explicit, pinned and local-first update contract.
SOS never checks for updates, downloads a package, runs qualification or
activates a capability automatically.

## Alpha contract

Before updating, retain the exact predecessor wheel and its SHA-256. Acquire
the successor wheel separately and verify its published SHA-256 before changing
the tool environment.

For a project at `PATH`:

```text
sos status PATH
sos setup status codex PATH

uv tool install --force --no-config --no-sources --no-build \
  --no-python-downloads /exact/local/sigma_operator_stack-NEXT.whl

sos propose-update PATH
sos setup update codex PATH
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

If setup rebind or qualification fails, preserve the failure receipt and
reinstall the retained exact predecessor wheel:

```text
uv tool install --force --no-config --no-sources --no-build \
  --no-python-downloads /exact/local/sigma_operator_stack-PREVIOUS.whl

sos propose-update PATH
sos setup update codex PATH
```

Restart Codex and run `sos qualify PATH` separately. Do not delete `.sigma` or
run regeneration to hide an update failure.

## Shared tool environment

A user-level `uv tool` environment may serve more than one project. SOS does
not keep a global project inventory in this alpha. Instead, qualification is
bound to the exact executable package identity. After replacement, every
project opened by the new package independently reports its previous
qualification as stale and requires its own setup rebind and qualification.
No receipt, accepted record or currentness state is shared between projects.

Already-running agent processes are not evidence of the new package. Update
completion requires closing them and starting a fresh process after setup
rebind.

## Deferred

Automatic update discovery, background network calls, side-by-side package
slots, automatic binary rollback, schema migration, vector-memory activation
and fleet rollout are outside this alpha contract.
