# Project-runtime contracts (inactive)

The pure validators in `sos.project_runtime` are an implementation foundation,
not an available installation or migration route. The published installer,
runtime location and P106 receipt format are unchanged.

`sos_project_runtime_identity_v1` binds separately observed user, canonical-root
and repository digests to a project key. Its generation key additionally binds
the maintenance release, wheel and interpreter digests. Keys are domain-separated
SHA-256 values. Moving a project, copying its repository identity to another root,
or changing the observed user invalidates the old ownership comparison.

Callers must independently observe the filesystem owner and canonical project
root without following untrusted links. Reading these values from a marker and
passing them back as expected inputs proves nothing. This module performs no
filesystem observation and hashes do not authenticate a malicious same-user edit.
Generation consistency does not prove the wheel or interpreter was acquired or
verified against the release manifest; acquisition must establish that separately.
Linux x86_64 and macOS arm64 metadata are admitted; this is not native execution
qualification and does not add Windows migration support.

`sos_project_runtime_transition_event_v1` carries only digest anchors and phase
metadata: plan, original predecessor receipt, successor runtime identity, prior
event, sequence and phase. Validators accept the following structural progression:

```text
previewed -> confirmed -> provisioning -> ready -> switching -> committed
```

Pre-switch phases may abort. Provisioning, ready and switching may enter
`recovery_required`; switching or recovery may end `rolled_back`. Terminal states
cannot reopen. Recovery does not transition directly to committed. A later retry
requires a new plan and separately admitted transaction, not alteration of history.

Full-chain validation requires independently retained plan, receipt, identity
and expected-tip anchors. Missing/reordered/duplicate events, forks and truncation
against that tip are rejected. A caller supplying an untrusted prefix's own tip
cannot claim that the validator detected truncation of a longer history.

These functions can construct a structurally valid `confirmed` or `committed`
record. They do not provide human approval, provision a runtime, switch adapters,
write a journal, or verify successful mutation. A future coordinator must verify
those facts before persisting events. No CLI or MCP action currently invokes this
module; the eight-tool read/proposal boundary is unchanged.

Records are closed dictionaries, contain no raw paths or prompts, and validate
their canonical digest and exact false content-serialization flags. The returned
objects are detached copies. No filesystem writes, network or package-manager
calls are performed.

## Inactive POSIX reservation mechanism

`sos.platforms.project_runtime_posix` separately observes root/user anchors and
reserves `<project-runtimes>/<project-key>/<generation-key>` at its final path.
The namespace must already exist as an explicitly provisioned private directory
outside the project; this is not a general directory-creation or cleanup API.
The legacy shared-runtime namespace is rejected.

Every ancestor is opened without following symlinks. User-owned private
namespace/project directories and exact ownership markers are required. A
nonblocking namespace descriptor lock serializes reservations. Unknown existing
directories, foreign markers and existing generation paths are not adopted or
overwritten. Failed reservation material is retained for explicit recovery;
this mechanism has no deletion or automatic retry path.

The resulting record says `reserved`, with `runtime_ready=false`. It does not
install Python, verify an executable, acquire adapters, write project files or
modify the legacy runtime. It records a caller-supplied confirmed-plan digest;
human confirmation must be established by the future coordinator, not by the
presence of that string. The normal installer does not call this API yet.

POSIX filesystem tests currently provide Linux-host evidence only. macOS native
behavior, persistent schema integration, relocation and namespace provisioning
remain unqualified. Same-user malicious renames or edits are not authenticated
by these local markers. The mechanism must not be used as a privilege boundary.

## Explicit payload installation (not wired to the installer)

`install_reserved_wheel` is a separate low-level mechanism. Its caller must first
verify the canonical release/archive, complete manifest and wheelhouse and acquire
the expected Python executable digest. This API does not replace public release
admission. It rechecks the supplied uv and wheel digests, exact reservation and
plan digest before a single attempt. Unknown/previously attempted state refuses.

It installs managed Python 3.12.14 into that generation, checks its expected
executable digest and version, then installs the checked SOS wheel using offline,
no-build, no-index acquisition from the supplied wheelhouse. Tools, Python, cache
and temporary directories are generation-local. Python download requires an
explicit flag; no ambient UV/Python configuration is inherited. No PATH or shell
profile is changed. Each child command has a timeout and its raw output is not
serialized into evidence.

A successful SOS version check writes `payload-installed.json`, still with
`runtime_ready=false` and `adapter_switch_performed=false`. It is not proof of
adapter integrity or a completed migration. Interrupted/failed attempts retain
their marker and material for later explicit recovery; no implicit retry, deletion
or switch occurs. Full installed-package inventory, adapter transaction and
qualification checks remain higher-level admission requirements.

## Adapter integration boundary

The source tree includes the single atomic adapter coordinator in
`sos.atomic_switch`; runtime integration must reuse that coordinator and its
rollback journal. The reservation/provisioning mechanisms do not call it yet.

Synthetic two-project tests exercise adapter switching, interruption recovery
and detach with explicit launcher bindings and a reserved generation. They prove
that those adapter operations preserve the second project's bindings/files and
runtime material. They do not execute an installed predecessor/successor package,
mark a reservation ready, resolve a runtime transition as current maintenance or
remove an isolated generation. Adapter detach alone does not authorize runtime
deletion. Full migration remains unavailable until those admission, transition
and ownership/reference checks are implemented and independently verified.
