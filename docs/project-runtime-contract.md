# Project-runtime contracts (a6 candidate)

The a6 candidate connects the pure validators in `sos.project_runtime` to the
native carrier. This describes candidate behavior, not an activated public
release. Published a5 assets and its original P106 receipt remain unchanged.
Native qualification and release admission are separate gates.

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
write a journal, or verify successful mutation. The outer runtime coordinator
must verify those facts before persisting events. The native CLI invokes that
coordinator; the eight-tool MCP read/proposal boundary is unchanged.

Records are closed dictionaries, contain no raw paths or prompts, and validate
their canonical digest and exact false content-serialization flags. The returned
objects are detached copies. No filesystem writes, network or package-manager
calls are performed.

## POSIX reservation mechanism

`sos.platforms.project_runtime_posix` separately observes root/user anchors and
reserves `<project-runtimes>/<project-key>/<generation-key>` at its final path.
The reservation API requires a private namespace outside the project. The
confirmed carrier prepares its bounded namespace parents separately; this is
not a general directory-creation or cleanup API.
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
human confirmation must be established by the carrier, not by the presence of
that string. The candidate installer calls this API only after confirmation.

POSIX filesystem tests currently provide Linux-host evidence only. macOS native
behavior, persistent schema integration, relocation and namespace provisioning
remain unqualified. Same-user malicious renames or edits are not authenticated
by these local markers. The mechanism must not be used as a privilege boundary.

## Explicit payload installation

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

A closed wheel-inventory check is now required before and after the SOS version
check. The caller supplies the complete release-bound wheel filename/digest
inventory; sources and duplicate/version mismatches are checked before commands.
Installed files must match those wheels. Rewritten RECORD and bounded installer
metadata are permitted; unexpected directories, distributions, code, bytecode
and symlinks refuse. Import-hook reference bytes are independently generated by
the already checked uv binary in a temporary reference environment inside the
generation. They are never learned from the installation being verified.
Bytecode writing is disabled during provisioning. This is an initial payload
gate, not a general verifier for an active environment containing runtime caches.

A successful inventory and SOS version check writes `payload-installed.json`, still with
`runtime_ready=false` and `adapter_switch_performed=false`. It is not proof of
adapter integrity or a completed migration. Interrupted/failed attempts retain
their marker and material for later explicit recovery; no implicit retry, deletion
or switch occurs. The marker binds wheel/installed-inventory digests, not a claim
of full interpreter-tree verification, project migration or adapter readiness.
Adapter transaction, interpreter acquisition, current maintenance selection and
qualification checks remain separate requirements.

`observe_verified_generation_launcher` rechecks reservation, installed inventory,
payload receipt, venv isolation configuration and the independently expected
interpreter digest. It returns an ephemeral venv Python path/version/digest for
the later P107 binding, never a persisted raw path or activation authority.
A reserved or incomplete generation cannot supply that observation. The outer
transaction repeats admission under its locks before adapter writes.

## Adapter integration boundary

The source tree includes the single atomic adapter coordinator in
`sos.atomic_switch`; runtime integration must reuse that coordinator and its
rollback journal. The outer transaction calls it after verified provisioning.

Synthetic two-project tests exercise adapter switching, interruption recovery
and detach with explicit launcher bindings and a reserved generation. They prove
that those adapter operations preserve the second project's bindings/files and
runtime material. They do not execute an installed predecessor/successor package,
mark a reservation ready, resolve a runtime transition as current maintenance or
remove an isolated generation. Adapter detach alone does not authorize runtime
deletion. Installed-package replay and independent review are separate evidence
requirements; synthetic coverage must not be described as native lifecycle pass.

## Local outer transition coordinator (not publicly activated)

`sos.runtime_transition` composes the POSIX provisioner and the existing P107
coordinator. Its carrier must supply independently verified release acquisition
inputs. It is not canonical pointer/archive admission and is not connected to
the published install/update/remove entrypoints.

The read-only aggregate preview binds original install receipt, prior transition
history, old/new maintenance identities, final generation and executable binding,
uv/wheel inventory, network choice, control-plane/application observations, and
exact before/after adapter target hashes and modes. Target images are rendered
in memory using the adapters' existing renderers; raw images and paths are not
serialized. Confirmation requires the exact aggregate digest and an observed TTY.
Provisioning occurs afterward; incomplete payloads cannot reach P107.

Lock order is outer project transaction, runtime namespace, P107 coordinator,
then its managed-file locks. Acquisition takes the namespace lock separately
before switching; admission is repeated under switching locks. P107 remains the
sole adapter writer/rollback mechanism. Its optional in-process admission and
postcheck hooks do not change its existing persisted plan contract.

`lifecycle/runtime-transitions.json` stores bounded digest-linked transition
history separately from the immutable original P106 receipt. Missing middle
events, malformed records, mismatched original/previous history, and incomplete
transactions refuse maintenance selection. A crash in P107 uses P107 rollback;
a crash after its committed event can complete the outer terminal record only
after verifying adapters and runtime. Foreign drift or uncertain journal writes
remain recovery-required, never guessed successful.

Maintenance resolution currently selects local provenance only, not runtime
health or release admission. Local history is weak same-user evidence, not an
authenticated append-only service: deletion of all history cannot be detected by
its own hash chain. Public maintenance routing must also verify installed adapter
bindings and exact release evidence before using this selection.

Remaining release gates include full installed two-project cross-version replay,
exact source/wheel qualification, native macOS replay and independent review.
Runtime removal is separate from this coordinator. Synthetic orchestration tests mock
payload acquisition/verification and execute real adapter/journal code; they are
not a native installed-package migration pass.

## Active cache verification

Initial provisioning still rejects bytecode. Active verification separately
allows only CPython 3.12 cache names for exact known wheel/hook source files.
The expected interpreter digest is checked before and after a bounded `-I -S -B`
compiler invocation. It compiles checked source in memory without executing it
and compares the complete marshalled code body, not only its timestamp/hash
header. Unknown sources, malformed headers, different code bodies, symlinks and
interpreter mismatch refuse. Cache bytes are not included in the stable installed
payload digest. This does not claim verification of the entire Python stdlib.

## Detached generation removal

`sos.runtime_removal` admits only the latest committed project's generation,
after every supported adapter has a verified removed/rolled-back manifest.
Historical removed predecessor adapters need not name the active generation;
actual configuration is checked for surviving SOS references. Unknown references or nonterminal P107/runtime journals
block removal. It does not prune predecessors or the legacy shared environment.
It is a runtime-only API after official adapter removal. `sos.native_removal`
provides the user's single aggregate preview and confirmation before detach.

The preview binds complete owned-generation snapshot, current transition history,
identity, entry count and byte count. Exact digest and TTY confirmation are
required. A durable private snapshot precedes the first unlink. Descriptor-relative
deletion never follows symbolic links; files/inodes/modes are rechecked, new or
changed entries stop deletion, and recovery reloads the snapshot from disk.
Removal preserves `.sigma` and all paths outside the selected generation.
Partially deleted runtime bytes are not recoverable: the reported recovery path
finishes the already approved removal, not rollback. Foreign changes may require
operator resolution. Same-user hostile races and arbitrary unmanaged external
references are not authenticated by these local ownership records.

# Native maintenance bootstrap boundary

For install, update, detach, remove, recover and test, the POSIX shell verifies
the bundled uv and prepares a disposable controller outside the project. Managed
Python 3.12.14 acquisition may use the network; package installation uses the
checked offline wheelhouse. Preparation is announced before preview. No shared
a5 environment, PATH, shell profile or system Python is changed. The disposable
controller is cleaned on normal exit. Permanent generations are created only
after exact confirmation.

The interactive controller has no whole-session deadline: time spent awaiting
the owner's answer never confirms or cancels a plan automatically. Interpreter,
inventory, provisioning and smoke operations retain their individual deadlines.
Cancellation targets only the controller's newly created process group, with
bounded graceful and forced termination. If termination cannot be confirmed,
disposable preparation is retained and maintenance is blocked. Diagnostic
readback never modifies transition journals or claims a rollback. A pending
transition requires official recovery using its original exact release binding;
matching the unpublished version number alone does not grant recovery authority.
Best-effort stage messages are progress, not proof of a committed transition.

## Disposable controller and fresh-process reconstruction

Controller preparation verifies the extraction's manifest/release handoff and
exact wheelhouse, then unpacks root-layout wheels into a private disposable import
root. It uses observed managed Python 3.12.14 with `-I -S -B`: no editable install,
package-manager invocation, `.pth` execution, user site, or shared tool upgrade.
Conflicting members, links, traversal, import hooks and changed payloads refuse.
The bounded import inventory and interpreter digest are rechecked before command
construction. This is not authentication against a malicious same-user process.

The native update controller derives the predecessor from exact installed adapter
configuration and terminal maintenance history, not PATH or its own interpreter.
It rechecks successor manifest/artifacts and delegates preview/transition to the
existing coordinator. Namespace creation occurs only after confirmation and the
locked preview recheck. Version-changing native update dispatch now uses this
controller without reinstalling the shared package. Fresh installs use a
project-isolated generation; same-version updates verify that generation and
change only adapters. Public smoke selects the active bound interpreter, not
shared PATH. Truthful stale/not_verified states never become qualification green.

Fresh install computes the final launcher and bootstrap plan with one
confirmation seed. A root-bound durable intent is written before provisioning;
recovery reloads it, checks exact successor inputs and verifies the generation
again, including authenticated active caches. Incomplete provisioning remains
`recovery_required` with retained material, never an implicit retry or green
runtime. A completed bootstrap can publish its missing final runtime record from
a fresh process. Normal install refuses an existing intent instead of overwriting
it.

Aggregate removal binds the generation snapshot before detach. Official setup,
P107 and removal share the adapter lock; incomplete removal blocks new setup.
Before irreversible deletion begins, changed owned bytes require a new explicit
preview. Once deletion starts, recovery resumes only the retained approved
snapshot. Shared a5 and predecessor generations are never automatically pruned.

`load_runtime_transition` reconstructs the saved plan with freshly verified wheel
paths and explicit predecessor/namespace observations. It preserves the original
plan digest and refuses release, wheelhouse and launcher drift. Recovery before
the switching intent can explicitly abort after verifying unchanged predecessor
targets and absence of a conflicting P107 plan. It retains any incomplete runtime
files. Recovery during switching continues through the existing P107 journal.

Launcher digests at the adapter boundary use the platform's qualified
`sha256:<hex>` format. Raw wheel/file checksums are converted only at that
boundary; unpublished raw-digest P107 fixtures are not a production contract.

During the outer runtime transaction only, a complete, valid control-plane
observation may remain source-stale after the intended adapter change. P107
enables that path only when its caller supplies a target postcheck; the outer
coordinator checks the exact expected target bytes and projected application
fingerprint before commit. Ordinary setup update keeps its default postcheck,
and invalid/incomplete observations still refuse. Adapter success does not
qualify or reaccept the changed source.

### Offline maintenance controller

The default carrier may acquire pinned Python for its disposable controller;
it is not a promise of offline bootstrap. With a previously verified complete
bundle, `remove`, `detach`, `recover` and `test` also accept the paired options
`--controller-python` and `--controller-python-sha256`. The caller must supply
an independently verified, retained Python 3.12.14 outside project generations.
No Python discovery, acquisition or online fallback occurs in this mode.
The executable checksum establishes consistency, not independent authenticity.
The interpreter, its standard library and dependencies must remain available
outside the runtime being removed. Links at the executable and project-runtime
locations are rejected. No system Python installation or PATH repair is needed.
