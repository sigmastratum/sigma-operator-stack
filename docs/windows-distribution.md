# Windows distribution boundary

SOS Windows public alpha uses a per-user MSIX distributed by Microsoft Store.
The Store product is **Sigma Operator Stack**, Store ID `9NNZT70C613H`. Its
canonical package identity is checked into
`installers/windows-msix/store-identity.json` and must match the exact MSIX
manifest. The unsigned ZIP and PE remain private diagnostic artifacts and are
not public distribution surfaces.

## Store signing lineage

The release process builds an exact unsigned MSIX from a clean reviewed Git
candidate and immutable payload. Build tooling runs from a separate checked
runtime; no executable inside the product payload is run while packaging.
Python bytecode and `__pycache__` are excluded because they can contain private
build paths and can change when Python imports a codec.

Two independent MakeAppx builds are unpacked by the same exact, digest-bound
MakeAppx binary with default semantic validation. The two materialized unpack
trees must have the exact expected inventory and identical bytes, including the
manifest and block map. MakeAppx keeps `[Content_Types].xml` container-only and
does not materialize it during default unpack; SOS reserves that name against
payload collisions but excludes it from the unpacked-inventory claim. Raw MSIX
container bytes may differ, so the release gate claims semantic package-content
reproducibility rather than byte-identical containers. The selected unsigned
MSIX is then frozen by its complete-file SHA-256 for upload.

The native build runner embeds the digest of one reviewed input lock. That lock
binds the candidate, source snapshot, payload artifacts, build toolchains and
MakeAppx identity before the runner is built. The outer build-packet SHA-256 is
distributed over an independent authenticated channel; a packet cannot
authenticate itself. Any package produced without both bindings is ineligible
for Store upload.

The build packet is a release-engineering tool, not an end-user installer. The
Windows SDK and MakeAppx are required only on the controlled package-build
host. Ordinary SOS users install the Store-delivered package and do not install
the SDK, Python, `uv`, or a compiler.

The package uploaded to Partner Center must match the reviewed digest and the
following Store-owned identity:

- package name: `SSRG.SigmaOperatorStack`;
- publisher: `CN=D713C275-467D-4A03-9D24-0DC02F1C3031`;
- publisher display name: `SSRG`;
- package family: `SSRG.SigmaOperatorStack_2358e20nvr064`.

Microsoft Store certification and signing are separate external operations.
The package is public only after Store certification succeeds and the owner
explicitly approves availability. Creating a local MSIX or uploading a package
does not by itself authorize publication.

## Certification and update discipline

Microsoft Store certification is an external release gate, not the inner
development loop. An in-flight package remains immutable while Microsoft
evaluates it. SOS development, documentation and offline route tests may
continue in parallel, but they do not change the submitted package.

The Windows package candidate and the public release-routing commit have
separate exact bindings. README, support text or `release/current.json`
changes do not by themselves require a rebuilt MSIX. Before publication, an
explicit rebind must prove that the unchanged Store package still matches the
advertised SOS version, platform boundary and lifecycle.

If certification or clean-host testing finds several Windows defects, they are
combined into one reviewed successor. A replacement MSIX is submitted only
for a reproducible release-blocking change to the packaged payload or
manifest, after the complete package validation and ordinary-user lifecycle
have been rerun. This avoids a one-fix/one-certification loop.

After release, ordinary SOS feature updates use the same Store identity and
per-user lifecycle. Each package update receives a higher Store transport
version and normal Store certification. The Store updates the immutable host
payload; SOS then presents a project update/rebind preview without rewriting
accepted records or deleting `.sigma`.

Azure Artifact Signing is not required for the Store-first public-alpha route.
It remains a possible future paid signing channel for direct downloads outside
Microsoft Store. Self-signed packages are limited to private development and
must not be presented as a frictionless public distribution path.

## Release build threat boundary

The unsigned package build runs as an ordinary, non-elevated user on a local
fixed NTFS volume with UAC enabled. The native runner rejects reparse points,
alternate data streams, mapped or substituted drives, unbound inputs and
drift. Child build processes are bounded as one kill-on-close process tree.

The alpha release-build gate assumes a controlled host without a concurrently
malicious process running as the same Windows identity. It does not claim to
defend an unsigned packet from an active local administrator or same-user
attacker. Store signing, Store delivery and clean-host certification are the
distribution trust boundary for users.

## Host and project authority

Installing the Store MSIX grants Windows package installation authority only.
It does not grant authority to modify a Git project. After host installation,
the user or agent runs `sos install "C:\path\to\project"`; SOS shows one
digest-bound project preview and only the user confirms that mutation.

The supported public-alpha host is Windows 11 x86_64 with UAC enabled, Defender
and SmartScreen enabled, and an ordinary Medium Integrity interactive user.
Machine-wide installation, admin helpers, hidden custom actions, enterprise
deployment, direct Windows qualification execution, and security bypasses are
outside this boundary.

## Per-user MSIX lifecycle

The package payload contains `sos.exe`, pinned Python, pinned `uv`, the exact
SOS wheel, its wheelhouse, and already installed Python modules. Package files
are immutable and Windows integrity enforcement is enabled. After Store
download, SOS performs no executable acquisition, telemetry, or update check.

`sos install PATH` maps to the existing one-preview `init --with-codex` flow.
A Store package update changes only the immutable host payload; the project is
stale until `sos update PATH` previews and rebinds its managed integration.
Accepted records are not rewritten. `sos remove PATH` removes only the exact
SOS-managed Codex integration and preserves `.sigma` and user files. Removing
the package directly in Windows Settings cannot delete repository state and can
leave the project integration disconnected until a separately installed SOS
version performs the previewed cleanup.

The checked-in MSIX builder is preparation, not a distributable package. It
requires an exact externally assembled payload, a separately reviewed exact
MakeAppx version and digest, Store identity validation, two default-validated
unpacks with exact content equality, Partner Center
certification, Store signing, and clean-host replay before the Windows alpha
gate can pass.
