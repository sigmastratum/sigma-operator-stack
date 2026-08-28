# Windows distribution boundary

SOS Windows public alpha uses a per-user MSIX distributed by Microsoft Store.
The Store product is **Sigma Operator Stack**, Store ID `9NNZT70C613H`. Its
canonical package identity is checked into
`installers/windows-msix/store-identity.json` and must match the exact MSIX
manifest. The unsigned ZIP and PE remain private diagnostic artifacts and are
not public distribution surfaces.

## Store signing lineage

The release process builds an exact unsigned MSIX from a clean reviewed Git
candidate and immutable payload. Two independent builds must be byte-identical.
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

Azure Artifact Signing is not required for the Store-first public-alpha route.
It remains a possible future paid signing channel for direct downloads outside
Microsoft Store. Self-signed packages are limited to private development and
must not be presented as a frictionless public distribution path.

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
requires an exact externally assembled payload, an exact MakeAppx digest, Store
identity validation, two byte-identical package builds, Partner Center
certification, Store signing, and clean-host replay before the Windows alpha
gate can pass.
