# Windows distribution boundary

SOS Windows public alpha uses a signed per-user MSIX. The unsigned ZIP and PE
remain diagnostic artifacts and are not public distribution surfaces.

## Signing lineage

The protected signing workflow accepts only an independently approved exact
candidate and unsigned PE digest. It rebuilds the PE twice, compares both
unsigned bytes, authenticates to Azure Artifact Signing with GitHub OIDC, and
performs one controlled signing transformation:

`candidate/tree -> unsigned SHA-256 -> signed SHA-256 -> signing account and certificate profile -> RFC3161 timestamp`

No PFX, certificate password, long-lived signing token, Defender exception,
SmartScreen bypass, TLS weakening, or Administrator execution is allowed. The
signed result is accepted only when Windows reports a valid Authenticode chain,
the publisher exactly matches the approved Artifact Signing identity, and a
valid timestamp certificate is present.

Creating the Azure Artifact Signing account, identity validation, certificate
profile, OIDC federation, protected GitHub environment, or Microsoft Security
Intelligence submission is an external operation requiring separate approval.
Checking this workflow into the repository performs none of those operations.

## Host and project authority

Installing a signed MSIX grants Windows package installation authority only.
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
are immutable and Windows integrity enforcement is enabled. After the MSIX has
been downloaded, SOS performs no executable acquisition or update check.

`sos install PATH` maps to the existing one-preview `init --with-codex` flow.
An MSIX version update changes only the immutable host payload; the project is
stale until `sos update PATH` previews and rebinds its managed integration.
`sos remove PATH` removes only the exact SOS-managed Codex integration and
preserves `.sigma` and user files. Windows package removal happens afterward.
Removing the package directly in Settings cannot delete repository state and
can leave the project integration disconnected until a separately installed
SOS version performs the previewed cleanup.

The checked-in MSIX builder is preparation, not a distributable package. It
requires an exact externally assembled payload, an exact MakeAppx digest, the
approved Artifact Signing publisher subject, two byte-identical package builds,
signing, and clean-host replay before the Windows alpha gate can pass.
