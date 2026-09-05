# SOS Community alpha for Linux and macOS

This archive is an exact, checksum-bound SOS `0.1.0a2` release artifact. The
canonical route starts at the repository's `release/current.json`; do not use
an archive copied from a branch, source snapshot or third-party mirror.

Give the repository URL to a fresh Codex task and say:

> Install SOS in my current project. Show me the preview before changing it.

Codex verifies the release pointer, index, archive and inner manifest before
running the launcher. The launcher supplies pinned `uv`, installs a separate
SOS-owned Python `3.12.14` when required, and installs all Python dependencies
from the included offline wheelhouse. It does not modify system Python, PATH,
shell profiles or package managers.

One bounded network acquisition may occur for the exact managed Python
runtime. After that verified handoff, SOS itself is local, has no telemetry and
does not access a package index. Git and Codex must already be available to the
current user because SOS integrates with an existing Git project and Codex
session.

## Supported archive profiles

- Linux x86_64 on a local native filesystem. Executable qualification also
  requires the admitted Landlock ABI 3+ and seccomp profile.
- macOS 14 or newer on Apple Silicon and local APFS. Control-plane lifecycle is
  supported; executable project qualification remains unsupported in this
  alpha and must return a typed refusal.

Do not use `sudo`, remove quarantine attributes, bypass Gatekeeper, weaken TLS
verification or disable endpoint security. A platform refusal is a terminal
result, not a request to weaken the host.

## Direct invocation

The agent-first route normally performs these steps. For inspection after the
archive and every digest have already been verified:

```sh
./Install-SOS.command install /path/to/project
./Test-SOS.command /path/to/project
```

Use `update` or `remove` as the first argument for those lifecycle operations.
Installation shows one aggregate preview and the human confirms the project
mutation. Qualification remains a separate action. Removal deletes only the
SOS-managed Codex integration and SOS-owned environment; `.sigma` records and
unrelated user files are preserved.

## Included attribution

`LICENSE-CPYTHON.txt`, `LICENSE-UV-APACHE` and `LICENSE-UV-MIT` contain the
license texts for the pinned external components used by this archive. Python
dependency license files remain inside their exact wheels. The release SBOM
and manifest bind the complete component and file inventory.

Report only typed SOS reasons, versions and content-safe synthetic evidence as
described in `alpha-feedback.md`. Never publish project files, prompts,
credentials, absolute paths or raw `.sigma` content.
