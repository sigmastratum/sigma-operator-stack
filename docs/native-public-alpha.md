# SOS Community alpha for Linux and macOS

This archive is an exact, checksum-bound SOS `0.1.0a4` release artifact. The
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
  supported through an **unsigned and not notarized Community Alpha** archive;
  executable project qualification remains unsupported and must return a typed
  refusal. macOS may require one explicit human approval in System Settings.

Do not use `sudo`, remove quarantine attributes, disable Gatekeeper, weaken TLS
verification or disable endpoint security. If macOS blocks the checked
`Install-SOS.command`, open **System Settings → Privacy & Security**, review the
named SOS refusal, choose **Open Anyway**, authenticate if macOS requests it,
and retry the same launcher. This is a human trust decision: Codex must report
`user_action_required` and cannot approve it. Any other platform refusal is a
terminal result, not a request to weaken the host.

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

The macOS public artifact is distributed as `.tar.gz`. Extract it with Finder
or the system `tar` utility into a new directory. Its inner
`release-manifest.json` explicitly records that signing and notarization are
absent; a manifest that hides or changes that status is invalid. Signed and
notarized distribution is deferred until Developer ID funding is available.

## Included attribution

`LICENSE-CPYTHON.txt`, `LICENSE-UV-APACHE` and `LICENSE-UV-MIT` contain the
license texts for the pinned external components used by this archive. Python
dependency license files remain inside their exact wheels. The release SBOM
and manifest bind the complete component and file inventory.

Report only typed SOS reasons, versions and content-safe synthetic evidence as
described in `alpha-feedback.md`. Never publish project files, prompts,
credentials, absolute paths or raw `.sigma` content.
