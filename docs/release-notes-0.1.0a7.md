# Sigma Operator Stack 0.1.0a7

Community Alpha maintenance release for the Linux-primary agent-first route
and the unsigned experimental macOS control-plane route.

Give the public repository URL to a fresh Codex task and say:

> Install SOS in my current project. Show me the preview before changing it.

Windows remains pending Microsoft Store admission and a Store-signed
clean-user lifecycle. PyPI is not part of this release route.

## Exact release binding

- Product candidate: `936195c24334ae2fbfd5bfd2fbdc45229a431b7c`
- Product tree: `66098fb45f35e65cdf02ef3368aecb33e5d77fa0`
- Release index SHA-256: `b389f4b66f27487486002973d7722b17aa49ac6c1e5e13dcef33ed4e5086589d`
- Linux archive SHA-256: `be754567f71ff8beb62c813771a4dfd4429395f32146bae113aac0462b98d962`
- macOS archive SHA-256: `cd739f6dfaca422fc0547ffc3a41e1023b99b9627667ba0d7a7e90fd1d0ee736`
- Wheel SHA-256: `fa8e770a90cac79ced4c80209781d64dd4d20b26b8210d4243f23fe4fc01bee3`
- SBOM SHA-256: `ea97c5b766d66515ea9b9f8e544534c34a433cf173da48d1758cfcbd1bb38d85`

The routing successor is recorded in the GitHub Release body after its exact
commit and tree pass review. A commit cannot embed its own final identity.

## What changed

- Each newly installed project receives an isolated SOS runtime generation.
  Updating one project does not replace the shared predecessor runtime used by
  another project.
- Cross-version adapter switching uses one confirmed plan and a recoverable
  journal. Interrupted switching returns an explicit recovery state.
- Same-version maintenance reuses the verified active generation instead of
  reinstalling it.
- Removal previews the managed adapters and selected generation, removes only
  that project runtime after confirmation, and preserves `.sigma` and user
  files.
- Interactive confirmation no longer consumes the controller execution
  timeout. Individual provisioning and verification operations remain bounded.
- Runtime cache verification accepts equivalent CPython marshal reference
  graphs while detecting executable and metadata drift without executing cache
  code.
- The qualification worker keeps its private output sink outside the writable
  tree observed by its parent, eliminating a false writable-budget race.
- Managed-Python acquisition failures are typed before controller startup and
  no longer falsely claim an unresolved controller process.

## Qualification

- Source and non-editable installed-wheel suites pass on Python 3.11.14 and
  3.12.14 with zero failures, errors or skips.
- Independent wheel and native archive builds are byte-identical.
- Linux and native macOS lifecycle tests cover predecessor isolation,
  cross-version and same-version update, fresh recovery, smoke, removal preview
  and confirmed removal.
- The macOS replay preserved the second project, shared predecessor runtime,
  `.sigma`, user sentinels and Git heads. A lost test-harness PTY delivered no
  confirmation and caused no mutation; installed state was independently
  re-established before a new confirmed removal completed successfully.

## Trust boundary

- The human confirms the complete project or maintenance preview.
- SOS does not change PATH, shell profiles, system Python or package managers.
- Qualification remains separate and may honestly be `not_configured`,
  `not_verified` or stale after an executor change.
- The macOS archive is unsigned and not notarized. It may require an explicit
  **Open Anyway** decision and is not a notarization-complete claim.

See the canonical [installation route](../INSTALL.md),
[security policy](../SECURITY.md), [support boundary](../SUPPORT.md), and
[uninstall contract](version-update.md#removal).
