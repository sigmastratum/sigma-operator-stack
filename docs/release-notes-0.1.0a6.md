# Sigma Operator Stack 0.1.0a6

Community Alpha maintenance release for the Linux-primary agent-first route
and the unsigned experimental macOS control-plane route.

Give the public repository URL to a fresh Codex task and say:

> Install SOS in my current project. Show me the preview before changing it.

Windows remains pending Microsoft Store admission and a Store-signed
clean-user lifecycle. PyPI is not part of this release route.

## Exact release binding

- Product candidate: `154a9dfdf3e014a0443ada8f1dca5e796477bafb`
- Product tree: `aab1a509e95e44cbf817abf0a94428c3d1f798ac`
- Release index SHA-256: `782e1fce7b3209dd627a0bb81f9028fb56edc35ce0ebd82ea3ec72cf60f3af20`
- Linux archive SHA-256: `33fb2df159e38afabb8c19560eeec5ec6780ab07e26739fbc4e375062cbe6c0c`
- macOS archive SHA-256: `2c4062e5f235d2613aca0ece40076a0901beeaaffd88693aa64efd3aea138f1e`
- Wheel SHA-256: `b728cd5012a4438cf7477251b36026d1b086ada9bae082b92a2f220688da9fa5`
- SBOM SHA-256: `9ab3364f5c01b926a8642e3eeaaeecacd56d3f78e06c22bee541d0455e7e1f65`

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

## Qualification

- Source and non-editable installed-wheel suites pass on Python 3.11.14 and
  3.12.14 with zero failures, errors or skips.
- Independent wheel and native archive builds are byte-identical.
- Linux and native macOS lifecycle tests cover predecessor isolation,
  cross-version and same-version update, fresh recovery, smoke, removal preview
  and confirmed removal.
- The macOS replay preserved the second project and shared predecessor runtime;
  a cache produced by a diagnostic command was identified, removed and followed
  by an exact baseline comparison.

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
