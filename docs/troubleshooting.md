# Troubleshooting

SOS refusals are product behavior, not prompts to bypass the boundary. Preserve
the exact reason code and use only synthetic data when filing an issue.

## Platform refusal

`SOS_ALPHA_UAC_DISABLED_UNSUPPORTED` means Windows UAC is disabled. SOS does
not change that system policy, de-elevate itself, or install an admin helper.

`SOS_ALPHA_ELEVATION_FORBIDDEN` means the Windows launcher is running with an
elevated token. Close that terminal and use an ordinary interactive session.
Do not use **Run as administrator**.

`SOS_ALPHA_USER_STORAGE_ACCESS_DENIED` means the signed-in Windows identity
cannot safely create the per-user managed environment in canonical Local
AppData. SOS does not change ACLs or owners and does not fall back to `%TEMP%`,
Downloads, the project, or roaming storage.

On macOS, a filesystem-profile refusal means the project is not on a verified
local APFS object graph or contains an unsupported alias/cloud-placeholder
condition. SOS does not remove quarantine attributes or bypass Gatekeeper.

`SOS_LINUX_SUBSTRATE_REQUIRED` remains the typed refusal for any other
unsupported host platform.

## Filesystem refusal

`SOS_FILESYSTEM_PROFILE_UNSUPPORTED` means the project is on a filesystem SOS
cannot safely use for atomic canonical state, such as a network/share mount,
Windows-backed Linux mount, non-local APFS/NTFS object, or unsupported reparse
shape. Use a clean checkout on an admitted local filesystem; do not copy an
active dirty worktree.

## Existing-stack collision

Run `sos compatibility PATH --json`. A `block` disposition means SOS found
foreign managed bytes, an incompatible `.sigma`, an unsafe object type, or
multiple authority systems. If a primary authority is requested, select one
exact discovered ID; SOS will not merge policies.

## Integrity refusal

Do not delete receipts or hand-edit `.sigma`. Run:

```bash
sos status PATH --json
sos doctor PATH --json
sos recover PATH --json
```

Recovery is read-only or bounded to an interrupted SOS journal. Forged,
replayed, missing, or hash-invalid authority remains invalid.

## Capability refusal

Run `sos capabilities --json` without changing the project. Common reasons:

- `SOS_LANDLOCK_SYSCALL_UNAVAILABLE`;
- `SOS_LANDLOCK_ABI_TOO_OLD`;
- `SOS_NO_NEW_PRIVS_UNAVAILABLE`;
- `SOS_SECCOMP_FILTER_UNAVAILABLE`.

Control-plane commands can remain available while executable unittest is
unsupported. SOS does not fall back to unisolated execution.

## Stale or not verified

`stale` means observed application state changed after acceptance or
qualification. Follow the returned next action, normally regeneration and
ordered acceptance. `not_verified` means no current qualification receipt is
green; it is not an integrity failure.

## Update or downgrade is stale

After an exact package replacement, historical qualification remains valid
history but is not current for the new executable identity. Expected order:

```text
sos propose-update PATH
sos setup update codex PATH
# close and reopen Codex
sos qualify PATH
sos preflight PATH
```

Setup update alone must not turn qualification green. If successor
qualification fails, preserve the failure receipt, reinstall the retained
exact predecessor wheel, repeat the setup rebind, restart Codex, and qualify
again. Do not delete `.sigma`, edit receipts, or regenerate accepted state to
hide the failure. See [version update and downgrade](version-update.md).
