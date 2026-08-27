# SOS native private alpha 0.1.0a2

This checked bundle is for an invited native-platform test. It is not a signed
public installer.

## Requirements

- Windows 11 x86_64 on a fixed local NTFS volume, or macOS 14+ Apple Silicon on
  a local APFS volume;
- Python 3.11 or 3.12, Git, `uv`, and Codex already installed for the current
  user;
- an existing conventional Git project on the admitted local filesystem.

SOS does not request administrator, UAC or `sudo` access. Do not bypass
PowerShell policy, Gatekeeper, TLS verification or endpoint security to run it.

## Windows

Open PowerShell in the extracted bundle and run:

```powershell
.\Install-SOS.ps1 -Mode install -Project C:\path\to\project
.\Test-SOS.ps1 -Project C:\path\to\project
```

Update with `-Mode update`. Remove the managed Codex integration and package
with `-Mode remove`; repository-owned `.sigma` records are preserved.

## macOS

Open Terminal in the extracted bundle and run:

```sh
./Install-SOS.command install /path/to/project
./Test-SOS.command /path/to/project
```

Use `update` or `remove` as the first argument for those lifecycle operations.
Do not remove quarantine attributes or bypass Gatekeeper. If macOS refuses the
unsigned private-alpha script, stop and report the exact refusal.

## Expected boundary

Control-plane initialization, status, recovery, update and removal are under
test. Executable project qualification is intentionally unsupported on Windows
and macOS in this build; SOS must return a typed refusal and must not run project
tests without a separately qualified isolation profile.

Send only the provided content-safe smoke JSON plus OS/Python/Git/uv/Codex
versions and exit codes. Do not send project files, prompts, credentials,
absolute paths, usernames or raw `.sigma` content.
