# SOS native private alpha 0.1.0a2

This checked bundle is for an invited native-platform test. It is not a signed
public installer.

## What the installer manages

- Linux x86_64 on a local native filesystem, Windows 11 x86_64 on a fixed local
  NTFS volume, or macOS 14+ Apple Silicon on a local APFS volume;
- Git and Codex already installed for the current user;
- an existing conventional Git project on the admitted local filesystem.

The checked bundle includes exact uv `0.12.6`. During one explicit acquisition
phase it installs SOS-owned managed Python `3.12.14` when absent. System Python,
Homebrew, WSL and Docker are not prerequisites and are not modified. After the
managed Python handoff, the SOS wheel and all Python dependencies are installed
only from the bundle's digest-bound wheelhouse with uv offline mode, index
access and automatic Python downloads disabled.

The acquisition phase can use the network only for uv's exact managed-Python
distribution. SOS execution, project inspection, install/update handoff,
qualification and removal perform no network, telemetry or update check.

SOS does not request administrator, UAC or `sudo` access. Do not bypass
PowerShell policy, Gatekeeper, TLS verification or endpoint security to run it.

## Windows

Open Command Prompt or Windows Terminal in the extracted bundle and run the
native user-scope executable. It does not invoke a `.ps1` file and does not
require an Execution Policy change, `Bypass`, Administrator access or UAC
elevation. Windows UAC must remain enabled:

```bat
"%USERPROFILE%\Downloads\SOS-Windows-0.1.0a2\SOS-Installer.exe" install "C:\Users\Example\source\example-project"
"%USERPROFILE%\Downloads\SOS-Windows-0.1.0a2\SOS-Installer.exe" test "C:\Users\Example\source\example-project"
"%USERPROFILE%\Downloads\SOS-Windows-0.1.0a2\SOS-Installer.exe" update "C:\Users\Example\source\example-project"
"%USERPROFILE%\Downloads\SOS-Windows-0.1.0a2\SOS-Installer.exe" remove "C:\Users\Example\source\example-project"
```

Replace the quoted example project path with the real path. Do not type angle
brackets such as `<PROJECT>`, and do not copy the `C:\...>` command prompt or
program output back into Command Prompt. Run one command at a time from an
ordinary, non-Administrator session with Windows UAC enabled.

`Install-SOS.ps1` remains a developer/debug surface and is not the supported
private-alpha entrypoint. Do not alter Execution Policy to run it. The current
private build is unsigned and is suitable only for an invited tester who
verifies the published SHA-256; Authenticode signing is required before public
distribution.

Update with the `update` command. Remove the managed Codex integration and
package with the `remove` command; repository-owned `.sigma` records are
preserved.

## macOS

Open Terminal in the extracted bundle and run:

```sh
./Install-SOS.command install /path/to/project
./Test-SOS.command /path/to/project
```

Use `update` or `remove` as the first argument for those lifecycle operations.
Do not remove quarantine attributes or bypass Gatekeeper. If macOS refuses the
unsigned private-alpha script, stop and report the exact refusal.

## Linux

Open a terminal in the extracted bundle and run:

```sh
./Install-SOS.command install /path/to/project
./Test-SOS.command /path/to/project
```

Use `update` or `remove` as the first argument. The same SOS-owned runtime,
offline wheelhouse and repository-preservation rules apply.

Update reuses the same pinned bootstrap and offline wheelhouse. Remove first
removes the managed Codex integration and SOS package, then removes only the
SOS-owned managed runtime. Repository-owned `.sigma` records and user files are
preserved.

## Expected boundary

Control-plane initialization, status, recovery, update and removal are under
test. Executable project qualification is intentionally unsupported on Windows
and macOS in this build; SOS must return a typed refusal and must not run project
tests without a separately qualified isolation profile.

Send only the provided content-safe smoke JSON plus OS/Python/Git/uv/Codex
versions and exit codes. Do not send project files, prompts, credentials,
absolute paths, usernames or raw `.sigma` content.
