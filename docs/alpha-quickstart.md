# SOS alpha quickstart

This path is for an invited alpha tester who has an existing Git project and
wants SOS to connect it to Codex without learning the SOS architecture first.

## Before you start

Use a Linux x86_64 machine with:

- Python 3.11 or 3.12;
- Git;
- [`uv`](https://docs.astral.sh/uv/getting-started/installation/);
- Codex installed for the same Linux user;
- an existing conventional Git project.

If your computer runs Windows, do not use native PowerShell Python, a Docker
bind mount or a project under WSL `/mnt/<drive>`. Use the checked Windows/WSL2
launcher described below. It imports an exactly clean committed Git repository
through a verified Git bundle into the WSL native Linux home, then runs SOS and
Codex in that same Linux workspace. It does not copy working-tree files,
install WSL, elevate privileges, accept a reboot or run qualification.
Ignored local files and machine-specific environments are not imported; recreate
them inside WSL after setup.

macOS requires a separately qualified Linux-VM launcher and is not supported
by this artifact.

The launcher checks these requirements. It never installs or reconfigures
Python, Git, `uv` or Codex for you.

## Download and unpack

Download `sigma-operator-stack-0.1.0a1-linux-x86_64-alpha.tar.gz` and compare
its SHA-256 value with the checksum supplied by your inviter. Do not continue
if the values differ.

Extract the archive with your file manager or run:

```bash
tar -xzf sigma-operator-stack-0.1.0a1-linux-x86_64-alpha.tar.gz
```

Keep every extracted file together. The resulting directory is
`sigma-operator-stack-0.1.0a1-alpha`.

## Start

### Windows with WSL2

Prerequisites are explicit: Windows PowerShell 5.1 or newer, Git for Windows,
an installed x86_64 WSL2 Ubuntu distribution, and Python 3.11/3.12, Git, `uv`
and Codex inside that distribution. Complete WSL first-run user setup yourself.
The launcher never enables Windows features, installs a distribution or asks
for administrator elevation.

Commit or otherwise safely preserve every tracked and untracked project change,
then open PowerShell in the extracted bundle and run:

```powershell
.\start-sos-windows.ps1 -Project 'C:\path\to\your-project'
```

For a distribution whose registered name is not `Ubuntu`, pass it exactly:

```powershell
.\start-sos-windows.ps1 -Project 'C:\path\to\your-project' -Distro 'Ubuntu-24.04'
```

The launcher verifies the complete bundle, WSL2 kernel and source commit. It
shows one JSON plan and asks once for `INSTALL`. The canonical project is a
native Linux workspace under `~/.local/share/sos/workspaces`; the Windows
working copy is never used as SOS state. A stable local mapping makes reruns
idempotent. Mapping drift, a dirty source, submodules, target collision or an
interrupted staging import stops with one typed next action.

After SOS succeeds, the launcher opens `codex -C <exact-linux-workspace>` in
the same WSL2 distribution. Use `-NoOpenCodex` if you only want installation.
Use `-PlanOnly` for a read-only plan without confirmation or mutation.

### Linux

Open a terminal in your Git project and run the launcher by its extracted
path:

```bash
/path/to/sigma-operator-stack-0.1.0a1-alpha/start-sos-alpha
```

Alternatively, run it from the bundle directory and provide the project:

```bash
cd sigma-operator-stack-0.1.0a1-alpha
./start-sos-alpha /path/to/your-project
```

The launcher first checks the machine, project, bundle inventory and every
SHA-256 digest. If a check fails, it stops before installing SOS and prints one
specific correction.

It then performs a read-only compatibility check for existing agent
instructions, Codex/SOS state and recognized governance systems. Most projects
continue automatically. If more than one possible authority is found, the
launcher changes nothing and prints the exact IDs. Choose one and rerun:

```bash
/path/to/sigma-operator-stack-0.1.0a1-alpha/start-sos-alpha \
  --primary-authority '<exact-discovered-id>' /path/to/your-project
```

If the checks pass, it installs the exact wheel from that bundle and shows one
complete SOS preview. Read the preview, then answer the single confirmation.
SOS preserves existing project files and refuses conflicting or changed
targets instead of overwriting them.

## Finish

After the success message:

1. restart or reopen Codex if the SOS tools are not visible;
2. trust the project when Codex asks you;
3. run this separately from the project:

```bash
sos qualify .
```

Qualification is deliberately separate because it can execute the registered
project checks. SOS shows its plan and asks before it runs them.

The alpha supports Linux x86_64, Python 3.11/3.12 and the Codex-first client
path. It does not install system prerequisites, run `curl | sh`, accept Codex
trust prompts, execute qualification automatically, send telemetry or check
for updates.
