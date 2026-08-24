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
bind mount or a project under WSL `/mnt/<drive>`. The current safe manual path
is to keep the project under the WSL native Linux home filesystem and run both
SOS and Codex from that same WSL environment. The one-step Windows/WSL2 host
launcher is not part of this artifact yet. macOS requires a separately
qualified Linux-VM launcher and is also not supported by this artifact.

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
