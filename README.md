# Sigma Operator Stack

Sigma Operator Stack (`sos`) is a local-first operating layer for recovering
repository authority, current work, boundaries and required checks across
coding-agent sessions.

The repository is pre-alpha and currently private while the public-safe source
boundary is qualified. The current local candidate composes one narrow,
end-to-end Linux/Git/Python vertical:

```text
sos init [PATH]
sos regenerate [PATH]
sos accept REVISION [PATH]
sos check [PATH]
sos qualify [PATH] [--family FAMILY]
sos doctor [PATH]
sos recover [PATH]
sos mcp --root PATH
sos client install codex [PATH]
sos client status codex [PATH]
sos client remove codex [PATH]
```

`sos init` preserves existing project files and atomically creates a local
`.sigma/` control plane after one confirmation. Bootstrap writes exact
P101-v2 record envelopes plus an ordered three-receipt acceptance lineage for
authority, policy and operator state. The shipped Draft 2020-12 schema pair is
validated before bootstrap and replayed by `status`, `validate`, `recover`,
`doctor` and their MCP equivalents. Record, receipt, source-observation,
exclusion-policy, check-plan and qualification-pointer integrity failures are
`invalid`; they take precedence over source staleness.

Acceptance requires an observed controlling terminal. `--yes` removes the
extra prompt but does not bypass that boundary; a non-interactive invocation
returns `SOS_ACCEPTANCE_TTY_REQUIRED` and writes nothing. This is intentionally
weak local evidence, not authentication, and SOS does not claim that an agent
cannot invoke the CLI.

When application source changes, `sos regenerate` creates one immutable,
content-safe successor plan without changing accepted state. The plan contains
exact authority, policy and operator-state proposal revisions in dependency
order. `sos accept REVISION` accepts exactly one displayed revision: authority
first, then policy, then operator state. An out-of-order or source-stale
proposal is refused. The workspace remains stale between transitions and
becomes current only after the complete three-record sequence is replayable.
Accepted revisions, receipts, transitions and monotonic tips are append-only;
an interrupted write cannot advance the authoritative tip, and a gap or hash
failure makes every authoritative read fail closed.

External agent/documentation files are not part of that acceptance lineage.
They use a separate [managed-file journal](docs/managed-file-journal.md) with
immutable digest-only plans and ordinal events. Only exact `create_file` and
`append_suffix` operations are supported; drift blocks recovery rather than
overwriting user content.

Bootstrap accepts clean or dirty Git application state only after producing a
complete P101-v2 application fingerprint. Staged index entries, unstaged and
untracked bytes, deletions, symlink targets and bounded submodule state use the
normative canonical encoding. Protected local paths contribute presence, type
and a stable class identifier without opening or hashing their content. Every
authoritative read re-observes the application fingerprint, so an untracked
file content change can make recovery stale even when Git's textual status is
unchanged. A commit containing only the excluded `.sigma` control plane does
not make the application source stale. Limits, unsupported filesystem types or
a snapshot race produce `not_verified` and no usable fingerprint.

The default qualification family performs a bounded syntax qualification of
tracked Python source without executing project code. On Linux x86_64,
`python.stdlib-unittest` can be selected explicitly:

```text
sos check PATH
sos qualify PATH --family python.stdlib-unittest
```

The selected family uses the narrow
`linux-landlock-seccomp-snapshot-v1` profile: SOS copies only eligible tracked
files into a disposable read-only source projection, runs one fixed standard
library unittest command with `shell=false`, and gives it a separate bounded
writable root. Landlock denies access outside the declared system/source/output
roots; seccomp denies network, child-process, namespace and mount syscalls; the
environment contains no inherited credentials. Raw test output is never
serialized. A missing Landlock capability, protected tracked path, unsupported
file type, failed/skipped/empty suite, timeout or resource-limit result never
becomes green. See [Qualification isolation](docs/qualification-isolation.md)
for the exact boundary and residuals.

Before execution, `sos qualify` freezes a closed source-bound plan containing
the exact registered family, fixed argv digest, isolation profile and limits.
One explicit confirmation creates an expiring, one-use admission with a fresh
nonce. The nonce is claimed before project code runs. Execution produces a
closed result and an append-only, source-bound receipt whose monotonic tip is
replayed by every authoritative read. Foreign, stale, modified, rolled-back or
replayed artifacts cannot become local green. These records are
non-authoritative: they do not modify accepted P101 records or grant commit,
push, deploy, release or production authority.

The MCP surface is read-only and exposes the same status, doctor, recovery and
check decisions as the CLI. It has no acceptance, regeneration, shell, commit,
push, deploy or qualification tool. `sos client install codex` previews and,
after an observed terminal confirmation, appends one project-scoped server to
`.codex/config.toml`. The launcher is bound to the exact installed package,
Python executable, project root and four-tool allow-list. Removal restores the
original config bytes only when the managed digest is unchanged and never
removes `.sigma/`. See [Codex MCP integration](docs/codex-mcp-integration.md).

No command performs provider, commit, push, deploy or production actions. The
default product path is local and offline; package acquisition is a separate
distribution concern.

Public P101 contracts are packaged at
`src/sos/schemas/sos-contracts-v1.schema.json` and
`src/sos/schemas/sos-contracts-v2.schema.json`. Four additional closed P104
schemas cover the qualification plan, one-run command admission, execution
result and source-bound receipt. Every packaged schema has a frozen SHA-256
value checked at runtime before validation.

See `PUBLIC_REPOSITORY_BOUNDARY.md` before contributing.
