# Sigma Operator Stack

Sigma Operator Stack (`sos`) is a local-first operating layer for recovering
repository authority, current work, boundaries and required checks across
coding-agent sessions.

The repository is pre-alpha and currently private while the public-safe source
boundary is qualified. The current local candidate composes one narrow,
end-to-end Linux/Git/Python vertical:

```text
sos init [PATH]
sos check [PATH]
sos qualify [PATH]
sos doctor [PATH]
sos recover [PATH]
sos mcp --root PATH
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

The first supported
qualification family performs a bounded syntax qualification of tracked
Python source without executing project code. Standard-library unit-test
execution is discovered but remains explicitly unsupported until the host has
a qualified disposable, network-denied execution profile. Unsupported
isolation never becomes a green result.

The MCP surface is read-only and exposes the same status, doctor, recovery and
check decisions as the CLI. It has no acceptance, shell, commit, push, deploy
or qualification tool.

No command performs provider, commit, push, deploy or production actions. The
default product path is local and offline; package acquisition is a separate
distribution concern.

Public contracts are packaged at
`src/sos/schemas/sos-contracts-v1.schema.json` and
`src/sos/schemas/sos-contracts-v2.schema.json`. Their frozen SHA-256 values are
checked at runtime before they can validate accepted state.

See `PUBLIC_REPOSITORY_BOUNDARY.md` before contributing.
