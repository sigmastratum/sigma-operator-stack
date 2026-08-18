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
`.sigma/` control plane after one confirmation. The first supported
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

See `PUBLIC_REPOSITORY_BOUNDARY.md` before contributing.
