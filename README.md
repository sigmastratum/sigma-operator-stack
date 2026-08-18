# Sigma Operator Stack

Sigma Operator Stack (`sos`) is a local-first operating layer for recovering
repository authority, current work, boundaries and required checks across
coding-agent sessions.

The repository is pre-alpha and currently private while the public-safe source
boundary is qualified. The current P102 surface is intentionally read-only:

```text
sos status [PATH] --json
sos validate [PATH] --json
```

No command performs network, provider, commit, push, deploy or production
actions. Bootstrap mutation is not exposed through the CLI in P102.

See `PUBLIC_REPOSITORY_BOUNDARY.md` before contributing.

