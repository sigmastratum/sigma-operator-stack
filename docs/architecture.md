# Architecture overview

SOS is a local control plane embedded in a Git repository. It separates five
concerns that coding-agent workflows often collapse:

1. **Observation** — discover repository state and existing authority systems
   without opening protected content.
2. **Acceptance** — bind authority, policy, operator state, and source
   observation through append-only records and receipts.
3. **Projection** — expose one deterministic status and safe next action to the
   CLI and the exact eight-tool MCP surface.
4. **Qualification** — plan and run only registered checks through a named,
   bounded isolation profile, producing non-authoritative receipts.
5. **Execution identity** — bind qualification currentness to the exact
   installed SOS package version and executable/schema resource digest.

```text
Git repository
    |
    v
compatibility + source observer
    |
    v
.sigma records and append-only tips
    |                 \
    v                  v
CLI decision core    qualification planner/worker
    |
    v
Codex MCP: eight read/proposal tools
```

Managed integration files use a journal separate from accepted project-state
records. This lets SOS append a bounded block to an existing `AGENTS.md` and a
project MCP entry to `.codex/config.toml` without treating either file as the
project's sole authority. Preview digests, a sibling staging root, reverse
rollback, and post-application fingerprint verification prevent partial state
from becoming current.

Qualification receipts never grant permission to commit, push, deploy, or
mutate production. Green means only that one exact registered check passed for
one exact observed source and artifact.

Package replacement does not rewrite historical receipts. Their recorded
executor remains valid history, while current projection compares that
executor with the package now running. A mismatch is `valid_stale`. Updating
managed Codex files cannot change it to green: the user must restart/reopen the
agent and run qualification separately for each project. SOS keeps no global
project inventory and performs no automatic package acquisition or migration.
