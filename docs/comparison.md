# What SOS complements

SOS is a local continuity and qualification control plane. It is designed to
coexist with the tools a repository already uses, not to replace them.

| Existing tool category | What it usually provides | What SOS adds | What SOS does not claim |
| --- | --- | --- | --- |
| Agent instruction files | Durable instructions for a coding agent | Discovery, managed-block ownership, drift detection and a safe recovery projection | Automatic authority over foreign instructions |
| Specification workflows | Intent, requirements, plans and change artifacts | Exact accepted-state binding, current/stale evaluation and one next action | A preferred specification methodology |
| Memory and retrieval tools | Search or recalled project context | Authority-aware recovery that distinguishes retrieved context from accepted current state | General semantic memory or hosted retrieval |
| Issue trackers | Work ownership, status and collaboration | Local binding from current work to exact repository and qualification state | Replacement for team planning or reporting |
| Test runners and CI | Execution of project checks | Registered fixed plans, isolated local execution and digest-bound receipts | A new test framework or a substitute for CI |
| Package managers | Install or replace a tool version | Per-project detection that prior qualification belongs to another exact SOS package, plus an explicit rebind/restart/requalify path | Automatic update discovery, package acquisition, schema migration or fleet rollout |

The practical boundary is simple: existing systems remain their own sources
of truth. SOS records which source was selected, whether the repository still
matches the accepted observation, which checks are current, and what action is
allowed next. If those answers are ambiguous, SOS stops instead of silently
merging policy.
