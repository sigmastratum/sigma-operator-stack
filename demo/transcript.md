# Fresh-agent recovery transcript

1. **Discover.** `sos compatibility . --json` returns
   `owner_required / SOS_PRIMARY_AUTHORITY_REQUIRED` because the synthetic
   project has both `AGENTS.md` and OpenSpec authority candidates. No write is
   performed.
2. **Install.** The operator runs `sos init --with-codex
   --primary-authority agents:AGENTS.md .`, inspects one aggregate preview, and
   confirms once. Existing project instructions and unrelated Codex settings
   are preserved.
3. **Stay honest.** `sos preflight . --json` returns `not_verified` and names
   qualification as the next action. Installation did not run tests.
4. **Qualify separately.** On an admitted native-Linux host, the operator runs
   `sos qualify . --family python.stdlib-unittest`, inspects the plan, and confirms. The receipt becomes
   `passed_local` for the exact source.
5. **Recover fresh.** A new local process runs `sos status . --json` without
   the previous process state. It recovers current accepted state from the
   repository control plane.
6. **Detect change.** A synthetic source comment is added. The next status is
   `stale / SOS_SOURCE_STATUS_CHANGED`; the old green receipt is not reused.
7. **Continue safely.** `sos next-action . --json` returns one bounded recovery
   action. A final provider-backed fresh Codex capture is intentionally pending
   separate approval and is never simulated here.
