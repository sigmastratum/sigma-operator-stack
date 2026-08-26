# Fresh-agent recovery transcript

This transcript is the canonical text equivalent of one exact-candidate run
against a wholly synthetic repository. The local SOS lifecycle performed no
network request. One separately approved ephemeral Codex session used the
project-local read-only SOS MCP server. Raw task text, response text, tool
results, session identifiers and absolute paths were not retained.

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
5. **Recover fresh.** A genuinely new Codex session runs with `--ephemeral`,
   ignores user configuration and receives only the generated eight-tool SOS
   MCP allow-list in a read-only sandbox. The capture verifier observes
   completed calls to `sos_status`, `sos_preflight`, `sos_active_task`,
   `sos_next_action` and `sos_recover`, with no shell or mutation call.
6. **Project a content-safe result.** The fresh session identifies authority
   as `accepted_local_weak_evidence`, current work as `tasks/current.md`,
   qualification as `passed_local`, external actions as `owner_required`, and
   the safe next-action class as `review-and-qualify`. Only those categorical
   fields and raw-input digests survive in `fresh-codex-receipt.json`.
7. **Detect change.** A synthetic source comment is added. The next status is
   `stale / SOS_SOURCE_STATUS_CHANGED`; the old green receipt is not reused.
8. **Continue safely.** `sos next-action . --json` returns the bounded
   `review-and-qualify` action instead of silently continuing.

The public media is rendered from this transcript, the canonical terminal
frame and the receipt for product candidate `0f81483`. It is product evidence,
not a compatibility, release-readiness or broad adoption claim.
