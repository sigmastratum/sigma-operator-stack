# P101-v2 Contracts And Integrity

SOS ships the exact public Draft 2020-12 P101 schema pair. The v2 schema keeps
its normative reference to the v1 definitions; neither file is flattened or
silently substituted.

| Resource | SHA-256 |
| --- | --- |
| `sos-contracts-v1.schema.json` | `19164d394c55ed29e30ddef638dc79241e19692b552e3a91ef81233c6bd59208` |
| `sos-contracts-v2.schema.json` | `79155ac28d419d3750fb02c1c23a5c018dc51a914ca708092a4e6065727e5d1f` |

Bootstrap creates three immutable proposal records and three acceptance
receipts in this exact order:

1. `authority_bootstrap`;
2. `policy_bootstrap_plan` bound to the accepted authority;
3. `operator_state_bootstrap_plan` bound to the accepted authority and policy.

All receipts bind one repository, bootstrap intent, bootstrap plan, source
observation and exclusion policy. Each accepted revision equals its proposal
revision. Record hashes remove only `revision_id` and
`integrity.record_sha256`; receipt hashes remove only `receipt_id` and
`integrity.receipt_sha256` before canonical JSON SHA-256 calculation.

Every authoritative read replays the schema bundle, record hashes, record
lineage, receipt hashes and predecessor chain, check-plan digest, manifest
bindings and any qualification view-to-immutable-receipt pointer. A failed
replay returns `SOS_CONTROL_PLANE_INTEGRITY_INVALID` before stale or readiness
decisions. Generated Markdown and recovery views are not independent
authority.

The local CLI acceptance evidence is deliberately weak: it records intended
local operator use but claims neither strong authentication nor prevention of
agent invocation. SOS exposes no acceptance operation through MCP.
