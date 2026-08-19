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

## Application fingerprint currentness

The source observation binds `sos_application_dirty_fingerprint_v2`. Its byte
stream uses the P101-v2 `sos_dirty_v1\0` domain header, repository identity,
acceptance-time application HEAD, exclusion-policy digest and sorted entries.
Index entries bind Git mode, object ID and stage. Worktree and untracked regular
files bind complete SHA-256 bytes; symlinks bind only raw link-target bytes;
deletions and submodule state have their own closed encodings.

Observation is bounded to 10,000 entries, 16 MiB per file, 256 MiB total and
256 submodules. Paths are UTF-8 repository-relative values of at most 4,096
bytes. Reads use beneath-root no-follow traversal and before/after identity
checks. Candidate enumeration is repeated after hashing. A limit, unsupported
type or race yields `complete=false`, `fingerprint=null` and cannot bootstrap a
usable source binding.

The exact `.sigma` control root and one valid
`.sigma.init.<64-lowercase-hex>` staging root are excluded. Lookalikes are not.
This keeps control-plane commits separate from application currentness.

Default protected-presence classes cover environment/secret files, private
keys, credential stores, raw chat/transcript exports, production/database
dumps and authenticated remote configuration. Their content, link target and
content-derived metadata are not opened or hashed. Presence, repository path,
filesystem type and stable class ID remain fingerprint-bound. Consequently a
protected file's byte-only change is deliberately unobserved, while its
creation, deletion, rename, type or classification change alters currentness.
Matching is case-sensitive with no Unicode normalization. The built-in v2
set is exact and public: `.env`, `.env.*`, `*.secret`, `*.secrets`; the
`id_rsa`, `id_dsa`, `id_ecdsa`, `id_ed25519` basenames and `.pem`, `.key`,
`.p12`, `.pfx` suffixes; `credentials`, `credentials.json`, `.netrc`,
`.git-credentials` and paths below exact `.aws` or `.ssh` components; basenames
containing `conversation`, `transcript`, `chat_export` or `messages_export`;
`.db`, `.sqlite`, `.sqlite3`, `.dump`, `.sql` suffixes or basenames containing
`production_dump`/`prod_dump`; and exact `.npmrc`, `.pypirc`, `settings.xml`,
`pip.conf` or `.config/gcloud/**` paths. User-declared protected patterns and
explicit byte consent remain separate future policy operations; bootstrap does
not infer them.

The local CLI acceptance evidence is deliberately weak: it records intended
local operator use but claims neither strong authentication nor prevention of
agent invocation. SOS exposes no acceptance operation through MCP.
