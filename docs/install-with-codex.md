# Install SOS with Codex

This is the only public installation route for SOS Community alpha.

Give the public repository URL to a genuinely fresh Codex task and say:

> Install SOS in my current project. Show me the preview before changing it.

## Release gate

Codex must first read `release/current.json` from this repository. If that file
is absent, malformed, marked non-public, or fails its schema, **stop**. No
public SOS release is available. Do not substitute a branch archive, source
checkout, private bundle, issue command, PyPI search result, or GitHub “latest
source” archive.

## Deterministic agent procedure

When a public pointer exists, Codex must:

1. validate it against `sos-public-release-pointer-v1.schema.json`;
2. download its exact release index from the declared immutable release tag;
3. verify the index SHA-256 before parsing it;
4. validate it against `sos-public-release-index-v1.schema.json`;
5. require exact agreement on version, candidate and tree;
6. observe the host system and architecture without changing host settings;
7. select exactly one `admitted` platform entry or stop with its typed reason;
8. download the declared archive and verify its size and SHA-256;
9. extract into a new disposable directory without following links;
10. verify the declared inner manifest and every manifest artifact digest;
11. invoke only the exact launcher and argument grammar named by the index;
12. show the SOS aggregate preview and wait for the human to confirm or refuse;
13. retain the exact managed executable path returned by the launcher;
14. render setup, workspace, check-plan and qualification state truthfully;
15. recommend qualification only when a configured executable family exists;
16. ask the user to open a genuinely fresh Codex task for recovery proof.

Codex may request ordinary network or command-execution permission. It must
not answer the SOS mutation prompt, select project authority, change PATH or a
shell profile, install undeclared host dependencies, weaken TLS/platform
security, run qualification automatically, commit, push or deploy.

## Expected terminal states

- `success`: setup completed; this does not mean the project is qualified.
- `not_configured`: no executable check family applies; do not run qualify.
- `not_verified`: a configured family has not been run; propose qualification
  as a separate human-reviewed action.
- `owner_required`: show only discovered authority candidate IDs and wait for
  the human choice.
- `unsupported`, `blocked`, `stale` or `invalid`: stop and report the exact
  typed reason and one safe next action.

## Removal

Use only the exact platform removal grammar from the same release index.
Removal may remove SOS-owned executable integration and managed runtime. It
must preserve repository-owned `.sigma` records and unrelated user files.

See [troubleshooting](troubleshooting.md) for typed refusals and
[support](../SUPPORT.md) for content-safe reporting.
