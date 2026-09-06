# Install SOS with Codex

This is the only public installation route for SOS Community alpha.

Give the public repository URL to a genuinely fresh Codex task and say:

> Install SOS in my current project. Show me the preview before changing it.

## Release gate

Codex must start at the root [`INSTALL.md`](../INSTALL.md) and issue a direct
request for the canonical raw pointer:

<https://raw.githubusercontent.com/sigmastratum/sigma-operator-stack/main/release/current.json>

Only a direct HTTP `404` or `410` proves that no public pointer is available.
A search result, cached GitHub page, missing directory-listing link, timeout,
rate limit, permission refusal or other transport failure does not. Those
failures return `SOS_PUBLIC_RELEASE_DISCOVERY_BLOCKED`. A malformed or
schema-invalid response returns `SOS_PUBLIC_RELEASE_METADATA_INVALID`.

Do not substitute a branch archive, source checkout, private bundle, issue
command, PyPI search result, or GitHub “latest source” archive.

## Deterministic agent procedure

When a public pointer exists, Codex must:

1. validate the directly fetched bytes against
   `sos-public-release-pointer-v1.schema.json`;
2. download its exact release index from the declared immutable release tag;
3. verify the index SHA-256 before parsing it;
4. validate it against `sos-public-release-index-v1.schema.json`;
5. require exact agreement on version, candidate and tree;
6. observe the host system and architecture without changing host settings;
7. select exactly one `admitted` platform entry or stop with its typed reason;
8. follow exactly one declared delivery contract:
   - `archive`: download the declared archive and verify its size and SHA-256;
   - `microsoft_store`: require the exact Store product, package identity,
     publisher, package family and transport version from the index;
9. for an archive, extract into a new disposable directory without following
   links and verify the inner manifest plus every artifact digest;
10. for Microsoft Store, open the declared Store deep link and wait for the
    ordinary signed-in user to complete the Store installation;
11. observe the installed Store identity/version and launcher availability;
12. invoke only the exact launcher and argument grammar named by the index;
13. show the SOS aggregate preview and wait for the human to confirm or refuse;
14. retain the exact managed executable path returned by the launcher;
15. render setup, workspace, check-plan and qualification state truthfully;
16. recommend qualification only when a configured executable family exists;
17. ask the user to open a genuinely fresh Codex task for recovery proof.

The initial explicit request to install SOS authorizes download, verification,
archive extraction and preparation of the SOS-owned per-user environment. It
does **not** authorize project mutation. Codex must not insert an agent-level
approval before invoking the verified launcher. It invokes the launcher until
the launcher emits its digest-bound aggregate project preview and pauses at
its confirmation prompt, presents that exact preview to the user, and answers
the existing launcher prompt only after the user's single confirmation. A
second paraphrased preview, approval to start the launcher, or confirmation
layer is a failed onboarding replay.

Codex may request ordinary network or command-execution permission. It must
not answer the SOS mutation prompt, select project authority, change PATH or a
shell profile, install undeclared host dependencies, weaken TLS/platform
security, run qualification automatically, commit, push or deploy.

### Installation maintenance is not project qualification

After recovery, `owner_required` current work, `not_configured` checks or
`not_verified` qualification do not by themselves prohibit an explicit
owner-requested status check, same-version update, public smoke test or removal
preview. Those operations are installation maintenance, not a claim that the
project is qualified. Codex must use the exact platform launcher selected by
the verified release index, not an SOS MCP mutation tool. The owner's explicit
maintenance request authorizes only that launcher and the bound public smoke
launcher even when the MCP surface is read-only; it grants no arbitrary shell
authority. Codex must stop for any launcher confirmation.

Invalid control-plane integrity, required recovery, managed-file drift or an
unverified launcher still blocks maintenance. This exception never permits
application edits, qualification claims, commit, push, deploy or external
actions.

The repository-owned route projection uses five states: `ready`,
`user_action_required`, `unsupported`, `blocked` and `invalid`. Only `ready`
permits automatic continuation. `user_action_required` is a typed stop, not a
green result.

On Windows, a Store install and SOS project mutation are two different user
decisions. If a sandbox can verify the Store package but cannot invoke the
per-user launcher, return `SOS_INTERACTIVE_USER_HANDOFF_REQUIRED`. Do not use
Administrator, change ACLs, repair PATH or weaken the sandbox. Continue only
through the ordinary interactive user session. The exact public-alpha handoff
mechanism remains a release gate until the clean Store-signed AF104 drill
passes.

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
[support](../SUPPORT.md) for content-safe reporting. The exact release proof is
defined by the [AF104 public URL-only drill](agent-first-public-drill.md).
