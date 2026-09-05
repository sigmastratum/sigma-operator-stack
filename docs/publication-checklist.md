# Repository publication checklist

This file records the independent gates for source opening, artifact release,
Windows admission and promotion. It grants no remote mutation or release
authority.

The exact ordered transaction, readback and rollback boundary are defined in
the [public repository opening runbook](repository-opening-runbook.md).

## Metadata

- About: `Project state and fresh-session recovery for coding agents.`
- Homepage: repository README
- Topics: `coding-agents`, `codex`, `mcp`, `developer-tools`,
  `ai-native-sdlc`, `local-first`, `agent-governance`, `provenance`, `python`,
  `git`

## Repository features

- Issues: enabled
- Discussions: disabled
- Wiki: disabled
- Private vulnerability reporting: enable and confirm immediately after public
  visibility; GitHub does not expose it for private repositories

## Gate 1: source preview opening

- exact reviewed candidate, clean linear source lineage and full-history scan;
- README states that no installable public release or release pointer exists;
- `release/current.json`, public tag, GitHub Release and package publication
  remain absent;
- public metadata, community files, dependency/license inventory and links pass;
- visibility change, private-vulnerability-reporting activation and readback
  form one rollback-bound transaction; activation failure returns the
  repository to private;
- push, remote settings and visibility each retain a separate approval.

This gate precedes an installable release. A later reviewed routing successor
may add `release/current.json` without changing the frozen product candidate.

The predecessor demo may illustrate the product principle at this gate only
when it is explicitly described as neither current-HEAD nor URL-only release
evidence.

## Gate 2: Linux/macOS installable release

- one exact release candidate binds the wheel, Linux/macOS archives, SBOM,
  checksums, provenance, dependency licenses and release index;
- Linux lifecycle and admitted qualification pass on the exact artifact;
- macOS lifecycle passes from the exact unsigned/not-notarized `.tar.gz` after
  the documented system `Open Anyway` approval; no Gatekeeper-clean claim is
  made, and executable qualification remains explicitly unsupported;
- AF102/AF103 and fresh URL-only Codex drills pass for each claimed platform;
- launch media is regenerated from that exact candidate;
- tag, GitHub Release, PyPI and release-pointer activation remain separately
  approved operations.

Developer ID signing and notarization remain a required beta/stable gate, but
are an explicitly accepted Community Alpha defer. The release must never
recommend `xattr`, Gatekeeper disablement, administrator execution or another
security bypass.

## Gate 3: Windows Store admission

- Microsoft certification is read back for the exact Store transport artifact;
- Store-signed clean-user install, Start Menu, CLI alias, update and removal pass;
- AF104 proves the sandbox-to-interactive-user handoff without admin, PATH
  repair, dependency preparation or security bypass;
- Windows is absent from the release index and support claim until those gates
  and an independent review pass.

## Gate 4: promotion

- the exact public source and artifacts pass anonymous readback and public CI;
- a 24--48 hour quiet observation window has no integrity or support blocker;
- the alpha-scope issue is created from the checked-in draft and pinned;
- D+2, D+7, D+14 and D+30 observations follow the public measurement contract;
- promotion and adoption claims require separate approval and attributable
  evidence.

## Source-publication boundary

The repository may become public before an installable release only when:

- `release/current.json` is absent;
- README identifies the repository as source preview, not package availability;
- all installation agents fail closed on the missing release pointer;
- Windows Store certification and lifecycle evidence remain explicitly pending;
- no tag, GitHub Release, PyPI upload, Store publication, or promotion is
  implied by the visibility change.

The source-only opening transaction and the later release-routing transaction
are different commits and approvals. The current routing packet binds Linux
and macOS only; Windows remains absent until Store certification and lifecycle
evidence pass.

Before the gated publication workflow runs, a separately approved operator
creates the immutable tag and a draft GitHub Release containing the complete
reviewed asset set. The workflow refuses an absent or non-draft release and
checks both native archives against the release index before publication. It
does not construct an incomplete release from generic wheel assets.

The submitted Store MSIX was the correct reviewed artifact when uploaded. It
is now classified as predecessor evidence because the later source successor
adds schemas that are included in the release wheel. This is candidate drift,
not an erroneous upload, and it is not a reason to cancel the in-flight
certification.

This source-publication successor does not inherit exact-package evidence from
an earlier candidate. Before package release, every Linux, macOS, Windows,
wheel, SBOM, release-index, demo, and Store artifact must be rebuilt or
explicitly rebound to the one final reviewed candidate. Store certification of
an earlier MSIX cannot authorize the successor.

Checked-in media becomes exact-candidate evidence only when its manifest binds
the sole candidate, wheel, transcript, terminal frame and receipt-verified
fresh-agent step. A documentation or candidate change invalidates the old
media binding even when the commands remain visually identical.

Dependency and license admission is defined in
[dependency licenses](dependency-licenses.md). Launch observation ownership and
the distinction between evidence and reach metrics are defined in
[launch operations](launch-operations.md).
