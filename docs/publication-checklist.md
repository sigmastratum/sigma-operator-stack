# Repository publication checklist

This file records the independent gates for source opening, artifact release,
Windows admission and promotion. It grants no remote mutation or release
authority.

The exact ordered transaction, readback and rollback boundary are defined in
the [public repository opening runbook](repository-opening-runbook.md).

## Metadata

- About: `Project state and fresh-session recovery for coding agents.`
- Homepage: canonical `INSTALL.md`
- Topics: `coding-agents`, `codex`, `mcp`, `developer-tools`,
  `ai-native-sdlc`, `local-first`, `agent-governance`, `provenance`, `python`,
  `git`

## Repository features

- Issues: enabled
- Discussions: disabled
- Wiki: disabled
- Private vulnerability reporting: enabled and confirmed

## Gate 1: source preview opening — completed

- The source-opening transaction completed before installable release routing.
- Exact source, public-history scan, community files, dependency/license
  inventory, anonymous readback and public CI passed.
- Private vulnerability reporting is enabled.
- The historical opening transaction did not authorize the later tag, release,
  pointer, package publication or promotion.

The later reviewed routing successor added `release/current.json` without
changing the frozen product candidate.

The predecessor demo may illustrate the product principle at this gate only
when it is explicitly described as neither current-HEAD nor URL-only release
evidence.

## Gate 2: Linux/macOS installable release — completed, promotion observation pending

- one exact release candidate binds the wheel, Linux/macOS archives, SBOM,
  checksums, provenance, dependency licenses and release index;
- Linux lifecycle and admitted qualification pass on the exact artifact;
- macOS lifecycle passes from the exact unsigned/not-notarized `.tar.gz` after
  the documented system `Open Anyway` approval; no Gatekeeper-clean claim is
  made, and executable qualification remains explicitly unsupported;
- AF102/AF103 and URL-only lifecycle evidence pass for the admitted archive
  routes; promotion uses Linux as the primary demonstrated path;
- tag `v0.1.0a5`, GitHub Release and the canonical pointer are public;
- PyPI remains unpublished and is not part of the current installation route;
- current-candidate launch media and the 24--48 hour observation window remain
  promotion gates.

Developer ID signing and notarization remain a required beta/stable gate, but
are an explicitly accepted Community Alpha defer. The release must never
recommend `xattr`, Gatekeeper disablement, administrator execution or another
security bypass.

## Gate 3: Windows Store admission — pending

- Microsoft certification is read back for the exact Store transport artifact;
- Store-signed clean-user install, Start Menu, CLI alias, update and removal pass;
- AF104 proves the sandbox-to-interactive-user handoff without admin, PATH
  repair, dependency preparation or security bypass;
- Windows is absent from the release index and support claim until those gates
  and an independent review pass.

## Gate 4: promotion — blocked pending this checklist

- the exact public source and artifacts pass anonymous readback and public CI;
- a 24--48 hour quiet observation window has no integrity or support blocker;
- the alpha-scope issue is created from the checked-in draft and pinned;
- D+2, D+7, D+14 and D+30 observations follow the public measurement contract;
- promotion and adoption claims require separate approval and attributable
  evidence.

## Historical source-publication boundary

The repository became public before an installable release only when:

- `release/current.json` is absent;
- README identifies the repository as source preview, not package availability;
- all installation agents fail closed on the missing release pointer;
- Windows Store certification and lifecycle evidence remain explicitly pending;
- no tag, GitHub Release, PyPI upload, Store publication, or promotion is
  implied by the visibility change.

The source-only opening transaction and the later release-routing transaction
were different commits and approvals. The current routing packet binds Linux
and macOS only; Windows remains absent until Store certification and lifecycle
evidence pass.

The gated publication workflow consumed a separately approved immutable tag
and complete draft GitHub Release. It verified both native archives against
the release index before publishing and did not construct an incomplete
release from generic wheel assets.

Release history is represented only by immutable `v*` tags and GitHub
Releases. Remote `release/*` branches are forbidden because a historical copy
of `release/current.json` can be mistaken for current installation authority.
Any temporary release-preparation branch must be deleted before pointer
activation; the publication workflow fails closed while any such remote head
exists. The only canonical mutable discovery location is
`main:release/current.json`.

GitHub Release activation and PyPI publication are separate authorities. The
manual workflow defaults `publish_pypi` to false; PyPI remains skipped unless a
later approval explicitly sets that input to true.

Windows Store artifacts remain a separate predecessor/evidence line. They do
not authorize a Windows support claim in the current Linux/macOS release.

The current `0.1.0a5` Linux/macOS package set is bound to one reviewed product
candidate. A future product candidate cannot inherit those exact-package
bindings, and Store certification of an earlier MSIX cannot authorize a
successor.

Checked-in media becomes exact-candidate evidence only when its manifest binds
the sole candidate, wheel, transcript, terminal frame and receipt-verified
fresh-agent step. A documentation or candidate change invalidates the old
media binding even when the commands remain visually identical.

Dependency and license admission is defined in
[dependency licenses](dependency-licenses.md). Launch observation ownership and
the distinction between evidence and reach metrics are defined in
[launch operations](launch-operations.md).
