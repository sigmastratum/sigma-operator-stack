# Repository publication checklist

This file records public repository metadata and reversible settings for a
future publication operation. It grants no remote mutation or release
authority.

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
- Private vulnerability reporting: required before public visibility

## Publication gates

- exact current candidate and clean source lineage;
- green public CI for the published commit;
- reproducible wheel, SBOM, provenance, and public-content scan;
- current support matrix and regenerated demo media;
- update/downgrade documentation and qualification claims bound to the exact
  release candidate;
- no known release-blocking existing-stack or platform ambiguity;
- separate approval for remote metadata, visibility, tag, release, and package
  publication.

## Source-publication boundary

The repository may become public before an installable release only when:

- `release/current.json` is absent;
- README identifies the repository as source preview, not package availability;
- all installation agents fail closed on the missing release pointer;
- Windows Store certification and lifecycle evidence remain explicitly pending;
- no tag, GitHub Release, PyPI upload, Store publication, or promotion is
  implied by the visibility change.

Current preparation state: source-publication candidate in progress. Microsoft
Store certification is external and pending; Windows Store lifecycle evidence
does not yet exist.

This source-publication successor does not inherit exact-package evidence from
an earlier candidate. Before package release, every Linux, macOS, Windows,
wheel, SBOM, release-index, demo, and Store artifact must be rebuilt or
explicitly rebound to the one final reviewed candidate. Store certification of
an earlier MSIX cannot authorize the successor.

Checked-in media becomes exact-candidate evidence only when its manifest binds
the sole candidate, wheel, transcript, terminal frame and receipt-verified
fresh-agent step. A documentation or candidate change invalidates the old
media binding even when the commands remain visually identical.
