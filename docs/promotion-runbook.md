# Community Alpha promotion runbook

This runbook begins only after the documentation/media successor passes
independent review. It grants no push, provider, issue, settings, release-body
or promotion authority by itself.

## 1. Publish the reviewed documentation successor

- Require the exact reviewed commit and tree and a clean local worktree.
- Push that commit to `main` without rewriting history.
- Require successful `source (3.11)`, `source (3.12)` and `release-artifacts`
  checks on the exact public SHA.
- Read back `README.md`, `INSTALL.md`, `LICENSE`, `release/current.json` and the
  current demo anonymously.

The immutable `v0.1.0a5` tag and package assets are not moved or replaced.

## 2. Complete the GitHub surface

- Set Homepage to
  `https://github.com/sigmastratum/sigma-operator-stack/blob/main/INSTALL.md`.
- Keep Issues enabled and Discussions and Wiki disabled.
- Create the scope issue from `alpha-scope-issue.md`, assign it to
  `@sigmastratum`, and pin it.
- Create the five issues from `good-first-issues/` with the GitHub
  `good first issue` label and only their applicable typed category label.
- Replace the `v0.1.0a5` release body with the reviewed release notes, adding
  the exact documentation successor SHA/tree and links to its current demo.

Every remote write is followed by an API and anonymous-web readback. Stop on
partial state; do not edit package assets to repair metadata.

## 3. Apply repository safeguards

- Enable Dependabot alerts and security updates.
- Enable secret scanning, validity checks and push protection where GitHub
  exposes them for this public repository.
- Preserve private vulnerability reporting as enabled.
- Protect `main` against deletion and force-push, require linear history and
  pull requests, and require the three exact check names listed in section 1.
- Limit emergency bypass to the repository owner and rely on GitHub's audit
  log; no routine release uses bypass.
- Protect the `public-alpha` environment with reviewer `@sigmastratum`, allow
  owner self-review because there is one maintainer, and limit deployments to
  `main` or immutable release tags.
- Preserve `SOS_RELEASE_APPROVED_CANDIDATE` and
  `SOS_RELEASE_APPROVED_ROUTING_COMMIT` until a separately reviewed release
  changes them. PyPI remains disabled.

An unavailable safeguard is recorded truthfully and blocks promotion when it
would leave force-push, unreviewed publication or secret exposure unbounded.

## 4. Observation and promotion

Start a new observation window after all readbacks and CI pass:

- first 24 hours: no promotion; monitor pointer/assets, CI, install failures,
  security reports and documentation mismatches;
- 24--48 hours: resolve only reproducible blockers through one consolidated
  successor;
- after 48 hours without a blocker: request separate owner approval for
  Linux-primary promotion posts.

Public copy uses one repository URL and the canonical installation prompt.
It does not claim Windows support, notarized macOS, zero-click installation,
broad agent support, adoption or time savings.
