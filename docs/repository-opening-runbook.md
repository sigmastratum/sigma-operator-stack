# Public repository opening runbook

This runbook records the already separate source-opening transaction and must
not be reused as package-release authority. It separates publication of
auditable source from package release.
It grants no remote mutation authority. Every phase requires its own owner
approval and an exact candidate/tree recorded immediately before execution.

## Preconditions

- the repository-designated canonical local checkout is clean;
- the candidate is a linear descendant of the public product-only root;
- the current-tree and full-history public scans pass;
- independent review binds the exact candidate and tree;
- for the completed source-opening transaction, `release/current.json`, public
  tags and GitHub Releases were absent;
- the later routing successor does not retroactively broaden that transaction;
- the private-vulnerability-reporting API is available for immediate activation
  after visibility changes; GitHub exposes that feature only for public
  repositories, so the exact rollback operation is ready in advance.

## Transaction

1. With separate push approval, push the exact reviewed candidate to a new
   release-candidate branch while the repository remains private.
2. Read the remote branch back and require the exact candidate/tree. Stop on
   any drift; do not merge, force-push or rewrite history.
3. With separate settings approval, set the reviewed branch as default and
   apply the checked About/topics/features metadata. Read every available
   setting back. Do not treat private vulnerability reporting as configurable
   while the repository is private.
4. With separate visibility approval, change only repository visibility to
   public, immediately enable private vulnerability reporting and read it
   back. These operations form one rollback-bound transaction: if activation
   or readback fails, return the repository to private. Do not create a tag,
   Release, package, Store publication or release pointer in this transaction.
5. Read the anonymous public repository back, verify the default candidate,
   tree, README and license, then observe public Actions for that exact SHA.
   Record pointer presence or absence exactly as it existed at source opening.

## Stop conditions

Stop before visibility on candidate/tree drift, a dirty worktree, history-scan
failure, an unavailable vulnerability-reporting activation or rollback route,
wrong default branch, broken links, private content or any unsupported
package-availability claim.

After visibility, immediately return the repository to private if private
vulnerability reporting cannot be enabled and confirmed, or if the public
readback exposes the wrong source, private content, credentials, an unexpected
release pointer or a materially broader claim. Public exposure cannot be
undone historically, so retain the incident record privately and rotate any
credential even if the repository is made private again.

A failing public CI job without a content or trust-boundary violation does not
authorize history rewriting. Keep package publication blocked, diagnose on a
successor, and require a new exact review before changing the default branch.

## Separate later gates

The following are deliberately outside the source-opening transaction:

- immutable release tag;
- GitHub Release and release assets;
- PyPI publication;
- `release/current.json` activation and its complete native asset set;
- Microsoft Store publication;
- macOS signed/notarized distribution;
- promotion or adoption claims.

Each later gate binds one final release candidate and has its own rollback or
successor policy.
