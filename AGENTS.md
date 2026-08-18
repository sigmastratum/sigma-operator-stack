# SOS Repository Instructions

Read `PUBLIC_REPOSITORY_BOUNDARY.md` before every task.

This repository is intended to become public. Treat every uncommitted file,
test fixture, log and generated artifact as publicly disclosable regardless of
the repository's current visibility.

Only public SOS product source, public contracts, synthetic fixtures,
hermetic qualification, user documentation and distribution metadata belong
here.

Never add:

- secrets, credentials or environment values;
- user, customer, session, connector or production data;
- raw prompts, messages, responses, transcripts or attachments;
- private filesystem paths, infrastructure topology or deployment material;
- private planning, commercial pipeline, owner packets or internal evidence;
- operator personas/configuration or private write authority;
- source or Git history copied wholesale from a private, internal or Runtime
  repository.

Product code uses the public `sos` namespace. Fixtures must be wholly
synthetic. Default execution is local, offline and without telemetry. Unknown
authority, provenance, license or content safety fails closed.

Commit, push, release, package publication and visibility changes require the
task's explicit authority.
