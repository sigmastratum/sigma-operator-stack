# Agent-first offline replay

The AF103 replay is a contributor qualification tool, not an end-user
installer and not evidence of a successful Microsoft Store or fresh Codex
session.

It verifies the deterministic parts of the public route:

- pointer and release-index admission;
- archive versus Microsoft Store selection;
- exact platform and Store metadata binding;
- fail-closed archive inspection and logical extraction;
- sandbox-to-interactive-user refusal;
- truthful terminal states and safe next actions.

Run it from a source checkout with the repository's test environment:

```text
python tools/replay_agent_first_route.py \
  --matrix tests/fixtures/agent-first-release/replay-matrix.json \
  --pointer tests/fixtures/agent-first-release/current.json \
  --index tests/fixtures/agent-first-release/sos-release-index-v1.json \
  --schemas src/sos/schemas
```

The receipt is deterministic and content-safe. It records no path, prompt,
response, credential or project content. Its external counters remain zero.
`simulated_store_success` and `simulated_fresh_session` are always false.

A passing replay does not activate `release/current.json`, qualify a Store
package or authorize publication. Those claims require the separate AF104
clean-host drill.
