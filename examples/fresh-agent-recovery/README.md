# Fresh-agent recovery demo

This wholly synthetic project demonstrates the SOS continuity loop without
provider calls or private repository content.

Do not run the tutorial in this checked-in template. Create a disposable copy:

```bash
python3 tools/reset_fresh_agent_demo.py /tmp/sos-fresh-agent-demo
cd /tmp/sos-fresh-agent-demo
```

The project intentionally contains an existing `AGENTS.md`, unrelated Codex
configuration, and an OpenSpec authority candidate. SOS must preserve all
three and ask which authority is primary.

Run the interactive sequence:

```bash
sos compatibility . --json
sos init --with-codex --primary-authority agents:AGENTS.md .
sos preflight . --json
sos qualify . --family python.stdlib-unittest
sos status . --json

printf '\n# synthetic source change\n' >> src/demo_app.py
sos status . --json
sos next-action . --json
```

The init and qualification confirmations are real terminal confirmations.
Qualification is separate from installation. After the source change, SOS
must refuse to report the previous state current and must return one safe next
action.

From the SOS source repository, run the zero-provider verifier with:

```bash
PYTHONPATH=src python3 tools/check_fresh_agent_demo.py
```

Expected typed states and reasons are frozen in [`expected.json`](expected.json).
The executable step is admitted only on the native-Linux profile described in
the root support matrix.
