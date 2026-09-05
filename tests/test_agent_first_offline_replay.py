from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
import unittest
from pathlib import Path

from jsonschema import Draft202012Validator


ROOT = Path(__file__).resolve().parents[1]
SCHEMAS = ROOT / "src/sos/schemas"
FIXTURES = ROOT / "tests/fixtures/agent-first-release"
TOOL = ROOT / "tools/replay_agent_first_route.py"
SPEC = importlib.util.spec_from_file_location("sos_agent_first_offline_replay", TOOL)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class AgentFirstOfflineReplayTests(unittest.TestCase):
    def load(self, name: str) -> dict[str, object]:
        return json.loads((FIXTURES / name).read_text(encoding="utf-8"))

    def test_terminal_projection_precedence_and_contradiction(self) -> None:
        snapshot = {
            "contract": "sos_agent_first_terminal_snapshot_v1",
            "authority_state": "owner_required",
            "configured_family_count": 1,
            "qualification_state": "passed_local",
            "setup_state": "success",
            "workspace_state": "stale",
        }
        result = MODULE.terminal_projection(snapshot, SCHEMAS)
        self.assertEqual(result["status"], "owner_required")
        snapshot["authority_state"] = "accepted"
        self.assertEqual(MODULE.terminal_projection(snapshot, SCHEMAS)["status"], "stale")
        snapshot.update(
            configured_family_count=0,
            qualification_state="passed_local",
            workspace_state="current",
        )
        result = MODULE.terminal_projection(snapshot, SCHEMAS)
        self.assertEqual(result["status"], "invalid")
        self.assertEqual(result["reasons"], ["SOS_AGENT_FIRST_TERMINAL_SNAPSHOT_CONTRADICTORY"])

    def test_archive_verification_is_fail_closed(self) -> None:
        archive = MODULE._synthetic_archive()
        import hashlib

        digest = hashlib.sha256(archive).hexdigest()
        self.assertEqual(
            MODULE.verify_synthetic_archive(archive, digest),
            ("success", "SOS_AGENT_FIRST_ARCHIVE_VERIFIED"),
        )
        self.assertEqual(
            MODULE.verify_synthetic_archive(archive, "0" * 64),
            ("blocked", "SOS_AGENT_FIRST_ARCHIVE_DIGEST_MISMATCH"),
        )

    def test_exact_matrix_passes_and_is_deterministic(self) -> None:
        arguments = {
            "matrix": self.load("replay-matrix.json"),
            "pointer": self.load("current.json"),
            "index": self.load("sos-release-index-v1.json"),
            "schema_root": SCHEMAS,
        }
        first = MODULE.replay(**arguments)
        second = MODULE.replay(**arguments)
        self.assertEqual(first, second)
        self.assertEqual(first["status"], "passed")
        self.assertEqual(first["case_count"], 17)
        self.assertFalse(first["simulated_store_success"])
        self.assertFalse(first["simulated_fresh_session"])
        schema = json.loads(
            (SCHEMAS / "sos-agent-first-offline-replay-v1.schema.json").read_text()
        )
        Draft202012Validator(schema).validate(first)

    def test_checked_in_linux_macos_release_matrix_passes_offline(self) -> None:
        arguments = {
            "matrix": self.load("linux-macos-release-matrix.json"),
            "pointer": json.loads((ROOT / "release" / "current.json").read_text()),
            "index": json.loads(
                (ROOT / "release" / "sos-release-index-v1.json").read_text()
            ),
            "schema_root": SCHEMAS,
        }
        first = MODULE.replay(**arguments)
        second = MODULE.replay(**arguments)
        self.assertEqual(first, second)
        self.assertEqual(first["status"], "passed", first)
        self.assertEqual(first["case_count"], 11)
        self.assertEqual(first["provider_calls"], 0)
        self.assertFalse(first["network_performed"])
        self.assertFalse(first["mutations_performed"])
        self.assertFalse(first["simulated_fresh_session"])
        self.assertFalse(first["simulated_store_success"])

    def test_cli_receipt_has_zero_external_actions(self) -> None:
        completed = subprocess.run(
            [
                sys.executable,
                str(TOOL),
                "--matrix",
                str(FIXTURES / "replay-matrix.json"),
                "--pointer",
                str(FIXTURES / "current.json"),
                "--index",
                str(FIXTURES / "sos-release-index-v1.json"),
                "--schemas",
                str(SCHEMAS),
            ],
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        self.assertEqual(completed.returncode, 0)
        receipt = json.loads(completed.stdout)
        self.assertEqual(receipt["provider_calls"], 0)
        self.assertFalse(receipt["network_performed"])
        self.assertFalse(receipt["mutations_performed"])
        self.assertEqual(completed.stderr, "")


if __name__ == "__main__":
    unittest.main()
