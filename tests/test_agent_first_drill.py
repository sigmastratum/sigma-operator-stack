from __future__ import annotations

import hashlib
import importlib.util
import json
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
TOOL = ROOT / "tools/check_agent_first_drill.py"
SPEC = importlib.util.spec_from_file_location("sos_agent_first_drill", TOOL)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


def canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


class AgentFirstDrillTests(unittest.TestCase):
    def make_repository(self, root: Path) -> Path:
        repository = root / "repository"
        (repository / "src/sos/schemas").mkdir(parents=True)
        (repository / "release").mkdir()
        shutil.copy2(
            ROOT / "src/sos/schemas/sos-agent-first-drill-receipt-v1.schema.json",
            repository / "src/sos/schemas/sos-agent-first-drill-receipt-v1.schema.json",
        )
        shutil.copy2(
            ROOT / "tests/fixtures/agent-first-release/current.json",
            repository / "release/current.json",
        )
        shutil.copy2(
            ROOT / "tests/fixtures/agent-first-release/sos-release-index-v1.json",
            repository / "release/sos-release-index-v1.json",
        )
        return repository

    def passing_receipt(self) -> dict[str, object]:
        pointer = json.loads(
            (ROOT / "tests/fixtures/agent-first-release/current.json").read_text()
        )
        receipt: dict[str, object] = {
            "absolute_paths_serialized": False,
            "architecture": "x86_64",
            "attempt_id": "af104-synthetic-contract-test",
            "candidate": pointer["candidate"],
            "clean_host": True,
            "contract": "sos_agent_first_drill_receipt_v1",
            "defender_enabled": True,
            "founder_hints": False,
            "hidden_confirmation": False,
            "instruction": "Install SOS in my current project. Show me the preview before changing it.",
            "manual_commands": False,
            "mutations_outside_confirmed_project": False,
            "ordinary_user": True,
            "path_repair": False,
            "provider_calls": 2,
            "raw_content_serialized": False,
            "release_tag": pointer["release_tag"],
            "security_bypass": False,
            "sigma_preserved": True,
            "source_url": "https://github.com/sigmastratum/sigma-operator-stack",
            "status": "passed",
            "steps": [
                {"step_id": step, "status": "passed"}
                for step in MODULE.STEP_ORDER
            ],
            "store_product_id": "9NNZT70C613H",
            "store_signed": True,
            "store_trust_valid": True,
            "system": "windows",
            "tree": pointer["tree"],
            "uac_enabled": True,
            "user_project_confirmation": True,
            "user_store_confirmation": True,
            "version": pointer["version"],
        }
        receipt["receipt_digest"] = "sha256:" + hashlib.sha256(canonical(receipt)).hexdigest()
        return receipt

    def write_receipt(self, root: Path, receipt: dict[str, object]) -> Path:
        path = root / "receipt.json"
        path.write_text(json.dumps(receipt), encoding="utf-8")
        return path

    def test_absent_receipt_is_truthful_not_run(self) -> None:
        self.assertEqual(MODULE.inspect(ROOT, None)["status"], "not_run")

    def test_exact_receipt_passes(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            repository = self.make_repository(root)
            receipt = self.write_receipt(root, self.passing_receipt())
            self.assertEqual(MODULE.inspect(repository, receipt), {
                "contract": "sos_agent_first_drill_check_v1",
                "failures": [],
                "status": "passed",
            })

    def test_hidden_confirmation_and_step_reordering_fail(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            repository = self.make_repository(root)
            value = self.passing_receipt()
            value["hidden_confirmation"] = True
            value["steps"] = list(reversed(value["steps"]))
            value["receipt_digest"] = "sha256:" + hashlib.sha256(
                canonical({key: item for key, item in value.items() if key != "receipt_digest"})
            ).hexdigest()
            result = MODULE.inspect(repository, self.write_receipt(root, value))
            self.assertEqual(result["status"], "failed")
            self.assertIn("SOS_AGENT_FIRST_DRILL_RECEIPT_SCHEMA_INVALID", result["failures"])
            self.assertIn("SOS_AGENT_FIRST_DRILL_STEP_ORDER_INVALID", result["failures"])

    def test_release_and_store_binding_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            repository = self.make_repository(root)
            value = self.passing_receipt()
            value["candidate"] = "0" * 40
            value["store_product_id"] = "AAAAAAAAAAAA"
            value["receipt_digest"] = "sha256:" + hashlib.sha256(
                canonical({key: item for key, item in value.items() if key != "receipt_digest"})
            ).hexdigest()
            result = MODULE.inspect(repository, self.write_receipt(root, value))
            self.assertEqual(result["status"], "failed")
            self.assertIn("SOS_AGENT_FIRST_DRILL_RELEASE_BINDING_MISMATCH", result["failures"])
            self.assertIn("SOS_AGENT_FIRST_DRILL_STORE_BINDING_MISMATCH", result["failures"])


if __name__ == "__main__":
    unittest.main()
