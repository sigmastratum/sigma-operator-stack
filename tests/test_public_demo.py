from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


class PublicDemoTests(unittest.TestCase):
    def test_zero_provider_tutorial_replay(self) -> None:
        root = Path(__file__).resolve().parents[1]
        completed = subprocess.run(
            [sys.executable, str(root / "tools" / "check_fresh_agent_demo.py")],
            cwd=root,
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=60,
        )
        report = json.loads(completed.stdout.splitlines()[-1])
        self.assertEqual(report["status"], "passed", report)
        self.assertEqual(report["provider_calls"], 0)
        self.assertEqual(report["network_calls"], 0)

    def test_reset_refuses_foreign_existing_directory(self) -> None:
        root = Path(__file__).resolve().parents[1]
        with tempfile.TemporaryDirectory() as directory:
            foreign = Path(directory) / "foreign"
            foreign.mkdir()
            (foreign / "keep.txt").write_text("synthetic\n", encoding="utf-8")
            completed = subprocess.run(
                [sys.executable, str(root / "tools" / "reset_fresh_agent_demo.py"), str(foreign)],
                cwd=root,
                check=False,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=30,
            )
            self.assertNotEqual(completed.returncode, 0)
            self.assertIn("SOS_DEMO_TARGET_NOT_MARKER_OWNED", completed.stderr)
            self.assertEqual((foreign / "keep.txt").read_text(encoding="utf-8"), "synthetic\n")

    def test_transcript_and_expected_steps_match(self) -> None:
        root = Path(__file__).resolve().parents[1]
        expected = json.loads(
            (root / "examples" / "fresh-agent-recovery" / "expected.json").read_text(encoding="utf-8")
        )
        transcript = (root / "demo" / "transcript.md").read_text(encoding="utf-8")
        names = [step["name"] for step in expected["steps"]]
        self.assertEqual(
            names,
            [
                "compatibility",
                "init",
                "preflight_before_qualification",
                "qualify_python_unittest",
                "fresh_recovery",
                "source_change",
                "safe_next_action",
            ],
        )
        for token in (
            "SOS_PRIMARY_AUTHORITY_REQUIRED",
            "not_verified",
            "passed_local",
            "SOS_SOURCE_STATUS_CHANGED",
        ):
            self.assertIn(token, transcript)


if __name__ == "__main__":
    unittest.main()
