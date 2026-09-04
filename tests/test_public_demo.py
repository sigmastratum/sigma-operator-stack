from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


class PublicDemoTests(unittest.TestCase):
    def load_verifier(self):
        root = Path(__file__).resolve().parents[1]
        specification = importlib.util.spec_from_file_location(
            "sos_demo_capture_verifier", root / "demo" / "verify_fresh_codex_capture.py"
        )
        self.assertIsNotNone(specification)
        self.assertIsNotNone(specification.loader)
        module = importlib.util.module_from_spec(specification)
        specification.loader.exec_module(module)
        return module

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

    def test_media_renderer_requests_bitexact_containers_and_codecs(self) -> None:
        root = Path(__file__).resolve().parents[1]
        renderer = (root / "demo" / "render_video.py").read_text(encoding="utf-8")
        self.assertIn('"-fflags", "+bitexact"', renderer)
        self.assertEqual(renderer.count('"-flags:v", "+bitexact"'), 2)
        self.assertEqual(renderer.count('"-flags:a", "+bitexact"'), 2)

    def test_terminal_frame_displays_abbreviated_candidate_and_wheel_sha(self) -> None:
        root = Path(__file__).resolve().parents[1]
        manifest = json.loads(
            (root / "demo" / "media-manifest.json").read_text(encoding="utf-8")
        )
        frame = (root / "demo" / "terminal-frame.txt").read_text(encoding="utf-8")
        self.assertIn(f"candidate {manifest['candidate'][:7]}", frame)
        self.assertIn(f"wheel {manifest['wheel_sha256'][:8]}", frame)

    def test_fresh_codex_verifier_requires_exact_read_only_mcp_recovery(self) -> None:
        module = self.load_verifier()
        events = [
            {"type": "thread.started", "thread_id": "synthetic"},
            {"type": "turn.started"},
        ]
        for name in sorted(module.REQUIRED_TOOLS):
            events.append(
                {
                    "type": "item.completed",
                    "item": {
                        "type": "mcp_tool_call",
                        "server": "sigma_operator_stack",
                        "tool": name,
                        "status": "completed",
                    },
                }
            )
        events.extend(
            [
                {"type": "item.completed", "item": {"type": "agent_message"}},
                {"type": "turn.completed"},
            ]
        )
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            event_path = root / "events.jsonl"
            response_path = root / "response.json"
            event_path.write_text(
                "".join(json.dumps(event) + "\n" for event in events), encoding="utf-8"
            )
            response_path.write_text(json.dumps(module.EXPECTED_OUTPUT), encoding="utf-8")
            receipt = module.verify(
                event_path,
                response_path,
                candidate="a" * 40,
                tree="b" * 40,
                wheel_sha256="c" * 64,
                client="codex-cli 0.145.0",
                model="gpt-5.6-sol",
            )
        self.assertEqual(receipt["status"], "passed")
        self.assertEqual(receipt["provider_calls"], 1)
        self.assertEqual(receipt["shell_calls"], 0)
        self.assertEqual(receipt["mutation_tool_calls"], 0)
        self.assertFalse(receipt["raw_prompt_stored"])
        self.assertFalse(receipt["raw_response_stored"])

    def test_fresh_codex_verifier_rejects_shell_or_missing_tool(self) -> None:
        module = self.load_verifier()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            response_path = root / "response.json"
            response_path.write_text(json.dumps(module.EXPECTED_OUTPUT), encoding="utf-8")
            for item in (
                {"type": "command_execution", "status": "completed"},
                {
                    "type": "mcp_tool_call",
                    "server": "sigma_operator_stack",
                    "tool": "sos_status",
                    "status": "completed",
                },
            ):
                event_path = root / "events.jsonl"
                event_path.write_text(
                    "\n".join(
                        json.dumps(event)
                        for event in (
                            {"type": "thread.started"},
                            {"type": "item.completed", "item": item},
                            {"type": "turn.completed"},
                        )
                    )
                    + "\n",
                    encoding="utf-8",
                )
                with self.assertRaises(ValueError):
                    module.verify(
                        event_path,
                        response_path,
                        candidate="a" * 40,
                        tree="b" * 40,
                        wheel_sha256="c" * 64,
                        client="codex-cli 0.145.0",
                        model="gpt-5.6-sol",
                    )

    def test_fresh_codex_verifier_allows_every_manifest_tool(self) -> None:
        module = self.load_verifier()
        events = [{"type": "thread.started"}]
        for name in sorted(module.ALLOWED_TOOLS):
            events.append(
                {
                    "type": "item.started",
                    "item": {
                        "type": "mcp_tool_call",
                        "server": "sigma_operator_stack",
                        "tool": name,
                        "status": "in_progress",
                    },
                }
            )
            events.append(
                {
                    "type": "item.completed",
                    "item": {
                        "type": "mcp_tool_call",
                        "server": "sigma_operator_stack",
                        "tool": name,
                        "status": "completed",
                    },
                }
            )
        events.append({"type": "turn.completed"})
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            event_path = root / "events.jsonl"
            response_path = root / "response.json"
            event_path.write_text(
                "".join(json.dumps(event) + "\n" for event in events), encoding="utf-8"
            )
            response_path.write_text(json.dumps(module.EXPECTED_OUTPUT), encoding="utf-8")
            receipt = module.verify(
                event_path,
                response_path,
                candidate="a" * 40,
                tree="b" * 40,
                wheel_sha256="c" * 64,
                client="codex-cli 0.145.0",
                model="gpt-5.6-sol",
            )
        self.assertEqual(set(receipt["mcp_tools_completed"]), module.ALLOWED_TOOLS)


if __name__ == "__main__":
    unittest.main()
