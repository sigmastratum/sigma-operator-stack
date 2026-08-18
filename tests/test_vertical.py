from __future__ import annotations

import io
import json
import subprocess
import tempfile
import unittest
from pathlib import Path

from sos.checks import discover_checks, qualify_supported
from sos.mcp import handle_message, serve_stdio
from sos.workspace import (
    WorkspaceError,
    doctor_workspace,
    initialize_workspace,
    recover_workspace,
    store_qualification,
    workspace_status,
)
from sos.validation import validate_repository


def git(root: Path, *args: str) -> None:
    subprocess.run(["git", "-C", str(root), *args], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)


class DifferentiatedVerticalTests(unittest.TestCase):
    def make_project(self) -> tuple[tempfile.TemporaryDirectory[str], Path]:
        temporary = tempfile.TemporaryDirectory()
        root = Path(temporary.name)
        git(root, "init", "-q")
        git(root, "config", "user.name", "Synthetic Operator")
        git(root, "config", "user.email", "synthetic@example.invalid")
        (root / "AGENTS.md").write_text("Synthetic public instructions.\n", encoding="utf-8")
        (root / "README.md").write_text("Synthetic project.\n", encoding="utf-8")
        (root / "pyproject.toml").write_text(
            "[build-system]\nrequires = []\nbuild-backend = 'synthetic.backend'\n",
            encoding="utf-8",
        )
        (root / "tasks").mkdir()
        (root / "tasks" / "current.md").write_text("Synthetic current task.\n", encoding="utf-8")
        (root / "tests").mkdir()
        (root / "tests" / "test_smoke.py").write_text(
            "import unittest\n\nclass Smoke(unittest.TestCase):\n    def test_true(self):\n        self.assertTrue(True)\n",
            encoding="utf-8",
        )
        git(root, "add", ".")
        git(root, "commit", "-qm", "synthetic project")
        return temporary, root

    def test_one_command_bootstrap_is_existing_first_and_idempotent(self) -> None:
        temporary, root = self.make_project()
        self.addCleanup(temporary.cleanup)
        result = initialize_workspace(str(root), confirmed=True)
        self.assertEqual(result.status, "success")
        self.assertTrue((root / ".sigma" / "manifest.json").is_file())
        project_map = (root / ".sigma" / "views" / "project-map.md").read_text(encoding="utf-8")
        self.assertIn("AGENTS.md", project_map)
        self.assertIn("tasks/current.md", project_map)
        second = initialize_workspace(str(root), confirmed=True)
        self.assertEqual(second.status, "success")
        self.assertIn("SOS_ALREADY_INITIALIZED", second.reasons)

    def test_unconfirmed_bootstrap_does_not_write(self) -> None:
        temporary, root = self.make_project()
        self.addCleanup(temporary.cleanup)
        result = initialize_workspace(str(root), confirmed=False)
        self.assertEqual(result.status, "owner_required")
        self.assertFalse((root / ".sigma").exists())

    def test_doctor_requires_current_work(self) -> None:
        temporary, root = self.make_project()
        self.addCleanup(temporary.cleanup)
        (root / "tasks" / "current.md").unlink()
        git(root, "add", "tasks/current.md")
        git(root, "commit", "-qm", "remove synthetic current work")
        initialize_workspace(str(root), confirmed=True)
        receipt = qualify_supported(str(root))
        store_qualification(str(root), receipt)
        doctor = doctor_workspace(str(root))
        self.assertEqual(doctor.status, "owner_required")
        self.assertEqual(doctor.reasons, ("SOS_CURRENT_WORK_NOT_CONFIGURED",))

    def test_supported_structural_check_passes_and_project_execution_fails_closed(self) -> None:
        temporary, root = self.make_project()
        self.addCleanup(temporary.cleanup)
        initialize_workspace(str(root), confirmed=True)
        plan = discover_checks(str(root))
        self.assertEqual(plan.families[0].status, "configured")
        self.assertEqual(plan.families[0].family_id, "python.syntax")
        self.assertEqual(plan.families[0].isolation, "non-executing-structural-v1")
        self.assertEqual(plan.families[1].family_id, "python.stdlib-unittest")
        self.assertEqual(plan.families[1].status, "unsupported")
        receipt = qualify_supported(str(root))
        self.assertEqual(receipt.status, "passed_local")
        self.assertFalse(receipt.raw_output_serialized)
        self.assertIsNotNone(receipt.output_digest)
        store_qualification(str(root), receipt)
        store_qualification(str(root), receipt)
        self.assertEqual(doctor_workspace(str(root)).status, "success")

    def test_qualification_write_rejects_symlinked_control_directory(self) -> None:
        temporary, root = self.make_project()
        self.addCleanup(temporary.cleanup)
        initialize_workspace(str(root), confirmed=True)
        receipt = qualify_supported(str(root))
        outside = root / "outside"
        outside.mkdir()
        (root / ".sigma" / "qualification").symlink_to(outside, target_is_directory=True)
        with self.assertRaises(WorkspaceError):
            store_qualification(str(root), receipt)
        self.assertEqual(list(outside.iterdir()), [])

    def test_fresh_agent_recovery_exposes_composed_state_without_content(self) -> None:
        temporary, root = self.make_project()
        self.addCleanup(temporary.cleanup)
        initialize_workspace(str(root), confirmed=True)
        receipt = qualify_supported(str(root))
        store_qualification(str(root), receipt)
        recovery = recover_workspace(str(root))
        self.assertEqual(recovery.status, "success")
        self.assertEqual(recovery.details["authority"]["paths"][0], "AGENTS.md")
        self.assertEqual(recovery.details["current_work"]["path"], "tasks/current.md")
        self.assertEqual(recovery.details["qualification"]["status"], "passed_local")
        serialized = json.dumps(recovery.to_dict(), sort_keys=True)
        self.assertNotIn(str(root), serialized)
        self.assertNotIn("Synthetic current task", serialized)

    def test_source_change_makes_workspace_and_recovery_stale(self) -> None:
        temporary, root = self.make_project()
        self.addCleanup(temporary.cleanup)
        initialize_workspace(str(root), confirmed=True)
        (root / "README.md").write_text("changed\n", encoding="utf-8")
        self.assertEqual(workspace_status(str(root)).status, "stale")
        self.assertEqual(recover_workspace(str(root)).status, "stale")
        self.assertEqual(validate_repository(str(root)).status, "stale")

    def test_validate_checks_workspace_manifest(self) -> None:
        temporary, root = self.make_project()
        self.addCleanup(temporary.cleanup)
        initialize_workspace(str(root), confirmed=True)
        (root / ".sigma" / "manifest.json").write_text("{}\n", encoding="utf-8")
        result = validate_repository(str(root))
        self.assertEqual(result.status, "invalid")
        self.assertEqual(result.reasons, ("SOS_WORKSPACE_MANIFEST_INVALID",))

    def test_committing_only_control_plane_does_not_make_application_stale(self) -> None:
        temporary, root = self.make_project()
        self.addCleanup(temporary.cleanup)
        initialize_workspace(str(root), confirmed=True)
        git(root, "add", ".sigma")
        git(root, "commit", "-qm", "accept synthetic SOS control plane")
        self.assertEqual(workspace_status(str(root)).status, "success")

    def test_syntax_failure_is_not_green(self) -> None:
        temporary, root = self.make_project()
        self.addCleanup(temporary.cleanup)
        (root / "broken.py").write_text("def broken(:\n", encoding="utf-8")
        git(root, "add", "broken.py")
        git(root, "commit", "-qm", "synthetic syntax failure")
        initialize_workspace(str(root), confirmed=True)
        receipt = qualify_supported(str(root))
        self.assertEqual(receipt.status, "failed")
        self.assertEqual(receipt.reasons, ("SOS_QUALIFICATION_FAILED",))
        store_qualification(str(root), receipt)
        self.assertEqual(doctor_workspace(str(root)).status, "not_verified")

    def test_mcp_is_read_only_and_matches_recovery_core(self) -> None:
        temporary, root = self.make_project()
        self.addCleanup(temporary.cleanup)
        initialize_workspace(str(root), confirmed=True)
        listed = handle_message({"jsonrpc": "2.0", "id": 1, "method": "tools/list"}, str(root))
        names = [tool["name"] for tool in listed["result"]["tools"]]
        self.assertEqual(names, ["sos_status", "sos_doctor", "sos_recover", "sos_check"])
        self.assertFalse(any(name in names for name in ("accept", "commit", "push", "deploy", "qualify")))
        response = handle_message(
            {"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": {"name": "sos_recover", "arguments": {}}},
            str(root),
        )
        direct = recover_workspace(str(root)).to_dict()
        self.assertEqual(response["result"]["structuredContent"], direct)

    def test_mcp_stdio_handles_initialize_and_tool_call(self) -> None:
        temporary, root = self.make_project()
        self.addCleanup(temporary.cleanup)
        initialize_workspace(str(root), confirmed=True)
        input_stream = io.StringIO(
            '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05"}}\n'
            '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"sos_recover","arguments":{}}}\n'
        )
        output_stream = io.StringIO()
        self.assertEqual(serve_stdio(str(root), stdin=input_stream, stdout=output_stream), 0)
        responses = [json.loads(line) for line in output_stream.getvalue().splitlines()]
        self.assertEqual(responses[0]["result"]["protocolVersion"], "2024-11-05")
        self.assertEqual(responses[1]["result"]["structuredContent"]["contract"], "sos_recovery_result_v1")


if __name__ == "__main__":
    unittest.main()
