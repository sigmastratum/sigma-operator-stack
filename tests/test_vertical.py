from __future__ import annotations

import io
import json
import subprocess
import tempfile
import unittest
from pathlib import Path

from sos.checks import discover_checks, qualify_supported
from sos.contracts import (
    V1_SCHEMA_SHA256,
    V2_SCHEMA_SHA256,
    schema_bundle_hashes,
    validate_p101_v2,
    verify_receipt,
    verify_record,
)
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
        result = initialize_workspace(str(root), confirmed=True, controlling_tty_observed=True)
        self.assertEqual(result.status, "success")
        self.assertTrue((root / ".sigma" / "manifest.json").is_file())
        project_map = (root / ".sigma" / "views" / "project-map.md").read_text(encoding="utf-8")
        self.assertIn("AGENTS.md", project_map)
        self.assertIn("tasks/current.md", project_map)
        second = initialize_workspace(str(root), confirmed=True, controlling_tty_observed=True)
        self.assertEqual(second.status, "success")
        self.assertIn("SOS_ALREADY_INITIALIZED", second.reasons)

    def test_bootstrap_ships_exact_p101_v2_records_and_ordered_receipts(self) -> None:
        temporary, root = self.make_project()
        self.addCleanup(temporary.cleanup)
        self.assertEqual(initialize_workspace(str(root), confirmed=True, controlling_tty_observed=True).status, "success")
        hashes = schema_bundle_hashes()
        self.assertEqual(hashes["sos-contracts-v1.schema.json"], V1_SCHEMA_SHA256)
        self.assertEqual(hashes["sos-contracts-v2.schema.json"], V2_SCHEMA_SHA256)
        record_paths = (
            root / ".sigma" / "records" / "authority.json",
            root / ".sigma" / "records" / "policy.json",
            root / ".sigma" / "records" / "operator-state.json",
        )
        records = [json.loads(path.read_text(encoding="utf-8")) for path in record_paths]
        for record in records:
            validate_p101_v2(record)
            verify_record(record)
            self.assertEqual(record["schema"], "sos_record_envelope_v2")
        receipt_paths = sorted((root / ".sigma" / "receipts").glob("*.json"))
        receipts = [json.loads(path.read_text(encoding="utf-8")) for path in receipt_paths]
        self.assertEqual([item["sequence_ordinal"] for item in receipts], [1, 2, 3])
        self.assertEqual(
            [item["receipt_kind"] for item in receipts],
            ["authority_bootstrap", "policy_bootstrap_plan", "operator_state_bootstrap_plan"],
        )
        for receipt in receipts:
            validate_p101_v2(receipt)
            verify_receipt(receipt)
            self.assertEqual(receipt["accepted_revision"], receipt["proposal_revision"])
        self.assertIsNone(receipts[0]["predecessor_receipt"])
        self.assertEqual(receipts[1]["predecessor_receipt"], receipts[0]["receipt_id"])
        self.assertEqual(receipts[2]["predecessor_receipt"], receipts[1]["receipt_id"])

    def test_local_identity_nonce_is_bound_but_not_recovered(self) -> None:
        temporary, root = self.make_project()
        self.addCleanup(temporary.cleanup)
        initialize_workspace(str(root), confirmed=True, controlling_tty_observed=True)
        authority = json.loads((root / ".sigma" / "records" / "authority.json").read_text(encoding="utf-8"))
        nonce = authority["extensions"]["org.sigmastratum.sos"]["local_repository_nonce"]
        repository = authority["repository"]
        self.assertEqual(repository["identity_mode"], "local_nonce_bound")
        self.assertIsNotNone(repository["local_nonce_commitment"])
        recovery = recover_workspace(str(root))
        serialized = json.dumps(recovery.to_dict(), sort_keys=True)
        self.assertNotIn(nonce, serialized)
        self.assertNotIn("local_repository_nonce", serialized)

    def test_remote_identity_hashes_sanitized_remote_without_serializing_it(self) -> None:
        temporary, root = self.make_project()
        self.addCleanup(temporary.cleanup)
        remote = "https://synthetic-user@example.invalid/example/project.git?private-marker=synthetic"
        git(root, "remote", "add", "origin", remote)
        initialize_workspace(str(root), confirmed=True, controlling_tty_observed=True)
        authority_text = (root / ".sigma" / "records" / "authority.json").read_text(encoding="utf-8")
        authority = json.loads(authority_text)
        self.assertEqual(authority["repository"]["identity_mode"], "remote_bound")
        self.assertEqual(len(authority["repository"]["identity_remote_hashes"]), 1)
        self.assertNotIn("synthetic-user", authority_text)
        self.assertNotIn("private-marker=synthetic", authority_text)

    def test_dirty_bootstrap_binds_complete_application_fingerprint(self) -> None:
        temporary, root = self.make_project()
        self.addCleanup(temporary.cleanup)
        (root / "README.md").write_text("synthetic dirty state\n", encoding="utf-8")
        result = initialize_workspace(str(root), confirmed=True, controlling_tty_observed=True)
        self.assertEqual(result.status, "success")
        authority = json.loads((root / ".sigma" / "records" / "authority.json").read_text(encoding="utf-8"))
        application = authority["source_binding"]["source_observation"]["application_state"]
        self.assertEqual(application["state"], "dirty")
        self.assertTrue(application["complete"])
        self.assertEqual(application["entry_count"], 1)
        self.assertGreater(application["bytes_hashed"], 0)
        self.assertRegex(application["fingerprint"], r"^sha256:[0-9a-f]{64}$")
        self.assertEqual(workspace_status(str(root)).status, "success")

    def test_unconfirmed_bootstrap_does_not_write(self) -> None:
        temporary, root = self.make_project()
        self.addCleanup(temporary.cleanup)
        result = initialize_workspace(str(root), confirmed=False)
        self.assertEqual(result.status, "owner_required")
        self.assertFalse((root / ".sigma").exists())

    def test_non_tty_acceptance_does_not_claim_operator_evidence(self) -> None:
        temporary, root = self.make_project()
        self.addCleanup(temporary.cleanup)
        result = initialize_workspace(str(root), confirmed=True, controlling_tty_observed=False)
        self.assertEqual(result.status, "owner_required")
        self.assertEqual(result.reasons, ("SOS_ACCEPTANCE_TTY_REQUIRED",))
        self.assertFalse((root / ".sigma").exists())

    def test_doctor_requires_current_work(self) -> None:
        temporary, root = self.make_project()
        self.addCleanup(temporary.cleanup)
        (root / "tasks" / "current.md").unlink()
        git(root, "add", "tasks/current.md")
        git(root, "commit", "-qm", "remove synthetic current work")
        initialize_workspace(str(root), confirmed=True, controlling_tty_observed=True)
        receipt = qualify_supported(str(root))
        store_qualification(str(root), receipt)
        doctor = doctor_workspace(str(root))
        self.assertEqual(doctor.status, "owner_required")
        self.assertEqual(doctor.reasons, ("SOS_CURRENT_WORK_NOT_CONFIGURED",))

    def test_supported_structural_check_passes_and_project_execution_fails_closed(self) -> None:
        temporary, root = self.make_project()
        self.addCleanup(temporary.cleanup)
        initialize_workspace(str(root), confirmed=True, controlling_tty_observed=True)
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
        initialize_workspace(str(root), confirmed=True, controlling_tty_observed=True)
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
        initialize_workspace(str(root), confirmed=True, controlling_tty_observed=True)
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
        initialize_workspace(str(root), confirmed=True, controlling_tty_observed=True)
        (root / "README.md").write_text("changed\n", encoding="utf-8")
        self.assertEqual(workspace_status(str(root)).status, "stale")
        self.assertEqual(recover_workspace(str(root)).status, "stale")
        self.assertEqual(validate_repository(str(root)).status, "stale")

    def test_validate_checks_workspace_manifest(self) -> None:
        temporary, root = self.make_project()
        self.addCleanup(temporary.cleanup)
        initialize_workspace(str(root), confirmed=True, controlling_tty_observed=True)
        (root / ".sigma" / "manifest.json").write_text("{}\n", encoding="utf-8")
        result = validate_repository(str(root))
        self.assertEqual(result.status, "invalid")
        self.assertEqual(result.reasons, ("SOS_CONTROL_PLANE_INTEGRITY_INVALID",))

    def test_integrity_corruption_precedes_source_stale_on_every_read_surface(self) -> None:
        temporary, root = self.make_project()
        self.addCleanup(temporary.cleanup)
        initialize_workspace(str(root), confirmed=True, controlling_tty_observed=True)
        authority_path = root / ".sigma" / "records" / "authority.json"
        authority = json.loads(authority_path.read_text(encoding="utf-8"))
        authority["payload"]["approved_roots"] = ["docs"]
        authority_path.write_text(json.dumps(authority), encoding="utf-8")
        (root / "README.md").write_text("source also changed\n", encoding="utf-8")
        for result in (
            workspace_status(str(root)),
            validate_repository(str(root)),
            recover_workspace(str(root)),
            doctor_workspace(str(root)),
        ):
            self.assertEqual(result.status, "invalid")
            self.assertEqual(result.reasons, ("SOS_CONTROL_PLANE_INTEGRITY_INVALID",))
        response = handle_message(
            {"jsonrpc": "2.0", "id": 7, "method": "tools/call", "params": {"name": "sos_status", "arguments": {}}},
            str(root),
        )
        self.assertEqual(response["result"]["structuredContent"]["status"], "invalid")

    def test_full_integrity_replay_rejects_each_bootstrap_authority_surface(self) -> None:
        mutations = (
            ("records/policy.json", lambda value: value["payload"].update({"default_decision": "blocked"})),
            ("receipts/02-policy_bootstrap_plan.json", lambda value: value.update({"sequence_ordinal": 3})),
            ("manifest.json", lambda value: value.update({"receipt_tip": "sha256:" + "f" * 64})),
            ("checks/plan.json", lambda value: value.update({"plan_digest": "sha256:" + "e" * 64})),
        )
        for relative, mutate in mutations:
            with self.subTest(relative=relative):
                temporary, root = self.make_project()
                try:
                    initialize_workspace(str(root), confirmed=True, controlling_tty_observed=True)
                    target = root / ".sigma" / relative
                    value = json.loads(target.read_text(encoding="utf-8"))
                    mutate(value)
                    target.write_text(json.dumps(value), encoding="utf-8")
                    result = workspace_status(str(root))
                    self.assertEqual(result.status, "invalid")
                    self.assertEqual(result.reasons, ("SOS_CONTROL_PLANE_INTEGRITY_INVALID",))
                finally:
                    temporary.cleanup()

    def test_qualification_pointer_and_immutable_receipt_are_replayed(self) -> None:
        temporary, root = self.make_project()
        self.addCleanup(temporary.cleanup)
        initialize_workspace(str(root), confirmed=True, controlling_tty_observed=True)
        store_qualification(str(root), qualify_supported(str(root)))
        view_path = root / ".sigma" / "views" / "qualification.json"
        view = json.loads(view_path.read_text(encoding="utf-8"))
        immutable_path = root / ".sigma" / "qualification" / "receipts" / (
            view["receipt_digest"].removeprefix("sha256:") + ".json"
        )
        immutable = json.loads(immutable_path.read_text(encoding="utf-8"))
        immutable["status"] = "failed"
        immutable_path.write_text(json.dumps(immutable), encoding="utf-8")
        result = workspace_status(str(root))
        self.assertEqual(result.status, "invalid")
        self.assertEqual(result.reasons, ("SOS_CONTROL_PLANE_INTEGRITY_INVALID",))

    def test_committing_only_control_plane_does_not_make_application_stale(self) -> None:
        temporary, root = self.make_project()
        self.addCleanup(temporary.cleanup)
        initialize_workspace(str(root), confirmed=True, controlling_tty_observed=True)
        git(root, "add", ".sigma")
        git(root, "commit", "-qm", "accept synthetic SOS control plane")
        self.assertEqual(workspace_status(str(root)).status, "success")

    def test_syntax_failure_is_not_green(self) -> None:
        temporary, root = self.make_project()
        self.addCleanup(temporary.cleanup)
        (root / "broken.py").write_text("def broken(:\n", encoding="utf-8")
        git(root, "add", "broken.py")
        git(root, "commit", "-qm", "synthetic syntax failure")
        initialize_workspace(str(root), confirmed=True, controlling_tty_observed=True)
        receipt = qualify_supported(str(root))
        self.assertEqual(receipt.status, "failed")
        self.assertEqual(receipt.reasons, ("SOS_QUALIFICATION_FAILED",))
        store_qualification(str(root), receipt)
        self.assertEqual(doctor_workspace(str(root)).status, "not_verified")

    def test_mcp_is_read_only_and_matches_recovery_core(self) -> None:
        temporary, root = self.make_project()
        self.addCleanup(temporary.cleanup)
        initialize_workspace(str(root), confirmed=True, controlling_tty_observed=True)
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
        initialize_workspace(str(root), confirmed=True, controlling_tty_observed=True)
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
