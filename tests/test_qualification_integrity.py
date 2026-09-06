from __future__ import annotations

import json
import subprocess
import tempfile
import unittest
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from importlib import resources
from pathlib import Path
from unittest.mock import patch

from jsonschema import Draft202012Validator

from sos.agent_api import project_tool
from sos.checks import discover_checks, qualify_supported
from sos.qualification_contracts import (
    EXECUTOR_DIGEST,
    PACKAGE_EXECUTION_IDENTITY,
    schema_hashes,
    seal_contract,
    validate_contract,
)
from sos.workspace import (
    WorkspaceError,
    accept_proposal,
    admit_qualification_plan,
    doctor_workspace,
    execute_admitted_qualification,
    initialize_workspace,
    prepare_qualification_plan,
    qualify_once,
    recover_workspace,
    regenerate_workspace,
    store_qualification,
    workspace_status,
)


def git(root: Path, *args: str) -> None:
    subprocess.run(["git", "-C", str(root), *args], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)


class QualificationIntegrityTests(unittest.TestCase):
    def make_project(self) -> tuple[tempfile.TemporaryDirectory[str], Path]:
        temporary = tempfile.TemporaryDirectory()
        root = Path(temporary.name)
        git(root, "init", "-q")
        git(root, "config", "user.name", "Synthetic Operator")
        git(root, "config", "user.email", "synthetic@example.invalid")
        (root / "AGENTS.md").write_text("Synthetic public instructions.\n", encoding="utf-8")
        (root / "README.md").write_text("Synthetic qualification project.\n", encoding="utf-8")
        (root / "pyproject.toml").write_text(
            "[build-system]\nrequires = []\nbuild-backend = 'synthetic.backend'\n",
            encoding="utf-8",
        )
        (root / "tasks").mkdir()
        (root / "tasks" / "current.md").write_text("Synthetic current task.\n", encoding="utf-8")
        (root / "tests").mkdir()
        (root / "tests" / "test_smoke.py").write_text(
            "import unittest\n\nclass Smoke(unittest.TestCase):\n"
            "    def test_true(self):\n        self.assertTrue(True)\n",
            encoding="utf-8",
        )
        git(root, "add", ".")
        git(root, "commit", "-qm", "synthetic qualification project")
        result = initialize_workspace(str(root), confirmed=True, controlling_tty_observed=True)
        self.assertEqual(result.status, "success")
        return temporary, root

    def test_four_closed_schemas_are_valid_and_integrity_pinned(self) -> None:
        hashes = schema_hashes()
        self.assertEqual(
            set(hashes),
            {
                "sos_qualification_plan_v1",
                "sos_command_admission_v1",
                "sos_execution_result_v1",
                "sos_qualification_receipt_v1",
            },
        )
        for filename in (
            "sos-qualification-plan-v1.schema.json",
            "sos-command-admission-v1.schema.json",
            "sos-execution-result-v1.schema.json",
            "sos-qualification-receipt-v1.schema.json",
        ):
            schema = json.loads(resources.files("sos.schemas").joinpath(filename).read_text(encoding="utf-8"))
            Draft202012Validator.check_schema(schema)

    def test_exact_chain_binds_source_plan_admission_executor_and_result(self) -> None:
        temporary, root = self.make_project()
        self.addCleanup(temporary.cleanup)
        now = datetime(2026, 1, 1, tzinfo=timezone.utc)
        with patch("sos.workspace._utc_now", return_value=now):
            plan, admission, receipt = qualify_once(
                str(root),
                family_id="python.stdlib-unittest",
                confirmed=True,
                controlling_tty_observed=True,
            )
        validate_contract(plan, "sos_qualification_plan_v1")
        validate_contract(admission, "sos_command_admission_v1")
        validate_contract(receipt, "sos_qualification_receipt_v1")
        self.assertEqual(receipt["status"], "passed_local")
        self.assertEqual(receipt["plan_digest"], plan["plan_digest"])
        self.assertEqual(receipt["admission_id"], admission["admission_id"])
        self.assertEqual(receipt["repository_id"], plan["repository_id"])
        self.assertFalse(receipt["raw_output_serialized"])
        self.assertNotIn(str(root), json.dumps((plan, admission, receipt), sort_keys=True))
        tip = json.loads(
            (root / ".sigma" / "qualification" / "tips" / "00000001.json").read_text(encoding="utf-8")
        )
        self.assertEqual(tip["receipt_digest"], receipt["receipt_digest"])
        self.assertIsNone(tip["predecessor_receipt"])
        self.assertEqual(workspace_status(str(root)).details["qualification_integrity"], "valid")

    def test_executor_identity_binds_package_version_and_executable_bytes(self) -> None:
        self.assertEqual(PACKAGE_EXECUTION_IDENTITY["contract"], "sos_package_execution_identity_v1")
        self.assertEqual(PACKAGE_EXECUTION_IDENTITY["package"], "sigma-operator-stack")
        self.assertEqual(PACKAGE_EXECUTION_IDENTITY["package_version"], "0.1.0a4")
        self.assertGreater(PACKAGE_EXECUTION_IDENTITY["file_count"], 1)
        self.assertRegex(PACKAGE_EXECUTION_IDENTITY["content_digest"], r"^sha256:[0-9a-f]{64}$")
        self.assertRegex(EXECUTOR_DIGEST, r"^sha256:[0-9a-f]{64}$")

    def test_package_execution_change_keeps_chain_valid_but_stales_green(self) -> None:
        temporary, root = self.make_project()
        self.addCleanup(temporary.cleanup)
        _, _, receipt = qualify_once(
            str(root),
            family_id="python.syntax",
            confirmed=True,
            controlling_tty_observed=True,
        )
        changed_character = "0" if receipt["executor_digest"][-1] != "0" else "1"
        changed_executor = "sha256:" + changed_character * 64
        with patch("sos.workspace.EXECUTOR_DIGEST", changed_executor):
            status = workspace_status(str(root))
            self.assertEqual(status.status.value, "success", status.to_dict())
            self.assertEqual(status.details["qualification_integrity"], "valid_stale")
            doctor = doctor_workspace(str(root))
            self.assertEqual(doctor.status.value, "stale", doctor.to_dict())
            self.assertEqual(doctor.reasons, ("SOS_QUALIFICATION_STALE",))
            preflight = project_tool(str(root), "sos_preflight")
            self.assertEqual(preflight.status.value, "stale", preflight.to_dict())
            self.assertEqual(preflight.reasons, ("SOS_QUALIFICATION_STALE",))

    def test_shared_tool_update_stales_each_project_without_cross_project_state(self) -> None:
        first_temporary, first_root = self.make_project()
        second_temporary, second_root = self.make_project()
        self.addCleanup(first_temporary.cleanup)
        self.addCleanup(second_temporary.cleanup)
        first_receipt = qualify_once(
            str(first_root),
            family_id="python.syntax",
            confirmed=True,
            controlling_tty_observed=True,
        )[2]
        second_receipt = qualify_once(
            str(second_root),
            family_id="python.syntax",
            confirmed=True,
            controlling_tty_observed=True,
        )[2]
        self.assertNotEqual(first_receipt["repository_id"], second_receipt["repository_id"])
        changed_executor = "sha256:" + "e" * 64
        with patch("sos.workspace.EXECUTOR_DIGEST", changed_executor):
            first = workspace_status(str(first_root))
            second = workspace_status(str(second_root))
        self.assertEqual(first.details["qualification_integrity"], "valid_stale")
        self.assertEqual(second.details["qualification_integrity"], "valid_stale")
        self.assertEqual(
            json.loads((first_root / ".sigma" / "views" / "qualification.json").read_text()),
            first_receipt,
        )
        self.assertEqual(
            json.loads((second_root / ".sigma" / "views" / "qualification.json").read_text()),
            second_receipt,
        )

    def test_plan_is_deterministic_read_only_and_confirmation_is_required(self) -> None:
        temporary, root = self.make_project()
        self.addCleanup(temporary.cleanup)
        first = prepare_qualification_plan(str(root), "python.stdlib-unittest")
        second = prepare_qualification_plan(str(root), "python.stdlib-unittest")
        self.assertEqual(first, second)
        self.assertFalse((root / ".sigma" / "qualification").exists())
        with self.assertRaisesRegex(WorkspaceError, "SOS_QUALIFICATION_CONFIRMATION_REQUIRED"):
            admit_qualification_plan(str(root), first, confirmed=False)
        self.assertFalse((root / ".sigma" / "qualification").exists())
        with self.assertRaisesRegex(WorkspaceError, "SOS_QUALIFICATION_TTY_REQUIRED"):
            admit_qualification_plan(
                str(root), first, confirmed=True, controlling_tty_observed=False
            )
        self.assertFalse((root / ".sigma" / "qualification").exists())
        tampered = dict(first)
        tampered.pop("plan_digest")
        tampered["argv_template"] = ["python", "-c", "pass"]
        tampered["argv_digest"] = "sha256:" + "0" * 64
        tampered = seal_contract(tampered)
        with self.assertRaisesRegex(WorkspaceError, "SOS_QUALIFICATION_PLAN_STALE"):
            admit_qualification_plan(
                str(root), tampered, confirmed=True, controlling_tty_observed=True
            )
        self.assertFalse((root / ".sigma" / "qualification").exists())

    def test_admission_is_unique_expires_and_is_consumed_before_execution(self) -> None:
        temporary, root = self.make_project()
        self.addCleanup(temporary.cleanup)
        issued = datetime(2026, 1, 1, tzinfo=timezone.utc)
        plan = prepare_qualification_plan(str(root), "python.stdlib-unittest")
        with patch("sos.workspace._utc_now", return_value=issued):
            first = admit_qualification_plan(
                str(root),
                plan,
                confirmed=True,
                controlling_tty_observed=True,
                ttl_seconds=5,
            )
            second = admit_qualification_plan(
                str(root),
                plan,
                confirmed=True,
                controlling_tty_observed=True,
                ttl_seconds=5,
            )
        self.assertNotEqual(first["nonce_digest"], second["nonce_digest"])
        with patch("sos.workspace._utc_now", return_value=issued + timedelta(seconds=6)):
            with self.assertRaisesRegex(WorkspaceError, "SOS_QUALIFICATION_ADMISSION_EXPIRED"):
                execute_admitted_qualification(str(root), plan, first)
        first_claim = root / ".sigma" / "qualification" / "claims" / f"{first['admission_id'][7:]}.json"
        self.assertFalse(first_claim.exists())
        with patch("sos.workspace._utc_now", return_value=issued + timedelta(seconds=1)):
            execute_admitted_qualification(str(root), plan, second)
        self.assertTrue(
            (root / ".sigma" / "qualification" / "claims" / f"{second['admission_id'][7:]}.json").is_file()
        )
        with patch("sos.workspace._utc_now", return_value=issued + timedelta(seconds=2)):
            with self.assertRaisesRegex(WorkspaceError, "SOS_QUALIFICATION_ADMISSION_REPLAYED"):
                execute_admitted_qualification(str(root), plan, second)

    def test_source_drift_blocks_before_nonce_consumption(self) -> None:
        temporary, root = self.make_project()
        self.addCleanup(temporary.cleanup)
        issued = datetime(2026, 1, 1, tzinfo=timezone.utc)
        plan = prepare_qualification_plan(str(root), "python.stdlib-unittest")
        with patch("sos.workspace._utc_now", return_value=issued):
            admission = admit_qualification_plan(
                str(root), plan, confirmed=True, controlling_tty_observed=True
            )
        (root / "README.md").write_text("Synthetic source drift.\n", encoding="utf-8")
        with patch("sos.workspace._utc_now", return_value=issued + timedelta(seconds=1)):
            with self.assertRaisesRegex(WorkspaceError, "SOS_QUALIFICATION_STALE"):
                execute_admitted_qualification(str(root), plan, admission)
        claim = root / ".sigma" / "qualification" / "claims" / f"{admission['admission_id'][7:]}.json"
        self.assertFalse(claim.exists())

    def test_source_drift_during_execution_burns_admission_without_green_receipt(self) -> None:
        temporary, root = self.make_project()
        self.addCleanup(temporary.cleanup)
        plan = prepare_qualification_plan(str(root), "python.stdlib-unittest")
        admission = admit_qualification_plan(
            str(root), plan, confirmed=True, controlling_tty_observed=True
        )

        def run_then_drift(
            path: str,
            *,
            family_id: str,
            **binding: object,
        ):
            from sos.checks import _qualify_admitted_supported

            observation = _qualify_admitted_supported(
                path,
                family_id=family_id,
                **binding,
            )
            (root / "README.md").write_text("Synthetic drift during execution.\n", encoding="utf-8")
            return observation

        with patch("sos.workspace._qualify_admitted_supported", side_effect=run_then_drift):
            with self.assertRaisesRegex(WorkspaceError, "SOS_QUALIFICATION_STALE"):
                execute_admitted_qualification(str(root), plan, admission)
        claim = root / ".sigma" / "qualification" / "claims" / f"{admission['admission_id'][7:]}.json"
        self.assertTrue(claim.is_file())
        self.assertFalse((root / ".sigma" / "views" / "qualification.json").exists())

    def test_public_dirty_qualification_cannot_supply_admission_authority(self) -> None:
        temporary, root = self.make_project()
        self.addCleanup(temporary.cleanup)
        (root / "README.md").write_text("Synthetic managed state.\n", encoding="utf-8")

        ordinary = qualify_supported(str(root), family_id="python.stdlib-unittest")
        self.assertEqual(ordinary.status, "blocked")
        with self.assertRaises(TypeError):
            qualify_supported(
                str(root),
                family_id="python.stdlib-unittest",
                admitted_source_binding=object(),  # type: ignore[call-arg]
            )
        qualification_root = root / ".sigma" / "qualification"
        self.assertFalse((qualification_root / "admissions").exists())
        self.assertFalse((qualification_root / "claims").exists())

    def test_receipt_history_is_monotonic_and_rejects_rollback(self) -> None:
        temporary, root = self.make_project()
        self.addCleanup(temporary.cleanup)
        first_time = datetime(2026, 1, 1, tzinfo=timezone.utc)
        with patch("sos.workspace._utc_now", return_value=first_time):
            _, _, first = qualify_once(
                str(root),
                family_id="python.stdlib-unittest",
                confirmed=True,
                controlling_tty_observed=True,
            )
        with patch("sos.workspace._utc_now", return_value=first_time + timedelta(seconds=1)):
            _, _, second = qualify_once(
                str(root),
                family_id="python.stdlib-unittest",
                confirmed=True,
                controlling_tty_observed=True,
            )
        self.assertEqual(first["sequence_ordinal"], 1)
        self.assertIsNone(first["predecessor_receipt"])
        self.assertEqual(second["sequence_ordinal"], 2)
        self.assertEqual(second["predecessor_receipt"], first["receipt_digest"])
        with self.assertRaisesRegex(WorkspaceError, "SOS_QUALIFICATION_RECEIPT_REPLAYED"):
            store_qualification(str(root), first)
        recovery = recover_workspace(str(root))
        self.assertEqual(recovery.status.value, "success")
        self.assertEqual(recovery.details["qualification"]["receipt_digest"], second["receipt_digest"])
        tip_path = root / ".sigma" / "qualification" / "tips" / "00000002.json"
        tip = json.loads(tip_path.read_text(encoding="utf-8"))
        tip["predecessor_receipt"] = None
        tip_path.write_text(json.dumps(tip), encoding="utf-8")
        observed = workspace_status(str(root))
        self.assertEqual(observed.status.value, "invalid")
        self.assertEqual(observed.reasons, ("SOS_CONTROL_PLANE_INTEGRITY_INVALID",))

    def test_successor_source_qualification_does_not_wedge_bootstrap_check_plan(self) -> None:
        temporary, root = self.make_project()
        self.addCleanup(temporary.cleanup)
        bootstrap_plan = json.loads(
            (root / ".sigma" / "checks" / "plan.json").read_text(encoding="utf-8")
        )

        (root / "README.md").write_text(
            "Synthetic qualification project after accepted successor.\n",
            encoding="utf-8",
        )
        git(root, "add", "README.md")
        git(root, "commit", "-qm", "synthetic accepted source successor")
        self.assertEqual(workspace_status(str(root)).status.value, "stale")

        regeneration = regenerate_workspace(
            str(root), confirmed=True, controlling_tty_observed=True
        )
        self.assertEqual(regeneration.status.value, "success")
        for revision in regeneration.details["acceptance_order"]:
            accepted = accept_proposal(
                str(root),
                revision,
                confirmed=True,
                controlling_tty_observed=True,
            )
            self.assertEqual(accepted.status.value, "success", accepted.to_dict())
        self.assertEqual(workspace_status(str(root)).status.value, "success")

        syntax_plan, _syntax_admission, syntax_receipt = qualify_once(
            str(root),
            family_id="python.syntax",
            confirmed=True,
            controlling_tty_observed=True,
        )
        self.assertNotEqual(
            syntax_plan["discovery_plan_digest"],
            bootstrap_plan["plan_digest"],
        )
        self.assertEqual(syntax_receipt["status"], "passed_local")

        status = workspace_status(str(root))
        self.assertEqual(status.status.value, "success", status.to_dict())
        self.assertEqual(status.details["qualification_integrity"], "valid")
        doctor = doctor_workspace(str(root))
        self.assertEqual(doctor.status.value, "success", doctor.to_dict())
        preflight = project_tool(str(root), "sos_preflight")
        self.assertEqual(preflight.status.value, "success", preflight.to_dict())

        _test_plan, _test_admission, test_receipt = qualify_once(
            str(root),
            family_id="python.stdlib-unittest",
            confirmed=True,
            controlling_tty_observed=True,
        )
        self.assertEqual(test_receipt["status"], "passed_local")
        self.assertEqual(test_receipt["sequence_ordinal"], 2)
        self.assertEqual(
            test_receipt["predecessor_receipt"], syntax_receipt["receipt_digest"]
        )
        tip = json.loads(
            (root / ".sigma" / "qualification" / "tips" / "00000002.json").read_text(
                encoding="utf-8"
            )
        )
        self.assertEqual(tip["receipt_digest"], test_receipt["receipt_digest"])
        self.assertEqual(
            json.loads(
                (root / ".sigma" / "views" / "qualification.json").read_text(
                    encoding="utf-8"
                )
            ),
            test_receipt,
        )

    def test_live_discovery_drift_is_non_green_on_recovery_doctor_and_preflight(self) -> None:
        temporary, root = self.make_project()
        self.addCleanup(temporary.cleanup)
        qualify_once(
            str(root),
            family_id="python.syntax",
            confirmed=True,
            controlling_tty_observed=True,
        )
        discovered = discover_checks(str(root))
        drifted = replace(discovered, plan_digest="sha256:" + "f" * 64)

        with patch("sos.workspace.discover_checks", return_value=drifted):
            status = workspace_status(str(root))
            self.assertEqual(status.status.value, "success", status.to_dict())
            self.assertEqual(status.details["qualification_integrity"], "valid_stale")

            recovery = recover_workspace(str(root))
            self.assertEqual(recovery.status.value, "success", recovery.to_dict())
            self.assertEqual(recovery.details["qualification_integrity"], "valid_stale")

            doctor = doctor_workspace(str(root))
            self.assertEqual(doctor.status.value, "stale", doctor.to_dict())
            self.assertEqual(doctor.reasons, ("SOS_QUALIFICATION_STALE",))

            preflight = project_tool(str(root), "sos_preflight")
            self.assertEqual(preflight.status.value, "stale", preflight.to_dict())
            self.assertEqual(preflight.reasons, ("SOS_QUALIFICATION_STALE",))

    def test_foreign_and_validly_resealed_forged_receipts_fail_closed(self) -> None:
        first_temporary, first_root = self.make_project()
        second_temporary, second_root = self.make_project()
        self.addCleanup(first_temporary.cleanup)
        self.addCleanup(second_temporary.cleanup)
        _, _, receipt = qualify_once(
            str(first_root),
            family_id="python.stdlib-unittest",
            confirmed=True,
            controlling_tty_observed=True,
        )
        with self.assertRaisesRegex(WorkspaceError, "SOS_QUALIFICATION_STALE"):
            store_qualification(str(second_root), receipt)
        forged = dict(receipt)
        forged.pop("receipt_digest")
        forged["status"] = "failed"
        forged["reasons"] = ["SOS_QUALIFICATION_FAILED"]
        forged["exit_code"] = 1
        forged = seal_contract(forged)
        with self.assertRaisesRegex(WorkspaceError, "SOS_QUALIFICATION_BINDING_INVALID"):
            store_qualification(str(first_root), forged)

    def test_tampered_immutable_result_invalidates_every_authoritative_read(self) -> None:
        temporary, root = self.make_project()
        self.addCleanup(temporary.cleanup)
        _, _, receipt = qualify_once(
            str(root),
            family_id="python.stdlib-unittest",
            confirmed=True,
            controlling_tty_observed=True,
        )
        result_path = root / ".sigma" / "qualification" / "results" / (
            receipt["execution_result_digest"][7:] + ".json"
        )
        result = json.loads(result_path.read_text(encoding="utf-8"))
        result["status"] = "failed"
        result_path.write_text(json.dumps(result), encoding="utf-8")
        observed = workspace_status(str(root))
        self.assertEqual(observed.status, "invalid")
        self.assertEqual(observed.reasons, ("SOS_CONTROL_PLANE_INTEGRITY_INVALID",))


if __name__ == "__main__":
    unittest.main()
