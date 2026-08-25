from __future__ import annotations

import json
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import sos.workspace as workspace
from sos.contracts import verify_receipt, verify_record
from sos.mcp import handle_message
from sos.workspace import (
    accept_proposal,
    doctor_workspace,
    initialize_workspace,
    qualify_once,
    recover_workspace,
    regenerate_workspace,
    workspace_status,
)


def git(root: Path, *args: str) -> None:
    subprocess.run(["git", "-C", str(root), *args], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)


class SuccessorLifecycleTests(unittest.TestCase):
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
        (root / "tasks" / "current.md").write_text("Synthetic first task.\n", encoding="utf-8")
        (root / "tests").mkdir()
        (root / "tests" / "test_smoke.py").write_text(
            "import unittest\n\nclass Smoke(unittest.TestCase):\n    def test_true(self):\n        self.assertTrue(True)\n",
            encoding="utf-8",
        )
        git(root, "add", ".")
        git(root, "commit", "-qm", "synthetic project")
        result = initialize_workspace(str(root), confirmed=True, controlling_tty_observed=True)
        self.assertEqual(result.status, "success")
        return temporary, root

    def make_stale(self, root: Path, marker: str = "changed") -> None:
        (root / "README.md").write_text(f"Synthetic project {marker}.\n", encoding="utf-8")
        self.assertEqual(workspace_status(str(root)).status, "stale")

    def regenerate(self, root: Path):
        return regenerate_workspace(str(root), confirmed=True, controlling_tty_observed=True)

    def accept(self, root: Path, revision: str):
        return accept_proposal(
            str(root), revision, confirmed=True, controlling_tty_observed=True
        )

    def test_regeneration_is_proposal_only_idempotent_and_content_safe(self) -> None:
        temporary, root = self.make_project()
        self.addCleanup(temporary.cleanup)
        self.make_stale(root)
        before = {
            path.name: path.read_bytes() for path in (root / ".sigma" / "records").glob("*.json")
        }
        first = self.regenerate(root)
        self.assertEqual(first.status, "success")
        self.assertEqual(first.reasons, ("SOS_SUCCESSOR_PROPOSALS_CREATED",))
        self.assertFalse(first.details["accepted_state_modified"])
        self.assertEqual([item["slot"] for item in first.details["proposals"]], ["authority", "policy", "operator-state"])
        for item in first.details["proposals"]:
            proposal = json.loads(
                (root / ".sigma" / "proposals" / f"{item['revision'][7:]}.json").read_text(encoding="utf-8")
            )
            verify_record(proposal)
            self.assertEqual(proposal["lifecycle"], {"declared": "proposal"})
            control = proposal["source_binding"]["source_observation"]["control_plane_state"]
            self.assertEqual(control["integrity_status"], "valid")
            self.assertIsNotNone(control["tree_digest"])
            self.assertIsNotNone(control["accepted_ledger_tip"])
        self.assertEqual(
            before,
            {path.name: path.read_bytes() for path in (root / ".sigma" / "records").glob("*.json")},
        )
        self.assertFalse((root / ".sigma" / "ledger" / "tips").exists())
        second = self.regenerate(root)
        self.assertEqual(second.reasons, ("SOS_REGENERATION_PLAN_EXISTS",))
        self.assertEqual(second.details["plan_id"], first.details["plan_id"])
        serialized = json.dumps(first.to_dict(), sort_keys=True)
        self.assertNotIn(str(root), serialized)
        self.assertNotIn("Synthetic project changed", serialized)

    def test_regeneration_and_acceptance_require_tty(self) -> None:
        temporary, root = self.make_project()
        self.addCleanup(temporary.cleanup)
        self.make_stale(root)
        regeneration = regenerate_workspace(str(root), confirmed=True, controlling_tty_observed=False)
        self.assertEqual(regeneration.status, "owner_required")
        self.assertFalse((root / ".sigma" / "proposals").exists())
        plan = self.regenerate(root)
        revision = plan.details["acceptance_order"][0]
        acceptance = accept_proposal(str(root), revision, confirmed=True, controlling_tty_observed=False)
        self.assertEqual(acceptance.status, "owner_required")
        self.assertFalse((root / ".sigma" / "ledger" / "tips").exists())

    def test_exact_three_step_acceptance_restores_current_state(self) -> None:
        temporary, root = self.make_project()
        self.addCleanup(temporary.cleanup)
        old_records = {
            slot: json.loads(path.read_text(encoding="utf-8"))["revision_id"]
            for slot, path in {
                "authority": root / ".sigma" / "records" / "authority.json",
                "policy": root / ".sigma" / "records" / "policy.json",
                "operator-state": root / ".sigma" / "records" / "operator-state.json",
            }.items()
        }
        self.make_stale(root)
        plan = self.regenerate(root)
        authority, policy, operator = plan.details["acceptance_order"]

        out_of_order = self.accept(root, policy)
        self.assertEqual(out_of_order.status, "stale")
        self.assertEqual(out_of_order.reasons, ("SOS_PROPOSAL_PREDECESSOR_STALE",))

        first = self.accept(root, authority)
        self.assertEqual(first.status, "success")
        self.assertEqual(first.details["workspace_status"], "stale")
        self.assertIn("SOS_SUCCESSOR_SEQUENCE_INCOMPLETE", first.details["workspace_reasons"])
        second = self.accept(root, policy)
        self.assertEqual(second.status, "success")
        self.assertEqual(second.details["workspace_status"], "stale")
        third = self.accept(root, operator)
        self.assertEqual(third.status, "success")
        self.assertEqual(third.details["workspace_status"], "success")
        self.assertEqual(workspace_status(str(root)).status, "success")

        recovery = recover_workspace(str(root))
        self.assertEqual(recovery.status, "success")
        self.assertEqual(recovery.details["authority"]["revision"], authority)
        self.assertNotEqual(recovery.details["authority"]["revision"], old_records["authority"])
        self.assertEqual(len(list((root / ".sigma" / "ledger" / "tips").glob("*.json"))), 3)
        self.assertEqual(len(list((root / ".sigma" / "ledger" / "transitions").glob("*.json"))), 3)
        self.assertEqual(len(list((root / ".sigma" / "records" / "revisions").glob("*.json"))), 3)
        self.assertEqual(len(list((root / ".sigma" / "receipts" / "successors").glob("*.json"))), 3)
        for path in (root / ".sigma" / "receipts" / "successors").glob("*.json"):
            verify_receipt(json.loads(path.read_text(encoding="utf-8")))

        repeated = self.accept(root, authority)
        self.assertEqual(repeated.status, "success")
        self.assertEqual(repeated.reasons, ("SOS_PROPOSAL_ALREADY_ACCEPTED",))

    def test_proposal_source_change_and_tampering_fail_closed(self) -> None:
        temporary, root = self.make_project()
        self.addCleanup(temporary.cleanup)
        self.make_stale(root)
        plan = self.regenerate(root)
        revision = plan.details["acceptance_order"][0]
        (root / "README.md").write_text("Changed after proposal.\n", encoding="utf-8")
        stale = self.accept(root, revision)
        self.assertEqual(stale.status, "stale")
        self.assertEqual(stale.reasons, ("SOS_PROPOSAL_SOURCE_STALE",))
        self.assertFalse((root / ".sigma" / "ledger" / "tips").exists())

        proposal_path = root / ".sigma" / "proposals" / f"{revision[7:]}.json"
        proposal = json.loads(proposal_path.read_text(encoding="utf-8"))
        proposal["payload"]["approved_roots"] = ["docs"]
        proposal_path.write_text(json.dumps(proposal), encoding="utf-8")
        invalid = self.accept(root, revision)
        self.assertEqual(invalid.status, "invalid")
        self.assertEqual(invalid.reasons, ("SOS_PROPOSAL_INVALID",))

    def test_accepted_ledger_corruption_is_invalid_before_source_stale(self) -> None:
        temporary, root = self.make_project()
        self.addCleanup(temporary.cleanup)
        self.make_stale(root)
        plan = self.regenerate(root)
        first = self.accept(root, plan.details["acceptance_order"][0])
        transition_path = root / ".sigma" / "ledger" / "transitions" / f"{first.details['receipt_id'][7:]}.json"
        transition = json.loads(transition_path.read_text(encoding="utf-8"))
        transition["record_slot"] = "policy"
        transition_path.write_text(json.dumps(transition), encoding="utf-8")
        result = workspace_status(str(root))
        self.assertEqual(result.status, "invalid")
        self.assertEqual(result.reasons, ("SOS_CONTROL_PLANE_INTEGRITY_INVALID",))

    def test_interrupted_acceptance_never_advances_the_authoritative_tip(self) -> None:
        temporary, root = self.make_project()
        self.addCleanup(temporary.cleanup)
        self.make_stale(root)
        plan = self.regenerate(root)
        revision = plan.details["acceptance_order"][0]
        original_write = workspace._write_immutable_json

        def interrupt_before_tip(target: Path, relative: str, value: dict[str, object]) -> None:
            if relative.startswith("ledger/tips/"):
                raise workspace.WorkspaceError("SOS_SIMULATED_INTERRUPTION")
            original_write(target, relative, value)

        with mock.patch.object(workspace, "_write_immutable_json", side_effect=interrupt_before_tip):
            interrupted = self.accept(root, revision)
        self.assertEqual(interrupted.status, "invalid")
        self.assertEqual(interrupted.reasons, ("SOS_SIMULATED_INTERRUPTION",))
        self.assertFalse((root / ".sigma" / "ledger" / "tips").exists())
        self.assertEqual(workspace_status(str(root)).status, "stale")

        resumed = self.accept(root, revision)
        self.assertEqual(resumed.status, "success")
        self.assertEqual(resumed.details["accepted_revision"], revision)

    def test_tip_gap_fails_closed(self) -> None:
        temporary, root = self.make_project()
        self.addCleanup(temporary.cleanup)
        self.make_stale(root)
        plan = self.regenerate(root)
        results = [self.accept(root, revision) for revision in plan.details["acceptance_order"]]
        self.assertTrue(all(result.status == "success" for result in results))

        (root / ".sigma" / "ledger" / "tips" / "00000002.json").unlink()
        gap = workspace_status(str(root))
        self.assertEqual(gap.status, "invalid")
        self.assertEqual(gap.reasons, ("SOS_CONTROL_PLANE_INTEGRITY_INVALID",))

    def test_each_numbered_tip_is_bound_to_its_exact_transition(self) -> None:
        temporary, root = self.make_project()
        self.addCleanup(temporary.cleanup)
        self.make_stale(root)
        plan = self.regenerate(root)
        for revision in plan.details["acceptance_order"]:
            self.assertEqual(self.accept(root, revision).status, "success")
        first_tip_path = root / ".sigma" / "ledger" / "tips" / "00000001.json"
        first_tip = json.loads(first_tip_path.read_text(encoding="utf-8"))
        first_tip["receipt_tip"] = json.loads(
            (root / ".sigma" / "ledger" / "tips" / "00000002.json").read_text(encoding="utf-8")
        )["receipt_tip"]
        first_tip = workspace._seal_digest_object(first_tip, "tip_digest")
        first_tip_path.write_text(json.dumps(first_tip), encoding="utf-8")
        result = workspace_status(str(root))
        self.assertEqual(result.status, "invalid")
        self.assertEqual(result.reasons, ("SOS_CONTROL_PLANE_INTEGRITY_INVALID",))

    def test_second_successor_cycle_preserves_history_and_advances_lineage(self) -> None:
        temporary, root = self.make_project()
        self.addCleanup(temporary.cleanup)
        historical_revisions: set[str] = set()
        latest_authority: str | None = None
        for marker in ("first-cycle", "second-cycle"):
            self.make_stale(root, marker)
            plan = self.regenerate(root)
            latest_authority = plan.details["acceptance_order"][0]
            for revision in plan.details["acceptance_order"]:
                historical_revisions.add(revision)
                self.assertEqual(self.accept(root, revision).status, "success")
            self.assertEqual(workspace_status(str(root)).status, "success")

        revision_paths = list((root / ".sigma" / "records" / "revisions").glob("*.json"))
        self.assertEqual(len(revision_paths), 6)
        self.assertEqual({"sha256:" + path.stem for path in revision_paths}, historical_revisions)
        self.assertEqual(len(list((root / ".sigma" / "ledger" / "tips").glob("*.json"))), 6)
        recovery = recover_workspace(str(root))
        self.assertEqual(recovery.status, "success")
        self.assertEqual(recovery.details["authority"]["revision"], latest_authority)

    def test_acceptance_lock_blocks_without_writes(self) -> None:
        temporary, root = self.make_project()
        self.addCleanup(temporary.cleanup)
        self.make_stale(root)
        plan = self.regenerate(root)
        ledger = root / ".sigma" / "ledger"
        ledger.mkdir()
        (ledger / "accept.lock").write_text("synthetic lock\n", encoding="utf-8")
        result = self.accept(root, plan.details["acceptance_order"][0])
        self.assertEqual(result.status, "blocked")
        self.assertEqual(result.reasons, ("SOS_ACCEPTANCE_LOCKED",))
        self.assertFalse((ledger / "tips").exists())

    def test_prior_qualification_is_valid_but_stale_after_successor_cycle(self) -> None:
        temporary, root = self.make_project()
        self.addCleanup(temporary.cleanup)
        _, _, receipt = qualify_once(
            str(root), confirmed=True, controlling_tty_observed=True
        )
        self.make_stale(root)
        plan = self.regenerate(root)
        for revision in plan.details["acceptance_order"]:
            self.assertEqual(self.accept(root, revision).status, "success")
        status = workspace_status(str(root))
        self.assertEqual(status.status, "success")
        self.assertEqual(status.details["qualification_integrity"], "valid_stale")
        doctor = doctor_workspace(str(root))
        self.assertEqual(doctor.status, "stale")
        self.assertEqual(doctor.reasons, ("SOS_QUALIFICATION_STALE",))

    def test_mcp_never_exposes_regenerate_or_accept(self) -> None:
        temporary, root = self.make_project()
        self.addCleanup(temporary.cleanup)
        listed = handle_message({"jsonrpc": "2.0", "id": 1, "method": "tools/list"}, str(root))
        names = [tool["name"] for tool in listed["result"]["tools"]]
        self.assertNotIn("sos_accept", names)
        self.assertNotIn("sos_regenerate", names)


if __name__ == "__main__":
    unittest.main()
