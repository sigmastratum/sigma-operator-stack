from __future__ import annotations

import hashlib
import json
import subprocess
import tempfile
import unittest
from pathlib import Path

from jsonschema import Draft202012Validator

from sos.managed_files import (
    ManagedFileBatchError,
    ManagedFileError,
    build_managed_file_batch,
    build_managed_file_plan,
    coordinate_managed_file_batch,
    project_managed_file_batch,
    recover_managed_file_batch,
    rollback_managed_file_batch,
)
from sos.workspace import initialize_workspace, workspace_status


def git(root: Path, *args: str) -> None:
    subprocess.run(
        ["git", "-C", str(root), *args], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE
    )


def digest(payload: bytes) -> str:
    return "sha256:" + hashlib.sha256(payload).hexdigest()


class SyntheticCrash(BaseException):
    pass


class SyntheticTargets:
    def __init__(self, plans: list[dict]) -> None:
        self.states = {plan["journal_id"]: "before" for plan in plans}
        self.log: list[tuple[str, str]] = []
        self.fail_apply_before_once: str | None = None
        self.crash_apply_after_once: str | None = None
        self.crash_rollback_after_once: str | None = None

    def probe(self, plan: dict) -> str:
        return self.states[plan["journal_id"]]

    def apply(self, plan: dict) -> None:
        journal_id = plan["journal_id"]
        self.log.append(("apply", journal_id))
        if self.fail_apply_before_once == journal_id:
            self.fail_apply_before_once = None
            raise RuntimeError("synthetic apply failure")
        if self.states[journal_id] != "before":
            raise RuntimeError("synthetic apply drift")
        self.states[journal_id] = "after"
        if self.crash_apply_after_once == journal_id:
            self.crash_apply_after_once = None
            raise SyntheticCrash()

    def rollback(self, plan: dict) -> None:
        journal_id = plan["journal_id"]
        self.log.append(("rollback", journal_id))
        if self.states[journal_id] != "after":
            raise RuntimeError("synthetic rollback drift")
        self.states[journal_id] = "before"
        if self.crash_rollback_after_once == journal_id:
            self.crash_rollback_after_once = None
            raise RuntimeError("synthetic rollback interruption")


class ManagedFileBatchTests(unittest.TestCase):
    def make_project(self) -> tuple[tempfile.TemporaryDirectory[str], Path, str]:
        temporary = tempfile.TemporaryDirectory()
        root = Path(temporary.name)
        git(root, "init", "-q")
        git(root, "config", "user.name", "Synthetic Operator")
        git(root, "config", "user.email", "synthetic@example.invalid")
        (root / "README.md").write_text("Synthetic project.\n", encoding="utf-8")
        git(root, "add", ".")
        git(root, "commit", "-qm", "synthetic project")
        result = initialize_workspace(str(root), confirmed=True, controlling_tty_observed=True)
        self.assertEqual(result.status, "success")
        repository_id = workspace_status(str(root)).details["repository_id"]
        return temporary, root, repository_id

    def plans(self, repository_id: str, count: int = 3) -> list[dict]:
        values = []
        for ordinal in range(1, count + 1):
            payload = f"managed-{ordinal}\n".encode()
            values.append(
                build_managed_file_plan(
                    journal_id=f"synthetic-{ordinal}",
                    repository_id=repository_id,
                    target=f"docs/synthetic-{ordinal}.md",
                    patch_kind="create_file",
                    before_exists=False,
                    before_byte_count=0,
                    before_digest=digest(b""),
                    patch_byte_count=len(payload),
                    patch_digest=digest(payload),
                    after_byte_count=len(payload),
                    after_digest=digest(payload),
                )
            )
        return values

    def batch(self, repository_id: str, plans: list[dict]) -> dict:
        return build_managed_file_batch(
            batch_id="synthetic-bootstrap", repository_id=repository_id, plans=plans
        )

    def coordinate(self, root: Path, batch: dict, plans: list[dict], targets: SyntheticTargets) -> dict:
        return coordinate_managed_file_batch(
            root,
            batch,
            plans,
            apply_step=targets.apply,
            rollback_step=targets.rollback,
            probe_step=targets.probe,
        )

    def test_batch_and_projection_schemas_are_closed_content_safe_contracts(self) -> None:
        temporary, root, repository_id = self.make_project()
        self.addCleanup(temporary.cleanup)
        plans = self.plans(repository_id)
        batch = self.batch(repository_id, plans)
        targets = SyntheticTargets(plans)
        projection = self.coordinate(root, batch, plans, targets)
        schema_root = Path(__file__).parents[1] / "src" / "sos" / "schemas"
        pairs = (
            ("sos-managed-file-batch-v1.schema.json", batch),
            ("sos-managed-file-batch-projection-v1.schema.json", projection),
        )
        for name, value in pairs:
            schema = json.loads((schema_root / name).read_text(encoding="utf-8"))
            Draft202012Validator.check_schema(schema)
            Draft202012Validator(schema).validate(value)
            altered = dict(value)
            altered["unexpected"] = True
            self.assertFalse(Draft202012Validator(schema).is_valid(altered))
        serialized = json.dumps({"batch": batch, "projection": projection}, sort_keys=True)
        self.assertNotIn("managed-1\\n", serialized)
        self.assertNotIn(str(root), serialized)

    def test_ordered_apply_idempotent_projection_and_reverse_rollback(self) -> None:
        temporary, root, repository_id = self.make_project()
        self.addCleanup(temporary.cleanup)
        plans = self.plans(repository_id)
        batch = self.batch(repository_id, plans)
        targets = SyntheticTargets(plans)
        self.assertEqual(project_managed_file_batch(root, batch)["state"], "not_started")
        integrated = self.coordinate(root, batch, plans, targets)
        self.assertEqual(integrated["state"], "integrated")
        self.assertEqual(targets.log, [("apply", f"synthetic-{item}") for item in range(1, 4)])
        self.assertEqual(self.coordinate(root, batch, plans, targets), integrated)
        rolled_back = rollback_managed_file_batch(
            root, batch, rollback_step=targets.rollback, probe_step=targets.probe
        )
        self.assertEqual(rolled_back["state"], "rolled_back")
        self.assertEqual(
            targets.log[-3:], [("rollback", f"synthetic-{item}") for item in range(3, 0, -1)]
        )

    def test_apply_failure_rolls_back_completed_steps_and_projects_incomplete(self) -> None:
        temporary, root, repository_id = self.make_project()
        self.addCleanup(temporary.cleanup)
        plans = self.plans(repository_id)
        batch = self.batch(repository_id, plans)
        targets = SyntheticTargets(plans)
        targets.fail_apply_before_once = "synthetic-2"
        with self.assertRaisesRegex(
            ManagedFileBatchError, "SOS_MANAGED_FILE_BATCH_INTEGRATION_INCOMPLETE"
        ) as observed:
            self.coordinate(root, batch, plans, targets)
        self.assertEqual(observed.exception.projection["state"], "integration_incomplete")
        self.assertTrue(observed.exception.projection["recovery_required"])
        projection_schema = json.loads(
            (
                Path(__file__).parents[1]
                / "src"
                / "sos"
                / "schemas"
                / "sos-managed-file-batch-projection-v1.schema.json"
            ).read_text(encoding="utf-8")
        )
        Draft202012Validator(projection_schema).validate(observed.exception.projection)
        self.assertEqual(
            targets.log,
            [("apply", "synthetic-1"), ("apply", "synthetic-2"), ("rollback", "synthetic-1")],
        )
        recovered = recover_managed_file_batch(
            root,
            batch,
            apply_step=targets.apply,
            rollback_step=targets.rollback,
            probe_step=targets.probe,
        )
        self.assertEqual(recovered["state"], "rolled_back")
        self.assertFalse(recovered["recovery_required"])
        self.assertEqual(targets.log[-2:], [("apply", "synthetic-2"), ("rollback", "synthetic-2")])

    def test_crash_after_target_mutation_recovers_in_reverse_order(self) -> None:
        temporary, root, repository_id = self.make_project()
        self.addCleanup(temporary.cleanup)
        plans = self.plans(repository_id)
        batch = self.batch(repository_id, plans)
        targets = SyntheticTargets(plans)
        targets.crash_apply_after_once = "synthetic-2"
        with self.assertRaises(SyntheticCrash):
            self.coordinate(root, batch, plans, targets)
        incomplete = project_managed_file_batch(root, batch)
        self.assertEqual(incomplete["state"], "integration_incomplete")
        recovered = recover_managed_file_batch(
            root,
            batch,
            apply_step=targets.apply,
            rollback_step=targets.rollback,
            probe_step=targets.probe,
        )
        self.assertEqual(recovered["state"], "rolled_back")
        self.assertEqual(
            targets.log[-2:], [("rollback", "synthetic-2"), ("rollback", "synthetic-1")]
        )

    def test_rollback_interruption_is_typed_and_recoverable(self) -> None:
        temporary, root, repository_id = self.make_project()
        self.addCleanup(temporary.cleanup)
        plans = self.plans(repository_id)
        batch = self.batch(repository_id, plans)
        targets = SyntheticTargets(plans)
        self.coordinate(root, batch, plans, targets)
        targets.crash_rollback_after_once = "synthetic-2"
        with self.assertRaisesRegex(
            ManagedFileBatchError, "SOS_MANAGED_FILE_BATCH_INTEGRATION_INCOMPLETE"
        ) as observed:
            rollback_managed_file_batch(
                root, batch, rollback_step=targets.rollback, probe_step=targets.probe
            )
        self.assertEqual(observed.exception.projection["state"], "integration_incomplete")
        recovered = recover_managed_file_batch(
            root,
            batch,
            apply_step=targets.apply,
            rollback_step=targets.rollback,
            probe_step=targets.probe,
        )
        self.assertEqual(recovered["state"], "rolled_back")
        self.assertEqual(targets.log[-1], ("rollback", "synthetic-1"))

    def test_recovery_target_drift_is_typed_and_foreign_state_is_preserved(self) -> None:
        temporary, root, repository_id = self.make_project()
        self.addCleanup(temporary.cleanup)
        plans = self.plans(repository_id)
        batch = self.batch(repository_id, plans)
        targets = SyntheticTargets(plans)
        targets.crash_apply_after_once = "synthetic-2"
        with self.assertRaises(SyntheticCrash):
            self.coordinate(root, batch, plans, targets)
        targets.states["synthetic-2"] = "drift"
        with self.assertRaisesRegex(
            ManagedFileBatchError, "SOS_MANAGED_FILE_BATCH_TARGET_DRIFT"
        ) as observed:
            recover_managed_file_batch(
                root,
                batch,
                apply_step=targets.apply,
                rollback_step=targets.rollback,
                probe_step=targets.probe,
            )
        self.assertEqual(observed.exception.status, "stale")
        self.assertEqual(targets.states["synthetic-2"], "drift")
        self.assertEqual(observed.exception.projection["state"], "integration_incomplete")

    def test_duplicate_limit_transplant_and_missing_plan_fail_closed(self) -> None:
        temporary, root, repository_id = self.make_project()
        self.addCleanup(temporary.cleanup)
        plans = self.plans(repository_id, 2)
        duplicate_payload = b"synthetic duplicate\n"
        duplicate_target = build_managed_file_plan(
            journal_id="synthetic-duplicate",
            repository_id=repository_id,
            target=plans[0]["target"],
            patch_kind="create_file",
            before_exists=False,
            before_byte_count=0,
            before_digest=digest(b""),
            patch_byte_count=len(duplicate_payload),
            patch_digest=digest(duplicate_payload),
            after_byte_count=len(duplicate_payload),
            after_digest=digest(duplicate_payload),
        )
        with self.assertRaises(ManagedFileBatchError):
            self.batch(repository_id, [plans[0], duplicate_target])
        duplicate_journal = build_managed_file_plan(
            journal_id=plans[0]["journal_id"],
            repository_id=repository_id,
            target="docs/different.md",
            patch_kind="create_file",
            before_exists=False,
            before_byte_count=0,
            before_digest=digest(b""),
            patch_byte_count=len(duplicate_payload),
            patch_digest=digest(duplicate_payload),
            after_byte_count=len(duplicate_payload),
            after_digest=digest(duplicate_payload),
        )
        with self.assertRaises(ManagedFileBatchError):
            self.batch(repository_id, [plans[0], duplicate_journal])
        with self.assertRaisesRegex(ManagedFileBatchError, "SOS_MANAGED_FILE_BATCH_LIMIT_EXCEEDED"):
            self.batch(repository_id, self.plans(repository_id, 33))

        batch = self.batch(repository_id, plans)
        targets = SyntheticTargets(plans)
        self.coordinate(root, batch, plans, targets)
        other_temporary, other_root, _ = self.make_project()
        self.addCleanup(other_temporary.cleanup)
        with self.assertRaisesRegex(
            ManagedFileBatchError, "SOS_MANAGED_FILE_BATCH_REPOSITORY_MISMATCH"
        ):
            project_managed_file_batch(other_root, batch)

        missing = (
            root
            / ".sigma"
            / "managed-files"
            / "plans"
            / (plans[0]["plan_digest"].removeprefix("sha256:") + ".json")
        )
        missing.unlink()
        with self.assertRaisesRegex(ManagedFileError, "SOS_MANAGED_FILE_PLAN_MISSING"):
            project_managed_file_batch(root, batch)

    def test_batch_tamper_or_missing_binding_fails_closed(self) -> None:
        for mode in ("tamper", "missing"):
            with self.subTest(mode=mode):
                temporary, root, repository_id = self.make_project()
                self.addCleanup(temporary.cleanup)
                plans = self.plans(repository_id, 2)
                batch = self.batch(repository_id, plans)
                targets = SyntheticTargets(plans)
                self.coordinate(root, batch, plans, targets)
                binding = (
                    root
                    / ".sigma"
                    / "managed-files"
                    / "batches"
                    / "synthetic-bootstrap.json"
                )
                if mode == "tamper":
                    value = json.loads(binding.read_text(encoding="utf-8"))
                    value["batch_digest"] = "sha256:" + "0" * 64
                    binding.write_text(json.dumps(value), encoding="utf-8")
                    expected = "SOS_MANAGED_FILE_BATCH_INVALID"
                else:
                    binding.unlink()
                    expected = "SOS_MANAGED_FILE_BATCH_MANIFEST_MISSING"
                with self.assertRaisesRegex(ManagedFileBatchError, expected):
                    project_managed_file_batch(root, batch)


if __name__ == "__main__":
    unittest.main()
