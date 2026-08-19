from __future__ import annotations

import hashlib
import json
import subprocess
import tempfile
import unittest
from pathlib import Path

from jsonschema import Draft202012Validator

from sos.managed_files import (
    ManagedFileError,
    build_managed_file_plan,
    record_managed_file_state,
    replay_managed_file_journal,
    require_managed_file_state,
)
from sos.workspace import initialize_workspace, workspace_status


def git(root: Path, *args: str) -> None:
    subprocess.run(["git", "-C", str(root), *args], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)


def digest(payload: bytes) -> str:
    return "sha256:" + hashlib.sha256(payload).hexdigest()


class ManagedFileJournalTests(unittest.TestCase):
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

    def plan(self, repository_id: str, target: str = "AGENTS.md") -> dict:
        before = b"existing\n"
        patch = b"managed\n"
        return build_managed_file_plan(
            journal_id="synthetic-agent",
            repository_id=repository_id,
            target=target,
            patch_kind="append_suffix",
            before_exists=True,
            before_byte_count=len(before),
            before_digest=digest(before),
            patch_byte_count=len(patch),
            patch_digest=digest(patch),
            after_byte_count=len(before + patch),
            after_digest=digest(before + patch),
        )

    def test_two_closed_schemas_are_valid(self) -> None:
        schema_root = Path(__file__).parents[1] / "src" / "sos" / "schemas"
        for name in ("sos-managed-file-plan-v1.schema.json", "sos-managed-file-event-v1.schema.json"):
            Draft202012Validator.check_schema(json.loads((schema_root / name).read_text(encoding="utf-8")))

    def test_exact_four_state_chain_is_append_only_and_content_safe(self) -> None:
        temporary, root, repository_id = self.make_project()
        self.addCleanup(temporary.cleanup)
        plan = self.plan(repository_id)
        predecessor = None
        for ordinal, state in enumerate(("apply_prepared", "applied", "rollback_prepared", "rolled_back"), 1):
            event = record_managed_file_state(root, plan, state)
            self.assertEqual(event["sequence_ordinal"], ordinal)
            self.assertEqual(event["predecessor_event"], predecessor)
            predecessor = event["event_digest"]
        replay = replay_managed_file_journal(root, "synthetic-agent")
        self.assertIsNotNone(replay)
        self.assertEqual(replay["event_count"], 4)
        self.assertEqual(replay["latest"]["state"], "rolled_back")
        self.assertEqual(require_managed_file_state(root, plan, "rolled_back"), replay["latest"])
        serialized = json.dumps(replay, sort_keys=True)
        self.assertNotIn("existing\\n", serialized)
        self.assertNotIn("managed\\n", serialized)
        self.assertNotIn(str(root), serialized)

    def test_repeated_cycle_extends_history_and_invalid_transition_is_blocked(self) -> None:
        temporary, root, repository_id = self.make_project()
        self.addCleanup(temporary.cleanup)
        plan = self.plan(repository_id)
        with self.assertRaisesRegex(ManagedFileError, "SOS_MANAGED_FILE_STATE_TRANSITION_INVALID"):
            record_managed_file_state(root, plan, "applied")
        for _ in range(2):
            for state in ("apply_prepared", "applied", "rollback_prepared", "rolled_back"):
                record_managed_file_state(root, plan, state)
        replay = replay_managed_file_journal(root, "synthetic-agent")
        self.assertEqual(replay["event_count"], 8)

    def test_event_tamper_gap_and_repository_transplant_fail_closed(self) -> None:
        temporary, root, repository_id = self.make_project()
        self.addCleanup(temporary.cleanup)
        plan = self.plan(repository_id)
        record_managed_file_state(root, plan, "apply_prepared")
        record_managed_file_state(root, plan, "applied")
        events = root / ".sigma" / "managed-files" / "journals" / "synthetic-agent"
        second = events / "00000002.json"
        value = json.loads(second.read_text(encoding="utf-8"))
        value["state"] = "rolled_back"
        second.write_text(json.dumps(value), encoding="utf-8")
        with self.assertRaises(ManagedFileError):
            replay_managed_file_journal(root, "synthetic-agent")

        other_temporary, other_root, _ = self.make_project()
        self.addCleanup(other_temporary.cleanup)
        with self.assertRaisesRegex(ManagedFileError, "SOS_MANAGED_FILE_REPOSITORY_MISMATCH"):
            record_managed_file_state(other_root, plan, "apply_prepared")

    def test_target_and_plan_shapes_reject_unsafe_or_inconsistent_values(self) -> None:
        temporary, _root, repository_id = self.make_project()
        self.addCleanup(temporary.cleanup)
        for target in ("/absolute", ".sigma/manifest.json", "../escape", "a/../escape"):
            with self.subTest(target=target), self.assertRaises(ManagedFileError):
                self.plan(repository_id, target)
        with self.assertRaises(ManagedFileError):
            build_managed_file_plan(
                journal_id="synthetic-agent",
                repository_id=repository_id,
                target="AGENTS.md",
                patch_kind="create_file",
                before_exists=False,
                before_byte_count=0,
                before_digest=digest(b""),
                patch_byte_count=1,
                patch_digest=digest(b"x"),
                after_byte_count=2,
                after_digest=digest(b"xy"),
            )


if __name__ == "__main__":
    unittest.main()
