from __future__ import annotations

import hashlib
import json
import subprocess
import tempfile
import unittest
from pathlib import Path

from sos.cli import main
from sos.repository import RepositoryError, inspect_repository
from sos.transaction import BootstrapPlan, TransactionError, execute_disposable_bootstrap
from sos.validation import validate_repository


def git(root: Path, *args: str) -> None:
    subprocess.run(["git", "-C", str(root), *args], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)


class RepositoryTests(unittest.TestCase):
    def make_repo(self) -> tuple[tempfile.TemporaryDirectory[str], Path]:
        temporary = tempfile.TemporaryDirectory()
        root = Path(temporary.name)
        git(root, "init", "-q")
        git(root, "config", "user.name", "Synthetic Operator")
        git(root, "config", "user.email", "synthetic@example.invalid")
        (root / "README.md").write_text("synthetic\n", encoding="utf-8")
        git(root, "add", "README.md")
        git(root, "commit", "-qm", "synthetic root")
        return temporary, root

    def test_clean_repository(self) -> None:
        temporary, root = self.make_repo()
        self.addCleanup(temporary.cleanup)
        result = inspect_repository(root)
        self.assertEqual(result.application_state, "clean")
        self.assertEqual(result.application_entry_count, 0)
        self.assertEqual(result.control_plane_state, "absent")
        self.assertEqual(result.root, ".")
        self.assertFalse(result.root_path_serialized)

    def test_application_and_control_plane_are_separate(self) -> None:
        temporary, root = self.make_repo()
        self.addCleanup(temporary.cleanup)
        (root / ".sigma").mkdir()
        result = inspect_repository(root)
        self.assertEqual(result.application_state, "clean")
        self.assertEqual(result.control_plane_state, "present_unverified")

    def test_malformed_empty_staging_is_control_plane_collision(self) -> None:
        temporary, root = self.make_repo()
        self.addCleanup(temporary.cleanup)
        (root / ".sigma.init.not-valid").mkdir()
        result = inspect_repository(root)
        self.assertEqual(result.application_state, "clean")
        self.assertEqual(result.staging_roots, ())
        self.assertIn("SOS_CONTROL_PLANE_COLLISION", result.reasons)
        self.assertEqual(validate_repository(str(root)).status, "invalid")

    def test_valid_staging_is_recovery_blocker_not_application_dirty(self) -> None:
        temporary, root = self.make_repo()
        self.addCleanup(temporary.cleanup)
        staging = root / (".sigma.init." + "a" * 64)
        staging.mkdir()
        result = inspect_repository(root)
        self.assertEqual(result.application_state, "clean")
        self.assertEqual(result.staging_roots, (staging.name,))
        self.assertIn("SOS_STAGING_RECOVERY_REQUIRED", result.reasons)

    def test_control_plane_symlink_is_invalid(self) -> None:
        temporary, root = self.make_repo()
        self.addCleanup(temporary.cleanup)
        target = root / "target"
        target.mkdir()
        (root / ".sigma").symlink_to(target, target_is_directory=True)
        result = validate_repository(str(root))
        self.assertEqual(result.status, "invalid")
        self.assertIn("SOS_CONTROL_PLANE_COLLISION", result.reasons)

    def test_non_repository_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaises(RepositoryError):
                inspect_repository(directory)

    def test_missing_repository_path_fails_with_typed_reason(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            missing = Path(directory) / "missing"
            with self.assertRaisesRegex(RepositoryError, "SOS_REPOSITORY_ROOT_NOT_FOUND"):
                inspect_repository(missing)

    def test_unborn_repository_is_not_verified_not_non_repository(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            git(root, "init", "-q")
            inspection = inspect_repository(root)
            self.assertIsNone(inspection.head)
            self.assertIn("SOS_REPOSITORY_UNBORN", inspection.reasons)
            self.assertEqual(validate_repository(str(root)).status, "not_verified")

    def test_cli_status_and_validate(self) -> None:
        temporary, root = self.make_repo()
        self.addCleanup(temporary.cleanup)
        self.assertEqual(main(["status", str(root), "--json"]), 2)
        self.assertEqual(main(["validate", str(root), "--json"]), 0)

    def test_disposable_bootstrap_requires_marker_and_flag(self) -> None:
        temporary, root = self.make_repo()
        self.addCleanup(temporary.cleanup)
        plan = BootstrapPlan("a" * 64, "sha256:" + "b" * 64, "sha256:" + "c" * 64)
        with self.assertRaises(TransactionError):
            execute_disposable_bootstrap(root, plan, {}, allow_disposable=True)
        (root / ".sos-disposable-root").write_text("synthetic\n", encoding="utf-8")
        with self.assertRaises(TransactionError):
            execute_disposable_bootstrap(root, plan, {}, allow_disposable=False)

    def test_disposable_bootstrap_is_atomic_and_not_replayable(self) -> None:
        temporary, root = self.make_repo()
        self.addCleanup(temporary.cleanup)
        (root / ".sos-disposable-root").write_text("synthetic\n", encoding="utf-8")
        plan = BootstrapPlan("a" * 64, "sha256:" + "b" * 64, "sha256:" + "c" * 64)
        target = execute_disposable_bootstrap(root, plan, {"authority": {"synthetic": True}}, allow_disposable=True)
        payload = json.loads((target / "bootstrap.json").read_text(encoding="utf-8"))
        self.assertEqual(payload["plan_digest"], plan.plan_digest)
        with self.assertRaises(TransactionError):
            execute_disposable_bootstrap(root, plan, {}, allow_disposable=True)

    def test_status_digest_is_deterministic(self) -> None:
        temporary, root = self.make_repo()
        self.addCleanup(temporary.cleanup)
        (root / "z.txt").write_text("z", encoding="utf-8")
        first = inspect_repository(root)
        second = inspect_repository(root)
        self.assertEqual(first.application_status_digest, second.application_status_digest)
        self.assertEqual(len(first.application_status_digest), len("sha256:") + hashlib.sha256().digest_size * 2)


if __name__ == "__main__":
    unittest.main()
