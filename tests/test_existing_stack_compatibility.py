from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from sos.client_integration import LauncherBinding, remove_codex_setup
from sos.compatibility import compatibility_status, discover_compatibility
from sos.lifecycle import (
    execute_one_command_init,
    prepare_one_command_init,
    preview_one_command_init,
)
from sos.workspace import workspace_status


def git(root: Path, *args: str) -> None:
    subprocess.run(
        ["git", "-C", os.fspath(root), *args],
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )


class ExistingStackCompatibilityTests(unittest.TestCase):
    def make_project(self) -> tuple[tempfile.TemporaryDirectory[str], Path]:
        temporary = tempfile.TemporaryDirectory()
        root = Path(temporary.name)
        git(root, "init", "-q")
        git(root, "config", "user.name", "Synthetic Operator")
        git(root, "config", "user.email", "synthetic@example.invalid")
        (root / "README.md").write_text("Synthetic mature project.\n", encoding="utf-8")
        git(root, "add", ".")
        git(root, "commit", "-qm", "synthetic base")
        return temporary, root

    def binding(self) -> LauncherBinding:
        return LauncherBinding(
            os.fspath(Path(sys.executable)),
            "0.1.0a1",
            "sha256:" + "7" * 64,
        )

    def test_existing_targets_and_nested_agents_are_append_or_preserve(self) -> None:
        temporary, root = self.make_project()
        self.addCleanup(temporary.cleanup)
        (root / "AGENTS.md").write_text("# Foreign instructions\n", encoding="utf-8")
        (root / ".codex").mkdir()
        (root / ".codex" / "config.toml").write_text(
            'model = "synthetic"\n', encoding="utf-8"
        )
        (root / "services" / "api").mkdir(parents=True)
        nested = root / "services" / "api" / "AGENTS.md"
        nested.write_text("# Scoped foreign instructions\n", encoding="utf-8")
        git(root, "add", ".")
        git(root, "commit", "-qm", "add mature control surfaces")

        projection = discover_compatibility(root)
        actions = {item["path"]: item["action"] for item in projection.observations}
        self.assertEqual(projection.status, "success")
        self.assertEqual(projection.primary_authority_id, "agents:AGENTS.md")
        self.assertEqual(actions["AGENTS.md"], "append")
        self.assertEqual(actions[".codex/config.toml"], "append")
        self.assertEqual(actions["services/api/AGENTS.md"], "preserve")
        self.assertEqual(actions[".sigma"], "create")

        plan = prepare_one_command_init(str(root), launcher=self.binding())
        preview = plan.preview()
        managed = {
            item["target"]: item for item in preview.details["compatibility"]["managed_diff"]
        }
        self.assertEqual(managed["AGENTS.md"]["action"], "append")
        self.assertEqual(managed[".codex/config.toml"]["action"], "append")
        for item in managed.values():
            self.assertTrue(item["before_digest"].startswith("sha256:"))
            self.assertTrue(item["patch_digest"].startswith("sha256:"))
            self.assertTrue(item["after_digest"].startswith("sha256:"))
            self.assertTrue(item["plan_digest"].startswith("sha256:"))
            self.assertFalse(item["raw_content_serialized"])
            self.assertFalse(item["absolute_paths_serialized"])
        self.assertNotIn("Foreign instructions", json.dumps(preview.to_dict()))
        self.assertNotIn(os.fspath(root), json.dumps(preview.to_dict()))

    def test_multiple_authorities_require_exact_owner_choice_and_zero_writes(self) -> None:
        temporary, root = self.make_project()
        self.addCleanup(temporary.cleanup)
        (root / "AGENTS.md").write_text("# Foreign instructions\n", encoding="utf-8")
        for relative in (
            "openspec",
            "_bmad",
            ".specify",
            "docs/00-governance",
        ):
            directory = root / relative
            directory.mkdir(parents=True)
            (directory / "authority.md").write_text(
                f"# {relative} authority\n", encoding="utf-8"
            )
        git(root, "add", ".")
        git(root, "commit", "-qm", "add competing authority systems")
        before = self.project_bytes(root)

        result = preview_one_command_init(str(root), launcher=self.binding())

        self.assertEqual(result.status, "owner_required", result.to_dict())
        self.assertEqual(result.reasons, ("SOS_PRIMARY_AUTHORITY_REQUIRED",))
        self.assertEqual(before, self.project_bytes(root))
        self.assertFalse((root / ".sigma").exists())
        ids = {
            item["authority_id"]
            for item in result.details["authority_candidates"]
        }
        self.assertEqual(
            ids,
            {
                "agents:AGENTS.md",
                "openspec:openspec",
                "bmad:_bmad",
                "spec-kit:.specify",
                "governance:docs/00-governance",
            },
        )
        self.assertIn("--primary-authority", result.details["next_action"])

    def test_exact_owner_choice_is_bound_into_plan_and_canonical_record(self) -> None:
        temporary, root = self.make_project()
        self.addCleanup(temporary.cleanup)
        (root / "AGENTS.md").write_text("# Foreign instructions\n", encoding="utf-8")
        (root / "openspec").mkdir()
        (root / "openspec" / "spec.md").write_text("# OpenSpec\n", encoding="utf-8")
        git(root, "add", ".")
        git(root, "commit", "-qm", "add two authorities")

        plan = prepare_one_command_init(
            str(root),
            launcher=self.binding(),
            primary_authority_id="openspec:openspec",
        )
        preview = plan.preview()
        self.assertEqual(
            preview.details["compatibility"]["primary_authority_id"],
            "openspec:openspec",
        )
        result = execute_one_command_init(
            plan,
            confirmed=True,
            controlling_tty_observed=True,
        )
        self.assertEqual(result.status, "success", result.to_dict())
        authority = json.loads(
            (root / ".sigma" / "records" / "authority.json").read_text(
                encoding="utf-8"
            )
        )
        extension = authority["extensions"]["org.sigmastratum.sos"]
        self.assertEqual(extension["primary_authority_id"], "openspec:openspec")
        self.assertEqual(
            extension["compatibility_discovery_digest"],
            plan.compatibility.discovery_digest,
        )
        self.assertEqual(extension["authority_selection_state"], "selected")
        self.assertIn("openspec", extension["authority_paths"])
        self.assertEqual(workspace_status(str(root)).status, "success")

        nested_before = (root / "openspec" / "spec.md").read_bytes()
        removed = remove_codex_setup(
            str(root),
            confirmed=True,
            controlling_tty_observed=True,
            launcher=self.binding(),
        )
        self.assertEqual(removed.status, "success", removed.to_dict())
        self.assertEqual((root / "openspec" / "spec.md").read_bytes(), nested_before)
        self.assertTrue((root / ".sigma").is_dir())

    def test_unknown_owner_choice_fails_closed(self) -> None:
        temporary, root = self.make_project()
        self.addCleanup(temporary.cleanup)
        (root / "AGENTS.md").write_text("# Foreign instructions\n", encoding="utf-8")
        git(root, "add", ".")
        git(root, "commit", "-qm", "add authority")

        result = preview_one_command_init(
            str(root),
            launcher=self.binding(),
            primary_authority_id="governance:invented",
        )
        self.assertEqual(result.status, "invalid", result.to_dict())
        self.assertEqual(result.reasons, ("SOS_PRIMARY_AUTHORITY_INVALID",))
        self.assertFalse((root / ".sigma").exists())

    def test_authority_tree_drift_invalidates_preview_before_managed_write(self) -> None:
        temporary, root = self.make_project()
        self.addCleanup(temporary.cleanup)
        (root / "openspec").mkdir()
        source = root / "openspec" / "spec.md"
        source.write_text("# Initial\n", encoding="utf-8")
        git(root, "add", ".")
        git(root, "commit", "-qm", "add openspec")
        plan = prepare_one_command_init(str(root), launcher=self.binding())
        source.write_text("# Concurrent change\n", encoding="utf-8")

        result = execute_one_command_init(
            plan,
            confirmed=True,
            controlling_tty_observed=True,
        )
        self.assertEqual(result.status, "stale", result.to_dict())
        self.assertEqual(result.reasons, ("SOS_P106_PREVIEW_STALE",))
        self.assertFalse((root / ".sigma").exists())
        self.assertFalse((root / "AGENTS.md").exists())
        self.assertFalse((root / ".codex").exists())

    def test_malformed_config_and_foreign_managed_marker_block(self) -> None:
        for name, payload, reason in (
            ("malformed", b"[broken\n", "SOS_CODEX_CONFIG_INVALID"),
            (
                "marker",
                b"# >>> SOS managed Codex MCP (sos_codex_mcp_v1)\n",
                "SOS_CODEX_SETUP_SERVER_COLLISION",
            ),
        ):
            with self.subTest(name=name):
                temporary, root = self.make_project()
                try:
                    (root / ".codex").mkdir()
                    (root / ".codex" / "config.toml").write_bytes(payload)
                    git(root, "add", ".")
                    git(root, "commit", "-qm", "add invalid config")
                    result = compatibility_status(str(root))
                    self.assertEqual(result.status, "blocked", result.to_dict())
                    self.assertEqual(result.reasons, (reason,))
                    self.assertFalse((root / ".sigma").exists())
                finally:
                    temporary.cleanup()

    def test_symlinked_authority_and_oversized_instruction_fail_closed(self) -> None:
        temporary, root = self.make_project()
        self.addCleanup(temporary.cleanup)
        outside = Path(temporary.name).with_name(Path(temporary.name).name + "-outside")
        outside.mkdir()
        self.addCleanup(lambda: outside.rmdir())
        (root / "openspec").symlink_to(outside, target_is_directory=True)
        symlinked = compatibility_status(str(root))
        self.assertEqual(symlinked.status, "blocked", symlinked.to_dict())
        self.assertEqual(symlinked.reasons, ("SOS_COMPATIBILITY_SYMLINK_BLOCKED",))
        (root / "openspec").unlink()
        (root / "AGENTS.md").write_bytes(b"x" * (1024 * 1024 + 1))
        oversized = compatibility_status(str(root))
        self.assertEqual(oversized.status, "blocked", oversized.to_dict())
        self.assertEqual(
            oversized.reasons,
            ("SOS_COMPATIBILITY_FILE_LIMIT_EXCEEDED",),
        )

    @staticmethod
    def project_bytes(root: Path) -> dict[str, bytes]:
        return {
            path.relative_to(root).as_posix(): path.read_bytes()
            for path in root.rglob("*")
            if path.is_file() and ".git" not in path.relative_to(root).parts
        }


if __name__ == "__main__":
    unittest.main()
