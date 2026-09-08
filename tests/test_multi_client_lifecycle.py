from __future__ import annotations

import subprocess
import tempfile
import unittest
from pathlib import Path

from sos.claude_integration import install_claude_setup, remove_claude_setup
from sos.client_integration import LauncherBinding, install_codex_setup, remove_codex_setup
from sos.lifecycle import execute_one_command_init, prepare_one_command_init
from sos.multi_client_lifecycle import project_package_update
from sos.workspace import initialize_workspace, workspace_status


def git(root: Path, *args: str) -> None:
    subprocess.run(["git", "-C", str(root), *args], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)


class MultiClientLifecycleTests(unittest.TestCase):
    def project(self, initialized: bool = False):
        temporary = tempfile.TemporaryDirectory(); root = Path(temporary.name)
        git(root, "init", "-q"); git(root, "config", "user.name", "Synthetic Operator"); git(root, "config", "user.email", "synthetic@example.invalid")
        (root / "README.md").write_text("Synthetic.\n"); git(root, "add", "."); git(root, "commit", "-qm", "synthetic")
        if initialized:
            self.assertEqual(initialize_workspace(str(root), confirmed=True, controlling_tty_observed=True).status, "success")
        return temporary, root

    def binding(self):
        return LauncherBinding("/opt/synthetic/sos-python", "0.2.0a1", "c" * 64)

    def test_fresh_claude_bootstrap_is_one_plan_and_hands_off(self) -> None:
        temporary, root = self.project(); self.addCleanup(temporary.cleanup)
        plan = prepare_one_command_init(str(root), launcher=self.binding(), client="claude-code", confirmation_seed="1" * 64)
        self.assertEqual(plan.preview().details["managed_targets"], ["CLAUDE.md", ".mcp.json"])
        self.assertEqual(
            plan.preview().details["compatibility"]["contract"],
            "sos_compatibility_projection_v2",
        )
        result = execute_one_command_init(plan, confirmed=True, controlling_tty_observed=True)
        self.assertEqual(result.status, "owner_required")
        self.assertIn("SOS_INTERACTIVE_USER_HANDOFF_REQUIRED", result.reasons)
        self.assertEqual(workspace_status(str(root)).status, "success")
        self.assertTrue((root / ".sigma/integrations/claude-code.json").is_file())

    def test_coexistence_detach_preserves_other_adapter_and_sigma(self) -> None:
        temporary, root = self.project(initialized=True); self.addCleanup(temporary.cleanup)
        codex = install_codex_setup(str(root), confirmed=True, controlling_tty_observed=True, launcher=self.binding(), require_current=False)
        self.assertEqual(codex.status, "success")
        claude = install_claude_setup(str(root), confirmed=True, controlling_tty_observed=True, launcher=self.binding())
        self.assertEqual(claude.status, "owner_required")
        self.assertEqual(remove_claude_setup(str(root), confirmed=True, controlling_tty_observed=True, launcher=self.binding()).status, "success")
        self.assertTrue((root / ".codex/config.toml").is_file())
        install_claude_setup(str(root), confirmed=True, controlling_tty_observed=True, launcher=self.binding())
        self.assertEqual(remove_codex_setup(str(root), confirmed=True, controlling_tty_observed=True, launcher=self.binding()).status, "success")
        self.assertTrue((root / ".mcp.json").is_file())
        self.assertTrue((root / ".sigma").is_dir())

    def test_update_projection_is_client_neutral(self) -> None:
        temporary, root = self.project(initialized=True); self.addCleanup(temporary.cleanup)
        absent = project_package_update(str(root), launcher=self.binding())
        self.assertEqual(absent.status, "not_verified")

        claude = install_claude_setup(
            str(root),
            confirmed=True,
            controlling_tty_observed=True,
            launcher=self.binding(),
        )
        self.assertEqual(claude.status, "owner_required")
        claude_only = project_package_update(str(root), launcher=self.binding())
        self.assertEqual(claude_only.status, "success")
        self.assertEqual(claude_only.details["configuration_state"], "current")
        self.assertEqual(
            claude_only.details["client_bindings"]["codex"]["status"],
            "not_verified",
        )

        install_codex_setup(
            str(root),
            confirmed=True,
            controlling_tty_observed=True,
            launcher=self.binding(),
            require_current=False,
        )
        coexistence = project_package_update(str(root), launcher=self.binding())
        self.assertEqual(coexistence.status, "success")
        self.assertEqual(set(coexistence.details["client_bindings"]), {"codex", "claude-code"})
        successor = LauncherBinding("/opt/synthetic/sos-python-v2", "0.2.0a2", "d" * 64)
        stale = project_package_update(str(root), launcher=successor)
        self.assertEqual(stale.status, "success")
        self.assertEqual(stale.reasons, ("SOS_UPDATE_AVAILABLE",))
        self.assertFalse(stale.details["version_change_allowed"])

        (root / ".sigma/integrations/foreign-client.json").write_text(
            "{}\n", encoding="utf-8"
        )
        unknown = project_package_update(str(root), launcher=self.binding())
        self.assertEqual(unknown.status, "blocked")
        self.assertIn("SOS_INTEGRATION_INVENTORY_UNKNOWN_CLIENT", unknown.reasons)

        codex_temporary, codex_root = self.project(initialized=True)
        self.addCleanup(codex_temporary.cleanup)
        install_codex_setup(
            str(codex_root),
            confirmed=True,
            controlling_tty_observed=True,
            launcher=self.binding(),
            require_current=False,
        )
        codex_only = project_package_update(
            str(codex_root), launcher=self.binding()
        )
        self.assertEqual(codex_only.status, "success")
        self.assertEqual(codex_only.details["configuration_state"], "current")


if __name__ == "__main__": unittest.main()
