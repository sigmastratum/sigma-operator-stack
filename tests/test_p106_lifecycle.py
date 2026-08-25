from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from sos.agent_api import project_tool
from sos.client_integration import (
    LauncherBinding,
    codex_setup_status,
    project_codex_package_update,
    remove_codex_setup,
    update_codex_setup,
)
from sos.checks import qualify_supported
from sos.contracts import exclusion_policy_digest
from sos.dirty import observe_application
from sos.isolation import isolation_limits
from sos.lifecycle import (
    execute_one_command_init,
    prepare_one_command_init,
    preview_one_command_init,
    recover_one_command_init,
)
from sos.repository import inspect_repository, repository_identity_contract
from sos.result import Status, TerminalResult
from sos.workspace import qualify_once, workspace_status


def git(root: Path, *args: str) -> None:
    subprocess.run(
        ["git", "-C", os.fspath(root), *args],
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )


class P106LifecycleTests(unittest.TestCase):
    def make_project(
        self,
        *,
        agents: bytes | None = b"# Existing instructions\n",
        config: bytes | None = b"model = \"synthetic\"\n",
    ) -> tuple[tempfile.TemporaryDirectory[str], Path]:
        temporary = tempfile.TemporaryDirectory()
        root = Path(temporary.name)
        git(root, "init", "-q")
        git(root, "config", "user.name", "Synthetic Operator")
        git(root, "config", "user.email", "synthetic@example.invalid")
        (root / "README.md").write_text("Synthetic project.\n", encoding="utf-8")
        if agents is not None:
            (root / "AGENTS.md").write_bytes(agents)
        if config is not None:
            (root / ".codex").mkdir()
            (root / ".codex" / "config.toml").write_bytes(config)
        git(root, "add", ".")
        git(root, "commit", "-qm", "synthetic base")
        return temporary, root

    def binding(self, version: str = "0.1.0.dev0", fill: str = "1") -> LauncherBinding:
        return LauncherBinding(
            os.fspath(Path(sys.executable)), version, "sha256:" + fill * 64
        )

    def test_preview_is_zero_write_and_overlay_matches_actual_for_dirty_matrix(self) -> None:
        temporary, root = self.make_project()
        self.addCleanup(temporary.cleanup)
        (root / "README.md").write_text("staged\n", encoding="utf-8")
        git(root, "add", "README.md")
        (root / "README.md").write_text("unstaged\n", encoding="utf-8")
        (root / "notes.txt").write_text("untracked\n", encoding="utf-8")
        before = {path.relative_to(root): path.read_bytes() for path in root.rglob("*") if path.is_file()}
        plan = prepare_one_command_init(str(root), launcher=self.binding())
        preview = plan.preview()
        after = {path.relative_to(root): path.read_bytes() for path in root.rglob("*") if path.is_file()}
        self.assertEqual(before, after)
        self.assertEqual(preview.status, "owner_required")
        self.assertTrue(preview.details["one_confirmation"])
        self.assertFalse(preview.details["qualification_included"])
        result = execute_one_command_init(
            plan, confirmed=True, controlling_tty_observed=True
        )
        self.assertEqual(result.status, "success", result.to_dict())
        self.assertEqual(
            result.details["application_fingerprint"],
            plan.expected_application_fingerprint,
        )
        self.assertEqual(workspace_status(str(root)).status, "success")
        setup_status = codex_setup_status(str(root), launcher=self.binding())
        self.assertEqual(setup_status.status, "success")
        self.assertEqual(setup_status.details["workspace_currentness_authority"], "sos_status")
        self.assertNotIn("currentness_after_install", setup_status.details)

    def test_fresh_install_is_atomic_idempotent_and_preflight_stays_not_verified(self) -> None:
        temporary, root = self.make_project(agents=None, config=None)
        self.addCleanup(temporary.cleanup)
        plan = prepare_one_command_init(str(root), launcher=self.binding())
        result = execute_one_command_init(
            plan, confirmed=True, controlling_tty_observed=True
        )
        self.assertEqual(result.status, "success", result.to_dict())
        self.assertTrue((root / ".sigma" / "lifecycle" / "p106-install.json").is_file())
        self.assertIn("SOS managed project recovery", (root / "AGENTS.md").read_text())
        config = (root / ".codex" / "config.toml").read_text()
        self.assertIn("sigma_operator_stack", config)
        repeated = preview_one_command_init(str(root), launcher=self.binding())
        self.assertEqual(repeated.status, "success")
        self.assertEqual(repeated.reasons, ("SOS_P106_ALREADY_INSTALLED",))
        preflight = project_tool(str(root), "sos_preflight")
        self.assertEqual(preflight.status, "not_verified")
        self.assertEqual(preflight.details["next_action"], "sos qualify")

    def test_ignored_managed_targets_install_and_remain_digest_verified(self) -> None:
        temporary, root = self.make_project(agents=None, config=None)
        self.addCleanup(temporary.cleanup)
        (root / ".gitignore").write_text("AGENTS.md\n.codex/\n", encoding="utf-8")
        git(root, "add", ".gitignore")
        git(root, "commit", "-qm", "synthetic managed-target ignores")
        ignore_before = (root / ".gitignore").read_bytes()

        plan = prepare_one_command_init(str(root), launcher=self.binding())
        result = execute_one_command_init(
            plan, confirmed=True, controlling_tty_observed=True
        )

        self.assertEqual(result.status, "success", result.to_dict())
        self.assertEqual(
            result.details["application_fingerprint"],
            plan.expected_application_fingerprint,
        )
        self.assertEqual((root / ".gitignore").read_bytes(), ignore_before)
        self.assertEqual(workspace_status(str(root)).status, "success")
        self.assertEqual(
            codex_setup_status(str(root), launcher=self.binding()).status,
            "success",
        )

        config = root / ".codex" / "config.toml"
        config.write_bytes(config.read_bytes() + b"# synthetic drift\n")
        drifted = codex_setup_status(str(root), launcher=self.binding())
        self.assertEqual(drifted.status, "stale")
        self.assertIn("SOS_CODEX_SETUP_TARGET_DRIFT", drifted.reasons)

    def test_managed_dirty_state_requires_admission_and_qualifies_bound_snapshot(self) -> None:
        temporary, root = self.make_project(agents=None, config=None)
        self.addCleanup(temporary.cleanup)
        (root / "pyproject.toml").write_text(
            "[build-system]\nrequires = []\nbuild-backend = 'synthetic.backend'\n",
            encoding="utf-8",
        )
        (root / "tests").mkdir()
        (root / "tasks").mkdir()
        (root / "tasks" / "current.md").write_text(
            "# Synthetic current work\n",
            encoding="utf-8",
        )
        (root / "tests" / "test_synthetic.py").write_text(
            "import unittest\n\n"
            "class Synthetic(unittest.TestCase):\n"
            "    def test_pass(self):\n"
            "        self.assertTrue(True)\n",
            encoding="utf-8",
        )
        git(root, "add", "pyproject.toml", "tasks/current.md", "tests/test_synthetic.py")
        git(root, "commit", "-qm", "add synthetic qualification fixture")

        installed = execute_one_command_init(
            prepare_one_command_init(str(root), launcher=self.binding()),
            confirmed=True,
            controlling_tty_observed=True,
        )
        self.assertEqual(installed.status, "success", installed.to_dict())
        self.assertEqual(inspect_repository(root).application_state, "dirty")

        unadmitted = qualify_supported(str(root), family_id="python.stdlib-unittest")
        self.assertEqual(unadmitted.status, "blocked")
        self.assertEqual(unadmitted.reasons, ("SOS_QUALIFICATION_DIRTY_SOURCE",))
        self.assertEqual(unadmitted.limits, isolation_limits())

        _plan, _admission, receipt = qualify_once(
            str(root),
            family_id="python.stdlib-unittest",
            confirmed=True,
            controlling_tty_observed=True,
        )
        self.assertEqual(receipt["status"], "passed_local")
        preflight = project_tool(str(root), "sos_preflight")
        self.assertEqual(preflight.status, "success", preflight.to_dict())

    def test_crash_after_targets_is_recovered_in_reverse_without_sigma(self) -> None:
        temporary, root = self.make_project()
        self.addCleanup(temporary.cleanup)
        original_agents = (root / "AGENTS.md").read_bytes()
        original_config = (root / ".codex" / "config.toml").read_bytes()
        plan = prepare_one_command_init(str(root), launcher=self.binding())

        def crash(boundary: str) -> None:
            if boundary == "targets_applied":
                raise SystemExit(77)

        with self.assertRaises(SystemExit):
            execute_one_command_init(
                plan,
                confirmed=True,
                controlling_tty_observed=True,
                fault=crash,
            )
        self.assertFalse((root / ".sigma").exists())
        self.assertEqual(len(list(root.glob(".sigma.init.*"))), 1)
        recovered = recover_one_command_init(str(root), launcher=self.binding())
        self.assertEqual(recovered.status, "success", recovered.to_dict())
        self.assertEqual((root / "AGENTS.md").read_bytes(), original_agents)
        self.assertEqual((root / ".codex" / "config.toml").read_bytes(), original_config)
        self.assertFalse(list(root.glob(".sigma.init.*")))

    def test_each_p106_transaction_boundary_is_recoverable(self) -> None:
        for boundary in (
            "staging_created",
            "targets_applied",
            "fingerprint_verified",
            "staging_complete",
            "committed",
        ):
            with self.subTest(boundary=boundary):
                temporary, root = self.make_project()
                try:
                    original_agents = (root / "AGENTS.md").read_bytes()
                    original_config = (root / ".codex" / "config.toml").read_bytes()
                    plan = prepare_one_command_init(str(root), launcher=self.binding())

                    def crash(observed: str) -> None:
                        if observed == boundary:
                            raise SystemExit(78)

                    with self.assertRaises(SystemExit):
                        execute_one_command_init(
                            plan,
                            confirmed=True,
                            controlling_tty_observed=True,
                            fault=crash,
                        )
                    recovered = recover_one_command_init(str(root), launcher=self.binding())
                    self.assertEqual(recovered.status, "success", recovered.to_dict())
                    if boundary == "committed":
                        self.assertTrue((root / ".sigma" / "manifest.json").is_file())
                        self.assertEqual(workspace_status(str(root)).status, "success")
                    else:
                        self.assertFalse((root / ".sigma").exists())
                        self.assertFalse(list(root.glob(".sigma.init.*")))
                        self.assertEqual((root / "AGENTS.md").read_bytes(), original_agents)
                        self.assertEqual((root / ".codex" / "config.toml").read_bytes(), original_config)
                finally:
                    temporary.cleanup()

    def test_recovery_rejects_symlinked_pending_path_without_touching_targets(self) -> None:
        temporary, root = self.make_project()
        self.addCleanup(temporary.cleanup)
        plan = prepare_one_command_init(str(root), launcher=self.binding())

        def crash(boundary: str) -> None:
            if boundary == "targets_applied":
                raise SystemExit(79)

        with self.assertRaises(SystemExit):
            execute_one_command_init(
                plan,
                confirmed=True,
                controlling_tty_observed=True,
                fault=crash,
            )
        staging = next(root.glob(".sigma.init.*"))
        lifecycle = staging / "lifecycle"
        held = staging / "lifecycle-held"
        lifecycle.rename(held)
        lifecycle.symlink_to("lifecycle-held", target_is_directory=True)
        agents_after_crash = (root / "AGENTS.md").read_bytes()
        config_after_crash = (root / ".codex" / "config.toml").read_bytes()

        recovered = recover_one_command_init(str(root), launcher=self.binding())

        self.assertEqual(recovered.status, "invalid", recovered.to_dict())
        self.assertEqual(recovered.reasons, ("SOS_P106_PENDING_INVALID",))
        self.assertEqual((root / "AGENTS.md").read_bytes(), agents_after_crash)
        self.assertEqual((root / ".codex" / "config.toml").read_bytes(), config_after_crash)
        self.assertTrue(staging.exists())

    def test_changed_preview_and_foreign_marker_fail_without_overwrite(self) -> None:
        temporary, root = self.make_project()
        self.addCleanup(temporary.cleanup)
        plan = prepare_one_command_init(str(root), launcher=self.binding())
        (root / "README.md").write_text("concurrent edit\n", encoding="utf-8")
        result = execute_one_command_init(
            plan, confirmed=True, controlling_tty_observed=True
        )
        self.assertEqual(result.status, "stale")
        self.assertIn("SOS_P106_PREVIEW_STALE", result.reasons)
        self.assertFalse((root / ".sigma").exists())
        self.assertFalse(list(root.glob(".sigma.init.*")))

        (root / "AGENTS.md").write_text(
            "<!-- >>> SOS managed project recovery (sos_codex_first_v1) -->\nforeign\n",
            encoding="utf-8",
        )
        blocked = preview_one_command_init(str(root), launcher=self.binding())
        self.assertEqual(blocked.status, "blocked")
        self.assertIn("SOS_CODEX_SETUP_INSTRUCTION_COLLISION", blocked.reasons)

    def test_remove_preserves_sigma_and_local_update_projection_is_proposal_only(self) -> None:
        temporary, root = self.make_project()
        self.addCleanup(temporary.cleanup)
        plan = prepare_one_command_init(str(root), launcher=self.binding())
        installed = execute_one_command_init(
            plan, confirmed=True, controlling_tty_observed=True
        )
        self.assertEqual(installed.status, "success")
        update = project_codex_package_update(str(root), launcher=self.binding("0.1.1", "2"))
        self.assertEqual(update.status, "success")
        self.assertEqual(update.reasons, ("SOS_UPDATE_AVAILABLE",))
        self.assertTrue(update.details["proposal_only"])
        self.assertFalse(update.details["writes_performed"])
        accepted_before = (root / ".sigma" / "records" / "authority.json").read_bytes()
        updated = update_codex_setup(
            str(root),
            confirmed=True,
            controlling_tty_observed=True,
            launcher=self.binding("0.1.1", "2"),
        )
        self.assertEqual(updated.status, "success", updated.to_dict())
        self.assertEqual(
            (root / ".sigma" / "records" / "authority.json").read_bytes(),
            accepted_before,
        )
        self.assertEqual(workspace_status(str(root)).status, "success")
        removed = remove_codex_setup(
            str(root),
            confirmed=True,
            controlling_tty_observed=True,
            launcher=self.binding("0.1.1", "2"),
        )
        self.assertEqual(removed.status, "success", removed.to_dict())
        self.assertTrue((root / ".sigma" / "manifest.json").is_file())
        self.assertEqual(workspace_status(str(root)).status, "stale")

    def test_failed_update_restores_targets_and_retry_completes(self) -> None:
        temporary, root = self.make_project()
        self.addCleanup(temporary.cleanup)
        original_agents = (root / "AGENTS.md").read_bytes()
        original_config = (root / ".codex" / "config.toml").read_bytes()
        installed = execute_one_command_init(
            prepare_one_command_init(str(root), launcher=self.binding()),
            confirmed=True,
            controlling_tty_observed=True,
        )
        self.assertEqual(installed.status, "success")
        accepted_before = (root / ".sigma" / "records" / "authority.json").read_bytes()

        synthetic_failure = TerminalResult(
            "sos_codex_setup_result_v1",
            Status.BLOCKED,
            ("SOS_SYNTHETIC_REINSTALL_FAILURE",),
            {},
        )
        with mock.patch(
            "sos.client_integration.install_codex_setup",
            return_value=synthetic_failure,
        ):
            failed = update_codex_setup(
                str(root),
                confirmed=True,
                controlling_tty_observed=True,
                launcher=self.binding("0.1.1", "2"),
            )

        self.assertEqual(failed.status, "blocked", failed.to_dict())
        self.assertEqual(failed.reasons, ("SOS_CODEX_SETUP_UPDATE_INCOMPLETE",))
        self.assertEqual((root / "AGENTS.md").read_bytes(), original_agents)
        self.assertEqual((root / ".codex" / "config.toml").read_bytes(), original_config)
        self.assertEqual(
            (root / ".sigma" / "records" / "authority.json").read_bytes(),
            accepted_before,
        )

        (root / "README.md").write_text("concurrent source drift\n", encoding="utf-8")
        drifted = update_codex_setup(
            str(root),
            confirmed=True,
            controlling_tty_observed=True,
            launcher=self.binding("0.1.1", "2"),
        )
        self.assertEqual(drifted.status, "stale", drifted.to_dict())
        self.assertEqual(drifted.reasons, ("SOS_SOURCE_STATUS_CHANGED",))
        self.assertEqual((root / "AGENTS.md").read_bytes(), original_agents)
        self.assertEqual((root / ".codex" / "config.toml").read_bytes(), original_config)
        (root / "README.md").write_text("Synthetic project.\n", encoding="utf-8")
        git(root, "update-index", "--refresh")

        retried = update_codex_setup(
            str(root),
            confirmed=True,
            controlling_tty_observed=True,
            launcher=self.binding("0.1.1", "2"),
        )
        self.assertEqual(retried.status, "success", retried.to_dict())
        self.assertEqual(retried.reasons, ("SOS_CODEX_SETUP_UPDATED",))
        self.assertEqual(workspace_status(str(root)).status, "success")
        self.assertEqual(
            (root / ".sigma" / "records" / "authority.json").read_bytes(),
            accepted_before,
        )


if __name__ == "__main__":
    unittest.main()
