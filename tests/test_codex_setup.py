from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from sos import cli as sos_cli
from sos.client_integration import (
    ClientIntegrationError,
    LauncherBinding,
    codex_setup_status,
    install_codex_setup,
    preview_codex_setup,
    recover_codex_setup,
    remove_client,
    remove_codex_setup,
)
from sos.managed_files import project_managed_file_batch
from sos.workspace import accept_proposal, initialize_workspace, regenerate_workspace, workspace_status


def git(root: Path, *args: str) -> None:
    subprocess.run(
        ["git", "-C", str(root), *args], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE
    )


class CodexFirstSetupTests(unittest.TestCase):
    def test_cli_prints_aggregate_preview_before_confirmation(self) -> None:
        events: list[object] = []
        preview = mock.Mock(status="owner_required")
        preview.to_dict.return_value = {
            "contract": "sos_client_integration_result_v1",
            "status": "owner_required",
            "reasons": ["SOS_CODEX_SETUP_CONFIRMATION_REQUIRED"],
            "details": {"target_count": 2},
        }
        installed = mock.Mock(status="success")
        installed.to_dict.return_value = {
            "contract": "sos_client_integration_result_v1",
            "status": "success",
            "reasons": ["SOS_CODEX_SETUP_INSTALLED"],
            "details": {"target_count": 2},
        }

        def observe_preview(path: str):
            events.append(("preview", path))
            return preview

        def print_result(payload: object, as_json: bool) -> None:
            events.append(("print", payload["status"], as_json))

        def confirm(question: str) -> bool:
            events.append(("confirm", question))
            return True

        def install(path: str, *, confirmed: bool, controlling_tty_observed: bool):
            events.append(("install", path, confirmed, controlling_tty_observed))
            return installed

        synthetic_stdin = mock.Mock()
        synthetic_stdin.isatty.return_value = True
        with (
            mock.patch.object(sos_cli, "preview_codex_setup", side_effect=observe_preview),
            mock.patch.object(sos_cli, "_print", side_effect=print_result),
            mock.patch.object(sos_cli, "_ask_confirmation", side_effect=confirm),
            mock.patch.object(sos_cli, "install_codex_setup", side_effect=install),
            mock.patch.object(sos_cli.sys, "stdin", synthetic_stdin),
        ):
            exit_code = sos_cli.main(["setup", "install", "codex", "/synthetic/project"])

        self.assertEqual(exit_code, 0)
        self.assertEqual(
            events,
            [
                ("preview", "/synthetic/project"),
                ("print", "owner_required", False),
                (
                    "confirm",
                    "Install the SOS project-recovery instructions and Codex MCP adapter?",
                ),
                ("install", "/synthetic/project", True, True),
                ("print", "success", False),
            ],
        )

    def fresh_process(self, root: Path, operation: str) -> dict[str, object]:
        script = """
import json
import sys
from sos.client_integration import (
    LauncherBinding,
    codex_setup_status,
    install_codex_setup,
    recover_codex_setup,
    remove_codex_setup,
)
binding = LauncherBinding(sys.executable, '0.1.0.dev0', 'sha256:' + '1' * 64)
root, operation = sys.argv[1:]
if operation == 'install':
    result = install_codex_setup(
        root, confirmed=True, controlling_tty_observed=True, launcher=binding
    )
elif operation == 'status':
    result = codex_setup_status(root, launcher=binding)
elif operation == 'recover':
    result = recover_codex_setup(root, launcher=binding)
elif operation == 'remove':
    result = remove_codex_setup(
        root, confirmed=True, controlling_tty_observed=True, launcher=binding
    )
else:
    raise SystemExit(9)
print(json.dumps(result.to_dict(), sort_keys=True))
"""
        completed = subprocess.run(
            [sys.executable, "-c", script, str(root), operation],
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        return json.loads(completed.stdout)

    def accept_current_source(self, root: Path) -> None:
        plan = regenerate_workspace(
            str(root), confirmed=True, controlling_tty_observed=True
        )
        self.assertEqual(plan.status, "success")
        for proposal in plan.details["proposals"]:
            accepted = accept_proposal(
                str(root),
                proposal["revision"],
                confirmed=True,
                controlling_tty_observed=True,
            )
            self.assertEqual(accepted.status, "success")
        self.assertEqual(workspace_status(str(root)).status, "success")

    def make_project(
        self, *, agents: bytes | None = b"# Existing project instructions\n", config: bytes | None = None
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
        git(root, "commit", "-qm", "synthetic project")
        result = initialize_workspace(str(root), confirmed=True, controlling_tty_observed=True)
        self.assertEqual(result.status, "success")
        return temporary, root

    def binding(self) -> LauncherBinding:
        return LauncherBinding(
            command=os.fspath(Path(sys.executable)),
            package_version="0.1.0.dev0",
            executable_sha256="sha256:" + "1" * 64,
        )

    def install(self, root: Path):
        return install_codex_setup(
            str(root), confirmed=True, controlling_tty_observed=True, launcher=self.binding()
        )

    def remove(self, root: Path):
        return remove_codex_setup(
            str(root), confirmed=True, controlling_tty_observed=True, launcher=self.binding()
        )

    def manifest(self, root: Path) -> dict[str, object]:
        return json.loads(
            (root / ".sigma" / "integrations" / "codex-first.json").read_text(encoding="utf-8")
        )

    def test_preview_and_tty_gate_write_nothing(self) -> None:
        temporary, root = self.make_project()
        self.addCleanup(temporary.cleanup)
        before = sorted(path.relative_to(root) for path in root.rglob("*"))
        preview = preview_codex_setup(str(root), launcher=self.binding())
        self.assertEqual(preview.status, "owner_required")
        self.assertEqual(preview.reasons, ("SOS_CODEX_SETUP_CONFIRMATION_REQUIRED",))
        self.assertEqual(preview.details["target_count"], 2)
        denied = install_codex_setup(
            str(root), confirmed=True, controlling_tty_observed=False, launcher=self.binding()
        )
        self.assertEqual(denied.reasons, ("SOS_CODEX_SETUP_TTY_REQUIRED",))
        self.assertEqual(before, sorted(path.relative_to(root) for path in root.rglob("*")))

    def test_install_status_and_remove_preserve_both_originals(self) -> None:
        original_agents = b"# Existing project instructions\n"
        original_config = b'model = "synthetic"\n'
        temporary, root = self.make_project(agents=original_agents, config=original_config)
        self.addCleanup(temporary.cleanup)
        sigma_manifest = (root / ".sigma" / "manifest.json").read_bytes()
        installed = self.install(root)
        self.assertEqual(installed.status, "success")
        self.assertEqual(installed.details["batch_state"], "integrated")
        self.assertIn(b"SOS managed project recovery", (root / "AGENTS.md").read_bytes())
        self.assertIn(b"SOS managed Codex MCP", (root / ".codex" / "config.toml").read_bytes())
        self.assertEqual(workspace_status(str(root)).status, "stale")
        self.assertEqual(codex_setup_status(str(root), launcher=self.binding()).status, "success")
        removed = self.remove(root)
        self.assertEqual(removed.status, "success")
        self.assertEqual(removed.details["batch_state"], "rolled_back")
        self.assertEqual((root / "AGENTS.md").read_bytes(), original_agents)
        self.assertEqual((root / ".codex" / "config.toml").read_bytes(), original_config)
        self.assertEqual((root / ".sigma" / "manifest.json").read_bytes(), sigma_manifest)
        current = workspace_status(str(root))
        self.assertEqual(current.status, "stale")
        self.assertIn("SOS_SOURCE_STATUS_CHANGED", current.reasons)

    def test_fresh_process_install_status_and_remove_share_one_batch(self) -> None:
        temporary, root = self.make_project(config=b'model = "synthetic"\n')
        self.addCleanup(temporary.cleanup)
        installed = self.fresh_process(root, "install")
        self.assertEqual(installed["status"], "success")
        self.assertEqual(installed["details"]["batch_state"], "integrated")
        status = self.fresh_process(root, "status")
        self.assertEqual(status["status"], "success")
        self.assertEqual(status["details"]["target_count"], 2)
        removed = self.fresh_process(root, "remove")
        self.assertEqual(removed["status"], "success")
        self.assertEqual(removed["details"]["batch_state"], "rolled_back")
        self.assertEqual((root / "AGENTS.md").read_bytes(), b"# Existing project instructions\n")
        self.assertEqual((root / ".codex" / "config.toml").read_bytes(), b'model = "synthetic"\n')

        help_result = subprocess.run(
            [sys.executable, "-m", "sos", "setup", "--help"],
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        for operation in ("install", "status", "recover", "remove"):
            self.assertIn(operation, help_result.stdout)

    def test_created_targets_are_removed_and_legacy_remove_routes_to_batch(self) -> None:
        temporary, root = self.make_project(agents=None, config=None)
        self.addCleanup(temporary.cleanup)
        self.assertEqual(self.install(root).status, "success")
        removed = remove_client(
            str(root), confirmed=True, controlling_tty_observed=True, launcher=self.binding()
        )
        self.assertEqual(removed.status, "success")
        self.assertFalse((root / "AGENTS.md").exists())
        self.assertFalse((root / ".codex").exists())
        self.assertTrue((root / ".sigma").is_dir())

    def test_second_step_failure_rolls_back_first_and_retry_integrates(self) -> None:
        temporary, root = self.make_project()
        self.addCleanup(temporary.cleanup)
        from sos import client_integration as integration
        with mock.patch.object(
            integration,
            "_replace_target",
            side_effect=ClientIntegrationError("SOS_SYNTHETIC_CONFIG_FAILURE", integration.Status.BLOCKED),
        ):
            failed = self.install(root)
        self.assertEqual(failed.status, "blocked")
        self.assertEqual(failed.reasons, ("SOS_MANAGED_FILE_BATCH_INTEGRATION_INCOMPLETE",))
        recovered = self.fresh_process(root, "recover")
        self.assertEqual(recovered["status"], "success")
        self.assertEqual(recovered["details"]["batch_state"], "rolled_back")
        self.assertEqual((root / "AGENTS.md").read_bytes(), b"# Existing project instructions\n")
        self.assertFalse((root / ".codex").exists())
        projection = project_managed_file_batch(root, self.manifest(root)["batch"])
        self.assertEqual(projection["state"], "rolled_back")
        retry = self.install(root)
        self.assertEqual(retry.status, "stale")
        self.assertIn("SOS_SOURCE_STATUS_CHANGED", retry.reasons)
        self.assertEqual((root / "AGENTS.md").read_bytes(), b"# Existing project instructions\n")
        self.assertFalse((root / ".codex").exists())

    def test_incomplete_rollback_requires_recovery_and_preserves_foreign_drift(self) -> None:
        temporary, root = self.make_project()
        self.addCleanup(temporary.cleanup)
        from sos import client_integration as integration
        with (
            mock.patch.object(
                integration,
                "_replace_target",
                side_effect=ClientIntegrationError("SOS_SYNTHETIC_CONFIG_FAILURE", integration.Status.BLOCKED),
            ),
            mock.patch.object(
                integration,
                "_restore_instruction_target",
                side_effect=ClientIntegrationError("SOS_SYNTHETIC_ROLLBACK_FAILURE", integration.Status.BLOCKED),
            ),
        ):
            failed = self.install(root)
        self.assertEqual(failed.status, "blocked")
        self.assertEqual(failed.reasons, ("SOS_MANAGED_FILE_BATCH_INTEGRATION_INCOMPLETE",))
        status = codex_setup_status(str(root), launcher=self.binding())
        self.assertEqual(status.status, "blocked")
        self.assertTrue(status.details["recovery_required"])
        recovered = recover_codex_setup(str(root), launcher=self.binding())
        self.assertEqual(recovered.status, "success")
        self.assertEqual(recovered.details["batch_state"], "rolled_back")
        retry = self.install(root)
        self.assertEqual(retry.status, "stale")
        self.assertIn("SOS_SOURCE_STATUS_CHANGED", retry.reasons)
        self.accept_current_source(root)
        self.assertEqual(self.install(root).status, "success")
        target = root / "AGENTS.md"
        target.write_bytes(target.read_bytes() + b"# foreign edit\n")
        before = target.read_bytes()
        blocked = self.remove(root)
        self.assertEqual(blocked.status, "stale")
        self.assertEqual(target.read_bytes(), before)

    def test_manifest_is_content_safe_and_batch_is_exact_two_targets(self) -> None:
        temporary, root = self.make_project()
        self.addCleanup(temporary.cleanup)
        self.assertEqual(self.install(root).status, "success")
        manifest = self.manifest(root)
        serialized = json.dumps(manifest, sort_keys=True)
        self.assertNotIn(str(root), serialized)
        self.assertNotIn(str(Path(sys.executable)), serialized)
        self.assertFalse(manifest["raw_content_serialized"])
        self.assertFalse(manifest["absolute_paths_serialized"])
        self.assertEqual(
            [step["target"] for step in manifest["batch"]["steps"]],
            ["AGENTS.md", ".codex/config.toml"],
        )
        self.assertEqual(manifest["batch"]["step_count"], 2)


if __name__ == "__main__":
    unittest.main()
