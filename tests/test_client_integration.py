from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import tomllib
import unittest
from pathlib import Path
from unittest import mock

from sos.client_integration import (
    ClientIntegrationError,
    LauncherBinding,
    client_status,
    install_client,
    preview_client_install,
    remove_client,
)
from sos.mcp import handle_message
from sos.workspace import initialize_workspace, workspace_status


def git(root: Path, *args: str) -> None:
    subprocess.run(["git", "-C", str(root), *args], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)


class CodexClientIntegrationTests(unittest.TestCase):
    def make_project(self, config: bytes | None = None) -> tuple[tempfile.TemporaryDirectory[str], Path]:
        temporary = tempfile.TemporaryDirectory()
        root = Path(temporary.name)
        git(root, "init", "-q")
        git(root, "config", "user.name", "Synthetic Operator")
        git(root, "config", "user.email", "synthetic@example.invalid")
        (root / "README.md").write_text("Synthetic project.\n", encoding="utf-8")
        if config is not None:
            (root / ".codex").mkdir()
            (root / ".codex" / "config.toml").write_bytes(config)
        git(root, "add", ".")
        git(root, "commit", "-qm", "synthetic project")
        result = initialize_workspace(str(root), confirmed=True, controlling_tty_observed=True)
        self.assertEqual(result.status, "success")
        return temporary, root

    def binding(self, version: str = "0.1.0.dev0") -> LauncherBinding:
        return LauncherBinding(
            command=os.fspath(Path(sys.executable)),
            package_version=version,
            executable_sha256="sha256:" + "1" * 64,
        )

    def install(self, root: Path, binding: LauncherBinding | None = None):
        return install_client(
            str(root),
            confirmed=True,
            controlling_tty_observed=True,
            launcher=binding or self.binding(),
        )

    def remove(self, root: Path, binding: LauncherBinding | None = None):
        return remove_client(
            str(root),
            confirmed=True,
            controlling_tty_observed=True,
            launcher=binding or self.binding(),
        )

    def test_preview_and_tty_gate_write_nothing(self) -> None:
        temporary, root = self.make_project()
        self.addCleanup(temporary.cleanup)
        before = list((root / ".sigma").rglob("*"))
        preview = preview_client_install(str(root), launcher=self.binding())
        self.assertEqual(preview.status, "owner_required")
        self.assertEqual(preview.reasons, ("SOS_CLIENT_INSTALL_CONFIRMATION_REQUIRED",))
        denied = install_client(str(root), confirmed=True, controlling_tty_observed=False, launcher=self.binding())
        self.assertEqual(denied.status, "owner_required")
        self.assertFalse((root / ".codex").exists())
        self.assertEqual(before, list((root / ".sigma").rglob("*")))

    def test_install_binds_exact_project_package_and_read_only_allowlist(self) -> None:
        temporary, root = self.make_project()
        self.addCleanup(temporary.cleanup)
        result = self.install(root)
        self.assertEqual(result.status, "success")
        config = tomllib.loads((root / ".codex" / "config.toml").read_text(encoding="utf-8"))
        server = config["mcp_servers"]["sigma_operator_stack"]
        self.assertEqual(server["command"], os.fspath(Path(sys.executable)))
        self.assertEqual(server["cwd"], os.fspath(root))
        self.assertEqual(server["args"][:4], ["-m", "sos", "mcp", "--root"])
        self.assertEqual(server["args"][4], os.fspath(root))
        self.assertEqual(server["args"][-2:], ["--root", os.fspath(root)])
        self.assertEqual(
            server["enabled_tools"],
            [
                "sos_status",
                "sos_preflight",
                "sos_active_task",
                "sos_next_action",
                "sos_qualification_plan",
                "sos_recover",
                "sos_propose_qualification_receipt",
                "sos_propose_update",
            ],
        )
        self.assertEqual(server["default_tools_approval_mode"], "writes")
        self.assertNotIn("accept", json.dumps(server))
        self.assertNotIn("qualify", json.dumps(server))
        self.assertEqual(client_status(str(root), launcher=self.binding()).status, "success")
        self.assertEqual(workspace_status(str(root)).status, "stale")
        manifest_text = (root / ".sigma" / "integrations" / "codex-mcp.json").read_text(encoding="utf-8")
        self.assertNotIn(os.fspath(root), manifest_text)
        self.assertNotIn(os.fspath(Path(sys.executable)), manifest_text)

    def test_remove_restores_existing_config_byte_for_byte_and_preserves_sigma(self) -> None:
        original = b'model = "synthetic"\n'
        temporary, root = self.make_project(original)
        self.addCleanup(temporary.cleanup)
        sigma_manifest = (root / ".sigma" / "manifest.json").read_bytes()
        self.assertEqual(self.install(root).status, "success")
        self.assertTrue((root / ".codex" / "config.toml").read_bytes().startswith(original))
        removed = self.remove(root)
        self.assertEqual(removed.status, "success")
        self.assertEqual((root / ".codex" / "config.toml").read_bytes(), original)
        self.assertEqual((root / ".sigma" / "manifest.json").read_bytes(), sigma_manifest)
        diff = subprocess.run(
            ["git", "-C", str(root), "diff", "--quiet", "--", ".codex/config.toml"], check=False
        )
        self.assertEqual(diff.returncode, 0)

    def test_remove_deletes_only_created_surface_and_is_idempotent(self) -> None:
        temporary, root = self.make_project()
        self.addCleanup(temporary.cleanup)
        self.assertEqual(self.install(root).status, "success")
        self.assertEqual(self.install(root).reasons, ("SOS_CLIENT_ALREADY_INSTALLED",))
        self.assertEqual(self.remove(root).status, "success")
        self.assertFalse((root / ".codex").exists())
        self.assertTrue((root / ".sigma").is_dir())
        self.assertEqual(self.remove(root).reasons, ("SOS_CLIENT_ALREADY_REMOVED",))

    def test_config_drift_blocks_removal_without_touching_user_edit(self) -> None:
        temporary, root = self.make_project()
        self.addCleanup(temporary.cleanup)
        self.assertEqual(self.install(root).status, "success")
        target = root / ".codex" / "config.toml"
        target.write_bytes(target.read_bytes() + b"# user edit\n")
        before = target.read_bytes()
        status = client_status(str(root), launcher=self.binding())
        self.assertEqual(status.status, "stale")
        removed = self.remove(root)
        self.assertEqual(removed.status, "stale")
        self.assertEqual(target.read_bytes(), before)

    def test_concurrent_install_edits_are_rolled_back_without_overwrite(self) -> None:
        from sos.platforms.linux import LinuxPlatformServices

        for strategy in ("in_place", "atomic_replace"):
            with self.subTest(strategy=strategy):
                original = b'model = "synthetic"\n'
                foreign = f'# concurrent {strategy}\n'.encode()
                temporary, root = self.make_project(original)
                self.addCleanup(temporary.cleanup)
                target = root / ".codex" / "config.toml"
                real_exchange = LinuxPlatformServices._rename_exchange
                injected = False

                def concurrent_exchange(directory, source, destination):
                    nonlocal injected
                    if not injected:
                        injected = True
                        if strategy == "in_place":
                            target.write_bytes(foreign)
                        else:
                            competing = target.with_name("competing.toml")
                            competing.write_bytes(foreign)
                            os.replace(competing, target)
                    return real_exchange(directory, source, destination)

                with mock.patch.object(
                    LinuxPlatformServices,
                    "_rename_exchange",
                    side_effect=concurrent_exchange,
                ):
                    result = self.install(root)
                self.assertTrue(injected)
                self.assertEqual(result.status, "stale")
                self.assertEqual(result.reasons, ("SOS_CLIENT_CONFIG_DRIFT",))
                self.assertEqual(target.read_bytes(), foreign)
                self.assertFalse(any(target.parent.glob(".sos-platform.*")))

    def test_concurrent_remove_edits_are_preserved_without_overwrite_or_delete(self) -> None:
        from sos.platforms.linux import LinuxPlatformServices

        for original in (None, b'model = "synthetic"\n'):
            with self.subTest(original_existed=original is not None):
                temporary, root = self.make_project(original)
                self.addCleanup(temporary.cleanup)
                self.assertEqual(self.install(root).status, "success")
                target = root / ".codex" / "config.toml"
                foreign = b"# concurrent remove edit\n"
                method = "_rename_exchange" if original is not None else "_rename_noreplace"
                real_rename = getattr(LinuxPlatformServices, method)
                injected = False

                def concurrent_rename(*arguments):
                    nonlocal injected
                    if not injected:
                        injected = True
                        target.write_bytes(foreign)
                    return real_rename(*arguments)

                with mock.patch.object(
                    LinuxPlatformServices, method, side_effect=concurrent_rename
                ):
                    result = self.remove(root)
                self.assertTrue(injected)
                self.assertEqual(result.status, "stale")
                self.assertEqual(result.reasons, ("SOS_CLIENT_CONFIG_DRIFT",))
                self.assertEqual(target.read_bytes(), foreign)
                self.assertFalse(any(target.parent.glob(".sos-platform.*")))

    def test_existing_server_and_symlink_fail_closed(self) -> None:
        collision = b'[mcp_servers.sigma_operator_stack]\ncommand = "other"\n'
        temporary, root = self.make_project(collision)
        self.addCleanup(temporary.cleanup)
        result = preview_client_install(str(root), launcher=self.binding())
        self.assertEqual(result.status, "blocked")
        self.assertEqual(result.reasons, ("SOS_CLIENT_SERVER_COLLISION",))

        symlink_project = tempfile.TemporaryDirectory()
        self.addCleanup(symlink_project.cleanup)
        symlink_root = Path(symlink_project.name)
        git(symlink_root, "init", "-q")
        git(symlink_root, "config", "user.name", "Synthetic Operator")
        git(symlink_root, "config", "user.email", "synthetic@example.invalid")
        (symlink_root / "README.md").write_text("Synthetic project.\n", encoding="utf-8")
        (symlink_root / ".codex").mkdir()
        outside = symlink_root / "outside.toml"
        outside.write_text("", encoding="utf-8")
        (symlink_root / ".codex" / "config.toml").symlink_to(outside)
        git(symlink_root, "add", ".")
        git(symlink_root, "commit", "-qm", "synthetic symlink project")
        self.assertEqual(
            initialize_workspace(str(symlink_root), confirmed=True, controlling_tty_observed=True).status,
            "success",
        )
        result = preview_client_install(str(symlink_root), launcher=self.binding())
        self.assertEqual(result.status, "invalid")
        self.assertEqual(result.reasons, ("SOS_CLIENT_CONFIG_INVALID",))
        self.assertEqual(outside.read_text(encoding="utf-8"), "")

    def test_package_drift_is_stale_and_does_not_rewrite_config(self) -> None:
        temporary, root = self.make_project()
        self.addCleanup(temporary.cleanup)
        self.assertEqual(self.install(root).status, "success")
        target = root / ".codex" / "config.toml"
        before = target.read_bytes()
        status = client_status(str(root), launcher=self.binding("0.2.0"))
        self.assertEqual(status.status, "stale")
        self.assertEqual(status.reasons, ("SOS_CLIENT_LAUNCHER_STALE",))
        self.assertEqual(target.read_bytes(), before)
        # Exact managed cleanup remains available after a package upgrade.
        removed = remove_client(
            str(root), confirmed=True, controlling_tty_observed=True, launcher=self.binding("0.2.0")
        )
        self.assertEqual(removed.status, "success")
        self.assertFalse(target.exists())

    def test_interrupted_install_is_recovered_without_duplicate_block(self) -> None:
        temporary, root = self.make_project()
        self.addCleanup(temporary.cleanup)
        from sos import client_integration as integration

        real_write = integration._write_manifest
        calls = 0

        def interrupted(target_root, manifest):
            nonlocal calls
            calls += 1
            if calls == 2:
                raise ClientIntegrationError("SOS_SYNTHETIC_INTERRUPTION", status=integration.Status.BLOCKED)
            return real_write(target_root, manifest)

        with mock.patch.object(integration, "_write_manifest", side_effect=interrupted):
            first = self.install(root)
        self.assertEqual(first.status, "blocked")
        second = self.install(root)
        self.assertEqual(second.reasons, ("SOS_CLIENT_INSTALL_RECOVERED",))
        text = (root / ".codex" / "config.toml").read_text(encoding="utf-8")
        self.assertEqual(text.count("# >>> SOS managed Codex MCP"), 1)

    def test_interrupted_remove_recovers_after_original_is_restored(self) -> None:
        original = b'model = "synthetic"\n'
        temporary, root = self.make_project(original)
        self.addCleanup(temporary.cleanup)
        self.assertEqual(self.install(root).status, "success")
        from sos import client_integration as integration

        real_write = integration._write_manifest
        calls = 0

        def interrupted(target_root, manifest):
            nonlocal calls
            calls += 1
            if calls == 2:
                raise ClientIntegrationError("SOS_SYNTHETIC_INTERRUPTION", status=integration.Status.BLOCKED)
            return real_write(target_root, manifest)

        with mock.patch.object(integration, "_write_manifest", side_effect=interrupted):
            first = self.remove(root)
        self.assertEqual(first.status, "blocked")
        self.assertEqual((root / ".codex" / "config.toml").read_bytes(), original)
        second = self.remove(root)
        self.assertEqual(second.status, "success")
        self.assertEqual(second.reasons, ("SOS_CLIENT_REMOVED",))

    def test_journal_recovers_before_and_after_target_install_boundaries(self) -> None:
        from sos import client_integration as integration

        for boundary in ("before_target", "after_target"):
            with self.subTest(boundary=boundary):
                temporary, root = self.make_project()
                self.addCleanup(temporary.cleanup)
                if boundary == "before_target":
                    with mock.patch.object(
                        integration,
                        "_replace_target",
                        side_effect=ClientIntegrationError("SOS_SYNTHETIC_INTERRUPTION", integration.Status.BLOCKED),
                    ):
                        first = self.install(root)
                    self.assertFalse((root / ".codex" / "config.toml").exists())
                else:
                    real_record = integration.record_managed_file_state
                    interrupted = False

                    def interrupt_applied(target_root, plan, state):
                        nonlocal interrupted
                        if state == "applied" and not interrupted:
                            interrupted = True
                            raise integration.ManagedFileError("SOS_SYNTHETIC_INTERRUPTION", integration.Status.BLOCKED)
                        return real_record(target_root, plan, state)

                    with mock.patch.object(integration, "record_managed_file_state", side_effect=interrupt_applied):
                        first = self.install(root)
                    self.assertTrue((root / ".codex" / "config.toml").exists())
                self.assertEqual(first.status, "blocked")
                before = integration.replay_managed_file_journal(root, integration._JOURNAL_ID)
                self.assertEqual(before["latest"]["state"], "apply_prepared")
                recovered = self.install(root)
                expected_reason = (
                    "SOS_CLIENT_INSTALLED" if boundary == "before_target" else "SOS_CLIENT_INSTALL_RECOVERED"
                )
                self.assertEqual(recovered.reasons, (expected_reason,))
                after = integration.replay_managed_file_journal(root, integration._JOURNAL_ID)
                self.assertEqual(after["event_count"], 2)
                self.assertEqual(after["latest"]["state"], "applied")

    def test_journal_recovers_remove_after_target_restore(self) -> None:
        original = b'model = "synthetic"\n'
        temporary, root = self.make_project(original)
        self.addCleanup(temporary.cleanup)
        self.assertEqual(self.install(root).status, "success")
        from sos import client_integration as integration

        real_record = integration.record_managed_file_state
        interrupted = False

        def interrupt_rolled_back(target_root, plan, state):
            nonlocal interrupted
            if state == "rolled_back" and not interrupted:
                interrupted = True
                raise integration.ManagedFileError("SOS_SYNTHETIC_INTERRUPTION", integration.Status.BLOCKED)
            return real_record(target_root, plan, state)

        with mock.patch.object(integration, "record_managed_file_state", side_effect=interrupt_rolled_back):
            first = self.remove(root)
        self.assertEqual(first.status, "blocked")
        self.assertEqual((root / ".codex" / "config.toml").read_bytes(), original)
        before = integration.replay_managed_file_journal(root, integration._JOURNAL_ID)
        self.assertEqual(before["latest"]["state"], "rollback_prepared")
        self.assertEqual(self.remove(root).status, "success")
        after = integration.replay_managed_file_journal(root, integration._JOURNAL_ID)
        self.assertEqual(after["event_count"], 4)
        self.assertEqual(after["latest"]["state"], "rolled_back")

    def test_journal_corruption_or_tail_deletion_blocks_status_without_touching_target(self) -> None:
        for mode in ("corrupt", "delete_tail"):
            with self.subTest(mode=mode):
                temporary, root = self.make_project()
                self.addCleanup(temporary.cleanup)
                self.assertEqual(self.install(root).status, "success")
                target = root / ".codex" / "config.toml"
                before = target.read_bytes()
                event = root / ".sigma" / "managed-files" / "journals" / "codex-mcp" / "00000002.json"
                if mode == "corrupt":
                    value = json.loads(event.read_text(encoding="utf-8"))
                    value["event_digest"] = "sha256:" + "0" * 64
                    event.write_text(json.dumps(value), encoding="utf-8")
                    expected_reason = "SOS_MANAGED_FILE_EVENT_INVALID"
                else:
                    event.unlink()
                    expected_reason = "SOS_MANAGED_FILE_STATE_MISMATCH"
                result = client_status(str(root), launcher=self.binding())
                self.assertIn(result.status.value, {"invalid", "stale"})
                self.assertEqual(result.reasons, (expected_reason,))
                self.assertEqual(target.read_bytes(), before)

    def test_removed_or_orphaned_journal_never_becomes_not_installed_success(self) -> None:
        for mode in ("removed_tail_missing", "manifest_missing"):
            with self.subTest(mode=mode):
                temporary, root = self.make_project()
                self.addCleanup(temporary.cleanup)
                self.assertEqual(self.install(root).status, "success")
                self.assertEqual(self.remove(root).status, "success")
                if mode == "removed_tail_missing":
                    event = root / ".sigma" / "managed-files" / "journals" / "codex-mcp" / "00000004.json"
                    event.unlink()
                    expected_reason = "SOS_MANAGED_FILE_STATE_MISMATCH"
                else:
                    manifest = root / ".sigma" / "integrations" / "codex-mcp.json"
                    manifest.unlink()
                    expected_reason = "SOS_MANAGED_FILE_MANIFEST_MISSING"
                status = client_status(str(root), launcher=self.binding())
                self.assertIn(status.status.value, {"invalid", "stale"})
                self.assertEqual(status.reasons, (expected_reason,))
                removed = self.remove(root)
                self.assertIn(removed.status.value, {"invalid", "stale"})
                self.assertEqual(removed.reasons, (expected_reason,))

    def test_manifest_tamper_and_unknown_client_fail_closed(self) -> None:
        temporary, root = self.make_project()
        self.addCleanup(temporary.cleanup)
        self.assertEqual(preview_client_install(str(root), "other", launcher=self.binding()).status, "unsupported")
        self.assertEqual(self.install(root).status, "success")
        manifest = root / ".sigma" / "integrations" / "codex-mcp.json"
        value = json.loads(manifest.read_text(encoding="utf-8"))
        value["configured_digest"] = "sha256:" + "0" * 64
        manifest.write_text(json.dumps(value), encoding="utf-8")
        self.assertEqual(client_status(str(root), launcher=self.binding()).status, "invalid")

    def test_mcp_capabilities_are_explicitly_read_only(self) -> None:
        listed = handle_message({"jsonrpc": "2.0", "id": 1, "method": "tools/list"}, ".")
        for tool in listed["result"]["tools"]:
            self.assertEqual(
                tool["annotations"],
                {"readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": False},
            )
            self.assertNotIn(tool["name"], {"accept", "regenerate", "qualify", "shell", "commit", "push", "deploy"})


if __name__ == "__main__":
    unittest.main()
