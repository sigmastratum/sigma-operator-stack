from __future__ import annotations

import subprocess
import json
import os
import tempfile
import unittest
from pathlib import Path

from sos.atomic_switch import (
    AtomicSwitchError,
    execute_atomic_switch,
    prepare_atomic_switch,
    recover_atomic_switch,
)
from sos.claude_integration import claude_setup_status, install_claude_setup
from sos.client_integration import (
    LauncherBinding,
    codex_setup_status,
    install_codex_setup,
)
from sos.workspace import initialize_workspace


class SyntheticCrash(BaseException):
    pass


def git(root: Path, *args: str) -> None:
    subprocess.run(
        ["git", "-C", str(root), *args],
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )


class AtomicSwitchTests(unittest.TestCase):
    def test_target_drift_before_commit_never_reports_success(self) -> None:
        temporary, root, predecessor = self.project()
        self.addCleanup(temporary.cleanup)
        successor = self.binding("0.1.0a6", "b")
        plan = prepare_atomic_switch(str(root), predecessor=predecessor, successor=successor)
        foreign = b"Synthetic foreign replacement\n"

        def drift(point):
            if point == "before_commit":
                (root / "AGENTS.md").write_bytes(foreign)

        result = execute_atomic_switch(plan, confirmed=True, controlling_tty_observed=True, fault=drift)
        self.assertNotEqual(result.status, "success", result.to_dict())
        self.assertTrue(result.details["recovery_required"])
        self.assertEqual((root / "AGENTS.md").read_bytes(), foreign)
        events = (root / ".sigma/integrations/atomic-switches" / plan.switch_id).glob("[0-9]*.json")
        self.assertNotIn("committed", [json.loads(p.read_text())["state"] for p in events])
        recovered = recover_atomic_switch(str(root), plan.switch_id, predecessor=predecessor, successor=successor)
        self.assertNotEqual(recovered.status, "success")
        self.assertEqual((root / "AGENTS.md").read_bytes(), foreign)

    def test_unknown_adapter_before_preview_and_after_preview_refuses(self) -> None:
        temporary, root, predecessor = self.project()
        self.addCleanup(temporary.cleanup)
        successor = self.binding("0.1.0a6", "b")
        plan = prepare_atomic_switch(str(root), predecessor=predecessor, successor=successor)
        unknown = root / ".sigma/integrations/unknown-client.json"
        unknown.write_text("{}")
        with self.assertRaisesRegex(AtomicSwitchError, "UNKNOWN_CLIENT"):
            prepare_atomic_switch(str(root), predecessor=predecessor, successor=successor)
        result = execute_atomic_switch(plan, confirmed=True, controlling_tty_observed=True)
        self.assertNotEqual(result.status, "success")
        self.assertFalse((root / ".sigma/integrations/atomic-switches").exists())
        self.assertEqual(unknown.read_text(), "{}")
        self.assert_bound(root, predecessor)

    def test_coordinator_metadata_symlink_refuses(self) -> None:
        temporary, root, predecessor = self.project()
        self.addCleanup(temporary.cleanup)
        (root / ".sigma/integrations/atomic-switches").symlink_to(root, target_is_directory=True)
        with self.assertRaisesRegex(AtomicSwitchError, "INVENTORY_INVALID"):
            prepare_atomic_switch(str(root), predecessor=predecessor, successor=self.binding("0.1.0a6", "b"))

    def test_install_and_switch_preserve_modes_under_restrictive_umask(self) -> None:
        previous = os.umask(0o077)
        try:
            temporary, root, predecessor = self.project()
            self.addCleanup(temporary.cleanup)
            modes = {name: (root / name).stat().st_mode & 0o777
                     for name in ("AGENTS.md", ".codex/config.toml", "CLAUDE.md", ".mcp.json")}
            self.assertEqual(modes["CLAUDE.md"], 0o644)
            self.assertEqual(modes[".mcp.json"], 0o644)
            successor = self.binding("0.1.0a6", "b")
            plan = prepare_atomic_switch(str(root), predecessor=predecessor, successor=successor)
            result = execute_atomic_switch(plan, confirmed=True, controlling_tty_observed=True)
            self.assertEqual(result.status, "success", result.to_dict())
            self.assert_bound(root, successor)
            self.assertEqual(modes, {name: (root / name).stat().st_mode & 0o777 for name in modes})
        finally:
            os.umask(previous)

    def binding(self, version: str, marker: str) -> LauncherBinding:
        return LauncherBinding(
            f"/opt/synthetic/sos-python-{marker}", version, marker * 64
        )

    def project(self) -> tuple[tempfile.TemporaryDirectory[str], Path, LauncherBinding]:
        temporary = tempfile.TemporaryDirectory()
        root = Path(temporary.name)
        git(root, "init", "-q")
        git(root, "config", "user.name", "Synthetic Operator")
        git(root, "config", "user.email", "synthetic@example.invalid")
        (root / "README.md").write_text("Synthetic.\n", encoding="utf-8")
        git(root, "add", ".")
        git(root, "commit", "-qm", "synthetic")
        initialized = initialize_workspace(
            str(root), confirmed=True, controlling_tty_observed=True
        )
        self.assertEqual(initialized.status, "success")
        predecessor = self.binding("0.1.0a5", "a")
        codex = install_codex_setup(
            str(root),
            confirmed=True,
            controlling_tty_observed=True,
            launcher=predecessor,
            require_current=False,
        )
        self.assertEqual(codex.status, "success")
        claude = install_claude_setup(
            str(root),
            confirmed=True,
            controlling_tty_observed=True,
            launcher=predecessor,
        )
        self.assertEqual(claude.status, "owner_required")
        return temporary, root, predecessor

    def assert_bound(self, root: Path, binding: LauncherBinding) -> None:
        self.assertEqual(
            codex_setup_status(str(root), launcher=binding).status, "success"
        )
        claude = claude_setup_status(str(root), launcher=binding)
        self.assertEqual(claude.status, "owner_required")
        self.assertIn("SOS_INTERACTIVE_USER_HANDOFF_REQUIRED", claude.reasons)

    def test_one_preview_binds_every_adapter_and_explicit_successor(self) -> None:
        temporary, root, predecessor = self.project()
        self.addCleanup(temporary.cleanup)
        successor = self.binding("0.1.0a6", "b")
        plan = prepare_atomic_switch(
            str(root), predecessor=predecessor, successor=successor
        )
        preview = plan.preview()
        self.assertEqual(preview.status, "owner_required")
        self.assertEqual(preview.details["clients"], ["codex", "claude-code"])
        self.assertTrue(preview.details["one_confirmation"])
        self.assertTrue(preview.details["shared_switch_journal"])
        self.assertEqual(
            preview.details["successor_launcher"]["binding_digest"],
            successor.digest,
        )
        self.assertEqual(preview.details["package_manager_calls"], 0)
        self.assertFalse(
            (root / ".sigma/integrations/atomic-switches").exists()
        )

        no_tty = execute_atomic_switch(
            plan, confirmed=True, controlling_tty_observed=False
        )
        self.assertEqual(no_tty.status, "owner_required")
        self.assertFalse(
            (root / ".sigma/integrations/atomic-switches").exists()
        )

    def test_success_switches_both_clients_and_commits_shared_journal(self) -> None:
        temporary, root, predecessor = self.project()
        self.addCleanup(temporary.cleanup)
        successor = self.binding("0.1.0a6", "b")
        plan = prepare_atomic_switch(
            str(root), predecessor=predecessor, successor=successor
        )
        result = execute_atomic_switch(
            plan, confirmed=True, controlling_tty_observed=True
        )
        self.assertEqual(result.status, "success", result.to_dict())
        self.assertIn("SOS_ATOMIC_ADAPTER_SWITCH_COMMITTED", result.reasons)
        self.assertEqual(result.details["package_manager_calls"], 0)
        self.assert_bound(root, successor)
        events = sorted(
            (root / ".sigma/integrations/atomic-switches" / plan.switch_id).glob(
                "[0-9]*.json"
            )
        )
        self.assertEqual(len(events), 6)

    def test_second_adapter_failure_rolls_first_back(self) -> None:
        temporary, root, predecessor = self.project()
        self.addCleanup(temporary.cleanup)
        successor = self.binding("0.1.0a6", "b")
        plan = prepare_atomic_switch(
            str(root), predecessor=predecessor, successor=successor
        )

        def fail(point: str) -> None:
            if point == "before_client:claude-code":
                raise RuntimeError("synthetic second adapter failure")

        result = execute_atomic_switch(
            plan,
            confirmed=True,
            controlling_tty_observed=True,
            fault=fail,
        )
        self.assertEqual(result.status, "blocked")
        self.assertTrue(result.details["rolled_back"])
        self.assertFalse(result.details["recovery_required"])
        self.assertEqual(result.details["package_manager_calls"], 0)
        self.assert_bound(root, predecessor)

    def test_fresh_recovery_after_crash_starting_second_adapter(self) -> None:
        temporary, root, predecessor = self.project()
        self.addCleanup(temporary.cleanup)
        successor = self.binding("0.1.0a6", "b")
        plan = prepare_atomic_switch(
            str(root), predecessor=predecessor, successor=successor
        )

        def crash(point: str) -> None:
            if point == "before_client:claude-code":
                raise SyntheticCrash()

        with self.assertRaises(SyntheticCrash):
            execute_atomic_switch(
                plan,
                confirmed=True,
                controlling_tty_observed=True,
                fault=crash,
            )
        recovered = recover_atomic_switch(
            str(root),
            plan.switch_id,
            predecessor=predecessor,
            successor=successor,
        )
        self.assertEqual(recovered.status, "success", recovered.to_dict())
        self.assertIn(
            "SOS_ATOMIC_ADAPTER_SWITCH_ROLLBACK_RECOVERED", recovered.reasons
        )
        self.assertTrue(recovered.details["rolled_back"])
        self.assertEqual(recovered.details["package_manager_calls"], 0)
        self.assert_bound(root, predecessor)

    def test_failure_after_second_adapter_remove_restores_both(self) -> None:
        temporary, root, predecessor = self.project()
        self.addCleanup(temporary.cleanup)
        successor = self.binding("0.1.0a6", "b")
        plan = prepare_atomic_switch(
            str(root), predecessor=predecessor, successor=successor
        )

        def fail(point: str) -> None:
            if point == "after_remove:claude-code":
                raise RuntimeError("synthetic failure after second remove")

        result = execute_atomic_switch(
            plan,
            confirmed=True,
            controlling_tty_observed=True,
            fault=fail,
        )
        self.assertEqual(result.status, "blocked")
        self.assertTrue(result.details["rolled_back"])
        self.assert_bound(root, predecessor)

    def test_fresh_recovery_resumes_an_interrupted_rollback(self) -> None:
        temporary, root, predecessor = self.project()
        self.addCleanup(temporary.cleanup)
        successor = self.binding("0.1.0a6", "b")
        plan = prepare_atomic_switch(
            str(root), predecessor=predecessor, successor=successor
        )

        def fail_then_crash_rollback(point: str) -> None:
            if point == "before_client:claude-code":
                raise RuntimeError("synthetic second adapter failure")
            if point == "after_rollback_client:claude-code":
                raise SyntheticCrash()

        with self.assertRaises(SyntheticCrash):
            execute_atomic_switch(
                plan,
                confirmed=True,
                controlling_tty_observed=True,
                fault=fail_then_crash_rollback,
            )
        recovered = recover_atomic_switch(
            str(root),
            plan.switch_id,
            predecessor=predecessor,
            successor=successor,
        )
        self.assertEqual(recovered.status, "success", recovered.to_dict())
        self.assertIn(
            "SOS_ATOMIC_ADAPTER_SWITCH_ROLLBACK_RECOVERED", recovered.reasons
        )
        self.assert_bound(root, predecessor)


if __name__ == "__main__":
    unittest.main()
