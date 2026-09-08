from __future__ import annotations

import json
import subprocess
import tempfile
import unittest
from pathlib import Path

import sos.claude_integration as claude

from sos.claude_integration import (
    claude_setup_status,
    install_claude_setup,
    preview_claude_setup,
    recover_claude_setup,
    remove_claude_setup,
)
from sos.client_integration import LauncherBinding
from sos.workspace import initialize_workspace


def git(root: Path, *args: str) -> None:
    subprocess.run(["git", "-C", str(root), *args], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)


class ClaudeSetupTests(unittest.TestCase):
    def make_project(self, *, mcp: bytes | None = None, instructions: bytes | None = None) -> tuple[tempfile.TemporaryDirectory[str], Path]:
        temporary = tempfile.TemporaryDirectory()
        root = Path(temporary.name)
        git(root, "init", "-q")
        git(root, "config", "user.name", "Synthetic Operator")
        git(root, "config", "user.email", "synthetic@example.invalid")
        (root / "README.md").write_text("Synthetic project.\n")
        if mcp is not None:
            (root / ".mcp.json").write_bytes(mcp)
        if instructions is not None:
            (root / "CLAUDE.md").write_bytes(instructions)
        git(root, "add", ".")
        git(root, "commit", "-qm", "synthetic")
        result = initialize_workspace(str(root), confirmed=True, controlling_tty_observed=True)
        self.assertEqual(result.status, "success")
        return temporary, root

    def binding(self) -> LauncherBinding:
        return LauncherBinding("/opt/synthetic/sos-python", "0.2.0a1", "a" * 64)

    def test_clean_preview_refusal_install_status_and_remove(self) -> None:
        temporary, root = self.make_project(); self.addCleanup(temporary.cleanup)
        preview = preview_claude_setup(str(root), launcher=self.binding())
        self.assertEqual(preview.status, "owner_required")
        self.assertFalse((root / "CLAUDE.md").exists())
        refused = install_claude_setup(str(root), confirmed=False, launcher=self.binding())
        self.assertEqual(refused.status, "owner_required")
        self.assertFalse((root / ".mcp.json").exists())
        installed = install_claude_setup(str(root), confirmed=True, controlling_tty_observed=True, launcher=self.binding())
        self.assertEqual(installed.status, "owner_required")
        self.assertIn("SOS_INTERACTIVE_USER_HANDOFF_REQUIRED", installed.reasons)
        self.assertEqual(claude_setup_status(str(root), launcher=self.binding()).status, "owner_required")
        config = json.loads((root / ".mcp.json").read_text())
        self.assertEqual(config["mcpServers"]["sigma_operator_stack"]["type"], "stdio")
        removed = remove_claude_setup(str(root), confirmed=True, controlling_tty_observed=True, launcher=self.binding())
        self.assertEqual(removed.status, "success")
        self.assertFalse((root / "CLAUDE.md").exists())
        self.assertFalse((root / ".mcp.json").exists())
        self.assertTrue((root / ".sigma").is_dir())

    def test_irregular_existing_json_is_restored_byte_exact(self) -> None:
        original = b'{\r\n  "other" : [1,{"nested":[true,false]}],\r\n  "mcpServers" : { "existing" : {"command":"x"} }\r\n}\r\n'
        temporary, root = self.make_project(mcp=original, instructions=b"# Existing\r\n"); self.addCleanup(temporary.cleanup)
        installed = install_claude_setup(str(root), confirmed=True, controlling_tty_observed=True, launcher=self.binding())
        self.assertEqual(installed.status, "owner_required")
        self.assertIn(b"sigma_operator_stack", (root / ".mcp.json").read_bytes())
        removed = remove_claude_setup(str(root), confirmed=True, controlling_tty_observed=True, launcher=self.binding())
        self.assertEqual(removed.status, "success")
        self.assertEqual((root / ".mcp.json").read_bytes(), original)
        self.assertEqual((root / "CLAUDE.md").read_bytes(), b"# Existing\r\n")

    def test_invalid_duplicate_and_collision_fail_closed(self) -> None:
        for payload, reason in (
            (b'{"x":1,"x":2}', "SOS_CLAUDE_CODE_MCP_JSON_INVALID"),
            (b'{"mcpServers":{"sigma_operator_stack":{}}}', "SOS_CLAUDE_CODE_MCP_SERVER_COLLISION"),
        ):
            temporary, root = self.make_project(mcp=payload); self.addCleanup(temporary.cleanup)
            result = install_claude_setup(str(root), confirmed=True, controlling_tty_observed=True, launcher=self.binding())
            self.assertIn(reason, result.reasons)
            self.assertEqual((root / ".mcp.json").read_bytes(), payload)
            self.assertFalse((root / "CLAUDE.md").exists())

    def test_wrong_binding_is_stale_and_recovery_is_idempotent(self) -> None:
        temporary, root = self.make_project(); self.addCleanup(temporary.cleanup)
        install_claude_setup(str(root), confirmed=True, controlling_tty_observed=True, launcher=self.binding())
        wrong = LauncherBinding("/opt/synthetic/other", "0.2.0a1", "b" * 64)
        self.assertEqual(claude_setup_status(str(root), launcher=wrong).status, "stale")
        self.assertEqual(recover_claude_setup(str(root), launcher=self.binding()).status, "owner_required")

    def test_confirmation_digest_and_mode_drift_fail_before_writes(self) -> None:
        temporary, root = self.make_project(instructions=b"# Existing\n")
        self.addCleanup(temporary.cleanup)
        preview = preview_claude_setup(str(root), launcher=self.binding())
        (root / "CLAUDE.md").write_bytes(b"# Changed after preview\n")
        stale = install_claude_setup(
            str(root),
            confirmed=True,
            controlling_tty_observed=True,
            launcher=self.binding(),
            expected_manifest_digest=preview.details["manifest_digest"],
        )
        self.assertEqual(stale.status, "stale")
        self.assertFalse((root / ".mcp.json").exists())
        self.assertFalse((root / ".sigma/integrations/claude-code.json").exists())

        preview = preview_claude_setup(str(root), launcher=self.binding())
        (root / "CLAUDE.md").chmod(0o600)
        mode_stale = install_claude_setup(
            str(root),
            confirmed=True,
            controlling_tty_observed=True,
            launcher=self.binding(),
            expected_manifest_digest=preview.details["manifest_digest"],
        )
        self.assertEqual(mode_stale.status, "stale")
        self.assertFalse((root / ".mcp.json").exists())

    def test_manifest_cannot_redirect_detach_to_an_unrelated_target(self) -> None:
        temporary, root = self.make_project(); self.addCleanup(temporary.cleanup)
        install_claude_setup(
            str(root),
            confirmed=True,
            controlling_tty_observed=True,
            launcher=self.binding(),
        )
        manifest = json.loads(
            (root / ".sigma/integrations/claude-code.json").read_text(encoding="utf-8")
        )
        manifest["plans"][0]["target"] = "README.md"
        with self.assertRaisesRegex(
            claude.ClaudeIntegrationError,
            "SOS_CLAUDE_CODE_SETUP_MANIFEST_INVALID",
        ):
            claude._validate_manifest(manifest)

    def test_fresh_recovery_completes_persisted_remove_prepared(self) -> None:
        temporary, root = self.make_project(); self.addCleanup(temporary.cleanup)
        install_claude_setup(
            str(root),
            confirmed=True,
            controlling_tty_observed=True,
            launcher=self.binding(),
        )
        manifest = claude._read_manifest(root)
        self.assertIsNotNone(manifest)
        claude._write_manifest(root, claude._with_state(manifest, "remove_prepared"))
        recovered = recover_claude_setup(str(root), launcher=self.binding())
        self.assertEqual(recovered.status, "success")
        self.assertIn("SOS_CLAUDE_CODE_SETUP_ROLLBACK_RECOVERED", recovered.reasons)
        self.assertFalse((root / "CLAUDE.md").exists())
        self.assertFalse((root / ".mcp.json").exists())
        self.assertTrue((root / ".sigma").is_dir())

    def test_symlink_and_oversized_json_are_refused_without_target_writes(self) -> None:
        temporary, root = self.make_project(); self.addCleanup(temporary.cleanup)
        external = root / "external-mcp-user.json"
        external.write_text("{}\n", encoding="utf-8")
        (root / ".mcp.json").symlink_to(external)
        result = install_claude_setup(
            str(root),
            confirmed=True,
            controlling_tty_observed=True,
            launcher=self.binding(),
        )
        self.assertNotEqual(result.status, "success")
        self.assertEqual(external.read_text(encoding="utf-8"), "{}\n")
        self.assertFalse((root / "CLAUDE.md").exists())

        with self.assertRaisesRegex(
            claude.ClaudeIntegrationError,
            "SOS_CLAUDE_CODE_MCP_JSON_LIMIT_EXCEEDED",
        ):
            claude._strict_json(b'{"padding":"' + b"x" * claude._MAX_BYTES + b'"}')


if __name__ == "__main__":
    unittest.main()
