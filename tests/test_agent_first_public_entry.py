from __future__ import annotations

import hashlib
import json
import subprocess
import sys
import unittest
from pathlib import Path

from jsonschema import Draft202012Validator


ROOT = Path(__file__).resolve().parents[1]
SCHEMAS = ROOT / "src/sos/schemas"
FIXTURES = ROOT / "tests/fixtures/agent-first-release"
POINTER_URL = (
    "https://raw.githubusercontent.com/sigmastratum/"
    "sigma-operator-stack/main/release/current.json"
)


class AgentFirstPublicEntryTests(unittest.TestCase):
    def test_first_viewport_has_one_canonical_agent_route(self) -> None:
        readme = (ROOT / "README.md").read_text(encoding="utf-8")
        first_viewport = "\n".join(readme.splitlines()[:55])
        self.assertIn("Project state for coding agents.", first_viewport)
        self.assertIn("Community alpha", first_viewport)
        self.assertIn("demo/recovery-demo.mp4", first_viewport)
        self.assertIn(
            "Install SOS in my current project. Show me the preview before changing it.",
            first_viewport,
        )
        self.assertIn("docs/install-with-codex.md", first_viewport)
        self.assertIn("INSTALL.md", first_viewport)
        self.assertIn(POINTER_URL, first_viewport)
        self.assertIn("Current installable Community alpha: `0.1.0a5`", first_viewport)
        self.assertIn("Linux is the primary", first_viewport)
        normalized = " ".join(readme.split())
        self.assertIn("unsigned experimental macOS", normalized)
        self.assertIn("Windows 11 x86_64 pending Store lifecycle", normalized)
        self.assertNotIn("/release/0.1.0a3/release/current.json", first_viewport)
        self.assertIn("checked-in release", first_viewport)
        self.assertIn("Release activation is fail closed", readme)
        self.assertLess(
            first_viewport.index("demo/recovery-demo.mp4"),
            first_viewport.index("Install SOS in my current project"),
        )
        self.assertGreaterEqual(readme.count("docs/install-with-codex.md"), 1)
        self.assertNotIn("uv tool install", readme)
        self.assertNotIn("preinstalled `uv`", readme)

    def test_direct_discovery_contract_never_infers_absence_from_search(self) -> None:
        entry = (ROOT / "INSTALL.md").read_text(encoding="utf-8")
        route = (ROOT / "docs/install-with-codex.md").read_text(encoding="utf-8")
        for text in (entry, route):
            self.assertIn(POINTER_URL, text)
            self.assertNotIn("/release/0.1.0a3/release/current.json", text)
            self.assertIn("404", text)
            self.assertIn("410", text)
            self.assertIn("SOS_PUBLIC_RELEASE_DISCOVERY_BLOCKED", text)
            self.assertIn("SOS_PUBLIC_RELEASE_METADATA_INVALID", text)
        self.assertIn("Never infer pointer absence from search results", entry)
        self.assertIn("stable discovery surface", entry)
        self.assertIn("historical GitHub Release assets", " ".join(entry.split()))
        self.assertIn("Only a direct HTTP `404` or `410`", route)

    def test_install_route_has_exactly_one_project_confirmation_layer(self) -> None:
        route = (ROOT / "docs/install-with-codex.md").read_text(encoding="utf-8")
        normalized = " ".join(route.split())
        self.assertIn("must not insert an agent-level approval", normalized)
        self.assertIn("user's single confirmation", normalized)
        self.assertIn("answers the existing launcher prompt", normalized)
        self.assertIn("confirmation layer is a failed onboarding replay", normalized)
        self.assertIn("sos_p106_confirmation_handoff_v1", route)
        self.assertIn("--resume-confirmation-seed", route)
        self.assertIn("--expected-plan-digest", route)
        self.assertIn("refuses any digest drift before prompting", normalized)
        self.assertIn("cannot bypass the controlling-terminal requirement", normalized)
        self.assertIn("resumed route rejects `--yes`", normalized)

    def test_project_trust_and_sandbox_handoffs_remain_fail_closed(self) -> None:
        route = (ROOT / "docs/install-with-codex.md").read_text(encoding="utf-8")
        drill = (ROOT / "docs/agent-first-public-drill.md").read_text(
            encoding="utf-8"
        )
        for text in (route, drill):
            self.assertIn("SOS_INTERACTIVE_USER_HANDOFF_REQUIRED", text)
            self.assertIn("sandbox", text.lower())
        self.assertIn("must not edit Codex's user trust registry", route)
        self.assertIn("Do not inject a global trust override", route)
        self.assertIn("disabled sandboxing", route)
        self.assertIn("Archive delivery on Linux/macOS", " ".join(drill.split()))
        self.assertIn("regenerated unbound plan", drill)

    def test_historical_quickstart_is_not_install_authority(self) -> None:
        historical = (ROOT / "docs/alpha-quickstart.md").read_text(encoding="utf-8")
        self.assertIn("not** public installation authority", historical)
        for forbidden in ("```bash", "uv tool install", "start-sos-alpha --"):
            self.assertNotIn(forbidden, historical)

    def test_public_lifecycle_has_no_manual_dependency_prerequisite(self) -> None:
        lifecycle = (ROOT / "docs/one-command-codex-lifecycle.md").read_text(
            encoding="utf-8"
        )
        self.assertIn("platform launcher", lifecycle)
        self.assertIn("owns bounded acquisition", lifecycle)
        self.assertIn("does not install those dependencies", lifecycle)
        self.assertIn("does not install those dependencies or\nrepair `PATH` manually", lifecycle)
        self.assertNotIn("`uv` and package acquisition are prerequisites", lifecycle)

    def test_installation_maintenance_is_not_blocked_by_unverified_qualification(self) -> None:
        route = (ROOT / "docs/install-with-codex.md").read_text(encoding="utf-8")
        update = (ROOT / "docs/version-update.md").read_text(encoding="utf-8")
        for text in (route, update):
            normalized = " ".join(text.split())
            self.assertIn("same-version update", normalized)
            self.assertIn("public smoke test", normalized)
            self.assertIn("removal preview", normalized)
            self.assertIn("not_verified", text)
            self.assertIn("exact", text)
        self.assertIn("not an SOS MCP mutation tool", route)
        self.assertIn("even when the MCP surface is read-only", route)
        self.assertIn("grants no arbitrary shell authority", " ".join(route.split()))
        self.assertIn("Invalid control-plane integrity", route)

    def test_release_pointer_and_index_are_schema_valid_and_bound(self) -> None:
        pointer_schema = json.loads(
            (SCHEMAS / "sos-public-release-pointer-v1.schema.json").read_text()
        )
        index_schema = json.loads(
            (SCHEMAS / "sos-public-release-index-v1.schema.json").read_text()
        )
        Draft202012Validator.check_schema(pointer_schema)
        Draft202012Validator.check_schema(index_schema)
        pointer = json.loads((FIXTURES / "current.json").read_text())
        index_bytes = (FIXTURES / "sos-release-index-v1.json").read_bytes()
        index = json.loads(index_bytes)
        Draft202012Validator(pointer_schema).validate(pointer)
        Draft202012Validator(index_schema).validate(index)
        self.assertEqual(pointer["index_sha256"], hashlib.sha256(index_bytes).hexdigest())
        for field in ("candidate", "tree", "version", "release_tag"):
            self.assertEqual(pointer[field], index[field])
        linux = next(item for item in index["platforms"] if item["system"] == "linux")
        self.assertEqual(linux["launcher"], "Install-SOS.command")
        self.assertEqual(
            linux["invocation"],
            ["Install-SOS.command", "install", "{project}"],
        )

    def test_checked_in_release_routes_linux_and_macos_without_external_actions(self) -> None:
        tool = ROOT / "tools" / "resolve_agent_first_route.py"
        for system, architecture, filename in (
            ("linux", "x86_64", "SOS-Linux-0.1.0a5.zip"),
            ("darwin", "arm64", "SOS-macOS-0.1.0a5.tar.gz"),
        ):
            with self.subTest(system=system):
                completed = subprocess.run(
                    [
                        sys.executable,
                        str(tool),
                        "--pointer",
                        str(ROOT / "release" / "current.json"),
                        "--index",
                        str(ROOT / "release" / "sos-release-index-v1.json"),
                        "--schemas",
                        str(SCHEMAS),
                        "--system",
                        system,
                        "--architecture",
                        architecture,
                    ],
                    check=False,
                    stdin=subprocess.DEVNULL,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                )
                self.assertEqual(completed.returncode, 0, completed.stderr)
                projection = json.loads(completed.stdout)
                self.assertEqual(projection["status"], "ready")
                self.assertEqual(projection["action"]["kind"], "download_archive")
                self.assertEqual(projection["action"]["archive_filename"], filename)
                binding = projection["action"]["maintenance_binding"]
                self.assertEqual(binding["contract"], "sos_public_maintenance_handoff_v1")
                self.assertEqual(binding["archive_filename"], filename)
                self.assertEqual(binding["platform_launcher"], "Install-SOS.command")
                self.assertEqual(binding["version"], projection["version"])
                self.assertFalse(projection["network_performed"])
                self.assertFalse(projection["mutations_performed"])
                self.assertEqual(projection["provider_calls"], 0)

    def test_invalid_or_ambiguous_release_surfaces_fail_schema(self) -> None:
        schema = json.loads(
            (SCHEMAS / "sos-public-release-index-v1.schema.json").read_text()
        )
        validator = Draft202012Validator(schema)
        index = json.loads((FIXTURES / "sos-release-index-v1.json").read_text())
        admitted = dict(index["platforms"][0])
        admitted.pop("archive_sha256")
        invalid = dict(index)
        invalid["platforms"] = [admitted]
        self.assertTrue(tuple(validator.iter_errors(invalid)))
        unsupported = {
            "architecture": "x86_64",
            "profile_id": "windows-x86_64-unreleased",
            "reason": "SOS_PUBLIC_RELEASE_NOT_AVAILABLE",
            "status": "unsupported",
            "system": "windows",
        }
        unsupported["launcher"] = "SOS-Installer.exe"
        invalid["platforms"] = [unsupported]
        self.assertTrue(tuple(validator.iter_errors(invalid)))

    def test_mcp_and_maintenance_launcher_digests_are_never_compared(self) -> None:
        instructions = (ROOT / "src/sos/client_integration.py").read_text(encoding="utf-8")
        route = (ROOT / "docs/install-with-codex.md").read_text(encoding="utf-8")
        for text in (instructions, route):
            normalized = " ".join(text.split())
            self.assertIn("MCP launcher binding", normalized)
            self.assertIn("maintenance launcher binding", normalized)
            self.assertIn("must never be compared", normalized)
        self.assertIn("new disposable extraction", route)
        self.assertIn("--maintenance-release-binding-json", route)


if __name__ == "__main__":
    unittest.main()
