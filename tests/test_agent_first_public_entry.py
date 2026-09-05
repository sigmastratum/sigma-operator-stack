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
    "sigma-operator-stack/release/0.1.0a3/release/current.json"
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
            self.assertIn("404", text)
            self.assertIn("410", text)
            self.assertIn("SOS_PUBLIC_RELEASE_DISCOVERY_BLOCKED", text)
            self.assertIn("SOS_PUBLIC_RELEASE_METADATA_INVALID", text)
        self.assertIn("Never infer pointer absence from search results", entry)
        self.assertIn("Only a direct HTTP `404` or `410`", route)

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
            ("linux", "x86_64", "SOS-Linux-0.1.0a3.zip"),
            ("darwin", "arm64", "SOS-macOS-0.1.0a3.tar.gz"),
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


if __name__ == "__main__":
    unittest.main()
