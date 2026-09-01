from __future__ import annotations

import hashlib
import json
import unittest
from pathlib import Path

from jsonschema import Draft202012Validator


ROOT = Path(__file__).resolve().parents[1]
SCHEMAS = ROOT / "src/sos/schemas"
FIXTURES = ROOT / "tests/fixtures/agent-first-release"


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
        self.assertIn("no public release pointer is published yet", first_viewport)
        self.assertLess(
            first_viewport.index("demo/recovery-demo.mp4"),
            first_viewport.index("Install SOS in my current project"),
        )
        self.assertGreaterEqual(readme.count("docs/install-with-codex.md"), 1)
        self.assertNotIn("uv tool install", readme)
        self.assertNotIn("preinstalled `uv`", readme)

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
