from __future__ import annotations

import contextlib
import io
import os
import unittest
from importlib import metadata
from pathlib import Path

import sos
from sos import __version__
from sos.cli import main
from sos.mcp import handle_message


EXPECTED_VERSION = "0.1.0a5"


class PublicReleaseContractTests(unittest.TestCase):
    def test_version_is_identical_across_package_cli_and_mcp(self) -> None:
        self.assertEqual(__version__, EXPECTED_VERSION)

        output = io.StringIO()
        with self.assertRaises(SystemExit) as raised, contextlib.redirect_stdout(output):
            main(["--version"])
        self.assertEqual(raised.exception.code, 0)
        self.assertEqual(output.getvalue().strip(), f"sos {EXPECTED_VERSION}")

        response = handle_message(
            {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "initialize",
                "params": {"protocolVersion": "2024-11-05"},
            },
            ".",
        )
        self.assertIsNotNone(response)
        self.assertEqual(response["result"]["serverInfo"]["version"], EXPECTED_VERSION)

        if os.environ.get("SOS_REQUIRE_INSTALLED") == "1":
            repository = Path(__file__).resolve().parents[1]
            imported = Path(sos.__file__).resolve()
            self.assertNotIn(repository, imported.parents)
            self.assertEqual(metadata.version("sigma-operator-stack"), EXPECTED_VERSION)

    def test_public_metadata_and_support_truth_are_frozen(self) -> None:
        root = Path(__file__).resolve().parents[1]
        pyproject = (root / "pyproject.toml").read_text(encoding="utf-8")
        self.assertIn('version = "0.1.0a5"', pyproject)
        self.assertIn('requires-python = ">=3.11,<3.13"', pyproject)
        self.assertIn('license = {text = "Apache-2.0"}', pyproject)
        self.assertIn('requires = ["setuptools==84.0.0"]', pyproject)
        self.assertTrue((root / "LICENSE").is_file())

        release_requirements = (root / "requirements" / "release.txt").read_text(encoding="utf-8")
        for requirement in ("Pillow==12.3.0", "setuptools==84.0.0", "wheel==0.48.0"):
            self.assertIn(requirement, release_requirements)
        self.assertEqual(
            (root / "requirements" / "audit.txt").read_text(encoding="utf-8").strip(),
            "pip-audit==2.10.1",
        )

        public_text = "\n".join(
            (root / path).read_text(encoding="utf-8")
            for path in (
                "README.md",
                "docs/qualification-isolation.md",
                "docs/one-command-codex-lifecycle.md",
            )
        )
        self.assertNotIn("has not been qualified on an external or second server", public_text)
        self.assertIn("Cross-server qualification is specific to the exact release artifact", public_text)
        self.assertNotIn("sigma-operator-stack==0.1.0a1", public_text)
        self.assertIn("docs/install-with-codex.md", public_text)
        self.assertIn("release/current.json", public_text)
        self.assertIn("tag, index, artifact size", public_text)


if __name__ == "__main__":
    unittest.main()
