from __future__ import annotations

import contextlib
import io
import unittest
from pathlib import Path

from sos import __version__
from sos.cli import main
from sos.mcp import handle_message


EXPECTED_VERSION = "0.1.0a1"


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

    def test_public_metadata_and_support_truth_are_frozen(self) -> None:
        root = Path(__file__).resolve().parents[1]
        pyproject = (root / "pyproject.toml").read_text(encoding="utf-8")
        self.assertIn('version = "0.1.0a1"', pyproject)
        self.assertIn('requires-python = ">=3.11,<3.13"', pyproject)
        self.assertIn('license = {text = "Apache-2.0"}', pyproject)
        self.assertTrue((root / "LICENSE").is_file())

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
        self.assertIn("sigma-operator-stack==0.1.0a1", public_text)


if __name__ == "__main__":
    unittest.main()
