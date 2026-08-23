from __future__ import annotations

import json
import subprocess
import sys
import unittest
from pathlib import Path


class PublicReleaseSurfaceTests(unittest.TestCase):
    def test_repository_content_is_public_safe(self) -> None:
        root = Path(__file__).resolve().parents[1]
        result = self.run_tool(root, "check_public_release.py")
        self.assertEqual(result["status"], "passed", result)

    def test_ci_and_release_workflows_are_fail_closed(self) -> None:
        root = Path(__file__).resolve().parents[1]
        result = self.run_tool(root, "check_workflows.py")
        self.assertEqual(result["status"], "passed", result)

    def run_tool(self, root: Path, name: str) -> dict[str, object]:
        completed = subprocess.run(
            [sys.executable, str(root / "tools" / name), "--repository", str(root)],
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        return json.loads(completed.stdout)


if __name__ == "__main__":
    unittest.main()
