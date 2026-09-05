from __future__ import annotations

import hashlib
import json
import subprocess
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path


class ReproducibleReleaseWheelTests(unittest.TestCase):
    def test_exact_candidate_rebuild_is_byte_reproducible(self) -> None:
        repository = Path(__file__).resolve().parents[1]
        candidate = subprocess.run(
            ["git", "-C", str(repository), "rev-parse", "HEAD"],
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        ).stdout.strip()
        script = repository / "tools" / "build_release_wheel.py"
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            results: list[dict[str, object]] = []
            digests: list[str] = []
            for label in ("first", "second"):
                output_dir = root / label
                completed = subprocess.run(
                    [
                        sys.executable,
                        str(script),
                        "--repository",
                        str(repository),
                        "--candidate",
                        candidate,
                        "--output-dir",
                        str(output_dir),
                    ],
                    check=True,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                )
                result = json.loads(completed.stdout)
                wheel = output_dir / str(result["filename"])
                digest = hashlib.sha256(wheel.read_bytes()).hexdigest()
                self.assertEqual(result["candidate"], candidate)
                self.assertEqual(result["sha256"], digest)
                self.assertFalse(result["network_allowed"])
                with zipfile.ZipFile(wheel) as archive:
                    self.assertIn(
                        "sigma_operator_stack-0.1.0a3.dist-info/licenses/LICENSE",
                        archive.namelist(),
                    )
                results.append(result)
                digests.append(digest)

        self.assertEqual(results[0], results[1])
        self.assertEqual(digests[0], digests[1])


if __name__ == "__main__":
    unittest.main()
