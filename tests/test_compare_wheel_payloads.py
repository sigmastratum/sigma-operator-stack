from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path


class WheelPayloadComparisonTests(unittest.TestCase):
    def _wheel(self, path: Path, payload: bytes, compression: int) -> None:
        with zipfile.ZipFile(path, "w", compression=compression) as archive:
            archive.writestr("pkg/module.py", payload)
            archive.writestr("pkg-1.dist-info/METADATA", b"Name: pkg\nVersion: 1\n")

    def _run(self, rebuilt: Path, staged: Path) -> tuple[int, dict[str, object]]:
        script = Path(__file__).resolve().parents[1] / "tools/compare_wheel_payloads.py"
        result = subprocess.run(
            [sys.executable, str(script), "--rebuilt", str(rebuilt), "--staged", str(staged)],
            text=True,
            stdout=subprocess.PIPE,
        )
        return result.returncode, json.loads(result.stdout)

    def test_container_difference_with_exact_payload_passes(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self._wheel(root / "a.whl", b"value = 1\n", zipfile.ZIP_STORED)
            self._wheel(root / "b.whl", b"value = 1\n", zipfile.ZIP_DEFLATED)
            code, result = self._run(root / "a.whl", root / "b.whl")
            self.assertEqual(code, 0)
            self.assertEqual(result["status"], "passed")
            self.assertEqual(result["payload_digest"], result["staged_payload_digest"])

    def test_payload_drift_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self._wheel(root / "a.whl", b"value = 1\n", zipfile.ZIP_STORED)
            self._wheel(root / "b.whl", b"value = 2\n", zipfile.ZIP_STORED)
            code, result = self._run(root / "a.whl", root / "b.whl")
            self.assertEqual(code, 2)
            self.assertEqual(result["reason"], "SOS_WHEEL_PAYLOAD_MISMATCH")
