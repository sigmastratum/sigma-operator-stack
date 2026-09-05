from __future__ import annotations

import hashlib
import importlib.util
import io
import json
import tarfile
import tempfile
import unittest
import zipfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "sos_native_release_assets", ROOT / "tools" / "check_native_release_assets.py"
)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class NativeReleaseAssetTests(unittest.TestCase):
    def fixtures(self, root: Path) -> tuple[Path, Path]:
        assets = root / "assets"
        assets.mkdir()
        manifest = b'{"contract":"synthetic_release_manifest"}\n'
        linux = assets / "SOS-Linux.zip"
        with zipfile.ZipFile(linux, "w") as archive:
            archive.writestr("release-manifest.json", manifest)
        macos = assets / "SOS-macOS.tar.gz"
        with tarfile.open(macos, "w:gz") as archive:
            info = tarfile.TarInfo("SOS-macOS/release-manifest.json")
            info.size = len(manifest)
            archive.addfile(info, io.BytesIO(manifest))
        platforms = []
        for system, archive in (("linux", linux), ("darwin", macos)):
            platforms.append(
                {
                    "archive_filename": archive.name,
                    "archive_sha256": hashlib.sha256(archive.read_bytes()).hexdigest(),
                    "archive_size": archive.stat().st_size,
                    "delivery": "archive",
                    "inner_manifest": "release-manifest.json",
                    "inner_manifest_sha256": hashlib.sha256(manifest).hexdigest(),
                    "system": system,
                }
            )
        index = root / "index.json"
        index.write_text(json.dumps({"platforms": platforms}), encoding="utf-8")
        return index, assets

    def test_exact_linux_and_macos_assets_pass(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            index, assets = self.fixtures(Path(temporary))
            result = MODULE.inspect(index, assets)
            self.assertEqual(result["status"], "passed", result)
            self.assertEqual(result["checked_archives"], ["SOS-Linux.zip", "SOS-macOS.tar.gz"])

    def test_missing_tampered_and_inner_manifest_drift_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            index, assets = self.fixtures(Path(temporary))
            (assets / "SOS-Linux.zip").unlink()
            result = MODULE.inspect(index, assets)
            self.assertIn(
                "SOS_NATIVE_RELEASE_ARCHIVE_UNAVAILABLE:SOS-Linux.zip", result["failures"]
            )
        with tempfile.TemporaryDirectory() as temporary:
            index, assets = self.fixtures(Path(temporary))
            payload = json.loads(index.read_text())
            payload["platforms"][0]["archive_sha256"] = "0" * 64
            payload["platforms"][1]["inner_manifest_sha256"] = "0" * 64
            index.write_text(json.dumps(payload), encoding="utf-8")
            result = MODULE.inspect(index, assets)
            self.assertIn(
                "SOS_NATIVE_RELEASE_ARCHIVE_DIGEST_MISMATCH:SOS-Linux.zip",
                result["failures"],
            )
            self.assertIn(
                "SOS_NATIVE_RELEASE_INNER_MANIFEST_MISMATCH:SOS-macOS.tar.gz",
                result["failures"],
            )


if __name__ == "__main__":
    unittest.main()
