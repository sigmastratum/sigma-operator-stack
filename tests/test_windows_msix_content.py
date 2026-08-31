from __future__ import annotations

import base64
import hashlib
import html
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
CANDIDATE = "a" * 40
TREE = "b" * 40


def write(root: Path, relative: str, value: bytes) -> None:
    target = root / relative
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(value)


def package_fixture(root: Path, sos_source: bytes = b"VERSION = 'alpha'\n") -> None:
    payload = {
        "bootstrap/uv.exe": b"MZ-uv",
        "runtime/Lib/site-packages/sos/__init__.py": sos_source,
        "runtime/python.exe": b"MZ-python",
        "sos.exe": b"MZ-sos",
        "wheelhouse/sigma_operator_stack-0.1.0a2-py3-none-any.whl": b"PK-wheel",
    }
    for relative, value in payload.items():
        write(root, relative, value)
    manifest = {
        "artifacts": [
            {"path": path, "sha256": hashlib.sha256(value).hexdigest()}
            for path, value in sorted(payload.items())
        ],
        "candidate": CANDIDATE,
        "contract": "sos_windows_msix_payload_v1",
        "executable_acquisition_after_install": False,
        "msix_version": "0.1.0.2",
        "network_after_package_download": False,
        "platform": "windows-x86_64",
        "sos_version": "0.1.0a2",
        "tree": TREE,
    }
    generated = {
        "AppxManifest.xml": b"<Package/>",
        "Assets/Square150x150Logo.png": b"png150",
        "Assets/Square44x44Logo.png": b"png44",
        "payload-manifest.json": (
            json.dumps(manifest, sort_keys=True, separators=(",", ":")) + "\n"
        ).encode(),
    }
    for relative, value in generated.items():
        write(root, relative, value)
    block_files = {
        **payload,
        **generated,
    }
    records: list[str] = []
    for path, value in sorted(block_files.items()):
        blocks = "".join(
            '<Block Hash="'
            + base64.b64encode(
                hashlib.sha256(value[offset : offset + 65536]).digest()
            ).decode()
            + '" />'
            for offset in range(0, len(value), 65536)
        )
        records.append(
            f'<File Name="{html.escape(path.replace("/", chr(92)))}" '
            f'Size="{len(value)}" LfhSize="40">{blocks}</File>'
        )
    write(
        root,
        "AppxBlockMap.xml",
        (
            '<BlockMap xmlns="http://schemas.microsoft.com/appx/2010/blockmap" '
            'HashMethod="http://www.w3.org/2001/04/xmlenc#sha256">'
            + "".join(records)
            + "</BlockMap>"
        ).encode(),
    )


class WindowsMSIXContentTests(unittest.TestCase):
    def run_check(self, root: Path) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [
                sys.executable,
                "-I",
                "-B",
                os.fspath(ROOT / "tools/check_windows_msix_content.py"),
                "--unpacked-root",
                os.fspath(root),
                "--candidate",
                CANDIDATE,
                "--tree",
                TREE,
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )

    def test_content_safety_accepts_bound_opaque_artifacts_and_public_text(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            package_fixture(root)
            completed = self.run_check(root)
            self.assertEqual(completed.returncode, 0, completed.stderr)
            report = json.loads(completed.stdout)
            self.assertEqual(report["status"], "passed")
            self.assertFalse(report["raw_content_serialized"])
            self.assertFalse(report["absolute_paths_serialized"])
            self.assertGreaterEqual(report["scanned_text_file_count"], 3)
            self.assertRegex(report["report_digest"], r"^sha256:[0-9a-f]{64}$")

    def test_content_safety_rejects_private_patterns_without_echoing_them(self) -> None:
        cases = {
            "credential": b"client_secret = 'abcdefghijklmnopqrstuvwxyz'\n",
            "host-path": b"value = 'C:/Users/example-user/Documents/project'\n",
            "conversation": b"value = '<response-annotations>'\n",
        }
        for name, value in cases.items():
            with self.subTest(name=name), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                package_fixture(root, value)
                completed = self.run_check(root)
                self.assertEqual(completed.returncode, 2)
                self.assertIn("SOS_MSIX_CONTENT_SAFETY_FAILED", completed.stderr)
                self.assertNotIn(value.decode().strip(), completed.stderr)

    def test_content_safety_rejects_bytecode_even_when_manifest_bound(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            package_fixture(root)
            value = b"bytecode"
            relative = "runtime/Lib/site-packages/sos/__pycache__/x.cpython-312.pyc"
            write(root, relative, value)
            manifest_path = root / "payload-manifest.json"
            record = json.loads(manifest_path.read_text(encoding="utf-8"))
            record["artifacts"].append(
                {"path": relative, "sha256": hashlib.sha256(value).hexdigest()}
            )
            record["artifacts"].sort(key=lambda item: item["path"])
            manifest_path.write_text(
                json.dumps(record, sort_keys=True, separators=(",", ":")) + "\n",
                encoding="utf-8",
            )
            completed = self.run_check(root)
            self.assertEqual(completed.returncode, 2)
            self.assertIn("Python bytecode is forbidden", completed.stderr)


if __name__ == "__main__":
    unittest.main()
