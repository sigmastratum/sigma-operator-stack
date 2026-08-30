from __future__ import annotations

import hashlib
import io
import json
import os
import struct
import subprocess
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


class NonSeekableBytesIO(io.BytesIO):
    def seekable(self) -> bool:
        return False

    def seek(self, *args: object, **kwargs: object) -> int:
        raise io.UnsupportedOperation("seek")


class WindowsMSIXTests(unittest.TestCase):
    def _wrap_with_zip64(self, package: Path) -> None:
        """Convert a small classic ZIP trailer into a valid synthetic ZIP64 trailer."""
        value = bytearray(package.read_bytes())
        eocd = value.rfind(b"PK\x05\x06")
        self.assertGreaterEqual(eocd, 0)
        (
            _signature,
            disk,
            central_disk,
            disk_entries,
            total_entries,
            central_size,
            central_offset,
            comment_length,
        ) = struct.unpack_from("<4s4H2LH", value, eocd)
        self.assertEqual((disk, central_disk, comment_length), (0, 0, 0))
        zip64_end = struct.pack(
            "<4sQ2H2L4Q",
            b"PK\x06\x06",
            44,
            45,
            45,
            0,
            0,
            disk_entries,
            total_entries,
            central_size,
            central_offset,
        )
        locator = struct.pack("<4sLQL", b"PK\x06\x07", 0, eocd, 1)
        classic = struct.pack(
            "<4s4H2LH",
            b"PK\x05\x06",
            0xFFFF,
            0xFFFF,
            0xFFFF,
            0xFFFF,
            0xFFFFFFFF,
            0xFFFFFFFF,
            0,
        )
        package.write_bytes(bytes(value[:eocd]) + zip64_end + locator + classic)

    def test_msix_comparator_allows_only_timestamp_container_drift(self) -> None:
        comparator = ROOT / "tools/compare_windows_msix.py"
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            first = root / "first.msix"
            second = root / "second.msix"
            entries = {
                "AppxManifest.xml": b"<Package/>",
                "AppxBlockMap.xml": b"<BlockMap/>",
                "[Content_Types].xml": b"<Types/>",
                "payload-manifest.json": b"{}\n",
                "sos.exe": b"MZsos",
                "runtime/python.exe": b"MZpython",
            }
            for package, timestamp in (
                (first, (2026, 8, 27, 12, 0, 0)),
                (second, (2026, 8, 27, 12, 2, 0)),
            ):
                with zipfile.ZipFile(package, "w", zipfile.ZIP_DEFLATED) as archive:
                    for name, content in entries.items():
                        info = zipfile.ZipInfo(name, timestamp)
                        info.compress_type = zipfile.ZIP_DEFLATED
                        archive.writestr(info, content)
            completed = subprocess.run(
                [sys.executable, os.fspath(comparator), os.fspath(first), os.fspath(second)],
                check=True,
                stdout=subprocess.PIPE,
                text=True,
            )
            report = json.loads(completed.stdout)
            self.assertEqual(report["status"], "passed")
            self.assertFalse(report["byte_identical"])
            self.assertTrue(report["timestamp_drift_only"])
            self.assertEqual(report["timestamp_drift_entry_count"], len(entries))
            self.assertRegex(report["content_digest"], r"^sha256:[0-9a-f]{64}$")

            with zipfile.ZipFile(second, "w", zipfile.ZIP_DEFLATED) as archive:
                for name, content in entries.items():
                    archive.writestr(name, content + (b"drift" if name == "sos.exe" else b""))
            drifted = subprocess.run(
                [sys.executable, os.fspath(comparator), os.fspath(first), os.fspath(second)],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            self.assertEqual(drifted.returncode, 2)
            self.assertIn("package entry content differs", drifted.stderr)

    def test_msix_comparator_rejects_non_timestamp_metadata_drift(self) -> None:
        comparator = ROOT / "tools/compare_windows_msix.py"
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            first = root / "first.msix"
            second = root / "second.msix"
            required = {
                "AppxManifest.xml",
                "AppxBlockMap.xml",
                "[Content_Types].xml",
                "payload-manifest.json",
                "sos.exe",
                "runtime/python.exe",
            }
            for package, external_attr in ((first, 0), (second, 32)):
                with zipfile.ZipFile(package, "w") as archive:
                    for name in sorted(required):
                        info = zipfile.ZipInfo(name, (2026, 8, 27, 12, 0, 0))
                        info.external_attr = external_attr
                        archive.writestr(info, name.encode())
            completed = subprocess.run(
                [sys.executable, os.fspath(comparator), os.fspath(first), os.fspath(second)],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            self.assertEqual(completed.returncode, 2)
            self.assertIn("metadata differs beyond timestamps", completed.stderr)

    def test_msix_comparator_rejects_unexplained_container_bytes(self) -> None:
        comparator = ROOT / "tools/compare_windows_msix.py"
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            first = root / "first.msix"
            second = root / "second.msix"
            required = {
                "AppxManifest.xml",
                "AppxBlockMap.xml",
                "[Content_Types].xml",
                "payload-manifest.json",
                "sos.exe",
                "runtime/python.exe",
            }
            for package in (first, second):
                with zipfile.ZipFile(package, "w") as archive:
                    for name in sorted(required):
                        archive.writestr(name, name.encode())
            with second.open("ab") as handle:
                handle.write(b"unexplained")
            completed = subprocess.run(
                [sys.executable, os.fspath(comparator), os.fspath(first), os.fspath(second)],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            self.assertEqual(completed.returncode, 2)
            self.assertIn("trailer or comment is forbidden", completed.stderr)

    def test_msix_comparator_rejects_central_flags_and_timestamp_shape_drift(self) -> None:
        comparator = ROOT / "tools/compare_windows_msix.py"
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            first = root / "first.msix"
            second = root / "second.msix"
            required = {
                "AppxManifest.xml",
                "AppxBlockMap.xml",
                "[Content_Types].xml",
                "payload-manifest.json",
                "sos.exe",
                "runtime/python.exe",
            }
            for package in (first, second):
                with zipfile.ZipFile(package, "w") as archive:
                    for name in sorted(required):
                        archive.writestr(name, name.encode())
            central_drift = bytearray(second.read_bytes())
            eocd = central_drift.rfind(b"PK\x05\x06")
            central_offset = int.from_bytes(central_drift[eocd + 16 : eocd + 20], "little")
            central_drift[central_offset + 8] |= 0x08
            second.write_bytes(central_drift)
            flags = subprocess.run(
                [sys.executable, os.fspath(comparator), os.fspath(first), os.fspath(second)],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            self.assertEqual(flags.returncode, 2)
            self.assertIn("local and central ZIP flags differ", flags.stderr)

            for package, timestamp_flags in ((first, 0x01), (second, 0x07)):
                with zipfile.ZipFile(package, "w") as archive:
                    for name in sorted(required):
                        info = zipfile.ZipInfo(name)
                        info.extra = struct.pack("<HHB", 0x5455, 5, timestamp_flags) + b"\0" * 4
                        archive.writestr(info, name.encode())
            timestamp_shape = subprocess.run(
                [sys.executable, os.fspath(comparator), os.fspath(first), os.fspath(second)],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            self.assertEqual(timestamp_shape.returncode, 2)
            self.assertIn("malformed extended timestamp", timestamp_shape.stderr)

            malformed_ntfs = struct.pack("<HH", 0x000A, 32) + b"BAD!" + struct.pack(
                "<HH", 0x0001, 24
            ) + b"\0" * 24
            for package in (first, second):
                with zipfile.ZipFile(package, "w") as archive:
                    for name in sorted(required):
                        info = zipfile.ZipInfo(name)
                        info.extra = malformed_ntfs
                        archive.writestr(info, name.encode())
            ntfs_shape = subprocess.run(
                [sys.executable, os.fspath(comparator), os.fspath(first), os.fspath(second)],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            self.assertEqual(ntfs_shape.returncode, 2)
            self.assertIn("malformed NTFS timestamp", ntfs_shape.stderr)

    def test_msix_comparator_validates_bounded_data_descriptors(self) -> None:
        comparator = ROOT / "tools/compare_windows_msix.py"
        required = {
            "AppxManifest.xml",
            "AppxBlockMap.xml",
            "[Content_Types].xml",
            "payload-manifest.json",
            "sos.exe",
            "runtime/python.exe",
        }
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            first = root / "first.msix"
            second = root / "second.msix"
            for package, timestamp in (
                (first, (2026, 8, 27, 12, 0, 0)),
                (second, (2026, 8, 27, 12, 2, 0)),
            ):
                stream = NonSeekableBytesIO()
                with zipfile.ZipFile(stream, "w", zipfile.ZIP_DEFLATED) as archive:
                    for name in sorted(required):
                        info = zipfile.ZipInfo(name, timestamp)
                        info.compress_type = zipfile.ZIP_DEFLATED
                        archive.writestr(info, name.encode())
                package.write_bytes(stream.getvalue())
            completed = subprocess.run(
                [sys.executable, os.fspath(comparator), os.fspath(first), os.fspath(second)],
                check=True,
                stdout=subprocess.PIPE,
                text=True,
            )
            report = json.loads(completed.stdout)
            self.assertEqual(report["status"], "passed")
            self.assertTrue(report["timestamp_drift_only"])

            drifted = bytearray(second.read_bytes())
            with zipfile.ZipFile(second) as package:
                first_info = min(package.infolist(), key=lambda info: info.header_offset)
                name_length, extra_length = struct.unpack_from(
                    "<HH", drifted, first_info.header_offset + 26
                )
                descriptor = (
                    first_info.header_offset
                    + 30
                    + name_length
                    + extra_length
                    + first_info.compress_size
                )
            drifted[descriptor + 4] ^= 0x01
            second.write_bytes(drifted)
            rejected = subprocess.run(
                [sys.executable, os.fspath(comparator), os.fspath(first), os.fspath(second)],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            self.assertEqual(rejected.returncode, 2)
            self.assertIn("data descriptor binding failed", rejected.stderr)

    def test_msix_comparator_supports_bounded_zip64_directory(self) -> None:
        comparator = ROOT / "tools/compare_windows_msix.py"
        required = {
            "AppxManifest.xml",
            "AppxBlockMap.xml",
            "[Content_Types].xml",
            "payload-manifest.json",
            "sos.exe",
            "runtime/python.exe",
        }
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            first = root / "first.msix"
            second = root / "second.msix"
            for package, timestamp in (
                (first, (2026, 8, 27, 12, 0, 0)),
                (second, (2026, 8, 27, 12, 2, 0)),
            ):
                with zipfile.ZipFile(package, "w", zipfile.ZIP_DEFLATED) as archive:
                    for name in sorted(required):
                        info = zipfile.ZipInfo(name, timestamp)
                        info.compress_type = zipfile.ZIP_DEFLATED
                        archive.writestr(info, name.encode())
                self._wrap_with_zip64(package)
            completed = subprocess.run(
                [sys.executable, os.fspath(comparator), os.fspath(first), os.fspath(second)],
                check=True,
                stdout=subprocess.PIPE,
                text=True,
            )
            report = json.loads(completed.stdout)
            self.assertEqual(report["status"], "passed")
            self.assertTrue(report["timestamp_drift_only"])

    def test_msix_comparator_rejects_malformed_zip64_directory(self) -> None:
        comparator = ROOT / "tools/compare_windows_msix.py"
        required = {
            "AppxManifest.xml",
            "AppxBlockMap.xml",
            "[Content_Types].xml",
            "payload-manifest.json",
            "sos.exe",
            "runtime/python.exe",
        }
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            baseline = root / "baseline.msix"
            with zipfile.ZipFile(baseline, "w") as archive:
                for name in sorted(required):
                    archive.writestr(name, name.encode())
            self._wrap_with_zip64(baseline)

            cases = (
                ("locator-offset", 8, 1, "ZIP64 end record is missing"),
                ("locator-disks", 16, 2, "multi-disk ZIP64 package is forbidden"),
                ("record-size", 4, 45, "unsupported ZIP64 end record shape"),
                ("record-count", 32, len(required) + 1, "entry count is inconsistent"),
                ("central-size", 40, 1, "directory bounds are inconsistent"),
            )
            for name, relative_offset, replacement, expected in cases:
                with self.subTest(name=name):
                    malformed = root / f"{name}.msix"
                    value = bytearray(baseline.read_bytes())
                    eocd = value.rfind(b"PK\x05\x06")
                    locator = eocd - 20
                    zip64 = struct.unpack_from("<Q", value, locator + 8)[0]
                    width = 4 if name == "locator-disks" else 8
                    value[
                        (locator if name.startswith("locator") else zip64)
                        + relative_offset :
                        (locator if name.startswith("locator") else zip64)
                        + relative_offset
                        + width
                    ] = replacement.to_bytes(width, "little")
                    malformed.write_bytes(value)
                    completed = subprocess.run(
                        [
                            sys.executable,
                            os.fspath(comparator),
                            os.fspath(baseline),
                            os.fspath(malformed),
                        ],
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                        text=True,
                    )
                    self.assertEqual(completed.returncode, 2)
                    self.assertIn(expected, completed.stderr)

            for name, offset, replacement, expected in (
                ("missing-locator", -20, b"BAD!", "ZIP64 locator is missing"),
                (
                    "classic-disk-mismatch",
                    4,
                    (1).to_bytes(2, "little"),
                    "classic and ZIP64 disk number differ",
                ),
            ):
                with self.subTest(name=name):
                    malformed = root / f"{name}.msix"
                    value = bytearray(baseline.read_bytes())
                    eocd = value.rfind(b"PK\x05\x06")
                    start = eocd + offset
                    value[start : start + len(replacement)] = replacement
                    malformed.write_bytes(value)
                    completed = subprocess.run(
                        [
                            sys.executable,
                            os.fspath(comparator),
                            os.fspath(baseline),
                            os.fspath(malformed),
                        ],
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                        text=True,
                    )
                    self.assertEqual(completed.returncode, 2)
                    self.assertIn(expected, completed.stderr)

    def test_store_identity_is_exact_and_public(self) -> None:
        identity = json.loads(
            (ROOT / "installers/windows-msix/store-identity.json").read_text(
                encoding="utf-8"
            )
        )
        self.assertEqual(identity["contract"], "sos_windows_store_identity_v1")
        self.assertEqual(identity["package_identity_name"], "SSRG.SigmaOperatorStack")
        self.assertEqual(
            identity["package_identity_publisher"],
            "CN=D713C275-467D-4A03-9D24-0DC02F1C3031",
        )
        self.assertEqual(identity["publisher_display_name"], "SSRG")
        self.assertEqual(
            identity["package_family_name"],
            "SSRG.SigmaOperatorStack_2358e20nvr064",
        )
        self.assertEqual(identity["store_id"], "9NNZT70C613H")
        self.assertEqual(
            identity["store_url"],
            "https://apps.microsoft.com/detail/9NNZT70C613H",
        )

    def test_manifest_is_per_user_medium_integrity_and_alias_only(self) -> None:
        manifest = (ROOT / "installers/windows-msix/AppxManifest.xml.in").read_text(
            encoding="utf-8"
        )
        for required in (
            'ProcessorArchitecture="x64"',
            'MinVersion="10.0.22000.0"',
            'uap10:TrustLevel="mediumIL"',
            'uap10:RuntimeBehavior="packagedClassicApp"',
            'Category="windows.appExecutionAlias"',
            'Alias="sos.exe"',
            'Name="SSRG.SigmaOperatorStack"',
            'Publisher="CN=D713C275-467D-4A03-9D24-0DC02F1C3031"',
            '<PublisherDisplayName>SSRG</PublisherDisplayName>',
            '<uap10:Content Enforcement="on" />',
            '<rescap:Capability Name="runFullTrust" />',
        ):
            self.assertIn(required, manifest)
        for forbidden in ("allowElevation", "machine", "customAction"):
            self.assertNotIn(forbidden, manifest)

    def test_launcher_uses_immutable_runtime_without_shell_or_acquisition(self) -> None:
        source = (ROOT / "installers/windows-msix/main.go").read_text(encoding="utf-8")
        for required in (
            'filepath.Join(packageRoot, "runtime", "python.exe")',
            '"PYTHONNOUSERSITE=1"',
            '"PYTHONSAFEPATH=1"',
            'exec.Command(python, arguments...)',
            '[]string{"-m", "sos", "init", "--with-codex"',
            '[]string{"-m", "sos", "setup", arguments[0], "codex"',
        ):
            self.assertIn(required, source)
        for forbidden in ("cmd.exe", "powershell", "uv python install", "http://", "https://"):
            self.assertNotIn(forbidden, source.lower())

    def test_unsigned_msix_builder_is_exact_and_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            repository = root / "repository"
            (repository / "installers/windows-msix").mkdir(parents=True)
            for relative in (
                "installers/windows-msix/AppxManifest.xml.in",
                "installers/windows-msix/store-identity.json",
            ):
                destination = repository / relative
                destination.write_bytes((ROOT / relative).read_bytes())
            subprocess.run(["git", "init", "-q", os.fspath(repository)], check=True)
            subprocess.run(["git", "-C", os.fspath(repository), "add", "."], check=True)
            subprocess.run(
                ["git", "-C", os.fspath(repository), "-c", "user.name=Test", "-c", "user.email=test@example.invalid", "commit", "-qm", "fixture"],
                check=True,
            )
            candidate = subprocess.run(
                ["git", "-C", os.fspath(repository), "rev-parse", "HEAD"],
                check=True, stdout=subprocess.PIPE, text=True,
            ).stdout.strip()
            payload = root / "payload"
            required = {
                "sos.exe": b"MZlauncher",
                "runtime/python.exe": b"MZpython",
                "runtime/Lib/site-packages/sos/__init__.py": b'__version__="0.1.0a2"\n',
                "bootstrap/uv.exe": b"MZuv",
                "wheelhouse/sigma_operator_stack-0.1.0a2-py3-none-any.whl": b"PKwheel",
            }
            for relative, content in required.items():
                path = payload / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(content)
            makeappx = root / "makeappx"
            makeappx.write_text(
                "#!/usr/bin/env python3\n"
                "import pathlib,sys,zipfile\n"
                "args=sys.argv[1:]; assert args[0]=='pack'; source=pathlib.Path(args[args.index('/d')+1]); output=pathlib.Path(args[args.index('/p')+1])\n"
                "with zipfile.ZipFile(output,'w') as archive:\n"
                "  [archive.write(path,path.relative_to(source).as_posix()) for path in sorted(source.rglob('*')) if path.is_file()]\n"
                "  archive.writestr('AppxBlockMap.xml','<BlockMap/>')\n"
                "  archive.writestr('[Content_Types].xml','<Types/>')\n",
                encoding="utf-8",
            )
            makeappx.chmod(0o700)
            makeappx_digest = hashlib.sha256(makeappx.read_bytes()).hexdigest()
            output = root / "SOS.msix"
            command = [
                sys.executable, os.fspath(ROOT / "tools/build_windows_msix.py"),
                "--repository", os.fspath(repository), "--candidate", candidate,
                "--payload-root", os.fspath(payload),
                "--makeappx", os.fspath(makeappx), "--makeappx-sha256", makeappx_digest,
                "--output", os.fspath(output),
            ]
            completed = subprocess.run(command, check=True, stdout=subprocess.PIPE, text=True)
            report = json.loads(completed.stdout)
            self.assertEqual(report["status"], "passed")
            self.assertEqual(report["candidate"], candidate)
            self.assertEqual(report["store_id"], "9NNZT70C613H")
            self.assertEqual(report["package_identity_name"], "SSRG.SigmaOperatorStack")
            self.assertEqual(
                report["package_family_name"],
                "SSRG.SigmaOperatorStack_2358e20nvr064",
            )
            self.assertTrue(output.is_file())
            wrong_digest = subprocess.run(
                [*command[:-3], "0" * 64, *command[-2:-1], os.fspath(root / "bad.msix")],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
            )
            self.assertNotEqual(wrong_digest.returncode, 0)
            self.assertIn("MakeAppx digest mismatch", wrong_digest.stderr)

            identity_path = repository / "installers/windows-msix/store-identity.json"
            drifted_identity = json.loads(identity_path.read_text(encoding="utf-8"))
            drifted_identity["package_identity_publisher"] = "CN=ForeignPublisher"
            identity_path.write_text(
                json.dumps(drifted_identity, sort_keys=True) + "\n", encoding="utf-8"
            )
            subprocess.run(["git", "-C", os.fspath(repository), "add", "."], check=True)
            subprocess.run(
                [
                    "git",
                    "-C",
                    os.fspath(repository),
                    "-c",
                    "user.name=Test",
                    "-c",
                    "user.email=test@example.invalid",
                    "commit",
                    "-qm",
                    "drift identity",
                ],
                check=True,
            )
            drifted_candidate = subprocess.run(
                ["git", "-C", os.fspath(repository), "rev-parse", "HEAD"],
                check=True,
                stdout=subprocess.PIPE,
                text=True,
            ).stdout.strip()
            drifted_command = list(command)
            drifted_command[drifted_command.index("--candidate") + 1] = drifted_candidate
            drifted_command[drifted_command.index("--output") + 1] = os.fspath(
                root / "drifted.msix"
            )
            drifted = subprocess.run(
                drifted_command,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            self.assertNotEqual(drifted.returncode, 0)
            self.assertIn("MSIX Store identity binding failed", drifted.stderr)


if __name__ == "__main__":
    unittest.main()
