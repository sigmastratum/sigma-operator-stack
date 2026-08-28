from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


class WindowsMSIXTests(unittest.TestCase):
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
                "args=sys.argv[1:]; source=pathlib.Path(args[args.index('/d')+1]); output=pathlib.Path(args[args.index('/p')+1])\n"
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
                "--payload-root", os.fspath(payload), "--publisher", "CN=SigmaStratum Test",
                "--makeappx", os.fspath(makeappx), "--makeappx-sha256", makeappx_digest,
                "--output", os.fspath(output),
            ]
            completed = subprocess.run(command, check=True, stdout=subprocess.PIPE, text=True)
            report = json.loads(completed.stdout)
            self.assertEqual(report["status"], "passed")
            self.assertEqual(report["candidate"], candidate)
            self.assertTrue(output.is_file())
            wrong_digest = subprocess.run(
                [*command[:-3], "0" * 64, *command[-2:-1], os.fspath(root / "bad.msix")],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
            )
            self.assertNotEqual(wrong_digest.returncode, 0)
            self.assertIn("MakeAppx digest mismatch", wrong_digest.stderr)


if __name__ == "__main__":
    unittest.main()
