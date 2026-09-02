from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
CANDIDATE = "a" * 40
TREE = "b" * 40


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def source_record(root: Path) -> dict[str, object]:
    files = []
    for path in sorted(item for item in root.rglob("*") if item.is_file()):
        files.append(
            {
                "path": path.relative_to(root).as_posix(),
                "sha256": sha256(path),
                "size": path.stat().st_size,
            }
        )
    digest = hashlib.sha256()
    for item in files:
        digest.update(str(item["path"]).encode("utf-8"))
        digest.update(b"\0")
        digest.update(str(item["size"]).encode("ascii"))
        digest.update(b"\0")
        digest.update(str(item["sha256"]).encode("ascii"))
        digest.update(b"\n")
    return {
        "candidate": CANDIDATE,
        "contract": "sos_windows_msix_source_manifest_v1",
        "file_count": len(files),
        "files": files,
        "inventory_digest": f"sha256:{digest.hexdigest()}",
        "tree": TREE,
    }


def write_manifest(root: Path, destination: Path) -> dict[str, object]:
    record = source_record(root)
    destination.write_text(
        json.dumps(record, sort_keys=True, separators=(",", ":")) + "\n",
        encoding="utf-8",
        newline="",
    )
    return record


def run_verifier(root: Path, manifest: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [
            sys.executable,
            os.fspath(ROOT / "tools/verify_windows_msix_source.py"),
            "--source-root",
            os.fspath(root),
            "--source-manifest",
            os.fspath(manifest),
            "--candidate",
            CANDIDATE,
            "--tree",
            TREE,
        ],
        check=False,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )


class WindowsMSIXSourceTests(unittest.TestCase):
    def test_canonical_exact_full_inventory_is_admitted(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            source = base / "source"
            (source / "tools").mkdir(parents=True)
            (source / "tools/example.py").write_text("value = 1\n", encoding="utf-8")
            (source / "README.md").write_text("# Synthetic\n", encoding="utf-8")
            manifest = base / "source-manifest.json"
            write_manifest(source, manifest)
            completed = run_verifier(source, manifest)
            self.assertEqual(completed.returncode, 0, completed.stderr)
            report = json.loads(completed.stdout)
            self.assertEqual(report["status"], "passed")
            self.assertEqual(report["candidate"], CANDIDATE)
            self.assertEqual(report["tree"], TREE)
            self.assertEqual(report["source_file_count"], 2)

    def test_noncanonical_duplicate_missing_extra_and_tampered_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            source = base / "source"
            source.mkdir()
            target = source / "one.txt"
            target.write_text("one", encoding="utf-8")
            manifest = base / "source-manifest.json"
            record = write_manifest(source, manifest)

            manifest.write_text(json.dumps(record, indent=2) + "\n", encoding="utf-8")
            self.assertNotEqual(run_verifier(source, manifest).returncode, 0)

            write_manifest(source, manifest)
            target.write_text("changed", encoding="utf-8")
            self.assertNotEqual(run_verifier(source, manifest).returncode, 0)

            target.write_text("one", encoding="utf-8")
            write_manifest(source, manifest)
            (source / "extra.txt").write_text("extra", encoding="utf-8")
            self.assertNotEqual(run_verifier(source, manifest).returncode, 0)

            (source / "extra.txt").unlink()
            write_manifest(source, manifest)
            target.unlink()
            self.assertNotEqual(run_verifier(source, manifest).returncode, 0)

            duplicate_key = (
                '{"artifacts":[],"candidate":"'
                + CANDIDATE
                + '","candidate":"'
                + CANDIDATE
                + '","contract":"sos_windows_msix_source_manifest_v1","tree":"'
                + TREE
                + '"}\n'
            )
            manifest.write_text(duplicate_key, encoding="utf-8")
            rejected = run_verifier(source, manifest)
            self.assertNotEqual(rejected.returncode, 0)
            self.assertIn("duplicate key", rejected.stderr)

    def test_manifest_path_rules_and_case_collisions_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            source = base / "source"
            source.mkdir()
            (source / "safe.txt").write_text("safe", encoding="utf-8")
            manifest = base / "source-manifest.json"
            base_record = source_record(source)
            artifact = dict(base_record["files"][0])
            probes = (
                [artifact, artifact],
                [artifact, {**artifact, "path": "SAFE.TXT"}],
                [{**artifact, "path": "../safe.txt"}],
                [{**artifact, "path": "safe.txt:stream"}],
                [{**artifact, "path": "CON.txt"}],
                [{**artifact, "path": "CONIN$.txt"}],
                [{**artifact, "path": "CONOUT$.txt"}],
            )
            for artifacts in probes:
                with self.subTest(artifacts=artifacts):
                    digest = hashlib.sha256()
                    for item in artifacts:
                        digest.update(str(item["path"]).encode("utf-8"))
                        digest.update(b"\0")
                        digest.update(str(item["size"]).encode("ascii"))
                        digest.update(b"\0")
                        digest.update(str(item["sha256"]).encode("ascii"))
                        digest.update(b"\n")
                    record = {
                        **base_record,
                        "file_count": len(artifacts),
                        "files": artifacts,
                        "inventory_digest": f"sha256:{digest.hexdigest()}",
                    }
                    manifest.write_text(
                        json.dumps(record, sort_keys=True, separators=(",", ":")) + "\n",
                        encoding="utf-8",
                    )
                    self.assertNotEqual(run_verifier(source, manifest).returncode, 0)

    def test_closed_manifest_count_and_inventory_digest_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            source = base / "source"
            source.mkdir()
            (source / "safe.txt").write_text("safe", encoding="utf-8")
            manifest = base / "source-manifest.json"
            admitted = source_record(source)
            probes = (
                {**admitted, "file_count": 2},
                {**admitted, "inventory_digest": "sha256:" + "0" * 64},
                {**admitted, "unexpected": False},
                {
                    **admitted,
                    "files": [{**admitted["files"][0], "unexpected": False}],
                },
            )
            for record in probes:
                with self.subTest(keys=sorted(record)):
                    manifest.write_text(
                        json.dumps(record, sort_keys=True, separators=(",", ":")) + "\n",
                        encoding="utf-8",
                    )
                    self.assertNotEqual(run_verifier(source, manifest).returncode, 0)

    def test_links_and_unlisted_directories_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            source = base / "source"
            source.mkdir()
            (source / "safe.txt").write_text("safe", encoding="utf-8")
            manifest = base / "source-manifest.json"
            write_manifest(source, manifest)
            (source / "unlisted-empty").mkdir()
            self.assertNotEqual(run_verifier(source, manifest).returncode, 0)
            (source / "unlisted-empty").rmdir()
            (source / "linked").symlink_to(source / "safe.txt")
            self.assertNotEqual(run_verifier(source, manifest).returncode, 0)
            (source / "linked").unlink()
            os.link(source / "safe.txt", source / "hardlinked.txt")
            write_manifest(source, manifest)
            self.assertNotEqual(run_verifier(source, manifest).returncode, 0)

    def test_unsigned_builder_uses_only_the_exact_source_snapshot(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            source = base / "source"
            for relative in (
                "tools/build_windows_msix.py",
                "tools/verify_windows_msix_source.py",
                "installers/windows-msix/AppxManifest.xml.in",
                "installers/windows-msix/store-identity.json",
                "installers/windows-msix/assets/Square44x44Logo.png",
                "installers/windows-msix/assets/Square50x50Logo.png",
                "installers/windows-msix/assets/Square150x150Logo.png",
            ):
                destination = source / relative
                destination.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(ROOT / relative, destination)
            manifest = base / "source-manifest.json"
            write_manifest(source, manifest)

            payload = base / "payload"
            required = {
                "sos.exe": b"MZlauncher",
                "sos-launcher.exe": b"MZstorelauncher",
                "runtime/python.exe": b"MZpython",
                "runtime/Lib/site-packages/sos/__init__.py": b'version="0.1.0a2"\n',
                "bootstrap/uv.exe": b"MZuv",
                "wheelhouse/sigma_operator_stack-0.1.0a2-py3-none-any.whl": b"PKwheel",
            }
            for relative, content in required.items():
                destination = payload / relative
                destination.parent.mkdir(parents=True, exist_ok=True)
                destination.write_bytes(content)
            makeappx = base / "makeappx"
            makeappx.write_text(
                "#!/usr/bin/env python3\n"
                "import pathlib,sys\n"
                "a=sys.argv[1:]; assert a[0]=='pack'\n"
                "s=pathlib.Path(a[a.index('/d')+1]); p=pathlib.Path(a[a.index('/p')+1])\n"
                "p.write_bytes(b'MSIX'+str(len([x for x in s.rglob('*') if x.is_file()])).encode())\n",
                encoding="utf-8",
            )
            makeappx.chmod(0o700)
            output = base / "product.msix"
            completed = subprocess.run(
                [
                    sys.executable,
                    "-I",
                    "-B",
                    os.fspath(ROOT / "tools/build_windows_msix.py"),
                    "--source-root",
                    os.fspath(source),
                    "--source-manifest",
                    os.fspath(manifest),
                    "--candidate",
                    CANDIDATE,
                    "--tree",
                    TREE,
                    "--payload-root",
                    os.fspath(payload),
                    "--makeappx",
                    os.fspath(makeappx),
                    "--makeappx-sha256",
                    sha256(makeappx),
                    "--output",
                    os.fspath(output),
                ],
                check=False,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            self.assertEqual(completed.returncode, 0, completed.stderr)
            report = json.loads(completed.stdout)
            self.assertEqual(report["status"], "passed")
            self.assertRegex(report["source_manifest_sha256"], r"^sha256:[0-9a-f]{64}$")
            self.assertRegex(report["source_tree_digest"], r"^sha256:[0-9a-f]{64}$")
            self.assertTrue(output.is_file())

    def test_build_path_has_no_git_or_mutable_repository_contract(self) -> None:
        for relative in (
            "tools/build_windows_msix.py",
            "tools/build_windows_msix_pipeline.py",
        ):
            source = (ROOT / relative).read_text(encoding="utf-8")
            self.assertNotIn('"git"', source)
            self.assertNotIn("--repository", source)
            self.assertIn("--source-root", source)
            self.assertIn("--source-manifest", source)
            self.assertIn("source_manifest_sha256", source)
            self.assertIn("source_tree_digest", source)

    def test_pipeline_runs_all_bound_tools_under_isolated_python(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            source = base / "source"
            for relative in (
                "tools/build_windows_msix.py",
                "tools/build_windows_msix_pipeline.py",
                "tools/check_windows_msix_content.py",
                "tools/compare_windows_msix.py",
                "tools/verify_windows_msix_source.py",
                "installers/windows-msix/AppxManifest.xml.in",
                "installers/windows-msix/store-identity.json",
                "installers/windows-msix/assets/Square44x44Logo.png",
                "installers/windows-msix/assets/Square50x50Logo.png",
                "installers/windows-msix/assets/Square150x150Logo.png",
            ):
                destination = source / relative
                destination.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(ROOT / relative, destination)
            manifest = base / "source-manifest.json"
            write_manifest(source, manifest)

            payload = base / "payload"
            for relative, content in {
                "sos.exe": b"MZlauncher",
                "sos-launcher.exe": b"MZstorelauncher",
                "runtime/python.exe": b"MZpython",
                "runtime/Lib/site-packages/sos/__init__.py": b'version="alpha"\n',
                "bootstrap/uv.exe": b"MZuv",
                "wheelhouse/sigma_operator_stack-0.1.0a2-py3-none-any.whl": b"PKwheel",
            }.items():
                destination = payload / relative
                destination.parent.mkdir(parents=True, exist_ok=True)
                destination.write_bytes(content)

            makeappx = base / "MakeAppx.exe"
            makeappx.write_text(
                "#!/usr/bin/env python3\n"
                "import base64,hashlib,html,pathlib,shutil,sys\n"
                "a=sys.argv[1:]; mode=a[0]\n"
                "if mode=='pack':\n"
                " s=pathlib.Path(a[a.index('/d')+1]); p=pathlib.Path(a[a.index('/p')+1]); t=p.with_suffix('.tree')\n"
                " shutil.copytree(s,t); (t/'[Content_Types].xml').write_text('<Types/>')\n"
                " fs=[x for x in sorted(t.rglob('*')) if x.is_file() and x.name!='[Content_Types].xml']; records=[]\n"
                " for x in fs:\n"
                "  value=x.read_bytes(); blocks=''.join('<Block Hash=\\\"'+base64.b64encode(hashlib.sha256(value[o:o+65536]).digest()).decode()+'\\\" />' for o in range(0,len(value),65536)); name=html.escape(x.relative_to(t).as_posix().replace('/',chr(92))); records.append(f'<File Name=\\\"{name}\\\" Size=\\\"{len(value)}\\\" LfhSize=\\\"40\\\">{blocks}</File>')\n"
                " (t/'AppxBlockMap.xml').write_text('<BlockMap xmlns=\\\"http://schemas.microsoft.com/appx/2010/blockmap\\\" HashMethod=\\\"http://www.w3.org/2001/04/xmlenc#sha256\\\">'+''.join(records)+'</BlockMap>')\n"
                " p.write_bytes(b'MSIX-'+p.name.encode())\n"
                "elif mode=='unpack':\n"
                " p=pathlib.Path(a[a.index('/p')+1]); d=pathlib.Path(a[a.index('/d')+1]); shutil.copytree(p.with_suffix('.tree'),d,dirs_exist_ok=True); (d/'[Content_Types].xml').unlink()\n"
                "else: raise SystemExit(9)\n",
                encoding="utf-8",
            )
            makeappx.chmod(0o700)
            output = base / "output"
            completed = subprocess.run(
                [
                    sys.executable,
                    "-I",
                    "-B",
                    os.fspath(ROOT / "tools/build_windows_msix_pipeline.py"),
                    "--source-root",
                    os.fspath(source),
                    "--source-manifest",
                    os.fspath(manifest),
                    "--candidate",
                    CANDIDATE,
                    "--tree",
                    TREE,
                    "--payload-root",
                    os.fspath(payload),
                    "--makeappx",
                    os.fspath(makeappx),
                    "--makeappx-sha256",
                    sha256(makeappx),
                    "--output-root",
                    os.fspath(output),
                ],
                check=False,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            self.assertEqual(completed.returncode, 0, completed.stderr)
            result = json.loads(completed.stdout)
            self.assertEqual(result["status"], "passed")
            self.assertTrue((output / "first-content-safety.json").is_file())
            self.assertTrue((output / "second-content-safety.json").is_file())
            self.assertRegex(
                result["source_manifest_sha256"], r"^sha256:[0-9a-f]{64}$"
            )


if __name__ == "__main__":
    unittest.main()
