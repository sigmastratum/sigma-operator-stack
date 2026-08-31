from __future__ import annotations

import hashlib
import html
import json
import os
import base64
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
CANDIDATE = "1" * 40
TREE = "2" * 40
MAKEAPPX_SHA = "3" * 64


def write_file(root: Path, relative: str, content: bytes) -> None:
    destination = root / relative
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_bytes(content)


def write_source_manifest(
    source: Path, destination: Path, candidate: str, tree: str
) -> None:
    files = [
        {
            "path": path.relative_to(source).as_posix(),
            "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
            "size": path.stat().st_size,
        }
        for path in sorted(item for item in source.rglob("*") if item.is_file())
    ]
    digest = hashlib.sha256()
    for item in files:
        digest.update(item["path"].encode("utf-8"))
        digest.update(b"\0")
        digest.update(str(item["size"]).encode("ascii"))
        digest.update(b"\0")
        digest.update(item["sha256"].encode("ascii"))
        digest.update(b"\n")
    record = {
        "candidate": candidate,
        "contract": "sos_windows_msix_source_manifest_v1",
        "file_count": len(files),
        "files": files,
        "inventory_digest": f"sha256:{digest.hexdigest()}",
        "tree": tree,
    }
    destination.write_text(
        json.dumps(record, sort_keys=True, separators=(",", ":")) + "\n",
        encoding="utf-8",
    )


def payload_record(artifacts: dict[str, bytes]) -> bytes:
    return (
        json.dumps(
            {
                "artifacts": [
                    {"path": path, "sha256": hashlib.sha256(content).hexdigest()}
                    for path, content in sorted(artifacts.items())
                ],
                "candidate": CANDIDATE,
                "contract": "sos_windows_msix_payload_v1",
                "executable_acquisition_after_install": False,
                "msix_version": "0.1.0.2",
                "network_after_package_download": False,
                "platform": "windows-x86_64",
                "sos_version": "0.1.0a2",
                "tree": TREE,
            },
            sort_keys=True,
            separators=(",", ":"),
        )
        + "\n"
    ).encode()


def unpack_fixture(root: Path, artifacts: dict[str, bytes]) -> None:
    for relative, content in artifacts.items():
        write_file(root, relative, content)
    generated = {
        "AppxManifest.xml": b"<Package/>",
        "Assets/Square150x150Logo.png": b"png150",
        "Assets/Square44x44Logo.png": b"png44",
        "payload-manifest.json": payload_record(artifacts),
    }
    for relative, content in generated.items():
        write_file(root, relative, content)
    block_files = {
        **artifacts,
        **generated,
    }
    records = []
    for path, content in sorted(block_files.items()):
        blocks = "".join(
            '<Block Hash="'
            + base64.b64encode(hashlib.sha256(content[offset : offset + 65536]).digest()).decode()
            + '" />'
            for offset in range(0, len(content), 65536)
        )
        if len(content) > 65536:
            blocks += (
                '<b4:FileHash Hash="'
                + base64.b64encode(hashlib.sha256(content).digest()).decode()
                + '" />'
            )
        records.append(
            f'<File Name="{html.escape(path.replace("/", chr(92)))}" '
            f'Size="{len(content)}" LfhSize="40">{blocks}</File>'
        )
    write_file(
        root,
        "AppxBlockMap.xml",
        (
            '<BlockMap xmlns="http://schemas.microsoft.com/appx/2010/blockmap" '
            'xmlns:b4="http://schemas.microsoft.com/appx/2021/blockmap" '
            'IgnorableNamespaces="b4" '
            'HashMethod="http://www.w3.org/2001/04/xmlenc#sha256">'
            + "".join(records)
            + "</BlockMap>"
        ).encode(),
    )


class WindowsMSIXTests(unittest.TestCase):
    def comparator_command(
        self, first_msix: Path, second_msix: Path, first: Path, second: Path
    ) -> list[str]:
        return [
            sys.executable,
            os.fspath(ROOT / "tools/compare_windows_msix.py"),
            os.fspath(first_msix),
            os.fspath(second_msix),
            "--first-unpacked",
            os.fspath(first),
            "--second-unpacked",
            os.fspath(second),
            "--candidate",
            CANDIDATE,
            "--tree",
            TREE,
            "--makeappx-sha256",
            MAKEAPPX_SHA,
        ]

    def test_semantic_comparator_accepts_different_containers_with_exact_trees(self) -> None:
        artifacts = {
            "bootstrap/uv.exe": b"MZuv",
            "runtime/Lib/site-packages/sos/__init__.py": b"version",
            "runtime/large.bin": b"x" * 70000,
            "runtime/python.exe": b"MZpython",
            "sos.exe": b"MZsos",
            "wheelhouse/sigma_operator_stack-0.1.0a2-py3-none-any.whl": b"wheel",
        }
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            first = root / "first-unpacked"
            second = root / "second-unpacked"
            first.mkdir()
            second.mkdir()
            unpack_fixture(first, artifacts)
            unpack_fixture(second, artifacts)
            first_msix = root / "first.msix"
            second_msix = root / "second.msix"
            first_msix.write_bytes(b"container-one")
            second_msix.write_bytes(b"container-two")
            completed = subprocess.run(
                self.comparator_command(first_msix, second_msix, first, second),
                check=True,
                stdout=subprocess.PIPE,
                text=True,
            )
            report = json.loads(completed.stdout)
            self.assertEqual(report["status"], "passed")
            self.assertFalse(report["byte_identical"])
            self.assertFalse(report["container_equivalence_claimed"])
            self.assertEqual(
                report["verification_method"],
                "default_makeappx_unpack_exact_content_v1",
            )
            self.assertEqual(report["pyc_file_count"], 0)

    def test_semantic_comparator_rejects_content_inventory_and_binding_drift(self) -> None:
        artifacts = {
            "bootstrap/uv.exe": b"MZuv",
            "runtime/python.exe": b"MZpython",
            "sos.exe": b"MZsos",
            "wheelhouse/sigma_operator_stack-0.1.0a2-py3-none-any.whl": b"wheel",
        }
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            first_msix = root / "first.msix"
            second_msix = root / "second.msix"
            first_msix.write_bytes(b"first")
            second_msix.write_bytes(b"second")
            for case in (
                "content",
                "extra",
                "candidate",
                "pyc",
                "case-collision",
                "block-hash",
                "block-child",
                "file-hash",
                "file-hash-order",
                "file-hash-duplicate",
            ):
                with self.subTest(case=case):
                    first = root / f"{case}-first"
                    second = root / f"{case}-second"
                    first.mkdir()
                    second.mkdir()
                    case_artifacts = dict(artifacts)
                    if case.startswith("file-hash"):
                        case_artifacts["runtime/large.bin"] = b"x" * 70000
                    unpack_fixture(first, case_artifacts)
                    unpack_fixture(second, case_artifacts)
                    if case == "content":
                        (second / "sos.exe").write_bytes(b"drift")
                    elif case == "extra":
                        (second / "unexpected.txt").write_text("extra", encoding="utf-8")
                    elif case == "candidate":
                        record = json.loads((second / "payload-manifest.json").read_text())
                        record["candidate"] = "f" * 40
                        (second / "payload-manifest.json").write_text(
                            json.dumps(record, sort_keys=True, separators=(",", ":")) + "\n",
                            encoding="utf-8",
                        )
                    elif case == "pyc":
                        pyc = b"bytecode"
                        for directory in (first, second):
                            write_file(directory, "runtime/Lib/__pycache__/x.cpython-312.pyc", pyc)
                            record = json.loads((directory / "payload-manifest.json").read_text())
                            record["artifacts"].append(
                                {
                                    "path": "runtime/Lib/__pycache__/x.cpython-312.pyc",
                                    "sha256": hashlib.sha256(pyc).hexdigest(),
                                }
                            )
                            record["artifacts"].sort(key=lambda item: item["path"])
                            (directory / "payload-manifest.json").write_text(
                                json.dumps(record, sort_keys=True, separators=(",", ":")) + "\n",
                                encoding="utf-8",
                            )
                    else:
                        if case == "case-collision":
                            for directory in (first, second):
                                (directory / "Readme").write_bytes(b"a")
                                (directory / "README").write_bytes(b"b")
                        elif case == "block-hash":
                            for directory in (first, second):
                                block_map = directory / "AppxBlockMap.xml"
                                value = block_map.read_text(encoding="utf-8")
                                value = value.replace('Hash="', 'Hash="AAAA', 1)
                                block_map.write_text(value, encoding="utf-8")
                        elif case == "block-child":
                            for directory in (first, second):
                                block_map = directory / "AppxBlockMap.xml"
                                value = block_map.read_text(encoding="utf-8")
                                value = value.replace("<Block Hash=", "<Unexpected Hash=", 1)
                                block_map.write_text(value, encoding="utf-8")
                        else:
                            for directory in (first, second):
                                block_map = directory / "AppxBlockMap.xml"
                                value = block_map.read_text(encoding="utf-8")
                                entry_start = value.index('<File Name="runtime\\large.bin"')
                                entry_end = value.index("</File>", entry_start) + len("</File>")
                                entry = value[entry_start:entry_end]
                                hash_start = entry.index("<b4:FileHash")
                                hash_end = entry.index("/>", hash_start) + 2
                                file_hash = entry[hash_start:hash_end]
                                if case == "file-hash":
                                    changed = file_hash.replace('Hash="', 'Hash="AAAA', 1)
                                    entry = entry.replace(file_hash, changed, 1)
                                elif case == "file-hash-order":
                                    entry = entry.replace(file_hash, "", 1)
                                    entry = entry.replace(">", ">" + file_hash, 1)
                                else:
                                    entry = entry.replace(file_hash, file_hash + file_hash, 1)
                                value = value[:entry_start] + entry + value[entry_end:]
                                block_map.write_text(value, encoding="utf-8")
                    completed = subprocess.run(
                        self.comparator_command(first_msix, second_msix, first, second),
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                        text=True,
                    )
                    self.assertEqual(completed.returncode, 2)
                    self.assertIn("SOS_MSIX_SEMANTIC_COMPARISON_FAILED", completed.stderr)
                    if case == "file-hash":
                        self.assertIn("file hash differs", completed.stderr)
                    elif case in ("file-hash-order", "file-hash-duplicate"):
                        self.assertIn("file child record is invalid", completed.stderr)

    def test_payload_preparation_removes_only_source_backed_bytecode(self) -> None:
        tool = ROOT / "tools/prepare_windows_msix_payload.py"
        with tempfile.TemporaryDirectory() as temporary:
            payload = Path(temporary) / "payload"
            cache = payload / "runtime/Lib/encodings/__pycache__"
            cache.mkdir(parents=True)
            (payload / ".sos-msix-disposable-payload-v1").write_bytes(
                b"sos-windows-msix-disposable-payload-v1\n"
            )
            (payload / "runtime/Lib/encodings/cp437.py").write_text("value = 1\n")
            (cache / "cp437.cpython-312.pyc").write_bytes(b"bytecode")
            retained = payload / "runtime/keep.txt"
            retained.write_text("keep", encoding="utf-8")
            completed = subprocess.run(
                [sys.executable, os.fspath(tool), "--payload-root", os.fspath(payload)],
                check=True,
                stdout=subprocess.PIPE,
                text=True,
            )
            report = json.loads(completed.stdout)
            self.assertEqual(report["removed_bytecode_count"], 1)
            self.assertEqual(report["removed_cache_directory_count"], 1)
            self.assertEqual(retained.read_text(encoding="utf-8"), "keep")
            self.assertFalse(cache.exists())
            self.assertFalse((payload / ".sos-msix-disposable-payload-v1").exists())

    def test_payload_preparation_rejects_missing_marker_and_bytecode_only_module(self) -> None:
        tool = ROOT / "tools/prepare_windows_msix_payload.py"
        with tempfile.TemporaryDirectory() as temporary:
            payload = Path(temporary) / "payload"
            payload.mkdir()
            missing = subprocess.run(
                [sys.executable, os.fspath(tool), "--payload-root", os.fspath(payload)],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            self.assertEqual(missing.returncode, 2)
            self.assertIn("ownership marker is missing", missing.stderr)
            (payload / ".sos-msix-disposable-payload-v1").write_bytes(
                b"sos-windows-msix-disposable-payload-v1\n"
            )
            cache = payload / "__pycache__"
            cache.mkdir()
            (cache / "only.cpython-312.pyc").write_bytes(b"only")
            bytecode_only = subprocess.run(
                [sys.executable, os.fspath(tool), "--payload-root", os.fspath(payload)],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            self.assertEqual(bytecode_only.returncode, 2)
            self.assertIn("bytecode-only Python module is unsupported", bytecode_only.stderr)

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

    def test_launcher_disables_bytecode_writes_and_acquisition(self) -> None:
        source = (ROOT / "installers/windows-msix/main.go").read_text(encoding="utf-8")
        for required in (
            'filepath.Join(packageRoot, "runtime", "python.exe")',
            '"PYTHONDONTWRITEBYTECODE=1"',
            '"PYTHONNOUSERSITE=1"',
            '"PYTHONSAFEPATH=1"',
            'exec.Command(python, arguments...)',
            '[]string{"-B", "-m", "sos", "init", "--with-codex"',
            '[]string{"-B", "-m", "sos", "setup", arguments[0], "codex"',
        ):
            self.assertIn(required, source)
        for forbidden in ("cmd.exe", "powershell", "uv python install", "http://", "https://"):
            self.assertNotIn(forbidden, source.lower())

    def test_unsigned_builder_binds_payload_stage_source_and_makeappx(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "source"
            for relative in (
                "installers/windows-msix/AppxManifest.xml.in",
                "installers/windows-msix/store-identity.json",
                "tools/build_windows_msix.py",
                "tools/verify_windows_msix_source.py",
            ):
                destination = source / relative
                destination.parent.mkdir(parents=True, exist_ok=True)
                destination.write_bytes((ROOT / relative).read_bytes())
            source_manifest = root / "source-manifest.json"
            write_source_manifest(source, source_manifest, CANDIDATE, TREE)
            payload = root / "payload"
            required = {
                "sos.exe": b"MZlauncher",
                "runtime/python.exe": b"MZpython",
                "runtime/Lib/site-packages/sos/__init__.py": b'version="0.1.0a2"\n',
                "bootstrap/uv.exe": b"MZuv",
                "wheelhouse/sigma_operator_stack-0.1.0a2-py3-none-any.whl": b"PKwheel",
            }
            for relative, content in required.items():
                write_file(payload, relative, content)
            makeappx = root / "makeappx"
            makeappx.write_text(
                "#!/usr/bin/env python3\n"
                "import pathlib,sys\n"
                "args=sys.argv[1:]; assert args[0]=='pack'\n"
                "source=pathlib.Path(args[args.index('/d')+1]); output=pathlib.Path(args[args.index('/p')+1])\n"
                "output.write_bytes(b'MSIX'+str(len([p for p in source.rglob('*') if p.is_file()])).encode())\n",
                encoding="utf-8",
            )
            makeappx.chmod(0o700)
            makeappx_digest = hashlib.sha256(makeappx.read_bytes()).hexdigest()
            output = root / "SOS.msix"
            command = [
                sys.executable,
                os.fspath(ROOT / "tools/build_windows_msix.py"),
                "--source-root",
                os.fspath(source),
                "--source-manifest",
                os.fspath(source_manifest),
                "--candidate",
                CANDIDATE,
                "--tree",
                TREE,
                "--payload-root",
                os.fspath(payload),
                "--makeappx",
                os.fspath(makeappx),
                "--makeappx-sha256",
                makeappx_digest,
                "--output",
                os.fspath(output),
            ]
            completed = subprocess.run(
                command, check=True, stdout=subprocess.PIPE, text=True
            )
            report = json.loads(completed.stdout)
            self.assertEqual(report["status"], "passed")
            self.assertRegex(report["payload_tree_digest"], r"^sha256:[0-9a-f]{64}$")
            self.assertRegex(report["stage_tree_digest"], r"^sha256:[0-9a-f]{64}$")
            self.assertTrue(output.is_file())

            pyc = payload / "runtime/Lib/__pycache__/x.cpython-312.pyc"
            pyc.parent.mkdir(parents=True)
            pyc.write_bytes(b"bytecode")
            rejected = subprocess.run(
                [*command[:-1], os.fspath(root / "bad.msix")],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            self.assertNotEqual(rejected.returncode, 0)
            self.assertIn("Python bytecode is forbidden", rejected.stderr)

    def test_unsigned_builder_rejects_payload_mutation_during_pack(self) -> None:
        source = (ROOT / "tools/build_windows_msix.py").read_text(encoding="utf-8")
        for required in (
            "payload_inventory(stage) != stage_before",
            "payload_inventory(payload_root) != inventory",
            "sha256(makeappx) != makeappx_before",
            "source_verifier.verify_source_snapshot",
            "source_verifier.same_snapshot",
        ):
            self.assertIn(required, source)
        self.assertNotIn("--repository", source)
        self.assertNotIn("git(", source)

    def test_native_packet_runner_replaces_shell_and_path_discovery(self) -> None:
        sources = "\n".join(
            path.read_text(encoding="utf-8")
            for path in sorted((ROOT / "installers/windows-msix-builder").glob("*.go"))
            if not path.name.endswith("_test.go")
        ).lower()
        for required in (
            "build-sos-msix.exe",
            "currentprocesselevated",
            "useraccountcontrolenabled",
            "verifyregularfile",
            "hasunexpectedstreams",
            "inspectpipelineoutput",
            "samefilebindings",
        ):
            self.assertIn(required, sources)
        for forbidden in (
            "powershell",
            "cmd.exe",
            "certutil",
            "git.exe",
            "tar.exe",
            "lookpath(",
        ):
            self.assertNotIn(forbidden, sources)

    def test_native_runner_builder_is_offline_and_reproducible_by_contract(self) -> None:
        source = (ROOT / "tools/build_windows_msix_builder.py").read_text(
            encoding="utf-8"
        )
        for required in (
            'GO_VERSION = "go1.27.0"',
            '"GOPROXY": "off"',
            '"GOSUMDB": "off"',
            '"GOTOOLCHAIN": "local"',
            '"CGO_ENABLED": "0"',
            '"GOOS": "windows"',
            '"-buildvcs=false"',
            '"-trimpath"',
            '"-buildid= -s -w "',
            '"--input-lock-sha256"',
            '"-X main.inputLockDigest=',
            'input_lock_digest.encode("ascii") not in payload',
            '"verify-pe"',
            "first_bytes != second_bytes",
            "executing builder is not the exact candidate tool",
        ):
            self.assertIn(required, source)
        for go_source in sorted(
            (ROOT / "installers/windows-msix-builder").glob("*.go")
        ):
            self.assertIn(
                f'"installers/windows-msix-builder/{go_source.name}"', source
            )

    def test_pipeline_uses_two_default_unpacks_and_exact_semantic_comparison(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "source"
            for relative in (
                "installers/windows-msix/AppxManifest.xml.in",
                "installers/windows-msix/store-identity.json",
                "tools/build_windows_msix.py",
                "tools/build_windows_msix_pipeline.py",
                "tools/check_windows_msix_content.py",
                "tools/compare_windows_msix.py",
                "tools/verify_windows_msix_source.py",
            ):
                destination = source / relative
                destination.parent.mkdir(parents=True, exist_ok=True)
                destination.write_bytes((ROOT / relative).read_bytes())
            source_manifest = root / "source-manifest.json"
            write_source_manifest(source, source_manifest, CANDIDATE, TREE)
            payload = root / "payload"
            for relative, content in {
                "sos.exe": b"MZlauncher",
                "runtime/python.exe": b"MZpython",
                "runtime/Lib/site-packages/sos/__init__.py": b'version="0.1.0a2"\n',
                "bootstrap/uv.exe": b"MZuv",
                "wheelhouse/sigma_operator_stack-0.1.0a2-py3-none-any.whl": b"PKwheel",
            }.items():
                write_file(payload, relative, content)
            makeappx = root / "MakeAppx.exe"
            makeappx.write_text(
                "#!/usr/bin/env python3\n"
                "import base64,hashlib,pathlib,shutil,sys\n"
                "a=sys.argv[1:]; mode=a[0]\n"
                "if mode=='pack':\n"
                " s=pathlib.Path(a[a.index('/d')+1]); p=pathlib.Path(a[a.index('/p')+1]); t=p.with_suffix('.tree'); shutil.copytree(s,t); (t/'[Content_Types].xml').write_text('<Types/>'); fs=[x for x in sorted(t.rglob('*')) if x.is_file() and x.name!='[Content_Types].xml']; rs='';\n"
                " for x in fs:\n"
                "  b=x.read_bytes(); bs=''.join('<Block Hash=\"'+base64.b64encode(hashlib.sha256(b[o:o+65536]).digest()).decode()+'\" />' for o in range(0,len(b),65536)); rs+=f'<File Name=\"{x.relative_to(t).as_posix().replace(chr(47),chr(92))}\" Size=\"{len(b)}\" LfhSize=\"40\">{bs}</File>'\n"
                " (t/'AppxBlockMap.xml').write_text('<BlockMap xmlns=\"http://schemas.microsoft.com/appx/2010/blockmap\" HashMethod=\"http://www.w3.org/2001/04/xmlenc#sha256\">'+rs+'</BlockMap>'); p.write_bytes(b'MSIX-'+p.name.encode())\n"
                "elif mode=='unpack':\n"
                " p=pathlib.Path(a[a.index('/p')+1]); d=pathlib.Path(a[a.index('/d')+1]); sys.stdout.write('x'*(600*1024)); shutil.copytree(p.with_suffix('.tree'),d,dirs_exist_ok=True); (d/'[Content_Types].xml').unlink()\n"
                "else: raise SystemExit(9)\n",
                encoding="utf-8",
            )
            makeappx.chmod(0o700)
            digest = hashlib.sha256(makeappx.read_bytes()).hexdigest()
            output = root / "output"
            completed = subprocess.run(
                [
                    sys.executable,
                    os.fspath(ROOT / "tools/build_windows_msix_pipeline.py"),
                    "--source-root",
                    os.fspath(source),
                    "--source-manifest",
                    os.fspath(source_manifest),
                    "--candidate",
                    CANDIDATE,
                    "--tree",
                    TREE,
                    "--payload-root",
                    os.fspath(payload),
                    "--makeappx",
                    os.fspath(makeappx),
                    "--makeappx-sha256",
                    digest,
                    "--output-root",
                    os.fspath(output),
                ],
                check=True,
                stdout=subprocess.PIPE,
                text=True,
            )
            result = json.loads(completed.stdout)
            self.assertEqual(result["status"], "passed")
            self.assertEqual(
                result["verification_method"],
                "two_pack_two_default_unpack_exact_content_v1",
            )
            comparison = json.loads(
                (output / "msix-comparison.json").read_text(encoding="utf-8")
            )
            self.assertFalse(comparison["byte_identical"])
            self.assertEqual(comparison["pyc_file_count"], 0)
            first_content = json.loads(
                (output / "first-content-safety.json").read_text(encoding="utf-8")
            )
            second_content = json.loads(
                (output / "second-content-safety.json").read_text(encoding="utf-8")
            )
            self.assertEqual(first_content, second_content)
            self.assertEqual(first_content["status"], "passed")
            self.assertTrue((output / "SigmaOperatorStack_0.1.0.2_x64.msix").is_file())


if __name__ == "__main__":
    unittest.main()
