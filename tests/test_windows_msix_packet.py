from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SOURCE_FILES = (
    "installers/windows-msix/AppxManifest.xml.in",
    "installers/windows-msix/assets/Square44x44Logo.png",
    "installers/windows-msix/assets/Square50x50Logo.png",
    "installers/windows-msix/assets/Square150x150Logo.png",
    "installers/windows-msix/store-identity.json",
    "tools/build_windows_msix.py",
    "tools/build_windows_msix_pipeline.py",
    "tools/check_windows_msix_content.py",
    "tools/compare_windows_msix.py",
    "tools/prepare_windows_msix_payload.py",
    "tools/verify_windows_msix_source.py",
)
WHEELS = (
    "attrs-26.1.0-py3-none-any.whl",
    "jsonschema-4.26.0-py3-none-any.whl",
    "jsonschema_specifications-2025.9.1-py3-none-any.whl",
    "referencing-0.37.0-py3-none-any.whl",
    "rpds_py-2026.6.3-cp312-cp312-win_amd64.whl",
    "sigma_operator_stack-0.1.0a2-py3-none-any.whl",
    "typing_extensions-4.16.0-py3-none-any.whl",
)
MAKEAPPX_SHA = "0123456789abcdef" * 4


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


class WindowsMSIXPacketTests(unittest.TestCase):
    def test_packet_source_snapshot_includes_exact_store_icons(self) -> None:
        source = (ROOT / "tools/build_windows_msix_packet.py").read_text(
            encoding="utf-8"
        )
        for name in (
            "Square44x44Logo.png",
            "Square50x50Logo.png",
            "Square150x150Logo.png",
        ):
            self.assertEqual(
                source.count(f'"installers/windows-msix/assets/{name}"'), 1
            )

    def fixture(self, root: Path) -> dict[str, Path | str]:
        repository = root / "repository"
        for relative in SOURCE_FILES:
            target = repository / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes((ROOT / relative).read_bytes())
        packet_tool = repository / "tools/build_windows_msix_packet.py"
        packet_tool.parent.mkdir(parents=True, exist_ok=True)
        packet_tool.write_bytes((ROOT / "tools/build_windows_msix_packet.py").read_bytes())
        native_builder = repository / "tools/build_windows_msix_builder.py"
        native_builder.write_text(
            "#!/usr/bin/env python3\n"
            "import argparse,hashlib,json,pathlib,subprocess\n"
            "p=argparse.ArgumentParser()\n"
            "for name in ('--repository','--candidate','--git','--git-sha256','--go','--go-sha256','--input-lock-sha256','--output'): p.add_argument(name)\n"
            "a=p.parse_args()\n"
            "tree=subprocess.run([a.git,'-C',a.repository,'show','-s','--format=%T',a.candidate],check=True,stdout=subprocess.PIPE,text=True).stdout.strip()\n"
            "mode=pathlib.Path(a.go).read_text(encoding='utf-8')\n"
            "bound_lock='' if 'omit-lock' in mode else a.input_lock_sha256\n"
            "receipt_lock='0'*64 if 'wrong-lock' in mode else a.input_lock_sha256\n"
            "value=b'MZ-native-runner-'+a.candidate.encode()+b'-'+tree.encode()+b'-'+bound_lock.encode()\n"
            "pathlib.Path(a.output).write_bytes(value)\n"
            "record={'candidate':a.candidate,'contract':'sos_windows_msix_builder_build_v1','go_sha256':'sha256:'+a.go_sha256,'go_version':'go1.27.0','input_lock_sha256':'sha256:'+receipt_lock,'manifest_sha256':'0'*64,'runner_sha256':'sha256:'+hashlib.sha256(value).hexdigest(),'status':'passed','tree':tree}\n"
            "print(json.dumps(record,sort_keys=True,separators=(',',':')))\n",
            encoding="utf-8",
        )
        subprocess.run(["git", "init", "-q", os.fspath(repository)], check=True)
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
                "fixture",
            ],
            check=True,
        )
        candidate = subprocess.run(
            ["git", "-C", os.fspath(repository), "rev-parse", "HEAD"],
            check=True,
            stdout=subprocess.PIPE,
            text=True,
        ).stdout.strip()
        tree = subprocess.run(
            ["git", "-C", os.fspath(repository), "show", "-s", "--format=%T", "HEAD"],
            check=True,
            stdout=subprocess.PIPE,
            text=True,
        ).stdout.strip()
        go = root / "go"
        go.write_text(
            "#!/bin/sh\nprintf 'go version go1.27.0 linux/amd64\\n'\n# normal\n",
            encoding="utf-8",
        )
        go.chmod(0o700)
        sos = root / "sos.exe"
        sos.write_bytes(b"MZ-sos")
        uv = root / "uv.exe"
        uv.write_bytes(b"MZ-uv")
        runtime = root / "windows-python-runtime-3.12.14.zip"
        runtime.write_bytes(b"PK-runtime")
        wheelhouse = root / "wheelhouse"
        wheelhouse.mkdir()
        for name in WHEELS:
            (wheelhouse / name).write_bytes(b"PK-" + name.encode())
        git = Path(shutil.which("git") or "").resolve(strict=True)
        return {
            "candidate": candidate,
            "git": git,
            "git_sha": digest(git),
            "repository": repository,
            "go": go,
            "go_sha": digest(go),
            "runtime": runtime,
            "sos": sos,
            "tree": tree,
            "uv": uv,
            "wheelhouse": wheelhouse,
        }

    def command(self, values: dict[str, Path | str], output: Path) -> list[str]:
        return [
            sys.executable,
            os.fspath(ROOT / "tools/build_windows_msix_packet.py"),
            "--repository",
            os.fspath(values["repository"]),
            "--candidate",
            str(values["candidate"]),
            "--git",
            os.fspath(values["git"]),
            "--git-sha256",
            str(values["git_sha"]),
            "--go",
            os.fspath(values["go"]),
            "--go-sha256",
            str(values["go_sha"]),
            "--sos-launcher",
            os.fspath(values["sos"]),
            "--uv",
            os.fspath(values["uv"]),
            "--python-runtime",
            os.fspath(values["runtime"]),
            "--wheelhouse",
            os.fspath(values["wheelhouse"]),
            "--sdk-version",
            "10.0.28000.0",
            "--makeappx-sha256",
            MAKEAPPX_SHA,
            "--makeappx-size",
            "1234567",
            "--output",
            os.fspath(output),
        ]

    def test_packet_is_byte_reproducible_and_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            values = self.fixture(root)
            first = root / "first.zip"
            second = root / "second.zip"
            for output in (first, second):
                completed = subprocess.run(
                    self.command(values, output),
                    check=True,
                    stdout=subprocess.PIPE,
                    text=True,
                )
                report = json.loads(completed.stdout)
                self.assertEqual(report["status"], "passed")
                self.assertEqual(report["packet_sha256"], f"sha256:{digest(output)}")
            self.assertEqual(first.read_bytes(), second.read_bytes())
            with zipfile.ZipFile(first) as archive:
                names = archive.namelist()
                self.assertEqual(names, sorted(names))
                self.assertEqual(len(names), len(set(names)))
                manifest_name = next(
                    name for name in names if name.endswith("/packet-manifest.json")
                )
                manifest = json.loads(archive.read(manifest_name))
                prefix = manifest_name.removesuffix("packet-manifest.json")
                observed = {
                    name.removeprefix(prefix) for name in names if name != manifest_name
                }
                self.assertEqual(
                    observed, {item["path"] for item in manifest["files"]}
                )
                self.assertEqual(manifest["file_count"], len(observed))
                self.assertEqual(manifest["runner"], "Build-SOS-MSIX.exe")
                self.assertEqual(manifest["source_manifest"], "source-manifest.json")
                self.assertEqual(manifest["input_lock"], "input-lock.json")
                lock_name = prefix + manifest["input_lock"]
                lock_bytes = archive.read(lock_name)
                self.assertEqual(
                    lock_bytes,
                    (
                        json.dumps(
                            json.loads(lock_bytes),
                            sort_keys=True,
                            separators=(",", ":"),
                        )
                        + "\n"
                    ).encode("utf-8"),
                )
                lock = json.loads(lock_bytes)
                self.assertEqual(
                    set(lock),
                    {
                        "candidate",
                        "contract",
                        "git",
                        "go",
                        "makeappx",
                        "python_runtime",
                        "sos_launcher",
                        "source_manifest",
                        "tree",
                        "uv",
                        "wheelhouse",
                    },
                )
                self.assertEqual(lock["contract"], "sos_windows_msix_input_lock_v1")
                self.assertEqual(lock["candidate"], values["candidate"])
                self.assertEqual(lock["tree"], values["tree"])
                self.assertEqual(lock["git"]["sha256"], values["git_sha"])
                self.assertRegex(lock["git"]["version"], r"^git version ")
                self.assertEqual(lock["go"]["sha256"], values["go_sha"])
                self.assertEqual(lock["go"]["version"], "go1.27.0")
                self.assertEqual(
                    [item["path"] for item in lock["wheelhouse"]],
                    [f"wheelhouse/{name}" for name in WHEELS],
                )
                bindings = {item["path"]: item for item in manifest["files"]}
                for name in (
                    "source_manifest",
                    "sos_launcher",
                    "python_runtime",
                    "uv",
                ):
                    self.assertEqual(lock[name], bindings[lock[name]["path"]])
                for binding in lock["wheelhouse"]:
                    self.assertEqual(binding, bindings[binding["path"]])
                lock_binding = bindings["input-lock.json"]
                self.assertEqual(lock_binding["size"], len(lock_bytes))
                self.assertEqual(
                    lock_binding["sha256"], hashlib.sha256(lock_bytes).hexdigest()
                )
                runner = archive.read(prefix + manifest["runner"])
                self.assertIn(lock_binding["sha256"].encode("ascii"), runner)

    def test_packet_rejects_extra_wheel_placeholder_and_unbound_go(self) -> None:
        for case in ("extra", "placeholder", "go"):
            with self.subTest(case=case), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                values = self.fixture(root)
                command = self.command(values, root / "packet.zip")
                if case == "extra":
                    (Path(values["wheelhouse"]) / "extra.whl").write_bytes(b"PK-extra")
                elif case == "placeholder":
                    index = command.index("--makeappx-sha256") + 1
                    command[index] = "3" * 64
                else:
                    Path(values["go"]).write_bytes(b"drifted-go")
                completed = subprocess.run(
                    command,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                )
                self.assertEqual(completed.returncode, 2)
                self.assertIn("SOS_MSIX_PACKET_BUILD_FAILED", completed.stderr)

    def test_packet_rejects_dirty_or_drifting_source(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            values = self.fixture(root)
            (Path(values["repository"]) / SOURCE_FILES[0]).write_text("drift")
            completed = subprocess.run(
                self.command(values, root / "packet.zip"),
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            self.assertEqual(completed.returncode, 2)
            self.assertIn("repository must be clean", completed.stderr)

    def test_packet_rejects_runner_with_wrong_or_missing_input_lock(self) -> None:
        for mode in ("wrong-lock", "omit-lock"):
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                values = self.fixture(root)
                go = Path(values["go"])
                go.write_text(
                    "#!/bin/sh\nprintf 'go version go1.27.0 linux/amd64\\n'\n"
                    f"# {mode}\n",
                    encoding="utf-8",
                )
                go.chmod(0o700)
                values["go_sha"] = digest(go)
                completed = subprocess.run(
                    self.command(values, root / "packet.zip"),
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                )
                self.assertEqual(completed.returncode, 2)
                self.assertIn("SOS_MSIX_PACKET_BUILD_FAILED", completed.stderr)
                if mode == "wrong-lock":
                    self.assertIn("build receipt binding is invalid", completed.stderr)
                else:
                    self.assertIn("artifact binding is invalid", completed.stderr)

    def test_packet_rejects_untrusted_toolchain_version_observations(self) -> None:
        for tool in ("go", "git"):
            with self.subTest(tool=tool), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                values = self.fixture(root)
                if tool == "go":
                    executable = Path(values["go"])
                    executable.write_text(
                        "#!/bin/sh\nprintf 'go version go1.26.0 linux/amd64\\n'\n",
                        encoding="utf-8",
                    )
                    executable.chmod(0o700)
                    values["go_sha"] = digest(executable)
                else:
                    system_git = Path(values["git"])
                    executable = root / "git-wrapper"
                    executable.write_text(
                        "#!/bin/sh\n"
                        "if [ \"$1\" = \"--version\" ]; then printf 'untrusted-git\\n'; exit 0; fi\n"
                        f'exec "{system_git}" "$@"\n',
                        encoding="utf-8",
                    )
                    executable.chmod(0o700)
                    values["git"] = executable
                    values["git_sha"] = digest(executable)
                completed = subprocess.run(
                    self.command(values, root / "packet.zip"),
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                )
                self.assertEqual(completed.returncode, 2)
                self.assertIn("SOS_MSIX_PACKET_BUILD_FAILED", completed.stderr)
                self.assertIn(
                    "pinned Go toolchain version mismatch"
                    if tool == "go"
                    else "Git version observation is invalid",
                    completed.stderr,
                )

    def test_native_builder_rejects_malformed_input_lock_digest_before_io(self) -> None:
        completed = subprocess.run(
            [
                sys.executable,
                os.fspath(ROOT / "tools/build_windows_msix_builder.py"),
                "--repository",
                ".",
                "--candidate",
                "a" * 40,
                "--git",
                "/unavailable/git",
                "--git-sha256",
                "b" * 64,
                "--go",
                "/unavailable/go",
                "--go-sha256",
                "c" * 64,
                "--input-lock-sha256",
                "not-a-digest",
                "--output",
                "Build-SOS-MSIX.exe",
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        self.assertEqual(completed.returncode, 2)
        self.assertIn("input lock digest binding is invalid", completed.stderr)


if __name__ == "__main__":
    unittest.main()
