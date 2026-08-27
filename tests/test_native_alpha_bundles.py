from __future__ import annotations

import importlib.util
import hashlib
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]


def _load(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot import {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


alpha = _load("sos_native_alpha_launcher", ROOT / "tools/start_sos_alpha.py")
smoke = _load("sos_native_alpha_smoke", ROOT / "tools/native_alpha_smoke.py")


class NativeAlphaBundleTests(unittest.TestCase):
    def test_windows_installer_builder_rejects_dirty_or_mismatched_source(self) -> None:
        builder = ROOT / "tools/build_windows_installer.py"
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            repository = root / "repository"
            source = repository / "installers/windows-installer"
            source.mkdir(parents=True)
            (source / "go.mod").write_text("module example.invalid/sos\n", encoding="utf-8")
            (source / "main.go").write_text("package main\nfunc main() {}\n", encoding="utf-8")
            subprocess.run(["git", "init", "-q", os.fspath(repository)], check=True)
            subprocess.run(["git", "-C", os.fspath(repository), "add", "."], check=True)
            subprocess.run(
                [
                    "git", "-C", os.fspath(repository),
                    "-c", "user.name=SOS Test", "-c", "user.email=sos@example.invalid",
                    "commit", "-qm", "fixture",
                ],
                check=True,
            )
            candidate = subprocess.run(
                ["git", "-C", os.fspath(repository), "rev-parse", "HEAD"],
                check=True, stdout=subprocess.PIPE, text=True,
            ).stdout.strip()
            fake_go = root / "go"
            fake_go.write_text(
                "#!/usr/bin/env python3\n"
                "import pathlib,sys\n"
                "if sys.argv[1:] == ['version']:\n"
                " print('go version go1.27.0 linux/amd64')\n"
                "else:\n"
                " out=pathlib.Path(sys.argv[sys.argv.index('-o')+1])\n"
                " out.write_bytes(b'MZ'+pathlib.Path('main.go').read_bytes())\n",
                encoding="utf-8",
            )
            fake_go.chmod(0o700)

            def build(ref: str) -> subprocess.CompletedProcess[str]:
                return subprocess.run(
                    [
                        sys.executable, os.fspath(builder),
                        "--repository", os.fspath(repository),
                        "--candidate", ref,
                        "--go", os.fspath(fake_go),
                        "--output", os.fspath(root / "SOS-Installer.exe"),
                    ],
                    stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                )

            clean = build(candidate)
            self.assertEqual(clean.returncode, 0, clean.stderr)
            report = json.loads(clean.stdout)
            expected_tree = subprocess.run(
                ["git", "-C", os.fspath(repository), "rev-parse", "HEAD^{tree}"],
                check=True, stdout=subprocess.PIPE, text=True,
            ).stdout.strip()
            self.assertEqual(report["source_tree"], expected_tree)

            (source / "main.go").write_text("package main\n// dirty\nfunc main() {}\n", encoding="utf-8")
            dirty = build(candidate)
            self.assertNotEqual(dirty.returncode, 0)
            self.assertIn("worktree is not clean", dirty.stderr)

            subprocess.run(["git", "-C", os.fspath(repository), "restore", "."], check=True)
            (repository / "second.txt").write_text("second\n", encoding="utf-8")
            subprocess.run(["git", "-C", os.fspath(repository), "add", "."], check=True)
            subprocess.run(
                [
                    "git", "-C", os.fspath(repository),
                    "-c", "user.name=SOS Test", "-c", "user.email=sos@example.invalid",
                    "commit", "-qm", "second",
                ],
                check=True,
            )
            mismatch = build(candidate)
            self.assertNotEqual(mismatch.returncode, 0)
            self.assertIn("candidate does not match repository HEAD", mismatch.stderr)

    def test_native_windows_entrypoint_does_not_depend_on_powershell_policy(self) -> None:
        source = (ROOT / "installers/windows-installer/main.go").read_text(encoding="utf-8")
        builder = (ROOT / "tools/build_windows_installer.py").read_text(encoding="utf-8")
        bundle_builder = (ROOT / "tools/build_native_alpha_bundles.py").read_text(
            encoding="utf-8"
        )
        lowered = source.lower()
        for forbidden in (
            "powershell",
            "pwsh",
            "executionpolicy",
            "bypass",
            "cmd /c",
            "shell=true",
        ):
            self.assertNotIn(forbidden, lowered)
        for required in (
            "install|update|remove|test",
            "SOS_ALPHA_UV_CHECKSUM_MISMATCH",
            "SOS_ALPHA_RUNTIME_REMOVE_REFUSED",
            "SOS_ALPHA_PYTHON_ACQUISITION_FAILED",
            "SOS_ALPHA_SUBPROCESS_START_FAILED",
            '[]string{"--native-tls", "python", "install"',
            "--no-python-downloads",
            "hasReparsePoint",
        ):
            self.assertIn(required, source)
        self.assertIn('GO_VERSION = "go1.27.0"', builder)
        self.assertIn('"SOS-Installer.exe"', bundle_builder)
        self.assertIn("candidate.encode", bundle_builder)

    def test_windows_acquisition_keeps_tls_verification_and_typed_failures(self) -> None:
        source = (ROOT / "installers/windows-installer/main.go").read_text(
            encoding="utf-8"
        )
        self.assertIn('[]string{"--native-tls", "python", "install"', source)
        self.assertIn('"SOS_ALPHA_PYTHON_ACQUISITION_FAILED"', source)
        self.assertIn('"SOS_ALPHA_SUBPROCESS_START_FAILED"', source)
        for forbidden in (
            "--allow-insecure-host",
            "--insecure",
            "SSL_CERT_FILE=",
            "NODE_TLS_REJECT_UNAUTHORIZED",
            "Set-ExecutionPolicy",
            "runas",
        ):
            self.assertNotIn(forbidden.lower(), source.lower())

    def test_launchers_do_not_bypass_platform_security(self) -> None:
        joined = "\n".join(
            (ROOT / path).read_text(encoding="utf-8")
            for path in (
                "installers/Install-SOS.ps1",
                "installers/Test-SOS.ps1",
                "installers/Install-SOS.command",
                "installers/Test-SOS.command",
            )
        ).lower()
        for forbidden in (
            "executionpolicy bypass",
            "set-executionpolicy",
            "xattr -d",
            "spctl --master-disable",
            "sudo ",
            "curl ",
            "wget ",
        ):
            self.assertNotIn(forbidden, joined)
        self.assertIn("3.12.14", joined)
        self.assertIn("uv_python_install_dir", joined)
        self.assertNotIn("install Python", joined)

    def test_bootstrap_is_digest_bound_and_remove_cannot_acquire(self) -> None:
        shell = (ROOT / "installers/Install-SOS.command").read_text(encoding="utf-8")
        powershell = (ROOT / "installers/Install-SOS.ps1").read_text(encoding="utf-8")
        for digest in (
            "d381f11517c66523211b0876552ff7dea5c1b4b0f13800571b35225761302fba",
            "e8929237934c8679686428f5a7736c7ae7a5fe7a33b0504d1b03446cdbc43c94",
            "965816e654d8fac650b282345c89c1daff16a0cfe45e9d2d2a8f5af3fed466a4",
        ):
            self.assertIn(digest, shell + powershell)
        for launcher in (shell, powershell):
            self.assertIn("removal cannot acquire a runtime from the network", launcher)
            self.assertIn("--no-python-downloads", launcher)

    def test_checked_uv_must_match_manifest_digest_and_exact_version(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            uv = Path(temporary) / "uv"
            uv.write_bytes(b"exact-uv")
            manifest = {
                "artifacts": [
                    {
                        "filename": "uv",
                        "sha256": hashlib.sha256(b"exact-uv").hexdigest(),
                    }
                ]
            }

            def runner(arguments: list[str], **_: object) -> subprocess.CompletedProcess[str]:
                return subprocess.CompletedProcess(
                    arguments, 0, "uv 0.12.6 (x86_64-unknown-linux-gnu)\n", ""
                )

            with mock.patch.object(alpha.platform, "system", return_value="Linux"):
                alpha._admit_exact_uv(str(uv), manifest, runner)
                uv.write_bytes(b"drift")
                with self.assertRaises(alpha.StartError) as raised:
                    alpha._admit_exact_uv(str(uv), manifest, runner)
            self.assertEqual(raised.exception.code, "SOS_ALPHA_UV_BINDING_INVALID")

            uv.write_bytes(b"exact-uv")
            with (
                mock.patch.object(alpha.platform, "system", return_value="Linux"),
                self.assertRaises(alpha.StartError),
            ):
                alpha._admit_exact_uv(
                    str(uv),
                    manifest,
                    lambda arguments, **_: subprocess.CompletedProcess(
                        arguments, 0, "uv 0.12.60 (x86_64-unknown-linux-gnu)\n", ""
                    ),
                )

            for rejected in (
                "uv 0.12.6 (aarch64-apple-darwin)\nforged\n",
                "uv 0.12.6 (" + ("x" * 97) + ")\n",
            ):
                with (
                    mock.patch.object(alpha.platform, "system", return_value="Darwin"),
                    self.assertRaises(alpha.StartError),
                ):
                    alpha._admit_exact_uv(
                        str(uv),
                        manifest,
                        lambda arguments, output=rejected, **_: subprocess.CompletedProcess(
                            arguments, 0, output, ""
                        ),
                    )

    def test_checked_uv_accepts_exact_macos_version_with_build_metadata(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            uv = Path(temporary) / "uv"
            uv.write_bytes(b"exact-macos-uv")
            manifest = {
                "artifacts": [
                    {
                        "filename": "uv",
                        "sha256": hashlib.sha256(b"exact-macos-uv").hexdigest(),
                    }
                ]
            }

            def runner(arguments: list[str], **_: object) -> subprocess.CompletedProcess[str]:
                return subprocess.CompletedProcess(
                    arguments,
                    0,
                    "uv 0.12.6 (1654a82d0 2026-08-19)\n",
                    "",
                )

            with mock.patch.object(alpha.platform, "system", return_value="Darwin"):
                alpha._admit_exact_uv(str(uv), manifest, runner)

    def test_update_rebinds_only_after_exact_wheel_install(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            bundle = root / "bundle"
            project = root / "project"
            tool_bin = root / "bin"
            for path in (bundle, project, tool_bin):
                path.mkdir()
            (tool_bin / "sos").write_text("launcher", encoding="utf-8")
            (tool_bin / "sos").chmod(0o755)
            calls: list[list[str]] = []

            def runner(arguments: list[str], **_: object) -> subprocess.CompletedProcess[str]:
                calls.append(arguments)
                if arguments[-2:] == ["rev-parse", "--show-toplevel"]:
                    return subprocess.CompletedProcess(arguments, 0, str(project) + "\n", "")
                if arguments[1:] == ["tool", "dir", "--bin"]:
                    return subprocess.CompletedProcess(arguments, 0, str(tool_bin) + "\n", "")
                return subprocess.CompletedProcess(arguments, 0, "", "")

            with (
                mock.patch.object(alpha, "validate_platform"),
                mock.patch.object(alpha, "verify_bundle"),
                mock.patch.object(alpha, "find_codex"),
            ):
                alpha.run_update(
                    bundle,
                    project,
                    which=lambda name: f"/bin/{name}",
                    runner=runner,
                )
            install_index = next(index for index, call in enumerate(calls) if call[1:3] == ["tool", "install"])
            setup_index = next(index for index, call in enumerate(calls) if "update" in call and "codex" in call)
            self.assertLess(install_index, setup_index)
            self.assertIn("--force", calls[install_index])
            self.assertIn("--offline", calls[install_index])
            self.assertIn("--no-index", calls[install_index])
            self.assertIn("--no-python-downloads", calls[install_index])

    def test_remove_never_uninstalls_package_when_setup_remove_fails(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            bundle = root / "bundle"
            project = root / "project"
            tool_bin = root / "bin"
            for path in (bundle, project, tool_bin):
                path.mkdir()
            (tool_bin / "sos").write_text("launcher", encoding="utf-8")
            (tool_bin / "sos").chmod(0o755)
            calls: list[list[str]] = []

            def runner(arguments: list[str], **_: object) -> subprocess.CompletedProcess[str]:
                calls.append(arguments)
                if arguments[-2:] == ["rev-parse", "--show-toplevel"]:
                    return subprocess.CompletedProcess(arguments, 0, str(project) + "\n", "")
                if arguments[1:] == ["tool", "dir", "--bin"]:
                    return subprocess.CompletedProcess(arguments, 0, str(tool_bin) + "\n", "")
                if "remove" in arguments and "codex" in arguments:
                    return subprocess.CompletedProcess(arguments, 2, "", "")
                return subprocess.CompletedProcess(arguments, 0, "", "")

            with (
                mock.patch.object(alpha, "validate_platform"),
                mock.patch.object(alpha, "verify_bundle"),
            ):
                with self.assertRaises(alpha.StartError) as raised:
                    alpha.run_remove(
                        bundle,
                        project,
                        which=lambda name: f"/bin/{name}",
                        runner=runner,
                    )
            self.assertEqual(raised.exception.code, "SOS_ALPHA_SETUP_REMOVE_FAILED")
            self.assertFalse(any(call[1:3] == ["tool", "uninstall"] for call in calls))

    @staticmethod
    def smoke_payloads() -> dict[str, dict[str, object]]:
        return {
            "status": {
                "contract": "sos_workspace_status_v1",
                "status": "success",
                "reasons": [
                    "SOS_WORKSPACE_CURRENT",
                    "SOS_ACCEPTANCE_ASSURANCE_WEAK_LOCAL",
                ],
            },
            "setup": {
                "contract": "sos_client_integration_result_v1",
                "status": "success",
                "reasons": ["SOS_CODEX_SETUP_INSTALLED"],
            },
            "preflight": {
                "contract": "sos_preflight_result_v1",
                "status": "not_verified",
                "reasons": ["SOS_QUALIFICATION_NOT_RUN"],
            },
            "check": {
                "contract": "sos_check_plan_v1",
                "families": [
                    {
                        "family_id": "python.syntax",
                        "status": "configured",
                        "command_id": "python.compile.v1",
                        "isolation": "non-executing-structural-v1",
                        "reasons": ["SOS_CHECK_CONFIGURED"],
                    },
                    {
                        "family_id": "python.stdlib-unittest",
                        "status": "unsupported",
                        "command_id": None,
                        "isolation": "unavailable",
                        "reasons": ["SOS_CAPABILITY_PLATFORM_UNSUPPORTED"],
                    },
                ],
            },
        }

    def smoke_runner(
        self,
        tool_bin: Path,
        payloads: dict[str, dict[str, object]],
        *,
        version: str = "sos 0.1.0a2",
    ):
        def completed(arguments: list[str], **_: object) -> subprocess.CompletedProcess[str]:
            if arguments[1:] == ["tool", "dir", "--bin"]:
                return subprocess.CompletedProcess(arguments, 0, str(tool_bin) + "\n", "")
            if arguments[1:] == ["--version"]:
                return subprocess.CompletedProcess(arguments, 0, version + "\n", "")
            key = arguments[1]
            exit_code = 2 if key == "preflight" else 0
            return subprocess.CompletedProcess(
                arguments, exit_code, json.dumps(payloads[key]), ""
            )

        return completed

    def test_smoke_is_exact_uv_bound_fail_closed_and_content_safe(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            tool_bin = root / "uv-bin"
            tool_bin.mkdir()
            exact_sos = tool_bin / "sos"
            exact_sos.write_text("launcher", encoding="utf-8")
            payloads = self.smoke_payloads()
            calls: list[list[str]] = []
            runner = self.smoke_runner(tool_bin, payloads)

            def recorded(arguments: list[str], **kwargs: object):
                calls.append(arguments)
                return runner(arguments, **kwargs)

            with mock.patch.object(smoke.subprocess, "run", side_effect=recorded):
                report = smoke.smoke(Path("/private/project"), Path("/exact/uv"))
            rendered = json.dumps(report, sort_keys=True)
            self.assertNotIn("/private/project", rendered)
            self.assertNotIn("/exact/uv", rendered)
            self.assertNotIn("absolute", rendered.replace('"absolute_paths_serialized": false', ""))
            self.assertFalse(report["network_performed"])
            self.assertEqual(calls[0], ["/exact/uv", "tool", "dir", "--bin"])
            self.assertTrue(all(call[0] in {"/exact/uv", str(exact_sos)} for call in calls))
            bound_environment = smoke._closed_environment(Path("/managed/bootstrap/uv"))
            self.assertEqual(bound_environment["UV_TOOL_DIR"], "/managed/tools")
            self.assertEqual(bound_environment["UV_TOOL_BIN_DIR"], "/managed/bin")
            self.assertNotIn("HOME", bound_environment)

            invalid_cases = []
            stale = self.smoke_payloads()
            stale["status"] = {
                "contract": "sos_workspace_status_v1",
                "status": "stale",
                "reasons": ["SOS_SOURCE_STATUS_CHANGED"],
            }
            invalid_cases.append((stale, "sos 0.1.0a2"))
            executable = self.smoke_payloads()
            executable["check"]["families"][1] = {
                "family_id": "python.stdlib-unittest",
                "status": "configured",
                "command_id": "python.unittest.v1",
                "isolation": "unexpected",
                "reasons": ["SOS_CHECK_CONFIGURED"],
            }
            invalid_cases.append((executable, "sos 0.1.0a2"))
            invalid_cases.append((self.smoke_payloads(), "sos 0.1.0a1"))
            for invalid_payloads, version in invalid_cases:
                with (
                    self.subTest(version=version, status=invalid_payloads["status"].get("status")),
                    mock.patch.object(
                        smoke.subprocess,
                        "run",
                        side_effect=self.smoke_runner(
                            tool_bin, invalid_payloads, version=version
                        ),
                    ),
                    self.assertRaises(RuntimeError),
                ):
                    smoke.smoke(Path("/private/project"), Path("/exact/uv"))

    def test_smoke_accepts_valid_post_qualification_owner_required_preflight(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            tool_bin = Path(temporary) / "uv-bin"
            tool_bin.mkdir()
            (tool_bin / "sos").write_text("launcher", encoding="utf-8")
            payloads = self.smoke_payloads()
            payloads["preflight"] = {
                "contract": "sos_preflight_result_v1",
                "status": "owner_required",
                "reasons": ["SOS_CURRENT_WORK_NOT_CONFIGURED"],
            }
            with mock.patch.object(
                smoke.subprocess,
                "run",
                side_effect=self.smoke_runner(tool_bin, payloads),
            ):
                report = smoke.smoke(Path("/private/project"), Path("/exact/uv"))
        preflight = next(
            item for item in report["observations"] if item["name"] == "preflight"
        )
        self.assertEqual(preflight["status"], "owner_required")
        self.assertEqual(preflight["reasons"], ["SOS_CURRENT_WORK_NOT_CONFIGURED"])


if __name__ == "__main__":
    unittest.main()
