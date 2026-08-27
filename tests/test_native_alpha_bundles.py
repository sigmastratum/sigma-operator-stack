from __future__ import annotations

import importlib.util
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


if __name__ == "__main__":
    unittest.main()
