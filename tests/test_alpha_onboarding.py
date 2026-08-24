from __future__ import annotations

import hashlib
import importlib.util
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("sos_alpha_launcher", ROOT / "tools" / "start_sos_alpha.py")
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("alpha launcher import failed")
alpha = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = alpha
SPEC.loader.exec_module(alpha)


class AlphaOnboardingTests(unittest.TestCase):
    def make_bundle(self, root: Path) -> Path:
        bundle = root / "bundle"
        bundle.mkdir()
        payloads = {
            "START-HERE.md": b"# Start here\n",
            alpha.SBOM: b'{"bomFormat":"CycloneDX"}\n',
            "start-sos-alpha": b"#!/usr/bin/env python3\n",
            alpha.WHEEL: b"synthetic-wheel",
        }
        for name, data in payloads.items():
            (bundle / name).write_bytes(data)
        artifacts = [
            {
                "filename": name,
                "media_type": {
                    "START-HERE.md": "text/markdown",
                    alpha.SBOM: "application/vnd.cyclonedx+json",
                    "start-sos-alpha": "text/x-python",
                    alpha.WHEEL: "application/zip",
                }[name],
                "sha256": hashlib.sha256(data).hexdigest(),
            }
            for name, data in sorted(payloads.items())
        ]
        manifest = {
            "artifacts": artifacts,
            "build": {"network_allowed": False},
            "candidate": "a" * 40,
            "contract": "sos_public_release_manifest_v1",
            "tree": "b" * 40,
            "version": alpha.VERSION,
        }
        (bundle / "release-manifest.json").write_text(
            json.dumps(manifest, sort_keys=True, separators=(",", ":")) + "\n",
            encoding="utf-8",
        )
        sums = {
            name: hashlib.sha256((bundle / name).read_bytes()).hexdigest()
            for name in alpha.EXPECTED_FILES
        }
        (bundle / "SHA256SUMS").write_text(
            "".join(f"{digest}  {name}\n" for name, digest in sorted(sums.items())),
            encoding="utf-8",
        )
        return bundle

    def test_platform_boundary_is_explicit_and_fail_closed(self) -> None:
        alpha.validate_platform("Linux", "x86_64", (3, 11))
        alpha.validate_platform("Linux", "x86_64", (3, 12))
        cases = (
            ("Darwin", "x86_64", (3, 12), "SOS_ALPHA_LINUX_REQUIRED"),
            ("Linux", "aarch64", (3, 12), "SOS_ALPHA_ARCHITECTURE_UNSUPPORTED"),
            ("Linux", "x86_64", (3, 13), "SOS_ALPHA_PYTHON_UNSUPPORTED"),
        )
        for system, machine, version, code in cases:
            with self.subTest(code=code), self.assertRaises(alpha.StartError) as raised:
                alpha.validate_platform(system, machine, version)
            self.assertEqual(raised.exception.code, code)

    def test_checked_launcher_installs_exact_wheel_then_only_runs_init(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            bundle = self.make_bundle(root)
            project = root / "project"
            project.mkdir()
            tool_bin = root / "tool-bin"
            tool_bin.mkdir()
            calls: list[tuple[list[str], dict[str, object]]] = []

            def which(name: str) -> str | None:
                return f"/synthetic/bin/{name}" if name in {"git", "uv", "codex"} else None

            def runner(arguments: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
                calls.append((arguments, kwargs))
                if arguments[-2:] == ["rev-parse", "--show-toplevel"]:
                    return subprocess.CompletedProcess(arguments, 0, f"{project}\n", "")
                if arguments[1:3] == ["tool", "install"]:
                    sos = tool_bin / "sos"
                    sos.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
                    sos.chmod(0o755)
                    return subprocess.CompletedProcess(arguments, 0, "", "")
                if arguments[1:] == ["tool", "dir", "--bin"]:
                    return subprocess.CompletedProcess(arguments, 0, f"{tool_bin}\n", "")
                if arguments[0] == os.fspath(tool_bin / "sos"):
                    if arguments[1] == "compatibility":
                        return subprocess.CompletedProcess(
                            arguments,
                            0,
                            json.dumps(
                                {
                                    "contract": "sos_compatibility_projection_v1",
                                    "status": "success",
                                    "reasons": ["SOS_COMPATIBILITY_READY"],
                                    "details": {},
                                }
                            ),
                            "",
                        )
                    return subprocess.CompletedProcess(arguments, 0, "", "")
                raise AssertionError(arguments)

            observed = alpha.run_onboarding(bundle, project, which=which, runner=runner)

            self.assertEqual(observed, project)
            commands = [arguments for arguments, _ in calls]
            install = next(arguments for arguments in commands if arguments[1:3] == ["tool", "install"])
            self.assertEqual(install[-1], os.fspath(bundle / alpha.WHEEL))
            self.assertEqual(
                commands[-2],
                [
                    os.fspath(tool_bin / "sos"),
                    "compatibility",
                    os.fspath(project),
                    "--json",
                ],
            )
            self.assertEqual(commands[-1], [os.fspath(tool_bin / "sos"), "init", "--with-codex", os.fspath(project)])
            self.assertFalse(any("qualify" in arguments for arguments in commands))
            self.assertFalse(any(kwargs.get("shell") for _, kwargs in calls))

    def test_checksum_drift_fails_before_any_command(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            bundle = self.make_bundle(Path(temporary))
            (bundle / alpha.WHEEL).write_bytes(b"changed")
            with self.assertRaises(alpha.StartError) as raised:
                alpha.verify_bundle(bundle)
            self.assertEqual(raised.exception.code, "SOS_ALPHA_CHECKSUM_MISMATCH")

    def test_competing_authorities_stop_launcher_before_init(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            bundle = self.make_bundle(root)
            project = root / "project"
            project.mkdir()
            tool_bin = root / "tool-bin"
            tool_bin.mkdir()
            calls: list[list[str]] = []

            def which(name: str) -> str | None:
                return (
                    f"/synthetic/bin/{name}"
                    if name in {"git", "uv", "codex"}
                    else None
                )

            def runner(
                arguments: list[str], **_: object
            ) -> subprocess.CompletedProcess[str]:
                calls.append(arguments)
                if arguments[-2:] == ["rev-parse", "--show-toplevel"]:
                    return subprocess.CompletedProcess(arguments, 0, f"{project}\n", "")
                if arguments[1:3] == ["tool", "install"]:
                    sos = tool_bin / "sos"
                    sos.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
                    sos.chmod(0o755)
                    return subprocess.CompletedProcess(arguments, 0, "", "")
                if arguments[1:] == ["tool", "dir", "--bin"]:
                    return subprocess.CompletedProcess(arguments, 0, f"{tool_bin}\n", "")
                if arguments[0] == os.fspath(tool_bin / "sos"):
                    return subprocess.CompletedProcess(
                        arguments,
                        2,
                        json.dumps(
                            {
                                "contract": "sos_compatibility_projection_v1",
                                "status": "owner_required",
                                "reasons": ["SOS_PRIMARY_AUTHORITY_REQUIRED"],
                                "details": {
                                    "authority_candidates": [
                                        {"authority_id": "agents:AGENTS.md"},
                                        {"authority_id": "openspec:openspec"},
                                    ]
                                },
                            }
                        ),
                        "",
                    )
                raise AssertionError(arguments)

            with self.assertRaises(alpha.StartError) as raised:
                alpha.run_onboarding(bundle, project, which=which, runner=runner)

            self.assertEqual(
                raised.exception.code,
                "SOS_ALPHA_PRIMARY_AUTHORITY_REQUIRED",
            )
            self.assertIn("agents:AGENTS.md", raised.exception.problem)
            self.assertFalse(
                any("init" in arguments for arguments in calls),
                calls,
            )

    def test_missing_uv_fails_before_install_or_project_mutation(self) -> None:
        calls: list[list[str]] = []

        def which(name: str) -> str | None:
            return "/synthetic/bin/git" if name == "git" else None

        def runner(arguments: list[str], **_: object) -> subprocess.CompletedProcess[str]:
            calls.append(arguments)
            return subprocess.CompletedProcess(arguments, 0, "", "")

        with tempfile.TemporaryDirectory() as temporary, self.assertRaises(alpha.StartError) as raised:
            alpha.run_onboarding(Path(temporary), Path(temporary), which=which, runner=runner)
        self.assertEqual(raised.exception.code, "SOS_ALPHA_UV_MISSING")
        self.assertEqual(calls, [])

    def test_non_git_directory_fails_before_uv_install(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            bundle = self.make_bundle(root)
            project = root / "project"
            project.mkdir()
            calls: list[list[str]] = []

            def which(name: str) -> str | None:
                return f"/synthetic/bin/{name}" if name in {"git", "uv", "codex"} else None

            def runner(arguments: list[str], **_: object) -> subprocess.CompletedProcess[str]:
                calls.append(arguments)
                return subprocess.CompletedProcess(arguments, 128, "", "not a repository")

            with self.assertRaises(alpha.StartError) as raised:
                alpha.run_onboarding(bundle, project, which=which, runner=runner)
            self.assertEqual(raised.exception.code, "SOS_ALPHA_GIT_REPOSITORY_REQUIRED")
            self.assertFalse(any(arguments[1:3] == ["tool", "install"] for arguments in calls))

    def test_readme_front_loads_first_run_and_keeps_qualification_separate(self) -> None:
        root = Path(__file__).resolve().parents[1]
        readme = (root / "README.md").read_text(encoding="utf-8")
        self.assertLess(readme.index("## Start here"), readme.index("## What gets installed"))
        self.assertIn("start-sos-alpha", readme)
        self.assertIn("sos qualify .", readme)
        launcher = (root / "tools" / "start_sos_alpha.py").read_text(encoding="utf-8")
        self.assertNotIn('"qualify"', launcher)
        self.assertNotIn("curl | sh", launcher)

    def test_alpha_quickstart_explains_unpack_before_launcher(self) -> None:
        quickstart = (ROOT / "docs" / "alpha-quickstart.md").read_text(encoding="utf-8")
        unpack = "tar -xzf sigma-operator-stack-0.1.0a1-linux-x86_64-alpha.tar.gz"
        launcher = "/path/to/sigma-operator-stack-0.1.0a1-alpha/start-sos-alpha"
        self.assertIn("its SHA-256 value with the checksum supplied by your inviter", quickstart)
        self.assertIn(unpack, quickstart)
        self.assertIn(launcher, quickstart)
        self.assertLess(quickstart.index(unpack), quickstart.index(launcher))


if __name__ == "__main__":
    unittest.main()
