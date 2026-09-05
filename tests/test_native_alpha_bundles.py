from __future__ import annotations

import importlib.util
import hashlib
import json
import os
import struct
import subprocess
import sys
import tarfile
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
pe_manifest = _load("sos_windows_pe_manifest", ROOT / "tools/windows_pe_manifest.py")


def _synthetic_pe(manifests: list[bytes]) -> bytes:
    """Build a bounded parser fixture; it is not an executable product."""
    resource_rva = 0x1000
    count = len(manifests)
    type_directory = 24
    id_directories = type_directory + 16 + count * 8
    data_entries = id_directories + count * 24
    payload_offset = data_entries + count * 16
    resource = bytearray()
    resource.extend(struct.pack("<IIHHHH", 0, 0, 0, 0, 0, 1))
    resource.extend(struct.pack("<II", 24, 0x80000000 | type_directory))
    resource.extend(struct.pack("<IIHHHH", 0, 0, 0, 0, 0, count))
    for index in range(count):
        resource.extend(
            struct.pack("<II", index + 1, 0x80000000 | (id_directories + index * 24))
        )
    for index in range(count):
        resource.extend(struct.pack("<IIHHHH", 0, 0, 0, 0, 0, 1))
        resource.extend(struct.pack("<II", 0x0409, data_entries + index * 16))
    next_payload = payload_offset
    for manifest in manifests:
        resource.extend(
            struct.pack("<IIII", resource_rva + next_payload, len(manifest), 0, 0)
        )
        next_payload += len(manifest)
    for manifest in manifests:
        resource.extend(manifest)

    optional = bytearray(240)
    struct.pack_into("<H", optional, 0, 0x20B)
    struct.pack_into("<II", optional, 32, 0x1000, 0x200)
    struct.pack_into("<II", optional, 56, 0x2000, 0x200)
    struct.pack_into("<H", optional, 68, 3)
    struct.pack_into("<I", optional, 108, 16)
    struct.pack_into("<II", optional, 128, resource_rva, len(resource))
    dos = bytearray(0x80)
    dos[:2] = b"MZ"
    struct.pack_into("<I", dos, 0x3C, 0x80)
    file_header = struct.pack("<HHIIIHH", 0x8664, 1, 0, 0, 0, 240, 0x0022)
    raw_size = (len(resource) + 0x1FF) & ~0x1FF
    section = struct.pack(
        "<8sIIIIIIHHI",
        b".rsrc\0\0\0",
        len(resource),
        resource_rva,
        raw_size,
        0x200,
        0,
        0,
        0,
        0,
        0x40000040,
    )
    headers = bytes(dos) + b"PE\0\0" + file_header + bytes(optional) + section
    headers += b"\0" * (0x200 - len(headers))
    return headers + bytes(resource) + b"\0" * (raw_size - len(resource))


class NativeAlphaBundleTests(unittest.TestCase):
    def test_windows_installer_builder_rejects_dirty_or_mismatched_source(self) -> None:
        builder = ROOT / "tools/build_windows_installer.py"
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            repository = root / "repository"
            source = repository / "installers/windows-installer"
            source.mkdir(parents=True)
            tools = repository / "tools"
            tools.mkdir()
            (source / "go.mod").write_text("module example.invalid/sos\n", encoding="utf-8")
            (source / "main.go").write_text("package main\nfunc main() {}\n", encoding="utf-8")
            manifest = (ROOT / "installers/windows-installer/application.manifest").read_bytes()
            (source / "application.manifest").write_bytes(manifest)
            (tools / "windows_pe_manifest.py").write_bytes(
                (ROOT / "tools/windows_pe_manifest.py").read_bytes()
            )
            fixture_pe = root / "fixture.exe"
            fixture_pe.write_bytes(_synthetic_pe([manifest]))
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
                "import pathlib,shutil,sys\n"
                "if sys.argv[1:] == ['version']:\n"
                " print('go version go1.27.0 linux/amd64')\n"
                "else:\n"
                " out=pathlib.Path(sys.argv[sys.argv.index('-o')+1])\n"
                f" shutil.copyfile({os.fspath(fixture_pe)!r}, out)\n",
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
            self.assertEqual(report["requested_execution_level"], "asInvoker")
            self.assertFalse(report["ui_access"])

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

    def test_windows_manifest_resource_is_exact_deterministic_and_fail_closed(self) -> None:
        manifest = (ROOT / "installers/windows-installer/application.manifest").read_bytes()
        first = pe_manifest.build_manifest_coff(manifest)
        second = pe_manifest.build_manifest_coff(manifest)
        self.assertEqual(first, second)
        self.assertIn(b'level="asInvoker"', first)
        report = pe_manifest.verify_pe_manifest(_synthetic_pe([manifest]), manifest)
        self.assertEqual(report["status"], "passed")
        self.assertEqual(report["manifest_count"], 1)
        self.assertEqual(report["dpi_awareness"], "PerMonitorV2, PerMonitor")
        with self.assertRaises(pe_manifest.ManifestResourceError):
            pe_manifest.verify_pe_manifest(_synthetic_pe([]), manifest)
        with self.assertRaises(pe_manifest.ManifestResourceError):
            pe_manifest.verify_pe_manifest(_synthetic_pe([manifest, manifest]), manifest)
        with self.assertRaises(pe_manifest.ManifestResourceError):
            pe_manifest.verify_pe_manifest(
                _synthetic_pe([manifest.replace(b"asInvoker", b"highestAvailable")]),
                manifest,
            )
        with self.assertRaises(pe_manifest.ManifestResourceError):
            pe_manifest.build_manifest_coff(
                manifest.replace(b"PerMonitorV2, PerMonitor", b"unaware")
            )

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
            '"UV_NO_CACHE=1"',
            '[]string{"--native-tls", "--no-cache", "python", "install"',
            "--no-python-downloads",
            "hasReparsePoint",
        ):
            self.assertIn(required, source)
        self.assertIn('GO_VERSION = "go1.27.0"', builder)
        self.assertIn('"SOS-Installer.exe"', bundle_builder)
        self.assertIn("candidate.encode", bundle_builder)

    def test_public_native_builder_is_platform_scoped_and_license_bound(self) -> None:
        builder = (ROOT / "tools/build_native_alpha_bundles.py").read_text(
            encoding="utf-8"
        )
        documentation = (ROOT / "docs/native-public-alpha.md").read_text(
            encoding="utf-8"
        )
        smoke_source = (ROOT / "tools/native_alpha_smoke.py").read_text(
            encoding="utf-8"
        )
        for required in (
            '"sos_native_public_alpha_bundle_v1"',
            '"sos_native_public_alpha_build_v1"',
            '"LICENSE-CPYTHON.txt"',
            '"LICENSE-UV-APACHE"',
            '"LICENSE-UV-MIT"',
            'if public and "windows" in selected',
            'parser.add_argument("--platform"',
            '"open_anyway_may_be_required"',
            'archive_suffix = ".tar.gz" if public and platform_name == "macos"',
        ):
            self.assertIn(required, builder)
        self.assertIn("release/current.json", documentation)
        self.assertIn("does not modify system Python, PATH", documentation)
        self.assertIn("Do not use `sudo`", documentation)
        self.assertIn("System Settings → Privacy & Security", documentation)
        self.assertIn("`user_action_required`", documentation)
        self.assertNotIn("`xattr", documentation)
        self.assertIn("`.sigma` records", documentation)
        self.assertIn('"sos_native_alpha_smoke_v1"', smoke_source)
        self.assertNotIn("sos_native_private_alpha_smoke_v1", smoke_source)

    def test_public_macos_archive_is_deterministic_tar_with_explicit_unsigned_trust(self) -> None:
        builder = _load(
            "sos_native_alpha_bundle_builder",
            ROOT / "tools/build_native_alpha_bundles.py",
        )
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "SOS-macOS-0.1.0a2"
            source.mkdir()
            (source / "Install-SOS.command").write_text("#!/bin/sh\n", encoding="utf-8")
            (source / "Install-SOS.command").chmod(0o755)
            first = root / "first.tar.gz"
            second = root / "second.tar.gz"
            builder._tar_gz_tree(source, first, 1_700_000_000)
            builder._tar_gz_tree(source, second, 1_700_000_000)
            self.assertEqual(first.read_bytes(), second.read_bytes())
            with tarfile.open(first, "r:gz") as archive:
                members = archive.getmembers()
                self.assertEqual(
                    [member.name for member in members],
                    ["SOS-macOS-0.1.0a2", "SOS-macOS-0.1.0a2/Install-SOS.command"],
                )
                self.assertTrue(all(member.uid == member.gid == 0 for member in members))

    def test_windows_acquisition_keeps_tls_verification_and_typed_failures(self) -> None:
        source = (ROOT / "installers/windows-installer/main.go").read_text(
            encoding="utf-8"
        )
        self.assertIn(
            '[]string{"--native-tls", "--no-cache", "python", "install"',
            source,
        )
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

    def test_windows_uv_acquisition_is_cacheless(self) -> None:
        source = (ROOT / "installers/windows-installer/main.go").read_text(
            encoding="utf-8"
        )
        self.assertIn('"UV_NO_CACHE=1"', source)
        self.assertIn(
            '[]string{"--native-tls", "--no-cache", "python", "install"',
            source,
        )
        self.assertNotIn("UV_CACHE_DIR", source)
        self.assertNotIn("cacheRoot", source)
        self.assertNotIn("SOS_ALPHA_UV_CACHE_UNAVAILABLE", source)
        for forbidden in (
            'filepath.join(localappdata, "uv")',
            '"uv_cache_dir="+localappdata',
            "runas",
        ):
            self.assertNotIn(forbidden, source.lower())

    def test_windows_environment_is_current_user_bound_and_foreign_state_is_not_reused(self) -> None:
        source = (ROOT / "installers/windows-installer/main.go").read_text(
            encoding="utf-8"
        )
        for required in (
            "syscall.OpenCurrentProcessToken()",
            "token.GetTokenUser()",
            '"sos-managed-environment-owner-v1\\x00" + sid',
            'ownerMarker = ".sos-environment-owner-v1"',
            '"SOS_ALPHA_MANAGED_ENVIRONMENT_FOREIGN"',
            '"SOS_ALPHA_MANAGED_ENVIRONMENT_CREATE_FAILED"',
            '"SOS_ALPHA_MANAGED_ENVIRONMENT_MISSING"',
            '"SigmaOperatorStackEnvironment-"+ownerBinding[:16]',
            'filepath.Join(managedRoot, "environment")',
            'mode == "install" || mode == "update"',
            'os.Rename(temporary, path)',
        ):
            self.assertIn(required, source)
        self.assertNotIn('filepath.Join(managedRoot, "runtime")', source)
        self.assertNotIn('filepath.Join(localAppData, "SigmaOperatorStack", "runtime")', source)
        self.assertNotIn("SetNamedSecurityInfo", source)
        self.assertNotIn("runas", source.lower())

    def test_windows_known_folder_and_reversible_user_storage_admission_fail_closed(self) -> None:
        source = (ROOT / "installers/windows-installer/main.go").read_text(
            encoding="utf-8"
        )
        native = (ROOT / "installers/windows-installer/reparse_windows.go").read_text(
            encoding="utf-8"
        )
        for required in (
            "localAppDataKnownFolder()",
            "knownFolderHRESULT != 0",
            'environmentLocalAppData == "" || !filepath.IsAbs(environmentLocalAppData)',
            "strings.EqualFold",
            '"SOS_ALPHA_LOCALAPPDATA_KNOWN_FOLDER_UNAVAILABLE"',
            '"SOS_ALPHA_LOCALAPPDATA_MISMATCH"',
            '"SOS_ALPHA_USER_STORAGE_ACCESS_DENIED"',
            '"SOS_ALPHA_USER_STORAGE_UNAVAILABLE"',
            '"SOS_ALPHA_USER_STORAGE_CLEANUP_FAILED"',
            '".sos-storage-probe-"+hex.EncodeToString(nonce)',
            "os.Mkdir(probe, 0700)",
            "os.WriteFile(marker, payload, 0600)",
            "os.ReadFile(marker)",
            "os.Remove(marker)",
            "os.Remove(probe)",
        ):
            self.assertIn(required, source)
        self.assertNotIn('"SOS_ALPHA_LOCALAPPDATA_INVALID"', source)
        for required in (
            'syscall.NewLazyDLL("shell32.dll")',
            'NewProc("SHGetKnownFolderPath")',
            'NewProc("CoTaskMemFree")',
            "folderIDLocalAppData",
        ):
            self.assertIn(required, native)
        lowered = source.lower()
        for forbidden in ("setnamedsecurityinfo", "runas", "takeown", "icacls", "tempdir"):
            self.assertNotIn(forbidden, lowered)

    def test_windows_elevated_process_is_rejected_before_storage_or_project_observation(self) -> None:
        source = (ROOT / "installers/windows-installer/main.go").read_text(
            encoding="utf-8"
        )
        native = (ROOT / "installers/windows-installer/reparse_windows.go").read_text(
            encoding="utf-8"
        )
        for required in (
            "currentProcessElevated()",
            "userAccountControlEnabled()",
            '"SOS_ALPHA_ELEVATION_STATE_UNAVAILABLE"',
            '"SOS_ALPHA_UAC_DISABLED_UNSUPPORTED"',
            '"SOS_ALPHA_ELEVATION_FORBIDDEN"',
            'Fix: %s',
        ):
            self.assertIn(required, source)
        for required in (
            "syscall.OpenCurrentProcessToken()",
            "syscall.GetTokenInformation(",
            "syscall.TokenElevation",
            "elevated != 0",
            'NewProc("RegOpenKeyExW")',
            'NewProc("RegQueryValueExW")',
            'UTF16PtrFromString("EnableLUA")',
        ):
            self.assertIn(required, native)
        elevation_index = source.index("currentProcessElevated()")
        uac_index = source.index("userAccountControlEnabled()")
        disabled_index = source.index('"SOS_ALPHA_UAC_DISABLED_UNSUPPORTED"')
        forbidden_index = source.index('"SOS_ALPHA_ELEVATION_FORBIDDEN"')
        self.assertLess(elevation_index, uac_index)
        self.assertLess(uac_index, disabled_index)
        self.assertLess(disabled_index, forbidden_index)
        self.assertLess(elevation_index, source.index("filepath.Abs(project)"))
        self.assertLess(uac_index, source.index("filepath.Abs(project)"))
        self.assertLess(elevation_index, source.index("os.Executable()"))
        self.assertLess(elevation_index, source.index("localAppDataKnownFolder()"))
        self.assertLess(elevation_index, source.index("admitUserStorage(localAppData)"))

    def test_windows_builder_requires_exact_embedded_as_invoker_manifest(self) -> None:
        manifest = (ROOT / "installers/windows-installer/application.manifest").read_text(
            encoding="utf-8"
        )
        builder = (ROOT / "tools/build_windows_installer.py").read_text(encoding="utf-8")
        tool = (ROOT / "tools/windows_pe_manifest.py").read_text(encoding="utf-8")
        self.assertEqual(manifest.count("requestedExecutionLevel"), 1)
        self.assertIn('level="asInvoker"', manifest)
        self.assertIn('uiAccess="false"', manifest)
        self.assertIn('"build-resource"', builder)
        self.assertIn('"verify-pe"', builder)
        self.assertIn('"requested_execution_level"', builder)
        self.assertIn("PE must contain exactly one manifest resource", tool)
        self.assertNotIn("requireAdministrator", manifest)
        self.assertNotIn("highestAvailable", manifest)

    def test_windows_onboarding_uses_literal_safe_commands(self) -> None:
        documentation = (ROOT / "docs/native-private-alpha.md").read_text(
            encoding="utf-8"
        )
        command_blocks = documentation.split("```bat", 1)[1].split("```", 1)[0]
        self.assertNotIn("<PROJECT>", command_blocks)
        self.assertNotIn("-Mode update", documentation)
        self.assertNotIn("-Mode remove", documentation)
        self.assertIn('install "C:\\Users\\Example\\source\\example-project"', documentation)
        self.assertIn("Do not type angle", documentation)
        self.assertIn("Windows UAC must remain enabled", documentation)

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
        self.assertIn("--primary-authority EXACT_ID", shell)
        self.assertIn('set -- "$@" --primary-authority "$PRIMARY_AUTHORITY"', shell)
        self.assertIn('[ "$MODE" != "install" ]', shell)
        self.assertLess(
            shell.index('[ -n "$PRIMARY_AUTHORITY" ] && [ "$MODE" != "install" ]'),
            shell.index('/bin/mkdir -p "$RUNTIME_ROOT/bootstrap"'),
        )

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
