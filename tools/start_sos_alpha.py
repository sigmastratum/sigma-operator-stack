#!/usr/bin/env python3
"""Content-safe, checksum-bound first run for the SOS alpha bundle."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import re
import shutil
import subprocess
import sys
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from pathlib import Path


VERSION = "0.1.0a2"
UV_VERSION = "0.12.6"
PYTHON_VERSION = "3.12.14"
WHEEL = f"sigma_operator_stack-{VERSION}-py3-none-any.whl"
SBOM = f"sigma-operator-stack-{VERSION}.cdx.json"
UNIVERSAL_WHEELS = frozenset(
    {
        "attrs-26.1.0-py3-none-any.whl",
        "jsonschema-4.26.0-py3-none-any.whl",
        "jsonschema_specifications-2025.9.1-py3-none-any.whl",
        "referencing-0.37.0-py3-none-any.whl",
        "typing_extensions-4.16.0-py3-none-any.whl",
    }
)
PLATFORM_WHEELS = {
    "Linux": frozenset(
        {"rpds_py-2026.6.3-cp312-cp312-manylinux_2_17_x86_64.manylinux2014_x86_64.whl"}
    ),
    "Windows": frozenset({"rpds_py-2026.6.3-cp312-cp312-win_amd64.whl"}),
    "Darwin": frozenset({"rpds_py-2026.6.3-cp312-cp312-macosx_11_0_arm64.whl"}),
}
BOOTSTRAP_UV = {"Linux": "uv", "Windows": "uv.exe", "Darwin": "uv"}
EXPECTED_FILES = frozenset(
    {
        "START-HERE.md",
        "alpha-feedback.md",
        "release-manifest.json",
        SBOM,
        "start-sos-alpha",
        WHEEL,
    }
)
PUBLIC_LICENSE_FILES = frozenset(
    {"LICENSE-CPYTHON.txt", "LICENSE-UV-APACHE", "LICENSE-UV-MIT"}
)
NATIVE_FILES = {
    "Linux": frozenset({"Install-SOS.command", "Test-SOS.command", "native-smoke", "uv"})
    | UNIVERSAL_WHEELS
    | PLATFORM_WHEELS["Linux"],
    "Windows": frozenset({"Install-SOS.ps1", "Test-SOS.ps1", "native-smoke", "uv.exe"})
    | UNIVERSAL_WHEELS
    | PLATFORM_WHEELS["Windows"],
    "Darwin": frozenset({"Install-SOS.command", "Test-SOS.command", "native-smoke", "uv"})
    | UNIVERSAL_WHEELS
    | PLATFORM_WHEELS["Darwin"],
}
MAX_FILE_BYTES = {
    "START-HERE.md": 256 * 1024,
    "alpha-feedback.md": 256 * 1024,
    "release-manifest.json": 1024 * 1024,
    SBOM: 16 * 1024 * 1024,
    "start-sos-alpha": 1024 * 1024,
    WHEEL: 64 * 1024 * 1024,
    "Install-SOS.ps1": 256 * 1024,
    "Test-SOS.ps1": 256 * 1024,
    "Install-SOS.command": 256 * 1024,
    "Test-SOS.command": 256 * 1024,
    "native-smoke": 1024 * 1024,
    "uv": 64 * 1024 * 1024,
    "uv.exe": 64 * 1024 * 1024,
    "LICENSE-CPYTHON.txt": 256 * 1024,
    "LICENSE-UV-APACHE": 256 * 1024,
    "LICENSE-UV-MIT": 256 * 1024,
    **{name: 64 * 1024 * 1024 for name in UNIVERSAL_WHEELS},
    **{
        name: 64 * 1024 * 1024
        for wheels in PLATFORM_WHEELS.values()
        for name in wheels
    },
}
SHA256 = re.compile(r"[0-9a-f]{64}")
GIT_OBJECT = re.compile(r"[0-9a-f]{40}")
UV_VERSION_OUTPUT = re.compile(
    rf"uv {re.escape(UV_VERSION)}(?: \([ -~]{{1,96}}\))?"
)


@dataclass(frozen=True)
class StartError(Exception):
    code: str
    problem: str
    correction: str


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _fail(code: str, problem: str, correction: str) -> StartError:
    return StartError(code, problem, correction)


def validate_platform(
    system: str | None = None,
    machine: str | None = None,
    python_version: tuple[int, int] | None = None,
    system_version: str | None = None,
) -> None:
    system = platform.system() if system is None else system
    machine = platform.machine() if machine is None else machine
    python_version = sys.version_info[:2] if python_version is None else python_version
    if system_version is None:
        system_version = platform.mac_ver()[0] if system == "Darwin" else platform.version()
    normalized_machine = machine.lower()
    supported = (
        (system == "Linux" and normalized_machine == "x86_64")
        or (system == "Windows" and normalized_machine in {"amd64", "x86_64"})
        or (system == "Darwin" and normalized_machine in {"arm64", "aarch64"})
    )
    if not supported:
        raise _fail(
            "SOS_ALPHA_PLATFORM_UNSUPPORTED",
            f"This private alpha does not support {system or 'unknown'} {machine or 'unknown'}.",
            "Use Linux x86_64, Windows 11 x86_64, or macOS 14+ Apple Silicon.",
        )
    numeric_version = tuple(
        int(value) for value in re.findall(r"\d+", system_version or "")[:3]
    )
    platform_version_supported = (
        system == "Linux"
        or (system == "Windows" and len(numeric_version) >= 3 and numeric_version[2] >= 22000)
        or (system == "Darwin" and bool(numeric_version) and numeric_version[0] >= 14)
    )
    if not platform_version_supported:
        raise _fail(
            "SOS_ALPHA_PLATFORM_UNSUPPORTED",
            "This private alpha requires Windows 11 or macOS 14 or newer.",
            "Upgrade the operating system or use a supported Linux x86_64 host.",
        )
    if python_version not in {(3, 11), (3, 12)}:
        observed = ".".join(str(item) for item in python_version)
        raise _fail(
            "SOS_ALPHA_PYTHON_UNSUPPORTED",
            f"This alpha requires Python 3.11 or 3.12; detected {observed}.",
            "Install Python 3.11 or 3.12, then run the platform launcher again.",
        )


def _required_command(name: str, which: Callable[[str], str | None]) -> str:
    value = which(name)
    if value:
        return value
    raise _fail(
        f"SOS_ALPHA_{name.upper()}_MISSING",
        f"Required command '{name}' was not found.",
        f"Install {name} from its official distribution, then run the launcher again.",
    )


def find_codex(which: Callable[[str], str | None] = shutil.which, home: Path | None = None) -> Path:
    direct = which("codex")
    if direct:
        return Path(direct)
    root = (home or Path.home()).resolve()
    patterns = (
        ".vscode-server/extensions/openai.chatgpt-*/bin/*/codex",
        ".vscode/extensions/openai.chatgpt-*/bin/*/codex",
        "Library/Application Support/Code/User/globalStorage/openai.chatgpt/bin/*/codex",
    )
    for pattern_value in patterns:
        for candidate in sorted(root.glob(pattern_value)):
            if candidate.is_file() and os.access(candidate, os.X_OK):
                return candidate
    raise _fail(
        "SOS_ALPHA_CODEX_MISSING",
        "Codex was not found in PATH or in a supported VS Code extension location.",
        "Install or enable Codex for this user, then run the launcher again.",
    )


def _tool_command(tool_bin: Path) -> Path:
    candidates = (tool_bin / "sos.exe", tool_bin / "sos") if os.name == "nt" else (tool_bin / "sos",)
    for candidate in candidates:
        if candidate.is_file() and (os.name == "nt" or os.access(candidate, os.X_OK)):
            return candidate
    raise _fail(
        "SOS_ALPHA_TOOL_BINDING_MISSING",
        "The installed SOS command was not found in the uv tool directory.",
        "Check 'uv tool dir --bin', then run the launcher again.",
    )


def _installed_sos(
    uv: str,
    runner: Callable[..., subprocess.CompletedProcess[str]],
) -> Path:
    tool_bin = runner(
        [uv, "tool", "dir", "--bin"],
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    if tool_bin.returncode != 0 or not tool_bin.stdout.strip():
        raise _fail(
            "SOS_ALPHA_TOOL_BINDING_MISSING",
            "uv did not report its tool directory.",
            "Run 'uv tool dir --bin', correct the uv setup, then run the launcher again.",
        )
    return _tool_command(Path(tool_bin.stdout.strip()))


def _admit_exact_uv(
    uv: str,
    manifest: dict[str, object],
    runner: Callable[..., subprocess.CompletedProcess[str]],
) -> None:
    try:
        artifacts = {
            item["filename"]: item
            for item in manifest["artifacts"]  # type: ignore[index]
            if isinstance(item, dict) and isinstance(item.get("filename"), str)
        }
        bootstrap_name = BOOTSTRAP_UV[platform.system()]
        expected = artifacts[bootstrap_name]["sha256"]
        observed = _sha256(Path(uv))
    except (KeyError, OSError, TypeError) as error:
        raise _fail(
            "SOS_ALPHA_UV_BINDING_INVALID",
            "The managed uv bootstrap is not bound to this checked bundle.",
            "Do not continue; use the complete replacement bundle.",
        ) from error
    version = runner(
        [uv, "--version"],
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    if (
        observed != expected
        or version.returncode != 0
        or UV_VERSION_OUTPUT.fullmatch(version.stdout.strip()) is None
    ):
        raise _fail(
            "SOS_ALPHA_UV_BINDING_INVALID",
            "The managed uv executable does not match the checked bundle.",
            "Do not continue; use the complete replacement bundle.",
        )


def _offline_tool_install_command(uv: str, bundle: Path, *, force: bool = False) -> list[str]:
    command = [uv, "tool", "install"]
    if force:
        command.append("--force")
    command.extend(
        [
            "--offline",
            "--no-index",
            "--find-links",
            os.fspath(bundle),
            "--no-config",
            "--no-sources",
            "--no-build",
            "--no-python-downloads",
            "--python",
            sys.executable,
            os.fspath(bundle / WHEEL),
        ]
    )
    return command


def _expected_files(system: str) -> frozenset[str]:
    return EXPECTED_FILES | NATIVE_FILES.get(system, frozenset())


def _read_checksums(
    path: Path, expected_file_sets: tuple[frozenset[str], ...]
) -> dict[str, str]:
    try:
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeError) as error:
        raise _fail(
            "SOS_ALPHA_CHECKSUMS_MISSING",
            "SHA256SUMS is missing or unreadable.",
            "Download or copy the complete alpha bundle again.",
        ) from error
    values: dict[str, str] = {}
    for line in text.splitlines():
        parts = line.split("  ", 1)
        if len(parts) != 2 or not SHA256.fullmatch(parts[0]) or "/" in parts[1] or parts[1] in values:
            raise _fail(
                "SOS_ALPHA_CHECKSUMS_INVALID",
                "SHA256SUMS is not in the exact supported format.",
                "Download or copy the complete alpha bundle again.",
            )
        values[parts[1]] = parts[0]
    if not any(set(values) == expected for expected in expected_file_sets):
        raise _fail(
            "SOS_ALPHA_BUNDLE_INCOMPLETE",
            "The bundle file inventory does not match this alpha.",
            "Download or copy the complete alpha bundle again.",
        )
    return values


def verify_bundle(bundle: Path, *, system: str = platform.system()) -> dict[str, object]:
    try:
        bundle = bundle.resolve(strict=True)
    except OSError as error:
        raise _fail(
            "SOS_ALPHA_BUNDLE_MISSING",
            "The alpha bundle directory is missing or unreadable.",
            "Download or copy the complete alpha bundle again.",
        ) from error
    private_files = _expected_files(system)
    public_files = private_files | PUBLIC_LICENSE_FILES
    checksums = _read_checksums(
        bundle / "SHA256SUMS", (private_files, public_files)
    )
    expected_files = frozenset(checksums)
    public_bundle = expected_files == public_files
    for filename in sorted(expected_files):
        path = bundle / filename
        try:
            invalid_type = path.is_symlink() or not path.is_file()
            too_large = not invalid_type and path.stat().st_size > MAX_FILE_BYTES[filename]
        except OSError as error:
            raise _fail(
                "SOS_ALPHA_BUNDLE_FILE_INVALID",
                f"Bundle file '{filename}' is unreadable.",
                "Download or copy the complete alpha bundle again.",
            ) from error
        if invalid_type:
            raise _fail(
                "SOS_ALPHA_BUNDLE_FILE_INVALID",
                f"Bundle file '{filename}' is missing or has an unsupported file type.",
                "Download or copy the complete alpha bundle again.",
            )
        if too_large:
            raise _fail(
                "SOS_ALPHA_BUNDLE_FILE_TOO_LARGE",
                f"Bundle file '{filename}' exceeds its safety limit.",
                "Download or copy the complete alpha bundle again.",
            )
        try:
            observed_digest = _sha256(path)
        except OSError as error:
            raise _fail(
                "SOS_ALPHA_BUNDLE_FILE_INVALID",
                f"Bundle file '{filename}' is unreadable.",
                "Download or copy the complete alpha bundle again.",
            ) from error
        if observed_digest != checksums[filename]:
            raise _fail(
                "SOS_ALPHA_CHECKSUM_MISMATCH",
                f"Checksum verification failed for '{filename}'.",
                "Do not continue; download or copy the complete alpha bundle again.",
            )
    try:
        manifest = json.loads((bundle / "release-manifest.json").read_text(encoding="utf-8"))
        if (
            not isinstance(manifest, dict)
            or not isinstance(manifest.get("artifacts"), list)
            or not isinstance(manifest.get("build"), dict)
        ):
            raise TypeError("manifest shape")
        artifact_items = manifest["artifacts"]
        artifacts = {item["filename"]: item for item in artifact_items}
    except (KeyError, OSError, TypeError, UnicodeError, ValueError, json.JSONDecodeError) as error:
        raise _fail(
            "SOS_ALPHA_MANIFEST_INVALID",
            "The release manifest is malformed.",
            "Download or copy the complete alpha bundle again.",
        ) from error
    expected_artifacts = expected_files.difference({"release-manifest.json"})
    expected_media = {
        "START-HERE.md": "text/markdown",
        "alpha-feedback.md": "text/markdown",
        SBOM: "application/vnd.cyclonedx+json",
        "start-sos-alpha": "text/x-python",
        WHEEL: "application/zip",
        "Install-SOS.ps1": "text/x-powershell",
        "Test-SOS.ps1": "text/x-powershell",
        "Install-SOS.command": "text/x-shellscript",
        "Test-SOS.command": "text/x-shellscript",
        "native-smoke": "text/x-python",
        "uv": "application/octet-stream",
        "uv.exe": "application/vnd.microsoft.portable-executable",
        "LICENSE-CPYTHON.txt": "text/plain",
        "LICENSE-UV-APACHE": "text/plain",
        "LICENSE-UV-MIT": "text/plain",
        **{name: "application/zip" for name in UNIVERSAL_WHEELS},
        **{
            name: "application/zip"
            for wheels in PLATFORM_WHEELS.values()
            for name in wheels
        },
    }
    expected_contract = (
        "sos_native_public_alpha_bundle_v1"
        if public_bundle
        else (
            "sos_native_private_alpha_bundle_v2"
            if system in NATIVE_FILES
            else "sos_public_release_manifest_v1"
        )
    )
    build = manifest.get("build", {})
    build_valid = (
        build.get("acquisition_network_allowed") is True
        and build.get("network_allowed_after_verified_handoff") is False
        and build.get("managed_python") == PYTHON_VERSION
        and build.get("uv") == UV_VERSION
        if system in NATIVE_FILES
        else build.get("network_allowed") is False
    )
    if public_bundle and system == "Darwin":
        build_valid = build_valid and build.get("distribution_trust") == {
            "artifact_signed": False,
            "gatekeeper_user_action": "open_anyway_may_be_required",
            "notarized": False,
            "security_bypass_allowed": False,
        }
    if (
        manifest.get("contract") != expected_contract
        or manifest.get("version") != VERSION
        or not GIT_OBJECT.fullmatch(str(manifest.get("candidate", "")))
        or not GIT_OBJECT.fullmatch(str(manifest.get("tree", "")))
        or not build_valid
        or len(artifact_items) != len(expected_artifacts)
        or set(artifacts) != expected_artifacts
        or any(
            artifacts[name].get("sha256") != checksums[name]
            or artifacts[name].get("media_type") != expected_media[name]
            or set(artifacts[name]) != {"filename", "media_type", "sha256"}
            for name in expected_artifacts
        )
    ):
        raise _fail(
            "SOS_ALPHA_MANIFEST_BINDING_INVALID",
            "The bundle manifest is not bound to the exact checked artifacts.",
            "Do not continue; download or copy the complete alpha bundle again.",
        )
    return manifest


def discover_project_root(
    project: Path,
    git: str,
    runner: Callable[..., subprocess.CompletedProcess[str]] = subprocess.run,
) -> Path:
    try:
        requested = project.resolve(strict=True)
    except OSError as error:
        raise _fail(
            "SOS_ALPHA_PROJECT_MISSING",
            "The selected project directory does not exist.",
            "Open a terminal in an existing Git project, then run the launcher again.",
        ) from error
    if not requested.is_dir():
        raise _fail(
            "SOS_ALPHA_PROJECT_INVALID",
            "The selected project path is not a directory.",
            "Open a terminal in an existing Git project, then run the launcher again.",
        )
    completed = runner(
        [git, "-C", os.fspath(requested), "rev-parse", "--show-toplevel"],
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    if completed.returncode != 0 or not completed.stdout.strip():
        raise _fail(
            "SOS_ALPHA_GIT_REPOSITORY_REQUIRED",
            "The selected directory is not inside a Git repository.",
            "Open a terminal in the root of an existing Git project, then run the launcher again.",
        )
    try:
        root = Path(completed.stdout.strip()).resolve(strict=True)
        requested.relative_to(root)
    except (OSError, ValueError) as error:
        raise _fail(
            "SOS_ALPHA_GIT_ROOT_INVALID",
            "Git returned a project root that does not contain the selected directory.",
            "Check the repository and run the launcher from its root.",
        ) from error
    return root


def run_onboarding(
    bundle: Path,
    project: Path,
    *,
    primary_authority_id: str | None = None,
    uv_path: str | None = None,
    which: Callable[[str], str | None] = shutil.which,
    runner: Callable[..., subprocess.CompletedProcess[str]] = subprocess.run,
) -> Path:
    validate_platform()
    git = _required_command("git", which)
    uv = uv_path or _required_command("uv", which)
    find_codex(which=which)
    manifest = verify_bundle(bundle)
    if uv_path is not None:
        _admit_exact_uv(uv, manifest, runner)
    root = discover_project_root(project, git, runner)
    print("SOS alpha checks passed.")
    print(f"Release: {manifest['version']} ({str(manifest['candidate'])[:12]})")
    print(f"Project: {root}")
    print("Installing the exact checked SOS wheel. Project files are not changed yet.")
    # A previous attempt may have installed the same public version from an
    # older candidate before project admission stopped. Rebind the SOS-owned
    # tool environment to the exact checked wheel on every onboarding retry.
    installed = runner(
        _offline_tool_install_command(uv, bundle, force=True), check=False
    )
    if installed.returncode != 0:
        raise _fail(
            "SOS_ALPHA_INSTALL_FAILED",
            "uv could not install the exact SOS wheel.",
            "Read the uv error above, correct it, then run the launcher again.",
        )
    sos = _installed_sos(uv, runner)
    compatibility_command = [
        os.fspath(sos),
        "compatibility",
        os.fspath(root),
        "--json",
    ]
    if primary_authority_id is not None:
        compatibility_command.extend(["--primary-authority", primary_authority_id])
    compatibility = runner(
        compatibility_command,
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    try:
        compatibility_result = json.loads(compatibility.stdout)
    except (json.JSONDecodeError, TypeError) as error:
        raise _fail(
            "SOS_ALPHA_COMPATIBILITY_INVALID",
            "SOS did not return a valid existing-project compatibility result.",
            "Read the SOS error, correct the named issue, then run the launcher again.",
        ) from error
    if (
        not isinstance(compatibility_result, dict)
        or compatibility_result.get("contract")
        != "sos_compatibility_projection_v1"
    ):
        raise _fail(
            "SOS_ALPHA_COMPATIBILITY_INVALID",
            "SOS returned an unexpected existing-project compatibility contract.",
            "Stop and verify the exact installed SOS package before retrying.",
        )
    compatibility_status = compatibility_result.get("status")
    if compatibility_status == "owner_required":
        details = compatibility_result.get("details")
        candidates = (
            details.get("authority_candidates", [])
            if isinstance(details, dict)
            else []
        )
        candidate_ids = [
            value.get("authority_id")
            for value in candidates
            if isinstance(value, dict)
            and isinstance(value.get("authority_id"), str)
        ]
        choices = ", ".join(candidate_ids) or "no valid IDs returned"
        raise _fail(
            "SOS_ALPHA_PRIMARY_AUTHORITY_REQUIRED",
            f"This project has more than one possible authority: {choices}.",
            "Choose the primary one and rerun: start-sos-alpha "
            "--primary-authority '<exact-discovered-id>' /path/to/project",
        )
    if compatibility.returncode != 0 or compatibility_status != "success":
        reasons = compatibility_result.get("reasons")
        reason = (
            reasons[0]
            if isinstance(reasons, list) and reasons
            else "unknown blocker"
        )
        raise _fail(
            "SOS_ALPHA_COMPATIBILITY_BLOCKED",
            f"SOS stopped before changing project files: {reason}.",
            "Correct the reported compatibility issue, then run the launcher again.",
        )
    print("Existing project compatibility check passed.")
    print("\nSOS will now show one complete project plan and ask once before changing files.")
    init_command = [os.fspath(sos), "init", "--with-codex"]
    if primary_authority_id is not None:
        init_command.extend(["--primary-authority", primary_authority_id])
    init_command.append(os.fspath(root))
    initialized = runner(init_command, check=False)
    if initialized.returncode != 0:
        raise _fail(
            "SOS_ALPHA_INIT_FAILED",
            "SOS did not finish project initialization.",
            "Read the SOS result above, correct the named issue, then run the launcher again.",
        )
    print("\nSOS is installed and connected to this project.")
    print("Next:")
    print("1. Restart or reopen Codex if the SOS tools are not visible.")
    print("2. Trust this project when Codex asks you.")
    print("3. From the project root, run: sos qualify .")
    print("Qualification is intentionally separate and will ask before running project checks.")
    return root


def run_update(
    bundle: Path,
    project: Path,
    *,
    uv_path: str | None = None,
    which: Callable[[str], str | None] = shutil.which,
    runner: Callable[..., subprocess.CompletedProcess[str]] = subprocess.run,
) -> Path:
    validate_platform()
    git = _required_command("git", which)
    uv = uv_path or _required_command("uv", which)
    find_codex(which=which)
    manifest = verify_bundle(bundle)
    if uv_path is not None:
        _admit_exact_uv(uv, manifest, runner)
    root = discover_project_root(project, git, runner)
    updated = runner(_offline_tool_install_command(uv, bundle, force=True), check=False)
    if updated.returncode != 0:
        raise _fail(
            "SOS_ALPHA_UPDATE_FAILED",
            "uv could not install the exact replacement SOS wheel.",
            "Read the uv error and rerun the checked bundle after correcting it.",
        )
    sos = _installed_sos(uv, runner)
    rebound = runner([os.fspath(sos), "setup", "update", "codex", os.fspath(root)], check=False)
    if rebound.returncode != 0:
        raise _fail(
            "SOS_ALPHA_SETUP_UPDATE_FAILED",
            "SOS did not complete the previewed project integration update.",
            "Do not uninstall; read the typed SOS result and retry the same checked bundle.",
        )
    return root


def run_remove(
    bundle: Path,
    project: Path,
    *,
    uv_path: str | None = None,
    which: Callable[[str], str | None] = shutil.which,
    runner: Callable[..., subprocess.CompletedProcess[str]] = subprocess.run,
) -> Path:
    validate_platform()
    git = _required_command("git", which)
    uv = uv_path or _required_command("uv", which)
    manifest = verify_bundle(bundle)
    if uv_path is not None:
        _admit_exact_uv(uv, manifest, runner)
    root = discover_project_root(project, git, runner)
    sos = _installed_sos(uv, runner)
    removed = runner([os.fspath(sos), "setup", "remove", "codex", os.fspath(root)], check=False)
    if removed.returncode != 0:
        raise _fail(
            "SOS_ALPHA_SETUP_REMOVE_FAILED",
            "SOS did not safely remove its exact managed Codex integration.",
            "Do not remove the package; read the typed SOS result and retry recovery first.",
        )
    uninstalled = runner([uv, "tool", "uninstall", "sigma-operator-stack"], check=False)
    if uninstalled.returncode != 0:
        raise _fail(
            "SOS_ALPHA_PACKAGE_REMOVE_FAILED",
            "The project integration was removed but uv could not remove the SOS package.",
            "The project .sigma records were preserved; retry only the uv uninstall command.",
        )
    return root


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="start-sos-alpha",
        description="Check and install the exact SOS alpha bundle into one existing Git project.",
    )
    parser.add_argument("project", nargs="?", type=Path, default=Path.cwd())
    parser.add_argument("--primary-authority")
    parser.add_argument("--uv")
    parser.add_argument("--mode", choices=("install", "update", "remove"), default="install")
    arguments = parser.parse_args(argv)
    launcher = Path(__file__).absolute()
    try:
        if launcher.is_symlink():
            raise _fail(
                "SOS_ALPHA_LAUNCHER_SYMLINK_FORBIDDEN",
                "The alpha launcher must not be run through a symbolic link.",
                "Run the checked start-sos-alpha file directly from the extracted bundle.",
            )
        if arguments.mode == "install":
            run_onboarding(
                launcher.parent,
                arguments.project,
                primary_authority_id=arguments.primary_authority,
                uv_path=arguments.uv,
            )
        elif arguments.mode == "update":
            run_update(launcher.parent, arguments.project, uv_path=arguments.uv)
        else:
            run_remove(launcher.parent, arguments.project, uv_path=arguments.uv)
    except StartError as error:
        print("\nSOS alpha setup stopped.", file=sys.stderr)
        print(f"Code: {error.code}", file=sys.stderr)
        print(f"Problem: {error.problem}", file=sys.stderr)
        print(f"Fix: {error.correction}", file=sys.stderr)
        return 2
    except OSError:
        print("\nSOS alpha setup stopped.", file=sys.stderr)
        print("Code: SOS_ALPHA_LOCAL_IO_FAILED", file=sys.stderr)
        print("Problem: A required local command or file could not be accessed.", file=sys.stderr)
        print("Fix: Check the displayed project and bundle permissions, then run the launcher again.", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
