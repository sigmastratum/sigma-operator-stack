#!/usr/bin/env python3
"""Build deterministic checksum-bound Windows and macOS private-alpha ZIPs."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import stat
import subprocess
import zipfile
from pathlib import Path


VERSION = "0.1.0a2"
UV_VERSION = "0.12.6"
PYTHON_VERSION = "3.12.14"
WHEEL = f"sigma_operator_stack-{VERSION}-py3-none-any.whl"
SBOM = f"sigma-operator-stack-{VERSION}.cdx.json"
COMMON = {
    "docs/native-private-alpha.md": ("START-HERE.md", "text/markdown", 0o644),
    "docs/alpha-feedback.md": ("alpha-feedback.md", "text/markdown", 0o644),
    "tools/start_sos_alpha.py": ("start-sos-alpha", "text/x-python", 0o755),
    "tools/native_alpha_smoke.py": ("native-smoke", "text/x-python", 0o755),
}
PLATFORMS = {
    "linux": {
        "installers/Install-SOS.command": ("Install-SOS.command", "text/x-shellscript", 0o755),
        "installers/Test-SOS.command": ("Test-SOS.command", "text/x-shellscript", 0o755),
    },
    "windows": {
        "@windows-installer": ("SOS-Installer.exe", "application/vnd.microsoft.portable-executable", 0o755),
        "installers/Install-SOS.ps1": ("Install-SOS.ps1", "text/x-powershell", 0o644),
        "installers/Test-SOS.ps1": ("Test-SOS.ps1", "text/x-powershell", 0o644),
    },
    "macos": {
        "installers/Install-SOS.command": ("Install-SOS.command", "text/x-shellscript", 0o755),
        "installers/Test-SOS.command": ("Test-SOS.command", "text/x-shellscript", 0o755),
    },
}
DISPLAY_NAMES = {"linux": "Linux", "windows": "Windows", "macos": "macOS"}
UV_NAMES = {"linux": "uv", "windows": "uv.exe", "macos": "uv"}
UV_SHA256 = {
    "linux": "d381f11517c66523211b0876552ff7dea5c1b4b0f13800571b35225761302fba",
    "windows": "965816e654d8fac650b282345c89c1daff16a0cfe45e9d2d2a8f5af3fed466a4",
    "macos": "e8929237934c8679686428f5a7736c7ae7a5fe7a33b0504d1b03446cdbc43c94",
}
UNIVERSAL_WHEELS = {
    "attrs-26.1.0-py3-none-any.whl",
    "jsonschema-4.26.0-py3-none-any.whl",
    "jsonschema_specifications-2025.9.1-py3-none-any.whl",
    "referencing-0.37.0-py3-none-any.whl",
    "typing_extensions-4.16.0-py3-none-any.whl",
}
PLATFORM_WHEELS = {
    "linux": {
        "rpds_py-2026.6.3-cp312-cp312-manylinux_2_17_x86_64.manylinux2014_x86_64.whl"
    },
    "windows": {"rpds_py-2026.6.3-cp312-cp312-win_amd64.whl"},
    "macos": {"rpds_py-2026.6.3-cp312-cp312-macosx_11_0_arm64.whl"},
}


def _run(argv: list[str], cwd: Path) -> str:
    return subprocess.run(
        argv,
        cwd=cwd,
        check=True,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    ).stdout.strip()


def _git(repository: Path, *arguments: str) -> str:
    return _run(["git", "-C", os.fspath(repository), *arguments], repository)


def _git_bytes(repository: Path, candidate: str, path: str) -> bytes:
    return subprocess.run(
        ["git", "-C", os.fspath(repository), "show", f"{candidate}:{path}"],
        cwd=repository,
        check=True,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    ).stdout


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _write(path: Path, payload: bytes, mode: int) -> None:
    path.write_bytes(payload)
    path.chmod(mode)


def _zip_tree(source: Path, destination: Path, epoch: int) -> None:
    timestamp = __import__("time").gmtime(max(epoch, 315532800))[:6]
    with zipfile.ZipFile(destination, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as archive:
        for path in sorted(source.iterdir(), key=lambda item: item.name):
            info = zipfile.ZipInfo(path.name, timestamp)
            info.compress_type = zipfile.ZIP_DEFLATED
            mode = stat.S_IMODE(path.stat().st_mode)
            info.external_attr = (stat.S_IFREG | mode) << 16
            archive.writestr(info, path.read_bytes(), compress_type=zipfile.ZIP_DEFLATED, compresslevel=9)


def build(
    repository: Path,
    candidate_ref: str,
    wheel: Path,
    sbom: Path,
    output: Path,
    *,
    uv_binaries: dict[str, Path],
    wheelhouses: dict[str, Path],
    windows_installer: Path,
) -> dict[str, object]:
    repository = repository.resolve(strict=True)
    output = output.resolve()
    if output == repository or repository in output.parents:
        raise ValueError("output must be outside the repository")
    candidate = _git(repository, "rev-parse", "--verify", f"{candidate_ref}^{{commit}}")
    if not re.fullmatch(r"[0-9a-f]{40}", candidate):
        raise ValueError("candidate must resolve to one exact commit")
    tree = _git(repository, "show", "-s", "--format=%T", candidate)
    epoch = int(_git(repository, "show", "-s", "--format=%ct", candidate))
    if wheel.name != WHEEL or not wheel.is_file() or not sbom.is_file():
        raise ValueError("wheel or SBOM does not match the frozen private alpha")
    if windows_installer.is_symlink() or not windows_installer.is_file():
        raise ValueError("Windows installer must be one regular PE file")
    installer_payload = windows_installer.read_bytes()
    if (
        not installer_payload.startswith(b"MZ")
        or len(installer_payload) > 8 * 1024 * 1024
        or candidate.encode("ascii") not in installer_payload
    ):
        raise ValueError("Windows installer is not bound to the exact candidate")
    if set(uv_binaries) != set(PLATFORMS) or set(wheelhouses) != set(PLATFORMS):
        raise ValueError("exact uv and wheelhouse inputs are required for every platform")
    output.mkdir(parents=True, exist_ok=True)
    results: dict[str, object] = {}
    for platform_name, platform_files in PLATFORMS.items():
        display_name = DISPLAY_NAMES[platform_name]
        root = output / f"SOS-{display_name}-{VERSION}"
        if root.exists():
            raise FileExistsError(f"output directory already exists: {root.name}")
        root.mkdir()
        media: dict[str, str] = {}
        for source, (name, media_type, mode) in {**COMMON, **platform_files}.items():
            payload = (
                installer_payload
                if source == "@windows-installer"
                else _git_bytes(repository, candidate, source)
            )
            _write(root / name, payload, mode)
            media[name] = media_type
        shutil.copyfile(wheel, root / WHEEL)
        shutil.copyfile(sbom, root / SBOM)
        media[WHEEL] = "application/zip"
        media[SBOM] = "application/vnd.cyclonedx+json"
        uv_source = uv_binaries[platform_name].resolve(strict=True)
        if uv_source.is_symlink() or not uv_source.is_file():
            raise ValueError("uv bootstrap input must be one regular file")
        if _sha256(uv_source) != UV_SHA256[platform_name]:
            raise ValueError(f"{platform_name} uv bootstrap digest mismatch")
        uv_name = UV_NAMES[platform_name]
        shutil.copyfile(uv_source, root / uv_name)
        (root / uv_name).chmod(0o755)
        media[uv_name] = (
            "application/vnd.microsoft.portable-executable"
            if platform_name == "windows"
            else "application/octet-stream"
        )
        wheelhouse = wheelhouses[platform_name].resolve(strict=True)
        expected_wheels = UNIVERSAL_WHEELS | PLATFORM_WHEELS[platform_name]
        observed_wheels = {
            item.name
            for item in wheelhouse.iterdir()
            if item.is_file() and not item.is_symlink()
        }
        if observed_wheels != expected_wheels:
            raise ValueError(f"{platform_name} wheelhouse inventory mismatch")
        for dependency in sorted(expected_wheels):
            shutil.copyfile(wheelhouse / dependency, root / dependency)
            media[dependency] = "application/zip"
        artifacts = [
            {"filename": name, "media_type": media[name], "sha256": _sha256(root / name)}
            for name in sorted(media)
        ]
        manifest = {
            "artifacts": artifacts,
            "build": {
                "acquisition_network_allowed": True,
                "managed_python": PYTHON_VERSION,
                "network_allowed_after_verified_handoff": False,
                "source_date_epoch": epoch,
                "uv": UV_VERSION,
                "wheel_builds_equal": True,
            },
            "candidate": candidate,
            "contract": "sos_native_private_alpha_bundle_v2",
            "platform": platform_name,
            "tree": tree,
            "version": VERSION,
        }
        _write(
            root / "release-manifest.json",
            (json.dumps(manifest, sort_keys=True, separators=(",", ":")) + "\n").encode(),
            0o644,
        )
        names = [*media, "release-manifest.json"]
        sums = "".join(f"{_sha256(root / name)}  {name}\n" for name in sorted(names))
        _write(root / "SHA256SUMS", sums.encode(), 0o644)
        archive = output / f"SOS-{display_name}-{VERSION}.zip"
        if archive.exists():
            raise FileExistsError(f"output archive already exists: {archive.name}")
        _zip_tree(root, archive, epoch)
        results[platform_name] = {
            "archive": archive.name,
            "archive_sha256": _sha256(archive),
            "file_count": len(tuple(root.iterdir())),
        }
    return {"candidate": candidate, "contract": "sos_native_private_alpha_build_v2", "platforms": results, "tree": tree, "version": VERSION}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repository", type=Path, default=Path.cwd())
    parser.add_argument("--candidate", required=True)
    parser.add_argument("--wheel", required=True, type=Path)
    parser.add_argument("--sbom", required=True, type=Path)
    parser.add_argument("--output-dir", required=True, type=Path)
    parser.add_argument("--uv-linux", required=True, type=Path)
    parser.add_argument("--uv-windows", required=True, type=Path)
    parser.add_argument("--uv-macos", required=True, type=Path)
    parser.add_argument("--wheelhouse-windows", required=True, type=Path)
    parser.add_argument("--wheelhouse-macos", required=True, type=Path)
    parser.add_argument("--wheelhouse-linux", required=True, type=Path)
    parser.add_argument("--windows-installer", required=True, type=Path)
    args = parser.parse_args()
    try:
        result = build(
            args.repository,
            args.candidate,
            args.wheel,
            args.sbom,
            args.output_dir,
            uv_binaries={
                "linux": args.uv_linux,
                "windows": args.uv_windows,
                "macos": args.uv_macos,
            },
            wheelhouses={
                "linux": args.wheelhouse_linux,
                "windows": args.wheelhouse_windows,
                "macos": args.wheelhouse_macos,
            },
            windows_installer=args.windows_installer.resolve(strict=True),
        )
    except (OSError, ValueError, subprocess.CalledProcessError, zipfile.BadZipFile) as error:
        print(json.dumps({"contract": "sos_native_private_alpha_build_v2", "status": "failed", "reason": str(error)}, sort_keys=True, separators=(",", ":")))
        return 2
    result["status"] = "passed"
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
