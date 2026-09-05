#!/usr/bin/env python3
"""Build deterministic checksum-bound native alpha archives."""

from __future__ import annotations

import argparse
import gzip
import hashlib
import json
import os
import re
import shutil
import stat
import subprocess
import tarfile
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
PUBLIC_START = "docs/native-public-alpha.md"
PUBLIC_LICENSES = {
    "cpython": (
        "LICENSE-CPYTHON.txt",
        "3b2f81fe21d181c499c59a256c8e1968455d6689d269aa85373bfb6af41da3bf",
    ),
    "uv_apache": (
        "LICENSE-UV-APACHE",
        "c71d239df91726fc519c6eb72d318ec65820627232b2f796219e87dcf35d0ab4",
    ),
    "uv_mit": (
        "LICENSE-UV-MIT",
        "860e3d7a86b84e6a7012c7a635fc64df475cebc6cce34dfeb73a5982ec58176c",
    ),
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


def _tar_gz_tree(source: Path, destination: Path, epoch: int) -> None:
    root_name = source.name
    with destination.open("xb") as raw:
        with gzip.GzipFile(filename="", mode="wb", fileobj=raw, mtime=epoch) as compressed:
            with tarfile.open(fileobj=compressed, mode="w", format=tarfile.PAX_FORMAT) as archive:
                directory = tarfile.TarInfo(root_name)
                directory.type = tarfile.DIRTYPE
                directory.mode = 0o755
                directory.mtime = epoch
                directory.uid = directory.gid = 0
                directory.uname = directory.gname = ""
                archive.addfile(directory)
                for path in sorted(source.iterdir(), key=lambda item: item.name):
                    info = tarfile.TarInfo(f"{root_name}/{path.name}")
                    payload = path.read_bytes()
                    info.size = len(payload)
                    info.mode = stat.S_IMODE(path.stat().st_mode)
                    info.mtime = epoch
                    info.uid = info.gid = 0
                    info.uname = info.gname = ""
                    archive.addfile(info, __import__("io").BytesIO(payload))


def build(
    repository: Path,
    candidate_ref: str,
    wheel: Path,
    sbom: Path,
    output: Path,
    *,
    uv_binaries: dict[str, Path],
    wheelhouses: dict[str, Path],
    windows_installer: Path | None,
    selected_platforms: set[str] | None = None,
    public: bool = False,
    public_licenses: dict[str, Path] | None = None,
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
    selected = selected_platforms or set(PLATFORMS)
    if not selected or not selected.issubset(PLATFORMS):
        raise ValueError("at least one known platform must be selected")
    if public and "windows" in selected:
        raise ValueError("public Windows delivery uses Microsoft Store, not a native ZIP")
    installer_payload = b""
    if "windows" in selected:
        if windows_installer is None or windows_installer.is_symlink() or not windows_installer.is_file():
            raise ValueError("Windows installer must be one regular PE file")
        installer_payload = windows_installer.read_bytes()
        if (
            not installer_payload.startswith(b"MZ")
            or len(installer_payload) > 8 * 1024 * 1024
            or candidate.encode("ascii") not in installer_payload
        ):
            raise ValueError("Windows installer is not bound to the exact candidate")
    if set(uv_binaries) != selected or set(wheelhouses) != selected:
        raise ValueError("exact uv and wheelhouse inputs are required for selected platforms")
    license_payloads: dict[str, tuple[str, bytes]] = {}
    if public:
        if public_licenses is None or set(public_licenses) != set(PUBLIC_LICENSES):
            raise ValueError("exact CPython and uv licenses are required for public archives")
        for key, (filename, expected_digest) in PUBLIC_LICENSES.items():
            provided = public_licenses[key]
            if not isinstance(provided, Path):
                raise ValueError(f"public license input missing: {key}")
            source = provided.resolve(strict=True)
            if source.is_symlink() or not source.is_file() or _sha256(source) != expected_digest:
                raise ValueError(f"public license input mismatch: {key}")
            license_payloads[key] = (filename, source.read_bytes())
    output.mkdir(parents=True, exist_ok=True)
    results: dict[str, object] = {}
    for platform_name in sorted(selected):
        platform_files = PLATFORMS[platform_name]
        display_name = DISPLAY_NAMES[platform_name]
        root = output / f"SOS-{display_name}-{VERSION}"
        if root.exists():
            raise FileExistsError(f"output directory already exists: {root.name}")
        root.mkdir()
        media: dict[str, str] = {}
        common = dict(COMMON)
        if public:
            common.pop("docs/native-private-alpha.md")
            common[PUBLIC_START] = ("START-HERE.md", "text/markdown", 0o644)
        for source, (name, media_type, mode) in {**common, **platform_files}.items():
            payload = (
                installer_payload
                if source == "@windows-installer"
                else _git_bytes(repository, candidate, source)
            )
            _write(root / name, payload, mode)
            media[name] = media_type
        for filename, payload in license_payloads.values():
            _write(root / filename, payload, 0o644)
            media[filename] = "text/plain"
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
            "contract": (
                "sos_native_public_alpha_bundle_v1"
                if public
                else "sos_native_private_alpha_bundle_v2"
            ),
            "platform": platform_name,
            "tree": tree,
            "version": VERSION,
        }
        if public and platform_name == "macos":
            manifest["build"]["distribution_trust"] = {
                "artifact_signed": False,
                "gatekeeper_user_action": "open_anyway_may_be_required",
                "notarized": False,
                "security_bypass_allowed": False,
            }
        _write(
            root / "release-manifest.json",
            (json.dumps(manifest, sort_keys=True, separators=(",", ":")) + "\n").encode(),
            0o644,
        )
        names = [*media, "release-manifest.json"]
        sums = "".join(f"{_sha256(root / name)}  {name}\n" for name in sorted(names))
        _write(root / "SHA256SUMS", sums.encode(), 0o644)
        archive_suffix = ".tar.gz" if public and platform_name == "macos" else ".zip"
        archive = output / f"SOS-{display_name}-{VERSION}{archive_suffix}"
        if archive.exists():
            raise FileExistsError(f"output archive already exists: {archive.name}")
        if archive_suffix == ".tar.gz":
            _tar_gz_tree(root, archive, epoch)
        else:
            _zip_tree(root, archive, epoch)
        results[platform_name] = {
            "archive": archive.name,
            "archive_sha256": _sha256(archive),
            "file_count": len(tuple(root.iterdir())),
        }
    return {
        "candidate": candidate,
        "contract": (
            "sos_native_public_alpha_build_v1"
            if public
            else "sos_native_private_alpha_build_v2"
        ),
        "platforms": results,
        "tree": tree,
        "version": VERSION,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repository", type=Path, default=Path.cwd())
    parser.add_argument("--candidate", required=True)
    parser.add_argument("--wheel", required=True, type=Path)
    parser.add_argument("--sbom", required=True, type=Path)
    parser.add_argument("--output-dir", required=True, type=Path)
    parser.add_argument("--uv-linux", type=Path)
    parser.add_argument("--uv-windows", type=Path)
    parser.add_argument("--uv-macos", type=Path)
    parser.add_argument("--wheelhouse-windows", type=Path)
    parser.add_argument("--wheelhouse-macos", type=Path)
    parser.add_argument("--wheelhouse-linux", type=Path)
    parser.add_argument("--windows-installer", type=Path)
    parser.add_argument("--platform", action="append", choices=sorted(PLATFORMS))
    parser.add_argument("--public", action="store_true")
    parser.add_argument("--cpython-license", type=Path)
    parser.add_argument("--uv-license-apache", type=Path)
    parser.add_argument("--uv-license-mit", type=Path)
    args = parser.parse_args()
    try:
        result = build(
            args.repository,
            args.candidate,
            args.wheel,
            args.sbom,
            args.output_dir,
            uv_binaries={key: value for key, value in {
                "linux": args.uv_linux,
                "windows": args.uv_windows,
                "macos": args.uv_macos,
            }.items() if value is not None and (args.platform is None or key in args.platform)},
            wheelhouses={key: value for key, value in {
                "linux": args.wheelhouse_linux,
                "windows": args.wheelhouse_windows,
                "macos": args.wheelhouse_macos,
            }.items() if value is not None and (args.platform is None or key in args.platform)},
            windows_installer=(
                args.windows_installer.resolve(strict=True)
                if args.windows_installer is not None
                else None
            ),
            selected_platforms=set(args.platform) if args.platform else None,
            public=args.public,
            public_licenses=(
                {
                    "cpython": args.cpython_license,
                    "uv_apache": args.uv_license_apache,
                    "uv_mit": args.uv_license_mit,
                }
                if args.public
                else None
            ),
        )
    except (OSError, ValueError, subprocess.CalledProcessError, zipfile.BadZipFile) as error:
        print(json.dumps({"contract": "sos_native_private_alpha_build_v2", "status": "failed", "reason": str(error)}, sort_keys=True, separators=(",", ":")))
        return 2
    result["status"] = "passed"
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
