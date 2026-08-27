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
WHEEL = f"sigma_operator_stack-{VERSION}-py3-none-any.whl"
SBOM = f"sigma-operator-stack-{VERSION}.cdx.json"
COMMON = {
    "docs/native-private-alpha.md": ("START-HERE.md", "text/markdown", 0o644),
    "docs/alpha-feedback.md": ("alpha-feedback.md", "text/markdown", 0o644),
    "tools/start_sos_alpha.py": ("start-sos-alpha", "text/x-python", 0o755),
    "tools/native_alpha_smoke.py": ("native-smoke", "text/x-python", 0o755),
}
PLATFORMS = {
    "windows": {
        "installers/Install-SOS.ps1": ("Install-SOS.ps1", "text/x-powershell", 0o644),
        "installers/Test-SOS.ps1": ("Test-SOS.ps1", "text/x-powershell", 0o644),
    },
    "macos": {
        "installers/Install-SOS.command": ("Install-SOS.command", "text/x-shellscript", 0o755),
        "installers/Test-SOS.command": ("Test-SOS.command", "text/x-shellscript", 0o755),
    },
}
DISPLAY_NAMES = {"windows": "Windows", "macos": "macOS"}


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


def build(repository: Path, candidate_ref: str, wheel: Path, sbom: Path, output: Path) -> dict[str, object]:
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
            _write(root / name, _git_bytes(repository, candidate, source), mode)
            media[name] = media_type
        shutil.copyfile(wheel, root / WHEEL)
        shutil.copyfile(sbom, root / SBOM)
        media[WHEEL] = "application/zip"
        media[SBOM] = "application/vnd.cyclonedx+json"
        artifacts = [
            {"filename": name, "media_type": media[name], "sha256": _sha256(root / name)}
            for name in sorted(media)
        ]
        manifest = {
            "artifacts": artifacts,
            "build": {"network_allowed": False, "source_date_epoch": epoch, "wheel_builds_equal": True},
            "candidate": candidate,
            "contract": "sos_native_private_alpha_bundle_v1",
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
    return {"candidate": candidate, "contract": "sos_native_private_alpha_build_v1", "platforms": results, "tree": tree, "version": VERSION}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repository", type=Path, default=Path.cwd())
    parser.add_argument("--candidate", required=True)
    parser.add_argument("--wheel", required=True, type=Path)
    parser.add_argument("--sbom", required=True, type=Path)
    parser.add_argument("--output-dir", required=True, type=Path)
    args = parser.parse_args()
    try:
        result = build(args.repository, args.candidate, args.wheel, args.sbom, args.output_dir)
    except (OSError, ValueError, subprocess.CalledProcessError, zipfile.BadZipFile) as error:
        print(json.dumps({"contract": "sos_native_private_alpha_build_v1", "status": "failed", "reason": str(error)}, sort_keys=True, separators=(",", ":")))
        return 2
    result["status"] = "passed"
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
