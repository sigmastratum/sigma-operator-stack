#!/usr/bin/env python3
"""Build one exact unsigned per-user SOS MSIX from an immutable payload."""

from __future__ import annotations

import argparse
import binascii
import hashlib
import json
import os
import re
import shutil
import struct
import subprocess
import tempfile
import zlib
import zipfile
from pathlib import Path, PurePosixPath

VERSION = "0.1.0a2"
MSIX_VERSION = "0.1.0.2"
REQUIRED = {
    "sos.exe",
    "runtime/python.exe",
    "runtime/Lib/site-packages/sos/__init__.py",
    "bootstrap/uv.exe",
    "wheelhouse/sigma_operator_stack-0.1.0a2-py3-none-any.whl",
}
STORE_IDENTITY_KEYS = {
    "contract",
    "package_family_name",
    "package_identity_name",
    "package_identity_publisher",
    "product_name",
    "publisher_display_name",
    "store_id",
    "store_url",
}


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def git(repository: Path, *args: str) -> str:
    return subprocess.run(
        ["git", "-C", os.fspath(repository), *args], check=True,
        stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
    ).stdout.strip()


def png(width: int, height: int) -> bytes:
    def chunk(kind: bytes, payload: bytes) -> bytes:
        return struct.pack(">I", len(payload)) + kind + payload + struct.pack(">I", binascii.crc32(kind + payload) & 0xFFFFFFFF)
    row = b"\0" + b"\x12\x34\x56\xff" * width
    return b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", struct.pack(">IIBBBBB", width, height, 8, 6, 0, 0, 0)) + chunk(b"IDAT", zlib.compress(row * height, 9)) + chunk(b"IEND", b"")


def payload_inventory(root: Path) -> list[dict[str, str]]:
    found: list[dict[str, str]] = []
    for path in sorted(root.rglob("*")):
        if path.is_symlink():
            raise ValueError("payload links are forbidden")
        if path.is_dir():
            continue
        if not path.is_file():
            raise ValueError("payload object type is unsupported")
        relative = path.relative_to(root).as_posix()
        if PurePosixPath(relative).is_absolute() or ".." in PurePosixPath(relative).parts:
            raise ValueError("payload path is unsafe")
        found.append({"path": relative, "sha256": sha256(path)})
    paths = {item["path"] for item in found}
    if not REQUIRED.issubset(paths):
        raise ValueError("immutable payload inventory is incomplete")
    return found


def store_identity(repository: Path, candidate: str, manifest: str) -> dict[str, str]:
    raw = subprocess.run(
        [
            "git",
            "-C",
            os.fspath(repository),
            "show",
            f"{candidate}:installers/windows-msix/store-identity.json",
        ],
        check=True,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
    ).stdout
    identity = json.loads(raw.decode("utf-8"))
    if not isinstance(identity, dict) or set(identity) != STORE_IDENTITY_KEYS:
        raise SystemExit("Store identity contract is invalid")
    if not all(isinstance(value, str) and value for value in identity.values()):
        raise SystemExit("Store identity values are invalid")
    expected = (
        f'Name="{identity["package_identity_name"]}"',
        f'Publisher="{identity["package_identity_publisher"]}"',
        f'<PublisherDisplayName>{identity["publisher_display_name"]}</PublisherDisplayName>',
        f'<DisplayName>{identity["product_name"]}</DisplayName>',
    )
    if any(manifest.count(value) != 1 for value in expected):
        raise SystemExit("MSIX Store identity binding failed")
    if identity["contract"] != "sos_windows_store_identity_v1":
        raise SystemExit("Store identity contract is unsupported")
    if identity["store_url"] != f'https://apps.microsoft.com/detail/{identity["store_id"]}':
        raise SystemExit("Store identity URL binding failed")
    return identity


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repository", type=Path, default=Path.cwd())
    parser.add_argument("--candidate", required=True)
    parser.add_argument("--payload-root", type=Path, required=True)
    parser.add_argument("--makeappx", type=Path, required=True)
    parser.add_argument("--makeappx-sha256", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    repository = args.repository.resolve(strict=True)
    payload_root = args.payload_root.resolve(strict=True)
    output = args.output.resolve()
    makeappx = args.makeappx.resolve(strict=True)
    if repository == payload_root or repository in payload_root.parents:
        raise SystemExit("payload root must be external to the repository")
    if output == repository or repository in output.parents:
        raise SystemExit("output must be external to the repository")
    if git(repository, "status", "--porcelain"):
        raise SystemExit("repository must be clean")
    candidate = git(repository, "rev-parse", "--verify", f"{args.candidate}^{{commit}}")
    if candidate != git(repository, "rev-parse", "HEAD"):
        raise SystemExit("candidate does not match repository HEAD")
    tree = git(repository, "show", "-s", "--format=%T", candidate)
    epoch = int(git(repository, "show", "-s", "--format=%ct", candidate))
    if not re.fullmatch(r"[0-9a-f]{64}", args.makeappx_sha256) or sha256(makeappx) != args.makeappx_sha256:
        raise SystemExit("MakeAppx digest mismatch")
    inventory = payload_inventory(payload_root)
    template = subprocess.run(
        ["git", "-C", os.fspath(repository), "show", f"{candidate}:installers/windows-msix/AppxManifest.xml.in"],
        check=True, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
    ).stdout.decode("utf-8")
    manifest = template
    identity = store_identity(repository, candidate, manifest)
    output.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="sos-msix-stage-") as temporary:
        stage = Path(temporary)
        for item in inventory:
            destination = stage / PurePosixPath(item["path"])
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(payload_root / PurePosixPath(item["path"]), destination)
        (stage / "Assets").mkdir()
        (stage / "Assets" / "Square44x44Logo.png").write_bytes(png(44, 44))
        (stage / "Assets" / "Square150x150Logo.png").write_bytes(png(150, 150))
        (stage / "AppxManifest.xml").write_text(manifest, encoding="utf-8", newline="")
        payload_record = {
            "artifacts": inventory,
            "candidate": candidate,
            "contract": "sos_windows_msix_payload_v1",
            "executable_acquisition_after_install": False,
            "msix_version": MSIX_VERSION,
            "network_after_package_download": False,
            "platform": "windows-x86_64",
            "sos_version": VERSION,
            "tree": tree,
        }
        (stage / "payload-manifest.json").write_text(json.dumps(payload_record, sort_keys=True, separators=(",", ":")) + "\n", encoding="utf-8", newline="")
        for path in stage.rglob("*"):
            if path.is_file():
                os.utime(path, (epoch, epoch))
        subprocess.run(
            [os.fspath(makeappx), "/pack", "/o", "/d", os.fspath(stage), "/p", os.fspath(output)],
            check=True, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        )
    with zipfile.ZipFile(output) as package:
        names = set(package.namelist())
        required_package = {"AppxManifest.xml", "AppxBlockMap.xml", "[Content_Types].xml", "sos.exe", "runtime/python.exe", "payload-manifest.json"}
        if not required_package.issubset(names) or "AppxSignature.p7x" in names:
            raise SystemExit("unsigned MSIX inventory is invalid")
        if package.read("AppxManifest.xml").decode("utf-8") != manifest:
            raise SystemExit("MSIX manifest bytes drifted")
    print(json.dumps({
        "candidate": candidate, "contract": "sos_windows_unsigned_msix_build_v1",
        "makeappx_sha256": args.makeappx_sha256, "msix_sha256": sha256(output),
        "msix_version": MSIX_VERSION, "payload_file_count": len(inventory),
        "package_family_name": identity["package_family_name"],
        "package_identity_name": identity["package_identity_name"],
        "store_id": identity["store_id"], "status": "passed", "tree": tree,
    }, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
