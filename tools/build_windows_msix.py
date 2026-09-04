#!/usr/bin/env python3
"""Build one exact unsigned per-user SOS MSIX from an immutable payload."""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
import re
import shutil
import stat
import subprocess
import sys
import tempfile
from pathlib import Path, PurePosixPath


def _load_source_verifier():
    path = Path(__file__).with_name("verify_windows_msix_source.py")
    spec = importlib.util.spec_from_file_location("_sos_msix_source_verifier", path)
    if spec is None or spec.loader is None:
        raise SystemExit("exact source verifier cannot be loaded")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


source_verifier = _load_source_verifier()

VERSION = "0.1.0a2"
MSIX_VERSION = "1.0.5.0"
LOGO_ASSETS = {
    "Square44x44Logo.png": (44, 44),
    "Square50x50Logo.png": (50, 50),
    "Square150x150Logo.png": (150, 150),
}
REQUIRED = {
    "sos.exe",
    "sos-launcher.exe",
    "runtime/python.exe",
    "runtime/Lib/site-packages/sos/__init__.py",
    "uv.exe",
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
WINDOWS_RESERVED = {
    "CON", "CONIN$", "CONOUT$", "PRN", "AUX", "NUL",
    *(f"COM{number}" for number in range(1, 10)),
    *(f"LPT{number}" for number in range(1, 10)),
}
MAX_PAYLOAD_FILES = 50_000
MAX_PAYLOAD_SIZE = 2 * 1024 * 1024 * 1024
FIXED_SOURCE_EPOCH = 315_532_800


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for block in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def validate_logo(value: bytes, expected: tuple[int, int]) -> None:
    if len(value) < 24 or value[:8] != b"\x89PNG\r\n\x1a\n" or value[12:16] != b"IHDR":
        raise SystemExit("MSIX logo asset is not a bounded PNG")
    observed = (int.from_bytes(value[16:20], "big"), int.from_bytes(value[20:24], "big"))
    if observed != expected:
        raise SystemExit("MSIX logo asset dimensions do not match the Store contract")


def is_reparse(observed: os.stat_result) -> bool:
    attributes = getattr(observed, "st_file_attributes", 0)
    reparse = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
    return bool(attributes & reparse)


def safe_payload_path(value: str) -> str:
    if (
        not value
        or "\\" in value
        or "\0" in value
        or any(ord(character) < 32 or character in '<>"|?*' for character in value)
    ):
        raise ValueError("payload path is unsafe")
    relative = PurePosixPath(value)
    if relative.is_absolute() or any(part in ("", ".", "..") for part in relative.parts):
        raise ValueError("payload path is unsafe")
    for part in relative.parts:
        if part.endswith((" ", ".")) or ":" in part:
            raise ValueError("payload path is unsafe on Windows")
        if part.split(".", 1)[0].upper() in WINDOWS_RESERVED:
            raise ValueError("payload path is reserved on Windows")
    return relative.as_posix()


def payload_inventory(root: Path) -> list[dict[str, str]]:
    root_observed = root.lstat()
    if not stat.S_ISDIR(root_observed.st_mode) or is_reparse(root_observed):
        raise ValueError("payload root is not a plain directory")
    found: list[dict[str, str]] = []
    folded: dict[str, str] = {}
    total_size = 0
    for directory, names, files in os.walk(root, topdown=True, followlinks=False):
        names.sort()
        files.sort()
        directory_path = Path(directory)
        admitted: list[str] = []
        for name in names:
            child = directory_path / name
            observed = child.lstat()
            if not stat.S_ISDIR(observed.st_mode) or is_reparse(observed):
                raise ValueError("payload links and reparse objects are forbidden")
            safe_payload_path(child.relative_to(root).as_posix())
            admitted.append(name)
        names[:] = admitted
        for name in files:
            path = directory_path / name
            observed = path.lstat()
            if (
                not stat.S_ISREG(observed.st_mode)
                or is_reparse(observed)
                or observed.st_nlink != 1
            ):
                raise ValueError("payload object type is unsupported")
            relative = safe_payload_path(path.relative_to(root).as_posix())
            folded_name = relative.casefold()
            if folded_name in folded and folded[folded_name] != relative:
                raise ValueError("payload contains a case-fold collision")
            folded[folded_name] = relative
            if relative.lower().endswith((".pyc", ".pyo")) or "__pycache__" in PurePosixPath(relative).parts:
                raise ValueError("Python bytecode is forbidden in the MSIX payload")
            total_size += observed.st_size
            if total_size > MAX_PAYLOAD_SIZE or len(found) >= MAX_PAYLOAD_FILES:
                raise ValueError("payload inventory exceeds its bounded limits")
            found.append({"path": relative, "sha256": sha256(path)})
    found.sort(key=lambda item: item["path"])
    paths = {item["path"] for item in found}
    if not REQUIRED.issubset(paths):
        raise ValueError("immutable payload inventory is incomplete")
    return found


def inventory_digest(inventory: list[dict[str, str]]) -> str:
    encoded = json.dumps(inventory, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(encoded).hexdigest()


def store_identity(raw: bytes, manifest: str) -> dict[str, str]:
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


def validate_launch_contract(manifest: str) -> None:
    application = re.findall(
        r'<Application\b[^>]*\bExecutable="([^"]+)"[^>]*>', manifest
    )
    aliases = re.findall(
        r'<desktop:ExecutionAlias\b[^>]*\bAlias="([^"]+)"[^>]*/>', manifest
    )
    alias_extensions = re.findall(
        r'<uap3:Extension\b[^>]*\bCategory="windows\.appExecutionAlias"[^>]*\bExecutable="([^"]+)"[^>]*>',
        manifest,
    )
    if application != ["sos-launcher.exe"]:
        raise SystemExit("MSIX Start-menu entrypoint binding is invalid")
    if aliases != ["sos.exe"] or alias_extensions != ["sos.exe"]:
        raise SystemExit("MSIX command alias binding is invalid")
    if manifest.count('Version="1.0.5.0"') != 1:
        raise SystemExit("MSIX transport version binding is invalid")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--source-root", type=Path, required=True)
    parser.add_argument("--source-manifest", type=Path, required=True)
    parser.add_argument("--candidate", required=True)
    parser.add_argument("--tree", required=True)
    parser.add_argument("--payload-root", type=Path, required=True)
    parser.add_argument("--makeappx", type=Path, required=True)
    parser.add_argument("--makeappx-sha256", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    for supplied, kind in (
        (args.source_root, "source"),
        (args.source_manifest, "source manifest"),
        (args.payload_root, "payload"),
        (args.makeappx, "MakeAppx"),
    ):
        supplied_stat = supplied.lstat()
        if stat.S_ISLNK(supplied_stat.st_mode) or is_reparse(supplied_stat):
            raise SystemExit(f"{kind} path must not be a link or reparse object")
    if args.output.exists():
        raise SystemExit("MSIX output already exists")
    source_root = args.source_root.resolve(strict=True)
    source_manifest = args.source_manifest.resolve(strict=True)
    payload_root = args.payload_root.resolve(strict=True)
    output = args.output.resolve()
    makeappx = args.makeappx.resolve(strict=True)
    if (
        source_root == payload_root
        or source_root in payload_root.parents
        or payload_root in source_root.parents
    ):
        raise SystemExit("payload root must be external to the source snapshot")
    if output == source_root or source_root in output.parents:
        raise SystemExit("output must be external to the source snapshot")
    if output == payload_root or payload_root in output.parents:
        raise SystemExit("output must be external to the payload")
    if source_manifest == payload_root or payload_root in source_manifest.parents:
        raise SystemExit("source manifest must be external to the payload")
    if not stat.S_ISREG(makeappx.lstat().st_mode):
        raise SystemExit("MakeAppx is not a regular file")
    baseline = source_verifier.verify_source_snapshot(
        source_root,
        source_manifest,
        args.candidate,
        args.tree,
    )
    for relative, local_path in (
        ("tools/build_windows_msix.py", Path(__file__)),
        ("tools/verify_windows_msix_source.py", Path(source_verifier.__file__)),
    ):
        expected = baseline.artifact(relative)
        if sha256(local_path) != expected.sha256:
            raise SystemExit("executing source tool is not bound to the exact snapshot")
    candidate = baseline.candidate
    tree = baseline.tree
    if not re.fullmatch(r"[0-9a-f]{64}", args.makeappx_sha256) or sha256(makeappx) != args.makeappx_sha256:
        raise SystemExit("MakeAppx digest mismatch")
    inventory = payload_inventory(payload_root)
    payload_digest = inventory_digest(inventory)
    template = source_verifier.read_bound_source_file(
        source_root,
        baseline,
        "installers/windows-msix/AppxManifest.xml.in",
    ).decode("utf-8")
    manifest = template
    validate_launch_contract(manifest)
    identity = store_identity(
        source_verifier.read_bound_source_file(
            source_root,
            baseline,
            "installers/windows-msix/store-identity.json",
        ),
        manifest,
    )
    output.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="sos-msix-stage-") as temporary:
        stage = Path(temporary)
        for item in inventory:
            destination = stage / PurePosixPath(item["path"])
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(payload_root / PurePosixPath(item["path"]), destination)
        (stage / "Assets").mkdir()
        for name, dimensions in LOGO_ASSETS.items():
            value = source_verifier.read_bound_source_file(
                source_root,
                baseline,
                f"installers/windows-msix/assets/{name}",
            )
            validate_logo(value, dimensions)
            (stage / "Assets" / name).write_bytes(value)
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
                os.utime(path, (FIXED_SOURCE_EPOCH, FIXED_SOURCE_EPOCH))
        stage_before = payload_inventory(stage)
        stage_digest = inventory_digest(stage_before)
        expected_stage_paths = {item["path"] for item in inventory} | {
            "AppxManifest.xml",
            "Assets/Square150x150Logo.png",
            "Assets/Square44x44Logo.png",
            "Assets/Square50x50Logo.png",
            "payload-manifest.json",
        }
        if {item["path"] for item in stage_before} != expected_stage_paths:
            raise SystemExit("MSIX stage inventory is not exact")
        makeappx_before = sha256(makeappx)
        if makeappx_before != args.makeappx_sha256:
            raise SystemExit("MakeAppx digest drifted before pack")
        source_verifier.same_snapshot(
            baseline,
            source_verifier.verify_source_snapshot(
                source_root, source_manifest, candidate, tree
            ),
        )
        subprocess.run(
            [os.fspath(makeappx), "pack", "/o", "/d", os.fspath(stage), "/p", os.fspath(output)],
            check=True, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        )
        if payload_inventory(stage) != stage_before:
            raise SystemExit("MSIX stage changed during MakeAppx pack")
        if sha256(makeappx) != makeappx_before:
            raise SystemExit("MakeAppx digest drifted during pack")
        source_verifier.same_snapshot(
            baseline,
            source_verifier.verify_source_snapshot(
                source_root, source_manifest, candidate, tree
            ),
        )
    if not output.is_file() or output.is_symlink() or output.stat().st_size == 0:
        raise SystemExit("MakeAppx did not create a regular package")
    if payload_inventory(payload_root) != inventory:
        raise SystemExit("immutable payload changed during MSIX build")
    source_verifier.same_snapshot(
        baseline,
        source_verifier.verify_source_snapshot(
            source_root, source_manifest, candidate, tree
        ),
    )
    print(json.dumps({
        "candidate": candidate, "contract": "sos_windows_unsigned_msix_build_v1",
        "makeappx_sha256": args.makeappx_sha256, "msix_sha256": sha256(output),
        "msix_version": MSIX_VERSION, "payload_file_count": len(inventory),
        "payload_tree_digest": f"sha256:{payload_digest}",
        "stage_file_count": len(stage_before),
        "stage_tree_digest": f"sha256:{stage_digest}",
        "package_family_name": identity["package_family_name"],
        "package_identity_name": identity["package_identity_name"],
        "source_manifest_sha256": f"sha256:{baseline.manifest_sha256}",
        "source_tree_digest": f"sha256:{baseline.source_tree_digest}",
        "store_id": identity["store_id"], "status": "passed", "tree": tree,
    }, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
