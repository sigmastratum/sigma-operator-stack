#!/usr/bin/env python3
"""Verify every archive declared by the public release index."""

from __future__ import annotations

import argparse
import hashlib
import json
import tarfile
import zipfile
from pathlib import Path, PurePosixPath


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _safe_member(name: str) -> PurePosixPath:
    path = PurePosixPath(name)
    if path.is_absolute() or not path.parts or ".." in path.parts or "" in path.parts:
        raise ValueError("unsafe archive member")
    return path


def _inner_manifest(archive: Path, expected_name: str) -> bytes:
    matches: list[tuple[str, bytes]] = []
    if archive.suffix == ".zip":
        with zipfile.ZipFile(archive) as bundle:
            for item in bundle.infolist():
                path = _safe_member(item.filename)
                if item.is_dir():
                    continue
                if path.name == expected_name:
                    matches.append((item.filename, bundle.read(item)))
    elif archive.name.endswith(".tar.gz"):
        with tarfile.open(archive, mode="r:gz") as bundle:
            for item in bundle.getmembers():
                path = _safe_member(item.name)
                if item.issym() or item.islnk():
                    raise ValueError("archive links are forbidden")
                if item.isfile() and path.name == expected_name:
                    stream = bundle.extractfile(item)
                    if stream is None:
                        raise ValueError("inner manifest is unreadable")
                    matches.append((item.name, stream.read()))
    else:
        raise ValueError("unsupported archive format")
    if len(matches) != 1:
        raise ValueError("inner manifest must occur exactly once")
    member_path = PurePosixPath(matches[0][0])
    if len(member_path.parts) not in {1, 2}:
        raise ValueError("inner manifest depth is invalid")
    return matches[0][1]


def inspect(index_path: Path, asset_dir: Path) -> dict[str, object]:
    index = json.loads(index_path.read_text(encoding="utf-8"))
    failures: list[str] = []
    checked: list[str] = []
    platforms = index.get("platforms")
    if not isinstance(platforms, list):
        platforms = []
        failures.append("SOS_NATIVE_RELEASE_INDEX_INVALID")
    seen: set[str] = set()
    for platform in platforms:
        if not isinstance(platform, dict) or platform.get("delivery") != "archive":
            continue
        filename = platform.get("archive_filename")
        if not isinstance(filename, str) or PurePosixPath(filename).name != filename:
            failures.append("SOS_NATIVE_RELEASE_ARCHIVE_NAME_INVALID")
            continue
        if filename in seen:
            failures.append(f"SOS_NATIVE_RELEASE_ARCHIVE_DUPLICATED:{filename}")
            continue
        seen.add(filename)
        archive = asset_dir / filename
        try:
            if archive.is_symlink() or not archive.is_file():
                raise FileNotFoundError(filename)
            if archive.stat().st_size != platform.get("archive_size"):
                failures.append(f"SOS_NATIVE_RELEASE_ARCHIVE_SIZE_MISMATCH:{filename}")
            if _sha256(archive) != platform.get("archive_sha256"):
                failures.append(f"SOS_NATIVE_RELEASE_ARCHIVE_DIGEST_MISMATCH:{filename}")
            payload = _inner_manifest(archive, str(platform.get("inner_manifest")))
            if hashlib.sha256(payload).hexdigest() != platform.get("inner_manifest_sha256"):
                failures.append(f"SOS_NATIVE_RELEASE_INNER_MANIFEST_MISMATCH:{filename}")
            checked.append(filename)
        except (FileNotFoundError, OSError, ValueError, tarfile.TarError, zipfile.BadZipFile):
            failures.append(f"SOS_NATIVE_RELEASE_ARCHIVE_UNAVAILABLE:{filename}")
    if not checked:
        failures.append("SOS_NATIVE_RELEASE_ARCHIVE_SET_EMPTY")
    return {
        "checked_archives": sorted(checked),
        "contract": "sos_native_release_asset_check_v1",
        "failures": sorted(set(failures)),
        "status": "passed" if not failures else "failed",
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--index", type=Path, required=True)
    parser.add_argument("--asset-dir", type=Path, required=True)
    arguments = parser.parse_args(argv)
    try:
        result = inspect(
            arguments.index.resolve(strict=True), arguments.asset_dir.resolve(strict=True)
        )
    except (OSError, TypeError, ValueError, json.JSONDecodeError) as error:
        result = {
            "checked_archives": [],
            "contract": "sos_native_release_asset_check_v1",
            "failures": ["SOS_NATIVE_RELEASE_ASSET_CHECK_FAILED"],
            "message": type(error).__name__,
            "status": "failed",
        }
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0 if result["status"] == "passed" else 2


if __name__ == "__main__":
    raise SystemExit(main())
