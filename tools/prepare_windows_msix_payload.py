#!/usr/bin/env python3
"""Remove non-portable Python bytecode from a marker-owned MSIX payload."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import stat
import sys
from pathlib import Path


MARKER = ".sos-msix-disposable-payload-v1"
MARKER_BYTES = {
    b"sos-windows-msix-disposable-payload-v1\n",
    b"sos-windows-msix-disposable-payload-v1\r\n",
}
MAX_OBJECTS = 100_000


class PreparationError(ValueError):
    """The disposable payload cannot be prepared safely."""


def is_reparse(observed: os.stat_result) -> bool:
    attributes = getattr(observed, "st_file_attributes", 0)
    reparse = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
    return bool(attributes & reparse)


def tree_digest(root: Path) -> tuple[int, str]:
    records: list[tuple[str, int, str]] = []
    for directory, names, files in os.walk(root, topdown=True, followlinks=False):
        names.sort()
        files.sort()
        directory_path = Path(directory)
        admitted: list[str] = []
        for name in names:
            child = directory_path / name
            observed = child.lstat()
            if not stat.S_ISDIR(observed.st_mode) or is_reparse(observed):
                raise PreparationError("payload contains a link or reparse object")
            admitted.append(name)
        names[:] = admitted
        for name in files:
            child = directory_path / name
            observed = child.lstat()
            if not stat.S_ISREG(observed.st_mode) or is_reparse(observed):
                raise PreparationError("payload contains a non-regular object")
            digest = hashlib.sha256()
            with child.open("rb") as source:
                for block in iter(lambda: source.read(1024 * 1024), b""):
                    digest.update(block)
            records.append(
                (child.relative_to(root).as_posix(), observed.st_size, digest.hexdigest())
            )
            if len(records) > MAX_OBJECTS:
                raise PreparationError("payload object count is unbounded")
    canonical = json.dumps(records, separators=(",", ":")).encode()
    return len(records), hashlib.sha256(canonical).hexdigest()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--payload-root", required=True, type=Path)
    args = parser.parse_args()
    supplied_root = args.payload_root.lstat()
    if stat.S_ISLNK(supplied_root.st_mode) or is_reparse(supplied_root):
        raise PreparationError("payload root is a link or reparse object")
    root = args.payload_root.resolve(strict=True)
    observed_root = root.lstat()
    if not stat.S_ISDIR(observed_root.st_mode) or is_reparse(observed_root):
        raise PreparationError("payload root is not a plain directory")
    marker = root / MARKER
    try:
        marker_stat = marker.lstat()
        if not stat.S_ISREG(marker_stat.st_mode) or is_reparse(marker_stat):
            raise PreparationError("payload ownership marker is invalid")
        marker_bytes = marker.read_bytes()
    except OSError as error:
        raise PreparationError("payload ownership marker is missing") from error
    if marker_bytes not in MARKER_BYTES:
        raise PreparationError("payload ownership marker is invalid")

    bytecode: list[Path] = []
    cache_directories: list[Path] = []
    object_count = 0
    for directory, names, files in os.walk(root, topdown=True, followlinks=False):
        names.sort()
        files.sort()
        directory_path = Path(directory)
        admitted: list[str] = []
        for name in names:
            child = directory_path / name
            observed = child.lstat()
            if not stat.S_ISDIR(observed.st_mode) or is_reparse(observed):
                raise PreparationError("payload contains a link or reparse object")
            admitted.append(name)
            if name == "__pycache__":
                cache_directories.append(child)
        names[:] = admitted
        for name in files:
            child = directory_path / name
            observed = child.lstat()
            if not stat.S_ISREG(observed.st_mode) or is_reparse(observed):
                raise PreparationError("payload contains a non-regular object")
            if child == marker:
                continue
            if name.lower().endswith((".pyc", ".pyo")):
                if child.parent.name == "__pycache__":
                    stem = name.split(".cpython-", 1)[0].split(".pypy", 1)[0]
                    source = child.parent.parent / f"{stem}.py"
                else:
                    source = child.with_suffix(".py")
                if not source.is_file() or source.is_symlink():
                    raise PreparationError("bytecode-only Python module is unsupported")
                bytecode.append(child)
            object_count += 1
            if object_count > MAX_OBJECTS:
                raise PreparationError("payload object count is unbounded")

    for path in bytecode:
        path.unlink()
    for directory in sorted(cache_directories, key=lambda item: len(item.parts), reverse=True):
        try:
            directory.rmdir()
        except OSError as error:
            raise PreparationError("Python cache directory contains unexpected data") from error
    marker.unlink()

    for path in root.rglob("*"):
        if path.name == "__pycache__" or path.name.lower().endswith((".pyc", ".pyo")):
            raise PreparationError("Python bytecode remains in the payload")
    file_count, digest = tree_digest(root)
    print(
        json.dumps(
            {
                "contract": "sos_windows_msix_payload_preparation_v1",
                "payload_file_count": file_count,
                "payload_tree_digest": f"sha256:{digest}",
                "removed_bytecode_count": len(bytecode),
                "removed_cache_directory_count": len(cache_directories),
                "status": "passed",
            },
            sort_keys=True,
            separators=(",", ":"),
        )
    )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (PreparationError, OSError) as error:
        print(f"SOS_MSIX_PAYLOAD_PREPARATION_FAILED: {error}", file=sys.stderr)
        raise SystemExit(2)
