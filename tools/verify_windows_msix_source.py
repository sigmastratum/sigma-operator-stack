#!/usr/bin/env python3
"""Verify an exact Git-free SOS source snapshot for the Windows MSIX build.

The source manifest is external to the source tree so that its digest can be
bound by the outer distribution packet without a self-referential inventory.
Only regular, non-reparse files are admitted.  The manifest is a closed full
inventory: an omitted, additional, renamed, or changed source object fails
closed before a build tool is invoked.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
import sys
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import BinaryIO


CONTRACT = "sos_windows_msix_source_manifest_v1"
MANIFEST_KEYS = {
    "candidate",
    "contract",
    "file_count",
    "files",
    "inventory_digest",
    "tree",
}
ARTIFACT_KEYS = {"path", "sha256", "size"}
WINDOWS_RESERVED = {
    "CON",
    "CONIN$",
    "CONOUT$",
    "PRN",
    "AUX",
    "NUL",
    *(f"COM{number}" for number in range(1, 10)),
    *(f"LPT{number}" for number in range(1, 10)),
}
MAX_MANIFEST_BYTES = 16 * 1024 * 1024
MAX_SOURCE_FILES = 20_000
MAX_SOURCE_FILE_SIZE = 64 * 1024 * 1024
MAX_SOURCE_SIZE = 512 * 1024 * 1024


class SourceVerificationError(ValueError):
    """The exact source snapshot cannot be admitted."""


def is_reparse(observed: os.stat_result) -> bool:
    attributes = getattr(observed, "st_file_attributes", 0)
    reparse = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
    return bool(attributes & reparse)


def sha256_stream(source: BinaryIO) -> str:
    digest = hashlib.sha256()
    for block in iter(lambda: source.read(1024 * 1024), b""):
        digest.update(block)
    return digest.hexdigest()


def sha256(path: Path) -> str:
    with path.open("rb") as source:
        return sha256_stream(source)


def safe_source_path(value: object) -> str:
    if (
        not isinstance(value, str)
        or not value
        or "\\" in value
        or "\0" in value
        or any(ord(character) < 32 or character in '<>"|?*' for character in value)
    ):
        raise SourceVerificationError("source path is unsafe")
    relative = PurePosixPath(value)
    if relative.is_absolute() or any(part in ("", ".", "..") for part in relative.parts):
        raise SourceVerificationError("source path is unsafe")
    for part in relative.parts:
        if part.endswith((" ", ".")) or ":" in part:
            raise SourceVerificationError("source path is unsafe on Windows")
        if part.split(".", 1)[0].upper() in WINDOWS_RESERVED:
            raise SourceVerificationError("source path is reserved on Windows")
    return relative.as_posix()


def _closed_json(payload: bytes) -> object:
    def reject_duplicate_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
        result: dict[str, object] = {}
        for key, value in pairs:
            if key in result:
                raise SourceVerificationError("source manifest contains a duplicate key")
            result[key] = value
        return result

    try:
        return json.loads(payload.decode("utf-8"), object_pairs_hook=reject_duplicate_keys)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise SourceVerificationError("source manifest is not canonical JSON") from error


def _plain_regular(path: Path, kind: str) -> os.stat_result:
    try:
        observed = path.lstat()
    except OSError as error:
        raise SourceVerificationError(f"{kind} is unavailable") from error
    if (
        not stat.S_ISREG(observed.st_mode)
        or stat.S_ISLNK(observed.st_mode)
        or is_reparse(observed)
        or observed.st_nlink != 1
    ):
        raise SourceVerificationError(f"{kind} is not a plain regular file")
    return observed


def _plain_directory(path: Path, kind: str) -> os.stat_result:
    try:
        observed = path.lstat()
    except OSError as error:
        raise SourceVerificationError(f"{kind} is unavailable") from error
    if (
        not stat.S_ISDIR(observed.st_mode)
        or stat.S_ISLNK(observed.st_mode)
        or is_reparse(observed)
    ):
        raise SourceVerificationError(f"{kind} is not a plain directory")
    return observed


@dataclass(frozen=True)
class SourceArtifact:
    path: str
    size: int
    sha256: str


@dataclass(frozen=True)
class VerifiedSourceSnapshot:
    candidate: str
    tree: str
    manifest_sha256: str
    source_tree_digest: str
    artifacts: tuple[SourceArtifact, ...]

    def artifact(self, relative: str) -> SourceArtifact:
        admitted = safe_source_path(relative)
        for artifact in self.artifacts:
            if artifact.path == admitted:
                return artifact
        raise SourceVerificationError("required source artifact is absent")


def _parse_manifest(
    manifest_path: Path,
    candidate: str,
    tree: str,
) -> tuple[bytes, tuple[SourceArtifact, ...]]:
    observed = _plain_regular(manifest_path, "source manifest")
    if observed.st_size <= 0 or observed.st_size > MAX_MANIFEST_BYTES:
        raise SourceVerificationError("source manifest size is invalid")
    before = (observed.st_dev, observed.st_ino, observed.st_size, observed.st_mtime_ns)
    payload = manifest_path.read_bytes()
    after_observed = _plain_regular(manifest_path, "source manifest")
    after = (
        after_observed.st_dev,
        after_observed.st_ino,
        after_observed.st_size,
        after_observed.st_mtime_ns,
    )
    if before != after or len(payload) != observed.st_size:
        raise SourceVerificationError("source manifest changed while it was read")
    record = _closed_json(payload)
    if not isinstance(record, dict) or set(record) != MANIFEST_KEYS:
        raise SourceVerificationError("source manifest contract is not closed")
    canonical = (
        json.dumps(record, sort_keys=True, separators=(",", ":")) + "\n"
    ).encode("utf-8")
    if payload != canonical:
        raise SourceVerificationError("source manifest bytes are not canonical")
    if (
        record["contract"] != CONTRACT
        or record["candidate"] != candidate
        or record["tree"] != tree
    ):
        raise SourceVerificationError("source manifest binding is invalid")
    raw_artifacts = record["files"]
    if (
        not isinstance(raw_artifacts, list)
        or not raw_artifacts
        or len(raw_artifacts) > MAX_SOURCE_FILES
    ):
        raise SourceVerificationError("source manifest artifact count is invalid")
    file_count = record["file_count"]
    if (
        not isinstance(file_count, int)
        or isinstance(file_count, bool)
        or file_count != len(raw_artifacts)
    ):
        raise SourceVerificationError("source manifest file count is invalid")
    artifacts: list[SourceArtifact] = []
    exact: set[str] = set()
    folded: dict[str, str] = {}
    total_size = 0
    for item in raw_artifacts:
        if not isinstance(item, dict) or set(item) != ARTIFACT_KEYS:
            raise SourceVerificationError("source artifact contract is not closed")
        path = safe_source_path(item["path"])
        size = item["size"]
        digest = item["sha256"]
        if path in exact:
            raise SourceVerificationError("source manifest contains a duplicate path")
        folded_path = path.casefold()
        if folded_path in folded and folded[folded_path] != path:
            raise SourceVerificationError("source manifest contains a case-fold collision")
        if (
            not isinstance(size, int)
            or isinstance(size, bool)
            or size < 0
            or size > MAX_SOURCE_FILE_SIZE
        ):
            raise SourceVerificationError("source artifact size is invalid")
        if not isinstance(digest, str) or not re.fullmatch(r"[0-9a-f]{64}", digest):
            raise SourceVerificationError("source artifact digest is invalid")
        total_size += size
        if total_size > MAX_SOURCE_SIZE:
            raise SourceVerificationError("source manifest exceeds the total size limit")
        exact.add(path)
        folded[folded_path] = path
        artifacts.append(SourceArtifact(path=path, size=size, sha256=digest))
    if [artifact.path for artifact in artifacts] != sorted(exact):
        raise SourceVerificationError("source manifest artifacts are not canonically ordered")
    admitted = tuple(artifacts)
    inventory_digest = record["inventory_digest"]
    if (
        not isinstance(inventory_digest, str)
        or inventory_digest != f"sha256:{_tree_digest(admitted)}"
    ):
        raise SourceVerificationError("source manifest inventory digest is invalid")
    return payload, admitted


def _source_inventory(
    root: Path,
    expected_directories: set[str],
) -> tuple[SourceArtifact, ...]:
    _plain_directory(root, "source root")
    artifacts: list[SourceArtifact] = []
    folded: dict[str, str] = {}
    observed_directories: set[str] = set()
    total_size = 0
    for directory, names, files in os.walk(root, topdown=True, followlinks=False):
        names.sort()
        files.sort()
        directory_path = Path(directory)
        admitted_names: list[str] = []
        for name in names:
            child = directory_path / name
            observed = child.lstat()
            if (
                not stat.S_ISDIR(observed.st_mode)
                or stat.S_ISLNK(observed.st_mode)
                or is_reparse(observed)
            ):
                raise SourceVerificationError("source links and reparse objects are forbidden")
            relative = safe_source_path(child.relative_to(root).as_posix())
            folded_path = relative.casefold()
            if folded_path in folded and folded[folded_path] != relative:
                raise SourceVerificationError("source contains a case-fold collision")
            folded[folded_path] = relative
            observed_directories.add(relative)
            admitted_names.append(name)
        names[:] = admitted_names
        for name in files:
            path = directory_path / name
            observed = path.lstat()
            if (
                not stat.S_ISREG(observed.st_mode)
                or stat.S_ISLNK(observed.st_mode)
                or is_reparse(observed)
            ):
                raise SourceVerificationError("source contains a non-regular object")
            relative = safe_source_path(path.relative_to(root).as_posix())
            folded_path = relative.casefold()
            if folded_path in folded and folded[folded_path] != relative:
                raise SourceVerificationError("source contains a case-fold collision")
            folded[folded_path] = relative
            if observed.st_size > MAX_SOURCE_FILE_SIZE:
                raise SourceVerificationError("source file exceeds the size limit")
            total_size += observed.st_size
            if total_size > MAX_SOURCE_SIZE or len(artifacts) >= MAX_SOURCE_FILES:
                raise SourceVerificationError("source inventory exceeds its bounded limits")
            before = (observed.st_dev, observed.st_ino, observed.st_size, observed.st_mtime_ns)
            digest = sha256(path)
            after_observed = _plain_regular(path, "source artifact")
            after = (
                after_observed.st_dev,
                after_observed.st_ino,
                after_observed.st_size,
                after_observed.st_mtime_ns,
            )
            if before != after:
                raise SourceVerificationError("source artifact changed while it was read")
            artifacts.append(SourceArtifact(relative, observed.st_size, digest))
    artifacts.sort(key=lambda artifact: artifact.path)
    if observed_directories != expected_directories:
        raise SourceVerificationError("source directory inventory is not exact")
    return tuple(artifacts)


def _tree_digest(artifacts: tuple[SourceArtifact, ...]) -> str:
    digest = hashlib.sha256()
    for item in artifacts:
        digest.update(item.path.encode("utf-8"))
        digest.update(b"\0")
        digest.update(str(item.size).encode("ascii"))
        digest.update(b"\0")
        digest.update(item.sha256.encode("ascii"))
        digest.update(b"\n")
    return digest.hexdigest()


def verify_source_snapshot(
    source_root: Path,
    source_manifest: Path,
    candidate: str,
    tree: str,
) -> VerifiedSourceSnapshot:
    if not re.fullmatch(r"[0-9a-f]{40}", candidate):
        raise SourceVerificationError("candidate binding is invalid")
    if not re.fullmatch(r"[0-9a-f]{40}", tree):
        raise SourceVerificationError("tree binding is invalid")
    _plain_directory(source_root, "source root")
    _plain_regular(source_manifest, "source manifest")
    root = source_root.resolve(strict=True)
    manifest = source_manifest.resolve(strict=True)
    if manifest == root or root in manifest.parents:
        raise SourceVerificationError("source manifest must be external to the source root")
    manifest_payload, expected = _parse_manifest(manifest, candidate, tree)
    expected_directories = {
        PurePosixPath(artifact.path).parent.as_posix()
        for artifact in expected
        if PurePosixPath(artifact.path).parent.as_posix() != "."
    }
    expected_directories |= {
        parent.as_posix()
        for artifact in expected
        for parent in PurePosixPath(artifact.path).parents
        if parent.as_posix() != "."
    }
    observed = _source_inventory(root, expected_directories)
    if observed != expected:
        raise SourceVerificationError("source inventory does not match its exact manifest")
    final_manifest_payload, final_expected = _parse_manifest(
        manifest, candidate, tree
    )
    final_observed = _source_inventory(root, expected_directories)
    if (
        final_manifest_payload != manifest_payload
        or final_expected != expected
        or final_observed != observed
    ):
        raise SourceVerificationError("source snapshot changed during verification")
    return VerifiedSourceSnapshot(
        candidate=candidate,
        tree=tree,
        manifest_sha256=hashlib.sha256(manifest_payload).hexdigest(),
        source_tree_digest=_tree_digest(observed),
        artifacts=observed,
    )


def read_bound_source_file(
    source_root: Path,
    snapshot: VerifiedSourceSnapshot,
    relative: str,
) -> bytes:
    artifact = snapshot.artifact(relative)
    path = source_root.resolve(strict=True) / PurePosixPath(artifact.path)
    observed = _plain_regular(path, "source artifact")
    if observed.st_size != artifact.size:
        raise SourceVerificationError("source artifact size drifted")
    payload = path.read_bytes()
    if len(payload) != artifact.size or hashlib.sha256(payload).hexdigest() != artifact.sha256:
        raise SourceVerificationError("source artifact digest drifted")
    after = _plain_regular(path, "source artifact")
    if (
        after.st_dev != observed.st_dev
        or after.st_ino != observed.st_ino
        or after.st_size != observed.st_size
        or after.st_mtime_ns != observed.st_mtime_ns
    ):
        raise SourceVerificationError("source artifact changed while it was read")
    return payload


def same_snapshot(
    expected: VerifiedSourceSnapshot,
    observed: VerifiedSourceSnapshot,
) -> None:
    if observed != expected:
        raise SourceVerificationError("source snapshot drifted")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--source-root", required=True, type=Path)
    parser.add_argument("--source-manifest", required=True, type=Path)
    parser.add_argument("--candidate", required=True)
    parser.add_argument("--tree", required=True)
    args = parser.parse_args()
    snapshot = verify_source_snapshot(
        args.source_root,
        args.source_manifest,
        args.candidate,
        args.tree,
    )
    print(
        json.dumps(
            {
                "candidate": snapshot.candidate,
                "contract": "sos_windows_msix_source_verification_v1",
                "manifest_sha256": f"sha256:{snapshot.manifest_sha256}",
                "source_file_count": len(snapshot.artifacts),
                "source_tree_digest": f"sha256:{snapshot.source_tree_digest}",
                "status": "passed",
                "tree": snapshot.tree,
            },
            sort_keys=True,
            separators=(",", ":"),
        )
    )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, SourceVerificationError) as error:
        print(f"SOS_MSIX_SOURCE_NOT_VERIFIED: {error}", file=sys.stderr)
        raise SystemExit(2)
