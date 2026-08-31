#!/usr/bin/env python3
"""Verify two default-MakeAppx-unpacked MSIX trees exactly.

This verifier intentionally does not parse ZIP/MSIX container structures.  The
same digest-bound MakeAppx binary that packed each candidate must first unpack
it with default semantic validation.  This program then proves that both
unpacked trees contain exactly the reviewed payload and have identical bytes.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import re
import stat
import sys
import urllib.parse
import xml.etree.ElementTree as ET
from pathlib import Path, PurePosixPath


CONTRACT = "sos_windows_msix_semantic_comparison_v2"
PAYLOAD_CONTRACT = "sos_windows_msix_payload_v1"
PAYLOAD_KEYS = {
    "artifacts",
    "candidate",
    "contract",
    "executable_acquisition_after_install",
    "msix_version",
    "network_after_package_download",
    "platform",
    "sos_version",
    "tree",
}
UNPACKED_GENERATED_ENTRIES = {
    "AppxBlockMap.xml",
    "AppxManifest.xml",
    "Assets/Square150x150Logo.png",
    "Assets/Square44x44Logo.png",
    "Assets/Square50x50Logo.png",
    "payload-manifest.json",
}
CONTAINER_ONLY_ENTRIES = {"[Content_Types].xml"}
RESERVED_GENERATED_ENTRIES = UNPACKED_GENERATED_ENTRIES | CONTAINER_ONLY_ENTRIES
MAX_FILES = 50_000
MAX_FILE_SIZE = 512 * 1024 * 1024
MAX_TOTAL_SIZE = 2 * 1024 * 1024 * 1024
MAX_MANIFEST_SIZE = 16 * 1024 * 1024
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
BLOCKMAP_NAMESPACE = "http://schemas.microsoft.com/appx/2010/blockmap"
BLOCKMAP_FILE_HASH_NAMESPACE = "http://schemas.microsoft.com/appx/2021/blockmap"
BLOCKMAP_HASH_METHOD = "http://www.w3.org/2001/04/xmlenc#sha256"


class ComparisonError(ValueError):
    """The semantic MSIX comparison cannot be admitted."""


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for block in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def is_reparse(stat_result: os.stat_result) -> bool:
    attributes = getattr(stat_result, "st_file_attributes", 0)
    reparse = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
    return bool(attributes & reparse)


def safe_relative(value: str) -> str:
    if (
        not value
        or "\\" in value
        or "\0" in value
        or any(ord(character) < 32 or character in '<>"|?*' for character in value)
    ):
        raise ComparisonError("unsafe package path")
    path = PurePosixPath(value)
    if path.is_absolute() or any(part in ("", ".", "..") for part in path.parts):
        raise ComparisonError("unsafe package path")
    for part in path.parts:
        if part.endswith((" ", ".")) or ":" in part:
            raise ComparisonError("Windows-unsafe package path")
        if part.split(".", 1)[0].upper() in WINDOWS_RESERVED:
            raise ComparisonError("Windows-reserved package path")
    return path.as_posix()


def inventory(root: Path) -> dict[str, tuple[int, str]]:
    resolved = root.resolve(strict=True)
    root_stat = resolved.lstat()
    if not stat.S_ISDIR(root_stat.st_mode) or is_reparse(root_stat):
        raise ComparisonError("unpack root is not a plain directory")
    found: dict[str, tuple[int, str]] = {}
    folded: dict[str, str] = {}
    total_size = 0
    for directory, names, files in os.walk(resolved, topdown=True, followlinks=False):
        names.sort()
        files.sort()
        directory_path = Path(directory)
        admitted_directories: list[str] = []
        for name in names:
            child = directory_path / name
            observed = child.lstat()
            if not stat.S_ISDIR(observed.st_mode) or is_reparse(observed):
                raise ComparisonError("unpack tree contains a link or reparse object")
            safe_relative(child.relative_to(resolved).as_posix())
            admitted_directories.append(name)
        names[:] = admitted_directories
        for name in files:
            child = directory_path / name
            observed = child.lstat()
            if not stat.S_ISREG(observed.st_mode) or is_reparse(observed):
                raise ComparisonError("unpack tree contains a non-regular object")
            relative = safe_relative(child.relative_to(resolved).as_posix())
            folded_name = relative.casefold()
            if folded_name in folded and folded[folded_name] != relative:
                raise ComparisonError("unpack tree contains a case-fold collision")
            folded[folded_name] = relative
            if observed.st_size > MAX_FILE_SIZE:
                raise ComparisonError("unpack tree file exceeds the size limit")
            total_size += observed.st_size
            if total_size > MAX_TOTAL_SIZE:
                raise ComparisonError("unpack tree exceeds the total size limit")
            found[relative] = (observed.st_size, sha256_file(child))
            if len(found) > MAX_FILES:
                raise ComparisonError("unpack tree exceeds the file-count limit")
    return found


def read_payload_manifest(
    root: Path,
    observed: dict[str, tuple[int, str]],
    candidate: str,
    tree: str,
) -> tuple[dict[str, object], dict[str, str]]:
    item = observed.get("payload-manifest.json")
    if item is None or item[0] > MAX_MANIFEST_SIZE:
        raise ComparisonError("payload manifest is missing or oversized")
    try:
        record = json.loads(
            read_bound_bytes(
                root, observed, "payload-manifest.json", MAX_MANIFEST_SIZE
            ).decode("utf-8")
        )
    except (UnicodeError, json.JSONDecodeError, OSError) as error:
        raise ComparisonError("payload manifest is unreadable") from error
    if not isinstance(record, dict) or set(record) != PAYLOAD_KEYS:
        raise ComparisonError("payload manifest contract is invalid")
    if (
        record["contract"] != PAYLOAD_CONTRACT
        or record["candidate"] != candidate
        or record["tree"] != tree
        or record["sos_version"] != "0.1.0a2"
        or record["msix_version"] != "1.0.2.0"
        or record["platform"] != "windows-x86_64"
        or record["network_after_package_download"] is not False
        or record["executable_acquisition_after_install"] is not False
    ):
        raise ComparisonError("payload manifest binding is invalid")
    artifacts = record["artifacts"]
    if not isinstance(artifacts, list):
        raise ComparisonError("payload artifact inventory is invalid")
    bound: dict[str, str] = {}
    previous = ""
    for artifact in artifacts:
        if not isinstance(artifact, dict) or set(artifact) != {"path", "sha256"}:
            raise ComparisonError("payload artifact record is invalid")
        path = artifact["path"]
        digest = artifact["sha256"]
        if not isinstance(path, str) or not isinstance(digest, str):
            raise ComparisonError("payload artifact record is invalid")
        path = safe_relative(path)
        if path <= previous or path in bound:
            raise ComparisonError("payload artifact inventory is not strictly ordered")
        if not re.fullmatch(r"[0-9a-f]{64}", digest):
            raise ComparisonError("payload artifact digest is invalid")
        if path.lower().endswith((".pyc", ".pyo")) or "__pycache__" in PurePosixPath(path).parts:
            raise ComparisonError("Python bytecode is forbidden in the MSIX payload")
        bound[path] = digest
        previous = path
    if set(bound) & RESERVED_GENERATED_ENTRIES:
        raise ComparisonError("payload artifact collides with a generated entry")
    expected = set(bound) | UNPACKED_GENERATED_ENTRIES
    if set(observed) != expected:
        raise ComparisonError("unpacked package inventory differs from the exact payload")
    for path, digest in bound.items():
        if observed[path][1] != digest:
            raise ComparisonError("unpacked payload digest differs from its manifest")
    if "AppxSignature.p7x" in observed:
        raise ComparisonError("unsigned package unexpectedly contains a signature")
    return record, bound


def read_bound_bytes(
    root: Path,
    observed: dict[str, tuple[int, str]],
    relative: str,
    limit: int,
) -> bytes:
    expected = observed.get(relative)
    if expected is None or expected[0] > limit:
        raise ComparisonError("bound package file is missing or oversized")
    value = (root / relative).read_bytes()
    if len(value) != expected[0] or hashlib.sha256(value).hexdigest() != expected[1]:
        raise ComparisonError("package file changed after inventory")
    return value


def validate_file_blocks(
    root: Path,
    relative: str,
    expected: tuple[int, str],
    children: list[ET.Element],
) -> None:
    blocks: list[ET.Element] = []
    file_hash: ET.Element | None = None
    for child in children:
        if child.tag == f"{{{BLOCKMAP_NAMESPACE}}}Block" and file_hash is None:
            blocks.append(child)
            continue
        if (
            child.tag == f"{{{BLOCKMAP_FILE_HASH_NAMESPACE}}}FileHash"
            and file_hash is None
            and set(child.attrib) == {"Hash"}
        ):
            file_hash = child
            continue
        raise ComparisonError("block map file child record is invalid")
    whole = hashlib.sha256()
    index = 0
    with (root / relative).open("rb") as source:
        while True:
            chunk = source.read(64 * 1024)
            if not chunk:
                break
            if index >= len(blocks):
                raise ComparisonError("block map omits package content")
            block = blocks[index]
            if block.tag != f"{{{BLOCKMAP_NAMESPACE}}}Block" or set(
                block.attrib
            ) not in ({"Hash"}, {"Hash", "Size"}):
                raise ComparisonError("block map block record is invalid")
            try:
                decoded = base64.b64decode(block.attrib["Hash"], validate=True)
            except (KeyError, ValueError) as error:
                raise ComparisonError("block map block hash is invalid") from error
            if len(decoded) != 32 or decoded != hashlib.sha256(chunk).digest():
                raise ComparisonError("block map block hash differs from package content")
            compressed_size = block.attrib.get("Size")
            if compressed_size is not None:
                try:
                    parsed_size = int(compressed_size, 10)
                except ValueError as error:
                    raise ComparisonError("block map compressed size is invalid") from error
                if parsed_size < 0 or parsed_size > MAX_FILE_SIZE:
                    raise ComparisonError("block map compressed size is invalid")
            whole.update(chunk)
            index += 1
    if index != len(blocks):
        raise ComparisonError("block map contains extra blocks")
    if expected[0] == 0 and blocks:
        raise ComparisonError("block map gives blocks to an empty file")
    if whole.hexdigest() != expected[1]:
        raise ComparisonError("package file changed during block validation")
    if file_hash is not None:
        try:
            decoded_file_hash = base64.b64decode(
                file_hash.attrib["Hash"], validate=True
            )
        except (KeyError, ValueError) as error:
            raise ComparisonError("block map file hash is invalid") from error
        if len(decoded_file_hash) != 32 or decoded_file_hash.hex() != expected[1]:
            raise ComparisonError("block map file hash differs from package content")


def validate_block_map(
    root: Path, observed: dict[str, tuple[int, str]]
) -> None:
    value = read_bound_bytes(root, observed, "AppxBlockMap.xml", MAX_MANIFEST_SIZE)
    upper = value.upper()
    if b"<!DOCTYPE" in upper or b"<!ENTITY" in upper:
        raise ComparisonError("block map contains a forbidden XML declaration")
    try:
        document = ET.fromstring(value)
    except ET.ParseError as error:
        raise ComparisonError("block map XML is invalid") from error
    if document.tag != f"{{{BLOCKMAP_NAMESPACE}}}BlockMap":
        raise ComparisonError("block map namespace is invalid")
    if set(document.attrib) not in (
        {"HashMethod"},
        {"HashMethod", "IgnorableNamespaces"},
    ):
        raise ComparisonError("block map root attributes are invalid")
    if document.attrib.get("HashMethod") != BLOCKMAP_HASH_METHOD:
        raise ComparisonError("block map hash method is invalid")
    if (
        "IgnorableNamespaces" in document.attrib
        and document.attrib["IgnorableNamespaces"] != "b4"
    ):
        raise ComparisonError("block map ignorable namespace is invalid")
    expected = set(observed) - {"AppxBlockMap.xml"}
    files: dict[str, int] = {}
    for child in document:
        if child.tag != f"{{{BLOCKMAP_NAMESPACE}}}File" or set(
            child.attrib
        ) != {"Name", "Size", "LfhSize"}:
            raise ComparisonError("block map file record is invalid")
        encoded_name = child.attrib.get("Name")
        encoded_size = child.attrib.get("Size")
        if not encoded_name or encoded_size is None:
            raise ComparisonError("block map file record is incomplete")
        try:
            name = safe_relative(
                urllib.parse.unquote(encoded_name.replace("\\", "/"), errors="strict")
            )
            size = int(encoded_size, 10)
            local_header_size = int(child.attrib["LfhSize"], 10)
        except (UnicodeError, ValueError) as error:
            raise ComparisonError("block map file record is invalid") from error
        if name in files or size < 0 or local_header_size <= 0:
            raise ComparisonError("block map file inventory is ambiguous")
        files[name] = size
        if name not in observed:
            raise ComparisonError("block map names content outside the package")
        children = list(child)
        if any(
            item.tag == f"{{{BLOCKMAP_FILE_HASH_NAMESPACE}}}FileHash"
            for item in children
        ) and document.attrib.get("IgnorableNamespaces") != "b4":
            raise ComparisonError("block map file hash namespace is not ignorable")
        validate_file_blocks(root, name, observed[name], children)
    if set(files) != expected:
        raise ComparisonError("block map inventory differs from package content")
    for name, size in files.items():
        if observed[name][0] != size:
            raise ComparisonError("block map file size differs from package content")


def validate_package_xml(
    root: Path, observed: dict[str, tuple[int, str]]
) -> None:
    for relative in ("AppxManifest.xml",):
        value = read_bound_bytes(root, observed, relative, MAX_MANIFEST_SIZE)
        upper = value.upper()
        if b"<!DOCTYPE" in upper or b"<!ENTITY" in upper:
            raise ComparisonError("package XML contains a forbidden declaration")
        try:
            ET.fromstring(value)
        except ET.ParseError as error:
            raise ComparisonError("package XML is invalid") from error


def content_digest(observed: dict[str, tuple[int, str]]) -> str:
    canonical = [
        {"path": path, "sha256": digest, "size": size}
        for path, (size, digest) in sorted(observed.items())
    ]
    encoded = json.dumps(canonical, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(encoded).hexdigest()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("first_msix", type=Path)
    parser.add_argument("second_msix", type=Path)
    parser.add_argument("--first-unpacked", required=True, type=Path)
    parser.add_argument("--second-unpacked", required=True, type=Path)
    parser.add_argument("--candidate", required=True)
    parser.add_argument("--tree", required=True)
    parser.add_argument("--makeappx-sha256", required=True)
    args = parser.parse_args()
    if not re.fullmatch(r"[0-9a-f]{40}", args.candidate):
        raise ComparisonError("candidate binding is invalid")
    if not re.fullmatch(r"[0-9a-f]{40}", args.tree):
        raise ComparisonError("tree binding is invalid")
    if not re.fullmatch(r"[0-9a-f]{64}", args.makeappx_sha256):
        raise ComparisonError("MakeAppx binding is invalid")
    for supplied in (
        args.first_msix,
        args.second_msix,
        args.first_unpacked,
        args.second_unpacked,
    ):
        supplied_stat = supplied.lstat()
        if stat.S_ISLNK(supplied_stat.st_mode) or is_reparse(supplied_stat):
            raise ComparisonError("input path is a link or reparse object")
    first_msix = args.first_msix.resolve(strict=True)
    second_msix = args.second_msix.resolve(strict=True)
    if not stat.S_ISREG(first_msix.lstat().st_mode) or not stat.S_ISREG(
        second_msix.lstat().st_mode
    ):
        raise ComparisonError("MSIX input is not a regular file")
    first_root = args.first_unpacked.resolve(strict=True)
    second_root = args.second_unpacked.resolve(strict=True)
    first = inventory(first_root)
    second = inventory(second_root)
    first_record, first_payload = read_payload_manifest(
        first_root, first, args.candidate, args.tree
    )
    second_record, second_payload = read_payload_manifest(
        second_root, second, args.candidate, args.tree
    )
    if first_record != second_record or first_payload != second_payload:
        raise ComparisonError("payload manifests differ")
    if first != second:
        raise ComparisonError("default-MakeAppx-unpacked package content differs")
    validate_package_xml(first_root, first)
    validate_package_xml(second_root, second)
    validate_block_map(first_root, first)
    validate_block_map(second_root, second)
    if inventory(first_root) != first or inventory(second_root) != second:
        raise ComparisonError("unpacked package changed during semantic validation")
    first_sha = sha256_file(first_msix)
    second_sha = sha256_file(second_msix)
    digest = content_digest(first)
    report = {
        "byte_identical": first_sha == second_sha,
        "candidate": args.candidate,
        "container_equivalence_claimed": False,
        "contract": CONTRACT,
        "first_msix_sha256": f"sha256:{first_sha}",
        "makeappx_sha256": f"sha256:{args.makeappx_sha256}",
        "package_content_digest": f"sha256:{digest}",
        "package_file_count": len(first),
        "payload_file_count": len(first_payload),
        "pyc_file_count": 0,
        "raw_content_serialized": False,
        "second_msix_sha256": f"sha256:{second_sha}",
        "status": "passed",
        "tree": args.tree,
        "verification_method": "default_makeappx_unpack_exact_content_v1",
    }
    print(json.dumps(report, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (ComparisonError, OSError) as error:
        print(f"SOS_MSIX_SEMANTIC_COMPARISON_FAILED: {error}", file=sys.stderr)
        raise SystemExit(2)
