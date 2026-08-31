#!/usr/bin/env python3
"""Fail closed on host-derived or private SOS-owned MSIX content.

The package payload contains opaque, separately digest-bound third-party
artifacts (the managed Python runtime, dependency wheels and native launchers).
Those bytes are not decoded heuristically here: doing so would make ordinary
compiler metadata look like user data.  This gate instead scans every
SOS-owned/generated text file after a default MakeAppx unpack, while proving
that all remaining files are exactly bound by the package payload manifest.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
import re
import stat
import sys
from pathlib import Path, PurePosixPath


def _load_semantic_module():
    path = Path(__file__).resolve().with_name("compare_windows_msix.py")
    specification = importlib.util.spec_from_file_location(
        "_sos_bound_compare_windows_msix", path
    )
    if specification is None or specification.loader is None:
        raise RuntimeError("bound semantic verifier could not be loaded")
    module = importlib.util.module_from_spec(specification)
    specification.loader.exec_module(module)
    return module


semantic = _load_semantic_module()


CONTRACT = "sos_windows_msix_content_safety_v1"
MAX_TEXT_BYTES = 4 * 1024 * 1024
MAX_TOTAL_TEXT_BYTES = 64 * 1024 * 1024
GENERATED_TEXT = {
    "AppxManifest.xml",
    "payload-manifest.json",
}
SOS_TEXT_PREFIXES = (
    "runtime/Lib/site-packages/sos/",
)
SOS_TEXT_SUFFIXES = (
    ".py",
    ".json",
    ".md",
    ".toml",
    ".txt",
    ".xml",
    ".yaml",
    ".yml",
)
FORBIDDEN_PATTERNS = (
    re.compile(rb"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----"),
    re.compile(rb"(?i)(?:api[_-]?key|access[_-]?token|client[_-]?secret)\s*[:=]\s*['\"]?[^\s'\"]{12,}"),
    re.compile(rb"\bAKIA[0-9A-Z]{16}\b"),
    re.compile(rb"\bgh[pousr]_[A-Za-z0-9_]{20,}\b"),
    re.compile(rb"\bsk-[A-Za-z0-9_-]{20,}\b"),
    re.compile(rb"(?i)(?:[A-Z]:[\\/](?:Users|Downloads|Documents|Desktop|Temp|tmp)[\\/])"),
    re.compile(rb"(?:/home/|/Users/|/tmp/|/private/var/|/var/folders/)"),
    re.compile(
        rb"\\\\[A-Za-z0-9][A-Za-z0-9._-]{0,252}\\"
        rb"[A-Za-z0-9$][A-Za-z0-9$._ -]{0,127}(?:\\[^\r\n\"']*)?"
    ),
    re.compile(rb"(?:sigma_worktrees|codex-clipboard|<response-annotations>|GTM-REQ-[0-9]+)"),
)


class ContentSafetyError(ValueError):
    """The final package content cannot be admitted as public-safe."""


def _is_plain_file(path: Path) -> bool:
    observed = path.lstat()
    attributes = getattr(observed, "st_file_attributes", 0)
    return (
        stat.S_ISREG(observed.st_mode)
        and not stat.S_ISLNK(observed.st_mode)
        and not attributes & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
    )


def _read_bound(
    root: Path,
    observed: dict[str, tuple[int, str]],
    relative: str,
) -> bytes:
    expected = observed[relative]
    if expected[0] > MAX_TEXT_BYTES:
        raise ContentSafetyError("SOS-owned text exceeds the bounded size limit")
    path = root / PurePosixPath(relative)
    if not _is_plain_file(path):
        raise ContentSafetyError("SOS-owned text is not a plain regular file")
    payload = path.read_bytes()
    if len(payload) != expected[0] or hashlib.sha256(payload).hexdigest() != expected[1]:
        raise ContentSafetyError("SOS-owned text drifted after package inventory")
    return payload


def _is_sos_owned_text(relative: str) -> bool:
    if relative in GENERATED_TEXT:
        return True
    return relative.startswith(SOS_TEXT_PREFIXES) and relative.lower().endswith(
        SOS_TEXT_SUFFIXES
    )


def check_content(root: Path, candidate: str, tree: str) -> dict[str, object]:
    resolved = root.resolve(strict=True)
    observed = semantic.inventory(resolved)
    _record, payload = semantic.read_payload_manifest(
        resolved, observed, candidate, tree
    )
    scanned = 0
    scanned_bytes = 0
    for relative in sorted(observed):
        if not _is_sos_owned_text(relative):
            continue
        value = _read_bound(resolved, observed, relative)
        scanned_bytes += len(value)
        if scanned_bytes > MAX_TOTAL_TEXT_BYTES:
            raise ContentSafetyError("SOS-owned text exceeds the total size limit")
        try:
            value.decode("utf-8")
        except UnicodeDecodeError as error:
            raise ContentSafetyError("SOS-owned text is not UTF-8") from error
        if any(pattern.search(value) for pattern in FORBIDDEN_PATTERNS):
            raise ContentSafetyError("SOS-owned text contains forbidden private material")
        scanned += 1
    if scanned < len(GENERATED_TEXT):
        raise ContentSafetyError("generated package text was not fully scanned")
    if semantic.inventory(resolved) != observed:
        raise ContentSafetyError("package content drifted during the safety scan")
    body: dict[str, object] = {
        "absolute_paths_serialized": False,
        "candidate": candidate,
        "contract": CONTRACT,
        "opaque_bound_file_count": len(observed) - scanned,
        "package_content_digest": f"sha256:{semantic.content_digest(observed)}",
        "package_file_count": len(observed),
        "payload_file_count": len(payload),
        "raw_content_serialized": False,
        "scanned_text_file_count": scanned,
        "status": "passed",
        "tree": tree,
    }
    digest = hashlib.sha256(
        json.dumps(body, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    body["report_digest"] = f"sha256:{digest}"
    return body


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--unpacked-root", required=True, type=Path)
    parser.add_argument("--candidate", required=True)
    parser.add_argument("--tree", required=True)
    arguments = parser.parse_args()
    if not re.fullmatch(r"[0-9a-f]{40}", arguments.candidate):
        raise ContentSafetyError("candidate binding is invalid")
    if not re.fullmatch(r"[0-9a-f]{40}", arguments.tree):
        raise ContentSafetyError("tree binding is invalid")
    report = check_content(
        arguments.unpacked_root, arguments.candidate, arguments.tree
    )
    print(json.dumps(report, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (ContentSafetyError, semantic.ComparisonError, OSError) as error:
        print(f"SOS_MSIX_CONTENT_SAFETY_FAILED: {error}", file=sys.stderr)
        raise SystemExit(2)
