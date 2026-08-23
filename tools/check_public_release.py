#!/usr/bin/env python3
"""Fail-closed public repository and release-contract inspection."""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
from pathlib import Path, PurePosixPath


MAX_FILE_BYTES = 2 * 1024 * 1024
MAX_FILES = 4096
FORBIDDEN_PARTS = {".env", "evidence", "private", "secrets"}
FORBIDDEN_TEXT = (
    re.compile(r"/home/[A-Za-z0-9._-]+/"),
    re.compile(r"-----BEGIN (?:OPENSSH|RSA|EC) PRIVATE KEY-----"),
    re.compile(r"\b(?:ghp|github_pat|sk_live|sk_test)_[A-Za-z0-9_-]{12,}\b"),
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    re.compile(r"\bGTM" + r"-REQ-[0-9]+\b"),
    re.compile(r"\bprod" + r"-SESSION\b", re.IGNORECASE),
    re.compile(r"\bSIGMA" + r"-GTM\b"),
    re.compile(r"\bsigma" + r"_runtime\b"),
)
REQUIRED_FILES = {
    "CHANGELOG.md",
    "CODE_OF_CONDUCT.md",
    "CONTRIBUTING.md",
    "LICENSE",
    "README.md",
    "SECURITY.md",
    "SUPPORT.md",
    "pyproject.toml",
}


def _inventory(repository: Path) -> list[str]:
    completed = subprocess.run(
        ["git", "-C", os.fspath(repository), "ls-files", "--cached", "--others", "--exclude-standard", "-z"],
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    files = [item.decode("utf-8") for item in completed.stdout.split(b"\0") if item]
    return sorted(files)


def inspect(repository: Path) -> dict[str, object]:
    repository = repository.resolve(strict=True)
    files = _inventory(repository)
    failures: list[str] = []
    if len(files) > MAX_FILES:
        failures.append("SOS_PUBLIC_FILE_LIMIT_EXCEEDED")
    missing = sorted(REQUIRED_FILES.difference(files))
    if missing:
        failures.append("SOS_PUBLIC_REQUIRED_FILE_MISSING")
    for name in files[: MAX_FILES + 1]:
        path_name = PurePosixPath(name)
        if path_name.is_absolute() or ".." in path_name.parts or FORBIDDEN_PARTS.intersection(path_name.parts):
            failures.append(f"SOS_PUBLIC_PATH_FORBIDDEN:{name}")
            continue
        path = repository / name
        if path.is_symlink() or not path.is_file():
            failures.append(f"SOS_PUBLIC_FILE_TYPE_FORBIDDEN:{name}")
            continue
        data = path.read_bytes()
        if len(data) > MAX_FILE_BYTES:
            failures.append(f"SOS_PUBLIC_FILE_TOO_LARGE:{name}")
            continue
        if b"\0" in data:
            continue
        try:
            text = data.decode("utf-8")
        except UnicodeDecodeError:
            failures.append(f"SOS_PUBLIC_TEXT_ENCODING_INVALID:{name}")
            continue
        for pattern in FORBIDDEN_TEXT:
            if pattern.search(text):
                failures.append(f"SOS_PUBLIC_CONTENT_FORBIDDEN:{name}")
                break
    return {
        "contract": "sos_public_release_scan_v1",
        "file_count": len(files),
        "failures": sorted(set(failures)),
        "status": "passed" if not failures else "failed",
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repository", type=Path, default=Path.cwd())
    arguments = parser.parse_args(argv)
    try:
        result = inspect(arguments.repository)
    except (OSError, subprocess.CalledProcessError, UnicodeError) as error:
        result = {
            "contract": "sos_public_release_scan_v1",
            "failures": ["SOS_PUBLIC_SCAN_FAILED"],
            "message": str(error),
            "status": "failed",
        }
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0 if result["status"] == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
