#!/usr/bin/env python3
"""Compare two wheel payloads while ignoring host-specific ZIP container bytes."""

from __future__ import annotations

import argparse
import hashlib
import json
import zipfile
from pathlib import Path, PurePosixPath


def _payload(path: Path) -> tuple[str, dict[str, bytes]]:
    entries: dict[str, bytes] = {}
    with zipfile.ZipFile(path.resolve(strict=True)) as archive:
        for info in archive.infolist():
            name = info.filename
            pure = PurePosixPath(name)
            if (
                info.is_dir()
                or name in entries
                or pure.is_absolute()
                or ".." in pure.parts
                or "\\" in name
            ):
                raise ValueError("unsafe or duplicate wheel entry")
            entries[name] = archive.read(info)
    digest = hashlib.sha256()
    for name in sorted(entries):
        encoded = name.encode("utf-8")
        digest.update(len(encoded).to_bytes(4, "big"))
        digest.update(encoded)
        digest.update(len(entries[name]).to_bytes(8, "big"))
        digest.update(entries[name])
    return digest.hexdigest(), entries


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--rebuilt", required=True, type=Path)
    parser.add_argument("--staged", required=True, type=Path)
    arguments = parser.parse_args()
    try:
        rebuilt_digest, rebuilt = _payload(arguments.rebuilt)
        staged_digest, staged = _payload(arguments.staged)
        if rebuilt != staged:
            raise ValueError("wheel payloads differ")
        result = {
            "contract": "sos_wheel_payload_comparison_v1",
            "entry_count": len(rebuilt),
            "payload_digest": rebuilt_digest,
            "staged_payload_digest": staged_digest,
            "status": "passed",
        }
        exit_code = 0
    except (OSError, ValueError, zipfile.BadZipFile) as error:
        result = {
            "contract": "sos_wheel_payload_comparison_v1",
            "reason": "SOS_WHEEL_PAYLOAD_MISMATCH",
            "status": "failed",
        }
        exit_code = 2
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
