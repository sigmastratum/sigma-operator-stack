#!/usr/bin/env python3
"""Verify that a PyPI filename is absent or has the exact expected digest."""

from __future__ import annotations

import argparse
import json
import urllib.error
import urllib.request
from pathlib import Path


def check(project: str, version: str, filename: str, digest: str) -> dict[str, object]:
    url = f"https://pypi.org/pypi/{project}/{version}/json"
    try:
        with urllib.request.urlopen(url, timeout=15) as response:
            document = json.load(response)
    except urllib.error.HTTPError as error:
        if error.code == 404:
            return {"publish_required": True, "status": "absent"}
        raise
    matches = [item for item in document.get("urls", []) if item.get("filename") == filename]
    if len(matches) != 1:
        raise RuntimeError("published version does not contain the expected immutable filename")
    observed = matches[0].get("digests", {}).get("sha256")
    if observed != digest:
        raise RuntimeError("published filename exists with a different digest")
    return {"publish_required": False, "status": "matching"}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--project", required=True)
    parser.add_argument("--version", required=True)
    parser.add_argument("--filename", required=True)
    parser.add_argument("--sha256", required=True)
    parser.add_argument("--github-output", type=Path)
    arguments = parser.parse_args(argv)
    try:
        result = check(arguments.project, arguments.version, arguments.filename, arguments.sha256)
    except (OSError, RuntimeError, ValueError) as error:
        print(json.dumps({"failure_code": "SOS_PYPI_STATE_INVALID", "message": str(error), "status": "failed"}, sort_keys=True))
        return 1
    if arguments.github_output is not None:
        with arguments.github_output.open("a", encoding="utf-8") as handle:
            handle.write(f"publish_required={'true' if result['publish_required'] else 'false'}\n")
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
