#!/usr/bin/env python3
"""Validate the optional public release pointer and its checked-in index."""

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
from pathlib import Path

from jsonschema import Draft202012Validator


POINTER_NAME = "release/current.json"
INDEX_NAME = "release/sos-release-index-v1.json"


def _git(repository: Path, *arguments: str) -> str:
    return subprocess.run(
        ["git", "-C", str(repository), *arguments],
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    ).stdout.strip()


def inspect(repository: Path, *, require_public: bool = False) -> dict[str, object]:
    pointer_path = repository / POINTER_NAME
    index_path = repository / INDEX_NAME
    if not pointer_path.exists() and not index_path.exists():
        if require_public:
            return {
                "contract": "sos_public_release_pointer_check_v1",
                "failures": ["SOS_PUBLIC_RELEASE_POINTER_REQUIRED"],
                "status": "failed",
            }
        return {
            "contract": "sos_public_release_pointer_check_v1",
            "failures": [],
            "status": "not_published",
        }
    failures: list[str] = []
    if not pointer_path.is_file() or not index_path.is_file():
        failures.append("SOS_PUBLIC_RELEASE_SURFACE_INCOMPLETE")
        return {
            "contract": "sos_public_release_pointer_check_v1",
            "failures": failures,
            "status": "failed",
        }

    schemas = repository / "src" / "sos" / "schemas"
    pointer_schema = json.loads(
        (schemas / "sos-public-release-pointer-v1.schema.json").read_text(
            encoding="utf-8"
        )
    )
    index_schema = json.loads(
        (schemas / "sos-public-release-index-v1.schema.json").read_text(
            encoding="utf-8"
        )
    )
    pointer = json.loads(pointer_path.read_text(encoding="utf-8"))
    index_bytes = index_path.read_bytes()
    index = json.loads(index_bytes)
    pointer_errors = tuple(Draft202012Validator(pointer_schema).iter_errors(pointer))
    index_errors = tuple(Draft202012Validator(index_schema).iter_errors(index))
    if pointer_errors:
        failures.append("SOS_PUBLIC_RELEASE_POINTER_SCHEMA_INVALID")
    if index_errors:
        failures.append("SOS_PUBLIC_RELEASE_INDEX_SCHEMA_INVALID")
    if not failures:
        if pointer["availability"] != "public":
            failures.append("SOS_PUBLIC_RELEASE_WITHHELD")
        for field in ("candidate", "tree", "version", "release_tag"):
            if pointer[field] != index[field]:
                failures.append("SOS_PUBLIC_RELEASE_BINDING_MISMATCH")
                break
        expected_path = f"releases/download/{pointer['release_tag']}/sos-release-index-v1.json"
        if pointer["index_path"] != expected_path:
            failures.append("SOS_PUBLIC_RELEASE_INDEX_PATH_MISMATCH")
        if pointer["index_sha256"] != hashlib.sha256(index_bytes).hexdigest():
            failures.append("SOS_PUBLIC_RELEASE_INDEX_DIGEST_MISMATCH")
        candidate = pointer["candidate"]
        candidate_tree = _git(repository, "show", "-s", "--format=%T", candidate)
        if pointer["tree"] != candidate_tree:
            failures.append("SOS_PUBLIC_RELEASE_SOURCE_BINDING_MISMATCH")
        if require_public:
            tag_candidate = _git(
                repository, "rev-parse", f"{pointer['release_tag']}^{{commit}}"
            )
            if tag_candidate != candidate:
                failures.append("SOS_PUBLIC_RELEASE_TAG_BINDING_MISMATCH")
    return {
        "contract": "sos_public_release_pointer_check_v1",
        "failures": sorted(set(failures)),
        "status": "passed" if not failures else "failed",
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repository", type=Path, default=Path.cwd())
    parser.add_argument("--require-public", action="store_true")
    arguments = parser.parse_args(argv)
    try:
        result = inspect(
            arguments.repository.resolve(strict=True),
            require_public=arguments.require_public,
        )
    except (json.JSONDecodeError, KeyError, OSError, subprocess.CalledProcessError):
        result = {
            "contract": "sos_public_release_pointer_check_v1",
            "failures": ["SOS_PUBLIC_RELEASE_POINTER_CHECK_FAILED"],
            "status": "failed",
        }
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0 if result["status"] in {"passed", "not_published"} else 2


if __name__ == "__main__":
    raise SystemExit(main())
