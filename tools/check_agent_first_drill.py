#!/usr/bin/env python3
"""Validate one exact, content-safe AF104 URL-only drill receipt."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

from jsonschema import Draft202012Validator


STEP_ORDER = [
    "release_discovery",
    "store_install",
    "project_preview",
    "project_apply",
    "truthful_state",
    "fresh_recovery",
    "update_remove",
]


def _canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")


def inspect(repository: Path, receipt_path: Path | None) -> dict[str, object]:
    if receipt_path is None or not receipt_path.is_file():
        return {
            "contract": "sos_agent_first_drill_check_v1",
            "failures": [],
            "status": "not_run",
        }
    failures: list[str] = []
    try:
        schemas = repository / "src/sos/schemas"
        receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
        pointer = json.loads((repository / "release/current.json").read_text(encoding="utf-8"))
        index = json.loads(
            (repository / "release/sos-release-index-v1.json").read_text(encoding="utf-8")
        )
        schema = json.loads(
            (schemas / "sos-agent-first-drill-receipt-v1.schema.json").read_text(
                encoding="utf-8"
            )
        )
        if tuple(Draft202012Validator(schema).iter_errors(receipt)):
            failures.append("SOS_AGENT_FIRST_DRILL_RECEIPT_SCHEMA_INVALID")
        if pointer.get("availability") != "public":
            failures.append("SOS_AGENT_FIRST_DRILL_PUBLIC_POINTER_REQUIRED")
        for field in ("candidate", "release_tag", "tree", "version"):
            if receipt.get(field) != pointer.get(field) or receipt.get(field) != index.get(field):
                failures.append("SOS_AGENT_FIRST_DRILL_RELEASE_BINDING_MISMATCH")
                break
        windows = [
            item
            for item in index.get("platforms", [])
            if item.get("system") == "windows"
            and item.get("architecture") == "x86_64"
            and item.get("status") == "admitted"
            and item.get("delivery") == "microsoft_store"
        ]
        if len(windows) != 1:
            failures.append("SOS_AGENT_FIRST_DRILL_STORE_ROUTE_INVALID")
        elif receipt.get("store_product_id") != windows[0].get("store_product_id"):
            failures.append("SOS_AGENT_FIRST_DRILL_STORE_BINDING_MISMATCH")
        if [step.get("step_id") for step in receipt.get("steps", [])] != STEP_ORDER:
            failures.append("SOS_AGENT_FIRST_DRILL_STEP_ORDER_INVALID")
        if any(step.get("status") != "passed" for step in receipt.get("steps", [])):
            failures.append("SOS_AGENT_FIRST_DRILL_STEP_FAILED")
        if receipt.get("status") != "passed":
            failures.append("SOS_AGENT_FIRST_DRILL_NOT_PASSED")
        supplied_digest = receipt.get("receipt_digest")
        digest_input = dict(receipt)
        digest_input.pop("receipt_digest", None)
        expected_digest = "sha256:" + hashlib.sha256(_canonical(digest_input)).hexdigest()
        if supplied_digest != expected_digest:
            failures.append("SOS_AGENT_FIRST_DRILL_RECEIPT_DIGEST_MISMATCH")
    except (json.JSONDecodeError, KeyError, OSError, TypeError):
        failures.append("SOS_AGENT_FIRST_DRILL_CHECK_FAILED")
    return {
        "contract": "sos_agent_first_drill_check_v1",
        "failures": sorted(set(failures)),
        "status": "passed" if not failures else "failed",
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repository", type=Path, default=Path.cwd())
    parser.add_argument("--receipt", type=Path)
    arguments = parser.parse_args(argv)
    result = inspect(arguments.repository.resolve(strict=True), arguments.receipt)
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0 if result["status"] in {"not_run", "passed"} else 2


if __name__ == "__main__":
    raise SystemExit(main())
