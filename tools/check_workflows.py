#!/usr/bin/env python3
"""Structural fail-closed inspection for the public CI and release workflows."""

from __future__ import annotations

import argparse
import json
import re
from pathlib import Path

import yaml


PINNED_ACTION = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+@[0-9a-f]{40}$")


def _load(path: Path) -> dict[str, object]:
    value = yaml.load(path.read_text(encoding="utf-8"), Loader=yaml.BaseLoader)
    if not isinstance(value, dict):
        raise ValueError(f"workflow is not an object: {path.name}")
    return value


def _action_uses(value: object) -> list[str]:
    found: list[str] = []
    if isinstance(value, dict):
        for key, child in value.items():
            if key == "uses" and isinstance(child, str):
                found.append(child)
            found.extend(_action_uses(child))
    elif isinstance(value, list):
        for child in value:
            found.extend(_action_uses(child))
    return found


def inspect(root: Path) -> dict[str, object]:
    ci = _load(root / ".github/workflows/ci.yml")
    release = _load(root / ".github/workflows/release.yml")
    failures: list[str] = []
    for workflow in (ci, release):
        for action in _action_uses(workflow):
            if not PINNED_ACTION.fullmatch(action):
                failures.append(f"SOS_WORKFLOW_ACTION_NOT_IMMUTABLE:{action}")

    source = ci.get("jobs", {}).get("source", {})
    versions = source.get("strategy", {}).get("matrix", {}).get("python", [])
    if versions != ["3.11", "3.12"]:
        failures.append("SOS_CI_PYTHON_MATRIX_INVALID")
    release_artifacts = ci.get("jobs", {}).get("release-artifacts", {})
    if release_artifacts.get("needs") != "source":
        failures.append("SOS_CI_RELEASE_DEPENDENCY_INVALID")

    triggers = release.get("on", {})
    if set(triggers) != {"workflow_dispatch"}:
        failures.append("SOS_RELEASE_TRIGGER_NOT_MANUAL")
    publish = release.get("jobs", {}).get("publish", {})
    if publish.get("environment") != "public-alpha":
        failures.append("SOS_RELEASE_ENVIRONMENT_MISSING")
    permissions = publish.get("permissions", {})
    if permissions.get("id-token") != "write" or permissions.get("contents") != "write":
        failures.append("SOS_RELEASE_PERMISSIONS_INVALID")
    condition = str(publish.get("if", ""))
    for required in ("refs/tags/", "v0.1.0a1", "SOS_RELEASE_APPROVED_CANDIDATE", "inputs.candidate"):
        if required not in condition:
            failures.append("SOS_RELEASE_CANDIDATE_GATE_INCOMPLETE")
            break
    serialized = json.dumps(release, sort_keys=True)
    if "password:" in serialized or "token:" in serialized or "PYPI_API_TOKEN" in serialized:
        failures.append("SOS_RELEASE_LONG_LIVED_TOKEN_SURFACE")
    return {
        "contract": "sos_workflow_contract_v1",
        "failures": sorted(set(failures)),
        "status": "passed" if not failures else "failed",
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repository", type=Path, default=Path.cwd())
    arguments = parser.parse_args(argv)
    try:
        result = inspect(arguments.repository.resolve(strict=True))
    except (KeyError, OSError, TypeError, ValueError, yaml.YAMLError) as error:
        result = {"contract": "sos_workflow_contract_v1", "failures": ["SOS_WORKFLOW_PARSE_FAILED"], "message": str(error), "status": "failed"}
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0 if result["status"] == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
