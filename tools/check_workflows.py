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
    windows_sign = _load(root / ".github/workflows/windows-sign.yml")
    failures: list[str] = []
    for workflow in (ci, release, windows_sign):
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
    for required in (
        "SOS_RELEASE_APPROVED_ROUTING_COMMIT",
        "inputs.routing_commit",
        "SOS_RELEASE_APPROVED_CANDIDATE",
        "inputs.candidate",
    ):
        if required not in condition:
            failures.append("SOS_RELEASE_CANDIDATE_GATE_INCOMPLETE")
            break
    ci_source = (root / ".github/workflows/ci.yml").read_text(encoding="utf-8")
    release_source = (root / ".github/workflows/release.yml").read_text(encoding="utf-8")
    for required in (
        "test -f release/current.json",
        "test -f release/sos-release-index-v1.json",
        "check_public_release_pointer.py --repository . --require-public",
        "Check out immutable release candidate",
    ):
        if required not in release_source:
            failures.append("SOS_RELEASE_POINTER_GATE_INCOMPLETE")
            break
    for required in (
        "Verify complete pre-staged draft GitHub Release",
        "check_native_release_assets.py --index",
        "SOS-Linux-0.1.0a2.zip",
        "SOS-macOS-0.1.0a2.tar.gz",
        "--json isDraft",
    ):
        if required not in release_source:
            failures.append("SOS_RELEASE_NATIVE_ASSET_GATE_INCOMPLETE")
            break
    if "gh release create" in release_source:
        failures.append("SOS_RELEASE_UNVERIFIED_ASSET_CREATION_FORBIDDEN")
    pointer_checker = (root / "tools/check_public_release_pointer.py").read_text(
        encoding="utf-8"
    )
    for required in (
        "sos-public-release-pointer-v1.schema.json",
        "sos-public-release-index-v1.schema.json",
        "SOS_PUBLIC_RELEASE_SOURCE_BINDING_MISMATCH",
    ):
        if required not in pointer_checker:
            failures.append("SOS_RELEASE_POINTER_CHECKER_INCOMPLETE")
            break
    serialized = json.dumps(release, sort_keys=True)
    if "password:" in serialized or "token:" in serialized or "PYPI_API_TOKEN" in serialized:
        failures.append("SOS_RELEASE_LONG_LIVED_TOKEN_SURFACE")
    sign_triggers = windows_sign.get("on", {})
    if set(sign_triggers) != {"workflow_dispatch"}:
        failures.append("SOS_WINDOWS_SIGNING_TRIGGER_NOT_MANUAL")
    sign = windows_sign.get("jobs", {}).get("sign", {})
    if sign.get("environment") != "windows-signing" or sign.get("runs-on") != "windows-2025":
        failures.append("SOS_WINDOWS_SIGNING_ENVIRONMENT_INVALID")
    sign_permissions = sign.get("permissions", {})
    if sign_permissions != {"contents": "read", "id-token": "write"}:
        failures.append("SOS_WINDOWS_SIGNING_PERMISSIONS_INVALID")
    sign_condition = str(sign.get("if", ""))
    for required in (
        "SOS_WINDOWS_APPROVED_CANDIDATE",
        "SOS_WINDOWS_APPROVED_UNSIGNED_SHA256",
        "inputs.candidate",
        "inputs.unsigned_sha256",
    ):
        if required not in sign_condition:
            failures.append("SOS_WINDOWS_SIGNING_GATE_INCOMPLETE")
            break
    sign_serialized = json.dumps(windows_sign, sort_keys=True)
    sign_source = (root / ".github/workflows/windows-sign.yml").read_text(encoding="utf-8")
    for required in (
        "azure/artifact-signing-action@208f8af4bf26cf2af8597424e3cb5582801523ba",
        "azure/login@93381592711f247e165c389ebb30b596c84cdc48",
        "file-digest: SHA256",
        "timestamp-rfc3161: http://timestamp.acs.microsoft.com",
        "timestamp-digest: SHA256",
        "verify_windows_signature.ps1",
    ):
        if required not in sign_source:
            failures.append("SOS_WINDOWS_SIGNING_CONTRACT_INCOMPLETE")
            break
    if any(token in sign_serialized for token in ("client-secret", "pfx", "password", "AZURE_CREDENTIALS")):
        failures.append("SOS_WINDOWS_SIGNING_LONG_LIVED_CREDENTIAL_SURFACE")
    audit_command = "python -m pip_audit --strict --progress-spinner off"
    all_workflows = json.dumps((ci, release), sort_keys=True)
    for required in (
        "requirements/audit.txt",
        f"{audit_command} -r requirements/release.txt",
        f"{audit_command} .",
    ):
        if all_workflows.count(required) < 2:
            failures.append("SOS_DEPENDENCY_AUDIT_GATE_INCOMPLETE")
            break
    for required in (
        "tools/check_dependency_licenses.py --repository .",
        "requirements/runtime.txt",
        "--environment-python",
        "--sbom",
    ):
        if all_workflows.count(required) < 2:
            failures.append("SOS_DEPENDENCY_LICENSE_GATE_INCOMPLETE")
            break
    if any(
        "verify_bundle" not in source or "system='Source'" not in source
        for source in (ci_source, release_source)
    ):
        failures.append("SOS_GENERIC_RELEASE_BUNDLE_GATE_INCOMPLETE")
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
