#!/usr/bin/env python3
"""Replay the agent-first route against synthetic, offline inputs."""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import io
import json
import stat
import zipfile
from copy import deepcopy
from pathlib import Path, PurePosixPath
from typing import Any

from jsonschema import Draft202012Validator


HERE = Path(__file__).resolve().parent
ROUTE_SPEC = importlib.util.spec_from_file_location(
    "sos_agent_first_route", HERE / "resolve_agent_first_route.py"
)
if ROUTE_SPEC is None or ROUTE_SPEC.loader is None:
    raise RuntimeError("agent-first route resolver import failed")
ROUTE = importlib.util.module_from_spec(ROUTE_SPEC)
ROUTE_SPEC.loader.exec_module(ROUTE)


def _canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _digest_bound(value: dict[str, object], field: str) -> dict[str, object]:
    result = dict(value)
    result[field] = "sha256:" + hashlib.sha256(_canonical(result)).hexdigest()
    return result


def terminal_projection(
    snapshot: dict[str, object], schema_root: Path
) -> dict[str, object]:
    schema = json.loads(
        (schema_root / "sos-agent-first-terminal-snapshot-v1.schema.json").read_text()
    )
    if tuple(Draft202012Validator(schema).iter_errors(snapshot)):
        status, reason, action = "invalid", "SOS_AGENT_FIRST_TERMINAL_SNAPSHOT_INVALID", "stop"
    elif snapshot["setup_state"] == "invalid" or snapshot["workspace_state"] == "invalid":
        status, reason, action = "invalid", "SOS_CONTROL_PLANE_INTEGRITY_INVALID", "stop"
    elif snapshot["setup_state"] == "blocked":
        status, reason, action = "blocked", "SOS_AGENT_FIRST_SETUP_BLOCKED", "remediate"
    elif snapshot["authority_state"] == "owner_required":
        status, reason, action = "owner_required", "SOS_PRIMARY_AUTHORITY_REQUIRED", "select_authority"
    elif snapshot["workspace_state"] == "stale":
        status, reason, action = "stale", "SOS_SOURCE_STATUS_CHANGED", "review_and_rebind"
    elif snapshot["configured_family_count"] == 0:
        if snapshot["qualification_state"] != "not_run":
            status, reason, action = "invalid", "SOS_AGENT_FIRST_TERMINAL_SNAPSHOT_CONTRADICTORY", "stop"
        else:
            status, reason, action = "not_configured", "SOS_CHECK_NOT_CONFIGURED", "configure_check_family"
    elif snapshot["qualification_state"] == "not_run":
        status, reason, action = "not_verified", "SOS_QUALIFICATION_NOT_RUN", "run_qualification"
    elif snapshot["qualification_state"] == "passed_local":
        status, reason, action = "success", "SOS_AGENT_FIRST_SETUP_AND_QUALIFICATION_CURRENT", "complete"
    elif snapshot["qualification_state"] == "stale":
        status, reason, action = "stale", "SOS_QUALIFICATION_STALE", "review_and_rebind"
    else:
        status, reason, action = "blocked", "SOS_QUALIFICATION_BLOCKED", "remediate"
    result: dict[str, object] = {
        "absolute_paths_serialized": False,
        "contract": "sos_agent_first_terminal_projection_v1",
        "mutations_performed": False,
        "network_performed": False,
        "next_action": action,
        "provider_calls": 0,
        "raw_content_serialized": False,
        "reasons": [reason],
        "status": status,
    }
    return _digest_bound(result, "projection_digest")


def _synthetic_archive() -> bytes:
    payload = b"synthetic agent-first payload\n"
    manifest = _canonical(
        {
            "artifacts": [
                {
                    "path": "payload/README.txt",
                    "sha256": hashlib.sha256(payload).hexdigest(),
                    "size": len(payload),
                }
            ],
            "contract": "sos_agent_first_synthetic_archive_v1",
        }
    )
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_STORED) as archive:
        for name, content in (
            ("release-manifest.json", manifest),
            ("payload/README.txt", payload),
        ):
            info = zipfile.ZipInfo(name, date_time=(2026, 1, 1, 0, 0, 0))
            info.create_system = 3
            info.external_attr = 0o100644 << 16
            archive.writestr(info, content)
    return output.getvalue()


def verify_synthetic_archive(archive_bytes: bytes, expected_digest: str) -> tuple[str, str]:
    if hashlib.sha256(archive_bytes).hexdigest() != expected_digest:
        return "blocked", "SOS_AGENT_FIRST_ARCHIVE_DIGEST_MISMATCH"
    materialized: dict[str, bytes] = {}
    try:
        with zipfile.ZipFile(io.BytesIO(archive_bytes), "r") as archive:
            for info in archive.infolist():
                path = PurePosixPath(info.filename)
                mode = info.external_attr >> 16
                if (
                    path.is_absolute()
                    or ".." in path.parts
                    or info.is_dir()
                    or stat.S_ISLNK(mode)
                    or info.file_size > 1024 * 1024
                ):
                    return "blocked", "SOS_AGENT_FIRST_ARCHIVE_UNSAFE"
                materialized[info.filename] = archive.read(info)
        manifest = json.loads(materialized["release-manifest.json"])
        for artifact in manifest["artifacts"]:
            content = materialized[artifact["path"]]
            if len(content) != artifact["size"]:
                return "blocked", "SOS_AGENT_FIRST_ARCHIVE_MANIFEST_MISMATCH"
            if hashlib.sha256(content).hexdigest() != artifact["sha256"]:
                return "blocked", "SOS_AGENT_FIRST_ARCHIVE_MANIFEST_MISMATCH"
    except (KeyError, OSError, ValueError, zipfile.BadZipFile, json.JSONDecodeError):
        return "blocked", "SOS_AGENT_FIRST_ARCHIVE_INVALID"
    return "success", "SOS_AGENT_FIRST_ARCHIVE_VERIFIED"


def _route_inputs(
    mutation: str,
    pointer: dict[str, Any],
    index: dict[str, Any],
) -> tuple[bytes | None, bytes | None, dict[str, object] | None]:
    selected_pointer = deepcopy(pointer)
    selected_index = deepcopy(index)
    observation = None
    if mutation == "pointer_absent":
        return None, _canonical(selected_index), None
    if mutation == "pointer_malformed":
        return b"{", _canonical(selected_index), None
    if mutation == "pointer_withheld":
        selected_pointer["availability"] = "withheld"
    elif mutation == "index_digest_mismatch":
        selected_pointer["index_sha256"] = "0" * 64
    elif mutation == "index_binding_mismatch":
        selected_index["version"] = "0.1.0a3"
    elif mutation == "platform_ambiguous":
        selected_index["platforms"].append(deepcopy(selected_index["platforms"][0]))
    elif mutation == "sandbox_handoff":
        observation = {
            "contract": "sos_windows_store_observation_v1",
            "execution_context": "sandbox",
            "installed": True,
            "launcher_available": False,
            "package_family_name": "SSRG.SigmaOperatorStack_2358e20nvr064",
            "package_identity_name": "SSRG.SigmaOperatorStack",
            "package_publisher": "CN=D713C275-467D-4A03-9D24-0DC02F1C3031",
            "package_version": "1.0.2.0",
        }
    index_bytes = _canonical(selected_index)
    if mutation != "index_digest_mismatch":
        selected_pointer["index_sha256"] = hashlib.sha256(index_bytes).hexdigest()
    return _canonical(selected_pointer), index_bytes, observation


def replay(
    *,
    matrix: dict[str, Any],
    pointer: dict[str, Any],
    index: dict[str, Any],
    schema_root: Path,
) -> dict[str, object]:
    archive_bytes = _synthetic_archive()
    archive_digest = hashlib.sha256(archive_bytes).hexdigest()
    cases: list[dict[str, object]] = []
    passed = True
    for case in matrix["cases"]:
        if case["kind"] == "route":
            pointer_bytes, index_bytes, observation = _route_inputs(
                case["mutation"], pointer, index
            )
            projection = ROUTE.resolve(
                schema_root=schema_root,
                pointer_bytes=pointer_bytes,
                index_bytes=index_bytes,
                system=case["system"],
                architecture=case["architecture"],
                observation=observation,
            )
            status = projection["status"]
            reason = projection["reasons"][0]
            action = projection["action"]["kind"]
        elif case["kind"] == "terminal":
            projection = terminal_projection(case["snapshot"], schema_root)
            status = projection["status"]
            reason = projection["reasons"][0]
            action = projection["next_action"]
        else:
            expected = archive_digest
            if case["mutation"] == "archive_digest_mismatch":
                expected = "0" * 64
            status, reason = verify_synthetic_archive(archive_bytes, expected)
            action = "none"
        if (
            status != case["expected_status"]
            or reason != case["expected_reason"]
            or action != case["expected_action"]
        ):
            passed = False
        record: dict[str, object] = {
            "action_kind": action,
            "case_id": case["case_id"],
            "reason": reason,
            "status": status,
        }
        cases.append(record)
    result: dict[str, object] = {
        "absolute_paths_serialized": False,
        "case_count": len(cases),
        "cases": cases,
        "contract": "sos_agent_first_offline_replay_v1",
        "mutations_performed": False,
        "network_performed": False,
        "provider_calls": 0,
        "raw_content_serialized": False,
        "simulated_fresh_session": False,
        "simulated_store_success": False,
        "status": "passed" if passed else "failed",
    }
    return _digest_bound(result, "receipt_digest")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--matrix", type=Path, required=True)
    parser.add_argument("--pointer", type=Path, required=True)
    parser.add_argument("--index", type=Path, required=True)
    parser.add_argument("--schemas", type=Path, default=Path("src/sos/schemas"))
    arguments = parser.parse_args(argv)
    try:
        result = replay(
            matrix=json.loads(arguments.matrix.read_text(encoding="utf-8")),
            pointer=json.loads(arguments.pointer.read_text(encoding="utf-8")),
            index=json.loads(arguments.index.read_text(encoding="utf-8")),
            schema_root=arguments.schemas,
        )
        schema = json.loads(
            (arguments.schemas / "sos-agent-first-offline-replay-v1.schema.json").read_text()
        )
        Draft202012Validator(schema).validate(result)
    except (OSError, ValueError, KeyError, json.JSONDecodeError):
        result = {
            "absolute_paths_serialized": False,
            "case_count": 1,
            "cases": [
                {
                    "action_kind": "none",
                    "case_id": "replay.internal-error",
                    "reason": "SOS_AGENT_FIRST_OFFLINE_REPLAY_FAILED",
                    "status": "invalid",
                }
            ],
            "contract": "sos_agent_first_offline_replay_v1",
            "mutations_performed": False,
            "network_performed": False,
            "provider_calls": 0,
            "raw_content_serialized": False,
            "simulated_fresh_session": False,
            "simulated_store_success": False,
            "status": "failed",
        }
        result = _digest_bound(result, "receipt_digest")
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0 if result["status"] == "passed" else 2


if __name__ == "__main__":
    raise SystemExit(main())
