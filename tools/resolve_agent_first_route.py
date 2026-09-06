#!/usr/bin/env python3
"""Resolve one content-safe agent-first acquisition route without side effects."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator


CONTRACT = "sos_agent_first_route_projection_v1"
SCHEMA_NAMES = {
    "pointer": "sos-public-release-pointer-v1.schema.json",
    "index": "sos-public-release-index-v1.schema.json",
    "observation": "sos-windows-store-observation-v1.schema.json",
    "projection": "sos-agent-first-route-projection-v1.schema.json",
}


def _canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _projection(
    *,
    system: str,
    architecture: str,
    status: str,
    reason: str,
    action: dict[str, object] | None = None,
    release: dict[str, Any] | None = None,
    delivery: str | None = None,
) -> dict[str, object]:
    result: dict[str, object] = {
        "absolute_paths_serialized": False,
        "action": action or {"kind": "none"},
        "architecture": architecture,
        "contract": CONTRACT,
        "mutations_performed": False,
        "network_performed": False,
        "provider_calls": 0,
        "raw_content_serialized": False,
        "reasons": [reason],
        "status": status,
        "system": system,
    }
    if release is not None:
        for field in ("candidate", "release_tag", "tree", "version"):
            result[field] = release[field]
    if delivery is not None:
        result["delivery"] = delivery
    result["projection_digest"] = "sha256:" + hashlib.sha256(_canonical(result)).hexdigest()
    return result


def _schema(schema_root: Path, name: str) -> dict[str, object]:
    return json.loads((schema_root / SCHEMA_NAMES[name]).read_text(encoding="utf-8"))


def _valid(schema: dict[str, object], instance: object) -> bool:
    return not tuple(Draft202012Validator(schema).iter_errors(instance))


def resolve(
    *,
    schema_root: Path,
    pointer_bytes: bytes | None,
    index_bytes: bytes | None,
    system: str,
    architecture: str,
    observation: dict[str, object] | None = None,
) -> dict[str, object]:
    safe_system = system if system in {"darwin", "linux", "windows"} else "unknown"
    safe_architecture = architecture if architecture in {"arm64", "x86_64"} else "unknown"
    if pointer_bytes is None or index_bytes is None:
        return _projection(
            system=safe_system,
            architecture=safe_architecture,
            status="blocked",
            reason="SOS_PUBLIC_RELEASE_NOT_AVAILABLE",
        )
    try:
        pointer = json.loads(pointer_bytes)
        index = json.loads(index_bytes)
        schemas = {name: _schema(schema_root, name) for name in SCHEMA_NAMES}
    except (json.JSONDecodeError, OSError, UnicodeDecodeError):
        return _projection(
            system=safe_system,
            architecture=safe_architecture,
            status="invalid",
            reason="SOS_PUBLIC_RELEASE_METADATA_INVALID",
        )
    if not _valid(schemas["pointer"], pointer) or not _valid(schemas["index"], index):
        return _projection(
            system=safe_system,
            architecture=safe_architecture,
            status="invalid",
            reason="SOS_PUBLIC_RELEASE_METADATA_INVALID",
        )
    if pointer["availability"] != "public":
        return _projection(
            system=safe_system,
            architecture=safe_architecture,
            status="blocked",
            reason="SOS_PUBLIC_RELEASE_WITHHELD",
        )
    expected_path = f"releases/download/{pointer['release_tag']}/sos-release-index-v1.json"
    if pointer["index_path"] != expected_path:
        return _projection(
            system=safe_system,
            architecture=safe_architecture,
            status="invalid",
            reason="SOS_PUBLIC_RELEASE_INDEX_PATH_MISMATCH",
        )
    if pointer["index_sha256"] != hashlib.sha256(index_bytes).hexdigest():
        return _projection(
            system=safe_system,
            architecture=safe_architecture,
            status="invalid",
            reason="SOS_PUBLIC_RELEASE_INDEX_DIGEST_MISMATCH",
        )
    for field in ("candidate", "release_tag", "tree", "version"):
        if pointer[field] != index[field]:
            return _projection(
                system=safe_system,
                architecture=safe_architecture,
                status="invalid",
                reason="SOS_PUBLIC_RELEASE_BINDING_MISMATCH",
            )
    matches = [
        item
        for item in index["platforms"]
        if item["system"] == safe_system and item["architecture"] == safe_architecture
    ]
    if not matches:
        return _projection(
            system=safe_system,
            architecture=safe_architecture,
            status="unsupported",
            reason="SOS_PUBLIC_RELEASE_PLATFORM_UNSUPPORTED",
            release=index,
        )
    if len(matches) != 1:
        return _projection(
            system=safe_system,
            architecture=safe_architecture,
            status="blocked",
            reason="SOS_PUBLIC_RELEASE_PLATFORM_AMBIGUOUS",
            release=index,
        )
    platform = matches[0]
    if platform["status"] == "unsupported":
        return _projection(
            system=safe_system,
            architecture=safe_architecture,
            status="unsupported",
            reason=platform["reason"],
            release=index,
        )
    delivery = platform["delivery"]
    if delivery == "archive":
        maintenance_binding = {
            "contract": "sos_public_maintenance_handoff_v1",
            "version": index["version"],
            "release_tag": index["release_tag"],
            "candidate": index["candidate"],
            "tree": index["tree"],
            "archive_filename": platform["archive_filename"],
            "archive_sha256": platform["archive_sha256"],
            "inner_manifest_sha256": platform["inner_manifest_sha256"],
            "system": platform["system"],
            "architecture": platform["architecture"],
            "profile_id": platform["profile_id"],
            "platform_launcher": platform["launcher"],
        }
        return _projection(
            system=safe_system,
            architecture=safe_architecture,
            status="ready",
            reason="SOS_AGENT_FIRST_ARCHIVE_READY",
            delivery=delivery,
            release=index,
            action={
                "archive_filename": platform["archive_filename"],
                "archive_sha256": platform["archive_sha256"],
                "invocation": platform["invocation"],
                "kind": "download_archive",
                "launcher": platform["launcher"],
                "maintenance_binding": maintenance_binding,
            },
        )
    if observation is None:
        return _projection(
            system=safe_system,
            architecture=safe_architecture,
            status="user_action_required",
            reason="SOS_MICROSOFT_STORE_INSTALL_REQUIRED",
            delivery=delivery,
            release=index,
            action={
                "kind": "open_store",
                "store_product_id": platform["store_product_id"],
                "store_protocol_uri": platform["store_protocol_uri"],
                "store_web_url": platform["store_web_url"],
            },
        )
    if not _valid(schemas["observation"], observation):
        return _projection(
            system=safe_system,
            architecture=safe_architecture,
            status="invalid",
            reason="SOS_WINDOWS_STORE_OBSERVATION_INVALID",
            delivery=delivery,
            release=index,
        )
    if not observation["installed"]:
        return _projection(
            system=safe_system,
            architecture=safe_architecture,
            status="user_action_required",
            reason="SOS_MICROSOFT_STORE_INSTALL_REQUIRED",
            delivery=delivery,
            release=index,
            action={
                "kind": "open_store",
                "store_product_id": platform["store_product_id"],
                "store_protocol_uri": platform["store_protocol_uri"],
                "store_web_url": platform["store_web_url"],
            },
        )
    expected = {
        field: platform[field]
        for field in (
            "package_family_name",
            "package_identity_name",
            "package_publisher",
            "package_version",
        )
    }
    if any(observation[field] != value for field, value in expected.items()):
        return _projection(
            system=safe_system,
            architecture=safe_architecture,
            status="blocked",
            reason="SOS_WINDOWS_STORE_PACKAGE_BINDING_MISMATCH",
            delivery=delivery,
            release=index,
        )
    if not observation["launcher_available"]:
        if observation["execution_context"] == "sandbox":
            return _projection(
                system=safe_system,
                architecture=safe_architecture,
                status="user_action_required",
                reason="SOS_INTERACTIVE_USER_HANDOFF_REQUIRED",
                delivery=delivery,
                release=index,
                action={"kind": "handoff_to_interactive_user"},
            )
        return _projection(
            system=safe_system,
            architecture=safe_architecture,
            status="blocked",
            reason="SOS_PUBLIC_RELEASE_LAUNCHER_UNAVAILABLE",
            delivery=delivery,
            release=index,
        )
    return _projection(
        system=safe_system,
        architecture=safe_architecture,
        status="ready",
        reason="SOS_AGENT_FIRST_LAUNCHER_READY",
        delivery=delivery,
        release=index,
        action={
            "invocation": platform["invocation"],
            "kind": "invoke_launcher",
            "launcher": platform["launcher"],
        },
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--pointer", type=Path, required=True)
    parser.add_argument("--index", type=Path, required=True)
    parser.add_argument("--schemas", type=Path, default=Path("src/sos/schemas"))
    parser.add_argument("--system", required=True)
    parser.add_argument("--architecture", required=True)
    parser.add_argument("--observation", type=Path)
    arguments = parser.parse_args(argv)
    try:
        pointer_bytes = arguments.pointer.read_bytes() if arguments.pointer.is_file() else None
        index_bytes = arguments.index.read_bytes() if arguments.index.is_file() else None
        observation = (
            json.loads(arguments.observation.read_text(encoding="utf-8"))
            if arguments.observation is not None
            else None
        )
        result = resolve(
            schema_root=arguments.schemas,
            pointer_bytes=pointer_bytes,
            index_bytes=index_bytes,
            system=arguments.system,
            architecture=arguments.architecture,
            observation=observation,
        )
        projection_schema = _schema(arguments.schemas, "projection")
        if not _valid(projection_schema, result):
            raise ValueError("projection schema mismatch")
    except (OSError, UnicodeDecodeError, ValueError, json.JSONDecodeError):
        result = _projection(
            system="unknown",
            architecture="unknown",
            status="invalid",
            reason="SOS_AGENT_FIRST_ROUTE_RESOLUTION_FAILED",
        )
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0 if result["status"] == "ready" else 2


if __name__ == "__main__":
    raise SystemExit(main())
