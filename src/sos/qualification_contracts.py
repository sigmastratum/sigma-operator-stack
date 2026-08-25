"""Closed public contracts for the non-authoritative P104 lifecycle."""

from __future__ import annotations

import hashlib
import json
import os
import stat
from datetime import datetime, timezone
from importlib import resources
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator, FormatChecker

from . import __version__


_SCHEMAS = {
    "sos_qualification_plan_v1": (
        "sos-qualification-plan-v1.schema.json",
        "90df5aeaa544a02a98f3bb718fe81a9b5b4fa8a512b500ee3766d1ab81da0178",
        "plan_digest",
    ),
    "sos_command_admission_v1": (
        "sos-command-admission-v1.schema.json",
        "3c6c54145113ff9738f41076c588a6840c54c4161fb5ba2d47d9dd7c067b087d",
        "admission_id",
    ),
    "sos_execution_result_v1": (
        "sos-execution-result-v1.schema.json",
        "e93ab778976ef73daa276d4e9fab5e91bdd71f9fa66df5e8fab96e240e7f8788",
        "result_digest",
    ),
    "sos_qualification_receipt_v1": (
        "sos-qualification-receipt-v1.schema.json",
        "266c7d4065ff48b1f1208ca056db79e559165d2ac9533b6dd38a82bc009107c0",
        "receipt_digest",
    ),
}

class QualificationContractError(RuntimeError):
    def __init__(self, reason: str = "SOS_QUALIFICATION_CONTRACT_INVALID") -> None:
        super().__init__(reason)
        self.reason = reason


def canonical_digest(value: object) -> str:
    payload = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    return "sha256:" + hashlib.sha256(payload).hexdigest()


_PACKAGE_FILE_LIMIT = 512
_PACKAGE_BYTE_LIMIT = 8 * 1024 * 1024
_EXECUTABLE_SUFFIXES = frozenset({".py", ".json"})


def package_execution_identity() -> dict[str, Any]:
    """Bind qualification to the exact executable SOS package bytes.

    Wheel archives are acquired outside SOS and are not available after an
    ordinary installation. The stable execution identity therefore covers the
    installed package version and every executable/schema resource consumed by
    SOS. Only repository-independent relative names and digests are retained.
    """

    root = Path(__file__).resolve().parent
    files: list[dict[str, Any]] = []
    total_bytes = 0
    for candidate in sorted(root.rglob("*"), key=lambda item: item.relative_to(root).as_posix()):
        if candidate.suffix not in _EXECUTABLE_SUFFIXES:
            continue
        try:
            observed = os.lstat(candidate)
        except OSError as exc:
            raise QualificationContractError("SOS_PACKAGE_EXECUTION_IDENTITY_INVALID") from exc
        if not stat.S_ISREG(observed.st_mode) or stat.S_ISLNK(observed.st_mode):
            raise QualificationContractError("SOS_PACKAGE_EXECUTION_IDENTITY_INVALID")
        if observed.st_size < 0 or observed.st_size > _PACKAGE_BYTE_LIMIT:
            raise QualificationContractError("SOS_PACKAGE_EXECUTION_IDENTITY_INVALID")
        total_bytes += observed.st_size
        if total_bytes > _PACKAGE_BYTE_LIMIT or len(files) >= _PACKAGE_FILE_LIMIT:
            raise QualificationContractError("SOS_PACKAGE_EXECUTION_IDENTITY_INVALID")
        try:
            payload = candidate.read_bytes()
        except OSError as exc:
            raise QualificationContractError("SOS_PACKAGE_EXECUTION_IDENTITY_INVALID") from exc
        if len(payload) != observed.st_size:
            raise QualificationContractError("SOS_PACKAGE_EXECUTION_IDENTITY_DRIFT")
        files.append(
            {
                "path": candidate.relative_to(root).as_posix(),
                "size": len(payload),
                "sha256": hashlib.sha256(payload).hexdigest(),
            }
        )
    if not files:
        raise QualificationContractError("SOS_PACKAGE_EXECUTION_IDENTITY_INVALID")
    return {
        "contract": "sos_package_execution_identity_v1",
        "package": "sigma-operator-stack",
        "package_version": __version__,
        "file_count": len(files),
        "content_digest": canonical_digest(files),
    }


PACKAGE_EXECUTION_IDENTITY = package_execution_identity()
EXECUTOR_DESCRIPTOR = {
    "contract": "sos_qualification_executor_descriptor_v1",
    "implementation": "sos-local-fixed-family-executor",
    "result_protocol": "sos_execution_result_v1",
    "shell": False,
    "network_default": "deny",
    "package_execution_identity": PACKAGE_EXECUTION_IDENTITY,
}
EXECUTOR_DIGEST = canonical_digest(EXECUTOR_DESCRIPTOR)


def seal_contract(value: dict[str, Any]) -> dict[str, Any]:
    contract = value.get("contract")
    if contract not in _SCHEMAS:
        raise QualificationContractError()
    field = _SCHEMAS[contract][2]
    if field in value:
        raise QualificationContractError()
    result = dict(value)
    result[field] = canonical_digest(result)
    validate_contract(result, contract)
    return result


def validate_contract(value: object, expected_contract: str) -> dict[str, Any]:
    if expected_contract not in _SCHEMAS or not isinstance(value, dict):
        raise QualificationContractError()
    if value.get("contract") != expected_contract:
        raise QualificationContractError()
    filename, expected_hash, digest_field = _SCHEMAS[expected_contract]
    raw_schema = resources.files("sos.schemas").joinpath(filename).read_bytes()
    if hashlib.sha256(raw_schema).hexdigest() != expected_hash:
        raise QualificationContractError("SOS_QUALIFICATION_SCHEMA_INTEGRITY_INVALID")
    try:
        schema = json.loads(raw_schema.decode("utf-8"))
        Draft202012Validator(schema, format_checker=FormatChecker()).validate(value)
    except Exception as exc:
        raise QualificationContractError() from exc
    material = dict(value)
    observed = material.pop(digest_field, None)
    if observed != canonical_digest(material):
        raise QualificationContractError("SOS_QUALIFICATION_DIGEST_INVALID")
    return value


def schema_hashes() -> dict[str, str]:
    return {contract: "sha256:" + item[1] for contract, item in _SCHEMAS.items()}


def utc_text(value: datetime) -> str:
    if value.tzinfo is None or value.utcoffset() is None:
        raise QualificationContractError("SOS_QUALIFICATION_TIME_INVALID")
    return value.astimezone(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def parse_utc(value: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except (AttributeError, ValueError) as exc:
        raise QualificationContractError("SOS_QUALIFICATION_TIME_INVALID") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise QualificationContractError("SOS_QUALIFICATION_TIME_INVALID")
    return parsed.astimezone(timezone.utc)
