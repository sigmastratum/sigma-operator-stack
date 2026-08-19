"""Closed public contracts for the non-authoritative P104 lifecycle."""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from importlib import resources
from typing import Any

from jsonschema import Draft202012Validator, FormatChecker


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

EXECUTOR_DESCRIPTOR = {
    "contract": "sos_qualification_executor_descriptor_v1",
    "implementation": "sos-local-fixed-family-executor",
    "result_protocol": "sos_execution_result_v1",
    "shell": False,
    "network_default": "deny",
}
EXECUTOR_DIGEST = "sha256:" + hashlib.sha256(
    json.dumps(EXECUTOR_DESCRIPTOR, sort_keys=True, separators=(",", ":")).encode("utf-8")
).hexdigest()


class QualificationContractError(RuntimeError):
    def __init__(self, reason: str = "SOS_QUALIFICATION_CONTRACT_INVALID") -> None:
        super().__init__(reason)
        self.reason = reason


def canonical_digest(value: object) -> str:
    payload = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    return "sha256:" + hashlib.sha256(payload).hexdigest()


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
