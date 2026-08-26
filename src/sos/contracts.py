"""Exact P101-v2 schema validation and canonical integrity primitives."""

from __future__ import annotations

import copy
import hashlib
import json
from functools import lru_cache
from typing import Any

from jsonschema import Draft202012Validator, RefResolver
from jsonschema.exceptions import ValidationError

from .package_resources import PackageResourceError, read_package_resource


V1_SCHEMA_SHA256 = "19164d394c55ed29e30ddef638dc79241e19692b552e3a91ef81233c6bd59208"
V2_SCHEMA_SHA256 = "79155ac28d419d3750fb02c1c23a5c018dc51a914ca708092a4e6065727e5d1f"


class ContractError(RuntimeError):
    """A content-safe P101 contract or integrity failure."""

    def __init__(self, reason: str = "SOS_CONTROL_PLANE_INTEGRITY_INVALID") -> None:
        super().__init__(reason)
        self.reason = reason


def canonical_json(value: object) -> bytes:
    """RFC-8785-compatible bytes for the closed P101 value domain.

    P101 records reject floating-point values, use ASCII object keys and carry
    only JSON integers, strings, booleans, nulls, arrays and objects.  For this
    closed domain Python's compact, UTF-8, key-sorted encoding is RFC 8785.
    """
    _reject_noncanonical_numbers(value)
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def digest_value(value: object) -> str:
    return "sha256:" + hashlib.sha256(canonical_json(value)).hexdigest()


def exclusion_policy_digest(value: dict[str, Any]) -> str:
    material = copy.deepcopy(value)
    material.pop("policy_digest", None)
    return digest_value(material)


def source_observation_digest(value: dict[str, Any]) -> str:
    material = copy.deepcopy(value)
    material.pop("observation_digest", None)
    return digest_value(material)


def seal_record(value: dict[str, Any]) -> dict[str, Any]:
    sealed = copy.deepcopy(value)
    sealed["revision_id"] = "sha256:" + "0" * 64
    sealed["integrity"] = {"record_sha256": "0" * 64}
    digest = _record_digest(sealed)
    sealed["revision_id"] = digest
    sealed["integrity"]["record_sha256"] = digest.removeprefix("sha256:")
    validate_p101_v2(sealed)
    return sealed


def verify_record(value: dict[str, Any]) -> None:
    validate_p101_v2(value)
    digest = _record_digest(value)
    if value.get("revision_id") != digest:
        raise ContractError()
    integrity = value.get("integrity")
    if not isinstance(integrity, dict) or integrity.get("record_sha256") != digest.removeprefix("sha256:"):
        raise ContractError()


def seal_receipt(value: dict[str, Any]) -> dict[str, Any]:
    sealed = copy.deepcopy(value)
    sealed["receipt_id"] = "sha256:" + "0" * 64
    sealed["integrity"] = {"receipt_sha256": "0" * 64}
    digest = _receipt_digest(sealed)
    sealed["receipt_id"] = digest
    sealed["integrity"]["receipt_sha256"] = digest.removeprefix("sha256:")
    validate_p101_v2(sealed)
    return sealed


def verify_receipt(value: dict[str, Any]) -> None:
    validate_p101_v2(value)
    digest = _receipt_digest(value)
    if value.get("receipt_id") != digest:
        raise ContractError()
    integrity = value.get("integrity")
    if not isinstance(integrity, dict) or integrity.get("receipt_sha256") != digest.removeprefix("sha256:"):
        raise ContractError()
    if value.get("accepted_revision") != value.get("proposal_revision"):
        raise ContractError()


def validate_source_observation(value: dict[str, Any]) -> None:
    validate_p101_v2(value)
    exclusion = value.get("exclusion_policy")
    if not isinstance(exclusion, dict) or exclusion.get("policy_digest") != exclusion_policy_digest(exclusion):
        raise ContractError()
    if value.get("observation_digest") != source_observation_digest(value):
        raise ContractError()


def validate_p101_v2(value: dict[str, Any]) -> None:
    try:
        _validator().validate(value)
    except (ValidationError, TypeError, ValueError) as exc:
        raise ContractError() from exc


def schema_bundle_hashes() -> dict[str, str]:
    v1_bytes = _schema_bytes("sos-contracts-v1.schema.json")
    v2_bytes = _schema_bytes("sos-contracts-v2.schema.json")
    observed = {
        "sos-contracts-v1.schema.json": hashlib.sha256(v1_bytes).hexdigest(),
        "sos-contracts-v2.schema.json": hashlib.sha256(v2_bytes).hexdigest(),
    }
    if observed["sos-contracts-v1.schema.json"] != V1_SCHEMA_SHA256:
        raise ContractError()
    if observed["sos-contracts-v2.schema.json"] != V2_SCHEMA_SHA256:
        raise ContractError()
    return observed


def _record_digest(value: dict[str, Any]) -> str:
    material = copy.deepcopy(value)
    material.pop("revision_id", None)
    integrity = material.get("integrity")
    if isinstance(integrity, dict):
        integrity.pop("record_sha256", None)
    return digest_value(material)


def _receipt_digest(value: dict[str, Any]) -> str:
    material = copy.deepcopy(value)
    material.pop("receipt_id", None)
    integrity = material.get("integrity")
    if isinstance(integrity, dict):
        integrity.pop("receipt_sha256", None)
    return digest_value(material)


def _reject_noncanonical_numbers(value: object) -> None:
    if isinstance(value, float):
        raise ContractError()
    if isinstance(value, dict):
        if any(not isinstance(key, str) for key in value):
            raise ContractError()
        for item in value.values():
            _reject_noncanonical_numbers(item)
    elif isinstance(value, (list, tuple)):
        for item in value:
            _reject_noncanonical_numbers(item)


def _schema_bytes(name: str) -> bytes:
    try:
        return read_package_resource(f"schema:{name}").payload
    except PackageResourceError as exc:
        raise ContractError() from exc


@lru_cache(maxsize=1)
def _validator() -> Draft202012Validator:
    schema_bundle_hashes()
    v1 = json.loads(_schema_bytes("sos-contracts-v1.schema.json"))
    v2 = json.loads(_schema_bytes("sos-contracts-v2.schema.json"))
    Draft202012Validator.check_schema(v1)
    Draft202012Validator.check_schema(v2)
    resolver = RefResolver.from_schema(v2, store={v1["$id"]: v1, v2["$id"]: v2})
    return Draft202012Validator(v2, resolver=resolver)
