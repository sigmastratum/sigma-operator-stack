"""Sealed, bounded access to immutable SOS package resources."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from importlib import resources


class PackageResourceError(RuntimeError):
    """A content-safe package-resource admission failure."""

    def __init__(self, reason: str = "SOS_PACKAGE_RESOURCE_INVALID") -> None:
        super().__init__(reason)
        self.reason = reason


@dataclass(frozen=True)
class PackageResourceRead:
    resource_id: str
    payload: bytes
    sha256: str

    def safe_projection(self) -> dict[str, object]:
        return {
            "resource_id": self.resource_id,
            "size": len(self.payload),
            "sha256": self.sha256,
            "raw_content_serialized": False,
        }


_SCHEMA_FILES = (
    "sos-command-admission-v1.schema.json",
    "sos-contracts-v1.schema.json",
    "sos-contracts-v2.schema.json",
    "sos-execution-result-v1.schema.json",
    "sos-managed-file-batch-projection-v1.schema.json",
    "sos-managed-file-batch-v1.schema.json",
    "sos-managed-file-event-v1.schema.json",
    "sos-managed-file-plan-v1.schema.json",
    "sos-qualification-plan-v1.schema.json",
    "sos-qualification-receipt-v1.schema.json",
)
PACKAGE_RESOURCE_REGISTRY = {
    f"schema:{name}": ("sos.schemas", name) for name in _SCHEMA_FILES
}
MAX_PACKAGE_RESOURCE_BYTES = 1024 * 1024


def read_package_resource(
    resource_id: str,
    *,
    byte_limit: int = MAX_PACKAGE_RESOURCE_BYTES,
) -> PackageResourceRead:
    """Read one exact registered package resource without caller path authority."""

    if not isinstance(resource_id, str) or resource_id not in PACKAGE_RESOURCE_REGISTRY:
        raise PackageResourceError("SOS_PACKAGE_RESOURCE_NOT_REGISTERED")
    if not isinstance(byte_limit, int) or isinstance(byte_limit, bool) or not 0 < byte_limit <= MAX_PACKAGE_RESOURCE_BYTES:
        raise PackageResourceError("SOS_PACKAGE_RESOURCE_LIMIT_INVALID")
    package, filename = PACKAGE_RESOURCE_REGISTRY[resource_id]
    try:
        payload = resources.files(package).joinpath(filename).read_bytes()
    except (OSError, TypeError) as exc:
        raise PackageResourceError("SOS_PACKAGE_RESOURCE_UNAVAILABLE") from exc
    if len(payload) > byte_limit:
        raise PackageResourceError("SOS_PACKAGE_RESOURCE_LIMIT_EXCEEDED")
    return PackageResourceRead(
        resource_id=resource_id,
        payload=payload,
        sha256=hashlib.sha256(payload).hexdigest(),
    )
