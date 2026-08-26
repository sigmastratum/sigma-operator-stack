"""Disposable-only bootstrap transaction primitive; not exposed by the CLI."""

from __future__ import annotations

import json
import hashlib
import re
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path

from .platform_admission import FilesystemAdmissionError, require_project_filesystem
from .platform_services import (
    PlatformServiceError,
    TreeStagingCapability,
    TreePublicationOperation,
    current_platform_services,
)


_TX = re.compile(r"^[0-9a-f]{64}$")
_DISPOSABLE_MARKER = ".sos-disposable-root"


class TransactionError(RuntimeError):
    pass


_MAX_BOOTSTRAP_BYTES = 4 * 1024 * 1024
_STAGING_CAPABILITIES: dict[tuple[str, str], TreeStagingCapability] = {}


def _capability_key(root: Path, transaction_id: str) -> tuple[str, str]:
    return root.as_posix(), transaction_id


def _recovery_binding(files: Mapping[tuple[str, ...], bytes]) -> str:
    pending = files.get(("lifecycle", "p106-pending.json"))
    return "none" if pending is None else "sha256:" + hashlib.sha256(pending).hexdigest()


@dataclass(frozen=True, slots=True)
class BootstrapPlan:
    transaction_id: str
    repository_id: str
    plan_digest: str

    def __post_init__(self) -> None:
        if not _TX.fullmatch(self.transaction_id):
            raise ValueError("SOS_TRANSACTION_ID_INVALID")
        if not self.repository_id.startswith("sha256:") or len(self.repository_id) != 71:
            raise ValueError("SOS_REPOSITORY_ID_INVALID")
        if not self.plan_digest.startswith("sha256:") or len(self.plan_digest) != 71:
            raise ValueError("SOS_PLAN_DIGEST_INVALID")


def execute_disposable_bootstrap(root: Path, plan: BootstrapPlan, records: dict[str, dict], *, allow_disposable: bool) -> Path:
    """Atomically create `.sigma` only in an explicitly marked disposable root."""
    if not allow_disposable or not _is_regular_repository_object(root, _DISPOSABLE_MARKER):
        raise TransactionError("SOS_DISPOSABLE_AUTHORITY_REQUIRED")
    _require_admitted_filesystem(root)
    target = root / ".sigma"
    staging = root / f".sigma.init.{plan.transaction_id}"
    staged_capability: TreeStagingCapability | None = None
    try:
        manifest = {
            "contract": "sos_disposable_bootstrap_v1",
            "repository_id": plan.repository_id,
            "plan_digest": plan.plan_digest,
            "records": records,
        }
        payload = json.dumps(manifest, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
        if len(payload) > _MAX_BOOTSTRAP_BYTES:
            raise TransactionError("SOS_BOOTSTRAP_OUTPUT_LIMIT_EXCEEDED")
        service = current_platform_services()
        with service.open_repository(root) as repository:
            staged = service.publish_tree(
                TreePublicationOperation(
                    repository,
                    staging.name,
                    target.name,
                    "create",
                    (("bootstrap.json", payload),),
                    recovery_binding_digest="none",
                )
            )
            if staged.capability is None:
                raise PlatformServiceError("staging_recovery_required")
            staged_capability = staged.capability
            service.publish_tree(
                TreePublicationOperation(
                    repository, staging.name, target.name, capability=staged.capability
                )
            )
        return target
    except PlatformServiceError as exc:
        _discard_live_capability(root, staging.name, target.name, staged_capability)
        reason = {
            "collision": "SOS_CONTROL_PLANE_COLLISION",
            "noreplace_unsupported": "SOS_NOREPLACE_RENAME_UNSUPPORTED",
            "publication_failed": "SOS_ATOMIC_RENAME_FAILED",
            "invalid_root": "SOS_REPOSITORY_ROOT_INVALID",
        }.get(exc.kind, "SOS_ATOMIC_RENAME_FAILED")
        raise TransactionError(reason) from exc
    except BaseException:
        _discard_live_capability(root, staging.name, target.name, staged_capability)
        raise


def execute_bootstrap_files(
    root: Path,
    transaction_id: str,
    files: Mapping[str, bytes],
    *,
    confirmed: bool,
) -> Path:
    """Create a new `.sigma` tree atomically without replacing existing state."""
    if not confirmed:
        raise TransactionError("SOS_BOOTSTRAP_CONFIRMATION_REQUIRED")
    if not _TX.fullmatch(transaction_id):
        raise TransactionError("SOS_TRANSACTION_ID_INVALID")
    _require_repository_root(root)
    target_name = ".sigma"
    staging_name = f".sigma.init.{transaction_id}"
    if not files:
        raise TransactionError("SOS_BOOTSTRAP_PLAN_EMPTY")
    total = 0
    normalized: dict[tuple[str, ...], bytes] = {}
    for relative, payload in files.items():
        path = Path(relative)
        parts = path.parts
        if path.is_absolute() or not parts or any(part in ("", ".", "..") for part in parts):
            raise TransactionError("SOS_BOOTSTRAP_PATH_INVALID")
        if any("/" in part or "\\" in part or "\x00" in part for part in parts):
            raise TransactionError("SOS_BOOTSTRAP_PATH_INVALID")
        total += len(payload)
        if total > _MAX_BOOTSTRAP_BYTES:
            raise TransactionError("SOS_BOOTSTRAP_OUTPUT_LIMIT_EXCEEDED")
        normalized[parts] = payload

    create_bootstrap_staging(root, transaction_id, normalized)
    return commit_bootstrap_staging(root, transaction_id)


def create_bootstrap_staging(
    root: Path,
    transaction_id: str,
    files: Mapping[str | tuple[str, ...], bytes],
) -> Path:
    """Create one exact sibling staging tree without making it canonical."""
    if not _TX.fullmatch(transaction_id):
        raise TransactionError("SOS_TRANSACTION_ID_INVALID")
    _require_repository_root(root)
    _require_admitted_filesystem(root)
    normalized = _normalize_files(files)
    if not normalized:
        raise TransactionError("SOS_BOOTSTRAP_PLAN_EMPTY")
    target_name = ".sigma"
    staging_name = f".sigma.init.{transaction_id}"
    try:
        service = current_platform_services()
        with service.open_repository(root) as repository:
            receipt = service.publish_tree(
                TreePublicationOperation(
                    repository,
                    staging_name,
                    target_name,
                    "create",
                    tuple(("/".join(parts), payload) for parts, payload in sorted(normalized.items())),
                    recovery_binding_digest=_recovery_binding(normalized),
                )
            )
            if receipt.capability is None:
                raise PlatformServiceError("staging_recovery_required")
            _STAGING_CAPABILITIES[_capability_key(root, transaction_id)] = receipt.capability
        return root / staging_name
    except PlatformServiceError as exc:
        reason = {
            "collision": "SOS_CONTROL_PLANE_COLLISION",
            "publication_failed": "SOS_BOOTSTRAP_WRITE_FAILED",
            "invalid_root": "SOS_REPOSITORY_ROOT_INVALID",
        }.get(exc.kind, "SOS_BOOTSTRAP_WRITE_FAILED")
        raise TransactionError(reason) from exc


def extend_bootstrap_staging(
    root: Path,
    transaction_id: str,
    files: Mapping[str | tuple[str, ...], bytes],
) -> Path:
    """Append non-colliding files to one exact staging tree."""
    if not _TX.fullmatch(transaction_id):
        raise TransactionError("SOS_TRANSACTION_ID_INVALID")
    _require_admitted_filesystem(root)
    normalized = _normalize_files(files)
    staging_name = f".sigma.init.{transaction_id}"
    try:
        service = current_platform_services()
        with service.open_repository(root) as repository:
            capability = _STAGING_CAPABILITIES.get(_capability_key(root, transaction_id))
            if capability is None:
                raise PlatformServiceError("staging_recovery_required")
            receipt = service.publish_tree(
                TreePublicationOperation(
                    repository,
                    staging_name,
                    ".sigma",
                    "extend",
                    tuple(("/".join(parts), payload) for parts, payload in sorted(normalized.items())),
                    capability=capability,
                )
            )
            if receipt.capability is not capability:
                raise PlatformServiceError("staging_recovery_required")
        return root / staging_name
    except PlatformServiceError as exc:
        raise TransactionError("SOS_STAGING_RECOVERY_REQUIRED") from exc


def commit_bootstrap_staging(root: Path, transaction_id: str) -> Path:
    """Atomically admit one fully prepared sibling tree as canonical `.sigma`."""
    if not _TX.fullmatch(transaction_id):
        raise TransactionError("SOS_TRANSACTION_ID_INVALID")
    _require_admitted_filesystem(root)
    staging_name = f".sigma.init.{transaction_id}"
    try:
        service = current_platform_services()
        with service.open_repository(root) as repository:
            capability = _STAGING_CAPABILITIES.get(_capability_key(root, transaction_id))
            if capability is None:
                raise PlatformServiceError("staging_recovery_required")
            service.publish_tree(
                TreePublicationOperation(
                    repository, staging_name, ".sigma", capability=capability
                )
            )
            _STAGING_CAPABILITIES.pop(_capability_key(root, transaction_id), None)
        return root / ".sigma"
    except PlatformServiceError as exc:
        reason = {
            "staging_missing": "SOS_STAGING_RECOVERY_REQUIRED",
            "collision": "SOS_CONTROL_PLANE_COLLISION",
            "noreplace_unsupported": "SOS_NOREPLACE_RENAME_UNSUPPORTED",
            "publication_failed": "SOS_ATOMIC_RENAME_FAILED",
            "invalid_root": "SOS_REPOSITORY_ROOT_INVALID",
        }.get(exc.kind, "SOS_ATOMIC_RENAME_FAILED")
        raise TransactionError(reason) from exc


def discard_bootstrap_staging(
    root: Path,
    transaction_id: str,
    *,
    recovery_binding_digest: str | None = None,
) -> None:
    """Remove only one validated sibling staging tree; never follow symlinks."""
    if not _TX.fullmatch(transaction_id):
        raise TransactionError("SOS_TRANSACTION_ID_INVALID")
    staging_name = f".sigma.init.{transaction_id}"
    try:
        service = current_platform_services()
        with service.open_repository(root) as repository:
            capability = _STAGING_CAPABILITIES.get(_capability_key(root, transaction_id))
            if capability is None:
                if recovery_binding_digest is None:
                    raise PlatformServiceError("staging_recovery_required")
                recovered = service.publish_tree(
                    TreePublicationOperation(
                        repository,
                        staging_name,
                        ".sigma",
                        "recover",
                        recovery_binding_digest=recovery_binding_digest,
                    )
                )
                capability = recovered.capability
            if capability is None:
                raise PlatformServiceError("staging_recovery_required")
            service.publish_tree(
                TreePublicationOperation(
                    repository,
                    staging_name,
                    ".sigma",
                    "discard",
                    capability=capability,
                )
            )
            _STAGING_CAPABILITIES.pop(_capability_key(root, transaction_id), None)
    except PlatformServiceError as exc:
        raise TransactionError("SOS_STAGING_RECOVERY_REQUIRED") from exc


def _require_admitted_filesystem(root: Path) -> None:
    try:
        require_project_filesystem(root)
    except FilesystemAdmissionError as exc:
        raise TransactionError(exc.reason) from exc


def _require_repository_root(root: Path) -> None:
    service = current_platform_services()
    try:
        with service.open_repository(root):
            return
    except PlatformServiceError as exc:
        raise TransactionError("SOS_REPOSITORY_ROOT_INVALID") from exc


def _is_regular_repository_object(root: Path, relative: str) -> bool:
    service = current_platform_services()
    try:
        with service.open_repository(root) as repository:
            return service.observe_object(repository, relative).kind == "regular"
    except PlatformServiceError:
        return False


def _discard_live_capability(
    root: Path,
    staging_name: str,
    target_name: str,
    capability: TreeStagingCapability | None,
) -> None:
    if capability is None or capability.consumed:
        return
    service = current_platform_services()
    try:
        with service.open_repository(root) as repository:
            service.publish_tree(
                TreePublicationOperation(
                    repository,
                    staging_name,
                    target_name,
                    "discard",
                    capability=capability,
                )
            )
    except PlatformServiceError:
        return


def _normalize_files(
    files: Mapping[str | tuple[str, ...], bytes],
) -> dict[tuple[str, ...], bytes]:
    total = 0
    normalized: dict[tuple[str, ...], bytes] = {}
    for relative, payload in files.items():
        path = Path(*relative) if isinstance(relative, tuple) else Path(relative)
        parts = path.parts
        if not isinstance(payload, bytes):
            raise TransactionError("SOS_BOOTSTRAP_PAYLOAD_INVALID")
        if path.is_absolute() or not parts or any(part in ("", ".", "..") for part in parts):
            raise TransactionError("SOS_BOOTSTRAP_PATH_INVALID")
        if any("/" in part or "\\" in part or "\x00" in part for part in parts):
            raise TransactionError("SOS_BOOTSTRAP_PATH_INVALID")
        total += len(payload)
        if total > _MAX_BOOTSTRAP_BYTES:
            raise TransactionError("SOS_BOOTSTRAP_OUTPUT_LIMIT_EXCEEDED")
        normalized[parts] = payload
    return normalized
