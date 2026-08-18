"""Minimal existing-first bootstrap, currentness, doctor and recovery views."""

from __future__ import annotations

import hashlib
import json
import os
import stat
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .checks import CheckPlan, QualificationReceipt, discover_checks
from .repository import RepositoryError, discover_repository_root, inspect_repository
from .result import Status, TerminalResult
from .transaction import TransactionError, execute_bootstrap_files


_MAX_RECORD_BYTES = 1024 * 1024
_AUTHORITY_CANDIDATES = (
    "AGENTS.md",
    "CLAUDE.md",
    ".github/copilot-instructions.md",
    "README.md",
)
_TASK_CANDIDATES = (
    "tasks/current.md",
    "tasks/active.md",
    "docs/current-sprint.md",
    "docs/roadmap.md",
    "ROADMAP.md",
    "TODO.md",
)
_DOC_CANDIDATES = (
    "README.md",
    "CONTRIBUTING.md",
    "ARCHITECTURE.md",
    "SECURITY.md",
    "docs",
)


def initialize_workspace(path: str = ".", *, confirmed: bool) -> TerminalResult:
    try:
        root = discover_repository_root(path)
        inspection = inspect_repository(root)
    except RepositoryError as exc:
        return _failure(Status.INVALID, exc.reason)
    if inspection.control_plane_state != "absent":
        status = workspace_status(os.fspath(root))
        if status.status == Status.SUCCESS:
            return TerminalResult(
                contract="sos_init_result_v1",
                status=Status.SUCCESS,
                reasons=("SOS_ALREADY_INITIALIZED",),
                details=status.details,
            )
        return TerminalResult(
            contract="sos_init_result_v1",
            status=status.status,
            reasons=status.reasons,
            details=status.details,
        )
    if inspection.head is None:
        return _failure(Status.NOT_VERIFIED, "SOS_REPOSITORY_UNBORN")
    if not confirmed:
        return _failure(Status.OWNER_REQUIRED, "SOS_BOOTSTRAP_CONFIRMATION_REQUIRED")

    plan = discover_checks(os.fspath(root))
    created_at = datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")
    authority_paths = tuple(candidate for candidate in _AUTHORITY_CANDIDATES if (root / candidate).is_file())
    docs = tuple(candidate for candidate in _DOC_CANDIDATES if (root / candidate).exists())
    task_path = next((candidate for candidate in _TASK_CANDIDATES if (root / candidate).is_file()), None)
    intent = {
        "repository_id": inspection.repository_id,
        "source_tree_digest": inspection.application_tree_digest,
        "source_status_digest": inspection.application_status_digest,
        "authority_paths": authority_paths,
        "documentation_paths": docs,
        "current_task_path": task_path,
        "check_plan_digest": plan.plan_digest,
    }
    bootstrap_intent_id = _digest_json(intent)
    authority = {
        "contract": "sos_authority_record_v1",
        "repository_id": inspection.repository_id,
        "authority_paths": list(authority_paths),
        "documentation_paths": list(docs),
        "authority_state": "accepted_local_weak_evidence" if authority_paths else "owner_required",
        "source_tree_digest": inspection.application_tree_digest,
    }
    policy = {
        "contract": "sos_policy_record_v1",
        "default_decision": "owner_required",
        "local_read": "allowed",
        "proposal_write": "allowed_inside_sigma",
        "external_actions": "owner_required",
        "network": "not_implicit",
        "commit_push_deploy": "not_granted",
    }
    operator = {
        "contract": "sos_operator_state_v1",
        "current_task_path": task_path,
        "current_task_state": "accepted_local_weak_evidence" if task_path else "not_configured",
        "next_action": {
            "action_class": "review_and_qualify",
            "target_paths": [task_path] if task_path else [".sigma/views/project-map.md"],
            "description": (
                "Review the detected current task, then run sos doctor."
                if task_path
                else "Review the generated project map, declare the current task, then run sos doctor."
            ),
            "stop_conditions": [
                "authority conflict",
                "source currentness changed",
                "qualification failed or is not verified",
                "external action requires owner confirmation",
            ],
        },
        "check_plan_digest": plan.plan_digest,
    }
    record_values = (authority, policy, operator)
    record_names = ("authority", "policy", "operator-state")
    record_digests = tuple(_digest_json(value) for value in record_values)
    receipts: list[dict[str, Any]] = []
    predecessor: str | None = None
    kinds = ("authority_bootstrap", "policy_bootstrap_plan", "operator_state_bootstrap_plan")
    for ordinal, (kind, record_digest) in enumerate(zip(kinds, record_digests, strict=True), start=1):
        receipt_without_id = {
            "contract": "sos_bootstrap_receipt_v1",
            "receipt_kind": kind,
            "sequence_ordinal": ordinal,
            "repository_id": inspection.repository_id,
            "accepted_revision": record_digest,
            "predecessor_receipt": predecessor,
            "bootstrap_intent_id": bootstrap_intent_id,
            "source_tree_digest": inspection.application_tree_digest,
            "source_status_digest": inspection.application_status_digest,
            "actor": {
                "surface": "human_intended_local_cli",
                "identity_assurance": "declared_local_evidence_only",
                "strong_authentication_claimed": False,
                "agent_invocation_prevented": False,
            },
            "accepted_at": created_at,
            "decision": "accepted",
        }
        receipt = dict(receipt_without_id)
        receipt["receipt_id"] = _digest_json(receipt_without_id)
        predecessor = receipt["receipt_id"]
        receipts.append(receipt)

    manifest = {
        "contract": "sos_workspace_manifest_v1",
        "repository_id": inspection.repository_id,
        "bootstrap_intent_id": bootstrap_intent_id,
        "source_binding": {
            "tree_digest": inspection.application_tree_digest,
            "status_digest": inspection.application_status_digest,
        },
        "records": {name: digest for name, digest in zip(record_names, record_digests, strict=True)},
        "receipt_tip": predecessor,
        "check_plan_digest": plan.plan_digest,
        "created_at": created_at,
    }
    project_map = _project_map_markdown(authority_paths, docs, task_path, plan)
    recovery = _recovery_payload(manifest, authority, policy, operator, plan, qualification=None, status="not_verified")
    files: dict[str, bytes] = {
        "manifest.json": _json_bytes(manifest),
        "records/authority.json": _json_bytes(authority),
        "records/policy.json": _json_bytes(policy),
        "records/operator-state.json": _json_bytes(operator),
        "checks/plan.json": _json_bytes(plan.to_dict()),
        "views/project-map.md": project_map.encode("utf-8"),
        "views/recovery.json": _json_bytes(recovery),
        "views/recovery.md": _recovery_markdown(recovery).encode("utf-8"),
    }
    for ordinal, receipt in enumerate(receipts, start=1):
        files[f"receipts/{ordinal:02d}-{receipt['receipt_kind']}.json"] = _json_bytes(receipt)
    transaction_id = bootstrap_intent_id.removeprefix("sha256:")
    try:
        execute_bootstrap_files(root, transaction_id, files, confirmed=True)
    except TransactionError as exc:
        return _failure(Status.BLOCKED, str(exc))
    return TerminalResult(
        contract="sos_init_result_v1",
        status=Status.SUCCESS,
        reasons=("SOS_BOOTSTRAP_COMPLETE",),
        details={
            "repository_id": inspection.repository_id,
            "source_tree_digest": inspection.application_tree_digest,
            "receipt_tip": predecessor,
            "configured_check_families": sum(family.status == "configured" for family in plan.families),
            "raw_project_content_serialized": False,
        },
    )


def workspace_status(path: str = ".") -> TerminalResult:
    try:
        root = discover_repository_root(path)
        inspection = inspect_repository(root)
        manifest = _read_json(root, "manifest.json")
    except RepositoryError as exc:
        return _failure(Status.INVALID, exc.reason)
    except WorkspaceError as exc:
        return _failure(Status.INVALID, str(exc))
    if manifest.get("contract") != "sos_workspace_manifest_v1":
        return _failure(Status.INVALID, "SOS_WORKSPACE_MANIFEST_INVALID")
    if manifest.get("repository_id") != inspection.repository_id:
        return _failure(Status.INVALID, "SOS_REPOSITORY_ID_MISMATCH")
    binding = manifest.get("source_binding")
    if not isinstance(binding, dict):
        return _failure(Status.INVALID, "SOS_SOURCE_BINDING_INVALID")
    reasons: list[str] = []
    if binding.get("tree_digest") != inspection.application_tree_digest:
        reasons.append("SOS_SOURCE_TREE_CHANGED")
    if binding.get("status_digest") != inspection.application_status_digest:
        reasons.append("SOS_SOURCE_STATUS_CHANGED")
    if reasons:
        return TerminalResult(
            contract="sos_workspace_status_v1",
            status=Status.STALE,
            reasons=tuple(reasons),
            details={
                "repository_id": inspection.repository_id,
                "source_tree_digest": inspection.application_tree_digest,
                "source_status_digest": inspection.application_status_digest,
                "raw_project_content_serialized": False,
            },
        )
    return TerminalResult(
        contract="sos_workspace_status_v1",
        status=Status.SUCCESS,
        reasons=("SOS_WORKSPACE_CURRENT",),
        details={
            "repository_id": inspection.repository_id,
            "source_tree_digest": inspection.application_tree_digest,
            "source_status_digest": inspection.application_status_digest,
            "receipt_tip": manifest.get("receipt_tip"),
            "raw_project_content_serialized": False,
        },
    )


def recover_workspace(path: str = ".") -> TerminalResult:
    status = workspace_status(path)
    if status.status in (Status.INVALID, Status.BLOCKED):
        return TerminalResult("sos_recovery_result_v1", status.status, status.reasons, status.details)
    try:
        root = discover_repository_root(path)
        manifest = _read_json(root, "manifest.json")
        authority = _read_json(root, "records/authority.json")
        policy = _read_json(root, "records/policy.json")
        operator = _read_json(root, "records/operator-state.json")
        plan = _read_json(root, "checks/plan.json")
        qualification = _read_optional_json(root, "views/qualification.json")
    except (RepositoryError, WorkspaceError) as exc:
        reason = exc.reason if isinstance(exc, RepositoryError) else str(exc)
        return _failure(Status.INVALID, reason, contract="sos_recovery_result_v1")
    payload = _recovery_payload(
        manifest,
        authority,
        policy,
        operator,
        plan,
        qualification,
        status=status.status.value,
    )
    reasons = status.reasons if status.status == Status.STALE else ("SOS_RECOVERY_READY",)
    return TerminalResult(
        contract="sos_recovery_result_v1",
        status=status.status,
        reasons=reasons,
        details=payload,
    )


def doctor_workspace(path: str = ".") -> TerminalResult:
    recovery = recover_workspace(path)
    if recovery.status != Status.SUCCESS:
        return TerminalResult("sos_doctor_result_v1", recovery.status, recovery.reasons, recovery.details)
    authority = recovery.details.get("authority")
    if not isinstance(authority, dict) or authority.get("state") != "accepted_local_weak_evidence":
        return TerminalResult(
            "sos_doctor_result_v1",
            Status.OWNER_REQUIRED,
            ("SOS_AUTHORITY_NOT_ACCEPTED",),
            recovery.details,
        )
    current_work = recovery.details.get("current_work")
    if not isinstance(current_work, dict) or current_work.get("state") != "accepted_local_weak_evidence":
        return TerminalResult(
            "sos_doctor_result_v1",
            Status.OWNER_REQUIRED,
            ("SOS_CURRENT_WORK_NOT_CONFIGURED",),
            recovery.details,
        )
    qualification = recovery.details.get("qualification")
    if not isinstance(qualification, dict):
        return TerminalResult(
            "sos_doctor_result_v1",
            Status.NOT_VERIFIED,
            ("SOS_QUALIFICATION_NOT_RUN",),
            recovery.details,
        )
    if qualification.get("source_tree_digest") != recovery.details.get("source_binding", {}).get("tree_digest"):
        return TerminalResult("sos_doctor_result_v1", Status.STALE, ("SOS_QUALIFICATION_STALE",), recovery.details)
    if qualification.get("status") != "passed_local":
        return TerminalResult("sos_doctor_result_v1", Status.NOT_VERIFIED, ("SOS_QUALIFICATION_NOT_PASSED",), recovery.details)
    return TerminalResult("sos_doctor_result_v1", Status.SUCCESS, ("SOS_READY_FOR_AGENT",), recovery.details)


def store_qualification(path: str, receipt: QualificationReceipt) -> None:
    root = discover_repository_root(path)
    status = workspace_status(os.fspath(root))
    if status.status != Status.SUCCESS:
        raise WorkspaceError("SOS_WORKSPACE_NOT_CURRENT")
    if receipt.source_tree_digest != status.details.get("source_tree_digest"):
        raise WorkspaceError("SOS_QUALIFICATION_STALE")
    view_directory = _open_control_directory(root, ("views",), create=False)
    os.close(view_directory)
    payload = receipt.to_dict()
    receipt_digest = _digest_json(payload).removeprefix("sha256:")
    _write_immutable_json(root, f"qualification/receipts/{receipt_digest}.json", payload)
    view = dict(payload)
    view["receipt_digest"] = "sha256:" + receipt_digest
    _replace_view_json(root, "views/qualification.json", view)


class WorkspaceError(RuntimeError):
    pass


def _read_json(root: Path, relative: str) -> dict[str, Any]:
    parts = Path(relative).parts
    descriptor = _open_control_directory(root, parts[:-1], create=False)
    try:
        try:
            file_descriptor = os.open(parts[-1], os.O_RDONLY | os.O_NOFOLLOW, dir_fd=descriptor)
        except FileNotFoundError as exc:
            raise WorkspaceError("SOS_WORKSPACE_RECORD_MISSING") from exc
        try:
            metadata = os.fstat(file_descriptor)
            if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > _MAX_RECORD_BYTES:
                raise WorkspaceError("SOS_WORKSPACE_RECORD_INVALID")
            payload = bytearray()
            while len(payload) <= _MAX_RECORD_BYTES:
                chunk = os.read(file_descriptor, min(65536, _MAX_RECORD_BYTES + 1 - len(payload)))
                if not chunk:
                    break
                payload.extend(chunk)
            if len(payload) > _MAX_RECORD_BYTES:
                raise WorkspaceError("SOS_WORKSPACE_RECORD_INVALID")
        finally:
            os.close(file_descriptor)
        value = json.loads(payload.decode("utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise WorkspaceError("SOS_WORKSPACE_RECORD_INVALID") from exc
    finally:
        os.close(descriptor)
    if not isinstance(value, dict):
        raise WorkspaceError("SOS_WORKSPACE_RECORD_INVALID")
    return value


def _read_optional_json(root: Path, relative: str) -> dict[str, Any] | None:
    try:
        return _read_json(root, relative)
    except WorkspaceError as exc:
        if str(exc) == "SOS_WORKSPACE_RECORD_MISSING":
            return None
        raise


def _write_immutable_json(root: Path, relative: str, value: dict[str, Any]) -> None:
    parts = Path(relative).parts
    descriptor = _open_control_directory(root, parts[:-1], create=True)
    payload = _json_bytes(value)
    try:
        try:
            file_descriptor = os.open(
                parts[-1],
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                0o600,
                dir_fd=descriptor,
            )
        except FileExistsError as exc:
            try:
                existing_descriptor = os.open(parts[-1], os.O_RDONLY | os.O_NOFOLLOW, dir_fd=descriptor)
                try:
                    existing_payload = os.read(existing_descriptor, _MAX_RECORD_BYTES + 1)
                finally:
                    os.close(existing_descriptor)
                existing = json.loads(existing_payload.decode("utf-8"))
            except (OSError, UnicodeError, json.JSONDecodeError) as read_exc:
                raise WorkspaceError("SOS_RECEIPT_COLLISION") from read_exc
            if existing != value:
                raise WorkspaceError("SOS_RECEIPT_COLLISION") from exc
            return
        try:
            _write_all(file_descriptor, payload)
            os.fsync(file_descriptor)
        finally:
            os.close(file_descriptor)
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _replace_view_json(root: Path, relative: str, value: dict[str, Any]) -> None:
    parts = Path(relative).parts
    descriptor = _open_control_directory(root, parts[:-1], create=False)
    temporary = parts[-1] + ".tmp"
    payload = _json_bytes(value)
    try:
        try:
            file_descriptor = os.open(
                temporary,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                0o600,
                dir_fd=descriptor,
            )
        except FileExistsError as exc:
            raise WorkspaceError("SOS_VIEW_UPDATE_COLLISION") from exc
        try:
            _write_all(file_descriptor, payload)
            os.fsync(file_descriptor)
        finally:
            os.close(file_descriptor)
        os.replace(temporary, parts[-1], src_dir_fd=descriptor, dst_dir_fd=descriptor)
        os.fsync(descriptor)
    finally:
        try:
            os.unlink(temporary, dir_fd=descriptor)
        except FileNotFoundError:
            pass
        os.close(descriptor)


def _open_control_directory(root: Path, parts: tuple[str, ...], *, create: bool) -> int:
    try:
        descriptor = os.open(root / ".sigma", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    except FileNotFoundError as exc:
        raise WorkspaceError("SOS_WORKSPACE_NOT_INITIALIZED") from exc
    except OSError as exc:
        raise WorkspaceError("SOS_WORKSPACE_RECORD_INVALID") from exc
    try:
        for part in parts:
            if part in ("", ".", "..") or "/" in part or "\\" in part:
                raise WorkspaceError("SOS_WORKSPACE_RECORD_INVALID")
            if create:
                try:
                    os.mkdir(part, mode=0o700, dir_fd=descriptor)
                except FileExistsError:
                    pass
            try:
                next_descriptor = os.open(
                    part,
                    os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                    dir_fd=descriptor,
                )
            except FileNotFoundError as exc:
                reason = "SOS_WORKSPACE_RECORD_MISSING" if not create else "SOS_WORKSPACE_RECORD_INVALID"
                raise WorkspaceError(reason) from exc
            except OSError as exc:
                raise WorkspaceError("SOS_WORKSPACE_RECORD_INVALID") from exc
            os.close(descriptor)
            descriptor = next_descriptor
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def _write_all(descriptor: int, payload: bytes) -> None:
    offset = 0
    while offset < len(payload):
        written = os.write(descriptor, payload[offset:])
        if written <= 0:
            raise WorkspaceError("SOS_WORKSPACE_RECORD_INVALID")
        offset += written


def _recovery_payload(
    manifest: dict[str, Any],
    authority: dict[str, Any],
    policy: dict[str, Any],
    operator: dict[str, Any],
    plan: CheckPlan | dict[str, Any],
    qualification: dict[str, Any] | None,
    *,
    status: str,
) -> dict[str, Any]:
    plan_value = plan.to_dict() if isinstance(plan, CheckPlan) else plan
    return {
        "contract": "sos_recovery_view_v1",
        "status": status,
        "repository_id": manifest.get("repository_id"),
        "source_binding": manifest.get("source_binding"),
        "authority": {
            "state": authority.get("authority_state"),
            "paths": authority.get("authority_paths", []),
        },
        "current_work": {
            "path": operator.get("current_task_path"),
            "state": operator.get("current_task_state"),
            "next_action": operator.get("next_action"),
        },
        "boundaries": {
            "default_decision": policy.get("default_decision"),
            "external_actions": policy.get("external_actions"),
            "commit_push_deploy": policy.get("commit_push_deploy"),
        },
        "checks": plan_value,
        "qualification": qualification,
        "receipt_tip": manifest.get("receipt_tip"),
        "raw_project_content_serialized": False,
        "absolute_paths_serialized": False,
    }


def _project_map_markdown(
    authority_paths: tuple[str, ...],
    docs: tuple[str, ...],
    task_path: str | None,
    plan: CheckPlan,
) -> str:
    authorities = ", ".join(f"`{item}`" for item in authority_paths) or "owner declaration required"
    documentation = ", ".join(f"`{item}`" for item in docs) or "none detected"
    task = f"`{task_path}`" if task_path else "not configured"
    checks = ", ".join(f"`{family.family_id}` ({family.status})" for family in plan.families)
    return (
        "# SOS Project Map\n\n"
        "Generated view; it is not independent authority.\n\n"
        f"- Authority candidates: {authorities}\n"
        f"- Documentation: {documentation}\n"
        f"- Current work: {task}\n"
        f"- Qualification: {checks}\n"
        "- External actions: owner confirmation required\n"
    )


def _recovery_markdown(payload: dict[str, Any]) -> str:
    authority = payload["authority"]
    work = payload["current_work"]
    qualification = payload.get("qualification") or {"status": "not_run"}
    paths = ", ".join(f"`{item}`" for item in authority.get("paths", [])) or "owner declaration required"
    return (
        "# SOS Recovery\n\n"
        f"- Status: `{payload['status']}`\n"
        f"- Authority: {paths}\n"
        f"- Current work: `{work.get('path') or 'not configured'}`\n"
        f"- Qualification: `{qualification.get('status', 'not_run')}`\n"
        f"- Next action: {work.get('next_action', {}).get('description', 'owner decision required')}\n"
        "- External actions: owner confirmation required\n"
    )


def _failure(status: Status, reason: str, *, contract: str = "sos_init_result_v1") -> TerminalResult:
    return TerminalResult(contract=contract, status=status, reasons=(reason,), details={})


def _digest_json(value: object) -> str:
    return "sha256:" + hashlib.sha256(_json_bytes(value)).hexdigest()


def _json_bytes(value: object) -> bytes:
    payload = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    if len(payload) > _MAX_RECORD_BYTES:
        raise WorkspaceError("SOS_WORKSPACE_RECORD_LIMIT_EXCEEDED")
    return payload + b"\n"
