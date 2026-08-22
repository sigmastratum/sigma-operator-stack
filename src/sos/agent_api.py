"""Shared repository-bound decisions for the SOS CLI and read-only MCP."""

from __future__ import annotations

from typing import Any

from .client_integration import project_codex_package_update
from .qualification_contracts import QualificationContractError, canonical_digest
from .repository import RepositoryError
from .result import Status, TerminalResult
from .workspace import (
    WorkspaceError,
    doctor_workspace,
    prepare_qualification_plan,
    recover_workspace,
    workspace_status,
)


TOOL_NAMES = (
    "sos_status",
    "sos_preflight",
    "sos_active_task",
    "sos_next_action",
    "sos_qualification_plan",
    "sos_recover",
    "sos_propose_qualification_receipt",
    "sos_propose_update",
)


def project_tool(root: str, name: str, arguments: dict[str, Any] | None = None) -> TerminalResult:
    """Project one closed tool decision without accepting or executing work."""
    args = arguments or {}
    if name not in TOOL_NAMES:
        return _result("sos_agent_tool_result_v1", Status.INVALID, "SOS_AGENT_TOOL_UNKNOWN")
    if name == "sos_qualification_plan":
        if set(args) - {"family_id"}:
            return _result("sos_qualification_plan_projection_v1", Status.INVALID, "SOS_TOOL_ARGUMENTS_CLOSED")
        family_id = args.get("family_id")
        if family_id is not None and (not isinstance(family_id, str) or not 1 <= len(family_id) <= 128):
            return _result("sos_qualification_plan_projection_v1", Status.INVALID, "SOS_CHECK_FAMILY_INVALID")
        return qualification_plan(root, family_id)
    if args:
        return _result("sos_agent_tool_result_v1", Status.INVALID, "SOS_TOOL_ARGUMENTS_CLOSED")
    if name == "sos_status":
        return workspace_status(root)
    if name == "sos_preflight":
        recovery = recover_workspace(root)
        if recovery.status == Status.SUCCESS and not isinstance(recovery.details.get("qualification"), dict):
            details = dict(recovery.details)
            details["qualification_state"] = "not_verified"
            details["next_action"] = "sos qualify"
            return TerminalResult(
                "sos_preflight_result_v1",
                Status.NOT_VERIFIED,
                ("SOS_QUALIFICATION_NOT_RUN",),
                details,
            )
        checked = doctor_workspace(root)
        details = dict(checked.details)
        if checked.status == Status.NOT_VERIFIED:
            details["qualification_state"] = "not_verified"
            details["next_action"] = "sos qualify"
        return TerminalResult("sos_preflight_result_v1", checked.status, checked.reasons, details)
    if name == "sos_active_task":
        return active_task(root)
    if name == "sos_next_action":
        return next_action(root)
    if name == "sos_recover":
        return recover_workspace(root)
    if name == "sos_propose_qualification_receipt":
        return propose_qualification_receipt(root)
    return propose_update(root)


def active_task(root: str) -> TerminalResult:
    recovery = recover_workspace(root)
    work = recovery.details.get("current_work") if isinstance(recovery.details, dict) else None
    details = {
        "source_binding": recovery.details.get("source_binding") if isinstance(recovery.details, dict) else None,
        "task": {
            "path": work.get("path") if isinstance(work, dict) else None,
            "state": work.get("state") if isinstance(work, dict) else None,
        },
        "raw_project_content_serialized": False,
        "absolute_paths_serialized": False,
    }
    if recovery.status != Status.SUCCESS:
        return TerminalResult("sos_active_task_result_v1", recovery.status, recovery.reasons, details)
    if not isinstance(work, dict) or work.get("state") != "accepted_local_weak_evidence" or not work.get("path"):
        return _result(
            "sos_active_task_result_v1",
            Status.OWNER_REQUIRED,
            "SOS_CURRENT_WORK_NOT_CONFIGURED",
            details,
        )
    return _result("sos_active_task_result_v1", Status.SUCCESS, "SOS_ACTIVE_TASK_READY", details)


def next_action(root: str) -> TerminalResult:
    recovery = recover_workspace(root)
    work = recovery.details.get("current_work") if isinstance(recovery.details, dict) else None
    action = work.get("next_action") if isinstance(work, dict) else None
    details = {
        "source_binding": recovery.details.get("source_binding") if isinstance(recovery.details, dict) else None,
        "action": action if isinstance(action, dict) else None,
        "raw_project_content_serialized": False,
        "absolute_paths_serialized": False,
    }
    if recovery.status != Status.SUCCESS:
        return TerminalResult("sos_next_action_result_v1", recovery.status, recovery.reasons, details)
    if not isinstance(action, dict):
        return _result(
            "sos_next_action_result_v1", Status.OWNER_REQUIRED, "SOS_NEXT_ACTION_NOT_CONFIGURED", details
        )
    return _result("sos_next_action_result_v1", Status.SUCCESS, "SOS_NEXT_ACTION_READY", details)


def qualification_plan(root: str, family_id: str | None = None) -> TerminalResult:
    try:
        plan = prepare_qualification_plan(root, family_id)
    except (RepositoryError, WorkspaceError, QualificationContractError) as exc:
        reason = exc.reason if hasattr(exc, "reason") else str(exc)
        status = Status.STALE if reason in {"SOS_QUALIFICATION_STALE", "SOS_QUALIFICATION_PLAN_STALE"} else Status.INVALID
        if reason in {"SOS_WORKSPACE_NOT_CURRENT", "SOS_CHECK_FAMILY_NOT_EXECUTABLE"}:
            status = Status.NOT_VERIFIED
        return _result("sos_qualification_plan_projection_v1", status, reason)
    return _result(
        "sos_qualification_plan_projection_v1",
        Status.SUCCESS,
        "SOS_QUALIFICATION_PLAN_READY",
        {
            "plan": plan,
            "execution_performed": False,
            "confirmation_granted": False,
            "raw_project_content_serialized": False,
            "absolute_paths_serialized": False,
        },
    )


def propose_qualification_receipt(root: str) -> TerminalResult:
    recovery = recover_workspace(root)
    details: dict[str, Any] = {
        "proposal_state": "not_configured",
        "proposal_only": True,
        "writes_performed": False,
        "raw_project_content_serialized": False,
        "absolute_paths_serialized": False,
    }
    if recovery.status != Status.SUCCESS:
        return TerminalResult(
            "sos_qualification_receipt_proposal_v1", recovery.status, recovery.reasons, details
        )
    receipt = recovery.details.get("qualification")
    if not isinstance(receipt, dict):
        return _result(
            "sos_qualification_receipt_proposal_v1",
            Status.NOT_VERIFIED,
            "SOS_QUALIFICATION_NOT_RUN",
            details,
        )
    source = recovery.details.get("source_binding", {})
    if (
        receipt.get("source_tree_digest") != source.get("tree_digest")
        or receipt.get("source_status_digest") != source.get("status_digest")
    ):
        details["proposal_state"] = "stale"
        return _result(
            "sos_qualification_receipt_proposal_v1", Status.STALE, "SOS_QUALIFICATION_STALE", details
        )
    if receipt.get("status") != "passed_local":
        details["proposal_state"] = "not_verified"
        return _result(
            "sos_qualification_receipt_proposal_v1",
            Status.NOT_VERIFIED,
            "SOS_QUALIFICATION_NOT_PASSED",
            details,
        )
    proposal = {
        "receipt_digest": receipt.get("receipt_digest"),
        "plan_digest": receipt.get("plan_digest"),
        "family_id": receipt.get("family_id"),
        "source_tree_digest": receipt.get("source_tree_digest"),
        "source_status_digest": receipt.get("source_status_digest"),
        "status": receipt.get("status"),
    }
    details.update(
        {
            "proposal_state": "ready",
            "proposal": proposal,
            "proposal_digest": canonical_digest(
                {"contract": "sos_qualification_receipt_proposal_v1", **proposal}
            ),
        }
    )
    return _result(
        "sos_qualification_receipt_proposal_v1",
        Status.SUCCESS,
        "SOS_QUALIFICATION_RECEIPT_PROPOSAL_READY",
        details,
    )


def propose_update(root: str) -> TerminalResult:
    current = workspace_status(root)
    details = {
        "configuration_state": "not_configured",
        "proposal_only": True,
        "writes_performed": False,
        "network_performed": False,
        "raw_project_content_serialized": False,
        "absolute_paths_serialized": False,
    }
    if current.status != Status.SUCCESS:
        return TerminalResult("sos_update_proposal_v1", current.status, current.reasons, details)
    projected = project_codex_package_update(root)
    merged = {**details, **projected.details}
    return TerminalResult("sos_update_proposal_v1", projected.status, projected.reasons, merged)


def _result(
    contract: str,
    status: Status,
    reason: str,
    details: dict[str, Any] | None = None,
) -> TerminalResult:
    return TerminalResult(contract, status, (reason,), details or {})
