"""Read-only validation projection over repository inspection."""

from __future__ import annotations

from .repository import RepositoryError, inspect_repository
from .result import Status, TerminalResult


def validate_repository(path: str = ".") -> TerminalResult:
    try:
        inspection = inspect_repository(path)
    except RepositoryError as exc:
        return TerminalResult(
            contract="sos_validate_result_v1",
            status=Status.INVALID,
            reasons=(exc.reason,),
            details={},
        )
    if "SOS_CONTROL_PLANE_COLLISION" in inspection.reasons:
        status = Status.INVALID
    elif "SOS_STAGING_RECOVERY_REQUIRED" in inspection.reasons:
        status = Status.BLOCKED
    elif "SOS_REPOSITORY_UNBORN" in inspection.reasons:
        status = Status.NOT_VERIFIED
    elif inspection.control_plane_state == "present_unverified":
        from .workspace import workspace_status

        workspace = workspace_status(path)
        return TerminalResult(
            contract="sos_validate_result_v1",
            status=workspace.status,
            reasons=workspace.reasons,
            details={"workspace": workspace.details},
        )
    else:
        status = Status.SUCCESS
    return TerminalResult(
        contract="sos_validate_result_v1",
        status=status,
        reasons=inspection.reasons or ("SOS_OK",),
        details={"repository": inspection.to_dict()},
    )
