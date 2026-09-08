"""Successor-only inventory and shared package lifetime decisions."""

from __future__ import annotations

from .claude_integration import (
    claude_setup_status,
    project_claude_package_update,
)
from .client_integration import (
    LauncherBinding,
    codex_setup_status,
    observe_installed_launcher,
    project_codex_package_update,
)
from .atomic_switch import execute_atomic_switch, prepare_atomic_switch
from .result import Status, TerminalResult
from .platform_services import PlatformServiceError, current_platform_services
from .repository import RepositoryError, discover_repository_root


_KNOWN_INTEGRATION_FILES = frozenset(
    {"codex-mcp.json", "codex-first.json", "claude-code.json", "atomic-switches"}
)


def _unknown_integration_files(path: str) -> list[str]:
    root = discover_repository_root(path)
    service = current_platform_services()
    with service.open_repository(root) as repository:
        observed = service.observe_object(repository, ".sigma/integrations")
        if observed.kind == "absent":
            return []
        if observed.kind != "directory":
            raise PlatformServiceError("invalid_integrations_directory")
        listing = service.enumerate_directory_bounded(
            repository, ".sigma/integrations", 64
        )
    return sorted(
        entry.name
        for entry in listing.entries
        if entry.name not in _KNOWN_INTEGRATION_FILES
    )


def integration_inventory(path: str = ".") -> TerminalResult:
    try:
        unknown = _unknown_integration_files(path)
    except (RepositoryError, PlatformServiceError):
        return TerminalResult(
            "sos_integration_inventory_v1",
            Status.INVALID,
            ("SOS_INTEGRATION_INVENTORY_INVALID",),
            {"raw_content_serialized": False, "absolute_paths_serialized": False},
        )
    codex = codex_setup_status(path)
    claude = claude_setup_status(path)
    details = {
        "clients": {
            "codex": {"status": codex.status.value, "reasons": list(codex.reasons)},
            "claude-code": {"status": claude.status.value, "reasons": list(claude.reasons)},
        },
        "global_project_inventory_available": False,
        "package_remove_allowed": False,
        "version_change_allowed": False,
        "unknown_integration_files": unknown,
        "raw_content_serialized": False,
        "absolute_paths_serialized": False,
    }
    return TerminalResult(
        "sos_integration_inventory_v1",
        Status.BLOCKED if unknown else Status.SUCCESS,
        (
            "SOS_INTEGRATION_INVENTORY_UNKNOWN_CLIENT"
            if unknown
            else "SOS_INTEGRATION_INVENTORY_READY"
        ,),
        details,
    )


def refuse_shared_package_mutation() -> TerminalResult:
    return TerminalResult(
        "sos_shared_environment_decision_v1",
        Status.BLOCKED,
        ("SOS_SHARED_ENVIRONMENT_INVENTORY_REQUIRED",),
        {"package_manager_calls": 0, "global_project_inventory_available": False},
    )


def project_package_update(path: str = ".", *, launcher=None) -> TerminalResult:
    try:
        unknown = _unknown_integration_files(path)
    except (RepositoryError, PlatformServiceError):
        return TerminalResult(
            "sos_multi_client_package_update_projection_v1",
            Status.INVALID,
            ("SOS_INTEGRATION_INVENTORY_INVALID",),
            {"proposal_only": True, "writes_performed": False},
        )
    if unknown:
        return TerminalResult(
            "sos_multi_client_package_update_projection_v1",
            Status.BLOCKED,
            ("SOS_INTEGRATION_INVENTORY_UNKNOWN_CLIENT",),
            {
                "unknown_integration_files": unknown,
                "proposal_only": True,
                "writes_performed": False,
                "network_performed": False,
                "raw_project_content_serialized": False,
                "absolute_paths_serialized": False,
            },
        )
    projections = {
        "codex": project_codex_package_update(path, launcher=launcher),
        "claude-code": project_claude_package_update(path, launcher=launcher),
    }
    configured = {
        client: result
        for client, result in projections.items()
        if "SOS_UPDATE_NOT_CONFIGURED" not in result.reasons
    }
    details = {
        "client_bindings": {
            client: {
                "status": result.status.value,
                "reasons": list(result.reasons),
                **result.details,
            }
            for client, result in projections.items()
        },
        "global_project_inventory_available": False,
        "package_remove_allowed": False,
        "version_change_allowed": False,
        "proposal_only": True,
        "writes_performed": False,
        "network_performed": False,
        "raw_project_content_serialized": False,
        "absolute_paths_serialized": False,
    }
    if not configured:
        details["configuration_state"] = "not_configured"
        return TerminalResult(
            "sos_multi_client_package_update_projection_v1",
            Status.NOT_VERIFIED,
            ("SOS_UPDATE_NOT_CONFIGURED",),
            details,
        )
    failed = {
        client: result
        for client, result in configured.items()
        if result.status != Status.SUCCESS
    }
    if failed:
        details["configuration_state"] = "blocked"
        details["failed_clients"] = sorted(failed)
        first = failed[sorted(failed)[0]]
        return TerminalResult(
            "sos_multi_client_package_update_projection_v1",
            first.status,
            first.reasons,
            details,
        )
    changed = any(
        result.details.get("configuration_state") == "update_available"
        for result in configured.values()
    )
    representative = configured.get("codex") or configured["claude-code"]
    details.update(representative.details)
    details["client_bindings"] = {
        client: {
            "status": result.status.value,
            "reasons": list(result.reasons),
            **result.details,
        }
        for client, result in projections.items()
    }
    details["configuration_state"] = "update_available" if changed else "current"
    details["setup_update_command"] = "sos setup update-all PATH" if changed else None
    details["tool_environment_inventory"] = "not_available"
    details["other_projects_fail_closed_on_next_open"] = changed
    details["predecessor_artifact_retention_required"] = changed
    return TerminalResult(
        "sos_multi_client_package_update_projection_v1",
        Status.SUCCESS,
        ("SOS_UPDATE_AVAILABLE" if changed else "SOS_UPDATE_NOT_REQUIRED",),
        details,
    )


def update_all_setups(
    path: str = ".",
    *,
    confirmed: bool,
    controlling_tty_observed: bool = False,
    predecessor_launcher: LauncherBinding | None = None,
    successor_launcher: LauncherBinding | None = None,
    fault=None,
) -> TerminalResult:
    inventory = integration_inventory(path)
    if inventory.status != Status.SUCCESS:
        return TerminalResult(
            "sos_multi_client_update_v1",
            inventory.status,
            inventory.reasons,
            {**inventory.details, "package_manager_calls": 0},
        )
    predecessor = predecessor_launcher or observe_installed_launcher()
    successor = successor_launcher or predecessor
    try:
        plan = prepare_atomic_switch(
            path, predecessor=predecessor, successor=successor
        )
    except Exception as exc:
        return TerminalResult(
            "sos_atomic_adapter_switch_result_v1",
            getattr(exc, "status", Status.INVALID),
            (getattr(exc, "reason", "SOS_ATOMIC_ADAPTER_SWITCH_INVALID"),),
            {"package_manager_calls": 0},
        )
    return execute_atomic_switch(
        plan,
        confirmed=confirmed,
        controlling_tty_observed=controlling_tty_observed,
        fault=fault,
    )
