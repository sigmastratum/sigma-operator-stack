"""Atomic multi-client launcher switching without package acquisition."""

from __future__ import annotations

import json
import os
import re
import secrets
from collections.abc import Callable
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .claude_integration import (
    claude_setup_status,
    install_claude_setup,
    recover_claude_setup,
    remove_claude_setup,
)
from .client_integration import (
    LauncherBinding,
    codex_setup_status,
    install_codex_setup,
    publish_integration_control_file,
    read_integration_control_file,
    recover_codex_setup,
    update_codex_setup,
    restoring_target_modes,
)
from .contracts import digest_value
from .integration_inventory import unknown_integration_files
from .repository import RepositoryError, discover_repository_root
from .result import Status, TerminalResult
from .platform_services import PlatformServiceError, current_platform_services
from .workspace import workspace_status


_PLAN_CONTRACT = "sos_atomic_adapter_switch_plan_v1"
_EVENT_CONTRACT = "sos_atomic_adapter_switch_event_v1"
_RESULT_CONTRACT = "sos_atomic_adapter_switch_result_v1"
_CLIENTS = ("codex", "claude-code")
_MAX_EVENTS = 64
_SWITCH_ID = re.compile(r"^p107-atomic-[0-9a-f]{32}$")
_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_NONCE = re.compile(r"^[0-9a-f]{32}$")


class AtomicSwitchError(RuntimeError):
    def __init__(self, reason: str, status: Status = Status.BLOCKED) -> None:
        super().__init__(reason)
        self.reason = reason
        self.status = status


@dataclass(frozen=True, slots=True)
class AtomicSwitchPlan:
    root: Path
    predecessor: LauncherBinding
    successor: LauncherBinding
    payload: dict[str, Any]

    @property
    def switch_id(self) -> str:
        return self.payload["switch_id"]

    @property
    def plan_digest(self) -> str:
        return self.payload["plan_digest"]

    @property
    def clients(self) -> tuple[str, ...]:
        return tuple(self.payload["clients"])

    def preview(self) -> TerminalResult:
        return TerminalResult(
            _RESULT_CONTRACT,
            Status.OWNER_REQUIRED,
            ("SOS_ATOMIC_ADAPTER_SWITCH_CONFIRMATION_REQUIRED",),
            {
                "switch_id": self.switch_id,
                "plan_digest": self.plan_digest,
                "clients": list(self.clients),
                "client_count": len(self.clients),
                "predecessor_launcher": _binding_projection(self.predecessor),
                "successor_launcher": _binding_projection(self.successor),
                "one_confirmation": True,
                "shared_switch_journal": True,
                "rollback_order": list(reversed(self.clients)),
                "package_manager_calls": 0,
                "writes_performed": False,
                "raw_project_content_serialized": False,
                "absolute_paths_serialized": False,
            },
        )


def prepare_atomic_switch(
    path: str,
    *,
    predecessor: LauncherBinding,
    successor: LauncherBinding,
    switch_nonce: str | None = None,
) -> AtomicSwitchPlan:
    root = discover_repository_root(path)
    try:
        _require_terminal_switches(root)
    except PlatformServiceError as exc:
        raise AtomicSwitchError("SOS_ATOMIC_ADAPTER_SWITCH_INVENTORY_INVALID", Status.INVALID) from exc
    current = workspace_status(os.fspath(root))
    repository_id = current.details.get("repository_id")
    if current.status in {Status.INVALID, Status.BLOCKED, Status.UNSUPPORTED}:
        raise AtomicSwitchError(
            current.reasons[0] if current.reasons else "SOS_WORKSPACE_NOT_READY",
            current.status,
        )
    if not isinstance(repository_id, str):
        raise AtomicSwitchError("SOS_WORKSPACE_NOT_READY", Status.NOT_VERIFIED)
    clients = _configured_clients(root, predecessor)
    if not clients:
        raise AtomicSwitchError(
            "SOS_ATOMIC_ADAPTER_SWITCH_NOT_CONFIGURED", Status.NOT_VERIFIED
        )
    nonce = switch_nonce or secrets.token_hex(16)
    if _NONCE.fullmatch(nonce) is None:
        raise AtomicSwitchError("SOS_ATOMIC_ADAPTER_SWITCH_NONCE_INVALID", Status.INVALID)
    material = {
        "contract": _PLAN_CONTRACT,
        "repository_id": repository_id,
        "clients": list(clients),
        "predecessor_launcher": _binding_projection(predecessor),
        "successor_launcher": _binding_projection(successor),
        "switch_nonce": nonce,
        "package_manager_calls": 0,
        "raw_project_content_serialized": False,
        "absolute_paths_serialized": False,
    }
    material_digest = digest_value(material)
    payload = {
        **material,
        "switch_id": "p107-atomic-" + material_digest.removeprefix("sha256:")[:32],
        "plan_digest": "sha256:" + "0" * 64,
    }
    payload["plan_digest"] = _sealed_digest(payload, "plan_digest")
    _validate_plan(payload)
    return AtomicSwitchPlan(root, predecessor, successor, payload)


def execute_atomic_switch(
    plan: AtomicSwitchPlan,
    *,
    confirmed: bool,
    controlling_tty_observed: bool,
    fault: Callable[[str], None] | None = None,
    admission_check: Callable[[], None] | None = None,
    target_check: Callable[[], None] | None = None,
    rollback_check: Callable[[], None] | None = None,
    rollback_targets: tuple | list = (),
) -> TerminalResult:
    # Preview and an unattended refusal are strictly read-only.  In particular,
    # do not create the coordinator lock until mutation has been authorized.
    if not confirmed:
        return plan.preview()
    if not controlling_tty_observed:
        return _result(
            Status.OWNER_REQUIRED,
            "SOS_ATOMIC_ADAPTER_SWITCH_TTY_REQUIRED",
            plan,
        )
    try:
        # Reject an already stale preview before creating even the coordinator
        # directory/lock. Recheck under the lock as well to close the admission race.
        observed = prepare_atomic_switch(
            os.fspath(plan.root), predecessor=plan.predecessor,
            successor=plan.successor, switch_nonce=plan.payload["switch_nonce"],
        )
        if observed.payload != plan.payload:
            raise AtomicSwitchError("SOS_ATOMIC_ADAPTER_SWITCH_PREVIEW_STALE", Status.STALE)
        with _switch_lock(plan.root):
            return _execute_atomic_switch_locked(
                plan,
                confirmed=confirmed,
                controlling_tty_observed=controlling_tty_observed,
                fault=fault,
                admission_check=admission_check,
                target_check=target_check,
                rollback_check=rollback_check,
                rollback_targets=rollback_targets,
            )
    except (AtomicSwitchError, RepositoryError) as exc:
        return _result(getattr(exc, "status", Status.INVALID), exc.reason, plan, recovery_required=False)
    except PlatformServiceError:
        return _result(
            Status.BLOCKED,
            "SOS_ATOMIC_ADAPTER_SWITCH_LOCK_FAILED",
            plan,
            recovery_required=True,
        )


def _execute_atomic_switch_locked(
    plan: AtomicSwitchPlan,
    *,
    confirmed: bool,
    controlling_tty_observed: bool,
    fault: Callable[[str], None] | None = None,
    admission_check: Callable[[], None] | None = None,
    target_check: Callable[[], None] | None = None,
    rollback_check: Callable[[], None] | None = None,
    rollback_targets: tuple | list = (),
) -> TerminalResult:
    if not confirmed:
        return plan.preview()
    if not controlling_tty_observed:
        return _result(
            Status.OWNER_REQUIRED,
            "SOS_ATOMIC_ADAPTER_SWITCH_TTY_REQUIRED",
            plan,
        )
    journal_started = False
    try:
        revalidated = prepare_atomic_switch(
            os.fspath(plan.root),
            predecessor=plan.predecessor,
            successor=plan.successor,
            switch_nonce=plan.payload["switch_nonce"],
        )
        if revalidated.payload != plan.payload:
            raise AtomicSwitchError(
                "SOS_ATOMIC_ADAPTER_SWITCH_PREVIEW_STALE", Status.STALE
            )
        if _read_plan(plan.root, plan.switch_id) is not None:
            raise AtomicSwitchError("SOS_ATOMIC_ADAPTER_SWITCH_RECOVERY_REQUIRED")
        if admission_check is not None:
            admission_check()
        if plan.predecessor == plan.successor:
            # No adapter bytes change for an identical verified launcher. Do not
            # create a mutation journal that could strand a no-op on interruption.
            if target_check is not None:
                target_check()
            return _result(Status.SUCCESS, "SOS_ATOMIC_ADAPTER_SWITCH_ALREADY_CURRENT",
                           plan, recovery_required=False)
        _write_plan(plan)
        journal_started = True
        _append_event(plan, "prepared")
        for client in plan.clients:
            _append_event(plan, "client_started", client)
            _call_fault(fault, f"before_client:{client}")
            if plan.predecessor.digest != plan.successor.digest:
                _switch_client(
                    plan.root,
                    client,
                    source=plan.predecessor,
                    target=plan.successor,
                    fault=fault,
                    allow_source_stale=target_check is not None,
                )
            _call_fault(fault, f"after_client:{client}")
            _append_event(plan, "client_applied", client)
        _call_fault(fault, "before_commit")
        # Progress is not a terminal receipt and does not change journal state.
        from .result import report_progress
        report_progress("verifying_clients")
        if _configured_clients(plan.root, plan.successor) != plan.clients:
            raise AtomicSwitchError("SOS_ATOMIC_ADAPTER_SWITCH_TARGET_DRIFT", Status.STALE)
        if target_check is not None:
            target_check()
        _append_event(plan, "committed")
        report_progress("adapter_committed")
        return _result(
            Status.SUCCESS,
            "SOS_ATOMIC_ADAPTER_SWITCH_COMMITTED",
            plan,
            recovery_required=False,
        )
    except Exception as exc:
        if not journal_started:
            return _result(
                getattr(exc, "status", Status.BLOCKED),
                getattr(exc, "reason", "SOS_ATOMIC_ADAPTER_SWITCH_FAILED"),
                plan,
                recovery_required=False,
            )
        try:
            _rollback_switch(plan, fault=fault, rollback_check=rollback_check, rollback_targets=rollback_targets)
        except Exception as rollback_exc:
            return _result(
                Status.BLOCKED,
                "SOS_ATOMIC_ADAPTER_SWITCH_RECOVERY_REQUIRED",
                plan,
                recovery_required=True,
                failure_reason=getattr(
                    exc, "reason", "SOS_ATOMIC_ADAPTER_SWITCH_EXECUTION_FAILED"
                ),
                rollback_failure_reason=getattr(
                    rollback_exc,
                    "reason",
                    "SOS_ATOMIC_ADAPTER_SWITCH_ROLLBACK_FAILED",
                ),
            )
        reason = getattr(exc, "reason", "SOS_ATOMIC_ADAPTER_SWITCH_FAILED_ROLLED_BACK")
        status = getattr(exc, "status", Status.BLOCKED)
        return _result(
            status,
            reason,
            plan,
            recovery_required=False,
            rolled_back=True,
        )


def recover_atomic_switch(
    path: str,
    switch_id: str,
    *,
    predecessor: LauncherBinding,
    successor: LauncherBinding,
    rollback_check: Callable[[], None] | None = None,
    rollback_targets: tuple | list = (),
) -> TerminalResult:
    try:
        root = discover_repository_root(path)
        with _switch_lock(root):
            return _recover_atomic_switch_locked(
                path,
                switch_id,
                predecessor=predecessor,
                successor=successor,
                rollback_check=rollback_check,
                rollback_targets=rollback_targets,
            )
    except (RepositoryError, PlatformServiceError):
        return TerminalResult(
            _RESULT_CONTRACT,
            Status.BLOCKED,
            ("SOS_ATOMIC_ADAPTER_SWITCH_LOCK_FAILED",),
            {"switch_id": switch_id, "package_manager_calls": 0},
        )


def _recover_atomic_switch_locked(
    path: str,
    switch_id: str,
    *,
    predecessor: LauncherBinding,
    successor: LauncherBinding,
    rollback_check: Callable[[], None] | None = None,
    rollback_targets: tuple | list = (),
) -> TerminalResult:
    try:
        root = discover_repository_root(path)
        if _SWITCH_ID.fullmatch(switch_id) is None:
            raise AtomicSwitchError("SOS_ATOMIC_ADAPTER_SWITCH_ID_INVALID", Status.INVALID)
        payload = _read_plan(root, switch_id)
        if payload is None:
            raise AtomicSwitchError(
                "SOS_ATOMIC_ADAPTER_SWITCH_NOT_FOUND", Status.NOT_VERIFIED
            )
        _validate_plan(payload)
        plan = AtomicSwitchPlan(root, predecessor, successor, payload)
        _verify_bindings(plan)
        events = _read_events(root, switch_id, plan.plan_digest, plan.clients)
        if not events:
            # Plan publication may precede a process crash before the first
            # event. Only unchanged, fully bound predecessors can reconcile it.
            if _configured_clients(root, predecessor) != plan.clients:
                raise AtomicSwitchError("SOS_ATOMIC_ADAPTER_SWITCH_TARGET_DRIFT", Status.STALE)
            _append_event(plan, "prepared")
            events = _read_events(root, switch_id, plan.plan_digest, plan.clients)
        if events[-1]["state"] == "committed":
            for client in plan.clients:
                if not _is_bound(root, client, successor):
                    raise AtomicSwitchError(
                        "SOS_ATOMIC_ADAPTER_SWITCH_TARGET_DRIFT", Status.STALE
                    )
            return _result(
                Status.SUCCESS,
                "SOS_ATOMIC_ADAPTER_SWITCH_ALREADY_COMMITTED",
                plan,
                recovery_required=False,
            )
        if events[-1]["state"] == "rolled_back":
            for client in plan.clients:
                if not _is_bound(root, client, predecessor):
                    raise AtomicSwitchError(
                        "SOS_ATOMIC_ADAPTER_SWITCH_TARGET_DRIFT", Status.STALE
                    )
            if rollback_check is not None:
                rollback_check()
            return _result(
                Status.SUCCESS,
                "SOS_ATOMIC_ADAPTER_SWITCH_ALREADY_ROLLED_BACK",
                plan,
                recovery_required=False,
                rolled_back=True,
            )
        _rollback_switch(plan, rollback_check=rollback_check, rollback_targets=rollback_targets)
        return _result(
            Status.SUCCESS,
            "SOS_ATOMIC_ADAPTER_SWITCH_ROLLBACK_RECOVERED",
            plan,
            recovery_required=False,
            rolled_back=True,
        )
    except (AtomicSwitchError, RepositoryError, OSError, ValueError, TypeError) as exc:
        return TerminalResult(
            _RESULT_CONTRACT,
            getattr(exc, "status", Status.INVALID),
            (getattr(exc, "reason", "SOS_ATOMIC_ADAPTER_SWITCH_INVALID"),),
            {"switch_id": switch_id, "package_manager_calls": 0},
        )


def _require_terminal_switches(root: Path) -> None:
    service = current_platform_services()
    relative = ".sigma/integrations/atomic-switches"
    with service.open_repository(root) as repository:
        if service.observe_object(repository, relative).kind == "absent":
            return
        listing = service.enumerate_directory_bounded(repository, relative, 64)
    for entry in listing.entries:
        if entry.name == "coordinator.lock" and entry.kind == "regular":
            continue
        if entry.kind != "directory":
            raise AtomicSwitchError("SOS_ATOMIC_ADAPTER_SWITCH_JOURNAL_INVALID")
        plan = _read_plan(root, entry.name)
        if plan is None:
            raise AtomicSwitchError("SOS_ATOMIC_ADAPTER_SWITCH_RECOVERY_REQUIRED")
        events = _read_events(root, entry.name, plan["plan_digest"], tuple(plan["clients"]))
        if not events or events[-1]["state"] not in {"committed", "rolled_back"}:
            raise AtomicSwitchError("SOS_ATOMIC_ADAPTER_SWITCH_RECOVERY_REQUIRED")


def _configured_clients(root: Path, binding: LauncherBinding) -> tuple[str, ...]:
    try:
        unknown = unknown_integration_files(os.fspath(root))
    except (RepositoryError, PlatformServiceError):
        raise AtomicSwitchError("SOS_INTEGRATION_INVENTORY_INVALID", Status.INVALID) from None
    if unknown:
        raise AtomicSwitchError("SOS_INTEGRATION_INVENTORY_UNKNOWN_CLIENT")
    clients: list[str] = []
    codex = codex_setup_status(os.fspath(root), launcher=binding)
    if "SOS_CODEX_SETUP_NOT_INSTALLED" not in codex.reasons:
        if codex.status != Status.SUCCESS:
            raise AtomicSwitchError(codex.reasons[0], codex.status)
        clients.append("codex")
    claude = claude_setup_status(os.fspath(root), launcher=binding)
    if "SOS_CLAUDE_CODE_SETUP_NOT_INSTALLED" not in claude.reasons:
        if claude.status != Status.OWNER_REQUIRED or "SOS_INTERACTIVE_USER_HANDOFF_REQUIRED" not in claude.reasons:
            raise AtomicSwitchError(claude.reasons[0], claude.status)
        clients.append("claude-code")
    return tuple(clients)


def _switch_client(
    root: Path,
    client: str,
    *,
    source: LauncherBinding,
    target: LauncherBinding,
    fault: Callable[[str], None] | None = None,
    allow_source_stale: bool = False,
) -> None:
    if client == "codex":
        result = update_codex_setup(
            os.fspath(root),
            confirmed=True,
            controlling_tty_observed=True,
            launcher=target,
            allow_source_stale=allow_source_stale,
        )
        if result.status != Status.SUCCESS:
            raise AtomicSwitchError(result.reasons[0], result.status)
        return
    removed = remove_claude_setup(
        os.fspath(root),
        confirmed=True,
        controlling_tty_observed=True,
        launcher=source,
    )
    if removed.status != Status.SUCCESS:
        raise AtomicSwitchError(removed.reasons[0], removed.status)
    _call_fault(fault, "after_remove:claude-code")
    installed = install_claude_setup(
        os.fspath(root),
        confirmed=True,
        controlling_tty_observed=True,
        launcher=target,
    )
    if installed.status != Status.OWNER_REQUIRED or "SOS_INTERACTIVE_USER_HANDOFF_REQUIRED" not in installed.reasons:
        raise AtomicSwitchError(installed.reasons[0], installed.status)


def _rollback_switch(
    plan: AtomicSwitchPlan,
    *,
    fault: Callable[[str], None] | None = None,
    rollback_check: Callable[[], None] | None = None,
    rollback_targets: tuple | list = (),
) -> None:
    events = _read_events(plan.root, plan.switch_id, plan.plan_digest, plan.clients)
    if events and events[-1]["state"] == "rolled_back":
        if rollback_check is not None:
            rollback_check()
        return
    rollback_events = [event for event in events if event["state"] == "client_rolled_back"]
    completed = [event["client"] for event in rollback_events]
    rollback_order = list(reversed(plan.clients))
    if completed != rollback_order[: len(completed)]:
        raise AtomicSwitchError(
            "SOS_ATOMIC_ADAPTER_SWITCH_JOURNAL_INVALID", Status.INVALID
        )
    if not any(event["state"] == "rollback_started" for event in events):
        _append_event(plan, "rollback_started")
    for client in rollback_order[len(completed) :]:
        with restoring_target_modes(plan.root, rollback_targets):
            _ensure_binding(
                plan.root,
                client,
                desired=plan.predecessor,
                alternative=plan.successor,
            )
        _call_fault(fault, f"after_rollback_client:{client}")
        _append_event(plan, "client_rolled_back", client)
    if rollback_check is not None:
        rollback_check()
    if _configured_clients(plan.root, plan.predecessor) != plan.clients:
        raise AtomicSwitchError("SOS_ATOMIC_ADAPTER_SWITCH_TARGET_DRIFT", Status.STALE)
    _append_event(plan, "rolled_back")


def _ensure_binding(
    root: Path,
    client: str,
    *,
    desired: LauncherBinding,
    alternative: LauncherBinding,
) -> None:
    if _is_bound(root, client, desired):
        return
    if client == "codex":
        recovered = recover_codex_setup(os.fspath(root), launcher=alternative)
        if recovered.status == Status.SUCCESS and _is_bound(root, client, desired):
            return
        status = codex_setup_status(os.fspath(root), launcher=alternative)
        if "SOS_CODEX_SETUP_NOT_INSTALLED" in status.reasons:
            installed = install_codex_setup(
                os.fspath(root),
                confirmed=True,
                controlling_tty_observed=True,
                launcher=desired,
                require_current=False,
            )
            if installed.status == Status.SUCCESS:
                return
        updated = update_codex_setup(
            os.fspath(root),
            confirmed=True,
            controlling_tty_observed=True,
            launcher=desired,
        )
        if updated.status == Status.SUCCESS and _is_bound(root, client, desired):
            return
        raise AtomicSwitchError("SOS_ATOMIC_ADAPTER_SWITCH_ROLLBACK_FAILED")
    recovered = recover_claude_setup(os.fspath(root), launcher=alternative)
    if recovered.status in {Status.SUCCESS, Status.OWNER_REQUIRED} and _is_bound(root, client, desired):
        return
    alternative_status = claude_setup_status(os.fspath(root), launcher=alternative)
    if alternative_status.status == Status.OWNER_REQUIRED:
        removed = remove_claude_setup(
            os.fspath(root),
            confirmed=True,
            controlling_tty_observed=True,
            launcher=alternative,
        )
        if removed.status != Status.SUCCESS:
            raise AtomicSwitchError("SOS_ATOMIC_ADAPTER_SWITCH_ROLLBACK_FAILED")
    installed = install_claude_setup(
        os.fspath(root),
        confirmed=True,
        controlling_tty_observed=True,
        launcher=desired,
    )
    if installed.status != Status.OWNER_REQUIRED or not _is_bound(root, client, desired):
        raise AtomicSwitchError("SOS_ATOMIC_ADAPTER_SWITCH_ROLLBACK_FAILED")


def _is_bound(root: Path, client: str, binding: LauncherBinding) -> bool:
    result = (
        codex_setup_status(os.fspath(root), launcher=binding)
        if client == "codex"
        else claude_setup_status(os.fspath(root), launcher=binding)
    )
    if client == "codex":
        return result.status == Status.SUCCESS and "SOS_CODEX_SETUP_INSTALLED" in result.reasons
    return result.status == Status.OWNER_REQUIRED and "SOS_INTERACTIVE_USER_HANDOFF_REQUIRED" in result.reasons


def _binding_projection(binding: LauncherBinding) -> dict[str, str]:
    return {
        "package_version": binding.package_version,
        "executable_sha256": binding.executable_sha256,
        "binding_digest": binding.digest,
    }


def _verify_bindings(plan: AtomicSwitchPlan) -> None:
    if plan.payload["predecessor_launcher"] != _binding_projection(plan.predecessor):
        raise AtomicSwitchError("SOS_ATOMIC_ADAPTER_SWITCH_BINDING_MISMATCH", Status.STALE)
    if plan.payload["successor_launcher"] != _binding_projection(plan.successor):
        raise AtomicSwitchError("SOS_ATOMIC_ADAPTER_SWITCH_BINDING_MISMATCH", Status.STALE)


def _plan_path(switch_id: str) -> str:
    return f"integrations/atomic-switches/{switch_id}/plan.json"


def _event_path(switch_id: str, ordinal: int) -> str:
    return f"integrations/atomic-switches/{switch_id}/{ordinal:08d}.json"


def _write_plan(plan: AtomicSwitchPlan) -> None:
    publish_integration_control_file(
        plan.root,
        _plan_path(plan.switch_id),
        _json_bytes(plan.payload),
    )


def _read_plan(root: Path, switch_id: str) -> dict[str, Any] | None:
    payload = read_integration_control_file(root, _plan_path(switch_id))
    if payload is None:
        return None
    value = _parse_json(payload)
    _validate_plan(value)
    return value


def _append_event(plan: AtomicSwitchPlan, state: str, client: str | None = None) -> None:
    events = _read_events(plan.root, plan.switch_id, plan.plan_digest, plan.clients)
    ordinal = len(events) + 1
    if ordinal > _MAX_EVENTS:
        raise AtomicSwitchError("SOS_ATOMIC_ADAPTER_SWITCH_JOURNAL_LIMIT_EXCEEDED", Status.UNSUPPORTED)
    event = {
        "contract": _EVENT_CONTRACT,
        "switch_id": plan.switch_id,
        "plan_digest": plan.plan_digest,
        "sequence_ordinal": ordinal,
        "state": state,
        "client": client,
        "predecessor_event_digest": events[-1]["event_digest"] if events else None,
        "package_manager_calls": 0,
        "raw_project_content_serialized": False,
        "absolute_paths_serialized": False,
        "event_digest": "sha256:" + "0" * 64,
    }
    event["event_digest"] = _sealed_digest(event, "event_digest")
    _validate_event(event, expected_ordinal=ordinal, predecessor=events[-1] if events else None)
    publish_integration_control_file(
        plan.root,
        _event_path(plan.switch_id, ordinal),
        _json_bytes(event),
    )


def _read_events(
    root: Path,
    switch_id: str,
    plan_digest: str,
    clients: tuple[str, ...] | None = None,
) -> list[dict[str, Any]]:
    events: list[dict[str, Any]] = []
    gap_observed = False
    for ordinal in range(1, _MAX_EVENTS + 1):
        payload = read_integration_control_file(root, _event_path(switch_id, ordinal))
        if payload is None:
            gap_observed = True
            continue
        if gap_observed:
            raise AtomicSwitchError(
                "SOS_ATOMIC_ADAPTER_SWITCH_JOURNAL_INVALID", Status.INVALID
            )
        event = _parse_json(payload)
        if (
            event.get("switch_id") != switch_id
            or event.get("plan_digest") != plan_digest
        ):
            raise AtomicSwitchError("SOS_ATOMIC_ADAPTER_SWITCH_JOURNAL_INVALID")
        _validate_event(
            event,
            expected_ordinal=ordinal,
            predecessor=events[-1] if events else None,
        )
        events.append(event)
    if len(events) == _MAX_EVENTS and read_integration_control_file(
        root, _event_path(switch_id, _MAX_EVENTS + 1)
    ) is not None:
        raise AtomicSwitchError("SOS_ATOMIC_ADAPTER_SWITCH_JOURNAL_LIMIT_EXCEEDED", Status.UNSUPPORTED)
    if clients is not None:
        _validate_journal_semantics(events, clients)
    return events


def _validate_journal_semantics(
    events: list[dict[str, Any]], clients: tuple[str, ...]
) -> None:
    if not events:
        return
    if events[0]["state"] != "prepared":
        raise AtomicSwitchError("SOS_ATOMIC_ADAPTER_SWITCH_JOURNAL_INVALID", Status.INVALID)
    index = 1
    for client in clients:
        if index >= len(events) or events[index]["state"] == "rollback_started":
            break
        if events[index]["state"] != "client_started" or events[index]["client"] != client:
            raise AtomicSwitchError("SOS_ATOMIC_ADAPTER_SWITCH_JOURNAL_INVALID", Status.INVALID)
        index += 1
        if index >= len(events) or events[index]["state"] == "rollback_started":
            break
        if events[index]["state"] != "client_applied" or events[index]["client"] != client:
            raise AtomicSwitchError("SOS_ATOMIC_ADAPTER_SWITCH_JOURNAL_INVALID", Status.INVALID)
        index += 1
    if index >= len(events):
        return
    if events[index]["state"] == "committed":
        expected_forward = 1 + 2 * len(clients)
        if index != expected_forward or index != len(events) - 1:
            raise AtomicSwitchError("SOS_ATOMIC_ADAPTER_SWITCH_JOURNAL_INVALID", Status.INVALID)
        return
    if events[index]["state"] != "rollback_started":
        raise AtomicSwitchError("SOS_ATOMIC_ADAPTER_SWITCH_JOURNAL_INVALID", Status.INVALID)
    index += 1
    for client in reversed(clients):
        if index >= len(events):
            return
        if events[index]["state"] != "client_rolled_back" or events[index]["client"] != client:
            raise AtomicSwitchError("SOS_ATOMIC_ADAPTER_SWITCH_JOURNAL_INVALID", Status.INVALID)
        index += 1
    if index < len(events):
        if events[index]["state"] != "rolled_back" or index != len(events) - 1:
            raise AtomicSwitchError("SOS_ATOMIC_ADAPTER_SWITCH_JOURNAL_INVALID", Status.INVALID)


def _validate_plan(value: object) -> None:
    required = {
        "contract", "switch_id", "repository_id", "clients",
        "predecessor_launcher", "successor_launcher", "package_manager_calls",
        "switch_nonce", "raw_project_content_serialized", "absolute_paths_serialized",
        "plan_digest",
    }
    if not isinstance(value, dict) or set(value) != required:
        raise AtomicSwitchError("SOS_ATOMIC_ADAPTER_SWITCH_PLAN_INVALID", Status.INVALID)
    if (
        value["contract"] != _PLAN_CONTRACT
        or not isinstance(value["switch_id"], str)
        or _SWITCH_ID.fullmatch(value["switch_id"]) is None
        or not isinstance(value["switch_nonce"], str)
        or _NONCE.fullmatch(value["switch_nonce"]) is None
        or not isinstance(value["repository_id"], str)
        or not isinstance(value["clients"], list)
        or not value["clients"]
        or any(client not in _CLIENTS for client in value["clients"])
        or len(set(value["clients"])) != len(value["clients"])
        or value["clients"] != [client for client in _CLIENTS if client in value["clients"]]
        or value["package_manager_calls"] != 0
        or value["raw_project_content_serialized"] is not False
        or value["absolute_paths_serialized"] is not False
        or value["plan_digest"] != _sealed_digest(value, "plan_digest")
    ):
        raise AtomicSwitchError("SOS_ATOMIC_ADAPTER_SWITCH_PLAN_INVALID", Status.INVALID)
    for field in ("predecessor_launcher", "successor_launcher"):
        binding = value[field]
        if not isinstance(binding, dict) or set(binding) != {
            "package_version", "executable_sha256", "binding_digest"
        } or not all(isinstance(item, str) and item for item in binding.values()):
            raise AtomicSwitchError("SOS_ATOMIC_ADAPTER_SWITCH_PLAN_INVALID", Status.INVALID)
        if (
            _DIGEST.fullmatch(binding["binding_digest"]) is None
            or _DIGEST.fullmatch(binding["executable_sha256"]) is None
        ):
            raise AtomicSwitchError(
                "SOS_ATOMIC_ADAPTER_SWITCH_PLAN_INVALID", Status.INVALID
            )
    material = {
        key: item
        for key, item in value.items()
        if key not in {"switch_id", "plan_digest"}
    }
    expected_switch_id = "p107-atomic-" + digest_value(material).removeprefix(
        "sha256:"
    )[:32]
    if value["switch_id"] != expected_switch_id:
        raise AtomicSwitchError("SOS_ATOMIC_ADAPTER_SWITCH_PLAN_INVALID", Status.INVALID)


def _validate_event(
    value: object,
    *,
    expected_ordinal: int,
    predecessor: dict[str, Any] | None,
) -> None:
    required = {
        "contract", "switch_id", "plan_digest", "sequence_ordinal", "state",
        "client", "predecessor_event_digest", "package_manager_calls",
        "raw_project_content_serialized", "absolute_paths_serialized", "event_digest",
    }
    states = {
        "prepared", "client_started", "client_applied", "rollback_started",
        "client_rolled_back", "committed", "rolled_back",
    }
    previous_state = predecessor["state"] if predecessor else None
    transitions = {
        None: {"prepared"},
        "prepared": {"client_started", "rollback_started"},
        "client_started": {"client_applied", "rollback_started"},
        "client_applied": {"client_started", "committed", "rollback_started"},
        "rollback_started": {"client_rolled_back", "rolled_back"},
        "client_rolled_back": {"client_rolled_back", "rolled_back"},
        "committed": set(),
        "rolled_back": set(),
    }
    if (
        not isinstance(value, dict)
        or set(value) != required
        or value["contract"] != _EVENT_CONTRACT
        or value["sequence_ordinal"] != expected_ordinal
        or value["state"] not in states
        or value["state"] not in transitions.get(previous_state, set())
        or value["client"] not in {*_CLIENTS, None}
        or (value["state"] in {"client_started", "client_applied", "client_rolled_back"})
        != (value["client"] is not None)
        or value["package_manager_calls"] != 0
        or value["raw_project_content_serialized"] is not False
        or value["absolute_paths_serialized"] is not False
        or value["predecessor_event_digest"]
        != (predecessor["event_digest"] if predecessor else None)
        or value["event_digest"] != _sealed_digest(value, "event_digest")
        or not isinstance(value["switch_id"], str)
        or _SWITCH_ID.fullmatch(value["switch_id"]) is None
        or not isinstance(value["plan_digest"], str)
        or _DIGEST.fullmatch(value["plan_digest"]) is None
    ):
        raise AtomicSwitchError("SOS_ATOMIC_ADAPTER_SWITCH_JOURNAL_INVALID", Status.INVALID)


def _sealed_digest(value: dict[str, Any], field: str) -> str:
    material = dict(value)
    material[field] = "sha256:" + "0" * 64
    return digest_value(material)


def _parse_json(payload: bytes) -> dict[str, Any]:
    if len(payload) > 64 * 1024:
        raise AtomicSwitchError("SOS_ATOMIC_ADAPTER_SWITCH_JOURNAL_LIMIT_EXCEEDED", Status.UNSUPPORTED)
    try:
        def pairs(values: list[tuple[str, Any]]) -> dict[str, Any]:
            result: dict[str, Any] = {}
            for key, item in values:
                if key in result:
                    raise ValueError("duplicate key")
                result[key] = item
            return result

        value = json.loads(payload.decode("utf-8"), object_pairs_hook=pairs)
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
        raise AtomicSwitchError("SOS_ATOMIC_ADAPTER_SWITCH_JOURNAL_INVALID", Status.INVALID) from exc
    if not isinstance(value, dict):
        raise AtomicSwitchError("SOS_ATOMIC_ADAPTER_SWITCH_JOURNAL_INVALID", Status.INVALID)
    return value


def _json_bytes(value: dict[str, Any]) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


def _call_fault(fault: Callable[[str], None] | None, point: str) -> None:
    if fault is not None:
        fault(point)


@contextmanager
def _switch_lock(root: Path):
    from .adapter_lock import adapter_mutation_lock
    with adapter_mutation_lock(root):
        yield


def _result(
    status: Status,
    reason: str,
    plan: AtomicSwitchPlan,
    **extra: Any,
) -> TerminalResult:
    return TerminalResult(
        _RESULT_CONTRACT,
        status,
        (reason,),
        {
            "switch_id": plan.switch_id,
            "plan_digest": plan.plan_digest,
            "clients": list(plan.clients),
            "predecessor_launcher": _binding_projection(plan.predecessor),
            "successor_launcher": _binding_projection(plan.successor),
            "shared_switch_journal": True,
            "package_manager_calls": 0,
            "raw_project_content_serialized": False,
            "absolute_paths_serialized": False,
            **extra,
        },
    )
