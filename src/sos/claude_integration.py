"""Bounded Claude Code project adapter over repository-owned SOS state."""

from __future__ import annotations

import hashlib
import json
import os
from dataclasses import dataclass
from decimal import Decimal
from pathlib import Path
from typing import Any

from .client_integration import (
    ClientIntegrationError,
    LauncherBinding,
    observe_installed_launcher,
    publish_integration_control_file,
    publish_integration_target,
    read_integration_control_file,
    read_integration_target,
)
from .contracts import digest_value
from .adapter_lock import serialized_setup
from .managed_files import (
    ManagedFileBatchError,
    ManagedFileError,
    build_managed_file_batch_v2,
    build_managed_file_plan_v2,
    coordinate_managed_file_batch,
    project_managed_file_batch,
    recover_managed_file_batch,
    rollback_managed_file_batch,
    render_applied_managed_file_batch_files,
)
from .repository import RepositoryError, discover_repository_root
from .result import Status, TerminalResult
from .workspace import WorkspaceError, workspace_status


_CLIENT = "claude-code"
_CONTRACT = "sos_claude_code_setup_manifest_v1"
_RESULT_CONTRACT = "sos_claude_code_setup_result_v1"
_MANIFEST = "integrations/claude-code.json"
_INSTRUCTION_TARGET = "CLAUDE.md"
_MCP_TARGET = ".mcp.json"
_INSTRUCTION_JOURNAL = "claude-code-instructions-v1"
_MCP_JOURNAL = "claude-code-mcp-v1"
_BATCH_ID_PREFIX = "claude-code-setup-v1"
_MAX_BYTES = 1024 * 1024
_MAX_JSON_DEPTH = 64
_MAX_JSON_MEMBERS = 4096
_EMPTY_DIGEST = "sha256:" + hashlib.sha256(b"").hexdigest()
_BEGIN = "<!-- SOS:CLAUDE-CODE:BEGIN -->"
_END = "<!-- SOS:CLAUDE-CODE:END -->"
_INSTRUCTION_BLOCK = (
    "<!-- SOS:CLAUDE-CODE:BEGIN -->\n"
    "## Sigma Operator Stack recovery\n\n"
    "Repository-owned `.sigma` records are the project-state authority. Use the eight "
    "`sigma_operator_stack` MCP tools only to read status, recovery, boundaries, checks, "
    "and proposals. A typed non-success result stops project work and supplies the next "
    "bounded action. Acceptance and maintenance stay outside MCP and require the verified "
    "SOS launcher plus its human preview and confirmation.\n"
    "<!-- SOS:CLAUDE-CODE:END -->\n"
).encode("utf-8")


class ClaudeIntegrationError(RuntimeError):
    def __init__(self, reason: str, status: Status = Status.INVALID) -> None:
        super().__init__(reason)
        self.reason = reason
        self.status = status


@dataclass(frozen=True, slots=True)
class ClaudeBootstrapSetup:
    root: Path
    binding: LauncherBinding
    manifest: dict[str, Any]
    target_bytes: tuple[tuple[str, bytes], ...]

    @property
    def overlays(self) -> dict[str, bytes]:
        return dict(self.target_bytes)

    @property
    def plan_digest(self) -> str:
        return digest_value({"contract": "sos_claude_code_bootstrap_subplan_v1", "repository_id": self.manifest["repository_id"], "batch_digest": self.manifest["batch"]["batch_digest"], "launcher_digest": self.binding.digest, "package_version": self.binding.package_version})


def prepare_claude_bootstrap_setup(path: str, repository_id: str, *, launcher: LauncherBinding | None = None) -> ClaudeBootstrapSetup:
    root = discover_repository_root(path)
    binding = launcher or observe_installed_launcher()
    manifest = _prepare_manifest(root, repository_id, binding)
    targets = []
    for plan in manifest["plans"]:
        before, existed, _ = read_integration_target(root, plan["target"])
        if existed != plan["before_exists"]:
            raise ClaudeIntegrationError("SOS_CLAUDE_CODE_SETUP_PLAN_STALE", Status.STALE)
        if plan["target"] == _INSTRUCTION_TARGET:
            separator = b"" if not before else (b"\n" if before.endswith(b"\n") else b"\n\n")
            patch = separator + _INSTRUCTION_BLOCK
        elif existed:
            offset, patch = _mcp_insert_patch(before, root, binding)
            if offset != plan["patch_offset"]:
                raise ClaudeIntegrationError("SOS_CLAUDE_CODE_SETUP_PLAN_STALE", Status.STALE)
        else:
            patch = _new_mcp_file(root, binding)
        after = before[: plan["patch_offset"]] + patch + before[plan["patch_offset"] :]
        _require_payload(plan, before, patch, after)
        targets.append((plan["target"], after))
    return ClaudeBootstrapSetup(root, binding, manifest, tuple(targets))


def apply_claude_bootstrap_setup(setup: ClaudeBootstrapSetup) -> None:
    apply, rollback, probe = _callbacks(setup.root, setup.manifest, setup.binding)
    try:
        for plan in setup.manifest["plans"]:
            apply(plan)
    except BaseException:
        for plan in reversed(setup.manifest["plans"]):
            if probe(plan) == "after": rollback(plan)
        raise


def rollback_claude_bootstrap_setup(setup: ClaudeBootstrapSetup) -> None:
    _, rollback, probe = _callbacks(setup.root, setup.manifest, setup.binding)
    for plan in reversed(setup.manifest["plans"]):
        if probe(plan) == "after": rollback(plan)
        elif probe(plan) != "before": raise ClaudeIntegrationError("SOS_CLAUDE_CODE_SETUP_TARGET_DRIFT", Status.STALE)


def probe_claude_bootstrap_setup(setup: ClaudeBootstrapSetup) -> str:
    _, _, probe = _callbacks(setup.root, setup.manifest, setup.binding)
    states = [probe(plan) for plan in setup.manifest["plans"]]
    return "before" if all(state == "before" for state in states) else "after" if all(state == "after" for state in states) else "drift"


def render_claude_bootstrap_control_files(setup: ClaudeBootstrapSetup) -> dict[str, bytes]:
    installed = _with_state(setup.manifest, "installed")
    files = render_applied_managed_file_batch_files(installed["batch"], installed["plans"])
    files[_MANIFEST] = json.dumps(installed, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
    return files


def preview_claude_setup(path: str = ".", *, launcher: LauncherBinding | None = None) -> TerminalResult:
    try:
        root, repository_id = _ready_root(path)
        binding = launcher or observe_installed_launcher()
        manifest = _prepare_manifest(root, repository_id, binding)
        return _result(Status.OWNER_REQUIRED, "SOS_CLAUDE_CODE_SETUP_CONFIRMATION_REQUIRED", manifest)
    except _ERRORS as exc:
        return _error_result(exc)


@serialized_setup
def install_claude_setup(
    path: str = ".",
    *,
    confirmed: bool,
    controlling_tty_observed: bool = False,
    launcher: LauncherBinding | None = None,
    expected_manifest_digest: str | None = None,
) -> TerminalResult:
    if not confirmed:
        return preview_claude_setup(path, launcher=launcher)
    if not controlling_tty_observed:
        return _result(Status.OWNER_REQUIRED, "SOS_CLAUDE_CODE_SETUP_TTY_REQUIRED")
    try:
        root, repository_id = _ready_root(path)
        existing = _read_manifest(root)
        if existing is not None and existing["state"] == "installed":
            return claude_setup_status(path, launcher=launcher)
        binding = launcher or observe_installed_launcher()
        manifest = _prepare_manifest(root, repository_id, binding)
        if (
            expected_manifest_digest is not None
            and manifest["manifest_digest"] != expected_manifest_digest
        ):
            raise ClaudeIntegrationError(
                "SOS_CLAUDE_CODE_SETUP_PREVIEW_STALE", Status.STALE
            )
        _write_manifest(root, manifest)
        apply_step, rollback_step, probe_step = _callbacks(root, manifest, binding)
        projection = coordinate_managed_file_batch(
            root,
            manifest["batch"],
            manifest["plans"],
            apply_step=apply_step,
            rollback_step=rollback_step,
            probe_step=probe_step,
        )
        installed = _with_state(manifest, "installed")
        _write_manifest(root, installed)
        return _result(
            Status.OWNER_REQUIRED,
            "SOS_INTERACTIVE_USER_HANDOFF_REQUIRED",
            installed,
            projection,
        )
    except _ERRORS as exc:
        return _error_result(exc)


def claude_setup_status(path: str = ".", *, launcher: LauncherBinding | None = None) -> TerminalResult:
    try:
        root = discover_repository_root(path)
        manifest = _read_manifest(root)
        if manifest is None or manifest["state"] == "removed":
            return _result(Status.SUCCESS, "SOS_CLAUDE_CODE_SETUP_NOT_INSTALLED", manifest)
        if manifest["state"] != "installed":
            raise ClaudeIntegrationError("SOS_CLAUDE_CODE_SETUP_RECOVERY_REQUIRED", Status.BLOCKED)
        binding = launcher or observe_installed_launcher()
        _verify_binding(manifest, binding)
        projection = project_managed_file_batch(root, manifest["batch"])
        if projection["state"] != "integrated":
            raise ClaudeIntegrationError("SOS_CLAUDE_CODE_SETUP_RECOVERY_REQUIRED", Status.BLOCKED)
        _, _, probe = _callbacks(root, manifest, binding)
        for plan in manifest["plans"]:
            if probe(plan) != "after":
                raise ClaudeIntegrationError("SOS_CLAUDE_CODE_SETUP_TARGET_DRIFT", Status.STALE)
        return _result(Status.OWNER_REQUIRED, "SOS_INTERACTIVE_USER_HANDOFF_REQUIRED", manifest, projection)
    except _ERRORS as exc:
        return _error_result(exc)


@serialized_setup
def recover_claude_setup(path: str = ".", *, launcher: LauncherBinding | None = None) -> TerminalResult:
    try:
        root = discover_repository_root(path)
        manifest = _read_manifest(root)
        if manifest is None:
            return _result(Status.SUCCESS, "SOS_CLAUDE_CODE_SETUP_NOT_INSTALLED")
        binding = launcher or observe_installed_launcher()
        _verify_binding(manifest, binding)
        apply_step, rollback_step, probe_step = _callbacks(root, manifest, binding)
        projection = project_managed_file_batch(root, manifest["batch"])
        if projection["state"] == "integration_incomplete":
            projection = recover_managed_file_batch(
                root,
                manifest["batch"],
                apply_step=apply_step,
                rollback_step=rollback_step,
                probe_step=probe_step,
            )
        if projection["state"] == "integrated" and manifest["state"] == "remove_prepared":
            projection = rollback_managed_file_batch(
                root,
                manifest["batch"],
                rollback_step=rollback_step,
                probe_step=probe_step,
            )
        if projection["state"] == "rolled_back":
            removed = _with_state(manifest, "removed")
            _write_manifest(root, removed)
            return _result(Status.SUCCESS, "SOS_CLAUDE_CODE_SETUP_ROLLBACK_RECOVERED", removed, projection)
        if projection["state"] == "integrated" and manifest["state"] in {"install_prepared", "installed"}:
            installed = _with_state(manifest, "installed")
            _write_manifest(root, installed)
            return _result(Status.OWNER_REQUIRED, "SOS_INTERACTIVE_USER_HANDOFF_REQUIRED", installed, projection)
        raise ClaudeIntegrationError("SOS_CLAUDE_CODE_SETUP_RECOVERY_REQUIRED", Status.BLOCKED)
    except _ERRORS as exc:
        return _error_result(exc)


def update_claude_setup(
    path: str = ".",
    *,
    confirmed: bool,
    controlling_tty_observed: bool = False,
    launcher: LauncherBinding | None = None,
) -> TerminalResult:
    status = claude_setup_status(path, launcher=launcher)
    if "SOS_CLAUDE_CODE_SETUP_BINDING_STALE" in status.reasons:
        return _result(Status.BLOCKED, "SOS_SHARED_ENVIRONMENT_INVENTORY_REQUIRED")
    if status.status not in {Status.SUCCESS, Status.OWNER_REQUIRED}:
        return status
    if "SOS_CLAUDE_CODE_SETUP_NOT_INSTALLED" in status.reasons:
        return status
    if not confirmed:
        return TerminalResult(_RESULT_CONTRACT, Status.OWNER_REQUIRED, ("SOS_CLAUDE_CODE_SETUP_UPDATE_CONFIRMATION_REQUIRED",), status.details)
    if not controlling_tty_observed:
        return _result(Status.OWNER_REQUIRED, "SOS_CLAUDE_CODE_SETUP_TTY_REQUIRED")
    details = dict(status.details)
    details["update_state"] = "same_version_current"
    details["package_manager_calls"] = 0
    return TerminalResult(_RESULT_CONTRACT, Status.OWNER_REQUIRED, ("SOS_INTERACTIVE_USER_HANDOFF_REQUIRED",), details)


def project_claude_package_update(
    path: str = ".", *, launcher: LauncherBinding | None = None
) -> TerminalResult:
    """Project the Claude binding delta without changing package or project state."""
    try:
        root = discover_repository_root(path)
        manifest = _read_manifest(root)
        if manifest is None or manifest["state"] == "removed":
            return TerminalResult(
                "sos_claude_code_package_update_projection_v1",
                Status.NOT_VERIFIED,
                ("SOS_UPDATE_NOT_CONFIGURED",),
                {"configuration_state": "not_configured", "client": _CLIENT},
            )
        if manifest["state"] != "installed":
            raise ClaudeIntegrationError(
                "SOS_CLAUDE_CODE_SETUP_RECOVERY_REQUIRED", Status.BLOCKED
            )
        projection = project_managed_file_batch(root, manifest["batch"])
        if projection["state"] != "integrated":
            raise ClaudeIntegrationError(
                "SOS_CLAUDE_CODE_SETUP_RECOVERY_REQUIRED", Status.BLOCKED
            )
        binding = launcher or observe_installed_launcher()
        changed = (
            manifest["package_version"] != binding.package_version
            or manifest["launcher_digest"] != binding.digest
        )
        workspace = workspace_status(os.fspath(root))
        return TerminalResult(
            "sos_claude_code_package_update_projection_v1",
            Status.SUCCESS,
            ("SOS_UPDATE_AVAILABLE" if changed else "SOS_UPDATE_NOT_REQUIRED",),
            {
                "client": _CLIENT,
                "configuration_state": "update_available" if changed else "current",
                "installed_package_version": manifest["package_version"],
                "installed_launcher_digest": manifest["launcher_digest"],
                "proposed_package_version": binding.package_version,
                "proposed_launcher_digest": binding.digest,
                "setup_update_command": "sos setup update-all PATH" if changed else None,
                "agent_restart_required": changed,
                "qualification_integrity": workspace.details.get("qualification_integrity"),
                "qualification_rerun_required": workspace.details.get("qualification_integrity") != "valid",
                "affected_project_scope": manifest["repository_id"],
                "proposal_only": True,
                "writes_performed": False,
                "network_performed": False,
                "raw_project_content_serialized": False,
                "absolute_paths_serialized": False,
            },
        )
    except _ERRORS as exc:
        return _error_result(exc)


@serialized_setup
def remove_claude_setup(
    path: str = ".",
    *,
    confirmed: bool,
    controlling_tty_observed: bool = False,
    launcher: LauncherBinding | None = None,
) -> TerminalResult:
    if not confirmed:
        status = claude_setup_status(path, launcher=launcher)
        if "SOS_CLAUDE_CODE_SETUP_NOT_INSTALLED" in status.reasons:
            return status
        return TerminalResult(_RESULT_CONTRACT, Status.OWNER_REQUIRED, ("SOS_CLAUDE_CODE_SETUP_REMOVE_CONFIRMATION_REQUIRED",), status.details)
    if not controlling_tty_observed:
        return _result(Status.OWNER_REQUIRED, "SOS_CLAUDE_CODE_SETUP_TTY_REQUIRED")
    try:
        root = discover_repository_root(path)
        manifest = _read_manifest(root)
        if manifest is None or manifest["state"] == "removed":
            return _result(Status.SUCCESS, "SOS_CLAUDE_CODE_SETUP_ALREADY_REMOVED", manifest)
        if manifest["state"] != "installed":
            raise ClaudeIntegrationError("SOS_CLAUDE_CODE_SETUP_RECOVERY_REQUIRED", Status.BLOCKED)
        binding = launcher or observe_installed_launcher()
        _verify_binding(manifest, binding)
        removing = _with_state(manifest, "remove_prepared")
        _write_manifest(root, removing)
        _, rollback_step, probe_step = _callbacks(root, removing, binding)
        projection = rollback_managed_file_batch(
            root, removing["batch"], rollback_step=rollback_step, probe_step=probe_step
        )
        removed = _with_state(removing, "removed")
        _write_manifest(root, removed)
        return _result(Status.SUCCESS, "SOS_CLAUDE_CODE_SETUP_REMOVED", removed, projection)
    except _ERRORS as exc:
        return _error_result(exc)


def _ready_root(path: str) -> tuple[Path, str]:
    root = discover_repository_root(path)
    status = workspace_status(os.fspath(root))
    repository_id = status.details.get("repository_id")
    if status.status in {Status.INVALID, Status.BLOCKED, Status.UNSUPPORTED} or not isinstance(repository_id, str):
        raise ClaudeIntegrationError(status.reasons[0] if status.reasons else "SOS_WORKSPACE_NOT_READY", status.status)
    return root, repository_id


def _prepare_manifest(root: Path, repository_id: str, binding: LauncherBinding) -> dict[str, Any]:
    instruction, instruction_exists, instruction_mode = read_integration_target(root, _INSTRUCTION_TARGET)
    if _BEGIN.encode() in instruction or _END.encode() in instruction:
        raise ClaudeIntegrationError("SOS_CLAUDE_CODE_INSTRUCTION_COLLISION", Status.BLOCKED)
    separator = b"" if not instruction else (b"\n" if instruction.endswith(b"\n") else b"\n\n")
    instruction_patch = separator + _INSTRUCTION_BLOCK
    instruction_after = instruction + instruction_patch

    mcp, mcp_exists, mcp_mode = read_integration_target(root, _MCP_TARGET)
    if mcp_exists:
        offset, mcp_patch = _mcp_insert_patch(mcp, root, binding)
        mcp_kind = "insert_bytes"
        mcp_after = mcp[:offset] + mcp_patch + mcp[offset:]
        _strict_json(mcp_after)
    else:
        offset = 0
        mcp_patch = _new_mcp_file(root, binding)
        mcp_kind = "create_file"
        mcp_after = mcp_patch
    instruction_plan = _plan(repository_id, _INSTRUCTION_JOURNAL, _INSTRUCTION_TARGET, "append_suffix" if instruction_exists else "create_file", len(instruction), instruction, instruction_patch, instruction_after, instruction_exists)
    mcp_plan = _plan(repository_id, _MCP_JOURNAL, _MCP_TARGET, mcp_kind, offset, mcp, mcp_patch, mcp_after, mcp_exists)
    plans = [instruction_plan, mcp_plan]
    seed = digest_value([plan["plan_digest"] for plan in plans]).removeprefix(
        "sha256:"
    )[:16]
    batch = build_managed_file_batch_v2(
        batch_id=f"{_BATCH_ID_PREFIX}-{seed}",
        repository_id=repository_id,
        plans=plans,
    )
    value = {
        "contract": _CONTRACT,
        "client": _CLIENT,
        "state": "install_prepared",
        "repository_id": repository_id,
        "batch": batch,
        "plans": plans,
        "launcher_digest": binding.digest,
        "package_version": binding.package_version,
        "instruction_mode": instruction_mode,
        "mcp_mode": mcp_mode,
        "raw_content_serialized": False,
        "absolute_paths_serialized": False,
        "client_trust_state": "not_observed",
        "manifest_digest": "sha256:" + "0" * 64,
    }
    value["manifest_digest"] = _manifest_digest(value)
    _validate_manifest(value)
    return value


def _plan(repository_id: str, journal: str, target: str, kind: str, offset: int, before: bytes, patch: bytes, after: bytes, existed: bool) -> dict[str, Any]:
    return build_managed_file_plan_v2(
        journal_id=journal,
        repository_id=repository_id,
        target=target,
        patch_kind=kind,
        patch_offset=offset,
        before_exists=existed,
        before_byte_count=len(before),
        before_digest=_digest(before),
        patch_byte_count=len(patch),
        patch_digest=_digest(patch),
        after_byte_count=len(after),
        after_digest=_digest(after),
    )


def _callbacks(root: Path, manifest: dict[str, Any], binding: LauncherBinding):
    plans = {plan["plan_digest"]: plan for plan in manifest["plans"]}

    def read(plan: dict[str, Any]) -> tuple[bytes, bool, int]:
        if plan["plan_digest"] not in plans or plans[plan["plan_digest"]] != plan:
            raise ClaudeIntegrationError("SOS_CLAUDE_CODE_SETUP_PLAN_INVALID")
        return read_integration_target(root, plan["target"])

    def probe(plan: dict[str, Any]) -> str:
        current, existed, mode = read(plan)
        expected_mode = (
            manifest["instruction_mode"]
            if plan["target"] == _INSTRUCTION_TARGET
            else manifest["mcp_mode"]
        )
        if mode != expected_mode:
            return "drift"
        if existed == plan["before_exists"] and len(current) == plan["before_byte_count"] and _digest(current) == plan["before_digest"]:
            return "before"
        if existed and len(current) == plan["after_byte_count"] and _digest(current) == plan["after_digest"]:
            return "after"
        return "drift"

    def patch_for(plan: dict[str, Any], before: bytes) -> bytes:
        if plan["target"] == _INSTRUCTION_TARGET:
            separator = b"" if not before else (b"\n" if before.endswith(b"\n") else b"\n\n")
            return separator + _INSTRUCTION_BLOCK
        if plan["target"] == _MCP_TARGET:
            if plan["patch_kind"] == "create_file":
                return _new_mcp_file(root, binding)
            offset, patch = _mcp_insert_patch(before, root, binding)
            if offset != plan["patch_offset"]:
                raise ClaudeIntegrationError("SOS_CLAUDE_CODE_SETUP_PLAN_STALE", Status.STALE)
            return patch
        raise ClaudeIntegrationError("SOS_CLAUDE_CODE_SETUP_PLAN_INVALID")

    def apply(plan: dict[str, Any]) -> None:
        before, existed, _ = read(plan)
        if probe(plan) != "before":
            raise ClaudeIntegrationError("SOS_CLAUDE_CODE_SETUP_TARGET_DRIFT", Status.STALE)
        patch = patch_for(plan, before)
        after = before[: plan["patch_offset"]] + patch + before[plan["patch_offset"] :]
        _require_payload(plan, before, patch, after)
        if plan["target"] == _MCP_TARGET:
            _strict_json(after)
        publish_integration_target(root, plan["target"], after, expected=before, expected_existed=existed, mode=manifest["instruction_mode"] if plan["target"] == _INSTRUCTION_TARGET else manifest["mcp_mode"], drift_reason="SOS_CLAUDE_CODE_SETUP_TARGET_DRIFT", recovery_reason="SOS_CLAUDE_CODE_SETUP_RECOVERY_REQUIRED")

    def rollback(plan: dict[str, Any]) -> None:
        after, existed, _ = read(plan)
        if not existed or probe(plan) != "after":
            raise ClaudeIntegrationError("SOS_CLAUDE_CODE_SETUP_TARGET_DRIFT", Status.STALE)
        start = plan["patch_offset"]
        end = start + plan["patch_byte_count"]
        patch = after[start:end]
        before = after[:start] + after[end:]
        _require_payload(plan, before, patch, after)
        publish_integration_target(root, plan["target"], before if plan["before_exists"] else None, expected=after, expected_existed=True, mode=manifest["instruction_mode"] if plan["target"] == _INSTRUCTION_TARGET else manifest["mcp_mode"], drift_reason="SOS_CLAUDE_CODE_SETUP_TARGET_DRIFT", recovery_reason="SOS_CLAUDE_CODE_SETUP_RECOVERY_REQUIRED")

    return apply, rollback, probe


def _server(root: Path, binding: LauncherBinding) -> dict[str, Any]:
    return {"args": ["-m", "sos", "mcp", "--root", os.fspath(root)], "command": binding.command, "type": "stdio"}


def _new_mcp_file(root: Path, binding: LauncherBinding) -> bytes:
    return (json.dumps({"mcpServers": {"sigma_operator_stack": _server(root, binding)}}, sort_keys=True, separators=(",", ":"), ensure_ascii=False) + "\n").encode()


def _mcp_insert_patch(payload: bytes, root: Path, binding: LauncherBinding) -> tuple[int, bytes]:
    parsed = _strict_json(payload)
    if not isinstance(parsed, dict):
        raise ClaudeIntegrationError("SOS_CLAUDE_CODE_MCP_JSON_INVALID")
    entries, root_close = _object_entries(payload, 0)
    server_bytes = json.dumps("sigma_operator_stack", ensure_ascii=False).encode() + b":" + json.dumps(_server(root, binding), sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
    for key, start, end in entries:
        if key != "mcpServers":
            continue
        if not isinstance(parsed[key], dict):
            raise ClaudeIntegrationError("SOS_CLAUDE_CODE_MCP_JSON_INVALID")
        if "sigma_operator_stack" in parsed[key]:
            raise ClaudeIntegrationError("SOS_CLAUDE_CODE_MCP_SERVER_COLLISION", Status.BLOCKED)
        nested, close = _object_entries(payload, start)
        return close, (b"," if nested else b"") + server_bytes
    member = json.dumps("mcpServers").encode() + b":{" + server_bytes + b"}"
    return root_close, (b"," if entries else b"") + member


def _strict_json(payload: bytes) -> Any:
    if len(payload) > _MAX_BYTES:
        raise ClaudeIntegrationError("SOS_CLAUDE_CODE_MCP_JSON_LIMIT_EXCEEDED", Status.UNSUPPORTED)
    members = 0
    def pairs(values):
        nonlocal members
        members += len(values)
        if members > _MAX_JSON_MEMBERS:
            raise ClaudeIntegrationError("SOS_CLAUDE_CODE_MCP_JSON_LIMIT_EXCEEDED", Status.UNSUPPORTED)
        result = {}
        for key, value in values:
            if key in result:
                raise ClaudeIntegrationError("SOS_CLAUDE_CODE_MCP_JSON_INVALID")
            result[key] = value
        return result
    try:
        value = json.loads(payload.decode("utf-8"), object_pairs_hook=pairs, parse_float=Decimal, parse_constant=lambda _: (_ for _ in ()).throw(ValueError()))
    except ClaudeIntegrationError:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError, RecursionError) as exc:
        raise ClaudeIntegrationError("SOS_CLAUDE_CODE_MCP_JSON_INVALID") from exc
    def depth(item: Any, level: int = 0) -> None:
        if level > _MAX_JSON_DEPTH:
            raise ClaudeIntegrationError("SOS_CLAUDE_CODE_MCP_JSON_LIMIT_EXCEEDED", Status.UNSUPPORTED)
        if isinstance(item, dict):
            for child in item.values(): depth(child, level + 1)
        elif isinstance(item, list):
            for child in item: depth(child, level + 1)
    depth(value)
    return value


def _object_entries(data: bytes, offset: int) -> tuple[list[tuple[str, int, int]], int]:
    index = _skip_ws(data, offset)
    if index >= len(data) or data[index] != 123:
        raise ClaudeIntegrationError("SOS_CLAUDE_CODE_MCP_INSERTION_INVALID")
    index += 1
    entries: list[tuple[str, int, int]] = []
    index = _skip_ws(data, index)
    if index < len(data) and data[index] == 125:
        return entries, index
    while True:
        key_start = index
        key_end = _scan_string(data, key_start)
        try: key = json.loads(data[key_start:key_end].decode())
        except (UnicodeDecodeError, json.JSONDecodeError) as exc: raise ClaudeIntegrationError("SOS_CLAUDE_CODE_MCP_INSERTION_INVALID") from exc
        index = _skip_ws(data, key_end)
        if index >= len(data) or data[index] != 58: raise ClaudeIntegrationError("SOS_CLAUDE_CODE_MCP_INSERTION_INVALID")
        value_start = _skip_ws(data, index + 1)
        value_end = _scan_value(data, value_start)
        entries.append((key, value_start, value_end))
        index = _skip_ws(data, value_end)
        if index < len(data) and data[index] == 125: return entries, index
        if index >= len(data) or data[index] != 44: raise ClaudeIntegrationError("SOS_CLAUDE_CODE_MCP_INSERTION_INVALID")
        index = _skip_ws(data, index + 1)


def _scan_value(data: bytes, index: int) -> int:
    if index >= len(data): raise ClaudeIntegrationError("SOS_CLAUDE_CODE_MCP_INSERTION_INVALID")
    if data[index] == 34: return _scan_string(data, index)
    if data[index] in (123, 91):
        opener, closer = data[index], 125 if data[index] == 123 else 93
        level, cursor = 1, index + 1
        while cursor < len(data):
            if data[cursor] == 34: cursor = _scan_string(data, cursor); continue
            if data[cursor] == opener: level += 1
            elif data[cursor] == closer:
                level -= 1
                if level == 0: return cursor + 1
            cursor += 1
        raise ClaudeIntegrationError("SOS_CLAUDE_CODE_MCP_INSERTION_INVALID")
    cursor = index
    while cursor < len(data) and data[cursor] not in b",}] \t\r\n": cursor += 1
    return cursor


def _scan_string(data: bytes, index: int) -> int:
    if index >= len(data) or data[index] != 34: raise ClaudeIntegrationError("SOS_CLAUDE_CODE_MCP_INSERTION_INVALID")
    cursor = index + 1
    while cursor < len(data):
        if data[cursor] == 92: cursor += 2; continue
        if data[cursor] == 34: return cursor + 1
        cursor += 1
    raise ClaudeIntegrationError("SOS_CLAUDE_CODE_MCP_INSERTION_INVALID")


def _skip_ws(data: bytes, index: int) -> int:
    while index < len(data) and data[index] in b" \t\r\n": index += 1
    return index


def _require_payload(plan: dict[str, Any], before: bytes, patch: bytes, after: bytes) -> None:
    if len(before) != plan["before_byte_count"] or _digest(before) != plan["before_digest"] or len(patch) != plan["patch_byte_count"] or _digest(patch) != plan["patch_digest"] or len(after) != plan["after_byte_count"] or _digest(after) != plan["after_digest"]:
        raise ClaudeIntegrationError("SOS_CLAUDE_CODE_SETUP_PLAN_STALE", Status.STALE)


def _read_manifest(root: Path) -> dict[str, Any] | None:
    payload = read_integration_control_file(root, _MANIFEST)
    if payload is None: return None
    try: value = json.loads(payload.decode())
    except (UnicodeDecodeError, json.JSONDecodeError) as exc: raise ClaudeIntegrationError("SOS_CLAUDE_CODE_SETUP_MANIFEST_INVALID") from exc
    _validate_manifest(value)
    return value


def _write_manifest(root: Path, value: dict[str, Any]) -> None:
    _validate_manifest(value)
    publish_integration_control_file(root, _MANIFEST, json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode())


def _validate_manifest(value: object) -> None:
    required = {"contract", "client", "state", "repository_id", "batch", "plans", "launcher_digest", "package_version", "instruction_mode", "mcp_mode", "raw_content_serialized", "absolute_paths_serialized", "client_trust_state", "manifest_digest"}
    if not isinstance(value, dict) or set(value) != required or value["contract"] != _CONTRACT or value["client"] != _CLIENT or value["state"] not in {"install_prepared", "installed", "remove_prepared", "removed"} or value["client_trust_state"] != "not_observed":
        raise ClaudeIntegrationError("SOS_CLAUDE_CODE_SETUP_MANIFEST_INVALID")
    if value["raw_content_serialized"] is not False or value["absolute_paths_serialized"] is not False or not isinstance(value["plans"], list) or len(value["plans"]) != 2:
        raise ClaudeIntegrationError("SOS_CLAUDE_CODE_SETUP_MANIFEST_INVALID")
    if (
        not isinstance(value["batch"].get("batch_id"), str)
        or not value["batch"]["batch_id"].startswith(_BATCH_ID_PREFIX + "-")
        or not isinstance(value["repository_id"], str)
        or not value["repository_id"]
        or not isinstance(value["launcher_digest"], str)
        or not isinstance(value["package_version"], str)
        or not value["package_version"]
        or any(
            not isinstance(value[field], int)
            or isinstance(value[field], bool)
            or not 0 <= value[field] <= 0o777
            for field in ("instruction_mode", "mcp_mode")
        )
    ):
        raise ClaudeIntegrationError("SOS_CLAUDE_CODE_SETUP_MANIFEST_INVALID")
    instruction, mcp = value["plans"]
    if (
        instruction.get("contract") != "sos_managed_file_plan_v2"
        or instruction.get("journal_id") != _INSTRUCTION_JOURNAL
        or instruction.get("target") != _INSTRUCTION_TARGET
        or instruction.get("patch_kind") not in {"create_file", "append_suffix"}
        or mcp.get("contract") != "sos_managed_file_plan_v2"
        or mcp.get("journal_id") != _MCP_JOURNAL
        or mcp.get("target") != _MCP_TARGET
        or mcp.get("patch_kind") not in {"create_file", "insert_bytes"}
    ):
        raise ClaudeIntegrationError("SOS_CLAUDE_CODE_SETUP_MANIFEST_INVALID")
    expected_batch_id = _BATCH_ID_PREFIX + "-" + digest_value(
        [plan["plan_digest"] for plan in value["plans"]]
    ).removeprefix("sha256:")[:16]
    if value["batch"]["batch_id"] != expected_batch_id:
        raise ClaudeIntegrationError("SOS_CLAUDE_CODE_SETUP_MANIFEST_INVALID")
    expected = build_managed_file_batch_v2(batch_id=value["batch"]["batch_id"], repository_id=value["repository_id"], plans=value["plans"])
    if expected != value["batch"] or value["manifest_digest"] != _manifest_digest(value):
        raise ClaudeIntegrationError("SOS_CLAUDE_CODE_SETUP_MANIFEST_INVALID")


def _with_state(value: dict[str, Any], state: str) -> dict[str, Any]:
    updated = dict(value); updated["state"] = state; updated["manifest_digest"] = "sha256:" + "0" * 64; updated["manifest_digest"] = _manifest_digest(updated); _validate_manifest(updated); return updated


def _verify_binding(value: dict[str, Any], binding: LauncherBinding) -> None:
    if value["launcher_digest"] != binding.digest or value["package_version"] != binding.package_version:
        raise ClaudeIntegrationError("SOS_CLAUDE_CODE_SETUP_BINDING_STALE", Status.STALE)


def _manifest_digest(value: dict[str, Any]) -> str:
    material = dict(value); material["manifest_digest"] = "sha256:" + "0" * 64; return digest_value(material)


def _digest(payload: bytes) -> str:
    return "sha256:" + hashlib.sha256(payload).hexdigest()


def _result(status: Status, reason: str, manifest: dict[str, Any] | None = None, projection: dict[str, Any] | None = None) -> TerminalResult:
    details = {"client": _CLIENT, "integration_state": manifest.get("state") if manifest else "absent", "client_readiness": "not_observed" if manifest and manifest.get("state") == "installed" else "not_applicable", "maintenance_eligible": bool(manifest and manifest.get("state") == "installed"), "raw_content_serialized": False, "absolute_paths_serialized": False}
    if manifest: details.update({"manifest_digest": manifest["manifest_digest"], "batch_digest": manifest["batch"]["batch_digest"], "package_version": manifest["package_version"]})
    if projection: details["batch_projection"] = projection
    return TerminalResult(_RESULT_CONTRACT, status, (reason,), details)


def _error_result(exc: BaseException) -> TerminalResult:
    return _result(getattr(exc, "status", Status.INVALID), getattr(exc, "reason", "SOS_CLAUDE_CODE_SETUP_INVALID"))


_ERRORS = (ClaudeIntegrationError, ClientIntegrationError, ManagedFileBatchError, ManagedFileError, RepositoryError, WorkspaceError, OSError, KeyError, TypeError, ValueError)
