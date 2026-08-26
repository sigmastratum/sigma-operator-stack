"""Project-local, reversible MCP client integration for one exact Codex profile."""

from __future__ import annotations

import hashlib
import json
import os
import re
import stat
import tomllib
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from . import __version__
from .contracts import digest_value
from .managed_files import (
    ManagedFileBatchError,
    ManagedFileError,
    build_managed_file_batch,
    build_managed_file_plan,
    coordinate_managed_file_batch,
    project_managed_file_batch,
    record_managed_file_state,
    recover_managed_file_batch,
    replay_managed_file_journal,
    require_managed_file_state,
    rollback_managed_file_batch,
    render_applied_managed_file_batch_files,
)
from .platform_services import (
    FilePublicationOperation,
    PlatformServiceError,
    current_platform_services,
)
from .repository import RepositoryError, discover_repository_root
from .result import Status, TerminalResult
from .workspace import WorkspaceError, project_workspace_application, workspace_status


_CLIENT = "codex"
_CONTRACT = "sos_client_integration_manifest_v1"
_RESULT_CONTRACT = "sos_client_integration_result_v1"
_TARGET = ".codex/config.toml"
_MANIFEST = "integrations/codex-mcp.json"
_SERVER = "sigma_operator_stack"
_MAX_CONFIG_BYTES = 1024 * 1024
_BEGIN = "# >>> SOS managed Codex MCP (sos_codex_mcp_v1)"
_END = "# <<< SOS managed Codex MCP (sos_codex_mcp_v1)"
_TOOLS = (
    "sos_status",
    "sos_preflight",
    "sos_active_task",
    "sos_next_action",
    "sos_qualification_plan",
    "sos_recover",
    "sos_propose_qualification_receipt",
    "sos_propose_update",
)
_JOURNAL_ID = "codex-mcp"
_INSTRUCTION_JOURNAL_ID = "codex-instructions"
_SETUP_JOURNAL_ID = "codex-mcp-v2"
_SETUP_INSTRUCTION_JOURNAL_ID = "codex-instructions-v2"
_SETUP_BATCH_ID = "codex-first"
_SETUP_CONTRACT = "sos_codex_first_setup_manifest_v1"
_SETUP_MANIFEST = "integrations/codex-first.json"
_INSTRUCTION_TARGET = "AGENTS.md"
_INSTRUCTION_BEGIN = "<!-- >>> SOS managed project recovery (sos_codex_first_v1) -->"
_INSTRUCTION_END = "<!-- <<< SOS managed project recovery (sos_codex_first_v1) -->"
_INSTRUCTION_BLOCK = (
    _INSTRUCTION_BEGIN
    + "\n# SOS project recovery\n\n"
    + "Before changing this repository, use only these enabled project-local SOS MCP tools: "
    + ", ".join(f"`{tool}`" for tool in _TOOLS)
    + ". Use them to read current authority, work, boundaries, checks and recovery state. Treat stale, "
    + "blocked, invalid, unsupported and not-verified results as stop conditions. "
    + "SOS tools do not grant acceptance, shell, commit, push, deploy or production authority.\n"
    + _INSTRUCTION_END
    + "\n"
).encode("utf-8")


class ClientIntegrationError(RuntimeError):
    def __init__(self, reason: str, status: Status = Status.INVALID) -> None:
        super().__init__(reason)
        self.reason = reason
        self.status = status


@dataclass(frozen=True, slots=True)
class LauncherBinding:
    """Observed installed-package launcher. Raw paths never enter receipts."""

    command: str
    package_version: str
    executable_sha256: str

    @property
    def digest(self) -> str:
        return digest_value(
            {
                "contract": "sos_mcp_launcher_binding_v1",
                "package": "sigma-operator-stack",
                "package_version": self.package_version,
                "executable_sha256": self.executable_sha256,
                "invocation": ["-m", "sos", "mcp"],
            }
        )


@dataclass(frozen=True, slots=True)
class CodexBootstrapSetup:
    root: Path
    binding: LauncherBinding
    manifest: dict[str, Any]
    target_bytes: tuple[tuple[str, bytes], ...]

    @property
    def overlays(self) -> dict[str, bytes]:
        return dict(self.target_bytes)

    @property
    def plan_digest(self) -> str:
        return digest_value(
            {
                "contract": "sos_codex_bootstrap_subplan_v1",
                "repository_id": self.manifest["repository_id"],
                "batch_digest": self.manifest["batch"]["batch_digest"],
                "launcher_digest": self.manifest["launcher_digest"],
                "package_version": self.manifest["package_version"],
            }
        )


def prepare_codex_bootstrap_setup(
    path: str,
    repository_id: str,
    *,
    launcher: LauncherBinding | None = None,
) -> CodexBootstrapSetup:
    """Build the exact two-target setup before a canonical `.sigma` exists."""
    root = discover_repository_root(path)
    try:
        service = current_platform_services()
        with service.open_repository(root) as repository:
            if service.observe_object(repository, ".sigma").kind != "absent":
                raise ClientIntegrationError("SOS_CONTROL_PLANE_COLLISION", Status.BLOCKED)
    except PlatformServiceError as exc:
        raise ClientIntegrationError("SOS_CONTROL_PLANE_COLLISION", Status.BLOCKED) from exc
    binding = launcher or observe_installed_launcher()
    prepared = _prepare_setup(root, repository_id, binding)
    targets = _prepared_setup_target_bytes(root, binding, prepared)
    return CodexBootstrapSetup(root, binding, prepared, targets)


def _prepared_setup_target_bytes(
    root: Path, binding: LauncherBinding, prepared: dict[str, Any]
) -> tuple[tuple[str, bytes], ...]:
    targets: list[tuple[str, bytes]] = []
    for plan in prepared["plans"]:
        target = root / plan["target"]
        if plan["target"] == _INSTRUCTION_TARGET:
            original, _existed = _read_instruction_target(root)
            updated = original + _render_instruction_addition(original)
        else:
            original, _existed, _parent = _read_target(root)
            updated = original + _render_addition(root, binding, original)
            _validate_toml(updated)
        if _bytes_digest(updated) != plan["after_digest"]:
            raise ClientIntegrationError("SOS_CODEX_SETUP_PLAN_STALE", Status.STALE)
        targets.append((plan["target"], updated))
    return tuple(targets)


def probe_codex_bootstrap_setup(setup: CodexBootstrapSetup) -> str:
    """Return before/after/drift for the complete ordered target set."""
    _apply_step, _rollback_step, probe_step = _setup_callbacks(
        setup.root, setup.manifest, setup.binding
    )
    states = [probe_step(plan) for plan in setup.manifest["plans"]]
    if all(state == "before" for state in states):
        return "before"
    if all(state == "after" for state in states):
        return "after"
    return "drift"


def apply_codex_bootstrap_setup(setup: CodexBootstrapSetup) -> None:
    """Apply the exact ordered targets; reverse completed steps on failure."""
    apply_step, rollback_step, probe_step = _setup_callbacks(
        setup.root, setup.manifest, setup.binding
    )
    applied: list[dict[str, Any]] = []
    try:
        for plan in setup.manifest["plans"]:
            if probe_step(plan) != "before":
                raise ClientIntegrationError("SOS_CODEX_SETUP_TARGET_DRIFT", Status.STALE)
            apply_step(plan)
            if probe_step(plan) != "after":
                raise ClientIntegrationError("SOS_CODEX_SETUP_TARGET_DRIFT", Status.STALE)
            applied.append(plan)
    except BaseException:
        for plan in reversed(applied):
            if probe_step(plan) == "after":
                rollback_step(plan)
        raise


def rollback_codex_bootstrap_setup(setup: CodexBootstrapSetup) -> None:
    """Rollback an applied bootstrap setup in exact reverse order."""
    _apply_step, rollback_step, probe_step = _setup_callbacks(
        setup.root, setup.manifest, setup.binding
    )
    for plan in reversed(setup.manifest["plans"]):
        observed = probe_step(plan)
        if observed == "after":
            rollback_step(plan)
        elif observed != "before":
            raise ClientIntegrationError("SOS_CODEX_SETUP_TARGET_DRIFT", Status.STALE)


def render_codex_bootstrap_control_files(setup: CodexBootstrapSetup) -> dict[str, bytes]:
    """Render the already-applied setup into the atomic canonical control plane."""
    installed = _with_setup_state(setup.manifest, "installed")
    files = render_applied_managed_file_batch_files(installed["batch"], installed["plans"])
    files[_SETUP_MANIFEST] = json.dumps(
        installed, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")
    return files


def observe_installed_launcher() -> LauncherBinding:
    try:
        observed = current_platform_services().observe_launcher(_CLIENT)
    except PlatformServiceError as exc:
        reason = (
            "SOS_CLIENT_PACKAGE_NOT_INSTALLED"
            if exc.kind == "package_not_installed"
            else "SOS_CLIENT_LAUNCHER_INVALID"
        )
        raise ClientIntegrationError(reason, Status.UNSUPPORTED) from exc
    if observed.package_version != __version__:
        raise ClientIntegrationError("SOS_CLIENT_PACKAGE_VERSION_MISMATCH", Status.STALE)
    if observed.editable_install:
        raise ClientIntegrationError("SOS_CLIENT_EDITABLE_PACKAGE_UNSUPPORTED", Status.UNSUPPORTED)
    return LauncherBinding(
        os.fspath(observed.executable),
        observed.package_version,
        observed.executable_digest,
    )


def preview_client_install(
    path: str = ".", client: str = _CLIENT, *, launcher: LauncherBinding | None = None
) -> TerminalResult:
    if client != _CLIENT:
        return _result(Status.UNSUPPORTED, "SOS_CLIENT_UNSUPPORTED")
    try:
        root = discover_repository_root(path)
        binding = launcher or observe_installed_launcher()
        setup = _read_setup_manifest(root)
        if setup is not None and setup["state"] != "removed":
            return codex_setup_status(os.fspath(root), launcher=binding)
        root, repository_id = _ready_root(os.fspath(root), allow_stale_installed=True)
        manifest = _read_manifest(root)
        if manifest is None:
            _require_no_orphan_journal(root)
        else:
            state = manifest["state"]
            if state == "installed":
                _verify_installed(root, manifest, binding)
                return _result(Status.SUCCESS, "SOS_CLIENT_ALREADY_INSTALLED", manifest)
            if state in {"install_prepared", "remove_prepared"}:
                return _result(Status.BLOCKED, "SOS_CLIENT_RECOVERY_REQUIRED", manifest)
            _require_journal(root, manifest, "rolled_back")
        current = workspace_status(os.fspath(root))
        if current.status != Status.SUCCESS:
            return TerminalResult(_RESULT_CONTRACT, current.status, current.reasons, _safe_details(None))
        original, existed, parent_existed = _read_target(root)
        addition = _render_addition(root, binding, original)
        updated = original + addition
        _validate_toml(updated)
        prepared = _manifest(
            state="install_prepared",
            repository_id=repository_id,
            binding=binding,
            original=original,
            original_existed=existed,
            parent_existed=parent_existed,
            addition=addition,
            updated=updated,
        )
        return _result(Status.OWNER_REQUIRED, "SOS_CLIENT_INSTALL_CONFIRMATION_REQUIRED", prepared)
    except (ClientIntegrationError, ManagedFileError, RepositoryError, WorkspaceError, OSError) as exc:
        return _error_result(exc)


def install_client(
    path: str = ".",
    client: str = _CLIENT,
    *,
    confirmed: bool,
    controlling_tty_observed: bool = False,
    launcher: LauncherBinding | None = None,
) -> TerminalResult:
    if client != _CLIENT:
        return _result(Status.UNSUPPORTED, "SOS_CLIENT_UNSUPPORTED")
    if not confirmed:
        return preview_client_install(path, client, launcher=launcher)
    if not controlling_tty_observed:
        return _result(Status.OWNER_REQUIRED, "SOS_CLIENT_TTY_REQUIRED")
    try:
        root = discover_repository_root(path)
        binding = launcher or observe_installed_launcher()
        setup = _read_setup_manifest(root)
        if setup is not None and setup["state"] != "removed":
            return codex_setup_status(os.fspath(root), launcher=binding)
        root, repository_id = _ready_root(os.fspath(root), allow_stale_installed=True)
        existing = _read_manifest(root)
        if existing is None:
            _require_no_orphan_journal(root)
        elif existing["state"] == "removed":
            _require_journal(root, existing, "rolled_back")
        if existing is not None and existing["state"] == "installed":
            _verify_installed(root, existing, binding)
            return _result(Status.SUCCESS, "SOS_CLIENT_ALREADY_INSTALLED", existing)
        if existing is not None and existing["state"] == "remove_prepared":
            raise ClientIntegrationError("SOS_CLIENT_REMOVE_RECOVERY_REQUIRED", Status.BLOCKED)
        if existing is not None and existing["state"] == "install_prepared":
            prepared = existing
            _verify_manifest_binding(prepared, repository_id, binding)
            original, existed, _ = _read_target(root)
            if _bytes_digest(original) == prepared["configured_digest"] and existed:
                _ensure_journal_state(root, prepared, "applied")
                installed = _with_state(prepared, "installed")
                _write_manifest(root, installed)
                return _result(Status.SUCCESS, "SOS_CLIENT_INSTALL_RECOVERED", installed)
            if _bytes_digest(original) != prepared["original_digest"] or existed != prepared["original_existed"]:
                raise ClientIntegrationError("SOS_CLIENT_CONFIG_DRIFT", Status.STALE)
            addition = _render_addition(root, binding, original)
            updated = original + addition
            if _bytes_digest(addition) != prepared["managed_addition_digest"] or _bytes_digest(updated) != prepared["configured_digest"]:
                raise ClientIntegrationError("SOS_CLIENT_PLAN_STALE", Status.STALE)
        else:
            current = workspace_status(os.fspath(root))
            if current.status != Status.SUCCESS:
                return TerminalResult(_RESULT_CONTRACT, current.status, current.reasons, _safe_details(None))
            original, existed, parent_existed = _read_target(root)
            addition = _render_addition(root, binding, original)
            updated = original + addition
            _validate_toml(updated)
            prepared = _manifest(
                state="install_prepared",
                repository_id=repository_id,
                binding=binding,
                original=original,
                original_existed=existed,
                parent_existed=parent_existed,
                addition=addition,
                updated=updated,
            )
            _write_manifest(root, prepared)
        _ensure_journal_state(root, prepared, "apply_prepared")
        _replace_target(root, updated, expected=original, expected_existed=existed)
        _ensure_journal_state(root, prepared, "applied")
        installed = _with_state(prepared, "installed")
        _write_manifest(root, installed)
        return _result(Status.SUCCESS, "SOS_CLIENT_INSTALLED", installed)
    except (ClientIntegrationError, ManagedFileError, RepositoryError, WorkspaceError, OSError) as exc:
        return _error_result(exc)


def client_status(
    path: str = ".", client: str = _CLIENT, *, launcher: LauncherBinding | None = None
) -> TerminalResult:
    if client != _CLIENT:
        return _result(Status.UNSUPPORTED, "SOS_CLIENT_UNSUPPORTED")
    try:
        root = discover_repository_root(path)
        setup = _read_setup_manifest(root)
        if setup is not None and setup["state"] != "removed":
            return codex_setup_status(os.fspath(root), launcher=launcher)
        workspace = workspace_status(os.fspath(root))
        manifest = _read_manifest(root)
        if manifest is None:
            _require_no_orphan_journal(root)
            return _result(Status.SUCCESS, "SOS_CLIENT_NOT_INSTALLED", manifest)
        if manifest["state"] == "removed":
            _require_journal(root, manifest, "rolled_back")
            return _result(Status.SUCCESS, "SOS_CLIENT_NOT_INSTALLED", manifest)
        if manifest["state"] != "installed":
            return _result(Status.BLOCKED, "SOS_CLIENT_RECOVERY_REQUIRED", manifest)
        if workspace.status == Status.INVALID or workspace.details.get("repository_id") != manifest["repository_id"]:
            raise ClientIntegrationError("SOS_CLIENT_REPOSITORY_MISMATCH", Status.STALE)
        binding = launcher or observe_installed_launcher()
        _verify_installed(root, manifest, binding)
        return _result(Status.SUCCESS, "SOS_CLIENT_INSTALLED", manifest)
    except (ClientIntegrationError, ManagedFileError, RepositoryError, WorkspaceError, OSError) as exc:
        return _error_result(exc)


def remove_client(
    path: str = ".",
    client: str = _CLIENT,
    *,
    confirmed: bool,
    controlling_tty_observed: bool = False,
    launcher: LauncherBinding | None = None,
) -> TerminalResult:
    if client != _CLIENT:
        return _result(Status.UNSUPPORTED, "SOS_CLIENT_UNSUPPORTED")
    if not confirmed:
        status = client_status(path, client, launcher=launcher)
        if status.status != Status.SUCCESS or "SOS_CLIENT_NOT_INSTALLED" in status.reasons:
            return status
        return TerminalResult(
            _RESULT_CONTRACT,
            Status.OWNER_REQUIRED,
            ("SOS_CLIENT_REMOVE_CONFIRMATION_REQUIRED",),
            status.details,
        )
    if not controlling_tty_observed:
        return _result(Status.OWNER_REQUIRED, "SOS_CLIENT_TTY_REQUIRED")
    try:
        root = discover_repository_root(path)
        setup = _read_setup_manifest(root)
        if setup is not None and setup["state"] != "removed":
            return remove_codex_setup(
                os.fspath(root),
                confirmed=True,
                controlling_tty_observed=controlling_tty_observed,
                launcher=launcher,
            )
        root, repository_id = _ready_root(os.fspath(root), allow_stale_installed=True)
        manifest = _read_manifest(root)
        if manifest is None:
            _require_no_orphan_journal(root)
            return _result(Status.SUCCESS, "SOS_CLIENT_ALREADY_REMOVED", manifest)
        if manifest["state"] == "removed":
            _require_journal(root, manifest, "rolled_back")
            return _result(Status.SUCCESS, "SOS_CLIENT_ALREADY_REMOVED", manifest)
        if manifest["repository_id"] != repository_id:
            raise ClientIntegrationError("SOS_CLIENT_REPOSITORY_MISMATCH", Status.STALE)
        if manifest["state"] == "install_prepared":
            raise ClientIntegrationError("SOS_CLIENT_INSTALL_RECOVERY_REQUIRED", Status.BLOCKED)
        if manifest["state"] == "installed":
            _verify_removable(root, manifest)
            _require_journal(root, manifest, "applied")
            removing = _with_state(manifest, "remove_prepared")
            _write_manifest(root, removing)
        elif manifest["state"] == "remove_prepared":
            removing = manifest
        else:
            raise ClientIntegrationError("SOS_CLIENT_MANIFEST_INVALID")
        _ensure_journal_state(root, removing, "rollback_prepared")
        current, exists, _ = _read_target(root)
        if exists and _bytes_digest(current) == removing["configured_digest"]:
            original_length = removing["original_byte_count"]
            original = current[:original_length]
            addition = current[original_length:]
            if _bytes_digest(original) != removing["original_digest"] or _bytes_digest(addition) != removing["managed_addition_digest"]:
                raise ClientIntegrationError("SOS_CLIENT_CONFIG_DRIFT", Status.STALE)
            _restore_target(
                root,
                original,
                original_existed=removing["original_existed"],
                parent_existed=removing["parent_existed"],
                expected=current,
            )
        else:
            expected_removed = not removing["original_existed"] and not exists
            expected_restored = removing["original_existed"] and exists and _bytes_digest(current) == removing["original_digest"]
            if not (expected_removed or expected_restored):
                raise ClientIntegrationError("SOS_CLIENT_CONFIG_DRIFT", Status.STALE)
        _ensure_journal_state(root, removing, "rolled_back")
        removed = _with_state(removing, "removed")
        _write_manifest(root, removed)
        return _result(Status.SUCCESS, "SOS_CLIENT_REMOVED", removed)
    except (ClientIntegrationError, ManagedFileError, RepositoryError, WorkspaceError, OSError) as exc:
        return _error_result(exc)


def preview_codex_setup(
    path: str = ".", *, launcher: LauncherBinding | None = None
) -> TerminalResult:
    """Preview the two-target Codex-first consumer without writing state."""
    try:
        root, repository_id = _ready_setup_root(path, require_current=True)
        binding = launcher or observe_installed_launcher()
        existing = _read_setup_manifest(root)
        if existing is not None and existing["state"] != "removed":
            return codex_setup_status(path, launcher=binding)
        legacy = _read_manifest(root)
        if legacy is not None and legacy["state"] != "removed":
            raise ClientIntegrationError("SOS_CODEX_SETUP_LEGACY_CLIENT_PRESENT", Status.BLOCKED)
        prepared = _prepare_setup(root, repository_id, binding)
        return _setup_result(Status.OWNER_REQUIRED, "SOS_CODEX_SETUP_CONFIRMATION_REQUIRED", prepared)
    except (ClientIntegrationError, ManagedFileBatchError, ManagedFileError, RepositoryError, WorkspaceError, OSError) as exc:
        return _setup_error_result(exc)


def install_codex_setup(
    path: str = ".",
    *,
    confirmed: bool,
    controlling_tty_observed: bool = False,
    launcher: LauncherBinding | None = None,
    require_current: bool = True,
) -> TerminalResult:
    """Install the exact instruction/config batch after one local confirmation."""
    if not confirmed:
        return preview_codex_setup(path, launcher=launcher)
    if not controlling_tty_observed:
        return _setup_result(Status.OWNER_REQUIRED, "SOS_CODEX_SETUP_TTY_REQUIRED")
    try:
        root = discover_repository_root(path)
        binding = launcher or observe_installed_launcher()
        existing = _read_setup_manifest(root)
        if existing is not None and existing["state"] == "installed":
            _verify_setup(root, existing, binding, expected_state="integrated")
            return _setup_result(Status.SUCCESS, "SOS_CODEX_SETUP_ALREADY_INSTALLED", existing)
        if existing is not None and existing["state"] == "remove_prepared":
            raise ClientIntegrationError("SOS_CODEX_SETUP_RECOVERY_REQUIRED", Status.BLOCKED)
        if existing is None or existing["state"] == "removed":
            root, repository_id = _ready_setup_root(path, require_current=require_current)
            legacy = _read_manifest(root)
            if legacy is not None and legacy["state"] != "removed":
                raise ClientIntegrationError("SOS_CODEX_SETUP_LEGACY_CLIENT_PRESENT", Status.BLOCKED)
            prepared = _prepare_setup(root, repository_id, binding)
            _write_setup_manifest(root, prepared)
        else:
            prepared = existing
            _verify_setup_binding(prepared, binding)
        projection = project_managed_file_batch(root, prepared["batch"])
        if projection["state"] == "integration_incomplete":
            raise ClientIntegrationError("SOS_CODEX_SETUP_RECOVERY_REQUIRED", Status.BLOCKED)
        apply_step, rollback_step, probe_step = _setup_callbacks(root, prepared, binding)
        projection = coordinate_managed_file_batch(
            root,
            prepared["batch"],
            prepared["plans"],
            apply_step=apply_step,
            rollback_step=rollback_step,
            probe_step=probe_step,
        )
        if projection["state"] != "integrated":
            raise ClientIntegrationError("SOS_CODEX_SETUP_RECOVERY_REQUIRED", Status.BLOCKED)
        installed = _with_setup_state(prepared, "installed")
        _write_setup_manifest(root, installed)
        return _setup_result(Status.SUCCESS, "SOS_CODEX_SETUP_INSTALLED", installed, projection)
    except (ClientIntegrationError, ManagedFileBatchError, ManagedFileError, RepositoryError, WorkspaceError, OSError) as exc:
        return _setup_error_result(exc)


def codex_setup_status(
    path: str = ".", *, launcher: LauncherBinding | None = None
) -> TerminalResult:
    """Project the aggregate consumer state without repairing or mutating it."""
    try:
        root = discover_repository_root(path)
        manifest = _read_setup_manifest(root)
        if manifest is None:
            return _setup_result(Status.SUCCESS, "SOS_CODEX_SETUP_NOT_INSTALLED")
        projection = project_managed_file_batch(root, manifest["batch"])
        if manifest["state"] == "removed" and projection["state"] == "rolled_back":
            return _setup_result(Status.SUCCESS, "SOS_CODEX_SETUP_NOT_INSTALLED", manifest, projection)
        if manifest["state"] != "installed" or projection["state"] != "integrated":
            return _setup_result(Status.BLOCKED, "SOS_CODEX_SETUP_RECOVERY_REQUIRED", manifest, projection)
        binding = launcher or observe_installed_launcher()
        _verify_setup(root, manifest, binding, expected_state="integrated")
        workspace = workspace_status(os.fspath(root))
        if workspace.status == Status.INVALID or workspace.details.get("repository_id") != manifest["repository_id"]:
            raise ClientIntegrationError("SOS_CLIENT_REPOSITORY_MISMATCH", Status.STALE)
        return _setup_result(Status.SUCCESS, "SOS_CODEX_SETUP_INSTALLED", manifest, projection)
    except (ClientIntegrationError, ManagedFileBatchError, ManagedFileError, RepositoryError, WorkspaceError, OSError) as exc:
        return _setup_error_result(exc)


def preview_codex_setup_update(
    path: str = ".", *, launcher: LauncherBinding | None = None
) -> TerminalResult:
    """Preview replacement of one exact historical managed setup."""
    try:
        root = discover_repository_root(path)
        binding = launcher or observe_installed_launcher()
        manifest = _read_setup_manifest(root)
        if manifest is None:
            return preview_codex_setup(path, launcher=binding)
        if manifest["state"] == "removed":
            root, repository_id = _ready_setup_root(path, require_current=False)
            if manifest["repository_id"] != repository_id:
                raise ClientIntegrationError("SOS_CLIENT_REPOSITORY_MISMATCH", Status.STALE)
            projection = project_managed_file_batch(root, manifest["batch"])
            if projection["state"] != "rolled_back":
                raise ClientIntegrationError("SOS_CODEX_SETUP_RECOVERY_REQUIRED", Status.BLOCKED)
            prepared = _prepare_setup(root, repository_id, binding)
            target_bytes = _prepared_setup_target_bytes(root, binding, prepared)
            projected = project_workspace_application(path, overlays=dict(target_bytes))
            if projected.status != Status.SUCCESS:
                raise ClientIntegrationError(
                    projected.reasons[0] if projected.reasons else "SOS_SOURCE_STATUS_CHANGED",
                    projected.status,
                )
            details = _setup_details(prepared)
            details.update(
                {
                    "update_state": "previewed_recovery",
                    "one_confirmation": True,
                    "rollback_before_reinstall": False,
                    "enabled_tools": list(_TOOLS),
                }
            )
            return TerminalResult(
                _RESULT_CONTRACT,
                Status.OWNER_REQUIRED,
                ("SOS_CODEX_SETUP_UPDATE_CONFIRMATION_REQUIRED",),
                details,
            )
        if manifest["state"] != "installed":
            raise ClientIntegrationError("SOS_CODEX_SETUP_RECOVERY_REQUIRED", Status.BLOCKED)
        _verify_setup(
            root,
            manifest,
            binding,
            expected_state="integrated",
            require_current_contract=False,
            require_binding=False,
        )
        try:
            _verify_setup(root, manifest, binding, expected_state="integrated")
        except ClientIntegrationError as exc:
            if exc.reason not in {"SOS_CODEX_SETUP_CONTRACT_STALE", "SOS_CLIENT_LAUNCHER_STALE"}:
                raise
        else:
            return _setup_result(Status.SUCCESS, "SOS_CODEX_SETUP_ALREADY_CURRENT", manifest)
        details = _setup_details(manifest, project_managed_file_batch(root, manifest["batch"]))
        details.update(
            {
                "update_state": "previewed",
                "one_confirmation": True,
                "rollback_before_reinstall": True,
                "enabled_tools": list(_TOOLS),
            }
        )
        return TerminalResult(
            _RESULT_CONTRACT,
            Status.OWNER_REQUIRED,
            ("SOS_CODEX_SETUP_UPDATE_CONFIRMATION_REQUIRED",),
            details,
        )
    except (ClientIntegrationError, ManagedFileBatchError, ManagedFileError, RepositoryError, WorkspaceError, OSError) as exc:
        return _setup_error_result(exc)


def project_codex_package_update(
    path: str = ".", *, launcher: LauncherBinding | None = None
) -> TerminalResult:
    """Project only the local package binding delta; never acquire or mutate."""
    try:
        root = discover_repository_root(path)
        manifest = _read_setup_manifest(root)
        if manifest is None or manifest["state"] == "removed":
            return TerminalResult(
                "sos_codex_package_update_projection_v1",
                Status.NOT_VERIFIED,
                ("SOS_UPDATE_NOT_CONFIGURED",),
                {"configuration_state": "not_configured"},
            )
        if manifest["state"] != "installed":
            raise ClientIntegrationError("SOS_CODEX_SETUP_RECOVERY_REQUIRED", Status.BLOCKED)
        projection = project_managed_file_batch(root, manifest["batch"])
        if projection["state"] != "integrated":
            raise ClientIntegrationError("SOS_CODEX_SETUP_RECOVERY_REQUIRED", Status.BLOCKED)
        binding = launcher or observe_installed_launcher()
        changed = (
            manifest["package_version"] != binding.package_version
            or manifest["launcher_digest"] != binding.digest
        )
        workspace = workspace_status(os.fspath(root))
        return TerminalResult(
            "sos_codex_package_update_projection_v1",
            Status.SUCCESS,
            ("SOS_UPDATE_AVAILABLE" if changed else "SOS_UPDATE_NOT_REQUIRED",),
            {
                "configuration_state": "update_available" if changed else "current",
                "installed_package_version": manifest["package_version"],
                "installed_launcher_digest": manifest["launcher_digest"],
                "proposed_package_version": binding.package_version,
                "proposed_launcher_digest": binding.digest,
                "setup_update_command": "sos setup update codex PATH" if changed else None,
                "agent_restart_required": changed,
                "qualification_integrity": workspace.details.get("qualification_integrity"),
                "qualification_rerun_required": workspace.details.get("qualification_integrity") != "valid",
                "affected_project_scope": manifest["repository_id"],
                "tool_environment_inventory": "not_available",
                "other_projects_fail_closed_on_next_open": changed,
                "predecessor_artifact_retention_required": changed,
                "proposal_only": True,
                "writes_performed": False,
                "network_performed": False,
                "raw_project_content_serialized": False,
                "absolute_paths_serialized": False,
            },
        )
    except (ClientIntegrationError, ManagedFileBatchError, ManagedFileError, RepositoryError, OSError) as exc:
        return _setup_error_result(exc)


def update_codex_setup(
    path: str = ".",
    *,
    confirmed: bool,
    controlling_tty_observed: bool = False,
    launcher: LauncherBinding | None = None,
) -> TerminalResult:
    """Replace an exact stale setup through one previewed owner action."""
    if not confirmed:
        return preview_codex_setup_update(path, launcher=launcher)
    if not controlling_tty_observed:
        return _setup_result(Status.OWNER_REQUIRED, "SOS_CODEX_SETUP_TTY_REQUIRED")
    binding = launcher or observe_installed_launcher()
    preview = preview_codex_setup_update(path, launcher=binding)
    if preview.status == Status.SUCCESS:
        return preview
    if preview.status != Status.OWNER_REQUIRED:
        return preview
    require_current_after_update = (
        workspace_status(path).status == Status.SUCCESS
        or preview.details.get("update_state") == "previewed_recovery"
    )
    removed = remove_codex_setup(
        path,
        confirmed=True,
        controlling_tty_observed=True,
        launcher=binding,
        require_current_contract=False,
        require_binding=False,
    )
    if removed.status != Status.SUCCESS:
        return removed
    installed = install_codex_setup(
        path,
        confirmed=True,
        controlling_tty_observed=True,
        launcher=binding,
        require_current=False,
    )
    if installed.status != Status.SUCCESS:
        details = dict(installed.details)
        details["update_state"] = "rolled_back_not_installed"
        details["update_failure_reasons"] = list(installed.reasons)
        return TerminalResult(
            _RESULT_CONTRACT,
            Status.BLOCKED,
            ("SOS_CODEX_SETUP_UPDATE_INCOMPLETE",),
            details,
        )
    current = workspace_status(path)
    if require_current_after_update and current.status != Status.SUCCESS:
        rollback = remove_codex_setup(
            path,
            confirmed=True,
            controlling_tty_observed=True,
            launcher=binding,
        )
        details = dict(current.details)
        details["update_state"] = "rolled_back_after_postcheck"
        details["rollback_status"] = rollback.status.value
        return TerminalResult(
            _RESULT_CONTRACT,
            current.status,
            current.reasons or ("SOS_CODEX_SETUP_UPDATE_POSTCHECK_FAILED",),
            details,
        )
    details = dict(installed.details)
    details["update_state"] = "updated"
    return TerminalResult(_RESULT_CONTRACT, Status.SUCCESS, ("SOS_CODEX_SETUP_UPDATED",), details)


def recover_codex_setup(
    path: str = ".", *, launcher: LauncherBinding | None = None
) -> TerminalResult:
    """Resolve an interrupted aggregate lifecycle only from exact probes."""
    try:
        root = discover_repository_root(path)
        manifest = _read_setup_manifest(root)
        if manifest is None:
            return _setup_result(Status.SUCCESS, "SOS_CODEX_SETUP_NOT_INSTALLED")
        binding = launcher or observe_installed_launcher()
        _verify_setup_binding(manifest, binding)
        apply_step, rollback_step, probe_step = _setup_callbacks(root, manifest, binding)
        projection = project_managed_file_batch(root, manifest["batch"])
        if projection["state"] == "integration_incomplete":
            projection = recover_managed_file_batch(
                root,
                manifest["batch"],
                apply_step=apply_step,
                rollback_step=rollback_step,
                probe_step=probe_step,
            )
        if manifest["state"] == "install_prepared" and projection["state"] == "integrated":
            installed = _with_setup_state(manifest, "installed")
            _write_setup_manifest(root, installed)
            return _setup_result(Status.SUCCESS, "SOS_CODEX_SETUP_INSTALL_RECOVERED", installed, projection)
        if projection["state"] == "rolled_back" and manifest["state"] in {"install_prepared", "remove_prepared"}:
            removed = _with_setup_state(manifest, "removed")
            _write_setup_manifest(root, removed)
            return _setup_result(Status.SUCCESS, "SOS_CODEX_SETUP_ROLLBACK_RECOVERED", removed, projection)
        if manifest["state"] == "installed" and projection["state"] == "integrated":
            _verify_setup(root, manifest, binding, expected_state="integrated")
            return _setup_result(Status.SUCCESS, "SOS_CODEX_SETUP_INSTALLED", manifest, projection)
        if manifest["state"] == "removed" and projection["state"] == "rolled_back":
            return _setup_result(Status.SUCCESS, "SOS_CODEX_SETUP_NOT_INSTALLED", manifest, projection)
        raise ClientIntegrationError("SOS_CODEX_SETUP_RECOVERY_REQUIRED", Status.BLOCKED)
    except (ClientIntegrationError, ManagedFileBatchError, ManagedFileError, RepositoryError, WorkspaceError, OSError) as exc:
        return _setup_error_result(exc)


def remove_codex_setup(
    path: str = ".",
    *,
    confirmed: bool,
    controlling_tty_observed: bool = False,
    launcher: LauncherBinding | None = None,
    require_current_contract: bool = True,
    require_binding: bool = True,
) -> TerminalResult:
    """Remove both exact managed targets while preserving the control plane."""
    if not confirmed:
        status = codex_setup_status(path, launcher=launcher)
        if status.status != Status.SUCCESS or "SOS_CODEX_SETUP_NOT_INSTALLED" in status.reasons:
            return status
        return TerminalResult(
            _RESULT_CONTRACT,
            Status.OWNER_REQUIRED,
            ("SOS_CODEX_SETUP_REMOVE_CONFIRMATION_REQUIRED",),
            status.details,
        )
    if not controlling_tty_observed:
        return _setup_result(Status.OWNER_REQUIRED, "SOS_CODEX_SETUP_TTY_REQUIRED")
    try:
        root = discover_repository_root(path)
        manifest = _read_setup_manifest(root)
        if manifest is None:
            return _setup_result(Status.SUCCESS, "SOS_CODEX_SETUP_ALREADY_REMOVED")
        if manifest["state"] == "removed":
            projection = project_managed_file_batch(root, manifest["batch"])
            if projection["state"] != "rolled_back":
                raise ClientIntegrationError("SOS_CODEX_SETUP_RECOVERY_REQUIRED", Status.BLOCKED)
            return _setup_result(Status.SUCCESS, "SOS_CODEX_SETUP_ALREADY_REMOVED", manifest, projection)
        if manifest["state"] == "install_prepared":
            raise ClientIntegrationError("SOS_CODEX_SETUP_RECOVERY_REQUIRED", Status.BLOCKED)
        binding = launcher or observe_installed_launcher()
        if require_binding:
            _verify_setup_binding(manifest, binding)
        else:
            _validate_setup_manifest(manifest)
        if manifest["state"] == "installed":
            _verify_setup(
                root,
                manifest,
                binding,
                expected_state="integrated",
                require_current_contract=require_current_contract,
                require_binding=require_binding,
            )
            removing = _with_setup_state(manifest, "remove_prepared")
            _write_setup_manifest(root, removing)
        elif manifest["state"] == "remove_prepared":
            removing = manifest
        else:
            raise ClientIntegrationError("SOS_CODEX_SETUP_MANIFEST_INVALID")
        _, rollback_step, probe_step = _setup_callbacks(root, removing, binding)
        projection = rollback_managed_file_batch(
            root,
            removing["batch"],
            rollback_step=rollback_step,
            probe_step=probe_step,
        )
        if projection["state"] != "rolled_back":
            raise ClientIntegrationError("SOS_CODEX_SETUP_RECOVERY_REQUIRED", Status.BLOCKED)
        removed = _with_setup_state(removing, "removed")
        _write_setup_manifest(root, removed)
        return _setup_result(Status.SUCCESS, "SOS_CODEX_SETUP_REMOVED", removed, projection)
    except (ClientIntegrationError, ManagedFileBatchError, ManagedFileError, RepositoryError, WorkspaceError, OSError) as exc:
        return _setup_error_result(exc)


def launcher_config(root: Path, binding: LauncherBinding) -> dict[str, Any]:
    """Return the exact supported Codex configuration without receipt paths."""
    return {
        "command": binding.command,
        "args": [
            "-m",
            "sos",
            "mcp",
            "--root",
            os.fspath(root),
        ],
        "cwd": os.fspath(root),
        "enabled": True,
        "required": False,
        "enabled_tools": list(_TOOLS),
        "default_tools_approval_mode": "writes",
    }


def _ready_setup_root(path: str, *, require_current: bool) -> tuple[Path, str]:
    root = discover_repository_root(path)
    status = workspace_status(os.fspath(root))
    repository_id = status.details.get("repository_id")
    if not isinstance(repository_id, str):
        raise ClientIntegrationError(status.reasons[0] if status.reasons else "SOS_WORKSPACE_NOT_READY", status.status)
    if require_current and status.status != Status.SUCCESS:
        raise ClientIntegrationError(status.reasons[0] if status.reasons else "SOS_WORKSPACE_NOT_READY", status.status)
    return root, repository_id


def _prepare_setup(root: Path, repository_id: str, binding: LauncherBinding) -> dict[str, Any]:
    instruction_original, instruction_existed = _read_instruction_target(root)
    instruction_mode = _read_setup_target_mode(root, _INSTRUCTION_TARGET, instruction_existed, 0o644)
    if _INSTRUCTION_BEGIN.encode() in instruction_original or _INSTRUCTION_END.encode() in instruction_original:
        raise ClientIntegrationError("SOS_CODEX_SETUP_INSTRUCTION_COLLISION", Status.BLOCKED)
    instruction_addition = _render_instruction_addition(instruction_original)
    instruction_updated = instruction_original + instruction_addition
    config_original, config_existed, config_parent_existed = _read_target(root)
    config_mode = _read_setup_target_mode(root, _TARGET, config_existed, 0o600)
    config_addition = _render_addition(root, binding, config_original)
    config_updated = config_original + config_addition
    _validate_toml(config_updated)
    instruction_plan = _build_setup_plan(
        journal_id=_SETUP_INSTRUCTION_JOURNAL_ID,
        repository_id=repository_id,
        target=_INSTRUCTION_TARGET,
        original=instruction_original,
        existed=instruction_existed,
        addition=instruction_addition,
        updated=instruction_updated,
    )
    config_plan = _build_setup_plan(
        journal_id=_SETUP_JOURNAL_ID,
        repository_id=repository_id,
        target=_TARGET,
        original=config_original,
        existed=config_existed,
        addition=config_addition,
        updated=config_updated,
    )
    plans = [instruction_plan, config_plan]
    seed = digest_value([plan["plan_digest"] for plan in plans]).removeprefix("sha256:")[:16]
    batch = build_managed_file_batch(
        batch_id=f"{_SETUP_BATCH_ID}-{seed}", repository_id=repository_id, plans=plans
    )
    manifest = {
        "contract": _SETUP_CONTRACT,
        "client": _CLIENT,
        "state": "install_prepared",
        "repository_id": repository_id,
        "batch": batch,
        "plans": plans,
        "launcher_digest": binding.digest,
        "package_version": binding.package_version,
        "config_parent_existed": config_parent_existed,
        "instruction_mode": instruction_mode,
        "config_mode": config_mode,
        "raw_content_serialized": False,
        "absolute_paths_serialized": False,
        "strong_authentication_claimed": False,
        "agent_invocation_prevented": False,
        "manifest_digest": "sha256:" + "0" * 64,
    }
    manifest["manifest_digest"] = _setup_manifest_digest(manifest)
    _validate_setup_manifest(manifest)
    return manifest


def _build_setup_plan(
    *,
    journal_id: str,
    repository_id: str,
    target: str,
    original: bytes,
    existed: bool,
    addition: bytes,
    updated: bytes,
) -> dict[str, Any]:
    return build_managed_file_plan(
        journal_id=journal_id,
        repository_id=repository_id,
        target=target,
        patch_kind="append_suffix" if existed else "create_file",
        before_exists=existed,
        before_byte_count=len(original),
        before_digest=_bytes_digest(original),
        patch_byte_count=len(addition),
        patch_digest=_bytes_digest(addition),
        after_byte_count=len(updated),
        after_digest=_bytes_digest(updated),
    )


def _render_instruction_addition(original: bytes) -> bytes:
    separator = b"" if not original else (b"\n" if original.endswith(b"\n") else b"\n\n")
    return separator + _INSTRUCTION_BLOCK


def _setup_callbacks(
    root: Path, manifest: dict[str, Any], binding: LauncherBinding
) -> tuple[Any, Any, Any]:
    plans = {plan["plan_digest"]: plan for plan in manifest["plans"]}

    def probe(plan: dict[str, Any]) -> str:
        _require_setup_plan(plan, plans)
        current, existed = _read_setup_target(root, plan["target"])
        if existed == plan["before_exists"] and len(current) == plan["before_byte_count"] and _bytes_digest(current) == plan["before_digest"]:
            return "before"
        if existed and len(current) == plan["after_byte_count"] and _bytes_digest(current) == plan["after_digest"]:
            return "after"
        return "drift"

    def apply(plan: dict[str, Any]) -> None:
        _require_setup_plan(plan, plans)
        current, existed = _read_setup_target(root, plan["target"])
        if probe(plan) != "before":
            raise ClientIntegrationError("SOS_CODEX_SETUP_TARGET_DRIFT", Status.STALE)
        if plan["target"] == _INSTRUCTION_TARGET:
            addition = _render_instruction_addition(current)
        elif plan["target"] == _TARGET:
            addition = _render_addition(root, binding, current)
        else:
            raise ClientIntegrationError("SOS_CODEX_SETUP_PLAN_INVALID")
        updated = current + addition
        _require_setup_payload(plan, current, addition, updated)
        if plan["target"] == _INSTRUCTION_TARGET:
            _replace_instruction_target(
                root,
                updated,
                expected=current,
                expected_existed=existed,
                mode=manifest["instruction_mode"],
            )
        else:
            _validate_toml(updated)
            _replace_target(
                root,
                updated,
                expected=current,
                expected_existed=existed,
                mode=manifest["config_mode"],
            )

    def rollback(plan: dict[str, Any]) -> None:
        _require_setup_plan(plan, plans)
        current, existed = _read_setup_target(root, plan["target"])
        if not existed or probe(plan) != "after":
            raise ClientIntegrationError("SOS_CODEX_SETUP_TARGET_DRIFT", Status.STALE)
        original = current[: plan["before_byte_count"]]
        addition = current[plan["before_byte_count"] :]
        _require_setup_payload(plan, original, addition, current)
        if plan["target"] == _INSTRUCTION_TARGET:
            _restore_instruction_target(
                root,
                original,
                original_existed=plan["before_exists"],
                expected=current,
                mode=manifest["instruction_mode"],
            )
        else:
            _restore_target(
                root,
                original,
                original_existed=plan["before_exists"],
                parent_existed=manifest["config_parent_existed"],
                expected=current,
                mode=manifest["config_mode"],
            )

    return apply, rollback, probe


def _require_setup_plan(plan: dict[str, Any], plans: dict[str, dict[str, Any]]) -> None:
    if plans.get(plan.get("plan_digest")) != plan or plan.get("target") not in {_INSTRUCTION_TARGET, _TARGET}:
        raise ClientIntegrationError("SOS_CODEX_SETUP_PLAN_INVALID", Status.STALE)


def _require_setup_payload(
    plan: dict[str, Any], original: bytes, addition: bytes, updated: bytes
) -> None:
    if (
        len(original) != plan["before_byte_count"]
        or _bytes_digest(original) != plan["before_digest"]
        or len(addition) != plan["patch_byte_count"]
        or _bytes_digest(addition) != plan["patch_digest"]
        or len(updated) != plan["after_byte_count"]
        or _bytes_digest(updated) != plan["after_digest"]
    ):
        raise ClientIntegrationError("SOS_CODEX_SETUP_PLAN_STALE", Status.STALE)


def _read_setup_target(root: Path, target: str) -> tuple[bytes, bool]:
    if target == _INSTRUCTION_TARGET:
        return _read_instruction_target(root)
    if target == _TARGET:
        payload, existed, _ = _read_target(root)
        return payload, existed
    raise ClientIntegrationError("SOS_CODEX_SETUP_PLAN_INVALID")


def _read_setup_target_mode(root: Path, target: str, existed: bool, default: int) -> int:
    if not existed:
        return default
    try:
        service = current_platform_services()
        with service.open_repository(root) as repository:
            observed = service.observe_object(repository, target)
        if observed.kind != "regular":
            raise ClientIntegrationError("SOS_CODEX_SETUP_TARGET_DRIFT", Status.STALE)
    except PlatformServiceError as exc:
        raise ClientIntegrationError("SOS_CODEX_SETUP_TARGET_DRIFT", Status.STALE) from exc
    return observed.mode


def _verify_setup(
    root: Path,
    manifest: dict[str, Any],
    binding: LauncherBinding,
    *,
    expected_state: str,
    require_current_contract: bool = True,
    require_binding: bool = True,
) -> None:
    if require_binding:
        _verify_setup_binding(manifest, binding)
    else:
        _validate_setup_manifest(manifest)
    projection = project_managed_file_batch(root, manifest["batch"])
    if projection["state"] != expected_state:
        raise ClientIntegrationError("SOS_CODEX_SETUP_RECOVERY_REQUIRED", Status.BLOCKED)
    _, _, probe = _setup_callbacks(root, manifest, binding)
    expected_probe = "after" if expected_state == "integrated" else "before"
    if any(probe(plan) != expected_probe for plan in manifest["plans"]):
        raise ClientIntegrationError("SOS_CODEX_SETUP_TARGET_DRIFT", Status.STALE)
    if require_current_contract and expected_state == "integrated":
        for plan in manifest["plans"]:
            current, existed = _read_setup_target(root, plan["target"])
            if not existed:
                raise ClientIntegrationError("SOS_CODEX_SETUP_TARGET_DRIFT", Status.STALE)
            original = current[: plan["before_byte_count"]]
            if plan["target"] == _INSTRUCTION_TARGET:
                expected = original + _render_instruction_addition(original)
            else:
                expected = original + _render_addition(root, binding, original)
            if current != expected:
                raise ClientIntegrationError("SOS_CODEX_SETUP_CONTRACT_STALE", Status.STALE)


def _verify_setup_binding(manifest: dict[str, Any], binding: LauncherBinding) -> None:
    _validate_setup_manifest(manifest)
    if manifest["launcher_digest"] != binding.digest or manifest["package_version"] != binding.package_version:
        raise ClientIntegrationError("SOS_CLIENT_LAUNCHER_STALE", Status.STALE)


def _ready_root(path: str, *, allow_stale_installed: bool) -> tuple[Path, str]:
    root = discover_repository_root(path)
    status = workspace_status(os.fspath(root))
    if status.status == Status.SUCCESS:
        return root, status.details["repository_id"]
    if allow_stale_installed:
        manifest = _read_manifest(root)
        observed_repository = status.details.get("repository_id")
        if manifest is not None and isinstance(observed_repository, str):
            if observed_repository != manifest["repository_id"]:
                raise ClientIntegrationError("SOS_CLIENT_REPOSITORY_MISMATCH", Status.STALE)
            return root, observed_repository
    raise ClientIntegrationError(status.reasons[0] if status.reasons else "SOS_WORKSPACE_NOT_READY", status.status)


def _render_addition(root: Path, binding: LauncherBinding, original: bytes) -> bytes:
    if _BEGIN.encode() in original or _END.encode() in original:
        raise ClientIntegrationError("SOS_CLIENT_MANAGED_BLOCK_COLLISION", Status.BLOCKED)
    try:
        parsed = tomllib.loads(original.decode("utf-8")) if original else {}
    except (UnicodeDecodeError, tomllib.TOMLDecodeError) as exc:
        raise ClientIntegrationError("SOS_CLIENT_CONFIG_INVALID") from exc
    servers = parsed.get("mcp_servers", {})
    if not isinstance(servers, dict) or _SERVER in servers:
        raise ClientIntegrationError("SOS_CLIENT_SERVER_COLLISION", Status.BLOCKED)
    config = launcher_config(root, binding)
    separator = b"" if not original else (b"\n" if original.endswith(b"\n") else b"\n\n")
    lines = [
        _BEGIN,
        f"[mcp_servers.{_SERVER}]",
        f"command = {_toml_string(config['command'])}",
        f"args = {_toml_array(config['args'])}",
        f"cwd = {_toml_string(config['cwd'])}",
        "enabled = true",
        "required = false",
        f"enabled_tools = {_toml_array(config['enabled_tools'])}",
        'default_tools_approval_mode = "writes"',
        _END,
        "",
    ]
    try:
        return separator + "\n".join(lines).encode("utf-8")
    except UnicodeEncodeError as exc:
        raise ClientIntegrationError("SOS_CLIENT_PATH_ENCODING_UNSUPPORTED", Status.UNSUPPORTED) from exc


def _validate_toml(updated: bytes) -> None:
    if len(updated) > _MAX_CONFIG_BYTES:
        raise ClientIntegrationError("SOS_CLIENT_CONFIG_LIMIT_EXCEEDED", Status.UNSUPPORTED)
    try:
        parsed = tomllib.loads(updated.decode("utf-8"))
    except (UnicodeDecodeError, tomllib.TOMLDecodeError) as exc:
        raise ClientIntegrationError("SOS_CLIENT_CONFIG_INVALID") from exc
    server = parsed.get("mcp_servers", {}).get(_SERVER)
    if not isinstance(server, dict) or set(server) != {
        "command", "args", "cwd", "enabled", "required", "enabled_tools", "default_tools_approval_mode"
    }:
        raise ClientIntegrationError("SOS_CLIENT_CONFIG_INVALID")


def _manifest(
    *,
    state: str,
    repository_id: str,
    binding: LauncherBinding,
    original: bytes,
    original_existed: bool,
    parent_existed: bool,
    addition: bytes,
    updated: bytes,
) -> dict[str, Any]:
    value = {
        "contract": _CONTRACT,
        "client": _CLIENT,
        "state": state,
        "repository_id": repository_id,
        "target": _TARGET,
        "original_existed": original_existed,
        "parent_existed": parent_existed,
        "original_byte_count": len(original),
        "original_digest": _bytes_digest(original),
        "managed_addition_byte_count": len(addition),
        "managed_addition_digest": _bytes_digest(addition),
        "configured_byte_count": len(updated),
        "configured_digest": _bytes_digest(updated),
        "launcher_digest": binding.digest,
        "package_version": binding.package_version,
        "absolute_paths_serialized": False,
        "raw_config_serialized": False,
        "manifest_digest": "sha256:" + "0" * 64,
    }
    value["manifest_digest"] = _manifest_digest(value)
    return value


def _with_state(manifest: dict[str, Any], state: str) -> dict[str, Any]:
    updated = dict(manifest)
    updated["state"] = state
    updated["manifest_digest"] = "sha256:" + "0" * 64
    updated["manifest_digest"] = _manifest_digest(updated)
    return updated


def _with_setup_state(manifest: dict[str, Any], state: str) -> dict[str, Any]:
    updated = dict(manifest)
    updated["state"] = state
    updated["manifest_digest"] = "sha256:" + "0" * 64
    updated["manifest_digest"] = _setup_manifest_digest(updated)
    _validate_setup_manifest(updated)
    return updated


def _read_setup_manifest(root: Path) -> dict[str, Any] | None:
    payload = _read_optional_platform_file(root, ".sigma/" + _SETUP_MANIFEST)
    if payload is None:
        return None
    try:
        value = json.loads(payload.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ClientIntegrationError("SOS_CODEX_SETUP_MANIFEST_INVALID") from exc
    _validate_setup_manifest(value)
    return value


def _write_setup_manifest(root: Path, manifest: dict[str, Any]) -> None:
    _validate_setup_manifest(manifest)
    payload = json.dumps(manifest, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
    if len(payload) > _MAX_CONFIG_BYTES:
        raise ClientIntegrationError("SOS_CODEX_SETUP_MANIFEST_INVALID")
    _publish_control_file(root, _SETUP_MANIFEST, payload)


def _validate_setup_manifest(value: object) -> None:
    required = {
        "contract", "client", "state", "repository_id", "batch", "plans",
        "launcher_digest", "package_version", "config_parent_existed",
        "instruction_mode", "config_mode",
        "raw_content_serialized", "absolute_paths_serialized",
        "strong_authentication_claimed", "agent_invocation_prevented", "manifest_digest",
    }
    if not isinstance(value, dict) or set(value) != required:
        raise ClientIntegrationError("SOS_CODEX_SETUP_MANIFEST_INVALID")
    if value["contract"] != _SETUP_CONTRACT or value["client"] != _CLIENT:
        raise ClientIntegrationError("SOS_CODEX_SETUP_MANIFEST_INVALID")
    if value["state"] not in {"install_prepared", "installed", "remove_prepared", "removed"}:
        raise ClientIntegrationError("SOS_CODEX_SETUP_MANIFEST_INVALID")
    if any(value[field] is not False for field in (
        "raw_content_serialized", "absolute_paths_serialized",
        "strong_authentication_claimed", "agent_invocation_prevented",
    )):
        raise ClientIntegrationError("SOS_CODEX_SETUP_MANIFEST_INVALID")
    if not isinstance(value["config_parent_existed"], bool):
        raise ClientIntegrationError("SOS_CODEX_SETUP_MANIFEST_INVALID")
    for field in ("instruction_mode", "config_mode"):
        if not isinstance(value[field], int) or isinstance(value[field], bool) or not 0 <= value[field] <= 0o777:
            raise ClientIntegrationError("SOS_CODEX_SETUP_MANIFEST_INVALID")
    if not isinstance(value["package_version"], str) or not value["package_version"]:
        raise ClientIntegrationError("SOS_CODEX_SETUP_MANIFEST_INVALID")
    for field in ("repository_id", "launcher_digest", "manifest_digest"):
        if not isinstance(value[field], str) or re.fullmatch(r"sha256:[0-9a-f]{64}", value[field]) is None:
            raise ClientIntegrationError("SOS_CODEX_SETUP_MANIFEST_INVALID")
    plans = value["plans"]
    batch = value["batch"]
    if not isinstance(plans, list) or len(plans) != 2 or not isinstance(batch, dict):
        raise ClientIntegrationError("SOS_CODEX_SETUP_MANIFEST_INVALID")
    try:
        expected = build_managed_file_batch(
            batch_id=batch["batch_id"], repository_id=value["repository_id"], plans=plans
        )
    except (KeyError, ManagedFileError) as exc:
        raise ClientIntegrationError("SOS_CODEX_SETUP_MANIFEST_INVALID") from exc
    if expected != batch:
        raise ClientIntegrationError("SOS_CODEX_SETUP_MANIFEST_INVALID")
    journal_ids = [plan.get("journal_id") for plan in plans]
    if journal_ids not in (
        [_INSTRUCTION_JOURNAL_ID, _JOURNAL_ID],
        [_SETUP_INSTRUCTION_JOURNAL_ID, _SETUP_JOURNAL_ID],
    ):
        raise ClientIntegrationError("SOS_CODEX_SETUP_MANIFEST_INVALID")
    if [plan.get("target") for plan in plans] != [_INSTRUCTION_TARGET, _TARGET]:
        raise ClientIntegrationError("SOS_CODEX_SETUP_MANIFEST_INVALID")
    if value["manifest_digest"] != _setup_manifest_digest(value):
        raise ClientIntegrationError("SOS_CODEX_SETUP_MANIFEST_INVALID")


def _setup_manifest_digest(value: dict[str, Any]) -> str:
    material = dict(value)
    material["manifest_digest"] = "sha256:" + "0" * 64
    return digest_value(material)


def _read_manifest(root: Path) -> dict[str, Any] | None:
    payload = _read_optional_platform_file(root, ".sigma/" + _MANIFEST)
    if payload is None:
        return None
    if len(payload) > _MAX_CONFIG_BYTES:
        raise ClientIntegrationError("SOS_CLIENT_MANIFEST_INVALID")
    try:
        value = json.loads(payload.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ClientIntegrationError("SOS_CLIENT_MANIFEST_INVALID") from exc
    _validate_manifest(value)
    return value


def _validate_manifest(value: object) -> None:
    required = {
        "contract", "client", "state", "repository_id", "target", "original_existed", "parent_existed",
        "original_byte_count", "original_digest", "managed_addition_byte_count", "managed_addition_digest",
        "configured_byte_count", "configured_digest",
        "launcher_digest", "package_version", "absolute_paths_serialized", "raw_config_serialized",
        "manifest_digest",
    }
    if not isinstance(value, dict) or set(value) != required:
        raise ClientIntegrationError("SOS_CLIENT_MANIFEST_INVALID")
    if value["contract"] != _CONTRACT or value["client"] != _CLIENT or value["target"] != _TARGET:
        raise ClientIntegrationError("SOS_CLIENT_MANIFEST_INVALID")
    if value["state"] not in {"install_prepared", "installed", "remove_prepared", "removed"}:
        raise ClientIntegrationError("SOS_CLIENT_MANIFEST_INVALID")
    if value["absolute_paths_serialized"] is not False or value["raw_config_serialized"] is not False:
        raise ClientIntegrationError("SOS_CLIENT_MANIFEST_INVALID")
    if not isinstance(value["original_existed"], bool) or not isinstance(value["parent_existed"], bool):
        raise ClientIntegrationError("SOS_CLIENT_MANIFEST_INVALID")
    if not isinstance(value["package_version"], str) or not value["package_version"]:
        raise ClientIntegrationError("SOS_CLIENT_MANIFEST_INVALID")
    for field in ("original_byte_count", "managed_addition_byte_count", "configured_byte_count"):
        if not isinstance(value[field], int) or isinstance(value[field], bool) or value[field] < 0:
            raise ClientIntegrationError("SOS_CLIENT_MANIFEST_INVALID")
    if value["configured_byte_count"] != value["original_byte_count"] + value["managed_addition_byte_count"]:
        raise ClientIntegrationError("SOS_CLIENT_MANIFEST_INVALID")
    for field in ("repository_id", "original_digest", "managed_addition_digest", "configured_digest", "launcher_digest", "manifest_digest"):
        item = value[field]
        if not isinstance(item, str) or re.fullmatch(r"sha256:[0-9a-f]{64}", item) is None:
            raise ClientIntegrationError("SOS_CLIENT_MANIFEST_INVALID")
    if value["manifest_digest"] != _manifest_digest(value):
        raise ClientIntegrationError("SOS_CLIENT_MANIFEST_INVALID")


def _verify_manifest_binding(manifest: dict[str, Any], repository_id: str, binding: LauncherBinding) -> None:
    if manifest["repository_id"] != repository_id:
        raise ClientIntegrationError("SOS_CLIENT_REPOSITORY_MISMATCH", Status.STALE)
    if manifest["launcher_digest"] != binding.digest or manifest["package_version"] != binding.package_version:
        raise ClientIntegrationError("SOS_CLIENT_LAUNCHER_STALE", Status.STALE)


def _managed_plan(manifest: dict[str, Any]) -> dict[str, Any]:
    return build_managed_file_plan(
        journal_id=_JOURNAL_ID,
        repository_id=manifest["repository_id"],
        target=manifest["target"],
        patch_kind="append_suffix" if manifest["original_existed"] else "create_file",
        before_exists=manifest["original_existed"],
        before_byte_count=manifest["original_byte_count"],
        before_digest=manifest["original_digest"],
        patch_byte_count=manifest["managed_addition_byte_count"],
        patch_digest=manifest["managed_addition_digest"],
        after_byte_count=manifest["configured_byte_count"],
        after_digest=manifest["configured_digest"],
    )


def _ensure_journal_state(root: Path, manifest: dict[str, Any], state: str) -> None:
    plan = _managed_plan(manifest)
    current = replay_managed_file_journal(root, _JOURNAL_ID)
    if current is not None and current["plan"] == plan:
        latest_state = current["latest"]["state"]
        if (state, latest_state) in {("apply_prepared", "applied"), ("rollback_prepared", "rolled_back")}:
            return
    record_managed_file_state(root, plan, state)


def _require_journal(root: Path, manifest: dict[str, Any], state: str) -> None:
    require_managed_file_state(root, _managed_plan(manifest), state)


def _require_no_orphan_journal(root: Path) -> None:
    if replay_managed_file_journal(root, _JOURNAL_ID) is not None:
        raise ManagedFileError("SOS_MANAGED_FILE_MANIFEST_MISSING")


def _verify_installed(root: Path, manifest: dict[str, Any], binding: LauncherBinding) -> None:
    _verify_manifest_binding(manifest, manifest["repository_id"], binding)
    current, exists, _ = _read_target(root)
    if not exists or _bytes_digest(current) != manifest["configured_digest"]:
        raise ClientIntegrationError("SOS_CLIENT_CONFIG_DRIFT", Status.STALE)
    original_length = manifest["original_byte_count"]
    if _bytes_digest(current[:original_length]) != manifest["original_digest"]:
        raise ClientIntegrationError("SOS_CLIENT_CONFIG_DRIFT", Status.STALE)
    if _bytes_digest(current[original_length:]) != manifest["managed_addition_digest"]:
        raise ClientIntegrationError("SOS_CLIENT_CONFIG_DRIFT", Status.STALE)
    expected_addition = _render_addition(root, binding, current[:original_length])
    if current != current[:original_length] + expected_addition:
        raise ClientIntegrationError("SOS_CLIENT_CONFIG_DRIFT", Status.STALE)
    _require_journal(root, manifest, "applied")


def _verify_removable(root: Path, manifest: dict[str, Any]) -> None:
    current, exists, _ = _read_target(root)
    if not exists or _bytes_digest(current) != manifest["configured_digest"]:
        raise ClientIntegrationError("SOS_CLIENT_CONFIG_DRIFT", Status.STALE)
    original_length = manifest["original_byte_count"]
    original = current[:original_length]
    addition = current[original_length:]
    if _bytes_digest(original) != manifest["original_digest"] or _bytes_digest(addition) != manifest["managed_addition_digest"]:
        raise ClientIntegrationError("SOS_CLIENT_CONFIG_DRIFT", Status.STALE)
    if _BEGIN.encode() not in addition or _END.encode() not in addition:
        raise ClientIntegrationError("SOS_CLIENT_CONFIG_DRIFT", Status.STALE)
    try:
        server = tomllib.loads(current.decode("utf-8"))["mcp_servers"][_SERVER]
    except (UnicodeDecodeError, tomllib.TOMLDecodeError, KeyError, TypeError) as exc:
        raise ClientIntegrationError("SOS_CLIENT_CONFIG_DRIFT", Status.STALE) from exc
    expected_tail = ["--root", os.fspath(root)]
    if (
        not isinstance(server, dict)
        or not isinstance(server.get("command"), str)
        or not Path(server["command"]).is_absolute()
        or server.get("args", [])[-2:] != expected_tail
        or server.get("enabled_tools") != list(_TOOLS)
        or server.get("default_tools_approval_mode") != "writes"
    ):
        raise ClientIntegrationError("SOS_CLIENT_CONFIG_DRIFT", Status.STALE)


def _read_target(root: Path) -> tuple[bytes, bool, bool]:
    try:
        service = current_platform_services()
        with service.open_repository(root) as repository:
            parent = service.observe_object(repository, ".codex")
            if parent.kind == "absent":
                return b"", False, False
            if parent.kind != "directory":
                raise ClientIntegrationError("SOS_CLIENT_CONFIG_PARENT_INVALID")
            try:
                payload = service.read_regular_file_bounded(
                    repository, _TARGET, _MAX_CONFIG_BYTES
                ).payload
            except PlatformServiceError as exc:
                if exc.kind == "not_found":
                    return b"", False, True
                raise
            return payload, True, True
    except PlatformServiceError as exc:
        raise ClientIntegrationError("SOS_CLIENT_CONFIG_INVALID") from exc


def _read_instruction_target(root: Path) -> tuple[bytes, bool]:
    try:
        payload = _read_optional_platform_file(root, _INSTRUCTION_TARGET)
        return (b"", False) if payload is None else (payload, True)
    except ClientIntegrationError as exc:
        raise ClientIntegrationError("SOS_CODEX_SETUP_INSTRUCTION_INVALID") from exc


def _replace_instruction_target(
    root: Path, payload: bytes, *, expected: bytes, expected_existed: bool, mode: int
) -> None:
    _publish_managed_target(
        root,
        _INSTRUCTION_TARGET,
        payload,
        expected=expected,
        expected_existed=expected_existed,
        mode=mode,
        drift_reason="SOS_CODEX_SETUP_TARGET_DRIFT",
        recovery_reason="SOS_CODEX_SETUP_RECOVERY_REQUIRED",
    )


def _restore_instruction_target(
    root: Path, original: bytes, *, original_existed: bool, expected: bytes, mode: int
) -> None:
    _publish_managed_target(
        root,
        _INSTRUCTION_TARGET,
        original if original_existed else None,
        expected=expected,
        expected_existed=True,
        mode=mode,
        drift_reason="SOS_CODEX_SETUP_TARGET_DRIFT",
        recovery_reason="SOS_CODEX_SETUP_RECOVERY_REQUIRED",
    )


def _replace_target(
    root: Path,
    payload: bytes,
    *,
    expected: bytes,
    expected_existed: bool,
    mode: int = 0o600,
) -> None:
    try:
        _publish_managed_target(
            root,
            _TARGET,
            payload,
            expected=expected,
            expected_existed=expected_existed,
            mode=mode,
            drift_reason="SOS_CLIENT_CONFIG_DRIFT",
            recovery_reason="SOS_CLIENT_CONFIG_RECOVERY_REQUIRED",
            parent_policy="create_managed_and_prune_if_empty_on_abort",
        )
    except BaseException:
        raise


def _restore_target(
    root: Path,
    original: bytes,
    *,
    original_existed: bool,
    parent_existed: bool,
    expected: bytes,
    mode: int = 0o600,
) -> None:
    _publish_managed_target(
        root,
        _TARGET,
        original if original_existed else None,
        expected=expected,
        expected_existed=True,
        mode=mode,
        drift_reason="SOS_CLIENT_CONFIG_DRIFT",
        recovery_reason="SOS_CLIENT_CONFIG_RECOVERY_REQUIRED",
        parent_policy=(
            "preserve_existing"
            if parent_existed
            else "create_managed_and_prune_if_empty_on_abort"
        ),
    )


def _publish_managed_target(
    root: Path,
    relative_path: str,
    payload: bytes | None,
    *,
    expected: bytes,
    expected_existed: bool,
    mode: int,
    drift_reason: str,
    recovery_reason: str,
    parent_policy: str = "preserve_existing",
) -> None:
    try:
        service = current_platform_services()
        with service.open_repository(root) as repository:
            parent_policy_enabled = parent_policy == "create_managed_and_prune_if_empty_on_abort"
            parent_observation = (
                service.observe_object(repository, ".codex")
                if parent_policy_enabled
                else None
            )
            service.publish_file(
                FilePublicationOperation(
                    repository,
                    relative_path,
                    payload,
                    expected if expected_existed else None,
                    expected_existed,
                    mode,
                    parent_policy,
                    parent_observation.kind if parent_observation is not None else None,
                    parent_observation.stable_identity_digest if parent_observation is not None else None,
                )
            )
    except PlatformServiceError as exc:
        if exc.kind in {"identity_changed", "collision"}:
            raise ClientIntegrationError(drift_reason, Status.STALE) from exc
        if exc.kind == "recovery_required":
            raise ClientIntegrationError(recovery_reason, Status.BLOCKED) from exc
        if exc.kind == "noreplace_unsupported":
            raise ClientIntegrationError(
                "SOS_CLIENT_ATOMIC_RENAME_UNSUPPORTED", Status.UNSUPPORTED
            ) from exc
        raise ClientIntegrationError("SOS_CLIENT_ATOMIC_RENAME_FAILED", Status.BLOCKED) from exc


def _write_manifest(root: Path, manifest: dict[str, Any]) -> None:
    _validate_manifest(manifest)
    payload = json.dumps(manifest, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
    _publish_control_file(root, _MANIFEST, payload)


def _read_optional_platform_file(root: Path, relative: str) -> bytes | None:
    try:
        service = current_platform_services()
        with service.open_repository(root) as repository:
            return service.read_regular_file_bounded(
                repository, relative, _MAX_CONFIG_BYTES
            ).payload
    except PlatformServiceError as exc:
        if exc.kind == "not_found":
            return None
        raise ClientIntegrationError("SOS_CLIENT_CONFIG_INVALID") from exc


def _publish_control_file(root: Path, relative: str, payload: bytes) -> None:
    if len(payload) > _MAX_CONFIG_BYTES:
        raise ClientIntegrationError("SOS_CLIENT_MANIFEST_INVALID")
    try:
        service = current_platform_services()
        with service.open_repository(root) as repository:
            try:
                current = service.read_regular_file_bounded(
                    repository, ".sigma/" + relative, _MAX_CONFIG_BYTES
                ).payload
            except PlatformServiceError as exc:
                if exc.kind != "not_found":
                    raise
                current = None
            service.publish_file(
                FilePublicationOperation(
                    repository,
                    ".sigma/" + relative,
                    payload,
                    current,
                    current is not None,
                    0o600,
                )
            )
    except PlatformServiceError as exc:
        if exc.kind in {"collision", "identity_changed"}:
            raise ClientIntegrationError("SOS_CLIENT_CONFIG_DRIFT", Status.STALE) from exc
        raise ClientIntegrationError("SOS_CLIENT_ATOMIC_RENAME_FAILED", Status.BLOCKED) from exc


def _safe_details(manifest: dict[str, Any] | None) -> dict[str, Any]:
    details: dict[str, Any] = {
        "client": _CLIENT,
        "target": _TARGET,
        "absolute_paths_serialized": False,
        "raw_config_serialized": False,
        "acceptance_tools_exposed": False,
        "arbitrary_shell_exposed": False,
        "external_action_tools_exposed": False,
        "client_project_trust_required": True,
        "client_restart_required": True,
    }
    if manifest is not None:
        details.update(
            {
                "integration_state": manifest["state"],
                "manifest_digest": manifest["manifest_digest"],
                "launcher_digest": manifest["launcher_digest"],
                "package_version": manifest["package_version"],
                "configured_digest": manifest["configured_digest"],
                "currentness_after_install": "stale_until_successor_acceptance",
            }
        )
    return details


def _result(status: Status, reason: str, manifest: dict[str, Any] | None = None) -> TerminalResult:
    return TerminalResult(_RESULT_CONTRACT, status, (reason,), _safe_details(manifest))


def _error_result(exc: BaseException) -> TerminalResult:
    if isinstance(exc, ClientIntegrationError):
        return _result(exc.status, exc.reason)
    if isinstance(exc, ManagedFileError):
        return _result(exc.status, exc.reason)
    if isinstance(exc, RepositoryError):
        return _result(Status.INVALID, exc.reason)
    if isinstance(exc, OSError):
        return _result(Status.BLOCKED, "SOS_CLIENT_IO_FAILED")
    return _result(Status.INVALID, str(exc))


def _setup_details(
    manifest: dict[str, Any] | None, projection: dict[str, Any] | None = None
) -> dict[str, Any]:
    details: dict[str, Any] = {
        "client": _CLIENT,
        "targets": [_INSTRUCTION_TARGET, _TARGET],
        "target_count": 2,
        "absolute_paths_serialized": False,
        "raw_content_serialized": False,
        "strong_authentication_claimed": False,
        "agent_invocation_prevented": False,
        "acceptance_tools_exposed": False,
        "arbitrary_shell_exposed": False,
        "external_action_tools_exposed": False,
        "client_project_trust_required": True,
        "client_restart_required": True,
    }
    if manifest is not None:
        details.update(
            {
                "integration_state": manifest["state"],
                "manifest_digest": manifest["manifest_digest"],
                "batch_digest": manifest["batch"]["batch_digest"],
                "launcher_digest": manifest["launcher_digest"],
                "package_version": manifest["package_version"],
                "workspace_currentness_authority": "sos_status",
            }
        )
    if projection is not None:
        details.update(
            {
                "batch_state": projection["state"],
                "recovery_required": projection["recovery_required"],
                "applied_count": projection["applied_count"],
                "rolled_back_count": projection["rolled_back_count"],
            }
        )
    return details


def _setup_result(
    status: Status,
    reason: str,
    manifest: dict[str, Any] | None = None,
    projection: dict[str, Any] | None = None,
) -> TerminalResult:
    return TerminalResult(_RESULT_CONTRACT, status, (reason,), _setup_details(manifest, projection))


def _setup_error_result(exc: BaseException) -> TerminalResult:
    projection = exc.projection if isinstance(exc, ManagedFileBatchError) else None
    if isinstance(exc, (ClientIntegrationError, ManagedFileError)):
        status = exc.status
        reason = exc.reason
    elif isinstance(exc, RepositoryError):
        status = Status.INVALID
        reason = exc.reason
    elif isinstance(exc, OSError):
        status = Status.BLOCKED
        reason = "SOS_CODEX_SETUP_IO_FAILED"
    else:
        status = Status.INVALID
        reason = "SOS_CODEX_SETUP_INVALID"
    return _setup_result(status, reason, projection=projection)


def _manifest_digest(value: dict[str, Any]) -> str:
    material = dict(value)
    material["manifest_digest"] = "sha256:" + "0" * 64
    return digest_value(material)


def _bytes_digest(payload: bytes) -> str:
    return "sha256:" + hashlib.sha256(payload).hexdigest()


def _toml_string(value: str) -> str:
    return json.dumps(value, ensure_ascii=False)


def _toml_array(values: list[str]) -> str:
    return "[" + ", ".join(_toml_string(value) for value in values) + "]"
