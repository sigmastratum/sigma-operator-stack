"""P106 one-confirmation bootstrap plus Codex integration lifecycle."""

from __future__ import annotations

import json
import hashlib
import os
import re
import secrets
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .client_integration import (
    ClientIntegrationError,
    CodexBootstrapSetup,
    LauncherBinding,
    apply_codex_bootstrap_setup,
    codex_setup_status,
    observe_installed_launcher,
    prepare_codex_bootstrap_setup,
    probe_codex_bootstrap_setup,
    render_codex_bootstrap_control_files,
    rollback_codex_bootstrap_setup,
)
from .claude_integration import (
    ClaudeBootstrapSetup,
    ClaudeIntegrationError,
    apply_claude_bootstrap_setup,
    claude_setup_status,
    prepare_claude_bootstrap_setup,
    probe_claude_bootstrap_setup,
    render_claude_bootstrap_control_files,
    rollback_claude_bootstrap_setup,
)
from .contracts import ContractError, digest_value, exclusion_policy_digest
from .compatibility import (
    CompatibilityError,
    CompatibilityProjection,
    discover_compatibility,
)
from .dirty import observe_application
from .maintenance_binding import (
    MaintenanceBindingError,
    MaintenanceLauncherBinding,
    mcp_launcher_binding_payload,
)
from .platform_admission import admit_project_filesystem
from .platform_services import PlatformServiceError, current_platform_services
from .repository import (
    RepositoryError,
    discover_repository_root,
    inspect_repository,
    repository_identity_contract,
)
from .result import Status, TerminalResult
from .transaction import (
    TransactionError,
    commit_bootstrap_staging,
    create_bootstrap_staging,
    discard_bootstrap_staging,
    extend_bootstrap_staging,
)
from .workspace import build_workspace_bootstrap_files, workspace_status


_PENDING = "lifecycle/p106-pending.json"
_RECEIPT = "lifecycle/p106-install.json"
_MAX_PENDING_BYTES = 1024 * 1024
_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_CONFIRMATION_SEED = re.compile(r"^[0-9a-f]{64}$")


class LifecycleError(RuntimeError):
    def __init__(
        self,
        reason: str,
        status: Status = Status.INVALID,
        details: dict[str, Any] | None = None,
    ) -> None:
        super().__init__(reason)
        self.reason = reason
        self.status = status
        self.details = details or {}


@dataclass(frozen=True, slots=True)
class OneCommandPlan:
    root: Path
    confirmation_seed: str
    transaction_id: str
    bootstrap_intent_id: str
    bootstrap_plan_id: str
    local_nonce: str | None
    repository_id: str
    setup: CodexBootstrapSetup | ClaudeBootstrapSetup
    compatibility: CompatibilityProjection
    expected_application_fingerprint: str
    expected_application_state: str
    aggregate_plan_digest: str
    maintenance_binding: MaintenanceLauncherBinding | None

    def pending_payload(self) -> dict[str, Any]:
        return {
            "contract": "sos_p106_pending_v2" if self.setup.manifest["client"] == "codex" else "sos_p107_pending_v1",
            "transaction_id": self.transaction_id,
            "bootstrap_intent_id": self.bootstrap_intent_id,
            "bootstrap_plan_id": self.bootstrap_plan_id,
            "local_nonce": self.local_nonce,
            "repository_id": self.repository_id,
            "setup_manifest": self.setup.manifest,
            "setup_plan_digest": self.setup.plan_digest,
            "compatibility_discovery_digest": self.compatibility.discovery_digest,
            "primary_authority_id": self.compatibility.primary_authority_id,
            "expected_application_fingerprint": self.expected_application_fingerprint,
            "expected_application_state": self.expected_application_state,
            "aggregate_plan_digest": self.aggregate_plan_digest,
            "maintenance_launcher_binding": (
                self.maintenance_binding.payload()
                if self.maintenance_binding is not None
                else None
            ),
            "raw_project_content_serialized": False,
            "absolute_paths_serialized": False,
            "qualification_included": False,
            "network_performed": False,
        }

    def preview(self) -> TerminalResult:
        client = self.setup.manifest["client"]
        targets = [plan["target"] for plan in self.setup.manifest["plans"]]
        details = {
            "aggregate_plan_digest": self.aggregate_plan_digest,
            "confirmation_handoff": {
                "contract": (
                    "sos_p106_confirmation_handoff_v1"
                    if client == "codex"
                    else "sos_p107_confirmation_handoff_v1"
                ),
                "seed": self.confirmation_seed,
                "plan_digest": self.aggregate_plan_digest,
            },
            "canonical_bootstrap_plan_digest": digest_value(
                {
                    "transaction_id": self.transaction_id,
                    "bootstrap_intent_id": self.bootstrap_intent_id,
                    "bootstrap_plan_id": self.bootstrap_plan_id,
                    "repository_id": self.repository_id,
                    "expected_application_fingerprint": self.expected_application_fingerprint,
                }
            ),
            f"{client.replace('-', '_')}_setup_plan_digest": self.setup.plan_digest,
            "compatibility": self.compatibility.details(self.setup.manifest["plans"]),
            "expected_application_fingerprint": self.expected_application_fingerprint,
            "expected_application_state": self.expected_application_state,
            "managed_targets": targets,
            "one_confirmation": True,
            "qualification_included": False,
            "qualification_next_action": "sos qualify",
            "rollback_order": list(reversed(targets)),
            "package_version": self.setup.binding.package_version,
            "mcp_launcher_binding": mcp_launcher_binding_payload(
                package_version=self.setup.binding.package_version,
                executable_sha256=self.setup.binding.executable_sha256,
                binding_digest=self.setup.binding.digest,
            ),
            "maintenance_launcher_binding": (
                self.maintenance_binding.payload()
                if self.maintenance_binding is not None
                else None
            ),
            "raw_project_content_serialized": False,
            "absolute_paths_serialized": False,
            "network_performed": False,
        }
        return TerminalResult(
            "sos_p106_init_preview_v1" if client == "codex" else "sos_p107_init_preview_v1",
            Status.OWNER_REQUIRED,
            (("SOS_P106_CONFIRMATION_REQUIRED" if client == "codex" else "SOS_P107_CONFIRMATION_REQUIRED"),),
            details,
        )


def prepare_one_command_init(
    path: str = ".",
    *,
    launcher: LauncherBinding | None = None,
    primary_authority_id: str | None = None,
    maintenance_binding: MaintenanceLauncherBinding | None = None,
    confirmation_seed: str | None = None,
    client: str = "codex",
) -> OneCommandPlan:
    root = discover_repository_root(path)
    admission = admit_project_filesystem(root)
    if admission.status != Status.SUCCESS:
        raise LifecycleError(
            admission.reasons[0], admission.status, admission.details
        )
    preliminary = inspect_repository(root)
    if preliminary.control_plane_state != "absent":
        raise LifecycleError("SOS_ALREADY_INITIALIZED", Status.SUCCESS)
    if "SOS_CONTROL_PLANE_COLLISION" in preliminary.reasons:
        raise LifecycleError("SOS_CONTROL_PLANE_COLLISION")
    if preliminary.staging_roots:
        raise LifecycleError("SOS_P106_RECOVERY_REQUIRED", Status.BLOCKED)
    if preliminary.head is None:
        raise LifecycleError("SOS_REPOSITORY_UNBORN", Status.NOT_VERIFIED)
    if confirmation_seed is None:
        confirmation_seed = secrets.token_hex(32)
    if _CONFIRMATION_SEED.fullmatch(confirmation_seed) is None:
        raise LifecycleError("SOS_P106_CONFIRMATION_SEED_INVALID")
    transaction_id = _confirmation_value(confirmation_seed, "transaction", 64)
    bootstrap_intent_id = "sha256:" + _confirmation_value(
        confirmation_seed, "bootstrap-intent", 64
    )
    bootstrap_plan_id = "sha256:" + _confirmation_value(
        confirmation_seed, "bootstrap-plan", 64
    )
    provisional = repository_identity_contract(root)
    local_nonce = (
        _confirmation_value(confirmation_seed, "repository-nonce", 32)
        if provisional.identity_mode == "local_nonce_bound"
        else None
    )
    identity = repository_identity_contract(root, local_repository_nonce=local_nonce)
    compatibility = discover_compatibility(
        root, primary_authority_id=primary_authority_id
    )
    binding = launcher or observe_installed_launcher()
    if client == "codex":
        setup = prepare_codex_bootstrap_setup(os.fspath(root), identity.repository_id, launcher=binding)
    elif client == "claude-code":
        setup = prepare_claude_bootstrap_setup(os.fspath(root), identity.repository_id, launcher=binding)
    else:
        raise LifecycleError("SOS_CLIENT_UNSUPPORTED", Status.UNSUPPORTED)
    compatibility_details = compatibility.details(setup.manifest["plans"])
    if compatibility.status != Status.SUCCESS:
        raise LifecycleError(
            compatibility.reasons[0],
            compatibility.status,
            compatibility_details,
        )
    exclusion = {
        "contract": "sos_bootstrap_exclusion_policy_v2",
        "schema_major": 2,
        "control_plane_root": ".sigma",
        "staging_prefix": ".sigma.init.",
        "transaction_id": transaction_id,
        "policy_digest": "sha256:" + "0" * 64,
    }
    exclusion["policy_digest"] = exclusion_policy_digest(exclusion)
    projected = observe_application(
        root,
        identity.repository_id,
        preliminary.head,
        exclusion["policy_digest"],
        overlays=setup.overlays,
    )
    if not projected.complete or projected.fingerprint is None:
        raise LifecycleError(projected.reasons[0] if projected.reasons else "SOS_DIRTY_OBSERVATION_FAILED", Status.NOT_VERIFIED)
    aggregate = {
        "contract": "sos_p106_aggregate_plan_v1" if client == "codex" else "sos_multi_client_lifecycle_plan_v1",
        "repository_id": identity.repository_id,
        "transaction_id": transaction_id,
        "bootstrap_intent_id": bootstrap_intent_id,
        "bootstrap_plan_id": bootstrap_plan_id,
        "compatibility_discovery_digest": compatibility.discovery_digest,
        "primary_authority_id": compatibility.primary_authority_id,
        "expected_application_fingerprint": projected.fingerprint,
        "package_version": setup.binding.package_version,
        "mcp_launcher_binding_digest": setup.binding.digest,
        "maintenance_launcher_binding_digest": (
            maintenance_binding.digest if maintenance_binding is not None else None
        ),
        "qualification_included": False,
    }
    if client == "codex":
        aggregate["codex_setup_plan_digest"] = setup.plan_digest
    else:
        aggregate["client"] = client
        aggregate["client_setup_plan_digest"] = setup.plan_digest
    return OneCommandPlan(
        root,
        confirmation_seed,
        transaction_id,
        bootstrap_intent_id,
        bootstrap_plan_id,
        local_nonce,
        identity.repository_id,
        setup,
        compatibility,
        projected.fingerprint,
        projected.state,
        digest_value(aggregate),
        maintenance_binding,
    )


def preview_one_command_init(
    path: str = ".",
    *,
    launcher: LauncherBinding | None = None,
    primary_authority_id: str | None = None,
    maintenance_binding: MaintenanceLauncherBinding | None = None,
    confirmation_seed: str | None = None,
    client: str = "codex",
) -> TerminalResult:
    try:
        return prepare_one_command_init(
            path,
            launcher=launcher,
            primary_authority_id=primary_authority_id,
            maintenance_binding=maintenance_binding,
            confirmation_seed=confirmation_seed,
            client=client,
        ).preview()
    except LifecycleError as exc:
        if exc.reason == "SOS_ALREADY_INITIALIZED":
            current = workspace_status(path)
            setup = _setup_status(client, path, launcher)
            expected = Status.SUCCESS if client == "codex" else Status.OWNER_REQUIRED
            if current.status == Status.SUCCESS and setup.status == expected:
                return TerminalResult(
                    "sos_p106_init_result_v1" if client == "codex" else "sos_p107_init_result_v1",
                    Status.SUCCESS if client == "codex" else Status.OWNER_REQUIRED,
                    (
                        "SOS_P106_ALREADY_INSTALLED"
                        if client == "codex"
                        else "SOS_INTERACTIVE_USER_HANDOFF_REQUIRED"
                    ,),
                    {**current.details, f"{client.replace('-', '_')}_setup_state": "installed"},
                )
        return TerminalResult(
            "sos_p106_init_result_v1" if client == "codex" else "sos_p107_init_result_v1",
            exc.status,
            (exc.reason,),
            exc.details,
        )
    except (RepositoryError, ClientIntegrationError, ClaudeIntegrationError, CompatibilityError) as exc:
        status = exc.status if hasattr(exc, "status") else Status.INVALID
        reason = exc.reason
        return TerminalResult(
            "sos_p106_init_result_v1" if client == "codex" else "sos_p107_init_result_v1",
            status,
            (reason,),
            {},
        )


def execute_one_command_init(
    plan: OneCommandPlan,
    *,
    confirmed: bool,
    controlling_tty_observed: bool,
    fault: Callable[[str], None] | None = None,
) -> TerminalResult:
    result_contract = (
        "sos_p106_init_result_v1"
        if plan.setup.manifest["client"] == "codex"
        else "sos_p107_init_result_v1"
    )
    if not confirmed:
        return plan.preview()
    if not controlling_tty_observed:
        return TerminalResult(
            result_contract,
            Status.OWNER_REQUIRED,
            ("SOS_ACCEPTANCE_TTY_REQUIRED",),
            {},
        )
    applied = False
    staging_created = False
    committed = False
    try:
        if _revalidated_plan_inputs(plan) != _stable_plan_inputs(plan):
            raise LifecycleError("SOS_P106_PREVIEW_STALE", Status.STALE)
        pending = plan.pending_payload()
        create_bootstrap_staging(
            plan.root,
            plan.transaction_id,
            {_PENDING: _json_bytes(pending)},
        )
        staging_created = True
        _call_fault(fault, "staging_created")
        _apply_setup(plan.setup)
        applied = True
        _call_fault(fault, "targets_applied")
        actual = _actual_application(plan)
        if actual.fingerprint != plan.expected_application_fingerprint:
            raise LifecycleError("SOS_P106_POST_APPLICATION_MISMATCH", Status.STALE)
        _call_fault(fault, "fingerprint_verified")
        files, configured_count = build_workspace_bootstrap_files(
            plan.root,
            transaction_id=plan.transaction_id,
            bootstrap_intent_id=plan.bootstrap_intent_id,
            bootstrap_plan_id=plan.bootstrap_plan_id,
            local_nonce=plan.local_nonce,
            primary_authority_id=plan.compatibility.primary_authority_id,
            compatibility_discovery_digest=plan.compatibility.discovery_digest,
            recognized_authority_paths=plan.compatibility.authority_paths,
        )
        files.update(_render_setup_control_files(plan.setup))
        receipt = {
                "contract": "sos_p106_install_receipt_v2" if plan.setup.manifest["client"] == "codex" else "sos_p107_install_receipt_v1",
                "aggregate_plan_digest": plan.aggregate_plan_digest,
                "repository_id": plan.repository_id,
                "application_fingerprint": actual.fingerprint,
                "compatibility_discovery_digest": plan.compatibility.discovery_digest,
                "primary_authority_id": plan.compatibility.primary_authority_id,
                "mcp_launcher_binding": mcp_launcher_binding_payload(
                    package_version=plan.setup.binding.package_version,
                    executable_sha256=plan.setup.binding.executable_sha256,
                    binding_digest=plan.setup.binding.digest,
                ),
                "maintenance_launcher_binding": (
                    plan.maintenance_binding.payload()
                    if plan.maintenance_binding is not None
                    else None
                ),
                "qualification_performed": False,
                "network_performed": False,
                "raw_project_content_serialized": False,
                "absolute_paths_serialized": False,
            }
        if plan.setup.manifest["client"] == "codex":
            receipt["codex_setup_plan_digest"] = plan.setup.plan_digest
        else:
            receipt["client"] = plan.setup.manifest["client"]
            receipt["client_setup_plan_digest"] = plan.setup.plan_digest
        receipt_path = _RECEIPT if plan.setup.manifest["client"] == "codex" else "lifecycle/p107-install.json"
        files[receipt_path] = _json_bytes(receipt)
        extend_bootstrap_staging(plan.root, plan.transaction_id, files)
        final_actual = _actual_application(plan)
        if final_actual.fingerprint != plan.expected_application_fingerprint:
            raise LifecycleError("SOS_P106_PREVIEW_STALE", Status.STALE)
        _call_fault(fault, "staging_complete")
        commit_bootstrap_staging(plan.root, plan.transaction_id)
        committed = True
        _call_fault(fault, "committed")
        current_status = workspace_status(os.fspath(plan.root))
        client = plan.setup.manifest["client"]
        setup_status = _setup_status(client, os.fspath(plan.root), plan.setup.binding)
        expected_setup_status = Status.SUCCESS if client == "codex" else Status.OWNER_REQUIRED
        if current_status.status != Status.SUCCESS or setup_status.status != expected_setup_status:
            raise LifecycleError("SOS_P106_POST_COMMIT_VERIFICATION_FAILED", Status.BLOCKED)
        return TerminalResult(
            "sos_p106_init_result_v1" if client == "codex" else "sos_p107_init_result_v1",
            Status.SUCCESS if client == "codex" else Status.OWNER_REQUIRED,
            (("SOS_P106_INSTALLED", "SOS_ACCEPTANCE_ASSURANCE_WEAK_LOCAL") if client == "codex" else ("SOS_INTERACTIVE_USER_HANDOFF_REQUIRED", "SOS_ACCEPTANCE_ASSURANCE_WEAK_LOCAL")),
            {
                **current_status.details,
                "aggregate_plan_digest": plan.aggregate_plan_digest,
                f"{client.replace('-', '_')}_setup_state": "installed",
                "compatibility_discovery_digest": plan.compatibility.discovery_digest,
                "primary_authority_id": plan.compatibility.primary_authority_id,
                "configured_check_families": configured_count,
                "qualification_state": "not_verified",
                "qualification_next_action": "sos qualify",
                "network_performed": False,
            },
        )
    except (
        LifecycleError,
        RepositoryError,
        ClientIntegrationError,
        ClaudeIntegrationError,
        ContractError,
        MaintenanceBindingError,
        TransactionError,
    ) as exc:
        if committed:
            return TerminalResult(
                result_contract,
                Status.BLOCKED,
                ("SOS_P106_POST_COMMIT_VERIFICATION_FAILED",),
                {"aggregate_plan_digest": plan.aggregate_plan_digest},
            )
        if applied:
            try:
                _rollback_setup(plan.setup)
            except Exception:
                return TerminalResult(
                    result_contract,
                    Status.BLOCKED,
                    ("SOS_P106_RECOVERY_REQUIRED",),
                    {"aggregate_plan_digest": plan.aggregate_plan_digest},
                )
        if staging_created:
            try:
                discard_bootstrap_staging(plan.root, plan.transaction_id)
            except TransactionError:
                return TerminalResult(
                    result_contract,
                    Status.BLOCKED,
                    ("SOS_P106_RECOVERY_REQUIRED",),
                    {"aggregate_plan_digest": plan.aggregate_plan_digest},
                )
        reason = exc.reason if hasattr(exc, "reason") else str(exc)
        status = exc.status if hasattr(exc, "status") else Status.BLOCKED
        return TerminalResult(result_contract, status, (reason,), {})


def recover_one_command_init(
    path: str = ".", *, launcher: LauncherBinding | None = None, client: str = "codex"
) -> TerminalResult:
    recovery_contract = (
        "sos_p106_recovery_result_v1"
        if client == "codex"
        else "sos_p107_recovery_result_v1"
    )
    try:
        root = discover_repository_root(path)
        inspection = inspect_repository(root)
        if inspection.control_plane_state != "absent":
            current = workspace_status(os.fspath(root))
            setup = _setup_status(client, os.fspath(root), launcher)
            expected = Status.SUCCESS if client == "codex" else Status.OWNER_REQUIRED
            if current.status == Status.SUCCESS and setup.status == expected:
                return TerminalResult(
                    recovery_contract,
                    Status.SUCCESS,
                    ("SOS_P106_INSTALLED",),
                    {"recovery_required": False},
                )
            return TerminalResult(
                recovery_contract, Status.BLOCKED, ("SOS_P106_RECOVERY_REQUIRED",), {}
            )
        if len(inspection.staging_roots) != 1:
            reason = "SOS_P106_NOT_CONFIGURED" if not inspection.staging_roots else "SOS_P106_RECOVERY_REQUIRED"
            status = Status.NOT_VERIFIED if not inspection.staging_roots else Status.BLOCKED
            return TerminalResult(recovery_contract, status, (reason,), {})
        staging_name = inspection.staging_roots[0]
        transaction_id = staging_name.removeprefix(".sigma.init.")
        pending, pending_digest = _read_pending(root, staging_name)
        if pending["transaction_id"] != transaction_id:
            raise LifecycleError("SOS_P106_PENDING_INVALID")
        binding = launcher or observe_installed_launcher()
        setup = (
            CodexBootstrapSetup(root, binding, pending["setup_manifest"], ())
            if pending["setup_manifest"].get("client") == "codex"
            else ClaudeBootstrapSetup(root, binding, pending["setup_manifest"], ())
        )
        if setup.plan_digest != pending["setup_plan_digest"] or binding.digest != setup.manifest["launcher_digest"]:
            raise LifecycleError("SOS_P106_PENDING_STALE", Status.STALE)
        observed = probe_codex_bootstrap_setup(setup) if setup.manifest["client"] == "codex" else probe_claude_bootstrap_setup(setup)
        if observed == "after":
            _rollback_setup(setup)
        elif observed != "before":
            raise LifecycleError("SOS_P106_TARGET_DRIFT", Status.STALE)
        discard_bootstrap_staging(
            root, transaction_id, recovery_binding_digest=pending_digest
        )
        return TerminalResult(
            recovery_contract,
            Status.SUCCESS,
            ("SOS_P106_ROLLBACK_RECOVERED",),
            {"recovery_required": False, "aggregate_plan_digest": pending["aggregate_plan_digest"]},
        )
    except (LifecycleError, RepositoryError, ClientIntegrationError, ClaudeIntegrationError, TransactionError, OSError, ValueError) as exc:
        reason = exc.reason if hasattr(exc, "reason") else "SOS_P106_PENDING_INVALID"
        status = exc.status if hasattr(exc, "status") else Status.INVALID
        return TerminalResult(recovery_contract, status, (reason,), {})


def _stable_plan_inputs(plan: OneCommandPlan) -> tuple[str, str, str, str, str, str | None]:
    return (
        plan.repository_id,
        plan.setup.plan_digest,
        plan.expected_application_fingerprint,
        plan.setup.binding.digest,
        plan.compatibility.discovery_digest,
        plan.compatibility.primary_authority_id,
    )


def _setup_status(client: str, path: str, launcher: LauncherBinding | None) -> TerminalResult:
    return codex_setup_status(path, launcher=launcher) if client == "codex" else claude_setup_status(path, launcher=launcher)


def _apply_setup(setup: CodexBootstrapSetup | ClaudeBootstrapSetup) -> None:
    if setup.manifest["client"] == "codex":
        apply_codex_bootstrap_setup(setup)
    else:
        apply_claude_bootstrap_setup(setup)


def _rollback_setup(setup: CodexBootstrapSetup | ClaudeBootstrapSetup) -> None:
    if setup.manifest["client"] == "codex":
        rollback_codex_bootstrap_setup(setup)
    else:
        rollback_claude_bootstrap_setup(setup)


def _render_setup_control_files(setup: CodexBootstrapSetup | ClaudeBootstrapSetup) -> dict[str, bytes]:
    return render_codex_bootstrap_control_files(setup) if setup.manifest["client"] == "codex" else render_claude_bootstrap_control_files(setup)


def _revalidated_plan_inputs(
    plan: OneCommandPlan,
) -> tuple[str, str, str, str, str, str | None]:
    inspection = inspect_repository(plan.root, local_repository_nonce=plan.local_nonce)
    if inspection.control_plane_state != "absent" or inspection.staging_roots:
        raise LifecycleError("SOS_P106_PREVIEW_STALE", Status.STALE)
    identity = repository_identity_contract(plan.root, local_repository_nonce=plan.local_nonce)
    if plan.setup.manifest["client"] == "codex":
        setup = prepare_codex_bootstrap_setup(os.fspath(plan.root), identity.repository_id, launcher=plan.setup.binding)
    else:
        setup = prepare_claude_bootstrap_setup(os.fspath(plan.root), identity.repository_id, launcher=plan.setup.binding)
    compatibility = discover_compatibility(
        plan.root,
        primary_authority_id=plan.compatibility.primary_authority_id,
    )
    if compatibility.status != Status.SUCCESS:
        raise LifecycleError("SOS_P106_PREVIEW_STALE", Status.STALE)
    exclusion = {
        "contract": "sos_bootstrap_exclusion_policy_v2",
        "schema_major": 2,
        "control_plane_root": ".sigma",
        "staging_prefix": ".sigma.init.",
        "transaction_id": plan.transaction_id,
        "policy_digest": "sha256:" + "0" * 64,
    }
    exclusion["policy_digest"] = exclusion_policy_digest(exclusion)
    observed = observe_application(
        plan.root,
        identity.repository_id,
        inspection.head or "",
        exclusion["policy_digest"],
        overlays=setup.overlays,
    )
    if not observed.complete or observed.fingerprint is None:
        raise LifecycleError("SOS_P106_PREVIEW_STALE", Status.STALE)
    return (
        identity.repository_id,
        setup.plan_digest,
        observed.fingerprint,
        setup.binding.digest,
        compatibility.discovery_digest,
        compatibility.primary_authority_id,
    )


def _actual_application(plan: OneCommandPlan):
    exclusion = {
        "contract": "sos_bootstrap_exclusion_policy_v2",
        "schema_major": 2,
        "control_plane_root": ".sigma",
        "staging_prefix": ".sigma.init.",
        "transaction_id": plan.transaction_id,
        "policy_digest": "sha256:" + "0" * 64,
    }
    exclusion["policy_digest"] = exclusion_policy_digest(exclusion)
    inspection = inspect_repository(plan.root, local_repository_nonce=plan.local_nonce)
    if inspection.head is None:
        raise LifecycleError("SOS_REPOSITORY_UNBORN", Status.NOT_VERIFIED)
    observed = observe_application(
        plan.root,
        plan.repository_id,
        inspection.head,
        exclusion["policy_digest"],
    )
    if not observed.complete:
        raise LifecycleError(observed.reasons[0] if observed.reasons else "SOS_DIRTY_OBSERVATION_FAILED", Status.NOT_VERIFIED)
    return observed


def _read_pending(root: Path, staging_name: str) -> tuple[dict[str, Any], str]:
    if re.fullmatch(r"\.sigma\.init\.[0-9a-f]{64}", staging_name) is None:
        raise LifecycleError("SOS_P106_PENDING_INVALID")
    try:
        service = current_platform_services()
        with service.open_repository(root) as repository:
            payload = service.read_regular_file_bounded(
                repository,
                f"{staging_name}/lifecycle/p106-pending.json",
                _MAX_PENDING_BYTES,
            ).payload
        value = json.loads(payload.decode("utf-8"))
    except (PlatformServiceError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise LifecycleError("SOS_P106_PENDING_INVALID") from exc
    required = {
        "contract", "transaction_id", "bootstrap_intent_id", "bootstrap_plan_id",
        "local_nonce", "repository_id", "setup_manifest", "setup_plan_digest",
        "compatibility_discovery_digest", "primary_authority_id",
        "expected_application_fingerprint", "expected_application_state",
        "aggregate_plan_digest", "maintenance_launcher_binding", "raw_project_content_serialized",
        "absolute_paths_serialized", "qualification_included", "network_performed",
    }
    if not isinstance(value, dict) or set(value) != required or value["contract"] not in {"sos_p106_pending_v2", "sos_p107_pending_v1"}:
        raise LifecycleError("SOS_P106_PENDING_INVALID")
    if value["maintenance_launcher_binding"] is not None:
        try:
            MaintenanceLauncherBinding.from_payload(value["maintenance_launcher_binding"])
        except MaintenanceBindingError as exc:
            raise LifecycleError("SOS_P106_PENDING_INVALID") from exc
    for field in (
        "bootstrap_intent_id", "bootstrap_plan_id", "repository_id", "setup_plan_digest",
        "compatibility_discovery_digest",
        "expected_application_fingerprint", "aggregate_plan_digest",
    ):
        if not isinstance(value[field], str) or _DIGEST.fullmatch(value[field]) is None:
            raise LifecycleError("SOS_P106_PENDING_INVALID")
    if re.fullmatch(r"[0-9a-f]{64}", value["transaction_id"]) is None:
        raise LifecycleError("SOS_P106_PENDING_INVALID")
    if value["local_nonce"] is not None and re.fullmatch(r"[0-9a-f]{32}", value["local_nonce"]) is None:
        raise LifecycleError("SOS_P106_PENDING_INVALID")
    if value["primary_authority_id"] is not None and (
        not isinstance(value["primary_authority_id"], str)
        or re.fullmatch(
            r"[a-z][a-z0-9-]*:[A-Za-z0-9._/-]+",
            value["primary_authority_id"],
        )
        is None
    ):
        raise LifecycleError("SOS_P106_PENDING_INVALID")
    if any(value[field] is not False for field in (
        "raw_project_content_serialized", "absolute_paths_serialized", "qualification_included", "network_performed"
    )):
        raise LifecycleError("SOS_P106_PENDING_INVALID")
    return value, "sha256:" + hashlib.sha256(payload).hexdigest()


def _json_bytes(value: dict[str, Any]) -> bytes:
    payload = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    if len(payload) > _MAX_PENDING_BYTES:
        raise LifecycleError("SOS_P106_PENDING_LIMIT_EXCEEDED", Status.UNSUPPORTED)
    return payload


def _confirmation_value(seed: str, label: str, length: int) -> str:
    payload = (
        b"sos-p106-confirmation-v1\0"
        + label.encode("ascii")
        + b"\0"
        + seed.encode("ascii")
    )
    return hashlib.sha256(payload).hexdigest()[:length]


def _call_fault(fault: Callable[[str], None] | None, boundary: str) -> None:
    if fault is not None:
        fault(boundary)
