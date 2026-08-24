"""P106 one-confirmation bootstrap plus Codex integration lifecycle."""

from __future__ import annotations

import json
import os
import re
import secrets
import stat
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
from .contracts import ContractError, digest_value, exclusion_policy_digest
from .compatibility import (
    CompatibilityError,
    CompatibilityProjection,
    discover_compatibility,
)
from .dirty import observe_application
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
    transaction_id: str
    bootstrap_intent_id: str
    bootstrap_plan_id: str
    local_nonce: str | None
    repository_id: str
    setup: CodexBootstrapSetup
    compatibility: CompatibilityProjection
    expected_application_fingerprint: str
    expected_application_state: str
    aggregate_plan_digest: str

    def pending_payload(self) -> dict[str, Any]:
        return {
            "contract": "sos_p106_pending_v1",
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
            "raw_project_content_serialized": False,
            "absolute_paths_serialized": False,
            "qualification_included": False,
            "network_performed": False,
        }

    def preview(self) -> TerminalResult:
        details = {
            "aggregate_plan_digest": self.aggregate_plan_digest,
            "canonical_bootstrap_plan_digest": digest_value(
                {
                    "transaction_id": self.transaction_id,
                    "bootstrap_intent_id": self.bootstrap_intent_id,
                    "bootstrap_plan_id": self.bootstrap_plan_id,
                    "repository_id": self.repository_id,
                    "expected_application_fingerprint": self.expected_application_fingerprint,
                }
            ),
            "codex_setup_plan_digest": self.setup.plan_digest,
            "compatibility": self.compatibility.details(self.setup.manifest["plans"]),
            "expected_application_fingerprint": self.expected_application_fingerprint,
            "expected_application_state": self.expected_application_state,
            "managed_targets": ["AGENTS.md", ".codex/config.toml"],
            "one_confirmation": True,
            "qualification_included": False,
            "qualification_next_action": "sos qualify",
            "rollback_order": [".codex/config.toml", "AGENTS.md"],
            "package_version": self.setup.binding.package_version,
            "launcher_digest": self.setup.binding.digest,
            "raw_project_content_serialized": False,
            "absolute_paths_serialized": False,
            "network_performed": False,
        }
        return TerminalResult(
            "sos_p106_init_preview_v1",
            Status.OWNER_REQUIRED,
            ("SOS_P106_CONFIRMATION_REQUIRED",),
            details,
        )


def prepare_one_command_init(
    path: str = ".",
    *,
    launcher: LauncherBinding | None = None,
    primary_authority_id: str | None = None,
) -> OneCommandPlan:
    root = discover_repository_root(path)
    preliminary = inspect_repository(root)
    if preliminary.control_plane_state != "absent":
        raise LifecycleError("SOS_ALREADY_INITIALIZED", Status.SUCCESS)
    if "SOS_CONTROL_PLANE_COLLISION" in preliminary.reasons:
        raise LifecycleError("SOS_CONTROL_PLANE_COLLISION")
    if preliminary.staging_roots:
        raise LifecycleError("SOS_P106_RECOVERY_REQUIRED", Status.BLOCKED)
    if preliminary.head is None:
        raise LifecycleError("SOS_REPOSITORY_UNBORN", Status.NOT_VERIFIED)
    transaction_id = secrets.token_hex(32)
    bootstrap_intent_id = "sha256:" + secrets.token_hex(32)
    bootstrap_plan_id = "sha256:" + secrets.token_hex(32)
    provisional = repository_identity_contract(root)
    local_nonce = secrets.token_hex(16) if provisional.identity_mode == "local_nonce_bound" else None
    identity = repository_identity_contract(root, local_repository_nonce=local_nonce)
    compatibility = discover_compatibility(
        root, primary_authority_id=primary_authority_id
    )
    setup = prepare_codex_bootstrap_setup(
        os.fspath(root), identity.repository_id, launcher=launcher or observe_installed_launcher()
    )
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
        "contract": "sos_p106_aggregate_plan_v1",
        "repository_id": identity.repository_id,
        "transaction_id": transaction_id,
        "bootstrap_intent_id": bootstrap_intent_id,
        "bootstrap_plan_id": bootstrap_plan_id,
        "codex_setup_plan_digest": setup.plan_digest,
        "compatibility_discovery_digest": compatibility.discovery_digest,
        "primary_authority_id": compatibility.primary_authority_id,
        "expected_application_fingerprint": projected.fingerprint,
        "package_version": setup.binding.package_version,
        "launcher_digest": setup.binding.digest,
        "qualification_included": False,
    }
    return OneCommandPlan(
        root,
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
    )


def preview_one_command_init(
    path: str = ".",
    *,
    launcher: LauncherBinding | None = None,
    primary_authority_id: str | None = None,
) -> TerminalResult:
    try:
        return prepare_one_command_init(
            path,
            launcher=launcher,
            primary_authority_id=primary_authority_id,
        ).preview()
    except LifecycleError as exc:
        if exc.reason == "SOS_ALREADY_INITIALIZED":
            current = workspace_status(path)
            setup = codex_setup_status(path, launcher=launcher)
            if current.status == Status.SUCCESS and setup.status == Status.SUCCESS:
                return TerminalResult(
                    "sos_p106_init_result_v1",
                    Status.SUCCESS,
                    ("SOS_P106_ALREADY_INSTALLED",),
                    {**current.details, "codex_setup_state": "installed"},
                )
        return TerminalResult(
            "sos_p106_init_result_v1", exc.status, (exc.reason,), exc.details
        )
    except (RepositoryError, ClientIntegrationError, CompatibilityError) as exc:
        status = exc.status if hasattr(exc, "status") else Status.INVALID
        reason = exc.reason
        return TerminalResult("sos_p106_init_result_v1", status, (reason,), {})


def execute_one_command_init(
    plan: OneCommandPlan,
    *,
    confirmed: bool,
    controlling_tty_observed: bool,
    fault: Callable[[str], None] | None = None,
) -> TerminalResult:
    if not confirmed:
        return plan.preview()
    if not controlling_tty_observed:
        return TerminalResult(
            "sos_p106_init_result_v1",
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
        apply_codex_bootstrap_setup(plan.setup)
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
        files.update(render_codex_bootstrap_control_files(plan.setup))
        files[_RECEIPT] = _json_bytes(
            {
                "contract": "sos_p106_install_receipt_v1",
                "aggregate_plan_digest": plan.aggregate_plan_digest,
                "repository_id": plan.repository_id,
                "application_fingerprint": actual.fingerprint,
                "codex_setup_plan_digest": plan.setup.plan_digest,
                "compatibility_discovery_digest": plan.compatibility.discovery_digest,
                "primary_authority_id": plan.compatibility.primary_authority_id,
                "launcher_digest": plan.setup.binding.digest,
                "package_version": plan.setup.binding.package_version,
                "qualification_performed": False,
                "network_performed": False,
                "raw_project_content_serialized": False,
                "absolute_paths_serialized": False,
            }
        )
        extend_bootstrap_staging(plan.root, plan.transaction_id, files)
        final_actual = _actual_application(plan)
        if final_actual.fingerprint != plan.expected_application_fingerprint:
            raise LifecycleError("SOS_P106_PREVIEW_STALE", Status.STALE)
        _call_fault(fault, "staging_complete")
        commit_bootstrap_staging(plan.root, plan.transaction_id)
        committed = True
        _call_fault(fault, "committed")
        current_status = workspace_status(os.fspath(plan.root))
        setup_status = codex_setup_status(os.fspath(plan.root), launcher=plan.setup.binding)
        if current_status.status != Status.SUCCESS or setup_status.status != Status.SUCCESS:
            raise LifecycleError("SOS_P106_POST_COMMIT_VERIFICATION_FAILED", Status.BLOCKED)
        return TerminalResult(
            "sos_p106_init_result_v1",
            Status.SUCCESS,
            ("SOS_P106_INSTALLED", "SOS_ACCEPTANCE_ASSURANCE_WEAK_LOCAL"),
            {
                **current_status.details,
                "aggregate_plan_digest": plan.aggregate_plan_digest,
                "codex_setup_state": "installed",
                "compatibility_discovery_digest": plan.compatibility.discovery_digest,
                "primary_authority_id": plan.compatibility.primary_authority_id,
                "configured_check_families": configured_count,
                "qualification_state": "not_verified",
                "qualification_next_action": "sos qualify",
                "network_performed": False,
            },
        )
    except (LifecycleError, RepositoryError, ClientIntegrationError, ContractError, TransactionError) as exc:
        if committed:
            return TerminalResult(
                "sos_p106_init_result_v1",
                Status.BLOCKED,
                ("SOS_P106_POST_COMMIT_VERIFICATION_FAILED",),
                {"aggregate_plan_digest": plan.aggregate_plan_digest},
            )
        if applied:
            try:
                rollback_codex_bootstrap_setup(plan.setup)
            except Exception:
                return TerminalResult(
                    "sos_p106_init_result_v1",
                    Status.BLOCKED,
                    ("SOS_P106_RECOVERY_REQUIRED",),
                    {"aggregate_plan_digest": plan.aggregate_plan_digest},
                )
        if staging_created:
            try:
                discard_bootstrap_staging(plan.root, plan.transaction_id)
            except TransactionError:
                return TerminalResult(
                    "sos_p106_init_result_v1",
                    Status.BLOCKED,
                    ("SOS_P106_RECOVERY_REQUIRED",),
                    {"aggregate_plan_digest": plan.aggregate_plan_digest},
                )
        reason = exc.reason if hasattr(exc, "reason") else str(exc)
        status = exc.status if hasattr(exc, "status") else Status.BLOCKED
        return TerminalResult("sos_p106_init_result_v1", status, (reason,), {})


def recover_one_command_init(
    path: str = ".", *, launcher: LauncherBinding | None = None
) -> TerminalResult:
    try:
        root = discover_repository_root(path)
        inspection = inspect_repository(root)
        if inspection.control_plane_state != "absent":
            current = workspace_status(os.fspath(root))
            setup = codex_setup_status(os.fspath(root), launcher=launcher)
            if current.status == Status.SUCCESS and setup.status == Status.SUCCESS:
                return TerminalResult(
                    "sos_p106_recovery_result_v1",
                    Status.SUCCESS,
                    ("SOS_P106_INSTALLED",),
                    {"recovery_required": False},
                )
            return TerminalResult(
                "sos_p106_recovery_result_v1", Status.BLOCKED, ("SOS_P106_RECOVERY_REQUIRED",), {}
            )
        if len(inspection.staging_roots) != 1:
            reason = "SOS_P106_NOT_CONFIGURED" if not inspection.staging_roots else "SOS_P106_RECOVERY_REQUIRED"
            status = Status.NOT_VERIFIED if not inspection.staging_roots else Status.BLOCKED
            return TerminalResult("sos_p106_recovery_result_v1", status, (reason,), {})
        staging_name = inspection.staging_roots[0]
        transaction_id = staging_name.removeprefix(".sigma.init.")
        pending = _read_pending(root, staging_name)
        if pending["transaction_id"] != transaction_id:
            raise LifecycleError("SOS_P106_PENDING_INVALID")
        binding = launcher or observe_installed_launcher()
        setup = CodexBootstrapSetup(root, binding, pending["setup_manifest"], ())
        if setup.plan_digest != pending["setup_plan_digest"] or binding.digest != setup.manifest["launcher_digest"]:
            raise LifecycleError("SOS_P106_PENDING_STALE", Status.STALE)
        observed = probe_codex_bootstrap_setup(setup)
        if observed == "after":
            rollback_codex_bootstrap_setup(setup)
        elif observed != "before":
            raise LifecycleError("SOS_P106_TARGET_DRIFT", Status.STALE)
        discard_bootstrap_staging(root, transaction_id)
        return TerminalResult(
            "sos_p106_recovery_result_v1",
            Status.SUCCESS,
            ("SOS_P106_ROLLBACK_RECOVERED",),
            {"recovery_required": False, "aggregate_plan_digest": pending["aggregate_plan_digest"]},
        )
    except (LifecycleError, RepositoryError, ClientIntegrationError, TransactionError, OSError, ValueError) as exc:
        reason = exc.reason if hasattr(exc, "reason") else "SOS_P106_PENDING_INVALID"
        status = exc.status if hasattr(exc, "status") else Status.INVALID
        return TerminalResult("sos_p106_recovery_result_v1", status, (reason,), {})


def _stable_plan_inputs(plan: OneCommandPlan) -> tuple[str, str, str, str, str, str | None]:
    return (
        plan.repository_id,
        plan.setup.plan_digest,
        plan.expected_application_fingerprint,
        plan.setup.binding.digest,
        plan.compatibility.discovery_digest,
        plan.compatibility.primary_authority_id,
    )


def _revalidated_plan_inputs(
    plan: OneCommandPlan,
) -> tuple[str, str, str, str, str, str | None]:
    inspection = inspect_repository(plan.root, local_repository_nonce=plan.local_nonce)
    if inspection.control_plane_state != "absent" or inspection.staging_roots:
        raise LifecycleError("SOS_P106_PREVIEW_STALE", Status.STALE)
    identity = repository_identity_contract(plan.root, local_repository_nonce=plan.local_nonce)
    setup = prepare_codex_bootstrap_setup(
        os.fspath(plan.root), identity.repository_id, launcher=plan.setup.binding
    )
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


def _read_pending(root: Path, staging_name: str) -> dict[str, Any]:
    if re.fullmatch(r"\.sigma\.init\.[0-9a-f]{64}", staging_name) is None:
        raise LifecycleError("SOS_P106_PENDING_INVALID")
    descriptors: list[int] = []
    try:
        descriptors.append(
            os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW)
        )
        descriptors.append(
            os.open(
                staging_name,
                os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
                dir_fd=descriptors[-1],
            )
        )
        descriptors.append(
            os.open(
                "lifecycle",
                os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
                dir_fd=descriptors[-1],
            )
        )
        descriptors.append(
            os.open(
                "p106-pending.json",
                os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW,
                dir_fd=descriptors[-1],
            )
        )
        observed = os.fstat(descriptors[-1])
        if not stat.S_ISREG(observed.st_mode) or observed.st_size > _MAX_PENDING_BYTES:
            raise LifecycleError("SOS_P106_PENDING_INVALID")
        payload = bytearray()
        while len(payload) <= _MAX_PENDING_BYTES:
            chunk = os.read(
                descriptors[-1],
                min(64 * 1024, _MAX_PENDING_BYTES + 1 - len(payload)),
            )
            if not chunk:
                break
            payload.extend(chunk)
        if len(payload) > _MAX_PENDING_BYTES:
            raise LifecycleError("SOS_P106_PENDING_INVALID")
        value = json.loads(payload.decode("utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise LifecycleError("SOS_P106_PENDING_INVALID") from exc
    finally:
        for descriptor in reversed(descriptors):
            os.close(descriptor)
    required = {
        "contract", "transaction_id", "bootstrap_intent_id", "bootstrap_plan_id",
        "local_nonce", "repository_id", "setup_manifest", "setup_plan_digest",
        "compatibility_discovery_digest", "primary_authority_id",
        "expected_application_fingerprint", "expected_application_state",
        "aggregate_plan_digest", "raw_project_content_serialized",
        "absolute_paths_serialized", "qualification_included", "network_performed",
    }
    if not isinstance(value, dict) or set(value) != required or value["contract"] != "sos_p106_pending_v1":
        raise LifecycleError("SOS_P106_PENDING_INVALID")
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
    return value


def _json_bytes(value: dict[str, Any]) -> bytes:
    payload = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    if len(payload) > _MAX_PENDING_BYTES:
        raise LifecycleError("SOS_P106_PENDING_LIMIT_EXCEEDED", Status.UNSUPPORTED)
    return payload


def _call_fault(fault: Callable[[str], None] | None, boundary: str) -> None:
    if fault is not None:
        fault(boundary)
