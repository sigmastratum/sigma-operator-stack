"""P101-v2 bootstrap, integrity replay, doctor and recovery projections."""

from __future__ import annotations

import copy
import hashlib
import json
import os
import secrets
import stat
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .checks import CheckPlan, QualificationReceipt, discover_checks
from .contracts import (
    ContractError,
    digest_value,
    exclusion_policy_digest,
    schema_bundle_hashes,
    seal_receipt,
    seal_record,
    source_observation_digest,
    validate_source_observation,
    verify_receipt,
    verify_record,
)
from .repository import (
    RepositoryError,
    RepositoryIdentity,
    RepositoryInspection,
    discover_repository_root,
    inspect_repository,
    repository_identity_contract,
    worktree_identity,
)
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
_RECORD_FILES = {
    "authority": "records/authority.json",
    "policy": "records/policy.json",
    "operator-state": "records/operator-state.json",
}
_RECEIPT_FILES = (
    "receipts/01-authority_bootstrap.json",
    "receipts/02-policy_bootstrap_plan.json",
    "receipts/03-operator_state_bootstrap_plan.json",
)
_RECORD_SCHEMAS = (
    "sos_authority_record_v2",
    "sos_policy_record_v2",
    "sos_operator_state_v2",
)
_RECEIPT_KINDS = (
    "authority_bootstrap",
    "policy_bootstrap_plan",
    "operator_state_bootstrap_plan",
)
_PUBLIC_EXTENSION = "org.sigmastratum.sos"


class WorkspaceError(RuntimeError):
    pass


def initialize_workspace(
    path: str = ".",
    *,
    confirmed: bool,
    controlling_tty_observed: bool = False,
) -> TerminalResult:
    try:
        root = discover_repository_root(path)
        preliminary = inspect_repository(root)
    except RepositoryError as exc:
        return _failure(Status.INVALID, exc.reason)
    if preliminary.control_plane_state != "absent":
        status = workspace_status(os.fspath(root))
        if status.status == Status.SUCCESS:
            return TerminalResult(
                contract="sos_init_result_v1",
                status=Status.SUCCESS,
                reasons=("SOS_ALREADY_INITIALIZED",),
                details=status.details,
            )
        return TerminalResult("sos_init_result_v1", status.status, status.reasons, status.details)
    if preliminary.head is None:
        return _failure(Status.NOT_VERIFIED, "SOS_REPOSITORY_UNBORN")
    if preliminary.application_state != "clean":
        return _failure(Status.NOT_VERIFIED, "SOS_DIRTY_FINGERPRINT_PROFILE_NOT_QUALIFIED")
    if not confirmed:
        return _failure(Status.OWNER_REQUIRED, "SOS_BOOTSTRAP_CONFIRMATION_REQUIRED")
    if not controlling_tty_observed:
        return _failure(Status.OWNER_REQUIRED, "SOS_ACCEPTANCE_TTY_REQUIRED")

    transaction_id = secrets.token_hex(32)
    bootstrap_intent_id = "sha256:" + secrets.token_hex(32)
    bootstrap_plan_id = "sha256:" + secrets.token_hex(32)
    provisional_identity = repository_identity_contract(root)
    local_nonce = secrets.token_hex(16) if provisional_identity.identity_mode == "local_nonce_bound" else None
    identity = repository_identity_contract(root, local_repository_nonce=local_nonce)
    inspection = inspect_repository(root, local_repository_nonce=local_nonce)
    plan = discover_checks(os.fspath(root))
    created_at = _timestamp()
    authority_paths = tuple(candidate for candidate in _AUTHORITY_CANDIDATES if (root / candidate).is_file())
    docs = tuple(candidate for candidate in _DOC_CANDIDATES if (root / candidate).exists())
    task_path = next((candidate for candidate in _TASK_CANDIDATES if (root / candidate).is_file()), None)
    try:
        source = _source_observation(inspection, identity, transaction_id, created_at)
        actor = _actor()
        records = _bootstrap_records(
            inspection=inspection,
            identity=identity,
            source=source,
            actor=actor,
            bootstrap_intent_id=bootstrap_intent_id,
            bootstrap_plan_id=bootstrap_plan_id,
            created_at=created_at,
            authority_paths=authority_paths,
            docs=docs,
            task_path=task_path,
            check_plan_digest=plan.plan_digest,
            local_nonce=local_nonce,
        )
        receipts = _bootstrap_receipts(
            records,
            source,
            actor,
            bootstrap_intent_id,
            bootstrap_plan_id,
            created_at,
        )
        schemas = schema_bundle_hashes()
    except ContractError as exc:
        return _failure(Status.INVALID, exc.reason)

    record_revisions = {name: record["revision_id"] for name, record in records.items()}
    receipt_ids = [receipt["receipt_id"] for receipt in receipts]
    control_plane_digest = _control_plane_digest(record_revisions, receipt_ids, plan.plan_digest, schemas)
    manifest = {
        "contract": "sos_workspace_manifest_v2",
        "repository_id": inspection.repository_id,
        "bootstrap_intent_id": bootstrap_intent_id,
        "bootstrap_plan_id": bootstrap_plan_id,
        "source_binding": {
            "head": inspection.head,
            "tree_digest": inspection.application_tree_digest,
            "status_digest": inspection.application_status_digest,
            "source_observation_digest": source["observation_digest"],
        },
        "records": record_revisions,
        "receipts": receipt_ids,
        "receipt_tip": receipt_ids[-1],
        "check_plan_digest": plan.plan_digest,
        "schema_bundle": schemas,
        "control_plane_digest": control_plane_digest,
        "created_at": created_at,
    }
    project_map = _project_map_markdown(authority_paths, docs, task_path, plan)
    recovery = _recovery_payload(manifest, records, plan, None, status="not_verified")
    files: dict[str, bytes] = {
        "manifest.json": _json_bytes(manifest),
        "records/authority.json": _json_bytes(records["authority"]),
        "records/policy.json": _json_bytes(records["policy"]),
        "records/operator-state.json": _json_bytes(records["operator-state"]),
        "checks/plan.json": _json_bytes(plan.to_dict()),
        "views/project-map.md": project_map.encode("utf-8"),
        "views/recovery.json": _json_bytes(recovery),
        "views/recovery.md": _recovery_markdown(recovery).encode("utf-8"),
    }
    for relative, receipt in zip(_RECEIPT_FILES, receipts, strict=True):
        files[relative] = _json_bytes(receipt)
    try:
        execute_bootstrap_files(root, transaction_id, files, confirmed=True)
    except TransactionError as exc:
        return _failure(Status.BLOCKED, str(exc))
    result = workspace_status(os.fspath(root))
    if result.status != Status.SUCCESS:
        return TerminalResult("sos_init_result_v1", result.status, result.reasons, result.details)
    return TerminalResult(
        contract="sos_init_result_v1",
        status=Status.SUCCESS,
        reasons=("SOS_BOOTSTRAP_COMPLETE", "SOS_ACCEPTANCE_ASSURANCE_WEAK_LOCAL"),
        details={
            **result.details,
            "configured_check_families": sum(family.status == "configured" for family in plan.families),
        },
    )


def workspace_status(path: str = ".") -> TerminalResult:
    try:
        root, inspection, manifest, replay = _load_and_replay(path)
    except RepositoryError as exc:
        return _failure(Status.INVALID, exc.reason, contract="sos_workspace_status_v1")
    except (WorkspaceError, ContractError):
        return _failure(
            Status.INVALID,
            "SOS_CONTROL_PLANE_INTEGRITY_INVALID",
            contract="sos_workspace_status_v1",
        )
    del root
    binding = manifest["source_binding"]
    reasons: list[str] = []
    # A commit containing only the excluded .sigma control plane does not
    # change application currentness.  The acceptance-time HEAD remains in the
    # immutable source observation, while the application-tree projection is
    # the currentness authority.
    if binding["tree_digest"] != inspection.application_tree_digest:
        reasons.append("SOS_SOURCE_TREE_CHANGED")
    if binding["status_digest"] != inspection.application_status_digest:
        reasons.append("SOS_SOURCE_STATUS_CHANGED")
    details = {
        "repository_id": inspection.repository_id,
        "source_tree_digest": inspection.application_tree_digest,
        "source_status_digest": inspection.application_status_digest,
        "receipt_tip": manifest["receipt_tip"],
        "control_plane_digest": manifest["control_plane_digest"],
        "control_plane_integrity": "valid",
        "schema_bundle": manifest["schema_bundle"],
        "qualification_integrity": replay["qualification_integrity"],
        "raw_project_content_serialized": False,
        "absolute_paths_serialized": False,
    }
    if reasons:
        return TerminalResult("sos_workspace_status_v1", Status.STALE, tuple(reasons), details)
    return TerminalResult(
        "sos_workspace_status_v1",
        Status.SUCCESS,
        ("SOS_WORKSPACE_CURRENT", "SOS_ACCEPTANCE_ASSURANCE_WEAK_LOCAL"),
        details,
    )


def recover_workspace(path: str = ".") -> TerminalResult:
    status = workspace_status(path)
    if status.status in (Status.INVALID, Status.BLOCKED):
        return TerminalResult("sos_recovery_result_v1", status.status, status.reasons, status.details)
    try:
        _root, _inspection, manifest, replay = _load_and_replay(path)
    except (RepositoryError, WorkspaceError, ContractError) as exc:
        reason = exc.reason if isinstance(exc, RepositoryError) else "SOS_CONTROL_PLANE_INTEGRITY_INVALID"
        return _failure(Status.INVALID, reason, contract="sos_recovery_result_v1")
    payload = _recovery_payload(
        manifest,
        replay["records"],
        replay["plan"],
        replay["qualification"],
        status=status.status.value,
    )
    reasons = status.reasons if status.status == Status.STALE else ("SOS_RECOVERY_READY",)
    return TerminalResult("sos_recovery_result_v1", status.status, reasons, payload)


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
        return TerminalResult(
            "sos_doctor_result_v1",
            Status.NOT_VERIFIED,
            ("SOS_QUALIFICATION_NOT_PASSED",),
            recovery.details,
        )
    return TerminalResult("sos_doctor_result_v1", Status.SUCCESS, ("SOS_READY_FOR_AGENT",), recovery.details)


def store_qualification(path: str, receipt: QualificationReceipt) -> None:
    root = discover_repository_root(path)
    status = workspace_status(os.fspath(root))
    if status.status != Status.SUCCESS:
        raise WorkspaceError("SOS_WORKSPACE_NOT_CURRENT")
    if receipt.source_tree_digest != status.details.get("source_tree_digest"):
        raise WorkspaceError("SOS_QUALIFICATION_STALE")
    _validate_qualification_payload(receipt.to_dict())
    view_directory = _open_control_directory(root, ("views",), create=False)
    os.close(view_directory)
    payload = receipt.to_dict()
    receipt_digest = digest_value(payload).removeprefix("sha256:")
    _write_immutable_json(root, f"qualification/receipts/{receipt_digest}.json", payload)
    view = dict(payload)
    view["receipt_digest"] = "sha256:" + receipt_digest
    _replace_view_json(root, "views/qualification.json", view)


def _load_and_replay(
    path: str,
) -> tuple[Path, RepositoryInspection, dict[str, Any], dict[str, Any]]:
    root = discover_repository_root(path)
    authority = _read_json(root, _RECORD_FILES["authority"])
    local_nonce = _extract_local_nonce(authority)
    inspection = inspect_repository(root, local_repository_nonce=local_nonce)
    identity = repository_identity_contract(root, local_repository_nonce=local_nonce)
    manifest = _read_json(root, "manifest.json")
    try:
        replay = _replay_integrity(root, inspection, identity, manifest, authority)
    except (KeyError, IndexError, TypeError, ValueError) as exc:
        raise ContractError() from exc
    return root, inspection, manifest, replay


def _replay_integrity(
    root: Path,
    inspection: RepositoryInspection,
    identity: RepositoryIdentity,
    manifest: dict[str, Any],
    authority: dict[str, Any],
) -> dict[str, Any]:
    expected_manifest_keys = {
        "contract",
        "repository_id",
        "bootstrap_intent_id",
        "bootstrap_plan_id",
        "source_binding",
        "records",
        "receipts",
        "receipt_tip",
        "check_plan_digest",
        "schema_bundle",
        "control_plane_digest",
        "created_at",
    }
    if set(manifest) != expected_manifest_keys or manifest.get("contract") != "sos_workspace_manifest_v2":
        raise ContractError()
    schemas = schema_bundle_hashes()
    if manifest.get("schema_bundle") != schemas or manifest.get("repository_id") != inspection.repository_id:
        raise ContractError()
    source_binding = manifest.get("source_binding")
    if not isinstance(source_binding, dict) or set(source_binding) != {
        "head",
        "tree_digest",
        "status_digest",
        "source_observation_digest",
    }:
        raise ContractError()
    records = {
        "authority": authority,
        "policy": _read_json(root, _RECORD_FILES["policy"]),
        "operator-state": _read_json(root, _RECORD_FILES["operator-state"]),
    }
    observations: list[dict[str, Any]] = []
    for expected_schema, record in zip(_RECORD_SCHEMAS, records.values(), strict=True):
        verify_record(record)
        if record.get("record_schema") != expected_schema:
            raise ContractError()
        if record.get("repository") != identity.to_dict():
            raise ContractError()
        binding = record.get("source_binding")
        if not isinstance(binding, dict) or not isinstance(binding.get("source_observation"), dict):
            raise ContractError()
        validate_source_observation(binding["source_observation"])
        observations.append(binding["source_observation"])
    if observations[1:] != observations[:-1]:
        raise ContractError()
    source = observations[0]
    if (
        source.get("repository_id") != inspection.repository_id
        or source.get("observation_digest") != source_binding.get("source_observation_digest")
        or source.get("head") != source_binding.get("head")
    ):
        raise ContractError()
    intent = manifest.get("bootstrap_intent_id")
    plan_id = manifest.get("bootstrap_plan_id")
    revisions = [record["revision_id"] for record in records.values()]
    if manifest.get("records") != dict(zip(_RECORD_FILES, revisions, strict=True)):
        raise ContractError()
    _validate_record_lineage(records, intent, plan_id, revisions)

    receipts = [_read_json(root, relative) for relative in _RECEIPT_FILES]
    previous: str | None = None
    for index, (receipt, kind, schema, revision) in enumerate(
        zip(receipts, _RECEIPT_KINDS, _RECORD_SCHEMAS, revisions, strict=True),
        start=1,
    ):
        verify_receipt(receipt)
        if (
            receipt.get("receipt_kind") != kind
            or receipt.get("sequence_ordinal") != index
            or receipt.get("accepted_record_schema") != schema
            or receipt.get("proposal_revision") != revision
            or receipt.get("accepted_revision") != revision
            or receipt.get("repository_id") != inspection.repository_id
            or receipt.get("predecessor_receipt") != previous
            or receipt.get("bootstrap_intent_id") != intent
            or receipt.get("bootstrap_plan_id") != plan_id
            or receipt.get("source_observation_digest") != source["observation_digest"]
            or receipt.get("exclusion_policy_digest") != source["exclusion_policy"]["policy_digest"]
        ):
            raise ContractError()
        expected_authority = None if index == 1 else revisions[0]
        expected_policy = revisions[1] if index == 3 else None
        if receipt.get("authority_revision_used") != expected_authority:
            raise ContractError()
        if receipt.get("policy_revision_observed") != expected_policy:
            raise ContractError()
        previous = receipt["receipt_id"]
    receipt_ids = [receipt["receipt_id"] for receipt in receipts]
    if manifest.get("receipts") != receipt_ids or manifest.get("receipt_tip") != receipt_ids[-1]:
        raise ContractError()

    plan = _read_json(root, "checks/plan.json")
    plan_material = copy.deepcopy(plan)
    observed_plan_digest = plan_material.pop("plan_digest", None)
    if observed_plan_digest != digest_value(plan_material) or observed_plan_digest != manifest.get("check_plan_digest"):
        raise ContractError()
    expected_control = _control_plane_digest(manifest["records"], receipt_ids, observed_plan_digest, schemas)
    if manifest.get("control_plane_digest") != expected_control:
        raise ContractError()
    context = authority.get("extensions", {}).get(_PUBLIC_EXTENSION, {})
    if not isinstance(context, dict) or context.get("check_plan_digest") != observed_plan_digest:
        raise ContractError()
    qualification, qualification_integrity = _replay_qualification(root, plan, source_binding)
    return {
        "records": records,
        "receipts": receipts,
        "plan": plan,
        "qualification": qualification,
        "qualification_integrity": qualification_integrity,
    }


def _validate_record_lineage(
    records: dict[str, dict[str, Any]],
    intent: object,
    plan_id: object,
    revisions: list[str],
) -> None:
    lineages = [record["source_binding"]["lineage"] for record in records.values()]
    expected = (
        {
            "binding_mode": "authority_bootstrap",
            "authority_predecessor": None,
            "current_authority": None,
            "policy_predecessor": None,
            "current_policy": None,
            "bootstrap_intent_id": intent,
            "bootstrap_plan_id": plan_id,
        },
        {
            "binding_mode": "policy_successor",
            "authority_predecessor": None,
            "current_authority": revisions[0],
            "policy_predecessor": None,
            "current_policy": None,
            "bootstrap_intent_id": intent,
            "bootstrap_plan_id": plan_id,
        },
        {
            "binding_mode": "operator_state",
            "authority_predecessor": None,
            "current_authority": revisions[0],
            "policy_predecessor": None,
            "current_policy": revisions[1],
            "bootstrap_intent_id": intent,
            "bootstrap_plan_id": plan_id,
        },
    )
    if tuple(lineages) != expected:
        raise ContractError()


def _replay_qualification(
    root: Path,
    plan: dict[str, Any],
    source_binding: dict[str, Any],
) -> tuple[dict[str, Any] | None, str]:
    view = _read_optional_json(root, "views/qualification.json")
    if view is None:
        return None, "absent"
    digest = view.get("receipt_digest")
    if not isinstance(digest, str) or not digest.startswith("sha256:") or len(digest) != 71:
        raise ContractError()
    payload = dict(view)
    payload.pop("receipt_digest")
    if digest_value(payload) != digest:
        raise ContractError()
    immutable = _read_json(root, f"qualification/receipts/{digest.removeprefix('sha256:')}.json")
    if immutable != payload:
        raise ContractError()
    _validate_qualification_payload(payload)
    if (
        payload.get("plan_digest") != plan.get("plan_digest")
        or payload.get("source_tree_digest") != source_binding.get("tree_digest")
        or payload.get("source_status_digest") != source_binding.get("status_digest")
    ):
        raise ContractError()
    return view, "valid"


def _validate_qualification_payload(payload: dict[str, Any]) -> None:
    expected = {
        "contract",
        "status",
        "reasons",
        "family_id",
        "command_id",
        "plan_digest",
        "source_tree_digest",
        "source_status_digest",
        "isolation",
        "exit_code",
        "output_digest",
        "output_bytes",
        "raw_output_serialized",
        "limits",
    }
    if (
        set(payload) != expected
        or payload.get("contract") != "sos_qualification_receipt_v1"
        or payload.get("status") not in {"passed_local", "failed", "blocked", "unsupported", "not_verified"}
        or payload.get("raw_output_serialized") is not False
    ):
        raise ContractError()


def _bootstrap_records(
    *,
    inspection: RepositoryInspection,
    identity: RepositoryIdentity,
    source: dict[str, Any],
    actor: dict[str, Any],
    bootstrap_intent_id: str,
    bootstrap_plan_id: str,
    created_at: str,
    authority_paths: tuple[str, ...],
    docs: tuple[str, ...],
    task_path: str | None,
    check_plan_digest: str,
    local_nonce: str | None,
) -> dict[str, dict[str, Any]]:
    context = {
        "authority_paths": list(authority_paths),
        "documentation_paths": list(docs),
        "current_task_path": task_path,
        "authority_state": "accepted_local_weak_evidence" if authority_paths else "owner_required",
        "current_task_state": "accepted_local_weak_evidence" if task_path else "not_configured",
        "check_plan_digest": check_plan_digest,
    }
    if local_nonce is not None:
        context["local_repository_nonce"] = local_nonce
    authority_lineage = _lineage("authority_bootstrap", bootstrap_intent_id, bootstrap_plan_id)
    authority = seal_record(
        _record_envelope(
            record_schema="sos_authority_record_v2",
            record_id="SOS_AUTHORITY",
            identity=identity,
            source=source,
            lineage=authority_lineage,
            actor=actor,
            created_at=created_at,
            payload={
                "repository_id": inspection.repository_id,
                "approved_roots": ["."],
                "source_roots": ["."],
                "protected_paths": [],
                "branch_classes": [
                    {
                        "class_id": "CURRENT_BRANCH",
                        "pattern": inspection.branch or "**",
                        "pattern_kind": "exact" if inspection.branch else "glob_v1",
                        "classification": "development" if inspection.branch else "unknown",
                    }
                ],
                "owners": [
                    {
                        "owner_label": "local operator",
                        "decision_scopes": ["bootstrap", "local-read", "proposal-write", "external-actions"],
                        "identity_assurance": "declared_local_evidence_only",
                    }
                ],
                "proposal_root": ".sigma/proposals",
                "canonical_record_roots": [".sigma/records"],
                "external_artifact_sources": [],
                "hard_boundaries": [
                    {
                        "pattern": ".sigma",
                        "pattern_kind": "exact",
                        "actions": ["mutate-control-plane"],
                    }
                ],
                "schema_support": list(_RECORD_SCHEMAS),
                "ignore_policy_fingerprint": source["exclusion_policy"]["policy_digest"],
                "expires_at": None,
            },
            extension=context,
        )
    )
    authority_revision = authority["revision_id"]
    policy_lineage = _lineage(
        "policy_successor",
        bootstrap_intent_id,
        bootstrap_plan_id,
        current_authority=authority_revision,
    )
    policy = seal_record(
        _record_envelope(
            record_schema="sos_policy_record_v2",
            record_id="SOS_POLICY",
            identity=identity,
            source=source,
            lineage=policy_lineage,
            actor=actor,
            created_at=created_at,
            payload={
                "policy_id": "LOCAL_DEFAULT",
                "action_classes": ["local-read", "proposal-write", "external-action"],
                "rules": [],
                "default_decision": "owner_required",
                "proposal_write_policy": {
                    "root": ".sigma/proposals",
                    "collision": "refuse",
                    "atomic_write": "same_directory_temp_fsync_noreplace_rename_fsync_directory",
                    "overwrite_accepted": False,
                },
                "acceptance_policy": {
                    "surface": "human_intended_local_cli",
                    "identity_assurance": "declared_local_evidence_only",
                    "controlling_tty_required": True,
                    "strong_authentication_claimed": False,
                    "agent_invocation_prevented": False,
                    "agent_acceptance_interface_exposed": False,
                    "receipt_schema": "sos_acceptance_receipt_v2",
                    "current_binding_required": True,
                },
                "content_policy": {
                    "denied_patterns": [],
                    "secret_action": "reject",
                    "raw_chat_allowed": False,
                    "authenticated_remote_allowed": False,
                },
                "limits_ref": "sos_limits_v1",
            },
            extension={},
        )
    )
    policy_revision = policy["revision_id"]
    operator_lineage = _lineage(
        "operator_state",
        bootstrap_intent_id,
        bootstrap_plan_id,
        current_authority=authority_revision,
        current_policy=policy_revision,
    )
    next_target = task_path or ".sigma/views/project-map.md"
    operator = seal_record(
        _record_envelope(
            record_schema="sos_operator_state_v2",
            record_id="SOS_OPERATOR_STATE",
            identity=identity,
            source=source,
            lineage=operator_lineage,
            actor=actor,
            created_at=created_at,
            payload={
                "active_task": {
                    "task_id": "CURRENT_WORK",
                    "objective": (
                        "Review the detected current work and run the configured local qualification."
                        if task_path
                        else "Review the generated project map and declare the current work."
                    ),
                    "external_artifact_refs": [],
                },
                "current_state": [
                    {
                        "fact_id": "BOOTSTRAP_SOURCE",
                        "statement": "Bootstrap is bound to one content-safe local source observation.",
                        "evidence_refs": [source["observation_digest"]],
                        "status": "observed",
                    }
                ],
                "proposal_refs": [],
                "blockers": [] if task_path else [
                    {
                        "reason": "SOS_CURRENT_WORK_NOT_CONFIGURED",
                        "needed_owner_scope": "current-work",
                        "clear_condition": "Declare one repository-relative current-work source.",
                    }
                ],
                "residuals": [],
                "next_action": {
                    "action_class": "review-and-qualify",
                    "target_paths": [next_target],
                    "description": (
                        "Review the detected current work, then run sos doctor."
                        if task_path
                        else "Review the generated project map, declare current work, then run sos doctor."
                    ),
                    "stop_conditions": [
                        "authority conflict",
                        "source currentness changed",
                        "qualification failed or is not verified",
                        "external action requires owner confirmation",
                    ],
                },
                "required_evidence": [
                    {
                        "check_id": "LOCAL_QUALIFICATION",
                        "evidence_contract": "sos_qualification_receipt_v1",
                        "required_status": "passed",
                    }
                ],
                "next_gate": {
                    "decision_scope": "external-actions",
                    "owner_label": "local operator",
                    "allowed_outcomes": ["approve", "hold", "reject"],
                },
                "recheck_triggers": [
                    {"trigger_type": "source", "bound_value": source["observation_digest"]},
                    {"trigger_type": "authority", "bound_value": authority_revision},
                    {"trigger_type": "policy", "bound_value": policy_revision},
                ],
                "scope_exclusions": [
                    "provider calls",
                    "network authority",
                    "commit push deploy authority",
                ],
            },
            extension={},
        )
    )
    return {"authority": authority, "policy": policy, "operator-state": operator}


def _bootstrap_receipts(
    records: dict[str, dict[str, Any]],
    source: dict[str, Any],
    actor: dict[str, Any],
    intent: str,
    plan_id: str,
    created_at: str,
) -> list[dict[str, Any]]:
    revisions = [record["revision_id"] for record in records.values()]
    receipts: list[dict[str, Any]] = []
    previous: str | None = None
    for ordinal, (kind, schema, revision) in enumerate(
        zip(_RECEIPT_KINDS, _RECORD_SCHEMAS, revisions, strict=True),
        start=1,
    ):
        receipt = seal_receipt(
            {
                "schema": "sos_acceptance_receipt_v2",
                "receipt_id": "sha256:" + "0" * 64,
                "receipt_kind": kind,
                "sequence_ordinal": ordinal,
                "repository_id": source["repository_id"],
                "proposal_revision": revision,
                "accepted_revision": revision,
                "accepted_record_schema": schema,
                "authority_revision_used": None if ordinal == 1 else revisions[0],
                "policy_revision_observed": revisions[1] if ordinal == 3 else None,
                "predecessor_revision": None,
                "predecessor_receipt": previous,
                "bootstrap_intent_id": intent,
                "bootstrap_plan_id": plan_id,
                "source_observation_digest": source["observation_digest"],
                "exclusion_policy_digest": source["exclusion_policy"]["policy_digest"],
                "actor": actor,
                "accepted_at": created_at,
                "decision": "accepted",
                "integrity": {"receipt_sha256": "0" * 64},
            }
        )
        previous = receipt["receipt_id"]
        receipts.append(receipt)
    return receipts


def _record_envelope(
    *,
    record_schema: str,
    record_id: str,
    identity: RepositoryIdentity,
    source: dict[str, Any],
    lineage: dict[str, Any],
    actor: dict[str, Any],
    created_at: str,
    payload: dict[str, Any],
    extension: dict[str, Any],
) -> dict[str, Any]:
    extensions = {_PUBLIC_EXTENSION: extension} if extension else {}
    return {
        "schema": "sos_record_envelope_v2",
        "record_schema": record_schema,
        "record_id": record_id,
        "revision_id": "sha256:" + "0" * 64,
        "lifecycle": {"declared": "proposal"},
        "repository": identity.to_dict(),
        "source_binding": {"source_observation": source, "lineage": lineage},
        "created_at": created_at,
        "created_by": actor,
        "supersedes": None,
        "provenance": {"record_inputs": [], "evidence_refs": [], "external_artifacts": []},
        "integrity": {"record_sha256": "0" * 64},
        "payload": payload,
        "extensions": extensions,
    }


def _source_observation(
    inspection: RepositoryInspection,
    identity: RepositoryIdentity,
    transaction_id: str,
    observed_at: str,
) -> dict[str, Any]:
    if inspection.head is None or inspection.application_state != "clean":
        raise ContractError("SOS_DIRTY_FINGERPRINT_PROFILE_NOT_QUALIFIED")
    exclusion = {
        "contract": "sos_bootstrap_exclusion_policy_v2",
        "schema_major": 2,
        "control_plane_root": ".sigma",
        "staging_prefix": ".sigma.init.",
        "transaction_id": transaction_id,
        "policy_digest": "sha256:" + "0" * 64,
    }
    exclusion["policy_digest"] = exclusion_policy_digest(exclusion)
    fingerprint = _clean_application_fingerprint(
        identity.repository_id,
        inspection.head,
        exclusion["policy_digest"],
    )
    source = {
        "contract": "sos_source_observation_v2",
        "repository_id": identity.repository_id,
        "head": inspection.head,
        "branch": inspection.branch,
        "detached": inspection.detached,
        "worktree_id": worktree_identity(identity.repository_id),
        "application_state": {
            "state": "clean",
            "fingerprint": fingerprint,
            "entry_count": 0,
            "bytes_hashed": 0,
            "complete": True,
            "content_completeness": "byte_complete",
            "exclusion_policy_ref": exclusion["policy_digest"],
            "protected_presence": [],
            "reasons": [],
        },
        "control_plane_state": {
            "root": ".sigma",
            "tree_digest": None,
            "integrity_status": "absent",
            "accepted_ledger_tip": None,
            "reasons": [],
        },
        "exclusion_policy": exclusion,
        "observed_at": observed_at,
        "observation_digest": "sha256:" + "0" * 64,
    }
    source["observation_digest"] = source_observation_digest(source)
    validate_source_observation(source)
    return source


def _clean_application_fingerprint(repository_id: str, head: str, exclusion_digest: str) -> str:
    repository_hash = bytes.fromhex(repository_id.removeprefix("sha256:"))
    head_bytes = bytes.fromhex(head)
    policy_hash = bytes.fromhex(exclusion_digest.removeprefix("sha256:"))
    material = (
        b"sos_dirty_v1"
        + bytes((0,))
        + repository_hash
        + bytes((len(head_bytes),))
        + head_bytes
        + policy_hash
        + (0).to_bytes(4, "big")
    )
    return "sha256:" + hashlib.sha256(material).hexdigest()


def _lineage(
    mode: str,
    intent: str,
    plan_id: str,
    *,
    current_authority: str | None = None,
    current_policy: str | None = None,
) -> dict[str, Any]:
    return {
        "binding_mode": mode,
        "authority_predecessor": None,
        "current_authority": current_authority,
        "policy_predecessor": None,
        "current_policy": current_policy,
        "bootstrap_intent_id": intent,
        "bootstrap_plan_id": plan_id,
    }


def _actor() -> dict[str, Any]:
    return {
        "actor_label": "local operator",
        "surface": "human_intended_local_cli",
        "identity_assurance": "declared_local_evidence_only",
        "controlling_tty_observed": True,
        "strong_authentication_claimed": False,
        "agent_invocation_prevented": False,
        "no_agent_acceptance_interface_exposed": True,
    }


def _extract_local_nonce(authority: dict[str, Any]) -> str | None:
    repository = authority.get("repository")
    if not isinstance(repository, dict):
        raise ContractError()
    if repository.get("identity_mode") == "remote_bound":
        return None
    extensions = authority.get("extensions")
    if not isinstance(extensions, dict):
        raise ContractError()
    extension = extensions.get(_PUBLIC_EXTENSION)
    if not isinstance(extension, dict):
        raise ContractError()
    nonce = extension.get("local_repository_nonce")
    if not isinstance(nonce, str) or len(nonce) != 32 or any(char not in "0123456789abcdef" for char in nonce):
        raise ContractError()
    return nonce


def _control_plane_digest(
    record_revisions: dict[str, str],
    receipt_ids: list[str],
    check_plan_digest: str,
    schemas: dict[str, str],
) -> str:
    return digest_value(
        {
            "contract": "sos_control_plane_integrity_v1",
            "records": record_revisions,
            "receipts": receipt_ids,
            "check_plan_digest": check_plan_digest,
            "schema_bundle": schemas,
        }
    )


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
    records: dict[str, dict[str, Any]],
    plan: CheckPlan | dict[str, Any],
    qualification: dict[str, Any] | None,
    *,
    status: str,
) -> dict[str, Any]:
    plan_value = plan.to_dict() if isinstance(plan, CheckPlan) else plan
    authority = records["authority"]
    policy = records["policy"]
    operator = records["operator-state"]
    context = authority.get("extensions", {}).get(_PUBLIC_EXTENSION, {})
    policy_payload = policy.get("payload", {})
    operator_payload = operator.get("payload", {})
    next_action = operator_payload.get("next_action")
    return {
        "contract": "sos_recovery_view_v1",
        "status": status,
        "repository_id": manifest.get("repository_id"),
        "source_binding": manifest.get("source_binding"),
        "authority": {
            "state": context.get("authority_state"),
            "paths": context.get("authority_paths", []),
            "revision": authority.get("revision_id"),
        },
        "current_work": {
            "path": context.get("current_task_path"),
            "state": context.get("current_task_state"),
            "next_action": next_action,
        },
        "boundaries": {
            "default_decision": policy_payload.get("default_decision"),
            "external_actions": "owner_required",
            "commit_push_deploy": "not_granted",
        },
        "checks": plan_value,
        "qualification": qualification,
        "receipt_tip": manifest.get("receipt_tip"),
        "control_plane_integrity": "valid",
        "control_plane_digest": manifest.get("control_plane_digest"),
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
        f"- Next action: {(work.get('next_action') or {}).get('description', 'owner decision required')}\n"
        "- External actions: owner confirmation required\n"
    )


def _failure(status: Status, reason: str, *, contract: str = "sos_init_result_v1") -> TerminalResult:
    return TerminalResult(contract=contract, status=status, reasons=(reason,), details={})


def _timestamp() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _json_bytes(value: object) -> bytes:
    payload = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    if len(payload) > _MAX_RECORD_BYTES:
        raise WorkspaceError("SOS_WORKSPACE_RECORD_LIMIT_EXCEEDED")
    return payload + b"\n"
