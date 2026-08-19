"""P101-v2 bootstrap, integrity replay, doctor and recovery projections."""

from __future__ import annotations

import copy
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
from .dirty import observe_application
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
_SUCCESSOR_LIMIT = 10_000
_SUCCESSOR_RECORD_ROOT = "records/revisions"
_SUCCESSOR_RECEIPT_ROOT = "receipts/successors"
_TRANSITION_ROOT = "ledger/transitions"
_LEDGER_TIP_ROOT = "ledger/tips"
_PROPOSAL_ROOT = "proposals"


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
    if "SOS_CONTROL_PLANE_COLLISION" in preliminary.reasons:
        return _failure(Status.INVALID, "SOS_CONTROL_PLANE_COLLISION")
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
        source = _source_observation(root, inspection, identity, transaction_id, created_at)
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
        incomplete_observation = exc.reason.startswith("SOS_DIRTY_") or exc.reason in {
            "SOS_PATH_LIMIT_EXCEEDED",
            "SOS_SUBMODULE_LIMIT_EXCEEDED",
        }
        status = Status.NOT_VERIFIED if incomplete_observation else Status.INVALID
        return _failure(status, exc.reason)

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
            "application_fingerprint": source["application_state"]["fingerprint"],
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


def regenerate_workspace(
    path: str = ".",
    *,
    confirmed: bool,
    controlling_tty_observed: bool = False,
) -> TerminalResult:
    """Create one immutable three-record successor plan without accepting it."""
    if not confirmed:
        return _failure(
            Status.OWNER_REQUIRED,
            "SOS_REGENERATION_CONFIRMATION_REQUIRED",
            contract="sos_regeneration_result_v1",
        )
    if not controlling_tty_observed:
        return _failure(
            Status.OWNER_REQUIRED,
            "SOS_REGENERATION_TTY_REQUIRED",
            contract="sos_regeneration_result_v1",
        )
    status = workspace_status(path)
    if status.status == Status.SUCCESS:
        return TerminalResult(
            "sos_regeneration_result_v1",
            Status.SUCCESS,
            ("SOS_REGENERATION_NOT_REQUIRED",),
            status.details,
        )
    if status.status != Status.STALE:
        return TerminalResult("sos_regeneration_result_v1", status.status, status.reasons, status.details)
    try:
        root, inspection, _manifest, replay = _load_and_replay(path)
        if not replay["source_coherent"]:
            return _failure(
                Status.BLOCKED,
                "SOS_SUCCESSOR_SEQUENCE_INCOMPLETE",
                contract="sos_regeneration_result_v1",
            )
        identity = repository_identity_contract(
            root,
            local_repository_nonce=_extract_local_nonce(replay["records"]["authority"]),
        )
        transaction_material = {
            "contract": "sos_regeneration_transaction_v1",
            "repository_id": identity.repository_id,
            "records": {slot: record["revision_id"] for slot, record in replay["records"].items()},
            "tree_digest": inspection.application_tree_digest,
            "status_digest": inspection.application_status_digest,
        }
        transaction_id = digest_value(transaction_material).removeprefix("sha256:")
        created_at = _timestamp()
        source = _source_observation(
            root,
            inspection,
            identity,
            transaction_id,
            created_at,
            control_plane_digest=replay["control_plane_digest"],
            accepted_ledger_tip=replay["receipt_tip"],
        )
        existing = _existing_regeneration(root, replay, source)
        if existing is not None:
            return TerminalResult(
                "sos_regeneration_result_v1",
                Status.SUCCESS,
                ("SOS_REGENERATION_PLAN_EXISTS",),
                existing,
            )
        proposals = _successor_proposals(root, identity, replay, source, created_at)
        plan = _regeneration_plan(identity, replay, source, proposals, created_at)
        for record in proposals.values():
            _write_immutable_json(
                root,
                f"{_PROPOSAL_ROOT}/{record['revision_id'].removeprefix('sha256:')}.json",
                record,
            )
        _write_immutable_json(
            root,
            f"{_PROPOSAL_ROOT}/plans/{plan['plan_id'].removeprefix('sha256:')}.json",
            plan,
        )
        view = {
            "contract": "sos_regeneration_view_v1",
            "plan_id": plan["plan_id"],
            "source_observation_digest": source["observation_digest"],
            "predecessors": plan["predecessors"],
            "proposals": plan["proposals"],
            "acceptance_order": [item["revision"] for item in plan["proposals"]],
            "accepted_state_modified": False,
            "raw_project_content_serialized": False,
            "absolute_paths_serialized": False,
        }
        _replace_view_json(root, "views/regeneration.json", view)
        return TerminalResult(
            "sos_regeneration_result_v1",
            Status.SUCCESS,
            ("SOS_SUCCESSOR_PROPOSALS_CREATED",),
            view,
        )
    except RepositoryError as exc:
        return _failure(Status.INVALID, exc.reason, contract="sos_regeneration_result_v1")
    except (WorkspaceError, ContractError):
        return _failure(
            Status.INVALID,
            "SOS_CONTROL_PLANE_INTEGRITY_INVALID",
            contract="sos_regeneration_result_v1",
        )


def accept_proposal(
    path: str,
    revision: str,
    *,
    confirmed: bool,
    controlling_tty_observed: bool = False,
) -> TerminalResult:
    """Accept one exact successor proposal through the human-intended CLI."""
    if not _is_sha256(revision):
        return _failure(Status.INVALID, "SOS_PROPOSAL_REVISION_INVALID", contract="sos_accept_result_v1")
    if not confirmed:
        return _failure(Status.OWNER_REQUIRED, "SOS_ACCEPTANCE_CONFIRMATION_REQUIRED", contract="sos_accept_result_v1")
    if not controlling_tty_observed:
        return _failure(Status.OWNER_REQUIRED, "SOS_ACCEPTANCE_TTY_REQUIRED", contract="sos_accept_result_v1")
    try:
        root = discover_repository_root(path)
        lock = _acquire_acceptance_lock(root)
        try:
            _root, inspection, _manifest, replay = _load_and_replay(os.fspath(root))
            accepted_receipt = replay["record_receipts"].get(revision)
            if accepted_receipt is not None:
                return TerminalResult(
                    "sos_accept_result_v1",
                    Status.SUCCESS,
                    ("SOS_PROPOSAL_ALREADY_ACCEPTED",),
                    {
                        "accepted_revision": revision,
                        "receipt_id": accepted_receipt,
                        "receipt_tip": replay["receipt_tip"],
                    },
                )
            proposal = _read_json(root, f"{_PROPOSAL_ROOT}/{revision.removeprefix('sha256:')}.json")
            verify_record(proposal)
            if proposal.get("revision_id") != revision:
                raise ContractError()
            slot = _slot_for_schema(proposal.get("record_schema"))
            identity = repository_identity_contract(
                root,
                local_repository_nonce=_extract_local_nonce(replay["records"]["authority"]),
            )
            if proposal.get("repository") != identity.to_dict():
                raise ContractError()
            source = proposal.get("source_binding", {}).get("source_observation")
            if not isinstance(source, dict):
                raise ContractError()
            validate_source_observation(source)
            application = observe_application(
                root,
                identity.repository_id,
                source["head"],
                source["exclusion_policy"]["policy_digest"],
            )
            if (
                not application.complete
                or application.fingerprint != source["application_state"]["fingerprint"]
                or inspection.branch != source["branch"]
                or inspection.detached != source["detached"]
            ):
                return _failure(Status.STALE, "SOS_PROPOSAL_SOURCE_STALE", contract="sos_accept_result_v1")
            receipt = _successor_receipt(replay, slot, proposal, _timestamp())
            try:
                _validate_successor_transition(
                    replay["records"], replay["record_receipts"], slot, proposal, receipt
                )
            except ContractError:
                return _failure(
                    Status.STALE,
                    "SOS_PROPOSAL_PREDECESSOR_STALE",
                    contract="sos_accept_result_v1",
                )
            transition = _seal_digest_object(
                {
                    "contract": "sos_acceptance_transition_v1",
                    "receipt_id": receipt["receipt_id"],
                    "predecessor_tip": replay["receipt_tip"],
                    "record_slot": slot,
                    "record_revision": revision,
                    "record_schema": proposal["record_schema"],
                    "source_tree_digest": inspection.application_tree_digest,
                    "source_status_digest": inspection.application_status_digest,
                    "transition_ordinal": replay["successor_count"] + 1,
                },
                "transition_digest",
            )
            _write_immutable_json(
                root,
                f"{_SUCCESSOR_RECORD_ROOT}/{revision.removeprefix('sha256:')}.json",
                proposal,
            )
            _write_immutable_json(
                root,
                f"{_SUCCESSOR_RECEIPT_ROOT}/{receipt['receipt_id'].removeprefix('sha256:')}.json",
                receipt,
            )
            _write_immutable_json(
                root,
                f"{_TRANSITION_ROOT}/{receipt['receipt_id'].removeprefix('sha256:')}.json",
                transition,
            )
            tip = _seal_digest_object(
                {
                    "contract": "sos_acceptance_ledger_tip_v1",
                    "receipt_tip": receipt["receipt_id"],
                    "transition_count": replay["successor_count"] + 1,
                },
                "tip_digest",
            )
            _write_immutable_json(
                root,
                f"{_LEDGER_TIP_ROOT}/{replay['successor_count'] + 1:08d}.json",
                tip,
            )
        finally:
            _release_acceptance_lock(lock)
        current = workspace_status(os.fspath(root))
        return TerminalResult(
            "sos_accept_result_v1",
            Status.SUCCESS,
            ("SOS_SUCCESSOR_ACCEPTED",),
            {
                "accepted_revision": revision,
                "receipt_id": receipt["receipt_id"],
                "workspace_status": current.status.value,
                "workspace_reasons": list(current.reasons),
                "receipt_tip": current.details.get("receipt_tip"),
            },
        )
    except RepositoryError as exc:
        return _failure(Status.INVALID, exc.reason, contract="sos_accept_result_v1")
    except WorkspaceError as exc:
        reason = str(exc)
        status = Status.BLOCKED if reason == "SOS_ACCEPTANCE_LOCKED" else Status.INVALID
        return _failure(status, reason, contract="sos_accept_result_v1")
    except ContractError:
        return _failure(Status.INVALID, "SOS_PROPOSAL_INVALID", contract="sos_accept_result_v1")


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
    binding = manifest["source_binding"]
    source = replay["source_observation"]
    application = observe_application(
        root,
        inspection.repository_id,
        source["head"],
        source["exclusion_policy"]["policy_digest"],
    )
    reasons: list[str] = []
    # A commit containing only the excluded .sigma control plane does not
    # change application currentness.  The acceptance-time HEAD remains in the
    # immutable source observation, while the application-tree projection is
    # the currentness authority.
    if binding["tree_digest"] != inspection.application_tree_digest:
        reasons.append("SOS_SOURCE_TREE_CHANGED")
    if (
        binding["status_digest"] != inspection.application_status_digest
        or (application.complete and binding["application_fingerprint"] != application.fingerprint)
    ):
        reasons.append("SOS_SOURCE_STATUS_CHANGED")
    if not replay["source_coherent"]:
        reasons.append("SOS_SUCCESSOR_SEQUENCE_INCOMPLETE")
    details = {
        "repository_id": inspection.repository_id,
        "source_tree_digest": inspection.application_tree_digest,
        "source_status_digest": inspection.application_status_digest,
        "application_fingerprint": application.fingerprint,
        "application_state": application.state,
        "application_observation_complete": application.complete,
        "application_content_completeness": application.content_completeness,
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
    if not application.complete:
        return TerminalResult(
            "sos_workspace_status_v1",
            Status.NOT_VERIFIED,
            application.reasons,
            details,
        )
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
    recovery_binding = recovery.details.get("source_binding", {})
    if (
        qualification.get("source_tree_digest") != recovery_binding.get("tree_digest")
        or qualification.get("source_status_digest") != recovery_binding.get("status_digest")
    ):
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
    if (
        receipt.source_tree_digest != status.details.get("source_tree_digest")
        or receipt.source_status_digest != status.details.get("source_status_digest")
    ):
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
    effective_manifest = copy.deepcopy(manifest)
    effective_manifest["records"] = {
        slot: record["revision_id"] for slot, record in replay["records"].items()
    }
    effective_manifest["receipts"] = [receipt["receipt_id"] for receipt in replay["receipts"]]
    effective_manifest["receipt_tip"] = replay["receipt_tip"]
    effective_manifest["source_binding"] = replay["source_binding"]
    effective_manifest["control_plane_digest"] = replay["control_plane_digest"]
    return root, inspection, effective_manifest, replay


def _replay_integrity(
    root: Path,
    inspection: RepositoryInspection,
    identity: RepositoryIdentity,
    manifest: dict[str, Any],
    authority: dict[str, Any],
) -> dict[str, Any]:
    if "SOS_CONTROL_PLANE_COLLISION" in inspection.reasons:
        raise ContractError()
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
        "application_fingerprint",
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
        or source.get("application_state", {}).get("fingerprint")
        != source_binding.get("application_fingerprint")
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
    successor = _replay_successors(
        root,
        identity,
        records,
        receipts,
        source_binding,
        observed_plan_digest,
        schemas,
    )
    qualification, qualification_integrity = _replay_qualification(
        root,
        plan,
        successor["source_binding"],
    )
    return {
        "records": successor["records"],
        "receipts": successor["receipts"],
        "receipt_tip": successor["receipt_tip"],
        "source_binding": successor["source_binding"],
        "control_plane_digest": successor["control_plane_digest"],
        "source_coherent": successor["source_coherent"],
        "source_observation": successor["source_observation"],
        "record_receipts": successor["record_receipts"],
        "successor_count": successor["successor_count"],
        "plan": plan,
        "qualification": qualification,
        "qualification_integrity": qualification_integrity,
    }


def _replay_successors(
    root: Path,
    identity: RepositoryIdentity,
    bootstrap_records: dict[str, dict[str, Any]],
    bootstrap_receipts: list[dict[str, Any]],
    bootstrap_source_binding: dict[str, Any],
    check_plan_digest: str,
    schemas: dict[str, str],
) -> dict[str, Any]:
    records = dict(bootstrap_records)
    receipts = list(bootstrap_receipts)
    record_receipts = {
        record["revision_id"]: receipt["receipt_id"]
        for record, receipt in zip(records.values(), bootstrap_receipts, strict=True)
    }
    bootstrap_tip = bootstrap_receipts[-1]["receipt_id"]
    tip = _read_ledger_tip(root)
    if tip is None:
        return {
            "records": records,
            "receipts": receipts,
            "receipt_tip": bootstrap_tip,
            "source_binding": bootstrap_source_binding,
            "control_plane_digest": _control_plane_digest(
                {slot: record["revision_id"] for slot, record in records.items()},
                [receipt["receipt_id"] for receipt in receipts],
                check_plan_digest,
                schemas,
            ),
            "source_coherent": True,
            "source_observation": bootstrap_records["authority"]["source_binding"]["source_observation"],
            "record_receipts": record_receipts,
            "successor_count": 0,
        }
    _verify_digest_object(tip, "tip_digest", "sos_acceptance_ledger_tip_v1")
    if set(tip) != {"contract", "receipt_tip", "transition_count", "tip_digest"}:
        raise ContractError()
    count = tip.get("transition_count")
    receipt_tip = tip.get("receipt_tip")
    if not isinstance(count, int) or isinstance(count, bool) or not 1 <= count <= _SUCCESSOR_LIMIT:
        raise ContractError()
    if not _is_sha256(receipt_tip):
        raise ContractError()
    transitions: list[dict[str, Any]] = []
    seen: set[str] = set()
    cursor = receipt_tip
    while cursor != bootstrap_tip:
        if cursor in seen or len(transitions) >= count:
            raise ContractError()
        seen.add(cursor)
        transition = _read_json(root, f"{_TRANSITION_ROOT}/{cursor.removeprefix('sha256:')}.json")
        _verify_digest_object(transition, "transition_digest", "sos_acceptance_transition_v1")
        if set(transition) != {
            "contract",
            "receipt_id",
            "predecessor_tip",
            "record_slot",
            "record_revision",
            "record_schema",
            "source_tree_digest",
            "source_status_digest",
            "transition_ordinal",
            "transition_digest",
        }:
            raise ContractError()
        if transition.get("receipt_id") != cursor:
            raise ContractError()
        transitions.append(transition)
        predecessor_tip = transition.get("predecessor_tip")
        if not _is_sha256(predecessor_tip):
            raise ContractError()
        cursor = predecessor_tip
    if len(transitions) != count:
        raise ContractError()
    transitions.reverse()
    global_tip = bootstrap_tip
    source_binding = bootstrap_source_binding
    source_observation = bootstrap_records["authority"]["source_binding"]["source_observation"]
    for ordinal, transition in enumerate(transitions, start=1):
        if transition.get("transition_ordinal") != ordinal or transition.get("predecessor_tip") != global_tip:
            raise ContractError()
        slot = transition.get("record_slot")
        schema = transition.get("record_schema")
        revision = transition.get("record_revision")
        receipt_id = transition.get("receipt_id")
        if slot not in _RECORD_FILES or schema != _RECORD_SCHEMAS[tuple(_RECORD_FILES).index(slot)]:
            raise ContractError()
        if not _is_sha256(revision) or not _is_sha256(receipt_id):
            raise ContractError()
        ordinal_tip = _read_json(root, f"{_LEDGER_TIP_ROOT}/{ordinal:08d}.json")
        _verify_digest_object(ordinal_tip, "tip_digest", "sos_acceptance_ledger_tip_v1")
        if ordinal_tip.get("transition_count") != ordinal or ordinal_tip.get("receipt_tip") != receipt_id:
            raise ContractError()
        record = _read_json(root, f"{_SUCCESSOR_RECORD_ROOT}/{revision.removeprefix('sha256:')}.json")
        receipt = _read_json(root, f"{_SUCCESSOR_RECEIPT_ROOT}/{receipt_id.removeprefix('sha256:')}.json")
        verify_record(record)
        verify_receipt(receipt)
        if record.get("revision_id") != revision or record.get("record_schema") != schema:
            raise ContractError()
        if record.get("repository") != identity.to_dict():
            raise ContractError()
        _validate_successor_transition(records, record_receipts, slot, record, receipt)
        source = record["source_binding"]["source_observation"]
        validate_source_observation(source)
        if (
            receipt.get("receipt_id") != receipt_id
            or receipt.get("source_observation_digest") != source.get("observation_digest")
            or receipt.get("exclusion_policy_digest") != source.get("exclusion_policy", {}).get("policy_digest")
        ):
            raise ContractError()
        source_binding = {
            "head": source["head"],
            "tree_digest": transition["source_tree_digest"],
            "status_digest": transition["source_status_digest"],
            "application_fingerprint": source["application_state"]["fingerprint"],
            "source_observation_digest": source["observation_digest"],
        }
        source_observation = source
        records[slot] = record
        receipts.append(receipt)
        record_receipts[revision] = receipt_id
        global_tip = receipt_id
    observations = [record["source_binding"]["source_observation"] for record in records.values()]
    source_coherent = observations[1:] == observations[:-1]
    return {
        "records": records,
        "receipts": receipts,
        "receipt_tip": global_tip,
        "source_binding": source_binding,
        "control_plane_digest": _control_plane_digest(
            {slot: record["revision_id"] for slot, record in records.items()},
            [receipt["receipt_id"] for receipt in receipts],
            check_plan_digest,
            schemas,
        ),
        "source_coherent": source_coherent,
        "source_observation": source_observation,
        "record_receipts": record_receipts,
        "successor_count": count,
    }


def _validate_successor_transition(
    records: dict[str, dict[str, Any]],
    record_receipts: dict[str, str],
    slot: str,
    record: dict[str, Any],
    receipt: dict[str, Any],
) -> None:
    predecessor = records[slot]["revision_id"]
    authority = records["authority"]["revision_id"]
    policy = records["policy"]["revision_id"]
    lineage = record.get("source_binding", {}).get("lineage")
    if not isinstance(lineage, dict):
        raise ContractError()
    if slot == "authority":
        expected_lineage = _successor_lineage("authority_successor", authority_predecessor=predecessor)
        expected_authority = predecessor
        expected_policy = None
    elif slot == "policy":
        expected_lineage = _successor_lineage(
            "policy_successor",
            current_authority=authority,
            policy_predecessor=predecessor,
        )
        expected_authority = authority
        expected_policy = None
    else:
        expected_lineage = _successor_lineage(
            "operator_state",
            current_authority=authority,
            current_policy=policy,
        )
        expected_authority = authority
        expected_policy = policy
    if lineage != expected_lineage or record.get("supersedes") != predecessor:
        raise ContractError()
    if (
        receipt.get("receipt_kind") != "successor_acceptance"
        or receipt.get("sequence_ordinal") != 0
        or receipt.get("proposal_revision") != record.get("revision_id")
        or receipt.get("accepted_revision") != record.get("revision_id")
        or receipt.get("accepted_record_schema") != record.get("record_schema")
        or receipt.get("repository_id") != record.get("repository", {}).get("repository_id")
        or receipt.get("authority_revision_used") != expected_authority
        or receipt.get("policy_revision_observed") != expected_policy
        or receipt.get("predecessor_revision") != predecessor
        or receipt.get("predecessor_receipt") != record_receipts.get(predecessor)
        or receipt.get("bootstrap_intent_id") is not None
        or receipt.get("bootstrap_plan_id") is not None
    ):
        raise ContractError()


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
    if payload.get("plan_digest") != plan.get("plan_digest"):
        raise ContractError()
    current = (
        payload.get("source_tree_digest") == source_binding.get("tree_digest")
        and payload.get("source_status_digest") == source_binding.get("status_digest")
    )
    return view, "valid" if current else "valid_stale"


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
    limits = payload.get("limits")
    reasons = payload.get("reasons")
    exit_code = payload.get("exit_code")
    output_digest = payload.get("output_digest")
    output_bytes = payload.get("output_bytes")
    if (
        set(payload) != expected
        or payload.get("contract") != "sos_qualification_receipt_v1"
        or payload.get("status")
        not in {"passed_local", "failed", "blocked", "unsupported", "not_verified", "skipped", "stale"}
        or payload.get("raw_output_serialized") is not False
        or not isinstance(reasons, list)
        or not 1 <= len(reasons) <= 16
        or any(not _is_public_token(reason, 128) for reason in reasons)
        or not _is_public_token(payload.get("family_id"), 128)
        or not _is_public_token(payload.get("command_id"), 128)
        or not _is_public_token(payload.get("isolation"), 128)
        or not _is_sha256(payload.get("plan_digest"))
        or not _is_sha256(payload.get("source_tree_digest"))
        or not _is_sha256(payload.get("source_status_digest"))
        or (exit_code is not None and (not isinstance(exit_code, int) or isinstance(exit_code, bool)))
        or (output_digest is not None and not _is_sha256(output_digest))
        or not isinstance(output_bytes, int)
        or isinstance(output_bytes, bool)
        or output_bytes < 0
        or not isinstance(limits, dict)
        or not limits
        or any(
            not isinstance(value, int) or isinstance(value, bool) or value <= 0
            for value in limits.values()
        )
    ):
        raise ContractError()
    if payload.get("isolation") == "linux-landlock-seccomp-snapshot-v1":
        if set(limits) != {
            "tracked_files",
            "tracked_bytes",
            "source_file_bytes",
            "timeout_seconds",
            "output_bytes",
            "processes",
            "cpu_seconds",
            "address_space_bytes",
            "open_files",
            "file_write_bytes",
            "writable_bytes",
            "writable_entries",
        }:
            raise ContractError()
        if payload.get("output_bytes", 0) > limits["output_bytes"]:
            raise ContractError()
    if payload.get("status") == "passed_local" and (
        payload.get("exit_code") != 0 or not _is_sha256(payload.get("output_digest"))
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


def _successor_proposals(
    root: Path,
    identity: RepositoryIdentity,
    replay: dict[str, Any],
    source: dict[str, Any],
    created_at: str,
) -> dict[str, dict[str, Any]]:
    current = replay["records"]
    authority_paths = tuple(candidate for candidate in _AUTHORITY_CANDIDATES if (root / candidate).is_file())
    docs = tuple(candidate for candidate in _DOC_CANDIDATES if (root / candidate).exists())
    task_path = next((candidate for candidate in _TASK_CANDIDATES if (root / candidate).is_file()), None)

    authority = _successor_record(
        current["authority"],
        identity,
        source,
        _successor_lineage(
            "authority_successor",
            authority_predecessor=current["authority"]["revision_id"],
        ),
        created_at,
    )
    context = authority.setdefault("extensions", {}).setdefault(_PUBLIC_EXTENSION, {})
    context.update(
        {
            "authority_paths": list(authority_paths),
            "documentation_paths": list(docs),
            "current_task_path": task_path,
            "authority_state": "accepted_local_weak_evidence" if authority_paths else "owner_required",
            "current_task_state": "accepted_local_weak_evidence" if task_path else "not_configured",
            "check_plan_digest": replay["plan"]["plan_digest"],
        }
    )
    authority = seal_record(authority)

    policy = seal_record(
        _successor_record(
            current["policy"],
            identity,
            source,
            _successor_lineage(
                "policy_successor",
                current_authority=authority["revision_id"],
                policy_predecessor=current["policy"]["revision_id"],
            ),
            created_at,
        )
    )

    operator = _successor_record(
        current["operator-state"],
        identity,
        source,
        _successor_lineage(
            "operator_state",
            current_authority=authority["revision_id"],
            current_policy=policy["revision_id"],
        ),
        created_at,
    )
    operator["payload"] = _regenerated_operator_payload(
        operator["payload"],
        source,
        task_path,
        authority["revision_id"],
        policy["revision_id"],
    )
    operator = seal_record(operator)
    return {"authority": authority, "policy": policy, "operator-state": operator}


def _successor_record(
    current: dict[str, Any],
    identity: RepositoryIdentity,
    source: dict[str, Any],
    lineage: dict[str, Any],
    created_at: str,
) -> dict[str, Any]:
    proposal = copy.deepcopy(current)
    predecessor = current["revision_id"]
    proposal["revision_id"] = "sha256:" + "0" * 64
    proposal["repository"] = identity.to_dict()
    proposal["source_binding"] = {"source_observation": source, "lineage": lineage}
    proposal["created_at"] = created_at
    proposal["created_by"] = _actor()
    proposal["supersedes"] = predecessor
    proposal["provenance"] = {
        "record_inputs": [predecessor],
        "evidence_refs": [],
        "external_artifacts": [],
    }
    proposal["integrity"] = {"record_sha256": "0" * 64}
    proposal["lifecycle"] = {"declared": "proposal"}
    return proposal


def _regenerated_operator_payload(
    payload: dict[str, Any],
    source: dict[str, Any],
    task_path: str | None,
    authority_revision: str,
    policy_revision: str,
) -> dict[str, Any]:
    result = copy.deepcopy(payload)
    result["active_task"] = {
        "task_id": "CURRENT_WORK",
        "objective": (
            "Review the detected current work and run the configured local qualification."
            if task_path
            else "Review the generated project map and declare the current work."
        ),
        "external_artifact_refs": [],
    }
    result["current_state"] = [
        {
            "fact_id": "REGENERATED_SOURCE",
            "statement": "Successor proposals are bound to one content-safe local source observation.",
            "evidence_refs": [source["observation_digest"]],
            "status": "observed",
        }
    ]
    result["proposal_refs"] = []
    result["blockers"] = [] if task_path else [
        {
            "reason": "SOS_CURRENT_WORK_NOT_CONFIGURED",
            "needed_owner_scope": "current-work",
            "clear_condition": "Declare one repository-relative current-work source.",
        }
    ]
    next_target = task_path or ".sigma/views/project-map.md"
    result["next_action"] = {
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
    }
    result["recheck_triggers"] = [
        {"trigger_type": "source", "bound_value": source["observation_digest"]},
        {"trigger_type": "authority", "bound_value": authority_revision},
        {"trigger_type": "policy", "bound_value": policy_revision},
    ]
    return result


def _regeneration_plan(
    identity: RepositoryIdentity,
    replay: dict[str, Any],
    source: dict[str, Any],
    proposals: dict[str, dict[str, Any]],
    created_at: str,
) -> dict[str, Any]:
    return _seal_digest_object(
        {
            "contract": "sos_regeneration_plan_v1",
            "repository_id": identity.repository_id,
            "source_observation_digest": source["observation_digest"],
            "source_application_fingerprint": source["application_state"]["fingerprint"],
            "source_branch": source["branch"],
            "source_detached": source["detached"],
            "predecessors": {
                slot: record["revision_id"] for slot, record in replay["records"].items()
            },
            "proposals": [
                {"slot": slot, "schema": record["record_schema"], "revision": record["revision_id"]}
                for slot, record in proposals.items()
            ],
            "created_at": created_at,
            "accepted_state_modified": False,
        },
        "plan_id",
    )


def _existing_regeneration(
    root: Path,
    replay: dict[str, Any],
    source: dict[str, Any],
) -> dict[str, Any] | None:
    try:
        view = _read_optional_json(root, "views/regeneration.json")
        if view is None or not _is_sha256(view.get("plan_id")):
            return None
        plan = _read_json(root, f"{_PROPOSAL_ROOT}/plans/{view['plan_id'].removeprefix('sha256:')}.json")
        _verify_digest_object(plan, "plan_id", "sos_regeneration_plan_v1")
        expected_predecessors = {
            slot: record["revision_id"] for slot, record in replay["records"].items()
        }
        if (
            plan.get("predecessors") != expected_predecessors
            or plan.get("source_application_fingerprint") != source["application_state"]["fingerprint"]
            or plan.get("source_branch") != source["branch"]
            or plan.get("source_detached") != source["detached"]
        ):
            return None
        proposals = plan.get("proposals")
        if not isinstance(proposals, list) or len(proposals) != 3:
            return None
        for item in proposals:
            if not isinstance(item, dict) or not _is_sha256(item.get("revision")):
                return None
            record = _read_json(root, f"{_PROPOSAL_ROOT}/{item['revision'].removeprefix('sha256:')}.json")
            verify_record(record)
            if record.get("revision_id") != item["revision"]:
                return None
        return {
            "plan_id": plan["plan_id"],
            "source_observation_digest": plan["source_observation_digest"],
            "predecessors": plan["predecessors"],
            "proposals": plan["proposals"],
            "acceptance_order": [item["revision"] for item in plan["proposals"]],
            "accepted_state_modified": False,
            "raw_project_content_serialized": False,
            "absolute_paths_serialized": False,
        }
    except (WorkspaceError, ContractError, KeyError, TypeError):
        return None


def _slot_for_schema(schema: object) -> str:
    try:
        return tuple(_RECORD_FILES)[_RECORD_SCHEMAS.index(schema)]
    except (ValueError, IndexError) as exc:
        raise ContractError() from exc


def _successor_receipt(
    replay: dict[str, Any],
    slot: str,
    proposal: dict[str, Any],
    accepted_at: str,
) -> dict[str, Any]:
    current = replay["records"]
    predecessor = current[slot]["revision_id"]
    authority = current["authority"]["revision_id"]
    policy = current["policy"]["revision_id"]
    authority_used = predecessor if slot == "authority" else authority
    policy_observed = policy if slot == "operator-state" else None
    source = proposal["source_binding"]["source_observation"]
    return seal_receipt(
        {
            "schema": "sos_acceptance_receipt_v2",
            "receipt_id": "sha256:" + "0" * 64,
            "receipt_kind": "successor_acceptance",
            "sequence_ordinal": 0,
            "repository_id": proposal["repository"]["repository_id"],
            "proposal_revision": proposal["revision_id"],
            "accepted_revision": proposal["revision_id"],
            "accepted_record_schema": proposal["record_schema"],
            "authority_revision_used": authority_used,
            "policy_revision_observed": policy_observed,
            "predecessor_revision": predecessor,
            "predecessor_receipt": replay["record_receipts"][predecessor],
            "bootstrap_intent_id": None,
            "bootstrap_plan_id": None,
            "source_observation_digest": source["observation_digest"],
            "exclusion_policy_digest": source["exclusion_policy"]["policy_digest"],
            "actor": _actor(),
            "accepted_at": accepted_at,
            "decision": "accepted",
            "integrity": {"receipt_sha256": "0" * 64},
        }
    )


def _source_observation(
    root: Path,
    inspection: RepositoryInspection,
    identity: RepositoryIdentity,
    transaction_id: str,
    observed_at: str,
    *,
    control_plane_digest: str | None = None,
    accepted_ledger_tip: str | None = None,
) -> dict[str, Any]:
    if inspection.head is None:
        raise ContractError("SOS_REPOSITORY_UNBORN")
    exclusion = {
        "contract": "sos_bootstrap_exclusion_policy_v2",
        "schema_major": 2,
        "control_plane_root": ".sigma",
        "staging_prefix": ".sigma.init.",
        "transaction_id": transaction_id,
        "policy_digest": "sha256:" + "0" * 64,
    }
    exclusion["policy_digest"] = exclusion_policy_digest(exclusion)
    application = observe_application(
        root,
        identity.repository_id,
        inspection.head,
        exclusion["policy_digest"],
    )
    if not application.complete:
        raise ContractError(application.reasons[0])
    if (control_plane_digest is None) != (accepted_ledger_tip is None):
        raise ContractError()
    control_plane = {
        "root": ".sigma",
        "tree_digest": control_plane_digest,
        "integrity_status": "valid" if control_plane_digest is not None else "absent",
        "accepted_ledger_tip": accepted_ledger_tip,
        "reasons": [],
    }
    source = {
        "contract": "sos_source_observation_v2",
        "repository_id": identity.repository_id,
        "head": inspection.head,
        "branch": inspection.branch,
        "detached": inspection.detached,
        "worktree_id": worktree_identity(identity.repository_id),
        "application_state": application.to_dict(),
        "control_plane_state": control_plane,
        "exclusion_policy": exclusion,
        "observed_at": observed_at,
        "observation_digest": "sha256:" + "0" * 64,
    }
    source["observation_digest"] = source_observation_digest(source)
    validate_source_observation(source)
    return source


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


def _successor_lineage(
    mode: str,
    *,
    authority_predecessor: str | None = None,
    current_authority: str | None = None,
    policy_predecessor: str | None = None,
    current_policy: str | None = None,
) -> dict[str, Any]:
    return {
        "binding_mode": mode,
        "authority_predecessor": authority_predecessor,
        "current_authority": current_authority,
        "policy_predecessor": policy_predecessor,
        "current_policy": current_policy,
        "bootstrap_intent_id": None,
        "bootstrap_plan_id": None,
    }


def _is_sha256(value: object) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 71
        and value.startswith("sha256:")
        and all(character in "0123456789abcdef" for character in value[7:])
    )


def _is_public_token(value: object, maximum: int) -> bool:
    return (
        isinstance(value, str)
        and 1 <= len(value) <= maximum
        and all(character.isascii() and (character.isalnum() or character in "._-") for character in value)
    )


def _verify_digest_object(value: dict[str, Any], field: str, contract: str) -> None:
    if value.get("contract") != contract or not _is_sha256(value.get(field)):
        raise ContractError()
    material = copy.deepcopy(value)
    observed = material.pop(field)
    if observed != digest_value(material):
        raise ContractError()


def _seal_digest_object(value: dict[str, Any], field: str) -> dict[str, Any]:
    sealed = copy.deepcopy(value)
    sealed.pop(field, None)
    sealed[field] = digest_value(sealed)
    return sealed


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


def _read_ledger_tip(root: Path) -> dict[str, Any] | None:
    try:
        descriptor = _open_control_directory(root, tuple(_LEDGER_TIP_ROOT.split("/")), create=False)
    except WorkspaceError as exc:
        if str(exc) == "SOS_WORKSPACE_RECORD_MISSING":
            return None
        raise
    try:
        names = sorted(os.listdir(descriptor))
    except OSError as exc:
        os.close(descriptor)
        raise WorkspaceError("SOS_WORKSPACE_RECORD_INVALID") from exc
    os.close(descriptor)
    names = [name for name in names if not name.startswith(".tmp.")]
    if not names:
        return None
    expected = [f"{index:08d}.json" for index in range(1, len(names) + 1)]
    if names != expected or len(names) > _SUCCESSOR_LIMIT:
        raise ContractError()
    latest: dict[str, Any] | None = None
    for index, name in enumerate(names, start=1):
        tip = _read_json(root, f"{_LEDGER_TIP_ROOT}/{name}")
        _verify_digest_object(tip, "tip_digest", "sos_acceptance_ledger_tip_v1")
        if tip.get("transition_count") != index:
            raise ContractError()
        latest = tip
    return latest


def _write_immutable_json(root: Path, relative: str, value: dict[str, Any]) -> None:
    parts = Path(relative).parts
    descriptor = _open_control_directory(root, parts[:-1], create=True)
    payload = _json_bytes(value)
    temporary = f".tmp.{secrets.token_hex(32)}"
    temporary_created = False
    try:
        try:
            temporary_descriptor = os.open(
                temporary,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                0o600,
                dir_fd=descriptor,
            )
            temporary_created = True
            try:
                _write_all(temporary_descriptor, payload)
                os.fsync(temporary_descriptor)
            finally:
                os.close(temporary_descriptor)
            os.link(
                temporary,
                parts[-1],
                src_dir_fd=descriptor,
                dst_dir_fd=descriptor,
                follow_symlinks=False,
            )
            os.fsync(descriptor)
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
        except OSError as exc:
            raise WorkspaceError("SOS_WORKSPACE_WRITE_FAILED") from exc
    finally:
        if temporary_created:
            try:
                os.unlink(temporary, dir_fd=descriptor)
                os.fsync(descriptor)
            except FileNotFoundError:
                pass
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


def _acquire_acceptance_lock(root: Path) -> int:
    descriptor = _open_control_directory(root, ("ledger",), create=True)
    try:
        lock = os.open(
            "accept.lock",
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
            0o600,
            dir_fd=descriptor,
        )
    except FileExistsError as exc:
        os.close(descriptor)
        raise WorkspaceError("SOS_ACCEPTANCE_LOCKED") from exc
    try:
        _write_all(lock, b"sos_acceptance_lock_v1\n")
        os.fsync(lock)
    finally:
        os.close(lock)
    os.fsync(descriptor)
    return descriptor


def _release_acceptance_lock(descriptor: int) -> None:
    try:
        os.unlink("accept.lock", dir_fd=descriptor)
        os.fsync(descriptor)
    finally:
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
