"""Content-safe append-only journal for reversible external managed files."""

from __future__ import annotations

import hashlib
import json
import os
import re
import stat
import fcntl
from collections.abc import Callable, Iterator, Sequence
from contextlib import contextmanager
from pathlib import Path
from typing import Any

from .contracts import digest_value
from .result import Status


_PLAN_CONTRACT = "sos_managed_file_plan_v1"
_EVENT_CONTRACT = "sos_managed_file_event_v1"
_BATCH_CONTRACT = "sos_managed_file_batch_v1"
_BATCH_PROJECTION_CONTRACT = "sos_managed_file_batch_projection_v1"
_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_JOURNAL_ID = re.compile(r"^[a-z][a-z0-9_-]{0,63}$")
_EVENT_NAME = re.compile(r"^([0-9]{8})\.json$")
_STATES = ("apply_prepared", "applied", "rollback_prepared", "rolled_back")
_TRANSITIONS = {
    None: "apply_prepared",
    "apply_prepared": "applied",
    "applied": "rollback_prepared",
    "rollback_prepared": "rolled_back",
    "rolled_back": "apply_prepared",
}
_MAX_PLAN_BYTES = 64 * 1024
_MAX_EVENT_BYTES = 64 * 1024
_MAX_EVENTS = 4096
_MAX_BATCH_BYTES = 64 * 1024
_MAX_BATCH_STEPS = 32
_EMPTY_DIGEST = "sha256:" + hashlib.sha256(b"").hexdigest()
_BATCH_STEP_STATES = {
    "not_started", "apply_prepared", "applied", "rollback_prepared", "rolled_back"
}

ManagedFileStepCallback = Callable[[dict[str, Any]], None]
ManagedFileProbeCallback = Callable[[dict[str, Any]], str]


class ManagedFileError(RuntimeError):
    def __init__(self, reason: str, status: Status = Status.INVALID) -> None:
        super().__init__(reason)
        self.reason = reason
        self.status = status


class ManagedFileBatchError(ManagedFileError):
    def __init__(
        self,
        reason: str,
        status: Status = Status.INVALID,
        projection: dict[str, Any] | None = None,
    ) -> None:
        super().__init__(reason, status)
        self.projection = projection


def build_managed_file_plan(
    *,
    journal_id: str,
    repository_id: str,
    target: str,
    patch_kind: str,
    before_exists: bool,
    before_byte_count: int,
    before_digest: str,
    patch_byte_count: int,
    patch_digest: str,
    after_byte_count: int,
    after_digest: str,
) -> dict[str, Any]:
    plan = {
        "contract": _PLAN_CONTRACT,
        "journal_id": journal_id,
        "repository_id": repository_id,
        "target": target,
        "patch_kind": patch_kind,
        "before_exists": before_exists,
        "before_byte_count": before_byte_count,
        "before_digest": before_digest,
        "patch_byte_count": patch_byte_count,
        "patch_digest": patch_digest,
        "after_exists": True,
        "after_byte_count": after_byte_count,
        "after_digest": after_digest,
        "raw_content_serialized": False,
        "absolute_paths_serialized": False,
        "plan_digest": "sha256:" + "0" * 64,
    }
    plan["plan_digest"] = _sealed_digest(plan, "plan_digest")
    _validate_plan(plan)
    return plan


def build_managed_file_batch(
    *, batch_id: str, repository_id: str, plans: Sequence[dict[str, Any]]
) -> dict[str, Any]:
    _validate_journal_id(batch_id)
    if not isinstance(plans, Sequence) or isinstance(plans, (str, bytes)):
        raise ManagedFileBatchError("SOS_MANAGED_FILE_BATCH_INVALID")
    if not 1 <= len(plans) <= _MAX_BATCH_STEPS:
        raise ManagedFileBatchError("SOS_MANAGED_FILE_BATCH_LIMIT_EXCEEDED", Status.UNSUPPORTED)
    steps: list[dict[str, Any]] = []
    journal_ids: set[str] = set()
    targets: set[str] = set()
    for ordinal, plan in enumerate(plans, start=1):
        _validate_plan(plan)
        if plan["repository_id"] != repository_id:
            raise ManagedFileBatchError("SOS_MANAGED_FILE_BATCH_REPOSITORY_MISMATCH", Status.STALE)
        if plan["journal_id"] in journal_ids or plan["target"] in targets:
            raise ManagedFileBatchError("SOS_MANAGED_FILE_BATCH_DUPLICATE_TARGET")
        journal_ids.add(plan["journal_id"])
        targets.add(plan["target"])
        steps.append(
            {
                "sequence_ordinal": ordinal,
                "journal_id": plan["journal_id"],
                "plan_digest": plan["plan_digest"],
                "target": plan["target"],
                "patch_kind": plan["patch_kind"],
            }
        )
    value = {
        "contract": _BATCH_CONTRACT,
        "batch_id": batch_id,
        "repository_id": repository_id,
        "step_count": len(steps),
        "steps": steps,
        "raw_content_serialized": False,
        "absolute_paths_serialized": False,
        "batch_digest": "sha256:" + "0" * 64,
    }
    value["batch_digest"] = _sealed_digest(value, "batch_digest")
    _validate_batch(value)
    return value


def project_managed_file_batch(root: Path, batch: dict[str, Any]) -> dict[str, Any]:
    _validate_batch(batch)
    if batch["repository_id"] != _observed_repository_id(root):
        raise ManagedFileBatchError("SOS_MANAGED_FILE_BATCH_REPOSITORY_MISMATCH", Status.STALE)
    stored = _read_batch(root, batch["batch_id"])
    if stored is None:
        for step in batch["steps"]:
            if replay_managed_file_journal(root, step["journal_id"]) is not None:
                raise ManagedFileBatchError("SOS_MANAGED_FILE_BATCH_MANIFEST_MISSING", Status.STALE)
        return _build_batch_projection(batch, ["not_started"] * batch["step_count"])
    if stored != batch:
        raise ManagedFileBatchError("SOS_MANAGED_FILE_BATCH_MISMATCH", Status.STALE)
    states: list[str] = []
    for step in batch["steps"]:
        plan = _read_plan(root, step["plan_digest"])
        _require_batch_step_plan(step, plan)
        current = replay_managed_file_journal(root, step["journal_id"])
        if current is None:
            states.append("not_started")
            continue
        if current["plan"] != plan:
            raise ManagedFileBatchError("SOS_MANAGED_FILE_BATCH_PLAN_MISMATCH", Status.STALE)
        states.append(current["latest"]["state"])
    return _build_batch_projection(batch, states)


def coordinate_managed_file_batch(
    root: Path,
    batch: dict[str, Any],
    plans: Sequence[dict[str, Any]],
    *,
    apply_step: ManagedFileStepCallback,
    rollback_step: ManagedFileStepCallback,
    probe_step: ManagedFileProbeCallback,
) -> dict[str, Any]:
    _validate_batch(batch)
    _require_batch_repository(root, batch)
    _require_callbacks(apply_step, rollback_step, probe_step)
    with _managed_batch_lock(root, batch["batch_id"]):
        _bind_batch(root, batch, plans)
        projection = project_managed_file_batch(root, batch)
        if projection["state"] == "integrated":
            return projection
        if projection["state"] == "integration_incomplete":
            raise ManagedFileBatchError(
                "SOS_MANAGED_FILE_BATCH_RECOVERY_REQUIRED", Status.BLOCKED, projection
            )
        plan_by_digest = {plan["plan_digest"]: plan for plan in plans}
        for step in batch["steps"]:
            _require_probe_state(probe_step, plan_by_digest[step["plan_digest"]], "before")
        try:
            for step in batch["steps"]:
                plan = plan_by_digest[step["plan_digest"]]
                _require_probe_state(probe_step, plan, "before")
                record_managed_file_state(root, plan, "apply_prepared")
                apply_step(plan)
                _require_probe_state(probe_step, plan, "after")
                record_managed_file_state(root, plan, "applied")
        except Exception as exc:
            try:
                projection = _rollback_managed_file_batch(
                    root,
                    batch,
                    apply_step=apply_step,
                    rollback_step=rollback_step,
                    probe_step=probe_step,
                    complete_prepared=False,
                )
            except Exception:
                projection = _safe_batch_projection(root, batch)
            reason = (
                "SOS_MANAGED_FILE_BATCH_APPLY_FAILED_ROLLED_BACK"
                if projection is not None and projection["state"] == "rolled_back"
                else "SOS_MANAGED_FILE_BATCH_INTEGRATION_INCOMPLETE"
            )
            raise ManagedFileBatchError(reason, Status.BLOCKED, projection) from exc
        projection = project_managed_file_batch(root, batch)
        if projection["state"] != "integrated":
            raise ManagedFileBatchError(
                "SOS_MANAGED_FILE_BATCH_INTEGRATION_INCOMPLETE", Status.BLOCKED, projection
            )
        return projection


def rollback_managed_file_batch(
    root: Path,
    batch: dict[str, Any],
    *,
    rollback_step: ManagedFileStepCallback,
    probe_step: ManagedFileProbeCallback,
) -> dict[str, Any]:
    _validate_batch(batch)
    _require_batch_repository(root, batch)
    _require_callbacks(rollback_step, probe_step)
    with _managed_batch_lock(root, batch["batch_id"]):
        projection = project_managed_file_batch(root, batch)
        if projection["state"] in {"not_started", "rolled_back"}:
            return projection
        if projection["state"] != "integrated":
            raise ManagedFileBatchError(
                "SOS_MANAGED_FILE_BATCH_RECOVERY_REQUIRED", Status.BLOCKED, projection
            )
        try:
            return _rollback_managed_file_batch(
                root,
                batch,
                apply_step=None,
                rollback_step=rollback_step,
                probe_step=probe_step,
                complete_prepared=False,
            )
        except ManagedFileBatchError as exc:
            raise ManagedFileBatchError(
                exc.reason, exc.status, exc.projection or _safe_batch_projection(root, batch)
            ) from exc
        except Exception as exc:
            raise ManagedFileBatchError(
                "SOS_MANAGED_FILE_BATCH_INTEGRATION_INCOMPLETE",
                Status.BLOCKED,
                _safe_batch_projection(root, batch),
            ) from exc


def recover_managed_file_batch(
    root: Path,
    batch: dict[str, Any],
    *,
    apply_step: ManagedFileStepCallback,
    rollback_step: ManagedFileStepCallback,
    probe_step: ManagedFileProbeCallback,
) -> dict[str, Any]:
    _validate_batch(batch)
    _require_batch_repository(root, batch)
    _require_callbacks(apply_step, rollback_step, probe_step)
    with _managed_batch_lock(root, batch["batch_id"]):
        projection = project_managed_file_batch(root, batch)
        if projection["state"] != "integration_incomplete":
            return projection
        try:
            recovered = _rollback_managed_file_batch(
                root,
                batch,
                apply_step=apply_step,
                rollback_step=rollback_step,
                probe_step=probe_step,
                complete_prepared=True,
            )
        except ManagedFileBatchError as exc:
            raise ManagedFileBatchError(
                exc.reason, exc.status, exc.projection or _safe_batch_projection(root, batch)
            ) from exc
        except Exception as exc:
            projection = _safe_batch_projection(root, batch)
            raise ManagedFileBatchError(
                "SOS_MANAGED_FILE_BATCH_INTEGRATION_INCOMPLETE", Status.BLOCKED, projection
            ) from exc
        if recovered["state"] != "rolled_back":
            raise ManagedFileBatchError(
                "SOS_MANAGED_FILE_BATCH_INTEGRATION_INCOMPLETE", Status.BLOCKED, recovered
            )
        return recovered


def replay_managed_file_journal(root: Path, journal_id: str) -> dict[str, Any] | None:
    _validate_journal_id(journal_id)
    repository_id = _observed_repository_id(root)
    try:
        journal = _open_control_directory(root, ("managed-files", "journals", journal_id), create=False)
    except FileNotFoundError:
        return None
    try:
        names = sorted(os.listdir(journal))
        if len(names) > _MAX_EVENTS:
            raise ManagedFileError("SOS_MANAGED_FILE_EVENT_LIMIT_EXCEEDED", Status.UNSUPPORTED)
        events: list[dict[str, Any]] = []
        predecessor: str | None = None
        active_plan: str | None = None
        previous_state: str | None = None
        for expected_ordinal, name in enumerate(names, start=1):
            match = _EVENT_NAME.fullmatch(name)
            if match is None or int(match.group(1)) != expected_ordinal:
                raise ManagedFileError("SOS_MANAGED_FILE_JOURNAL_INVALID")
            event = _read_json(journal, name, _MAX_EVENT_BYTES)
            _validate_event(event)
            if event["journal_id"] != journal_id or event["sequence_ordinal"] != expected_ordinal:
                raise ManagedFileError("SOS_MANAGED_FILE_JOURNAL_INVALID")
            if event["repository_id"] != repository_id:
                raise ManagedFileError("SOS_MANAGED_FILE_REPOSITORY_MISMATCH", Status.STALE)
            if event["predecessor_event"] != predecessor:
                raise ManagedFileError("SOS_MANAGED_FILE_JOURNAL_INVALID")
            expected_state = _TRANSITIONS[previous_state]
            if event["state"] != expected_state:
                raise ManagedFileError("SOS_MANAGED_FILE_STATE_TRANSITION_INVALID")
            if event["state"] == "apply_prepared":
                active_plan = event["plan_digest"]
                observed_plan = _read_plan(root, active_plan)
                if observed_plan["journal_id"] != journal_id or observed_plan["repository_id"] != repository_id:
                    raise ManagedFileError("SOS_MANAGED_FILE_PLAN_MISMATCH", Status.STALE)
            elif event["plan_digest"] != active_plan:
                raise ManagedFileError("SOS_MANAGED_FILE_PLAN_MISMATCH", Status.STALE)
            predecessor = event["event_digest"]
            previous_state = event["state"]
            events.append(event)
        if not events:
            raise ManagedFileError("SOS_MANAGED_FILE_JOURNAL_INVALID")
        plan = _read_plan(root, events[-1]["plan_digest"])
        if plan["journal_id"] != journal_id:
            raise ManagedFileError("SOS_MANAGED_FILE_PLAN_MISMATCH", Status.STALE)
        return {"plan": plan, "latest": events[-1], "event_count": len(events)}
    finally:
        os.close(journal)


def record_managed_file_state(root: Path, plan: dict[str, Any], state: str) -> dict[str, Any]:
    _validate_plan(plan)
    if plan["repository_id"] != _observed_repository_id(root):
        raise ManagedFileError("SOS_MANAGED_FILE_REPOSITORY_MISMATCH", Status.STALE)
    if state not in _STATES:
        raise ManagedFileError("SOS_MANAGED_FILE_STATE_INVALID")
    journal_id = plan["journal_id"]
    current = replay_managed_file_journal(root, journal_id)
    if current is not None:
        latest = current["latest"]
        if latest["state"] == state and latest["plan_digest"] == plan["plan_digest"]:
            return latest
        previous_state = latest["state"]
        predecessor = latest["event_digest"]
        ordinal = latest["sequence_ordinal"] + 1
    else:
        previous_state = None
        predecessor = None
        ordinal = 1
    if ordinal > _MAX_EVENTS:
        raise ManagedFileError("SOS_MANAGED_FILE_EVENT_LIMIT_EXCEEDED", Status.UNSUPPORTED)
    if _TRANSITIONS[previous_state] != state:
        raise ManagedFileError("SOS_MANAGED_FILE_STATE_TRANSITION_INVALID", Status.BLOCKED)
    if previous_state not in (None, "rolled_back") and current is not None:
        if current["latest"]["plan_digest"] != plan["plan_digest"]:
            raise ManagedFileError("SOS_MANAGED_FILE_PLAN_MISMATCH", Status.STALE)
    _write_plan(root, plan)
    event = {
        "contract": _EVENT_CONTRACT,
        "journal_id": journal_id,
        "repository_id": plan["repository_id"],
        "plan_digest": plan["plan_digest"],
        "state": state,
        "sequence_ordinal": ordinal,
        "predecessor_event": predecessor,
        "raw_content_serialized": False,
        "absolute_paths_serialized": False,
        "event_digest": "sha256:" + "0" * 64,
    }
    event["event_digest"] = _sealed_digest(event, "event_digest")
    _validate_event(event)
    journal = _open_control_directory(root, ("managed-files", "journals", journal_id), create=True)
    try:
        name = f"{ordinal:08d}.json"
        try:
            _write_immutable_json(journal, name, event, _MAX_EVENT_BYTES)
        except FileExistsError:
            observed = replay_managed_file_journal(root, journal_id)
            if observed is not None and observed["latest"] == event:
                return event
            raise ManagedFileError("SOS_MANAGED_FILE_JOURNAL_CONFLICT", Status.BLOCKED)
    finally:
        os.close(journal)
    return event


def require_managed_file_state(root: Path, plan: dict[str, Any], state: str) -> dict[str, Any]:
    _validate_plan(plan)
    current = replay_managed_file_journal(root, plan["journal_id"])
    if current is None:
        raise ManagedFileError("SOS_MANAGED_FILE_JOURNAL_MISSING", Status.STALE)
    if current["plan"] != plan or current["latest"]["plan_digest"] != plan["plan_digest"]:
        raise ManagedFileError("SOS_MANAGED_FILE_PLAN_MISMATCH", Status.STALE)
    if current["latest"]["state"] != state:
        raise ManagedFileError("SOS_MANAGED_FILE_STATE_MISMATCH", Status.STALE)
    return current["latest"]


def _bind_batch(
    root: Path, batch: dict[str, Any], plans: Sequence[dict[str, Any]]
) -> None:
    _validate_batch(batch)
    _require_batch_repository(root, batch)
    if len(plans) != batch["step_count"]:
        raise ManagedFileBatchError("SOS_MANAGED_FILE_BATCH_PLAN_MISMATCH", Status.STALE)
    for step, plan in zip(batch["steps"], plans, strict=True):
        _validate_plan(plan)
        _require_batch_step_plan(step, plan)
        if plan["repository_id"] != batch["repository_id"]:
            raise ManagedFileBatchError("SOS_MANAGED_FILE_BATCH_REPOSITORY_MISMATCH", Status.STALE)
        _write_plan(root, plan)
    stored = _read_batch(root, batch["batch_id"])
    if stored is not None:
        if stored != batch:
            raise ManagedFileBatchError("SOS_MANAGED_FILE_BATCH_MISMATCH", Status.STALE)
        return
    descriptor = _open_control_directory(root, ("managed-files", "batches"), create=True)
    try:
        try:
            _write_immutable_json(
                descriptor, batch["batch_id"] + ".json", batch, _MAX_BATCH_BYTES
            )
        except FileExistsError:
            observed = _read_json(
                descriptor, batch["batch_id"] + ".json", _MAX_BATCH_BYTES
            )
            _validate_batch(observed)
            if observed != batch:
                raise ManagedFileBatchError("SOS_MANAGED_FILE_BATCH_MISMATCH", Status.STALE)
    finally:
        os.close(descriptor)


def _read_batch(root: Path, batch_id: str) -> dict[str, Any] | None:
    _validate_journal_id(batch_id)
    try:
        descriptor = _open_control_directory(root, ("managed-files", "batches"), create=False)
    except FileNotFoundError:
        return None
    try:
        try:
            value = _read_json(descriptor, batch_id + ".json", _MAX_BATCH_BYTES)
        except FileNotFoundError:
            return None
    finally:
        os.close(descriptor)
    _validate_batch(value)
    if value["batch_id"] != batch_id:
        raise ManagedFileBatchError("SOS_MANAGED_FILE_BATCH_MISMATCH", Status.STALE)
    return value


def _rollback_managed_file_batch(
    root: Path,
    batch: dict[str, Any],
    *,
    apply_step: ManagedFileStepCallback | None,
    rollback_step: ManagedFileStepCallback,
    probe_step: ManagedFileProbeCallback,
    complete_prepared: bool,
) -> dict[str, Any]:
    for step in reversed(batch["steps"]):
        current = replay_managed_file_journal(root, step["journal_id"])
        if current is None or current["latest"]["state"] == "rolled_back":
            continue
        plan = _read_plan(root, step["plan_digest"])
        _require_batch_step_plan(step, plan)
        state = current["latest"]["state"]
        if state == "apply_prepared":
            observed = _probe_state(probe_step, plan)
            if observed == "before" and not complete_prepared:
                continue
            if observed == "before":
                if apply_step is None:
                    raise ManagedFileBatchError(
                        "SOS_MANAGED_FILE_BATCH_INTEGRATION_INCOMPLETE", Status.BLOCKED
                    )
                apply_step(plan)
                _require_probe_state(probe_step, plan, "after")
            elif observed != "after":
                raise ManagedFileBatchError("SOS_MANAGED_FILE_BATCH_TARGET_DRIFT", Status.STALE)
            record_managed_file_state(root, plan, "applied")
            state = "applied"
        if state == "applied":
            _require_probe_state(probe_step, plan, "after")
            record_managed_file_state(root, plan, "rollback_prepared")
            rollback_step(plan)
            _require_probe_state(probe_step, plan, "before")
            record_managed_file_state(root, plan, "rolled_back")
        elif state == "rollback_prepared":
            observed = _probe_state(probe_step, plan)
            if observed == "after":
                rollback_step(plan)
                _require_probe_state(probe_step, plan, "before")
            elif observed != "before":
                raise ManagedFileBatchError("SOS_MANAGED_FILE_BATCH_TARGET_DRIFT", Status.STALE)
            record_managed_file_state(root, plan, "rolled_back")
        elif state not in {"rolled_back", "apply_prepared"}:
            raise ManagedFileBatchError("SOS_MANAGED_FILE_BATCH_STATE_INVALID")
    return project_managed_file_batch(root, batch)


def _build_batch_projection(
    batch: dict[str, Any], states: Sequence[str]
) -> dict[str, Any]:
    if len(states) != batch["step_count"] or any(state not in _BATCH_STEP_STATES for state in states):
        raise ManagedFileBatchError("SOS_MANAGED_FILE_BATCH_PROJECTION_INVALID")
    if all(state == "not_started" for state in states):
        state = "not_started"
    elif all(item == "applied" for item in states):
        state = "integrated"
    elif all(item in {"not_started", "rolled_back"} for item in states) and any(
        item == "rolled_back" for item in states
    ):
        state = "rolled_back"
    else:
        state = "integration_incomplete"
    reasons = {
        "not_started": ["SOS_MANAGED_FILE_BATCH_NOT_STARTED"],
        "integrated": ["SOS_MANAGED_FILE_BATCH_INTEGRATED"],
        "rolled_back": ["SOS_MANAGED_FILE_BATCH_ROLLED_BACK"],
        "integration_incomplete": ["SOS_MANAGED_FILE_BATCH_INTEGRATION_INCOMPLETE"],
    }[state]
    step_values = [
        {
            "sequence_ordinal": step["sequence_ordinal"],
            "journal_id": step["journal_id"],
            "plan_digest": step["plan_digest"],
            "state": step_state,
        }
        for step, step_state in zip(batch["steps"], states, strict=True)
    ]
    projection = {
        "contract": _BATCH_PROJECTION_CONTRACT,
        "batch_id": batch["batch_id"],
        "repository_id": batch["repository_id"],
        "batch_digest": batch["batch_digest"],
        "state": state,
        "recovery_required": state == "integration_incomplete",
        "step_count": batch["step_count"],
        "not_started_count": states.count("not_started"),
        "applied_count": states.count("applied"),
        "rolled_back_count": states.count("rolled_back"),
        "in_progress_count": sum(
            item in {"apply_prepared", "rollback_prepared"} for item in states
        ),
        "reasons": reasons,
        "steps": step_values,
        "raw_content_serialized": False,
        "absolute_paths_serialized": False,
    }
    _validate_batch_projection(projection)
    return projection


def _safe_batch_projection(root: Path, batch: dict[str, Any]) -> dict[str, Any] | None:
    try:
        return project_managed_file_batch(root, batch)
    except Exception:
        return None


def _probe_state(probe_step: ManagedFileProbeCallback, plan: dict[str, Any]) -> str:
    observed = probe_step(plan)
    if observed not in {"before", "after", "drift"}:
        raise ManagedFileBatchError("SOS_MANAGED_FILE_BATCH_PROBE_INVALID")
    return observed


def _require_probe_state(
    probe_step: ManagedFileProbeCallback, plan: dict[str, Any], expected: str
) -> None:
    if _probe_state(probe_step, plan) != expected:
        raise ManagedFileBatchError("SOS_MANAGED_FILE_BATCH_TARGET_DRIFT", Status.STALE)


def _require_callbacks(*callbacks: object) -> None:
    if any(not callable(callback) for callback in callbacks):
        raise ManagedFileBatchError("SOS_MANAGED_FILE_BATCH_CALLBACK_INVALID")


def _require_batch_step_plan(step: dict[str, Any], plan: dict[str, Any]) -> None:
    if (
        step["journal_id"] != plan["journal_id"]
        or step["plan_digest"] != plan["plan_digest"]
        or step["target"] != plan["target"]
        or step["patch_kind"] != plan["patch_kind"]
    ):
        raise ManagedFileBatchError("SOS_MANAGED_FILE_BATCH_PLAN_MISMATCH", Status.STALE)


def _require_batch_repository(root: Path, batch: dict[str, Any]) -> None:
    if batch["repository_id"] != _observed_repository_id(root):
        raise ManagedFileBatchError("SOS_MANAGED_FILE_BATCH_REPOSITORY_MISMATCH", Status.STALE)


@contextmanager
def _managed_batch_lock(root: Path, batch_id: str) -> Iterator[None]:
    _validate_journal_id(batch_id)
    descriptor = _open_control_directory(root, ("managed-files", "batch-locks"), create=True)
    lock = -1
    try:
        lock = os.open(
            batch_id + ".lock", os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600, dir_fd=descriptor
        )
        observed = os.fstat(lock)
        if not stat.S_ISREG(observed.st_mode):
            raise ManagedFileBatchError("SOS_MANAGED_FILE_BATCH_LOCK_INVALID")
        fcntl.flock(lock, fcntl.LOCK_EX)
        yield
    finally:
        if lock >= 0:
            try:
                fcntl.flock(lock, fcntl.LOCK_UN)
            finally:
                os.close(lock)
        os.close(descriptor)


def _write_plan(root: Path, plan: dict[str, Any]) -> None:
    descriptor = _open_control_directory(root, ("managed-files", "plans"), create=True)
    try:
        name = plan["plan_digest"].removeprefix("sha256:") + ".json"
        try:
            _write_immutable_json(descriptor, name, plan, _MAX_PLAN_BYTES)
        except FileExistsError:
            if _read_json(descriptor, name, _MAX_PLAN_BYTES) != plan:
                raise ManagedFileError("SOS_MANAGED_FILE_PLAN_COLLISION")
    finally:
        os.close(descriptor)


def _read_plan(root: Path, digest: str) -> dict[str, Any]:
    if not _DIGEST.fullmatch(digest):
        raise ManagedFileError("SOS_MANAGED_FILE_PLAN_INVALID")
    descriptor = _open_control_directory(root, ("managed-files", "plans"), create=False)
    try:
        plan = _read_json(descriptor, digest.removeprefix("sha256:") + ".json", _MAX_PLAN_BYTES)
    except FileNotFoundError as exc:
        raise ManagedFileError("SOS_MANAGED_FILE_PLAN_MISSING") from exc
    finally:
        os.close(descriptor)
    _validate_plan(plan)
    if plan["plan_digest"] != digest:
        raise ManagedFileError("SOS_MANAGED_FILE_PLAN_MISMATCH", Status.STALE)
    return plan


def _validate_plan(value: object) -> None:
    required = {
        "contract", "journal_id", "repository_id", "target", "patch_kind",
        "before_exists", "before_byte_count", "before_digest", "patch_byte_count",
        "patch_digest", "after_exists", "after_byte_count", "after_digest",
        "raw_content_serialized", "absolute_paths_serialized", "plan_digest",
    }
    if not isinstance(value, dict) or set(value) != required:
        raise ManagedFileError("SOS_MANAGED_FILE_PLAN_INVALID")
    if value["contract"] != _PLAN_CONTRACT:
        raise ManagedFileError("SOS_MANAGED_FILE_PLAN_INVALID")
    _validate_journal_id(value["journal_id"])
    if not _DIGEST.fullmatch(value["repository_id"]):
        raise ManagedFileError("SOS_MANAGED_FILE_PLAN_INVALID")
    _validate_target(value["target"])
    if value["patch_kind"] not in {"create_file", "append_suffix"}:
        raise ManagedFileError("SOS_MANAGED_FILE_PLAN_INVALID")
    if not isinstance(value["before_exists"], bool) or value["after_exists"] is not True:
        raise ManagedFileError("SOS_MANAGED_FILE_PLAN_INVALID")
    for field in ("before_byte_count", "patch_byte_count", "after_byte_count"):
        if not isinstance(value[field], int) or isinstance(value[field], bool) or not 0 <= value[field] <= 1024 * 1024:
            raise ManagedFileError("SOS_MANAGED_FILE_PLAN_INVALID")
    for field in ("before_digest", "patch_digest", "after_digest", "plan_digest"):
        if not isinstance(value[field], str) or not _DIGEST.fullmatch(value[field]):
            raise ManagedFileError("SOS_MANAGED_FILE_PLAN_INVALID")
    if value["raw_content_serialized"] is not False or value["absolute_paths_serialized"] is not False:
        raise ManagedFileError("SOS_MANAGED_FILE_PLAN_INVALID")
    if value["patch_kind"] == "create_file":
        if value["before_exists"] or value["before_byte_count"] != 0 or value["before_digest"] != _EMPTY_DIGEST:
            raise ManagedFileError("SOS_MANAGED_FILE_PLAN_INVALID")
        if value["patch_byte_count"] != value["after_byte_count"] or value["patch_digest"] != value["after_digest"]:
            raise ManagedFileError("SOS_MANAGED_FILE_PLAN_INVALID")
    else:
        if (
            not value["before_exists"]
            or value["after_byte_count"] != value["before_byte_count"] + value["patch_byte_count"]
        ):
            raise ManagedFileError("SOS_MANAGED_FILE_PLAN_INVALID")
    if value["plan_digest"] != _sealed_digest(value, "plan_digest"):
        raise ManagedFileError("SOS_MANAGED_FILE_PLAN_INVALID")


def _validate_batch(value: object) -> None:
    required = {
        "contract", "batch_id", "repository_id", "step_count", "steps",
        "raw_content_serialized", "absolute_paths_serialized", "batch_digest",
    }
    if not isinstance(value, dict) or set(value) != required:
        raise ManagedFileBatchError("SOS_MANAGED_FILE_BATCH_INVALID")
    if value["contract"] != _BATCH_CONTRACT:
        raise ManagedFileBatchError("SOS_MANAGED_FILE_BATCH_INVALID")
    _validate_journal_id(value["batch_id"])
    if not isinstance(value["repository_id"], str) or not _DIGEST.fullmatch(value["repository_id"]):
        raise ManagedFileBatchError("SOS_MANAGED_FILE_BATCH_INVALID")
    if (
        not isinstance(value["step_count"], int)
        or isinstance(value["step_count"], bool)
        or not 1 <= value["step_count"] <= _MAX_BATCH_STEPS
        or not isinstance(value["steps"], list)
        or len(value["steps"]) != value["step_count"]
    ):
        raise ManagedFileBatchError("SOS_MANAGED_FILE_BATCH_INVALID")
    journal_ids: set[str] = set()
    targets: set[str] = set()
    for ordinal, step in enumerate(value["steps"], start=1):
        if not isinstance(step, dict) or set(step) != {
            "sequence_ordinal", "journal_id", "plan_digest", "target", "patch_kind"
        }:
            raise ManagedFileBatchError("SOS_MANAGED_FILE_BATCH_INVALID")
        if step["sequence_ordinal"] != ordinal:
            raise ManagedFileBatchError("SOS_MANAGED_FILE_BATCH_INVALID")
        _validate_journal_id(step["journal_id"])
        if not isinstance(step["plan_digest"], str) or not _DIGEST.fullmatch(step["plan_digest"]):
            raise ManagedFileBatchError("SOS_MANAGED_FILE_BATCH_INVALID")
        _validate_target(step["target"])
        if step["patch_kind"] not in {"create_file", "append_suffix"}:
            raise ManagedFileBatchError("SOS_MANAGED_FILE_BATCH_INVALID")
        if step["journal_id"] in journal_ids or step["target"] in targets:
            raise ManagedFileBatchError("SOS_MANAGED_FILE_BATCH_DUPLICATE_TARGET")
        journal_ids.add(step["journal_id"])
        targets.add(step["target"])
    if value["raw_content_serialized"] is not False or value["absolute_paths_serialized"] is not False:
        raise ManagedFileBatchError("SOS_MANAGED_FILE_BATCH_INVALID")
    if not isinstance(value["batch_digest"], str) or not _DIGEST.fullmatch(value["batch_digest"]):
        raise ManagedFileBatchError("SOS_MANAGED_FILE_BATCH_INVALID")
    if value["batch_digest"] != _sealed_digest(value, "batch_digest"):
        raise ManagedFileBatchError("SOS_MANAGED_FILE_BATCH_INVALID")


def _validate_batch_projection(value: object) -> None:
    required = {
        "contract", "batch_id", "repository_id", "batch_digest", "state",
        "recovery_required", "step_count", "not_started_count", "applied_count",
        "rolled_back_count", "in_progress_count", "reasons", "steps",
        "raw_content_serialized", "absolute_paths_serialized",
    }
    if not isinstance(value, dict) or set(value) != required:
        raise ManagedFileBatchError("SOS_MANAGED_FILE_BATCH_PROJECTION_INVALID")
    if value["contract"] != _BATCH_PROJECTION_CONTRACT:
        raise ManagedFileBatchError("SOS_MANAGED_FILE_BATCH_PROJECTION_INVALID")
    _validate_journal_id(value["batch_id"])
    for field in ("repository_id", "batch_digest"):
        if not isinstance(value[field], str) or not _DIGEST.fullmatch(value[field]):
            raise ManagedFileBatchError("SOS_MANAGED_FILE_BATCH_PROJECTION_INVALID")
    if value["state"] not in {"not_started", "integrated", "rolled_back", "integration_incomplete"}:
        raise ManagedFileBatchError("SOS_MANAGED_FILE_BATCH_PROJECTION_INVALID")
    if value["recovery_required"] is not (value["state"] == "integration_incomplete"):
        raise ManagedFileBatchError("SOS_MANAGED_FILE_BATCH_PROJECTION_INVALID")
    counts = (
        "step_count", "not_started_count", "applied_count", "rolled_back_count",
        "in_progress_count",
    )
    if any(
        not isinstance(value[field], int)
        or isinstance(value[field], bool)
        or not 0 <= value[field] <= _MAX_BATCH_STEPS
        for field in counts
    ):
        raise ManagedFileBatchError("SOS_MANAGED_FILE_BATCH_PROJECTION_INVALID")
    if not isinstance(value["steps"], list) or len(value["steps"]) != value["step_count"]:
        raise ManagedFileBatchError("SOS_MANAGED_FILE_BATCH_PROJECTION_INVALID")
    observed_counts = {state: 0 for state in _BATCH_STEP_STATES}
    for ordinal, step in enumerate(value["steps"], start=1):
        if not isinstance(step, dict) or set(step) != {
            "sequence_ordinal", "journal_id", "plan_digest", "state"
        }:
            raise ManagedFileBatchError("SOS_MANAGED_FILE_BATCH_PROJECTION_INVALID")
        if step["sequence_ordinal"] != ordinal:
            raise ManagedFileBatchError("SOS_MANAGED_FILE_BATCH_PROJECTION_INVALID")
        _validate_journal_id(step["journal_id"])
        if not isinstance(step["plan_digest"], str) or not _DIGEST.fullmatch(step["plan_digest"]):
            raise ManagedFileBatchError("SOS_MANAGED_FILE_BATCH_PROJECTION_INVALID")
        if step["state"] not in _BATCH_STEP_STATES:
            raise ManagedFileBatchError("SOS_MANAGED_FILE_BATCH_PROJECTION_INVALID")
        observed_counts[step["state"]] += 1
    if (
        value["not_started_count"] != observed_counts["not_started"]
        or value["applied_count"] != observed_counts["applied"]
        or value["rolled_back_count"] != observed_counts["rolled_back"]
        or value["in_progress_count"]
        != observed_counts["apply_prepared"] + observed_counts["rollback_prepared"]
    ):
        raise ManagedFileBatchError("SOS_MANAGED_FILE_BATCH_PROJECTION_INVALID")
    expected_reason = {
        "not_started": "SOS_MANAGED_FILE_BATCH_NOT_STARTED",
        "integrated": "SOS_MANAGED_FILE_BATCH_INTEGRATED",
        "rolled_back": "SOS_MANAGED_FILE_BATCH_ROLLED_BACK",
        "integration_incomplete": "SOS_MANAGED_FILE_BATCH_INTEGRATION_INCOMPLETE",
    }[value["state"]]
    if value["reasons"] != [expected_reason]:
        raise ManagedFileBatchError("SOS_MANAGED_FILE_BATCH_PROJECTION_INVALID")
    if value["raw_content_serialized"] is not False or value["absolute_paths_serialized"] is not False:
        raise ManagedFileBatchError("SOS_MANAGED_FILE_BATCH_PROJECTION_INVALID")


def _validate_event(value: object) -> None:
    required = {
        "contract", "journal_id", "repository_id", "plan_digest", "state",
        "sequence_ordinal", "predecessor_event", "raw_content_serialized",
        "absolute_paths_serialized", "event_digest",
    }
    if not isinstance(value, dict) or set(value) != required or value["contract"] != _EVENT_CONTRACT:
        raise ManagedFileError("SOS_MANAGED_FILE_EVENT_INVALID")
    _validate_journal_id(value["journal_id"])
    for field in ("repository_id", "plan_digest", "event_digest"):
        if not isinstance(value[field], str) or not _DIGEST.fullmatch(value[field]):
            raise ManagedFileError("SOS_MANAGED_FILE_EVENT_INVALID")
    if value["state"] not in _STATES:
        raise ManagedFileError("SOS_MANAGED_FILE_EVENT_INVALID")
    if not isinstance(value["sequence_ordinal"], int) or isinstance(value["sequence_ordinal"], bool):
        raise ManagedFileError("SOS_MANAGED_FILE_EVENT_INVALID")
    if not 1 <= value["sequence_ordinal"] <= _MAX_EVENTS:
        raise ManagedFileError("SOS_MANAGED_FILE_EVENT_INVALID")
    predecessor = value["predecessor_event"]
    if predecessor is not None and (not isinstance(predecessor, str) or not _DIGEST.fullmatch(predecessor)):
        raise ManagedFileError("SOS_MANAGED_FILE_EVENT_INVALID")
    if value["raw_content_serialized"] is not False or value["absolute_paths_serialized"] is not False:
        raise ManagedFileError("SOS_MANAGED_FILE_EVENT_INVALID")
    if value["event_digest"] != _sealed_digest(value, "event_digest"):
        raise ManagedFileError("SOS_MANAGED_FILE_EVENT_INVALID")


def _validate_journal_id(value: object) -> None:
    if not isinstance(value, str) or not _JOURNAL_ID.fullmatch(value):
        raise ManagedFileError("SOS_MANAGED_FILE_JOURNAL_ID_INVALID")


def _validate_target(value: object) -> None:
    if not isinstance(value, str) or len(value.encode("utf-8")) > 512:
        raise ManagedFileError("SOS_MANAGED_FILE_TARGET_INVALID")
    if any(character in value for character in "*?[]"):
        raise ManagedFileError("SOS_MANAGED_FILE_TARGET_INVALID")
    path = Path(value)
    if path.is_absolute() or not path.parts or path.parts[0] == ".sigma":
        raise ManagedFileError("SOS_MANAGED_FILE_TARGET_INVALID")
    if any(part in ("", ".", "..") or "/" in part or "\\" in part or "\x00" in part for part in path.parts):
        raise ManagedFileError("SOS_MANAGED_FILE_TARGET_INVALID")


def _sealed_digest(value: dict[str, Any], field: str) -> str:
    material = dict(value)
    material[field] = "sha256:" + "0" * 64
    return digest_value(material)


def _observed_repository_id(root: Path) -> str:
    from .workspace import workspace_status

    observed = workspace_status(os.fspath(root))
    repository_id = observed.details.get("repository_id")
    if not isinstance(repository_id, str) or not _DIGEST.fullmatch(repository_id):
        raise ManagedFileError("SOS_MANAGED_FILE_REPOSITORY_INVALID")
    return repository_id


def _open_control_directory(root: Path, parts: tuple[str, ...], *, create: bool) -> int:
    descriptor = os.open(root / ".sigma", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        for part in parts:
            if create:
                try:
                    os.mkdir(part, mode=0o700, dir_fd=descriptor)
                except FileExistsError:
                    pass
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=descriptor)
            os.close(descriptor)
            descriptor = child
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def _write_immutable_json(directory: int, name: str, value: dict[str, Any], limit: int) -> None:
    payload = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    if len(payload) > limit:
        raise ManagedFileError("SOS_MANAGED_FILE_OUTPUT_LIMIT_EXCEEDED", Status.UNSUPPORTED)
    temporary = f".sos-managed.{os.getpid()}.{os.urandom(8).hex()}"
    try:
        descriptor = os.open(
            temporary,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
            0o600,
            dir_fd=directory,
        )
        try:
            offset = 0
            while offset < len(payload):
                written = os.write(descriptor, payload[offset:])
                if written <= 0:
                    raise ManagedFileError("SOS_MANAGED_FILE_WRITE_FAILED", Status.BLOCKED)
                offset += written
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        os.link(temporary, name, src_dir_fd=directory, dst_dir_fd=directory, follow_symlinks=False)
        os.fsync(directory)
    finally:
        try:
            os.unlink(temporary, dir_fd=directory)
        except FileNotFoundError:
            pass


def _read_json(directory: int, name: str, limit: int) -> dict[str, Any]:
    descriptor = os.open(name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=directory)
    try:
        observed = os.fstat(descriptor)
        if not stat.S_ISREG(observed.st_mode) or observed.st_size > limit:
            raise ManagedFileError("SOS_MANAGED_FILE_ARTIFACT_INVALID")
        payload = bytearray()
        while len(payload) <= limit:
            chunk = os.read(descriptor, min(64 * 1024, limit + 1 - len(payload)))
            if not chunk:
                break
            payload.extend(chunk)
        if len(payload) > limit:
            raise ManagedFileError("SOS_MANAGED_FILE_ARTIFACT_INVALID")
    finally:
        os.close(descriptor)
    try:
        value = json.loads(payload.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ManagedFileError("SOS_MANAGED_FILE_ARTIFACT_INVALID") from exc
    if not isinstance(value, dict):
        raise ManagedFileError("SOS_MANAGED_FILE_ARTIFACT_INVALID")
    return value
