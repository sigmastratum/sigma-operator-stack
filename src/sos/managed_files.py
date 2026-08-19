"""Content-safe append-only journal for reversible external managed files."""

from __future__ import annotations

import hashlib
import json
import os
import re
import stat
from pathlib import Path
from typing import Any

from .contracts import digest_value
from .result import Status


_PLAN_CONTRACT = "sos_managed_file_plan_v1"
_EVENT_CONTRACT = "sos_managed_file_event_v1"
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
_EMPTY_DIGEST = "sha256:" + hashlib.sha256(b"").hexdigest()


class ManagedFileError(RuntimeError):
    def __init__(self, reason: str, status: Status = Status.INVALID) -> None:
        super().__init__(reason)
        self.reason = reason
        self.status = status


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
