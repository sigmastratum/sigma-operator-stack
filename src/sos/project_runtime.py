"""Pure, inactive project-runtime identity and transition-chain contracts.

These validators establish consistency, not filesystem ownership, confirmation,
provisioning, or successful adapter mutation. No caller is wired to them yet.
"""

from __future__ import annotations

import copy
import re

from .contracts import digest_value
from .maintenance_binding import MaintenanceBindingError, MaintenanceLauncherBinding


_DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
_EDGES = {
    "previewed": {"confirmed", "aborted"},
    "confirmed": {"provisioning", "aborted"},
    "provisioning": {"ready", "aborted", "recovery_required"},
    "ready": {"switching", "aborted", "recovery_required"},
    "switching": {"committed", "rolled_back", "recovery_required"},
    "recovery_required": {"rolled_back"},
    "committed": set(),
    "rolled_back": set(),
    "aborted": set(),
}
_FLAGS = {"raw_content_serialized": False, "absolute_paths_serialized": False}
_IDENTITY_FIELDS = {
    "contract", "owner_digest", "root_digest", "repository_digest", "project_key",
    "maintenance_binding", "wheel_digest", "interpreter_digest", "generation_key",
    "identity_digest", *_FLAGS,
}
_EVENT_FIELDS = {
    "contract", "sequence", "state", "previous_digest", "plan_digest",
    "predecessor_receipt_digest", "identity_digest", "event_digest", *_FLAGS,
}


class ProjectRuntimeError(RuntimeError):
    def __init__(self, reason: str = "SOS_PROJECT_RUNTIME_CONTRACT_INVALID") -> None:
        super().__init__(reason)
        self.reason = reason


def _digest(value: object) -> str:
    if not isinstance(value, str) or not _DIGEST.fullmatch(value):
        raise ProjectRuntimeError()
    return value


def _seal(value: dict[str, object], field: str) -> dict[str, object]:
    result = copy.deepcopy(value)
    result[field] = digest_value(result)
    return result


def _record(value: object, fields: set[str], contract: str, digest_field: str) -> dict:
    if not isinstance(value, dict) or set(value) != fields:
        raise ProjectRuntimeError()
    if value["contract"] != contract or any(value[key] is not False for key in _FLAGS):
        raise ProjectRuntimeError()
    supplied = _digest(value[digest_field])
    material = {key: item for key, item in value.items() if key != digest_field}
    try:
        actual = digest_value(material)
    except (TypeError, ValueError, RuntimeError, RecursionError):
        raise ProjectRuntimeError() from None
    if supplied != actual:
        raise ProjectRuntimeError("SOS_PROJECT_RUNTIME_DIGEST_MISMATCH")
    return copy.deepcopy(value)


def runtime_identity(
    *, owner_digest: str, root_digest: str, repository_digest: str,
    maintenance_binding: object, wheel_digest: str, interpreter_digest: str,
) -> dict[str, object]:
    """Bind caller-observed canonical root/user/repository digests to a payload.

    The caller must independently observe those identities without following
    untrusted links. Hashes in an untrusted marker are not observations.
    """
    for value in (owner_digest, root_digest, repository_digest, wheel_digest, interpreter_digest):
        _digest(value)
    try:
        binding = MaintenanceLauncherBinding.from_payload(maintenance_binding)
    except MaintenanceBindingError:
        raise ProjectRuntimeError("SOS_PROJECT_RUNTIME_RELEASE_INVALID") from None
    if (binding.system, binding.architecture) not in {("linux", "x86_64"), ("darwin", "arm64")}:
        raise ProjectRuntimeError("SOS_PROJECT_RUNTIME_PLATFORM_UNSUPPORTED")
    project_key = digest_value({
        "domain": "sos_project_runtime_project_v1", "owner_digest": owner_digest,
        "root_digest": root_digest, "repository_digest": repository_digest,
    })
    generation_key = digest_value({
        "domain": "sos_project_runtime_generation_v1", "project_key": project_key,
        "maintenance_binding_digest": binding.digest, "wheel_digest": wheel_digest,
        "interpreter_digest": interpreter_digest,
    })
    return _seal({
        "contract": "sos_project_runtime_identity_v1", **_FLAGS,
        "owner_digest": owner_digest, "root_digest": root_digest,
        "repository_digest": repository_digest, "project_key": project_key,
        "maintenance_binding": binding.payload(), "wheel_digest": wheel_digest,
        "interpreter_digest": interpreter_digest, "generation_key": generation_key,
    }, "identity_digest")


def validate_runtime_identity(
    value: object, *, owner_digest: str, root_digest: str, repository_digest: str,
) -> dict[str, object]:
    record = _record(value, _IDENTITY_FIELDS, "sos_project_runtime_identity_v1", "identity_digest")
    expected = runtime_identity(
        owner_digest=owner_digest, root_digest=root_digest, repository_digest=repository_digest,
        maintenance_binding=record["maintenance_binding"], wheel_digest=record["wheel_digest"],
        interpreter_digest=record["interpreter_digest"],
    )
    if record != expected:
        raise ProjectRuntimeError("SOS_PROJECT_RUNTIME_OWNERSHIP_MISMATCH")
    return expected


def transition_event(
    *, state: str, plan_digest: str, predecessor_receipt_digest: str,
    identity_digest: str, previous: object = None,
) -> dict[str, object]:
    """Construct a structurally valid event; this does not authorize its phase."""
    anchors = {
        "plan_digest": _digest(plan_digest),
        "predecessor_receipt_digest": _digest(predecessor_receipt_digest),
        "identity_digest": _digest(identity_digest),
    }
    if not isinstance(state, str) or state not in _EDGES:
        raise ProjectRuntimeError()
    if previous is None:
        if state != "previewed":
            raise ProjectRuntimeError("SOS_PROJECT_RUNTIME_TRANSITION_INVALID")
        sequence, previous_digest = 0, None
    else:
        prior = _validate_event(previous)
        if state not in _EDGES[prior["state"]] or any(prior[key] != value for key, value in anchors.items()):
            raise ProjectRuntimeError("SOS_PROJECT_RUNTIME_TRANSITION_INVALID")
        sequence, previous_digest = prior["sequence"] + 1, prior["event_digest"]
    return _seal({
        "contract": "sos_project_runtime_transition_event_v1", **_FLAGS, **anchors,
        "sequence": sequence, "state": state, "previous_digest": previous_digest,
    }, "event_digest")


def _validate_event(value: object) -> dict:
    record = _record(value, _EVENT_FIELDS, "sos_project_runtime_transition_event_v1", "event_digest")
    if type(record["sequence"]) is not int or not 0 <= record["sequence"] <= 32:
        raise ProjectRuntimeError()
    if not isinstance(record["state"], str) or record["state"] not in _EDGES:
        raise ProjectRuntimeError()
    for key in ("plan_digest", "predecessor_receipt_digest", "identity_digest"):
        _digest(record[key])
    if record["sequence"] == 0:
        if record["previous_digest"] is not None or record["state"] != "previewed":
            raise ProjectRuntimeError()
    else:
        _digest(record["previous_digest"])
    return record


def validate_transition_chain(
    events: object, *, plan_digest: str, predecessor_receipt_digest: str,
    identity_digest: str, expected_tip_digest: str,
) -> dict[str, object]:
    """Check a complete ordered chain against independently retained anchors.

    An expected tip is required: a prefix cannot claim to be the latest state.
    A valid committed record is still only a claim, not an executable postcheck.
    """
    _digest(expected_tip_digest)
    if not isinstance(events, list) or not 1 <= len(events) <= 32:
        raise ProjectRuntimeError()
    previous = None
    for event in events:
        record = _validate_event(event)
        expected = transition_event(
            state=record["state"], plan_digest=plan_digest,
            predecessor_receipt_digest=predecessor_receipt_digest,
            identity_digest=identity_digest, previous=previous,
        )
        if record != expected:
            raise ProjectRuntimeError("SOS_PROJECT_RUNTIME_CHAIN_INVALID")
        previous = record
    if previous["event_digest"] != expected_tip_digest:
        raise ProjectRuntimeError("SOS_PROJECT_RUNTIME_TIP_MISMATCH")
    return previous
