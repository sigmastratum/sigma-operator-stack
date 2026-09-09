"""One-confirmation adapter detach and project-runtime removal coordinator."""

from dataclasses import dataclass

from . import client_integration as codex
from . import claude_integration as claude
from .contracts import canonical_json, digest_value
from .project_runtime import ProjectRuntimeError
from .result import Status, TerminalResult
from .runtime_removal import prepare_runtime_removal, execute_runtime_removal, recover_runtime_removal
from .runtime_transition import _parse, _verified
from .integration_inventory import unknown_integration_files
from .platforms.project_runtime_removal import snapshot_owned_generation
from .adapter_lock import adapter_mutation_lock


_RECORD = "lifecycle/native-removal.json"


@dataclass(frozen=True)
class NativeRemovalPlan:
    transition: object
    sealed: bytes

    @property
    def payload(self):
        return _parse(self.sealed)

    def preview(self):
        return TerminalResult(
            "sos_native_removal_result_v1", Status.OWNER_REQUIRED,
            ("SOS_NATIVE_REMOVAL_CONFIRMATION_REQUIRED",),
            {**self.payload, "writes_performed": False,
             "preserve": [".sigma", "user_files", "git_head", "legacy_shared_runtime",
                          "predecessor_generations"]},
        )


def _client_state(root, client):
    manifest = (codex._read_setup_manifest(root) if client == "codex"
                else claude._read_manifest(root))
    if manifest is None:
        return None
    if manifest.get("state") not in {"installed", "remove_prepared", "removed"}:
        raise ProjectRuntimeError("SOS_PROJECT_RUNTIME_RECOVERY_REQUIRED")
    return {"client": client, "state": manifest["state"],
            "manifest_digest": digest_value(manifest)}


def prepare_native_removal(transition):
    if unknown_integration_files(str(transition.root)):
        raise ProjectRuntimeError("SOS_PROJECT_RUNTIME_REFERENCES_UNKNOWN")
    _verified(transition, active=True)
    snapshot = snapshot_owned_generation(transition.namespace, transition.root,
        transition.payload["identity"], transition.payload["plan_digest"])
    clients = [state for client in ("codex", "claude-code")
               if (state := _client_state(transition.root, client)) is not None]
    if not clients:
        raise ProjectRuntimeError("SOS_PROJECT_RUNTIME_STILL_REFERENCED")
    material = {
        "contract": "sos_native_removal_plan_v1",
        "transition_plan_digest": transition.payload["plan_digest"],
        "clients": clients,
        "runtime_identity_digest": transition.payload["identity"]["identity_digest"],
        "runtime_snapshot_digest": digest_value(snapshot),
        "runtime_entry_count": len(snapshot["entries"]),
        "runtime_byte_count": sum(entry.get("size", 0) for entry in snapshot["entries"].values()),
        "qualification_performed": False,
        "raw_content_serialized": False,
        "absolute_paths_serialized": False,
    }
    previous = _record(transition.root)
    if previous is not None:
        if codex.read_integration_control_file(transition.root, "lifecycle/runtime-removal.json") is not None:
            raise ProjectRuntimeError("SOS_PROJECT_RUNTIME_RECOVERY_REQUIRED")
        material["previous_plan_digest"] = previous["plan"]["plan_digest"]
    material["plan_digest"] = digest_value(material)
    return NativeRemovalPlan(transition, canonical_json(material))


def _remove_clients(plan):
    binding = plan.transition.successor
    for row in plan.payload["clients"]:
        state = _client_state(plan.transition.root, row["client"])
        if state is not None and state["state"] == "removed":
            continue
        if row["client"] == "codex":
            result = codex.remove_codex_setup(
                str(plan.transition.root), confirmed=True, controlling_tty_observed=True,
                launcher=binding, require_current_contract=False,
            )
        else:
            manifest = claude._read_manifest(plan.transition.root)
            if manifest is not None and manifest["state"] == "remove_prepared":
                result = claude.recover_claude_setup(str(plan.transition.root), launcher=binding)
            else:
                result = claude.remove_claude_setup(
                    str(plan.transition.root), confirmed=True, controlling_tty_observed=True,
                    launcher=binding,
                )
        if result.status != Status.SUCCESS:
            return result
    return None


def _record(root):
    raw = codex.read_integration_control_file(root, _RECORD)
    if raw is None:
        return None
    value = _parse(raw)
    if (not isinstance(value, dict) or set(value) != {"plan", "state"}
            or value["state"] not in {"detaching", "removing_runtime", "recovery_required", "removed"}):
        raise ProjectRuntimeError("SOS_PROJECT_RUNTIME_RECOVERY_REQUIRED")
    plan = value["plan"]
    fields = {"contract", "transition_plan_digest", "clients", "runtime_identity_digest",
              "runtime_snapshot_digest", "runtime_entry_count", "runtime_byte_count",
              "qualification_performed", "raw_content_serialized", "absolute_paths_serialized", "plan_digest"}
    if (not isinstance(plan, dict) or set(plan) not in (fields, fields | {"previous_plan_digest"})
            or plan.get("contract") != "sos_native_removal_plan_v1"
            or any(plan.get(key) is not False for key in ("qualification_performed", "raw_content_serialized", "absolute_paths_serialized"))
            or type(plan.get("runtime_entry_count")) is not int or not 1 <= plan["runtime_entry_count"] <= 30000
            or type(plan.get("runtime_byte_count")) is not int or not 0 <= plan["runtime_byte_count"] <= 2 * 1024**3
            or not isinstance(plan.get("clients"), list) or not 1 <= len(plan["clients"]) <= 2
            or plan.get("plan_digest") != digest_value({k: v for k, v in plan.items() if k != "plan_digest"})):
        raise ProjectRuntimeError("SOS_PROJECT_RUNTIME_RECOVERY_REQUIRED")
    seen = set()
    for row in plan["clients"]:
        if (not isinstance(row, dict) or set(row) != {"client", "state", "manifest_digest"}
                or row["client"] not in {"codex", "claude-code"} or row["client"] in seen
                or row["state"] not in {"installed", "remove_prepared", "removed"}):
            raise ProjectRuntimeError("SOS_PROJECT_RUNTIME_RECOVERY_REQUIRED")
        seen.add(row["client"])
    return value


def _finish_runtime(plan):
    runtime_record = codex.read_integration_control_file(
        plan.transition.root, "lifecycle/runtime-removal.json"
    )
    if runtime_record is None:
        removal = prepare_runtime_removal(plan.transition)
        if removal.payload["snapshot_digest"] != plan.payload["runtime_snapshot_digest"]:
            raise ProjectRuntimeError("SOS_PROJECT_RUNTIME_PREVIEW_STALE")
        result = execute_runtime_removal(removal,
            confirmed_plan_digest=removal.payload["plan_digest"], controlling_tty_observed=True)
    else:
        value = _parse(runtime_record)
        if not isinstance(value, dict) or set(value) != {"plan", "state"} or not isinstance(value["plan"], dict):
            raise ProjectRuntimeError("SOS_PROJECT_RUNTIME_RECOVERY_REQUIRED")
        digest = value["plan"].get("plan_digest")
        if value.get("plan", {}).get("snapshot_digest") != plan.payload["runtime_snapshot_digest"]:
            raise ProjectRuntimeError("SOS_PROJECT_RUNTIME_PREVIEW_STALE")
        result = recover_runtime_removal(plan.transition,
            confirmed_plan_digest=digest, controlling_tty_observed=True)
    state = "removed" if result.status == Status.SUCCESS else "recovery_required"
    codex.publish_integration_control_file(plan.transition.root, _RECORD,
        canonical_json({"plan": plan.payload, "state": state}))
    return TerminalResult("sos_native_removal_result_v1", result.status, result.reasons,
        {**result.details, "aggregate_plan_digest": plan.payload["plan_digest"],
         "adapters_removed": result.status == Status.SUCCESS})


def execute_native_removal(plan, *, confirmed_plan_digest=None,
                           controlling_tty_observed=False):
    if confirmed_plan_digest != plan.payload["plan_digest"] or not controlling_tty_observed:
        return plan.preview()
    with adapter_mutation_lock(plan.transition.root):
        detached = _detach_confirmed(plan)
        if detached is not None:
            return detached
    try:
        return _finish_runtime(plan)
    except (ProjectRuntimeError, OSError):
        codex.publish_integration_control_file(plan.transition.root, _RECORD,
            canonical_json({"plan": plan.payload, "state": "recovery_required"}))
        return TerminalResult("sos_native_removal_result_v1", Status.BLOCKED,
            ("SOS_NATIVE_REMOVAL_RECOVERY_REQUIRED",),
            {"recovery_required": True, "partial_deletion_possible": True})


def _detach_confirmed(plan):
    existing = _record(plan.transition.root)
    if existing is None:
        if prepare_native_removal(plan.transition).sealed != plan.sealed:
            raise ProjectRuntimeError("SOS_PROJECT_RUNTIME_PREVIEW_STALE")
        codex.publish_integration_control_file(
            plan.transition.root, _RECORD,
            canonical_json({"plan": plan.payload, "state": "detaching"}),
        )
    elif existing["plan"] != plan.payload:
        if (plan.payload.get("previous_plan_digest") != existing["plan"]["plan_digest"]
                or codex.read_integration_control_file(plan.transition.root, "lifecycle/runtime-removal.json") is not None
                or prepare_native_removal(plan.transition).sealed != plan.sealed):
            raise ProjectRuntimeError("SOS_PROJECT_RUNTIME_RECOVERY_REQUIRED")
        codex.publish_integration_control_file(plan.transition.root, _RECORD,
            canonical_json({"plan": plan.payload, "state": "detaching"}))
    elif existing["state"] == "removed":
        return None  # Runtime removal rechecks the retained completion journal.
    failed = _remove_clients(plan)
    if failed is not None:
        return TerminalResult("sos_native_removal_result_v1", Status.BLOCKED,
            ("SOS_NATIVE_REMOVAL_RECOVERY_REQUIRED",),
            {"plan_digest": plan.payload["plan_digest"], "recovery_required": True})
    codex.publish_integration_control_file(
        plan.transition.root, _RECORD,
        canonical_json({"plan": plan.payload, "state": "removing_runtime"}),
    )
    return None


def recover_native_removal(transition, *, confirmed_plan_digest=None,
                           controlling_tty_observed=False):
    existing = _record(transition.root)
    if existing is None:
        raise ProjectRuntimeError("SOS_PROJECT_RUNTIME_RECOVERY_REQUIRED")
    if (existing["plan"].get("transition_plan_digest") != transition.payload["plan_digest"]
            or existing["plan"].get("runtime_identity_digest") != transition.payload["identity"]["identity_digest"]):
        raise ProjectRuntimeError("SOS_PROJECT_RUNTIME_RECOVERY_REQUIRED")
    if codex.read_integration_control_file(transition.root, "lifecycle/runtime-removal.json") is None:
        # Before the first unlink, recovery can show a new exact snapshot and
        # require explicit confirmation. Never silently widen an old deletion.
        plan = prepare_native_removal(transition)
    else:
        plan = NativeRemovalPlan(transition, canonical_json(existing["plan"]))
    if confirmed_plan_digest is None or not controlling_tty_observed:
        return TerminalResult("sos_native_removal_result_v1", Status.OWNER_REQUIRED,
            ("SOS_NATIVE_REMOVAL_RECOVERY_CONFIRMATION_REQUIRED",),
            {**plan.payload, "writes_performed": False, "recovery_required": True})
    if confirmed_plan_digest != plan.payload["plan_digest"]:
        raise ProjectRuntimeError("SOS_PROJECT_RUNTIME_PREVIEW_STALE")
    return execute_native_removal(plan, confirmed_plan_digest=confirmed_plan_digest,
                                  controlling_tty_observed=True)
