"""Qualified runtime-only removal after the official adapters are detached.

This is not the public aggregate uninstall route. The carrier must finish the
adapter removal preview/confirmation first. Shared predecessor environments and
all other project generations are retained.
"""

from dataclasses import dataclass
import os
from pathlib import Path
import tomllib

from . import client_integration as codex
from . import claude_integration as claude
from .atomic_switch import _read_plan, _read_events, _switch_lock
from .contracts import canonical_json, digest_value
from .integration_inventory import unknown_integration_files
from .managed_files import project_managed_file_batch
from .platform_services import current_platform_services
from .platforms.project_runtime_posix import runtime_namespace_lock, resolve_runtime_reference
from .platforms.project_runtime_removal import snapshot_owned_generation, delete_owned_generation, read_removal_snapshot
from .project_runtime import ProjectRuntimeError
from .result import Status, TerminalResult
from .runtime_transition import _history, _lock, _parse, _verified


_RECORD = "lifecycle/runtime-removal.json"
_FIELDS = {"contract", "history_digest", "identity_digest", "snapshot_digest", "entry_count",
           "byte_count", "raw_content_serialized", "absolute_paths_serialized", "plan_digest"}


def _validate(value):
    if (not isinstance(value, dict) or set(value) != _FIELDS
            or value["contract"] != "sos_project_runtime_remove_plan_v1"
            or value["raw_content_serialized"] is not False or value["absolute_paths_serialized"] is not False
            or type(value["entry_count"]) is not int or not 0 <= value["entry_count"] <= 30000
            or type(value["byte_count"]) is not int or not 0 <= value["byte_count"] <= 2 * 1024**3
            or value["plan_digest"] != digest_value({k:v for k,v in value.items() if k != "plan_digest"})):
        raise ProjectRuntimeError("SOS_PROJECT_RUNTIME_REMOVAL_PLAN_INVALID")


def _detached(root, binding, generation):
    if unknown_integration_files(str(root)):
        raise ProjectRuntimeError("SOS_PROJECT_RUNTIME_REFERENCES_UNKNOWN")
    for read in (codex._read_setup_manifest, claude._read_manifest):
        manifest = read(root)
        if manifest is not None:
            if manifest["state"] != "removed":
                raise ProjectRuntimeError("SOS_PROJECT_RUNTIME_STILL_REFERENCED")
            if project_managed_file_batch(root, manifest["batch"])["state"] != "rolled_back":
                raise ProjectRuntimeError("SOS_PROJECT_RUNTIME_RECOVERY_REQUIRED")
    for target, group, parse in ((".codex/config.toml", "mcp_servers", lambda raw: tomllib.loads(raw.decode("utf-8"))),
                                  (".mcp.json", "mcpServers", claude._strict_json)):
        raw, exists, _ = codex.read_integration_target(root, target)
        if exists:
            try:
                value = parse(raw)
                if not isinstance(value, dict) or not isinstance(value.get(group, {}), dict):
                    raise ValueError()
                if "sigma_operator_stack" in value.get(group, {}):
                    raise ProjectRuntimeError("SOS_PROJECT_RUNTIME_STILL_REFERENCED")
                for server in value.get(group, {}).values():
                    if not isinstance(server, dict):
                        raise ValueError()
                    command = server.get("command")
                    if command is None and isinstance(server.get("url"), str):
                        continue
                    if not isinstance(command, str) or not command or "\x00" in command:
                        raise ValueError()
                    candidate = Path(os.path.normpath(command if os.path.isabs(command)
                                                       else os.fspath(root / command)))
                    if command == binding.command or candidate == generation or generation in candidate.parents:
                        raise ProjectRuntimeError("SOS_PROJECT_RUNTIME_STILL_REFERENCED")
                    if "/" in command:
                        resolved = resolve_runtime_reference(candidate)
                        if resolved == generation or generation in resolved.parents:
                            raise ProjectRuntimeError("SOS_PROJECT_RUNTIME_STILL_REFERENCED")
            except ProjectRuntimeError:
                raise
            except (ValueError, UnicodeError, OSError, RuntimeError):
                raise ProjectRuntimeError("SOS_PROJECT_RUNTIME_REFERENCES_UNKNOWN") from None
    if codex._read_manifest(root) is not None:
        # Legacy single-target configurations are not an implicitly supported
        # reference family for project-runtime deletion.
        raise ProjectRuntimeError("SOS_PROJECT_RUNTIME_REFERENCES_UNKNOWN")
    service = current_platform_services()
    relative = ".sigma/integrations/atomic-switches"
    with service.open_repository(root) as repository:
        if service.observe_object(repository, relative).kind == "absent":
            return
        listing = service.enumerate_directory_bounded(repository, relative, 64)
    for entry in listing.entries:
        if entry.name == "coordinator.lock" and entry.kind == "regular":
            continue
        if entry.kind != "directory":
            raise ProjectRuntimeError("SOS_PROJECT_RUNTIME_REFERENCES_UNKNOWN")
        plan = _read_plan(root, entry.name)
        if plan is None:
            raise ProjectRuntimeError("SOS_PROJECT_RUNTIME_RECOVERY_REQUIRED")
        events = _read_events(root, entry.name, plan["plan_digest"], tuple(plan["clients"]))
        if not events or events[-1]["state"] not in {"committed", "rolled_back"}:
            raise ProjectRuntimeError("SOS_PROJECT_RUNTIME_RECOVERY_REQUIRED")


def _admit(transition):
    identity = transition.payload["identity"]
    generation = transition.namespace / identity["project_key"][7:] / identity["generation_key"][7:]
    if transition.payload.get("contract") == "sos_project_runtime_install_plan_v1":
        rows, _ = _history(transition.root)
        if any(row["events"][-1]["state"] not in {"aborted", "rolled_back"} for row in rows):
            raise ProjectRuntimeError("SOS_PROJECT_RUNTIME_RETENTION_REQUIRED")
        raw = codex.read_integration_control_file(
            transition.root, "lifecycle/project-runtime-install.json"
        )
        if raw != transition.sealed:
            raise ProjectRuntimeError("SOS_PROJECT_RUNTIME_INSTALL_RECORD_INVALID")
        _detached(transition.root, transition.successor, generation)
        return transition.payload["record_digest"]
    rows, history = _history(transition.root)
    if (not rows or rows[-1]["plan"] != transition.payload
            or rows[-1]["events"][-1]["state"] != "committed"):
        # Only the latest detached active generation is admitted. A retained
        # predecessor or generation in any pending transition cannot be pruned.
        raise ProjectRuntimeError("SOS_PROJECT_RUNTIME_RETENTION_REQUIRED")
    _detached(transition.root, transition.successor, generation)
    return history


@dataclass(frozen=True)
class RuntimeRemovalPlan:
    transition: object
    snapshot_bytes: bytes
    sealed: bytes

    @property
    def payload(self):
        return _parse(self.sealed)

    def preview(self):
        return TerminalResult("sos_project_runtime_removal_result_v1", Status.OWNER_REQUIRED,
            ("SOS_PROJECT_RUNTIME_REMOVE_CONFIRMATION_REQUIRED",), {
                **self.payload, "writes_performed": False,
                "preserve": [".sigma", "original_install_receipt", "user_files", "legacy_shared_runtime", "predecessor_generations"]})


def prepare_runtime_removal(transition):
    history = _admit(transition)
    _verified(transition, active=True)
    p = transition.payload
    snapshot = snapshot_owned_generation(transition.namespace, transition.root, p["identity"], p["plan_digest"])
    material = {"contract": "sos_project_runtime_remove_plan_v1", "history_digest": history,
                "identity_digest": p["identity"]["identity_digest"], "snapshot_digest": digest_value(snapshot),
                "entry_count": len(snapshot["entries"]),
                "byte_count": sum(e.get("size", 0) for e in snapshot["entries"].values()),
                "raw_content_serialized": False, "absolute_paths_serialized": False}
    material["plan_digest"] = digest_value(material)
    return RuntimeRemovalPlan(transition, canonical_json(snapshot), canonical_json(material))


def execute_runtime_removal(plan, *, confirmed_plan_digest=None, controlling_tty_observed=False, fault=None):
    p = plan.payload
    _validate(p)
    if confirmed_plan_digest != p["plan_digest"] or not controlling_tty_observed:
        return plan.preview()
    transition = plan.transition
    root = transition.root
    with _lock(root), runtime_namespace_lock(transition.namespace), _switch_lock(root):
        if _admit(transition) != p["history_digest"]:
            raise ProjectRuntimeError("SOS_PROJECT_RUNTIME_PREVIEW_STALE")
        snapshot = _parse(plan.snapshot_bytes)
        if digest_value(snapshot) != p["snapshot_digest"]:
            raise ProjectRuntimeError("SOS_PROJECT_RUNTIME_PREVIEW_STALE")
        existing = codex.read_integration_control_file(root, _RECORD)
        if existing is None:
            # Revalidate readiness and complete snapshot before admitting the
            # first irreversible unlink. Retries use the exact retained manifest.
            if prepare_runtime_removal(transition).sealed != plan.sealed:
                raise ProjectRuntimeError("SOS_PROJECT_RUNTIME_PREVIEW_STALE")
            codex.publish_integration_control_file(root, _RECORD, canonical_json({"plan": p, "state": "removing"}))
        else:
            record = _parse(existing)
            if (not isinstance(record, dict) or set(record) != {"plan", "state"}
                    or record.get("plan") != p or record.get("state") not in {"removing", "removed"}):
                raise ProjectRuntimeError("SOS_PROJECT_RUNTIME_RECOVERY_REQUIRED")
        try:
            delete_owned_generation(transition.namespace, root, transition.payload["identity"],
                snapshot=snapshot, confirmed_plan_digest=p["plan_digest"], fault=fault, namespace_locked=True)
            codex.publish_integration_control_file(root, _RECORD, canonical_json({"plan": p, "state": "removed"}))
        except Exception:
            return TerminalResult("sos_project_runtime_removal_result_v1", Status.BLOCKED,
                ("SOS_PROJECT_RUNTIME_REMOVAL_RECOVERY_REQUIRED",), {"plan_digest": p["plan_digest"],
                    "recovery_required": True, "runtime_removed": False, "partial_deletion_possible": True})
        return TerminalResult("sos_project_runtime_removal_result_v1", Status.SUCCESS,
            ("SOS_PROJECT_RUNTIME_REMOVED",), {"plan_digest": p["plan_digest"], "runtime_removed": True,
                "legacy_shared_runtime_modified": False, "sigma_preserved": True})


def recover_runtime_removal(transition, *, confirmed_plan_digest=None, controlling_tty_observed=False):
    raw = codex.read_integration_control_file(transition.root, _RECORD)
    record = _parse(raw) if raw is not None else None
    if not isinstance(record, dict) or set(record) != {"plan", "state"} or record["state"] not in {"removing", "removed"}:
        raise ProjectRuntimeError("SOS_PROJECT_RUNTIME_RECOVERY_REQUIRED")
    p = record["plan"]
    _validate(p)
    if (not isinstance(p, dict) or p.get("plan_digest") != digest_value({k:v for k,v in p.items() if k != "plan_digest"})
            or p.get("identity_digest") != transition.payload["identity"]["identity_digest"]
            or _admit(transition) != p.get("history_digest")):
        raise ProjectRuntimeError("SOS_PROJECT_RUNTIME_RECOVERY_REQUIRED")
    snapshot = read_removal_snapshot(transition.namespace, transition.root, transition.payload["identity"],
        plan_digest=p["plan_digest"], snapshot_digest=p["snapshot_digest"],
        reservation_plan_digest=transition.payload["plan_digest"])
    plan = RuntimeRemovalPlan(transition, canonical_json(snapshot), canonical_json(p))
    return execute_runtime_removal(plan, confirmed_plan_digest=confirmed_plan_digest,
                                  controlling_tty_observed=controlling_tty_observed)
