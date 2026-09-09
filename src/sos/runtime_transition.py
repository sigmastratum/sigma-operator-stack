"""Local POSIX runtime transition coordinator; not a public installer route.

Release acquisition/admission is the carrier's responsibility. This coordinator
rechecks exact supplied payloads, preserves the original install receipt, and
uses P107 as the only adapter writer and rollback mechanism.
"""

from __future__ import annotations

import hashlib
import json
import re
import tomllib
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path

from .adapter_transition_preview import exact_adapter_targets, verify_adapter_targets
from .atomic_switch import prepare_atomic_switch, execute_atomic_switch, recover_atomic_switch, _validate_plan, _configured_clients
from .client_integration import LauncherBinding, read_integration_control_file, publish_integration_control_file, read_integration_target
from .contracts import canonical_json, digest_value
from .maintenance_binding import MaintenanceLauncherBinding, mcp_launcher_binding_payload
from .platform_services import current_platform_services
from .platforms.project_runtime_posix import (
    observe_project, reserve_generation, install_reserved_wheel,
    observe_verified_generation_launcher, _regular_digest,
    runtime_namespace_lock,
    observed_executable_digest,
    prepare_runtime_namespace,
)
from .platforms.project_runtime_inventory import checked_wheel_sources
from .project_runtime import ProjectRuntimeError, validate_runtime_identity, transition_event, validate_transition_chain
from .repository import discover_repository_root
from .result import Status, TerminalResult, report_progress
from .workspace import workspace_status, project_workspace_application


_RECEIPT = "lifecycle/p106-install.json"
_LEDGER = "lifecycle/runtime-transitions.json"
_TERMINAL = {"committed", "rolled_back", "aborted"}
_PLAN_FIELDS = {"contract", "identity", "old_maintenance", "original_receipt_digest", "predecessor_command_digest",
    "history_digest", "atomic", "targets", "application_fingerprint", "after_application_fingerprint",
    "control_plane_digest", "uv_sha256", "wheel_inventory", "python_network_allowed",
    "raw_content_serialized", "absolute_paths_serialized", "plan_digest"}


def _hash(raw):
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def _parse(raw):
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise ProjectRuntimeError("SOS_PROJECT_RUNTIME_HISTORY_INVALID")
            result[key] = value
        return result
    try:
        return json.loads(raw, object_pairs_hook=pairs)
    except (ValueError, TypeError, UnicodeError, RecursionError):
        raise ProjectRuntimeError("SOS_PROJECT_RUNTIME_HISTORY_INVALID") from None


def _original(root):
    raw = read_integration_control_file(root, _RECEIPT)
    contract = "sos_p106_install_receipt_v2"
    if raw is None:
        raw = read_integration_control_file(root, "lifecycle/p107-install.json")
        contract = "sos_p107_install_receipt_v1"
    if raw is None:
        raise ProjectRuntimeError("SOS_PROJECT_RUNTIME_ORIGINAL_RECEIPT_REQUIRED")
    value = _parse(raw)
    if not isinstance(value, dict) or value.get("contract") != contract:
        raise ProjectRuntimeError("SOS_PROJECT_RUNTIME_ORIGINAL_RECEIPT_REQUIRED")
    binding = MaintenanceLauncherBinding.from_payload(value.get("maintenance_launcher_binding"))
    return raw, value, binding


def _verify_predecessor(binding):
    if "sha256:" + observed_executable_digest(binding.command) != binding.executable_sha256:
        raise ProjectRuntimeError("SOS_PROJECT_RUNTIME_PREDECESSOR_MISMATCH")


def _history(root):
    try:
        return _read_history(root)
    except (KeyError, TypeError, ValueError, IndexError, RecursionError):
        raise ProjectRuntimeError("SOS_PROJECT_RUNTIME_HISTORY_INVALID") from None


def _read_history(root):
    raw = read_integration_control_file(root, _LEDGER)
    if raw is None:
        return [], digest_value([])
    rows = _parse(raw)
    if not isinstance(rows, list) or not 1 <= len(rows) <= 16:
        raise ProjectRuntimeError("SOS_PROJECT_RUNTIME_HISTORY_INVALID")
    previous = []
    original, receipt, current = _original(root)
    for row in rows:
        if not isinstance(row, dict) or set(row) != {"plan", "events"}:
            raise ProjectRuntimeError("SOS_PROJECT_RUNTIME_HISTORY_INVALID")
        plan = row["plan"]
        if (not isinstance(plan, dict) or set(plan) != _PLAN_FIELDS
                or plan["contract"] != "sos_project_runtime_plan_v1"
                or plan["raw_content_serialized"] is not False or plan["absolute_paths_serialized"] is not False
                or type(plan["python_network_allowed"]) is not bool
                or not isinstance(plan["predecessor_command_digest"], str)
                or re.fullmatch(r"sha256:[0-9a-f]{64}", plan["predecessor_command_digest"]) is None
                or plan.get("plan_digest") != digest_value({k:v for k,v in plan.items() if k != "plan_digest"})):
            raise ProjectRuntimeError("SOS_PROJECT_RUNTIME_HISTORY_INVALID")
        validate_runtime_identity(plan["identity"], **observe_project(root, digest_value(receipt["repository_id"])))
        _validate_plan(plan["atomic"])
        if plan["atomic"]["repository_id"] != receipt["repository_id"]:
            raise ProjectRuntimeError("SOS_PROJECT_RUNTIME_HISTORY_INVALID")
        if (plan.get("history_digest") != digest_value(previous)
                or plan.get("original_receipt_digest") != _hash(original)
                or plan.get("old_maintenance") != current.payload()):
            raise ProjectRuntimeError("SOS_PROJECT_RUNTIME_HISTORY_INVALID")
        events = row["events"]
        if not isinstance(events, list) or not events:
            raise ProjectRuntimeError("SOS_PROJECT_RUNTIME_HISTORY_INVALID")
        tip = validate_transition_chain(events, plan_digest=plan["plan_digest"],
            predecessor_receipt_digest=plan["original_receipt_digest"],
            identity_digest=plan["identity"]["identity_digest"], expected_tip_digest=events[-1]["event_digest"])
        if previous and previous[-1]["events"][-1]["state"] not in _TERMINAL:
            raise ProjectRuntimeError("SOS_PROJECT_RUNTIME_HISTORY_INVALID")
        if tip["state"] == "committed":
            current = MaintenanceLauncherBinding.from_payload(plan["identity"]["maintenance_binding"])
        previous.append(row)
    return rows, digest_value(rows)


def resolve_runtime_maintenance(path):
    """Read local history, never silently fall back across an incomplete switch.

    This selects provenance only, not executable health or public release
    admission. Same-user deletion of all local history is not authenticated.
    """
    root = discover_repository_root(str(path))
    _raw, _receipt, binding = _original(root)
    rows, _ = _history(root)
    for row in rows:
        state = row["events"][-1]["state"]
        if state not in _TERMINAL:
            raise ProjectRuntimeError("SOS_PROJECT_RUNTIME_RECOVERY_REQUIRED")
        if state == "committed":
            binding = MaintenanceLauncherBinding.from_payload(row["plan"]["identity"]["maintenance_binding"])
    return binding


def observe_current_runtime_launcher(path):
    """Observe exact configured executable; never search PATH or use this process.

    Project manifests and P107 validate every configured adapter against the
    receipt/history binding. This is for terminal installed state, not for
    reconstructing a predecessor from partially switched live configuration.
    """
    root = discover_repository_root(str(path))
    maintenance = resolve_runtime_maintenance(root)
    _raw, receipt, _binding = _original(root)
    rows, _ = _history(root)
    expected = receipt.get("mcp_launcher_binding")
    for row in rows:
        if row["events"][-1]["state"] == "committed":
            projection = row["plan"]["atomic"]["successor_launcher"]
            expected = mcp_launcher_binding_payload(**projection)
    if not isinstance(expected, dict):
        raise ProjectRuntimeError("SOS_PROJECT_RUNTIME_PREDECESSOR_MISMATCH")
    commands = []
    try:
        for filename, key, parser in ((".codex/config.toml", "mcp_servers", tomllib.loads),
                                      (".mcp.json", "mcpServers", _parse)):
            raw, exists, _mode = read_integration_target(root, filename)
            if not exists:
                continue
            config = parser(raw.decode("utf-8"))
            servers = config.get(key, {})
            if not isinstance(servers, dict):
                raise ValueError()
            if "sigma_operator_stack" not in servers:
                continue
            command = servers["sigma_operator_stack"]["command"]
            if not isinstance(command, str) or not Path(command).is_absolute():
                raise ValueError()
            commands.append(command)
    except (ValueError, TypeError, KeyError, AttributeError, UnicodeError):
        raise ProjectRuntimeError("SOS_PROJECT_RUNTIME_PREDECESSOR_MISMATCH") from None
    if not commands or len(set(commands)) != 1:
        raise ProjectRuntimeError("SOS_PROJECT_RUNTIME_PREDECESSOR_MISMATCH")
    observed = LauncherBinding(commands[0], maintenance.version, expected.get("executable_sha256"))
    if mcp_launcher_binding_payload(package_version=observed.package_version,
            executable_sha256=observed.executable_sha256, binding_digest=observed.digest) != expected:
        raise ProjectRuntimeError("SOS_PROJECT_RUNTIME_PREDECESSOR_MISMATCH")
    _verify_predecessor(observed)
    if not _configured_clients(root, observed):
        raise ProjectRuntimeError("SOS_PROJECT_RUNTIME_PREDECESSOR_MISMATCH")
    return observed


@dataclass(frozen=True)
class RuntimeTransitionPlan:
    root: Path
    namespace: Path
    predecessor: LauncherBinding
    successor: LauncherBinding
    uv: Path
    wheel: Path
    wheels: tuple
    sealed: bytes

    @property
    def payload(self):
        return _parse(self.sealed)

    def preview(self):
        return TerminalResult("sos_project_runtime_transition_result_v1", Status.OWNER_REQUIRED,
            ("SOS_PROJECT_RUNTIME_CONFIRMATION_REQUIRED",), {
                **self.payload, "writes_performed": False, "one_confirmation": True,
                "preserve": ["original_install_receipt", ".sigma", "user_files", "git_head", "legacy_shared_runtime"],
                "qualification_performed": False, "client_restart_required": True})


def load_runtime_transition(path, *, namespace, predecessor, uv, wheel, wheels,
                            maintenance_binding):
    """Reconstruct the last persisted plan using freshly admitted release files.

    The carrier independently supplies the predecessor executable and canonical
    namespace. Local receipts contain no raw paths. This function does not run
    preparation again, reinterpret a partial switch as a new plan, or authorize
    recovery. Runtime health is checked by the requested operation.
    """
    root = discover_repository_root(str(path))
    rows, _ = _history(root)
    if not rows:
        raise ProjectRuntimeError("SOS_PROJECT_RUNTIME_HISTORY_REQUIRED")
    p = rows[-1]["plan"]
    supplied = MaintenanceLauncherBinding.from_payload(maintenance_binding)
    if supplied.payload() != p["identity"]["maintenance_binding"]:
        raise ProjectRuntimeError("SOS_PROJECT_RUNTIME_RELEASE_INVALID")
    namespace, uv, wheel = Path(namespace), Path(uv), Path(wheel)
    if not namespace.is_absolute() or namespace.name != "project-runtimes" or namespace.is_relative_to(root):
        raise ProjectRuntimeError("SOS_PROJECT_RUNTIME_NAMESPACE_INVALID")
    if any(part == ".." for part in namespace.parts):
        raise ProjectRuntimeError("SOS_PROJECT_RUNTIME_NAMESPACE_INVALID")
    if (not isinstance(wheels, tuple) or any(path.parent != wheel.parent for path, _ in wheels)
            or [[path.name, digest] for path, digest in wheels] != p["wheel_inventory"]
            or _regular_digest(uv) != p["uv_sha256"]
            or "sha256:" + _regular_digest(wheel) != p["identity"]["wheel_digest"]):
        raise ProjectRuntimeError("SOS_PROJECT_RUNTIME_PAYLOAD_MISMATCH")
    checked_wheel_sources(wheels, supplied.version)
    before = {"package_version": predecessor.package_version,
              "executable_sha256": predecessor.executable_sha256,
              "binding_digest": predecessor.digest}
    if (before != p["atomic"]["predecessor_launcher"]
            or _hash(predecessor.command.encode()) != p["predecessor_command_digest"]):
        raise ProjectRuntimeError("SOS_PROJECT_RUNTIME_PREDECESSOR_MISMATCH")
    target = namespace / p["identity"]["project_key"][7:] / p["identity"]["generation_key"][7:]
    successor = LauncherBinding(str(target / "tools/sigma-operator-stack/bin/python3"),
                                supplied.version, p["identity"]["interpreter_digest"])
    after = {"package_version": successor.package_version,
             "executable_sha256": successor.executable_sha256,
             "binding_digest": successor.digest}
    if after != p["atomic"]["successor_launcher"]:
        raise ProjectRuntimeError("SOS_PROJECT_RUNTIME_LAUNCHER_MISMATCH")
    return RuntimeTransitionPlan(root, namespace, predecessor, successor, uv, wheel,
                                 wheels, canonical_json(p))


def load_latest_runtime_transition(path, *, namespace, uv, wheel, wheels,
                                   maintenance_binding):
    """Load the latest transition without trusting partially switched adapters."""
    root = discover_repository_root(str(path))
    rows, _ = _history(root)
    if not rows:
        raise ProjectRuntimeError("SOS_PROJECT_RUNTIME_HISTORY_REQUIRED")
    before = rows[-1]["plan"]["atomic"]["predecessor_launcher"]
    # Plans intentionally contain only digests, never absolute command paths.
    # Resolve candidates from the canonical retained namespace, checking the
    # recorded binding digest before admitting any executable.
    namespace = Path(namespace)
    candidates = []
    for row in rows[:-1]:
        identity = row["plan"]["identity"]
        target = namespace / identity["project_key"][7:] / identity["generation_key"][7:]
        candidates.append(target / "tools/sigma-operator-stack/bin/python3")
    initial = read_integration_control_file(root, "lifecycle/project-runtime-install.json")
    if initial is not None:
        initial = _parse(initial)
        identity = initial["identity"]
        candidates.append(namespace / identity["project_key"][7:] / identity["generation_key"][7:]
                          / "tools/sigma-operator-stack/bin/python3")
    for name in ("python", "python3", "python3.12"):
        candidates.append(namespace.parent / "runtime/tools/sigma-operator-stack/bin" / name)
    matches = [LauncherBinding(str(command), before["package_version"], before["executable_sha256"])
               for command in candidates]
    matches = [binding for binding in matches if binding.digest == before["binding_digest"]
               and _hash(binding.command.encode()) == rows[-1]["plan"]["predecessor_command_digest"]]
    if not matches:
        raise ProjectRuntimeError("SOS_PROJECT_RUNTIME_PREDECESSOR_MISMATCH")
    predecessor = matches[0]
    return load_runtime_transition(
        root, namespace=namespace, predecessor=predecessor, uv=uv, wheel=wheel,
        wheels=wheels, maintenance_binding=maintenance_binding,
    )


def prepare_runtime_transition(path, *, namespace, identity, predecessor, uv, uv_sha256,
                               wheel, wheels, python_network_allowed=False, switch_nonce=None):
    root = discover_repository_root(str(path))
    removal = read_integration_control_file(root, "lifecycle/runtime-removal.json")
    if removal is not None:
        removal_record = _parse(removal)
        if not isinstance(removal_record, dict) or removal_record.get("state") != "removed":
            raise ProjectRuntimeError("SOS_PROJECT_RUNTIME_REMOVAL_RECOVERY_REQUIRED")
    current = workspace_status(str(root))
    if current.status not in {Status.SUCCESS, Status.STALE} or current.details.get("application_observation_complete") is not True:
        raise ProjectRuntimeError("SOS_PROJECT_RUNTIME_WORKSPACE_INVALID")
    repository = digest_value(current.details["repository_id"])
    record = validate_runtime_identity(identity, **observe_project(root, repository))
    old_maintenance = resolve_runtime_maintenance(root)
    if old_maintenance.version != predecessor.package_version:
        raise ProjectRuntimeError("SOS_PROJECT_RUNTIME_PREDECESSOR_MISMATCH")
    if record["maintenance_binding"]["version"] == old_maintenance.version:
        raise ProjectRuntimeError("SOS_PROJECT_RUNTIME_SAME_VERSION_REPLACEMENT_REFUSED")
    raw, receipt, _ = _original(root)
    if receipt.get("repository_id") != current.details["repository_id"]:
        raise ProjectRuntimeError("SOS_PROJECT_RUNTIME_PREDECESSOR_MISMATCH")
    _verify_predecessor(predecessor)
    if _regular_digest(uv) != uv_sha256 or "sha256:" + _regular_digest(wheel) != record["wheel_digest"]:
        raise ProjectRuntimeError("SOS_PROJECT_RUNTIME_PAYLOAD_MISMATCH")
    checked_wheel_sources(wheels, record["maintenance_binding"]["version"])
    if type(python_network_allowed) is not bool or any(p.parent != wheel.parent for p, _ in wheels):
        raise ProjectRuntimeError("SOS_PROJECT_RUNTIME_PLAN_INVALID")
    namespace = Path(namespace)
    if namespace.name != "project-runtimes" or namespace.is_relative_to(root):
        raise ProjectRuntimeError("SOS_PROJECT_RUNTIME_NAMESPACE_INVALID")
    target = namespace / record["project_key"][7:] / record["generation_key"][7:]
    successor = LauncherBinding(str(target / "tools/sigma-operator-stack/bin/python3"),
                                record["maintenance_binding"]["version"], record["interpreter_digest"])
    atomic = prepare_atomic_switch(str(root), predecessor=predecessor, successor=successor, switch_nonce=switch_nonce)
    targets, images = exact_adapter_targets(root, atomic.clients, successor, with_images=True)
    projected = project_workspace_application(str(root), overlays=images)
    # The new launcher/configuration intentionally differs from accepted source;
    # a complete stale projection is expected and does not qualify that source.
    if (projected.status not in {Status.SUCCESS, Status.STALE}
            or projected.details.get("application_observation_complete") is not True):
        raise ProjectRuntimeError("SOS_PROJECT_RUNTIME_WORKSPACE_INVALID")
    rows, history = _history(root)
    if not rows:
        expected_mcp = mcp_launcher_binding_payload(package_version=predecessor.package_version,
            executable_sha256=predecessor.executable_sha256, binding_digest=predecessor.digest)
        if receipt.get("mcp_launcher_binding") != expected_mcp:
            raise ProjectRuntimeError("SOS_PROJECT_RUNTIME_PREDECESSOR_MISMATCH")
    material = {"contract": "sos_project_runtime_plan_v1", "identity": record,
                "old_maintenance": old_maintenance.payload(), "original_receipt_digest": _hash(raw),
                "predecessor_command_digest": _hash(predecessor.command.encode()),
                "history_digest": history, "atomic": atomic.payload,
                "targets": targets,
                "after_application_fingerprint": projected.details["projected_application_fingerprint"],
                "application_fingerprint": current.details["application_fingerprint"],
                "control_plane_digest": current.details["control_plane_digest"],
                "uv_sha256": uv_sha256, "wheel_inventory": [[p.name, h] for p,h in wheels],
                "python_network_allowed": python_network_allowed,
                "raw_content_serialized": False, "absolute_paths_serialized": False}
    material["plan_digest"] = digest_value(material)
    return RuntimeTransitionPlan(root, namespace, predecessor, successor, uv, wheel, wheels, canonical_json(material))


@contextmanager
def _lock(root):
    service = current_platform_services()
    with service.open_repository(root) as repository:
        with service.acquire_repository_lock(repository, 2.0,
                relative_lock_path=".sigma/lifecycle/runtime-transition.lock"):
            yield


def _event(root, rows, state):
    row = rows[-1]
    plan = row["plan"]
    row["events"].append(transition_event(state=state, plan_digest=plan["plan_digest"],
        predecessor_receipt_digest=plan["original_receipt_digest"], identity_digest=plan["identity"]["identity_digest"],
        previous=row["events"][-1] if row["events"] else None))
    publish_integration_control_file(root, _LEDGER, canonical_json(rows))
    report_progress(state)


def _result(state, plan):
    return TerminalResult("sos_project_runtime_transition_result_v1",
        Status.SUCCESS if state == "committed" else Status.BLOCKED,
        ("SOS_PROJECT_RUNTIME_" + state.upper(),), {"state": state,
        "plan_digest": plan.payload["plan_digest"], "qualification_performed": False,
        "legacy_shared_runtime_modified": False, "runtime_removed": False,
        "recovery_required": state not in _TERMINAL})


def _reprepare(plan):
    p = plan.payload
    return prepare_runtime_transition(plan.root, namespace=plan.namespace, identity=p["identity"],
        predecessor=plan.predecessor, uv=plan.uv, uv_sha256=p["uv_sha256"], wheel=plan.wheel,
        wheels=plan.wheels, python_network_allowed=p["python_network_allowed"],
        switch_nonce=p["atomic"]["switch_nonce"])


def _verified(plan, *, active=False):
    p = plan.payload
    command, version, digest = observe_verified_generation_launcher(plan.namespace, plan.root, p["identity"],
        repository_digest=p["identity"]["repository_digest"], confirmed_plan_digest=p["plan_digest"], wheels=plan.wheels,
        active=active)
    if LauncherBinding(str(command), version, "sha256:" + digest) != plan.successor:
        raise ProjectRuntimeError("SOS_PROJECT_RUNTIME_LAUNCHER_MISMATCH")


def execute_runtime_transition(plan, *, confirmed_plan_digest=None, controlling_tty_observed=False, fault=None):
    p = plan.payload
    if confirmed_plan_digest != p["plan_digest"] or not controlling_tty_observed:
        return plan.preview()
    if _reprepare(plan).sealed != plan.sealed:
        raise ProjectRuntimeError("SOS_PROJECT_RUNTIME_PREVIEW_STALE")
    with _lock(plan.root):
        if _reprepare(plan).sealed != plan.sealed:
            raise ProjectRuntimeError("SOS_PROJECT_RUNTIME_PREVIEW_STALE")
        prepare_runtime_namespace(plan.namespace)
        rows, _ = _history(plan.root)
        if len(rows) >= 16:
            raise ProjectRuntimeError("SOS_PROJECT_RUNTIME_HISTORY_LIMIT")
        rows.append({"plan": p, "events": []})
        _event(plan.root, rows, "previewed")
        _event(plan.root, rows, "confirmed")
        _event(plan.root, rows, "provisioning")
        switch_started = False
        try:
            reserve_generation(plan.namespace, plan.root, p["identity"],
                repository_digest=p["identity"]["repository_digest"], confirmed_plan_digest=p["plan_digest"])
            install_reserved_wheel(plan.namespace, plan.root, p["identity"],
                repository_digest=p["identity"]["repository_digest"], confirmed_plan_digest=p["plan_digest"],
                uv=plan.uv, uv_sha256=p["uv_sha256"], wheel=plan.wheel, wheelhouse=plan.wheel.parent,
                python_network_allowed=p["python_network_allowed"], wheel_inventory=tuple(map(tuple,p["wheel_inventory"])))
            _verified(plan)
            _event(plan.root, rows, "ready")
            atomic = prepare_atomic_switch(str(plan.root), predecessor=plan.predecessor,
                successor=plan.successor, switch_nonce=p["atomic"]["switch_nonce"])
            if atomic.payload != p["atomic"]:
                raise ProjectRuntimeError("SOS_PROJECT_RUNTIME_PREVIEW_STALE")
            def admission():
                _verified(plan)
                _verify_predecessor(plan.predecessor)
                verify_adapter_targets(plan.root, p["targets"], after=False)
                current = workspace_status(str(plan.root))
                if (current.details.get("application_fingerprint") != p["application_fingerprint"]
                        or current.details.get("control_plane_digest") != p["control_plane_digest"]
                        or _hash(_original(plan.root)[0]) != p["original_receipt_digest"]):
                    raise ProjectRuntimeError("SOS_PROJECT_RUNTIME_PREVIEW_STALE")
            def postcheck():
                report_progress("verifying_targets")
                verify_adapter_targets(plan.root, p["targets"], after=True)
                current = workspace_status(str(plan.root))
                if (current.details.get("application_fingerprint") != p["after_application_fingerprint"]
                        or current.details.get("control_plane_integrity") != "valid"
                        or _hash(_original(plan.root)[0]) != p["original_receipt_digest"]):
                    raise ProjectRuntimeError("SOS_PROJECT_RUNTIME_PREVIEW_STALE")
            switch_started = True
            _event(plan.root, rows, "switching")
            with runtime_namespace_lock(plan.namespace):
                outcome = execute_atomic_switch(atomic, confirmed=True, controlling_tty_observed=True,
                    fault=fault, admission_check=admission, target_check=postcheck,
                    rollback_targets=p["targets"],
                    rollback_check=lambda: verify_adapter_targets(plan.root, p["targets"], after=False))
            if fault:
                fault("after_adapter_terminal")
            state = "committed" if outcome.status == Status.SUCCESS else (
                "rolled_back" if outcome.details.get("rolled_back") else "recovery_required")
            _event(plan.root, rows, state)
            return _result(state, plan)
        except Exception:
            # A failed publication may have reached disk. Never infer rollback
            # from an in-memory event that was not durably acknowledged.
            state = "recovery_required" if switch_started else "aborted"
            try:
                persisted, _ = _history(plan.root)
                if (not persisted or persisted[-1]["plan"] != p
                        or persisted[-1]["events"][-1]["state"] in _TERMINAL):
                    return _result("recovery_required", plan)
                _event(plan.root, persisted, state)
            except Exception:
                return _result("recovery_required", plan)
            return _result(state, plan)


def recover_runtime_transition(plan, *, confirmed=False):
    if not confirmed:
        return _result("recovery_required", plan)
    with _lock(plan.root):
        rows, _ = _history(plan.root)
        if not rows or rows[-1]["plan"] != plan.payload:
            raise ProjectRuntimeError("SOS_PROJECT_RUNTIME_HISTORY_INVALID")
        state = rows[-1]["events"][-1]["state"]
        if state in _TERMINAL:
            if state == "committed":
                _verified(plan, active=True)
            verify_adapter_targets(plan.root, plan.payload["targets"], after=state == "committed")
            return _result(state, plan)
        if state in {"previewed", "confirmed", "provisioning", "ready"}:
            # The durable switching intent always precedes P107. Refuse any
            # conflicting P107 intent instead of assuming it never ran.
            switch_id = plan.payload["atomic"]["switch_id"]
            if read_integration_control_file(plan.root,
                    f"integrations/atomic-switches/{switch_id}/plan.json") is not None:
                return _result("recovery_required", plan)
            _verify_predecessor(plan.predecessor)
            verify_adapter_targets(plan.root, plan.payload["targets"], after=False)
            _event(plan.root, rows, "aborted")
            return _result("aborted", plan)
        if state not in {"switching", "recovery_required"}:
            # No guess that a failed/missing journal proves an adapter rollback.
            return _result("recovery_required", plan)
        with runtime_namespace_lock(plan.namespace):
            _verified(plan, active=True)
            _verify_predecessor(plan.predecessor)
            outcome = recover_atomic_switch(str(plan.root), plan.payload["atomic"]["switch_id"],
                predecessor=plan.predecessor, successor=plan.successor,
                rollback_targets=plan.payload["targets"],
                rollback_check=lambda: verify_adapter_targets(plan.root, plan.payload["targets"], after=False))
        if outcome.status != Status.SUCCESS:
            return _result("recovery_required", plan)
        recovered_state = "rolled_back" if outcome.details.get("rolled_back") else "committed"
        if state == "recovery_required" and recovered_state == "committed":
            return _result("recovery_required", plan)
        state = recovered_state
        verify_adapter_targets(plan.root, plan.payload["targets"], after=state == "committed")
        _event(plan.root, rows, state)
        return _result(state, plan)
