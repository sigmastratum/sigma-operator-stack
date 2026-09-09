"""Durable binding for a fresh project-isolated SOS runtime."""

from dataclasses import dataclass
from pathlib import Path
import re

from .client_integration import LauncherBinding, publish_integration_control_file, read_integration_control_file
from .contracts import canonical_json, digest_value
from .maintenance_binding import MaintenanceLauncherBinding
from .platforms.project_runtime_posix import observe_project
from .project_runtime import ProjectRuntimeError, validate_runtime_identity
from .repository import discover_repository_root
from .runtime_transition import _original, _parse
from .lifecycle import prepare_one_command_init, execute_one_command_init, recover_one_command_init
from .platforms.runtime_install_intent import (
    prepare_namespace_parents, install_intent_lock, read_install_intent, write_install_intent,
)
from .platforms.project_runtime_posix import (
    prepare_runtime_namespace, reserve_generation, install_reserved_wheel,
    observe_verified_generation_launcher,
)
from .project_runtime import runtime_identity
from .result import Status, TerminalResult


_RECORD = "lifecycle/project-runtime-install.json"


@dataclass(frozen=True)
class InstalledRuntime:
    root: Path
    namespace: Path
    successor: LauncherBinding
    wheels: tuple
    sealed: bytes

    @property
    def payload(self):
        return _parse(self.sealed)


@dataclass(frozen=True)
class NativeInstallPlan:
    root: Path
    namespace: Path
    identity: dict
    uv: Path
    wheel: Path
    wheels: tuple
    bootstrap: object
    maintenance_binding: MaintenanceLauncherBinding
    controller_command: str
    interpreter_digest: str
    primary_authority_id: str | None
    client: str
    sealed: bytes

    @property
    def payload(self):
        return _parse(self.sealed)

    def preview(self):
        bootstrap = self.bootstrap.preview().to_dict()
        return TerminalResult("sos_native_install_result_v1", Status.OWNER_REQUIRED,
            ("SOS_NATIVE_INSTALL_CONFIRMATION_REQUIRED",), {
                **self.payload, "bootstrap_preview": bootstrap,
                "confirmation_handoff": {"seed": self.bootstrap.confirmation_seed,
                                         "plan_digest": self.payload["plan_digest"]},
                "writes_performed": False, "one_confirmation": True,
                "qualification_performed": False,
            })


def prepare_native_install(path, *, namespace, maintenance_binding, uv, uv_sha256,
                           wheel, wheels, controller_command, interpreter_digest,
                           confirmation_seed=None, primary_authority_id=None,
                           client="codex"):
    root = discover_repository_root(str(path))
    release = MaintenanceLauncherBinding.from_payload(maintenance_binding)
    provisional = LauncherBinding(controller_command, release.version, interpreter_digest)
    first = prepare_one_command_init(str(root), launcher=provisional,
        primary_authority_id=primary_authority_id, maintenance_binding=release,
        confirmation_seed=confirmation_seed, client=client)
    identity = runtime_identity(**observe_project(root, digest_value(first.repository_id)),
        maintenance_binding=release.payload(),
        wheel_digest="sha256:" + dict((path.name, digest) for path, digest in wheels)[wheel.name],
        interpreter_digest=interpreter_digest)
    namespace = Path(namespace)
    target = namespace / identity["project_key"][7:] / identity["generation_key"][7:]
    successor = LauncherBinding(str(target / "tools/sigma-operator-stack/bin/python3"),
                                release.version, interpreter_digest)
    bootstrap = prepare_one_command_init(str(root), launcher=successor,
        primary_authority_id=primary_authority_id, maintenance_binding=release,
        confirmation_seed=first.confirmation_seed, client=client)
    material = {"contract": "sos_native_install_plan_v1", "identity": identity,
        "bootstrap_plan_digest": bootstrap.aggregate_plan_digest,
        "uv_sha256": uv_sha256, "wheel_inventory": [[p.name, d] for p, d in wheels],
        "qualification_performed": False, "raw_content_serialized": False,
        "absolute_paths_serialized": False}
    material["plan_digest"] = digest_value(material)
    return NativeInstallPlan(root, namespace, identity, Path(uv), Path(wheel), wheels,
        bootstrap, release, controller_command, interpreter_digest,
        primary_authority_id, client, canonical_json(material))


def execute_native_install(plan, *, confirmed_plan_digest=None,
                           controlling_tty_observed=False):
    if confirmed_plan_digest != plan.payload["plan_digest"] or not controlling_tty_observed:
        return plan.preview()
    prepare_namespace_parents(plan.namespace)
    prepare_runtime_namespace(plan.namespace)
    with install_intent_lock(plan.namespace, plan.root):
        if read_install_intent(plan.namespace, plan.root) is not None:
            raise ProjectRuntimeError("SOS_PROJECT_RUNTIME_RECOVERY_REQUIRED")
        return _execute_new_install(plan)


def _intent(plan, state):
    return {"contract": "sos_native_install_intent_v1", "plan": plan.payload,
            "confirmation_seed": plan.bootstrap.confirmation_seed,
            "primary_authority_id": plan.primary_authority_id, "client": plan.client,
            "state": state}


def _execute_new_install(plan):
    rebuilt = prepare_native_install(plan.root, namespace=plan.namespace,
        maintenance_binding=plan.maintenance_binding.payload(), uv=plan.uv,
        uv_sha256=plan.payload["uv_sha256"], wheel=plan.wheel, wheels=plan.wheels,
        controller_command=plan.controller_command, interpreter_digest=plan.interpreter_digest,
        confirmation_seed=plan.bootstrap.confirmation_seed,
        primary_authority_id=plan.primary_authority_id, client=plan.client)
    if rebuilt.sealed != plan.sealed:
        raise ProjectRuntimeError("SOS_PROJECT_RUNTIME_PREVIEW_STALE")
    write_install_intent(plan.namespace, plan.root, _intent(plan, "preparing"))
    repository_digest = plan.identity["repository_digest"]
    reserve_generation(plan.namespace, plan.root, plan.identity,
        repository_digest=repository_digest, confirmed_plan_digest=plan.payload["plan_digest"])
    install_reserved_wheel(plan.namespace, plan.root, plan.identity,
        repository_digest=repository_digest, confirmed_plan_digest=plan.payload["plan_digest"],
        uv=plan.uv, uv_sha256=plan.payload["uv_sha256"], wheel=plan.wheel,
        wheelhouse=plan.wheel.parent, python_network_allowed=True,
        wheel_inventory=tuple((p.name, d) for p, d in plan.wheels))
    observe_verified_generation_launcher(plan.namespace, plan.root, plan.identity,
        repository_digest=repository_digest, confirmed_plan_digest=plan.payload["plan_digest"],
        wheels=plan.wheels)
    write_install_intent(plan.namespace, plan.root, _intent(plan, "provisioned"))
    result = execute_one_command_init(plan.bootstrap, confirmed=True,
                                      controlling_tty_observed=True)
    if result.status not in {Status.SUCCESS, Status.OWNER_REQUIRED}:
        return result
    publish_installed_runtime(plan.root, plan.identity,
        confirmed_plan_digest=plan.payload["plan_digest"], wheels=plan.wheels)
    write_install_intent(plan.namespace, plan.root, _intent(plan, "committed"))
    return TerminalResult("sos_native_install_result_v1", result.status, result.reasons,
        {**result.details, "runtime_isolated": True,
         "native_install_plan_digest": plan.payload["plan_digest"]})


def recover_native_install(path, *, namespace, maintenance_binding, uv, uv_sha256,
                           wheel, wheels, controller_command, interpreter_digest,
                           confirmed=False):
    """Rebuild from durable intent and independently verified successor payload."""
    root = discover_repository_root(str(path))
    namespace = Path(namespace)
    intent = read_install_intent(namespace, root)
    if (not isinstance(intent, dict) or set(intent) != {"contract", "plan", "confirmation_seed", "primary_authority_id", "client", "state"}
            or intent.get("contract") != "sos_native_install_intent_v1"
            or intent.get("state") not in ("preparing", "provisioned", "committed")
            or intent.get("client") not in ("codex", "claude-code")
            or not isinstance(intent.get("confirmation_seed"), str)
            or re.fullmatch(r"[0-9a-f]{64}", intent["confirmation_seed"]) is None
            or (intent.get("primary_authority_id") is not None
                and not isinstance(intent["primary_authority_id"], str))):
        raise ProjectRuntimeError("SOS_PROJECT_RUNTIME_INSTALL_INTENT_INVALID")
    material = intent["plan"]
    if (not isinstance(material, dict)
            or set(material) != {"contract", "identity", "bootstrap_plan_digest", "uv_sha256",
                                "wheel_inventory", "qualification_performed", "raw_content_serialized",
                                "absolute_paths_serialized", "plan_digest"}
            or any(material.get(key) is not False for key in
                   ("qualification_performed", "raw_content_serialized", "absolute_paths_serialized"))
            or not isinstance(material.get("bootstrap_plan_digest"), str)
            or re.fullmatch(r"sha256:[0-9a-f]{64}", material["bootstrap_plan_digest"]) is None
            or material.get("plan_digest") != digest_value({k:v for k,v in material.items() if k != "plan_digest"})
            or material.get("contract") != "sos_native_install_plan_v1"
            or material.get("uv_sha256") != uv_sha256
            or material.get("wheel_inventory") != [[p.name, d] for p, d in wheels]):
        raise ProjectRuntimeError("SOS_PROJECT_RUNTIME_INSTALL_INTENT_INVALID")
    release = MaintenanceLauncherBinding.from_payload(maintenance_binding)
    identity = material["identity"]
    if (not isinstance(identity, dict)
            or not isinstance(identity.get("repository_digest"), str)
            or re.fullmatch(r"sha256:[0-9a-f]{64}", identity["repository_digest"]) is None):
        raise ProjectRuntimeError("SOS_PROJECT_RUNTIME_INSTALL_INTENT_INVALID")
    validate_runtime_identity(identity, **observe_project(root, identity["repository_digest"]))
    if identity["maintenance_binding"] != release.payload() or identity["interpreter_digest"] != interpreter_digest:
        raise ProjectRuntimeError("SOS_PROJECT_RUNTIME_RELEASE_INVALID")
    from .atomic_switch import _require_terminal_switches, AtomicSwitchError
    try:
        _require_terminal_switches(root)
    except AtomicSwitchError:
        raise ProjectRuntimeError("SOS_PROJECT_RUNTIME_ADAPTER_RECOVERY_REQUIRED") from None
    if not confirmed:
        return TerminalResult("sos_native_install_result_v1", Status.OWNER_REQUIRED,
            ("SOS_NATIVE_INSTALL_RECOVERY_CONFIRMATION_REQUIRED",),
            {"plan_digest": material["plan_digest"], "state": intent["state"], "writes_performed": False})
    with install_intent_lock(namespace, root):
        if read_install_intent(namespace, root) != intent:
            raise ProjectRuntimeError("SOS_PROJECT_RUNTIME_PREVIEW_STALE")
        # Never silently retry a partly populated environment. It remains owned
        # and retained for explicit recovery; no incomplete runtime becomes ready.
        try:
            command, version, executable_digest = observe_verified_generation_launcher(
                namespace, root, identity, repository_digest=identity["repository_digest"],
                confirmed_plan_digest=material["plan_digest"], wheels=wheels, active=True)
        except (ProjectRuntimeError, OSError):
            return TerminalResult("sos_native_install_result_v1", Status.BLOCKED,
                ("SOS_PROJECT_RUNTIME_PROVISIONING_RECOVERY_REQUIRED",),
                {"recovery_required": True, "generation_retained": True, "runtime_ready": False})
        launcher = LauncherBinding(str(command), version, "sha256:" + executable_digest)
        recovery = recover_one_command_init(str(root), launcher=launcher, client=intent["client"])
        if recovery.status not in {Status.SUCCESS, Status.NOT_VERIFIED}:
            return recovery
        if "SOS_P106_INSTALLED" in recovery.reasons:
            _raw, receipt, original_release = _original(root)
            if (receipt["aggregate_plan_digest"] != material["bootstrap_plan_digest"]
                    or original_release.payload() != release.payload()
                    or receipt["mcp_launcher_binding"]["binding_digest"] != launcher.digest):
                raise ProjectRuntimeError("SOS_PROJECT_RUNTIME_INSTALL_RECORD_CONFLICT")
        else:
            plan = prepare_native_install(root, namespace=namespace,
                maintenance_binding=release.payload(), uv=uv, uv_sha256=uv_sha256,
                wheel=wheel, wheels=wheels, controller_command=controller_command,
                interpreter_digest=interpreter_digest, confirmation_seed=intent["confirmation_seed"],
                primary_authority_id=intent["primary_authority_id"], client=intent["client"])
            if plan.payload != material:
                raise ProjectRuntimeError("SOS_PROJECT_RUNTIME_PREVIEW_STALE")
            result = execute_one_command_init(plan.bootstrap, confirmed=True, controlling_tty_observed=True)
            if result.status not in {Status.SUCCESS, Status.OWNER_REQUIRED}:
                return result
        publish_installed_runtime(root, identity, confirmed_plan_digest=material["plan_digest"], wheels=wheels)
        write_install_intent(namespace, root, {**intent, "state": "committed"})
        return TerminalResult("sos_native_install_result_v1", Status.SUCCESS,
            ("SOS_NATIVE_INSTALL_RECOVERED",), {"runtime_isolated": True, "qualification_performed": False})


def installed_runtime_record(identity, *, confirmed_plan_digest, wheels):
    material = {
        "contract": "sos_project_runtime_install_plan_v1",
        "identity": identity,
        "plan_digest": confirmed_plan_digest,
        "wheel_inventory": [[path.name, digest] for path, digest in wheels],
        "raw_content_serialized": False,
        "absolute_paths_serialized": False,
    }
    material["record_digest"] = digest_value(material)
    return material


def publish_installed_runtime(root, identity, *, confirmed_plan_digest, wheels):
    record = installed_runtime_record(identity, confirmed_plan_digest=confirmed_plan_digest, wheels=wheels)
    existing = read_integration_control_file(root, _RECORD)
    encoded = canonical_json(record)
    if existing is not None and existing != encoded:
        raise ProjectRuntimeError("SOS_PROJECT_RUNTIME_INSTALL_RECORD_CONFLICT")
    if existing is None:
        publish_integration_control_file(root, _RECORD, encoded)
    return record


def load_installed_runtime(path, *, namespace, wheels, maintenance_binding):
    root = discover_repository_root(str(path))
    raw = read_integration_control_file(root, _RECORD)
    if raw is None:
        raise ProjectRuntimeError("SOS_PROJECT_RUNTIME_HISTORY_REQUIRED")
    record = _parse(raw)
    if (not isinstance(record, dict)
            or record.get("contract") != "sos_project_runtime_install_plan_v1"
            or record.get("record_digest") != digest_value({k: v for k, v in record.items() if k != "record_digest"})
            or record.get("wheel_inventory") != [[path.name, digest] for path, digest in wheels]):
        raise ProjectRuntimeError("SOS_PROJECT_RUNTIME_INSTALL_RECORD_INVALID")
    _raw, receipt, _release = _original(root)
    supplied = MaintenanceLauncherBinding.from_payload(maintenance_binding)
    if record["identity"].get("maintenance_binding") != supplied.payload():
        raise ProjectRuntimeError("SOS_PROJECT_RUNTIME_RELEASE_INVALID")
    identity = validate_runtime_identity(
        record["identity"], **observe_project(root, digest_value(receipt["repository_id"]))
    )
    namespace = Path(namespace)
    target = namespace / identity["project_key"][7:] / identity["generation_key"][7:]
    successor = LauncherBinding(
        str(target / "tools/sigma-operator-stack/bin/python3"), supplied.version,
        identity["interpreter_digest"],
    )
    if receipt["mcp_launcher_binding"]["binding_digest"] != successor.digest:
        raise ProjectRuntimeError("SOS_PROJECT_RUNTIME_LAUNCHER_MISMATCH")
    return InstalledRuntime(root, namespace, successor, wheels, canonical_json(record))
