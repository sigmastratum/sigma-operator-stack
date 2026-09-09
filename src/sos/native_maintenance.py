"""Verified-wheel controller for isolated native version transitions.

The outer release route verifies pointer/index/archive before invoking this
controller. This entrypoint independently rechecks the extracted manifest and
payload. It never runs from the predecessor environment or searches PATH.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from . import __version__
from .result import Status
from .contracts import digest_value
from .maintenance_binding import MaintenanceLauncherBinding, MaintenanceBindingError
from .project_runtime import runtime_identity, ProjectRuntimeError
from .platforms.project_runtime_posix import (
    _regular_digest, observe_project, observe_verified_generation_launcher,
    controller_executable, run_checked_native_smoke,
)
from .atomic_switch import AtomicSwitchPlan, prepare_atomic_switch, execute_atomic_switch
from .platforms.project_runtime_inventory import _read
from .repository import discover_repository_root
from .runtime_transition import (
    _original, _parse, _history, observe_current_runtime_launcher, prepare_runtime_transition,
    execute_runtime_transition, resolve_runtime_maintenance, load_latest_runtime_transition,
    recover_runtime_transition,
)
from .native_removal import (
    prepare_native_removal, execute_native_removal, recover_native_removal,
    _record as removal_record,
)
from .runtime_install import load_installed_runtime, prepare_native_install, execute_native_install, NativeInstallPlan
from .runtime_install import recover_native_install
from .platforms.runtime_install_intent import read_install_intent


def _release_inputs(project, *, bundle, binding):
    root = discover_repository_root(str(project))
    bundle = Path(bundle)
    release = MaintenanceLauncherBinding.from_payload(binding)
    if release.version != __version__:
        raise ProjectRuntimeError("SOS_PROJECT_RUNTIME_RELEASE_INVALID")
    manifest_file = bundle / "release-manifest.json"
    if _regular_digest(manifest_file) != release.inner_manifest_sha256:
        raise ProjectRuntimeError("SOS_PROJECT_RUNTIME_RELEASE_INVALID")
    manifest = _parse(_read(manifest_file, 1024 * 1024))
    if (not isinstance(manifest, dict) or manifest.get("version") != release.version
            or manifest.get("candidate") != release.candidate or manifest.get("tree") != release.tree):
        raise ProjectRuntimeError("SOS_PROJECT_RUNTIME_RELEASE_INVALID")
    artifacts = manifest.get("artifacts")
    if not isinstance(artifacts, list):
        raise ProjectRuntimeError("SOS_PROJECT_RUNTIME_RELEASE_INVALID")
    files = {}
    for item in artifacts:
        if not isinstance(item, dict) or set(item) != {"filename", "sha256", "media_type"}:
            raise ProjectRuntimeError("SOS_PROJECT_RUNTIME_RELEASE_INVALID")
        name, digest = item["filename"], item["sha256"]
        if (not isinstance(name, str) or not name or Path(name).name != name
                or "\\" in name or name in {".", ".."} or name in files):
            raise ProjectRuntimeError("SOS_PROJECT_RUNTIME_RELEASE_INVALID")
        if _regular_digest(bundle / name) != digest:
            raise ProjectRuntimeError("SOS_PROJECT_RUNTIME_PAYLOAD_MISMATCH")
        files[name] = digest
    wheel_name = f"sigma_operator_stack-{release.version}-py3-none-any.whl"
    if (wheel_name not in files or "uv" not in files
            or files.get(release.platform_launcher) != release.platform_launcher_sha256):
        raise ProjectRuntimeError("SOS_PROJECT_RUNTIME_PAYLOAD_MISMATCH")
    wheels = tuple((bundle / name, digest) for name, digest in sorted(files.items()) if name.endswith(".whl"))
    return root, bundle, release, files, wheels


def prepare_native_update(project, *, bundle, namespace, binding, interpreter_digest):
    """No writes: derive predecessor from installed adapters, successor from wheels."""
    root, bundle, release, files, wheels = _release_inputs(
        project, bundle=bundle, binding=binding
    )
    predecessor = observe_current_runtime_launcher(root)
    if predecessor.package_version == release.version:
        if resolve_runtime_maintenance(root).payload() != release.payload():
            raise ProjectRuntimeError("SOS_PROJECT_RUNTIME_RELEASE_INVALID")
        rows, _ = _history(root)
        committed = [row for row in rows if row["events"][-1]["state"] == "committed"]
        if not committed:
            installed = load_installed_runtime(root, namespace=Path(namespace), wheels=wheels,
                                               maintenance_binding=release.payload())
            observe_verified_generation_launcher(Path(namespace), root, installed.payload["identity"],
                repository_digest=installed.payload["identity"]["repository_digest"],
                confirmed_plan_digest=installed.payload["plan_digest"], wheels=wheels, active=True)
            return prepare_atomic_switch(str(root), predecessor=predecessor, successor=predecessor)
        prior = committed[-1]["plan"]
        command, version, digest = observe_verified_generation_launcher(Path(namespace), root, prior["identity"],
            repository_digest=prior["identity"]["repository_digest"], confirmed_plan_digest=prior["plan_digest"],
            wheels=wheels, active=True)
        if (str(command), version, "sha256:" + digest) != (predecessor.command, predecessor.package_version, predecessor.executable_sha256):
            raise ProjectRuntimeError("SOS_PROJECT_RUNTIME_LAUNCHER_MISMATCH")
        return prepare_atomic_switch(str(root), predecessor=predecessor, successor=predecessor)
    _raw, receipt, _binding = _original(root)
    wheel_name = f"sigma_operator_stack-{release.version}-py3-none-any.whl"
    identity = runtime_identity(**observe_project(root, digest_value(receipt["repository_id"])),
        maintenance_binding=release.payload(), wheel_digest="sha256:" + files[wheel_name],
        interpreter_digest=interpreter_digest)
    return prepare_runtime_transition(root, namespace=Path(namespace), identity=identity,
        predecessor=predecessor, uv=bundle / "uv", uv_sha256=files["uv"],
        wheel=bundle / wheel_name, wheels=wheels, python_network_allowed=True)


def load_native_transition(project, *, bundle, namespace, binding):
    root, bundle, release, files, wheels = _release_inputs(
        project, bundle=bundle, binding=binding
    )
    wheel = bundle / f"sigma_operator_stack-{release.version}-py3-none-any.whl"
    try:
        return load_latest_runtime_transition(
            root, namespace=Path(namespace), uv=bundle / "uv", wheel=wheel,
            wheels=wheels, maintenance_binding=release.payload(),
        )
    except ProjectRuntimeError as error:
        if error.reason != "SOS_PROJECT_RUNTIME_HISTORY_REQUIRED":
            raise
        return load_installed_runtime(root, namespace=Path(namespace), wheels=wheels,
                                      maintenance_binding=release.payload())


def verify_active_native(project, *, bundle, namespace, binding):
    from .runtime_transition import _verified
    transition = load_native_transition(project, bundle=bundle, namespace=namespace, binding=binding)
    _verified(transition, active=True)
    if (resolve_runtime_maintenance(transition.root).payload() != binding
            or observe_current_runtime_launcher(transition.root) != transition.successor):
        raise ProjectRuntimeError("SOS_PROJECT_RUNTIME_LAUNCHER_MISMATCH")
    return transition


def main(argv=None):
    parser = argparse.ArgumentParser(description="Isolated SOS update controller")
    parser.add_argument("--project", required=True)
    parser.add_argument("--bundle", required=True)
    parser.add_argument("--namespace", required=True)
    parser.add_argument("--binding-json", required=True)
    parser.add_argument("--interpreter-digest", required=True)
    parser.add_argument("--mode", choices=("install", "update", "recover", "remove", "test", "detach"), default="update")
    parser.add_argument("--client", choices=("codex", "claude-code"), default="codex")
    parser.add_argument("--primary-authority")
    parser.add_argument("--confirmation-seed")
    parser.add_argument("--expected-plan-digest")
    args = parser.parse_args(argv)
    try:
        binding = _parse(args.binding_json)
        if args.mode == "recover":
            root, bundle, release, files, wheels = _release_inputs(args.project, bundle=args.bundle, binding=binding)
            intent = read_install_intent(Path(args.namespace), root)
            rows, _ = _history(root)
            if intent is not None and not rows and removal_record(root) is None:
                kwargs = dict(namespace=Path(args.namespace), maintenance_binding=release.payload(),
                    uv=bundle / "uv", uv_sha256=files["uv"],
                    wheel=bundle / f"sigma_operator_stack-{release.version}-py3-none-any.whl",
                    wheels=wheels, controller_command=controller_executable(), interpreter_digest=args.interpreter_digest)
                preview = recover_native_install(root, **kwargs)
                print(json.dumps(preview.to_dict(), sort_keys=True), flush=True)
                if not sys.stdin.isatty():
                    return 2
                print("Recover this exact fresh installation? [y/N] ", end="", flush=True)
                if sys.stdin.readline().strip().lower() not in {"y", "yes"}:
                    return 2
                result = recover_native_install(root, **kwargs, confirmed=True)
                print(json.dumps(result.to_dict(), sort_keys=True), flush=True)
                return 0 if result.status == Status.SUCCESS else 2
        if args.mode == "test":
            root, bundle, release, files, wheels = _release_inputs(args.project, bundle=args.bundle, binding=binding)
            transition = load_native_transition(root, bundle=bundle, namespace=args.namespace, binding=binding)
            from .runtime_transition import _verified
            _verified(transition, active=True)
            if (resolve_runtime_maintenance(root).payload() != release.payload()
                    or observe_current_runtime_launcher(root) != transition.successor):
                raise ProjectRuntimeError("SOS_PROJECT_RUNTIME_LAUNCHER_MISMATCH")
            from .atomic_switch import _configured_clients
            return run_checked_native_smoke(bundle / "native-smoke", files["native-smoke"], transition.successor, root,
                                            _configured_clients(root, transition.successor))
        if args.mode == "detach":
            from .runtime_transition import _verified
            from .client_integration import remove_codex_setup
            from .claude_integration import remove_claude_setup
            transition = load_native_transition(args.project, bundle=args.bundle,
                namespace=args.namespace, binding=binding)
            _verified(transition, active=True)
            if resolve_runtime_maintenance(transition.root).payload() != binding:
                raise ProjectRuntimeError("SOS_PROJECT_RUNTIME_RELEASE_INVALID")
            remove = remove_codex_setup if args.client == "codex" else remove_claude_setup
            kwargs = {"launcher": transition.successor}
            if args.client == "codex":
                kwargs["require_current_contract"] = False
            preview = remove(str(transition.root), confirmed=False, **kwargs)
            print(json.dumps(preview.to_dict(), sort_keys=True), flush=True)
            if not sys.stdin.isatty():
                return 2
            print("Detach only this client; preserve project runtime and records? [y/N] ", end="", flush=True)
            if sys.stdin.readline().strip().lower() not in {"y", "yes"}:
                return 2
            _verified(transition, active=True)
            result = remove(str(transition.root), confirmed=True, controlling_tty_observed=True, **kwargs)
            print(json.dumps(result.to_dict(), sort_keys=True), flush=True)
            return 0 if result.status == Status.SUCCESS else 2
        if args.mode == "install":
            root, bundle, release, files, wheels = _release_inputs(
                args.project, bundle=args.bundle, binding=binding)
            wheel = bundle / f"sigma_operator_stack-{release.version}-py3-none-any.whl"
            plan = prepare_native_install(root, namespace=Path(args.namespace),
                maintenance_binding=release.payload(), uv=bundle / "uv", uv_sha256=files["uv"],
                wheel=wheel, wheels=wheels, controller_command=controller_executable(),
                interpreter_digest=args.interpreter_digest, confirmation_seed=args.confirmation_seed,
                primary_authority_id=args.primary_authority, client=args.client)
            if args.expected_plan_digest is not None and args.expected_plan_digest != plan.payload["plan_digest"]:
                raise ProjectRuntimeError("SOS_P106_CONFIRMATION_BINDING_MISMATCH")
        elif args.mode == "update":
            plan = prepare_native_update(args.project, bundle=args.bundle, namespace=args.namespace,
                binding=binding, interpreter_digest=args.interpreter_digest)
        else:
            transition = load_native_transition(args.project, bundle=args.bundle,
                namespace=args.namespace, binding=binding)
            if args.mode == "recover":
                removal = removal_record(transition.root)
                preview = (recover_native_removal(transition)
                           if removal is not None else
                           recover_runtime_transition(transition, confirmed=False))
                print(json.dumps(preview.to_dict(), sort_keys=True), flush=True)
                if not sys.stdin.isatty():
                    return 2
                print("Recover this exact runtime transition? [y/N] ", end="", flush=True)
                if sys.stdin.readline().strip().lower() not in {"y", "yes"}:
                    return 2
                result = (recover_native_removal(transition,
                              confirmed_plan_digest=preview.details["plan_digest"],
                              controlling_tty_observed=True)
                          if removal is not None else
                          recover_runtime_transition(transition, confirmed=True))
                print(json.dumps(result.to_dict(), sort_keys=True), flush=True)
                return 0 if result.status == "success" else 2
            plan = prepare_native_removal(transition)
        print(json.dumps(plan.preview().to_dict(), sort_keys=True), flush=True)
        if not sys.stdin.isatty():
            return 2
        prompt = ("Remove this exact project runtime? [y/N] " if args.mode == "remove"
                  else "Apply this exact runtime and adapter transition? [y/N] ")
        print(prompt, end="", flush=True)
        if sys.stdin.readline().strip().lower() not in {"y", "yes"}:
            return 2
        result = (execute_native_install(plan, confirmed_plan_digest=plan.payload["plan_digest"],
                                         controlling_tty_observed=True)
                  if isinstance(plan, NativeInstallPlan) else
                  (execute_atomic_switch(plan, confirmed=True, controlling_tty_observed=True,
                      admission_check=lambda: verify_active_native(args.project, bundle=args.bundle,
                          namespace=args.namespace, binding=binding),
                      target_check=lambda: verify_active_native(args.project, bundle=args.bundle,
                          namespace=args.namespace, binding=binding))
                  if isinstance(plan, AtomicSwitchPlan) else
                  (execute_native_removal(plan, confirmed_plan_digest=plan.payload["plan_digest"],
                                          controlling_tty_observed=True)
                   if args.mode == "remove" else
                   execute_runtime_transition(plan, confirmed_plan_digest=plan.payload["plan_digest"],
                                              controlling_tty_observed=True))))
        print(json.dumps(result.to_dict(), sort_keys=True), flush=True)
        return 0 if result.status == "success" else 2
    except (ProjectRuntimeError, MaintenanceBindingError) as error:
        print(json.dumps({"status": "blocked", "reasons": [error.reason]}), flush=True)
        return 2
    except (OSError, ValueError, RuntimeError):
        print(json.dumps({"status": "blocked", "reasons": ["SOS_PROJECT_RUNTIME_CONTROLLER_FAILED"]}), flush=True)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
