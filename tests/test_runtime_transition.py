"""Real adapter/journal orchestration with synthetic payload acquisition."""

import json
import hashlib
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path
from unittest.mock import patch

import test_atomic_switch as atomic_fixtures
from test_project_runtime_adapter_isolation import snapshot
from sos.adapter_transition_preview import exact_adapter_targets, verify_adapter_targets
from sos.atomic_switch import execute_atomic_switch, prepare_atomic_switch
from sos.client_integration import publish_integration_control_file, LauncherBinding
from sos.contracts import canonical_json, digest_value
from sos.maintenance_binding import MaintenanceLauncherBinding, mcp_launcher_binding_payload
from sos.platforms.project_runtime_posix import observe_project
from sos.project_runtime import ProjectRuntimeError, runtime_identity
from sos.runtime_transition import (prepare_runtime_transition, execute_runtime_transition,
    recover_runtime_transition, resolve_runtime_maintenance, load_runtime_transition,
    observe_current_runtime_launcher)
from sos.workspace import workspace_status
from sos.result import TerminalResult, Status


class RuntimeTransitionTests(unittest.TestCase):
    def test_source_stale_requires_explicit_transition_and_complete_valid_observation(self):
        import sos.client_integration as client
        for allowed, state, complete, expected in (
            (False, Status.STALE, True, Status.STALE),
            (True, Status.STALE, True, Status.SUCCESS),
            (True, Status.STALE, False, Status.STALE),
            (True, Status.INVALID, True, Status.INVALID),
        ):
            with self.subTest(allowed=allowed, state=state, complete=complete):
                good = TerminalResult("synthetic", Status.SUCCESS, (), {})
                preview = TerminalResult("synthetic", Status.OWNER_REQUIRED, (), {})
                observed = TerminalResult("synthetic", state, ("SOS_SOURCE_STATUS_CHANGED",),
                    {"application_observation_complete": complete, "control_plane_integrity": "valid"})
                with patch.object(client, "preview_codex_setup_update", return_value=preview), \
                     patch.object(client, "remove_codex_setup", return_value=good) as remove, \
                     patch.object(client, "install_codex_setup", return_value=good), \
                     patch.object(client, "workspace_status", side_effect=[good, observed]):
                    result = client.update_codex_setup("synthetic", confirmed=True, controlling_tty_observed=True,
                        launcher=LauncherBinding("/synthetic/python", "0.1.0a6", "sha256:" + "a" * 64),
                        allow_source_stale=allowed)
                    self.assertEqual(result.status, expected)
                    self.assertEqual(remove.call_count, 1 if expected == Status.SUCCESS else 2)

    def test_real_predecessor_digest_uses_platform_qualified_format(self):
        from sos.runtime_transition import _verify_predecessor
        with tempfile.TemporaryDirectory() as temporary:
            executable = Path(temporary) / "python"
            executable.write_bytes(b"synthetic executable bytes")
            digest = hashlib.sha256(executable.read_bytes()).hexdigest()
            _verify_predecessor(LauncherBinding(str(executable), "0.1.0a5", "sha256:" + digest))
            with self.assertRaisesRegex(ProjectRuntimeError, "PREDECESSOR_MISMATCH"):
                _verify_predecessor(LauncherBinding(str(executable), "0.1.0a5", digest))

    def scenario(self, legacy_mode=None):
        fixture = atomic_fixtures.AtomicSwitchTests()
        modes = () if legacy_mode is None else tuple({"target": name, "before_mode": legacy_mode}
                    for name in ("AGENTS.md", "CLAUDE.md", ".mcp.json"))
        temp, root, old = fixture.project(target_modes=modes)
        self.addCleanup(temp.cleanup)
        if legacy_mode is not None:
            (root / "AGENTS.md").chmod(legacy_mode)
        other_temp, other, _ = fixture.project()
        self.addCleanup(other_temp.cleanup)
        payload = tempfile.TemporaryDirectory()
        self.addCleanup(payload.cleanup)
        base = Path(payload.name).resolve()
        namespace = base / "project-runtimes"
        namespace.mkdir(mode=0o700)
        binding = MaintenanceLauncherBinding("0.1.0a5", "v0.1.0a5", "1"*40, "2"*40,
            "SOS-Linux-0.1.0a5.zip", "3"*64, "4"*64, "linux", "x86_64", "linux-alpha",
            "Install-SOS.command", "5"*64)
        repository = workspace_status(str(root)).details["repository_id"]
        publish_integration_control_file(root, "lifecycle/p106-install.json", canonical_json({
            "contract": "sos_p106_install_receipt_v2", "repository_id": repository,
            "mcp_launcher_binding": mcp_launcher_binding_payload(package_version=old.package_version,
                executable_sha256=old.executable_sha256, binding_digest=old.digest),
            "maintenance_launcher_binding": binding.payload()}))
        identity = runtime_identity(**observe_project(root, digest_value(repository)),
            maintenance_binding=replace(binding, version="0.1.0a6", release_tag="v0.1.0a6").payload(),
            wheel_digest="sha256:" + "c"*64, interpreter_digest="sha256:"+"b"*64)
        def digest(path):
            return "d"*64 if path.name == "uv" else ("c"*64 if path.suffix == ".whl" else "a"*64)
        self.addCleanup(patch.stopall)
        patch("sos.runtime_transition._regular_digest", side_effect=digest).start()
        patch("sos.runtime_transition.checked_wheel_sources").start()
        patch("sos.runtime_transition._verify_predecessor").start()
        reserve = patch("sos.runtime_transition.reserve_generation").start()
        install = patch("sos.runtime_transition.install_reserved_wheel").start()
        plan = prepare_runtime_transition(root, namespace=namespace, identity=identity,
            predecessor=old, uv=base/"uv", uv_sha256="d"*64, wheel=base/"sos.whl",
            wheels=((base/"sos.whl", "c"*64),), switch_nonce="a"*32)
        patch("sos.runtime_transition.observe_verified_generation_launcher", return_value=(
            Path(plan.successor.command), plan.successor.package_version, plan.successor.executable_sha256.removeprefix("sha256:"))).start()
        return fixture, root, other, old, plan, reserve, install

    def execute(self, plan, **kwargs):
        return execute_runtime_transition(plan, confirmed_plan_digest=plan.payload["plan_digest"],
                                          controlling_tty_observed=True, **kwargs)

    def reload(self, plan, **overrides):
        arguments = dict(namespace=plan.namespace, predecessor=plan.predecessor,
                         uv=plan.uv, wheel=plan.wheel, wheels=plan.wheels,
                         maintenance_binding=plan.payload["identity"]["maintenance_binding"])
        arguments.update(overrides)
        return load_runtime_transition(plan.root, **arguments)

    def test_disk_reload_after_switch_crash_uses_fresh_extraction(self):
        fixture, root, other, old, plan, _, _ = self.scenario()
        other_before = snapshot(other)
        def crash(point):
            if point == "before_client:claude-code":
                raise atomic_fixtures.SyntheticCrash()
        with self.assertRaises(atomic_fixtures.SyntheticCrash):
            self.execute(plan, fault=crash)
        fresh = plan.wheel.parent / "fresh-extraction"
        recovered = self.reload(plan, uv=fresh / "uv", wheel=fresh / plan.wheel.name,
                                wheels=tuple((fresh / path.name, digest) for path, digest in plan.wheels))
        self.assertEqual(recovered.sealed, plan.sealed)
        self.assertIsNot(recovered, plan)
        result = recover_runtime_transition(recovered, confirmed=True)
        self.assertEqual(result.details["state"], "rolled_back")
        fixture.assert_bound(root, old)
        self.assertEqual(snapshot(other), other_before)

    def test_disk_reload_rejects_wrong_release_predecessor_and_wheels(self):
        _, _, _, old, plan, _, _ = self.scenario()
        self.execute(plan)
        wrong = dict(plan.payload["identity"]["maintenance_binding"])
        wrong["candidate"] = "f" * 40
        wrong.pop("binding_digest")
        with self.assertRaisesRegex(ProjectRuntimeError, "RELEASE_INVALID"):
            self.reload(plan, maintenance_binding=wrong)
        with self.assertRaisesRegex(ProjectRuntimeError, "PREDECESSOR_MISMATCH"):
            self.reload(plan, predecessor=replace(old, executable_sha256="f" * 64))
        alias = replace(old, command=old.command + "3")
        self.assertEqual(alias.digest, old.digest)
        with self.assertRaisesRegex(ProjectRuntimeError, "PREDECESSOR_MISMATCH"):
            self.reload(plan, predecessor=alias)
        with self.assertRaisesRegex(ProjectRuntimeError, "PAYLOAD_MISMATCH"):
            self.reload(plan, wheels=((plan.wheel, "f" * 64),))

    def test_observe_installed_launcher_follows_history_not_controller_or_path(self):
        _, root, _, old, plan, _, _ = self.scenario()
        self.assertEqual(observe_current_runtime_launcher(root), old)
        self.execute(plan)
        self.assertEqual(observe_current_runtime_launcher(root), plan.successor)
        target = root / ".codex/config.toml"
        target.write_text(target.read_text().replace(plan.successor.command, old.command))
        with self.assertRaisesRegex(ProjectRuntimeError, "PREDECESSOR_MISMATCH"):
            observe_current_runtime_launcher(root)

    def test_provisioning_process_crash_can_abort_without_successor_runtime(self):
        fixture, root, other, old, plan, _, install = self.scenario()
        before = snapshot(other)
        install.side_effect = atomic_fixtures.SyntheticCrash()
        with self.assertRaises(atomic_fixtures.SyntheticCrash):
            self.execute(plan)
        restored = self.reload(plan)
        refused = recover_runtime_transition(restored)
        self.assertTrue(refused.details["recovery_required"])
        result = recover_runtime_transition(restored, confirmed=True)
        self.assertEqual(result.details["state"], "aborted")
        fixture.assert_bound(root, old)
        self.assertEqual(snapshot(other), before)
        self.assertEqual(resolve_runtime_maintenance(root).version, "0.1.0a5")

    def test_preview_and_no_tty_are_read_only(self):
        _, root, _, _, plan, reserve, install = self.scenario()
        before = snapshot(root)
        result = execute_runtime_transition(plan, confirmed_plan_digest=plan.payload["plan_digest"])
        self.assertEqual(result.status, "owner_required")
        self.assertEqual(len(result.details["targets"]), 4)
        self.assertEqual(snapshot(root), before)
        reserve.assert_not_called()
        install.assert_not_called()

    def test_switch_resolves_new_binding_preserves_receipt_and_other_project(self):
        fixture, root, other, old, plan, reserve, install = self.scenario()
        other_before = snapshot(other)
        receipt = (root/".sigma/lifecycle/p106-install.json").read_bytes()
        result = self.execute(plan)
        self.assertEqual(result.status, "success", result.to_dict())
        fixture.assert_bound(root, plan.successor)
        fixture.assert_bound(other, old)
        verify_adapter_targets(root, plan.payload["targets"], after=True)
        self.assertEqual(resolve_runtime_maintenance(root).version, "0.1.0a6")
        self.assertEqual((root/".sigma/lifecycle/p106-install.json").read_bytes(), receipt)
        self.assertEqual(snapshot(other), other_before)
        reserve.assert_called_once()
        install.assert_called_once()

    def test_source_drift_after_preview_refuses_before_provisioning(self):
        _, root, _, _, plan, reserve, install = self.scenario()
        (root/"README.md").write_text("Synthetic changed content")
        with self.assertRaisesRegex(ProjectRuntimeError, "PREVIEW_STALE"):
            self.execute(plan)
        reserve.assert_not_called()
        install.assert_not_called()
        self.assertFalse((root/".sigma/lifecycle/runtime-transitions.json").exists())

    def test_crash_mid_switch_uses_p107_rollback(self):
        fixture, root, _, old, plan, _, _ = self.scenario()
        def crash(point):
            if point == "before_client:claude-code":
                raise atomic_fixtures.SyntheticCrash()
        with self.assertRaises(atomic_fixtures.SyntheticCrash):
            self.execute(plan, fault=crash)
        with self.assertRaisesRegex(ProjectRuntimeError, "RECOVERY_REQUIRED"):
            resolve_runtime_maintenance(root)
        result = recover_runtime_transition(plan, confirmed=True)
        self.assertEqual(result.details["state"], "rolled_back", result.to_dict())
        fixture.assert_bound(root, old)
        self.assertEqual(resolve_runtime_maintenance(root).version, "0.1.0a5")

    def test_cold_rollback_restores_legacy_a5_target_modes(self):
        fixture, root, _, old, plan, _, _ = self.scenario(legacy_mode=0o600)
        before = (root / "AGENTS.md").read_bytes()
        def crash(point):
            if point == "before_client:claude-code":
                raise atomic_fixtures.SyntheticCrash()
        with self.assertRaises(atomic_fixtures.SyntheticCrash):
            self.execute(plan, fault=crash)
        recovered = self.reload(plan)
        result = recover_runtime_transition(recovered, confirmed=True)
        self.assertEqual(result.details["state"], "rolled_back", result.to_dict())
        self.assertEqual((root / "AGENTS.md").stat().st_mode & 0o777, 0o600)
        self.assertEqual((root / "AGENTS.md").read_bytes(), before)
        fixture.assert_bound(root, old)
        for name in ("CLAUDE.md", ".mcp.json"):
            self.assertEqual((root / name).stat().st_mode & 0o777, 0o600)
        replay = recover_runtime_transition(self.reload(plan), confirmed=True)
        self.assertEqual(replay.details["state"], "rolled_back", replay.to_dict())
        fixture.assert_bound(root, old)

    def test_crash_after_p107_commit_recovers_verified_successor(self):
        _, root, _, _, plan, _, _ = self.scenario()
        def crash(point):
            if point == "after_adapter_terminal":
                raise atomic_fixtures.SyntheticCrash()
        with self.assertRaises(atomic_fixtures.SyntheticCrash):
            self.execute(plan, fault=crash)
        result = recover_runtime_transition(plan, confirmed=True)
        self.assertEqual(result.status, "success", result.to_dict())
        self.assertEqual(resolve_runtime_maintenance(root).version, "0.1.0a6")

    def test_payload_failure_leaves_adapters_and_current_release_unchanged(self):
        fixture, root, _, old, plan, _, install = self.scenario()
        install.side_effect = ProjectRuntimeError("SOS_PROJECT_RUNTIME_PAYLOAD_MISMATCH")
        result = self.execute(plan)
        self.assertEqual(result.details["state"], "aborted")
        fixture.assert_bound(root, old)
        self.assertEqual(resolve_runtime_maintenance(root).version, "0.1.0a5")

    def test_malformed_history_never_falls_back_to_original(self):
        _, root, _, _, plan, _, _ = self.scenario()
        self.assertEqual(self.execute(plan).status, "success")
        path = root/".sigma/lifecycle/runtime-transitions.json"
        rows = json.loads(path.read_bytes())
        rows[-1]["events"].pop(2)
        path.write_text(json.dumps(rows))
        with self.assertRaises(ProjectRuntimeError):
            resolve_runtime_maintenance(root)

    def test_exact_preview_matches_actual_p107_without_payload_mocks(self):
        fixture = atomic_fixtures.AtomicSwitchTests()
        temp, root, old = fixture.project()
        self.addCleanup(temp.cleanup)
        new = fixture.binding("0.1.0a6", "b")
        plan = prepare_atomic_switch(str(root), predecessor=old, successor=new)
        before = snapshot(root)
        targets = exact_adapter_targets(root, plan.clients, new)
        self.assertEqual(snapshot(root), before)
        result = execute_atomic_switch(plan, confirmed=True, controlling_tty_observed=True,
            target_check=lambda:verify_adapter_targets(root, targets, after=True))
        self.assertEqual(result.status, "success", result.to_dict())

    def test_terminal_ledger_write_failure_never_claims_aborted_or_success(self):
        _, root, _, _, plan, _, _ = self.scenario()
        real = publish_integration_control_file
        failed = False
        def publish(target, relative, payload):
            nonlocal failed
            if (relative == "lifecycle/runtime-transitions.json" and not failed
                    and json.loads(payload)[-1]["events"][-1]["state"] == "committed"):
                failed = True
                raise OSError("synthetic journal failure")
            return real(target, relative, payload)
        with patch("sos.runtime_transition.publish_integration_control_file", side_effect=publish):
            result = self.execute(plan)
        self.assertTrue(failed)
        self.assertEqual(result.details["state"], "recovery_required")
        with self.assertRaisesRegex(ProjectRuntimeError, "RECOVERY_REQUIRED"):
            resolve_runtime_maintenance(root)

    def test_foreign_target_drift_is_retained_and_blocks_maintenance(self):
        _, root, _, _, plan, _, _ = self.scenario()
        foreign = b"Synthetic unrelated replacement\n"
        def drift(point):
            if point == "before_commit":
                (root/"AGENTS.md").write_bytes(foreign)
        result = self.execute(plan, fault=drift)
        self.assertEqual(result.details["state"], "recovery_required")
        self.assertEqual((root/"AGENTS.md").read_bytes(), foreign)
        with self.assertRaisesRegex(ProjectRuntimeError, "RECOVERY_REQUIRED"):
            resolve_runtime_maintenance(root)
