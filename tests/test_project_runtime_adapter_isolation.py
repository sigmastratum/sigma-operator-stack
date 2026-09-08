"""Synthetic adapter isolation, not an installed a5-to-a6 runtime replay."""

import tempfile
import unittest
from pathlib import Path

import test_atomic_switch as atomic_fixtures
import test_project_runtime_posix as runtime_fixtures
from sos.atomic_switch import execute_atomic_switch, prepare_atomic_switch, recover_atomic_switch
from sos.claude_integration import remove_claude_setup
from sos.client_integration import LauncherBinding, remove_codex_setup
from sos.contracts import digest_value
from sos.platforms.project_runtime_posix import observe_project, reserve_generation
from sos.project_runtime import runtime_identity


def snapshot(root):
    return {str(p.relative_to(root)): (p.read_bytes(), p.stat().st_mode & 0o777)
            for p in root.rglob("*") if p.is_file()}


class ProjectRuntimeAdapterIsolationTests(unittest.TestCase):
    def scenario(self):
        fixture = atomic_fixtures.AtomicSwitchTests()
        first_tmp, first, predecessor = fixture.project()
        second_tmp, second, second_binding = fixture.project()
        self.addCleanup(first_tmp.cleanup)
        self.addCleanup(second_tmp.cleanup)
        self.assertEqual(predecessor, second_binding)
        for root in (first, second):
            (root / "user-sentinel.txt").write_bytes(b"synthetic user content\n")
        isolated = tempfile.TemporaryDirectory()
        self.addCleanup(isolated.cleanup)
        base = Path(isolated.name).resolve()
        namespace = base / "project-runtimes"
        namespace.mkdir(mode=0o700)
        legacy = base / "legacy-runtime"
        legacy.mkdir(mode=0o700)
        (legacy / "sentinel").write_bytes(b"synthetic shared a5 payload")
        runtime = runtime_fixtures.RuntimeReservationTests()
        runtime.setUp()
        self.addCleanup(runtime.doCleanups)
        template = runtime.identity()
        repository = digest_value("synthetic adapter isolation repository")
        identity = runtime_identity(
            **observe_project(first, repository),
            maintenance_binding=template["maintenance_binding"],
            wheel_digest=template["wheel_digest"],
            interpreter_digest=template["interpreter_digest"],
        )
        generation = reserve_generation(
            namespace, first, identity, repository_digest=repository,
            confirmed_plan_digest=digest_value("synthetic reservation confirmation"),
        )
        # A synthetic binding tests adapter routing only. This reserved location
        # contains no installed Python and is deliberately not marked ready.
        successor = LauncherBinding(str(generation / "python"), "0.1.0a6", "b" * 64)
        return fixture, first, second, predecessor, successor, generation, legacy

    def test_switch_and_detach_one_project_preserve_other_and_runtime_material(self):
        fixture, first, second, old, new, generation, legacy = self.scenario()
        other_before, legacy_before = snapshot(second), snapshot(legacy)
        generation_before = snapshot(generation)
        plan = prepare_atomic_switch(str(first), predecessor=old, successor=new)
        result = execute_atomic_switch(plan, confirmed=True, controlling_tty_observed=True)
        self.assertEqual(result.status, "success", result.to_dict())
        fixture.assert_bound(first, new)
        fixture.assert_bound(second, old)
        self.assertEqual(snapshot(second), other_before)
        for remove in (remove_claude_setup, remove_codex_setup):
            result = remove(str(first), confirmed=True, controlling_tty_observed=True, launcher=new)
            self.assertEqual(result.status, "success", result.to_dict())
        self.assertTrue((first / ".sigma").is_dir())
        self.assertEqual((first / "user-sentinel.txt").read_bytes(), b"synthetic user content\n")
        self.assertEqual(snapshot(second), other_before)
        self.assertEqual(snapshot(legacy), legacy_before)
        # Adapter detach must not claim runtime deletion: a separate ownership-
        # and reference-qualified remover is required for that operation.
        self.assertEqual(snapshot(generation), generation_before)

    def test_interrupted_switch_recovers_first_without_touching_second(self):
        fixture, first, second, old, new, generation, legacy = self.scenario()
        other_before, legacy_before = snapshot(second), snapshot(legacy)
        generation_before = snapshot(generation)
        plan = prepare_atomic_switch(str(first), predecessor=old, successor=new)

        def crash(point):
            if point == "before_client:claude-code":
                raise atomic_fixtures.SyntheticCrash()

        with self.assertRaises(atomic_fixtures.SyntheticCrash):
            execute_atomic_switch(plan, confirmed=True, controlling_tty_observed=True, fault=crash)
        result = recover_atomic_switch(str(first), plan.switch_id, predecessor=old, successor=new)
        self.assertEqual(result.status, "success", result.to_dict())
        self.assertTrue(result.details["rolled_back"])
        fixture.assert_bound(first, old)
        fixture.assert_bound(second, old)
        self.assertEqual(snapshot(second), other_before)
        self.assertEqual(snapshot(legacy), legacy_before)
        self.assertEqual(snapshot(generation), generation_before)
