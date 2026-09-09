"""Owned filesystem deletion and synthetic adapter-to-removal integration."""

import unittest
import json
from dataclasses import replace
from unittest.mock import patch

import test_project_runtime_posix as runtime_fixtures
import test_runtime_transition as transition_fixtures
from test_project_runtime_adapter_isolation import snapshot
from sos.claude_integration import remove_claude_setup
from sos.client_integration import remove_codex_setup
from sos.contracts import digest_value
from sos.platforms.project_runtime_posix import reserve_generation
from sos.platforms.project_runtime_removal import snapshot_owned_generation, delete_owned_generation
from sos.project_runtime import ProjectRuntimeError
from sos.runtime_removal import prepare_runtime_removal, execute_runtime_removal, recover_runtime_removal
from sos.native_removal import prepare_native_removal, execute_native_removal, recover_native_removal


class Crash(BaseException):
    pass


class OwnedRuntimeRemovalTests(unittest.TestCase):
    def scenario(self):
        fixture = runtime_fixtures.RuntimeReservationTests()
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        generation = fixture.reserve()
        (generation / "payload").mkdir()
        (generation / "payload/a").write_bytes(b"synthetic runtime")
        (generation / "payload/b").write_bytes(b"synthetic runtime two")
        observed = snapshot_owned_generation(fixture.namespace, fixture.project, fixture.identity(), fixture.plan)
        return fixture, generation, observed

    def delete(self, fixture, observed, **kwargs):
        return delete_owned_generation(fixture.namespace, fixture.project, fixture.identity(),
            snapshot=observed, confirmed_plan_digest=digest_value("synthetic removal"), **kwargs)

    def test_exact_generation_removed_but_legacy_and_project_preserved(self):
        fixture, generation, observed = self.scenario()
        before = snapshot(fixture.legacy), snapshot(fixture.project)
        self.delete(fixture, observed)
        self.assertFalse(generation.exists())
        self.assertEqual(before, (snapshot(fixture.legacy), snapshot(fixture.project)))
        self.delete(fixture, observed)  # exact durable completion is idempotent

    def test_unknown_new_file_refuses_before_any_deletion(self):
        fixture, generation, observed = self.scenario()
        (generation / "foreign").write_bytes(b"unrelated user file")
        before = snapshot(generation)
        with self.assertRaisesRegex(ProjectRuntimeError, "REMOVAL_DRIFT"):
            self.delete(fixture, observed)
        self.assertEqual(snapshot(generation), before)

    def test_symlink_is_unlinked_without_following_foreign_target(self):
        fixture, generation, observed = self.scenario()
        foreign = fixture.legacy / "sentinel"
        (generation / "external-link").symlink_to(foreign)
        observed = snapshot_owned_generation(fixture.namespace, fixture.project, fixture.identity(), fixture.plan)
        before = foreign.read_bytes()
        self.delete(fixture, observed)
        self.assertEqual(foreign.read_bytes(), before)
        self.assertFalse(generation.exists())

    def test_interrupted_deletion_resumes_but_new_file_blocks_retry(self):
        fixture, generation, observed = self.scenario()
        calls = 0
        def crash(point):
            nonlocal calls
            calls += 1
            if calls == 2:
                raise Crash()
        with self.assertRaises(Crash):
            self.delete(fixture, observed, fault=crash)
        (generation / "foreign").write_bytes(b"foreign after interruption")
        before = snapshot(generation)
        with self.assertRaisesRegex(ProjectRuntimeError, "REMOVAL_DRIFT"):
            self.delete(fixture, observed)
        self.assertEqual(snapshot(generation), before)

    def test_copied_identity_cannot_remove_another_project(self):
        fixture, generation, observed = self.scenario()
        other = fixture.base / "other-project"
        other.mkdir()
        with self.assertRaisesRegex(ProjectRuntimeError, "OWNERSHIP_MISMATCH"):
            delete_owned_generation(fixture.namespace, other, fixture.identity(), snapshot=observed,
                confirmed_plan_digest=digest_value("synthetic removal"))
        self.assertTrue(generation.exists())


class QualifiedRuntimeRemovalTests(unittest.TestCase):
    def test_live_reference_after_detach_blocks_and_exact_recovery_replans_before_deletion(self):
        fixture = transition_fixtures.RuntimeTransitionTests()
        _, root, _, _, transition, _, _ = fixture.scenario()
        self.addCleanup(fixture.doCleanups)
        self.assertEqual(fixture.execute(transition).status, "success")
        p = transition.payload
        generation = reserve_generation(transition.namespace, root, p["identity"],
            repository_digest=p["identity"]["repository_digest"], confirmed_plan_digest=p["plan_digest"])
        (generation / "synthetic-payload").write_bytes(b"synthetic")
        plan = prepare_native_removal(transition)
        with patch("sos.native_removal._finish_runtime", side_effect=ProjectRuntimeError("synthetic interruption")):
            interrupted = execute_native_removal(plan, confirmed_plan_digest=plan.payload["plan_digest"], controlling_tty_observed=True)
        self.assertTrue(interrupted.details["recovery_required"])
        self.assertTrue(generation.exists())
        config = root / ".mcp.json"
        config.write_text(json.dumps({"mcpServers": {"sigma_operator_stack": {"command": transition.successor.command}}}))
        with self.assertRaisesRegex(ProjectRuntimeError, "STILL_REFERENCED"):
            prepare_runtime_removal(transition)
        config.unlink()  # Remove only this test's deliberately restored fixture.
        for command in (transition.successor.command, str(generation / "bin/other")):
            config.write_text(json.dumps({"mcpServers": {"saved_alias": {"command": command}}}))
            with self.assertRaisesRegex(ProjectRuntimeError, "STILL_REFERENCED"):
                prepare_runtime_removal(transition)
            self.assertTrue(generation.exists())
            config.unlink()
        config.write_text(json.dumps({"mcpServers": {"malformed_alias": {"command": []}}}))
        with self.assertRaisesRegex(ProjectRuntimeError, "REFERENCES_UNKNOWN"):
            prepare_runtime_removal(transition)
        config.unlink()
        alias = root / "saved-python"
        alias.symlink_to(generation / "bin/python3")
        config.write_text(json.dumps({"mcpServers": {"saved_alias": {"command": str(alias)}}}))
        with self.assertRaisesRegex(ProjectRuntimeError, "STILL_REFERENCED"):
            prepare_runtime_removal(transition)
        config.unlink()
        alias.unlink()
        (generation / "synthetic-payload").write_bytes(b"changed synthetic bytes before first deletion")
        preview = recover_native_removal(transition)
        self.assertEqual(preview.status, "owner_required")
        self.assertNotEqual(preview.details["runtime_snapshot_digest"], plan.payload["runtime_snapshot_digest"])
        self.assertTrue(generation.exists())
        # A file appearing while the owner sees the preview must not silently
        # become part of the confirmed deletion snapshot.
        foreign = generation / "added-after-preview"
        foreign.write_bytes(b"not approved for removal")
        before = snapshot(root), snapshot(generation)
        with self.assertRaisesRegex(ProjectRuntimeError, "PREVIEW_STALE"):
            recover_native_removal(transition,
                confirmed_plan_digest=preview.details["plan_digest"], controlling_tty_observed=True)
        self.assertEqual(before, (snapshot(root), snapshot(generation)))
        foreign.unlink()
        completed = recover_native_removal(transition,
            confirmed_plan_digest=preview.details["plan_digest"], controlling_tty_observed=True)
        self.assertEqual(completed.status, "success", completed.to_dict())
        self.assertFalse(generation.exists())
        # Completed recovery also rechecks durable removal rather than reporting
        # green solely from the aggregate state string.
        self.assertEqual(recover_native_removal(transition,
            confirmed_plan_digest=preview.details["plan_digest"], controlling_tty_observed=True).status, "success")

    def test_one_aggregate_confirmation_detaches_both_and_removes_only_generation(self):
        fixture = transition_fixtures.RuntimeTransitionTests()
        adapter_fixture, root, other, old, transition, _, _ = fixture.scenario()
        self.addCleanup(fixture.doCleanups)
        self.assertEqual(fixture.execute(transition).status, "success")
        p = transition.payload
        generation = reserve_generation(transition.namespace, root, p["identity"],
            repository_digest=p["identity"]["repository_digest"], confirmed_plan_digest=p["plan_digest"])
        (generation / "synthetic-payload").write_bytes(b"synthetic installed runtime")
        project_before = snapshot(other)
        plan = prepare_native_removal(transition)
        self.assertEqual(execute_native_removal(plan).status, "owner_required")
        self.assertTrue(generation.exists())
        result = execute_native_removal(plan, confirmed_plan_digest=plan.payload["plan_digest"],
            controlling_tty_observed=True)
        self.assertEqual(result.status, "success", result.to_dict())
        self.assertFalse(generation.exists())
        self.assertTrue((root / ".sigma").is_dir())
        self.assertEqual(snapshot(other), project_before)
        adapter_fixture.assert_bound(other, old)

    def test_detach_required_then_interrupted_removal_recovers_from_disk(self):
        fixture = transition_fixtures.RuntimeTransitionTests()
        adapter_fixture, root, other, old, transition, _, _ = fixture.scenario()
        self.addCleanup(fixture.doCleanups)
        self.assertEqual(fixture.execute(transition).status, "success")
        p = transition.payload
        generation = reserve_generation(transition.namespace, root, p["identity"],
            repository_digest=p["identity"]["repository_digest"], confirmed_plan_digest=p["plan_digest"])
        (generation / "synthetic-payload").write_bytes(b"synthetic installed runtime")
        other_before = snapshot(other)
        with self.assertRaisesRegex(ProjectRuntimeError, "STILL_REFERENCED"):
            prepare_runtime_removal(transition)
        for remove in (remove_claude_setup, remove_codex_setup):
            result = remove(str(root), confirmed=True, controlling_tty_observed=True, launcher=transition.successor)
            self.assertEqual(result.status, "success")
        plan = prepare_runtime_removal(transition)
        before = snapshot(generation)
        self.assertEqual(execute_runtime_removal(plan).status, "owner_required")
        self.assertEqual(snapshot(generation), before)
        calls = 0
        def crash(point):
            nonlocal calls
            calls += 1
            if calls == 2:
                raise Crash()
        with self.assertRaises(Crash):
            execute_runtime_removal(plan, confirmed_plan_digest=plan.payload["plan_digest"],
                controlling_tty_observed=True, fault=crash)
        # No in-memory snapshot is supplied to recovery; it loads the exact
        # durable deletion manifest and separately retained project record.
        result = recover_runtime_removal(replace(transition),
            confirmed_plan_digest=plan.payload["plan_digest"], controlling_tty_observed=True)
        self.assertEqual(result.status, "success", result.to_dict())
        self.assertFalse(generation.exists())
        self.assertTrue((root / ".sigma/lifecycle/p106-install.json").is_file())
        self.assertEqual(snapshot(other), other_before)
        adapter_fixture.assert_bound(other, old)
