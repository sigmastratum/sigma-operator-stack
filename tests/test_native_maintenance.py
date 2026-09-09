"""Carrier admission/confirmation tests; not an installed migration replay."""

import io
import hashlib
import json
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from sos import native_maintenance as native
from sos.platforms.project_runtime_posix import prepare_runtime_namespace
from sos.project_runtime import ProjectRuntimeError
from sos.result import TerminalResult, Status
from sos.client_integration import LauncherBinding
from sos.maintenance_binding import MaintenanceLauncherBinding


class NativeMaintenanceTests(unittest.TestCase):
    def test_operation_timeout_returns_blocked_without_traceback(self):
        import subprocess
        args = ["--mode", "update", "--project", "synthetic", "--bundle", "bundle",
                "--namespace", "namespace", "--binding-json", "{}",
                "--interpreter-digest", "sha256:" + "a"*64]
        with patch.object(native, "prepare_native_update", side_effect=subprocess.TimeoutExpired("synthetic", 0.01)), \
             patch.object(native.sys, "stdout", io.StringIO()) as output:
            self.assertEqual(native.main(args), 2)
            result = json.loads(output.getvalue())
            self.assertEqual(result["status"], "blocked")
            self.assertEqual(result["details"]["transition_state"], "unknown")

    def test_observation_rejects_malformed_intent_without_traceback(self):
        args = ["--mode", "update", "--observe-only", "--project", "synthetic", "--bundle", "bundle",
                "--namespace", "namespace", "--binding-json", "{}",
                "--interpreter-digest", "sha256:" + "a"*64]
        for intent in ([], {"plan": None}, {"plan": {"identity": []}},
                       {"plan": {"identity": {}}, "state": []}):
            with self.subTest(intent=intent), \
                 patch.object(native, "_release_inputs", return_value=(Path("synthetic"), None, None, {}, ())), \
                 patch.object(native, "read_install_intent", return_value=intent), \
                 patch.object(native, "_history", return_value=([], None)), \
                 patch.object(native, "removal_record", return_value=None), \
                 patch.object(native.sys, "stdout", io.StringIO()) as output:
                self.assertEqual(native.main(args), 2)
                self.assertEqual(json.loads(output.getvalue())["status"], "blocked")

    def test_observation_preserves_pending_and_committed_journal_states(self):
        args = ["--mode", "update", "--observe-only", "--project", "synthetic", "--bundle", "bundle",
                "--namespace", "namespace", "--binding-json", "{}",
                "--interpreter-digest", "sha256:" + "a"*64]
        release = SimpleNamespace(version="0.1.0a6", payload=lambda: {})
        for state, pending in (("switching", True), ("recovery_required", True), ("committed", False)):
            rows = [{"plan": {"identity": {"maintenance_binding": {}}}, "events": [{"state": state}]}]
            before = json.dumps(rows)
            with patch.object(native, "_release_inputs", return_value=(Path("synthetic"), Path("bundle"), release, {}, ())), \
                 patch.object(native, "read_install_intent", return_value=None), \
                 patch.object(native, "_history", return_value=(rows, None)), \
                 patch.object(native, "removal_record", return_value=None), \
                 patch.object(native, "execute_runtime_transition") as execute, \
                 patch.object(native, "recover_runtime_transition") as recover, \
                 patch.object(native.sys, "stdout", io.StringIO()) as output:
                self.assertEqual(native.main(args), 0)
                result = json.loads(output.getvalue())
                self.assertEqual(result["status"], "blocked")
                self.assertEqual(result["details"]["transition_state"], state)
                self.assertEqual(result["details"]["recovery_required"], pending)
                self.assertFalse(result["details"]["terminal_success_claimed"])
                execute.assert_not_called()
                recover.assert_not_called()
            self.assertEqual(json.dumps(rows), before)

    def test_fresh_recovery_returns_success_exit_only_after_confirmation(self):
        args = ["--mode", "recover", "--project", "synthetic", "--bundle", "bundle",
                "--namespace", "namespace", "--binding-json", "{}",
                "--interpreter-digest", "sha256:" + "a"*64]
        release = SimpleNamespace(version="0.1.0a6", payload=lambda: {})
        for tty, response, expected in ((False, "yes\n", 2), (True, "no\n", 2), (True, "yes\n", 0)):
            with self.subTest(tty=tty, response=response):
                source = io.StringIO(response)
                source.isatty = lambda: tty
                with patch.object(native, "_release_inputs", return_value=(Path("synthetic"), Path("bundle"), release, {"uv": "b"*64}, ())), \
                     patch.object(native, "read_install_intent", return_value={}), \
                     patch.object(native, "_history", return_value=([], None)), \
                     patch.object(native, "removal_record", return_value=None), \
                     patch.object(native, "recover_native_install", return_value=TerminalResult("synthetic", Status.SUCCESS, (), {})) as recover, \
                     patch.object(native.sys, "stdin", source), patch.object(native.sys, "stdout", io.StringIO()):
                    self.assertEqual(native.main(args), expected)
                    self.assertEqual(recover.call_count, 2 if expected == 0 else 1)
                    if expected == 0:
                        self.assertTrue(recover.call_args.kwargs["confirmed"])

    def test_cross_version_update_uses_exact_successor_wheel_filename(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            bundle = root / "bundle"
            bundle.mkdir()
            release = MaintenanceLauncherBinding("0.1.0a6", "v0.1.0a6", "1"*40, "2"*40,
                "SOS-Linux-0.1.0a6.zip", "3"*64, "4"*64, "linux", "x86_64", "linux-alpha",
                "Install-SOS.command", "5"*64)
            wheel = bundle / "sigma_operator_stack-0.1.0a6-py3-none-any.whl"
            files = {wheel.name: "6"*64, "uv": "7"*64}
            predecessor = LauncherBinding("/synthetic/python", "0.1.0a5", "sha256:" + "8"*64)
            with patch.object(native, "_release_inputs", return_value=(root, bundle, release, files, ((wheel, "6"*64),))), \
                 patch.object(native, "observe_current_runtime_launcher", return_value=predecessor), \
                 patch.object(native, "_original", return_value=(b"", {"repository_id": "synthetic"}, None)), \
                 patch.object(native, "prepare_runtime_transition", return_value="prepared") as prepare:
                self.assertEqual(native.prepare_native_update(root, bundle=bundle, namespace=root.parent / "project-runtimes",
                    binding=release.payload(), interpreter_digest="sha256:" + "9"*64), "prepared")
            self.assertEqual(prepare.call_args.kwargs["wheel"], wheel)
            self.assertEqual(prepare.call_args.kwargs["identity"]["wheel_digest"], "sha256:" + "6"*64)

    def test_confirmation_precedes_execution(self):
        args = ["--project", "synthetic", "--bundle", "bundle", "--namespace", "namespace",
                "--binding-json", "{}", "--interpreter-digest", "sha256:" + "a" * 64]
        for tty, response, expected in ((False, "yes\n", 2), (True, "no\n", 2), (True, "yes\n", 0)):
            with self.subTest(tty=tty, response=response):
                source = io.StringIO(response)
                source.isatty = lambda: tty
                events = []
                plan = SimpleNamespace(namespace=Path("namespace"), payload={"plan_digest": "exact"},
                    preview=lambda: TerminalResult("synthetic", Status.OWNER_REQUIRED, ("CONFIRM",), {}))
                with patch.object(native, "prepare_native_update", return_value=plan), \
                     patch.object(native, "execute_runtime_transition", side_effect=lambda *a, **k: (
                         events.append("execute") or TerminalResult("synthetic", Status.SUCCESS, (), {}))) as execute, \
                     patch.object(native.sys, "stdin", source), patch.object(native.sys, "stdout", io.StringIO()):
                    self.assertEqual(native.main(args), expected)
                    if expected == 0:
                        self.assertEqual(events, ["execute"])
                        execute.assert_called_once_with(plan, confirmed_plan_digest="exact", controlling_tty_observed=True)
                    else:
                        execute.assert_not_called()
                        self.assertEqual(events, [])

    def test_namespace_creation_refuses_symlink_and_does_not_chmod_existing(self):
        with tempfile.TemporaryDirectory() as temporary:
            parent = Path(temporary).resolve()
            namespace = parent / "project-runtimes"
            prepare_runtime_namespace(namespace)
            self.assertEqual(namespace.stat().st_mode & 0o777, 0o700)
            prepare_runtime_namespace(namespace)
            namespace.chmod(0o755)
            with self.assertRaises(ProjectRuntimeError):
                prepare_runtime_namespace(namespace)
            self.assertEqual(namespace.stat().st_mode & 0o777, 0o755)
        with tempfile.TemporaryDirectory() as temporary:
            parent = Path(temporary).resolve()
            other = parent / "other"
            other.mkdir()
            namespace = parent / "project-runtimes"
            namespace.symlink_to(other, target_is_directory=True)
            with self.assertRaises(ProjectRuntimeError):
                prepare_runtime_namespace(namespace)
            self.assertEqual(list(other.iterdir()), [])

    def test_bad_binding_never_reaches_runtime_preparation(self):
        with patch.object(native, "discover_repository_root", return_value=Path("/synthetic")), \
             patch.object(native, "prepare_runtime_transition") as transition:
            with self.assertRaises(native.MaintenanceBindingError):
                native.prepare_native_update("synthetic", bundle=Path("bundle"), namespace=Path("namespace"),
                                             binding={}, interpreter_digest="sha256:" + "a" * 64)
            transition.assert_not_called()
