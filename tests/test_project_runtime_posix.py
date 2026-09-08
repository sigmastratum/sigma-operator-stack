from __future__ import annotations

import fcntl
import hashlib
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from sos.contracts import digest_value
from sos.maintenance_binding import MaintenanceLauncherBinding
from sos.project_runtime import ProjectRuntimeError, runtime_identity
from sos.platforms.project_runtime_posix import observe_project, reserve_generation, install_reserved_wheel


class RuntimeReservationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name).resolve()
        self.project = self.base / "project"
        self.namespace = self.base / "project-runtimes"
        self.legacy = self.base / "legacy"
        for path in (self.project, self.namespace, self.legacy):
            path.mkdir(mode=0o700)
        (self.legacy / "sentinel").write_bytes(b"legacy runtime remains unchanged")
        self.repo = digest_value("synthetic-repository")
        self.plan = digest_value("synthetic-confirmed-plan")

    def identity(self, project=None):
        return runtime_identity(
            **observe_project(project or self.project, self.repo),
            wheel_digest=digest_value("wheel"), interpreter_digest=digest_value("python"),
            maintenance_binding=MaintenanceLauncherBinding(
                "0.1.0a6", "v0.1.0a6", "1" * 40, "2" * 40,
                "SOS-Linux-0.1.0a6.zip", "3" * 64, "4" * 64,
                "linux", "x86_64", "linux-native-alpha", "Install-SOS.command", "5" * 64,
            ).payload(),
        )

    def reserve(self, **changes):
        args = dict(namespace=self.namespace, project=self.project,
                    identity=self.identity(), repository_digest=self.repo,
                    confirmed_plan_digest=self.plan)
        return reserve_generation(**(args | changes))

    def test_reservation_at_final_path_is_not_runtime_readiness(self):
        target = self.reserve()
        record = json.loads((target / "reservation.json").read_text())
        self.assertEqual(record["state"], "reserved")
        self.assertIs(record["runtime_ready"], False)
        self.assertNotIn(str(self.base), json.dumps(record))
        self.assertEqual(list(self.project.iterdir()), [])
        self.assertEqual((self.legacy / "sentinel").read_bytes(), b"legacy runtime remains unchanged")
        self.assertEqual(target.stat().st_mode & 0o777, 0o700)
        self.assertEqual((target / "reservation.json").stat().st_mode & 0o777, 0o600)

    def test_two_projects_have_separate_generations(self):
        other = self.base / "second-project"
        other.mkdir(mode=0o700)
        first = self.reserve()
        original = (first / "reservation.json").read_bytes()
        second = self.reserve(project=other, identity=self.identity(other))
        self.assertNotEqual(first.parent, second.parent)
        self.assertEqual((first / "reservation.json").read_bytes(), original)

    def test_copied_identity_and_missing_plan_refuse_before_writes(self):
        other = self.base / "second-project"
        other.mkdir(mode=0o700)
        for changes in ({"identity": self.identity(other)}, {"confirmed_plan_digest": None}):
            with self.assertRaises(ProjectRuntimeError):
                self.reserve(**changes)
            self.assertEqual(list(self.namespace.iterdir()), [])

    def test_symlinked_namespace_and_project_ancestor_are_rejected(self):
        alias = self.base / "alias"
        alias.symlink_to(self.base, target_is_directory=True)
        for changes in ({"namespace": alias / "project-runtimes"}, {"project": alias / "project"}):
            with self.assertRaises(ProjectRuntimeError):
                self.reserve(**changes)
        self.assertEqual(list(self.namespace.iterdir()), [])

    def test_shared_writable_or_in_project_namespace_is_rejected(self):
        self.namespace.chmod(0o777)
        with self.assertRaises(ProjectRuntimeError):
            self.reserve()
        inside = self.project / "project-runtimes"
        inside.mkdir(mode=0o700)
        with self.assertRaises(ProjectRuntimeError):
            self.reserve(namespace=inside)
        self.assertEqual(list(inside.iterdir()), [])

    def test_existing_generation_is_never_overwritten(self):
        target = self.reserve()
        before = (target / "reservation.json").read_bytes()
        with self.assertRaisesRegex(ProjectRuntimeError, "GENERATION_EXISTS"):
            self.reserve()
        self.assertEqual((target / "reservation.json").read_bytes(), before)

    def test_legacy_namespace_is_rejected(self):
        with self.assertRaisesRegex(ProjectRuntimeError, "NAMESPACE_INVALID"):
            self.reserve(namespace=self.legacy)
        self.assertEqual(sorted(p.name for p in self.legacy.iterdir()), ["sentinel"])

    def test_unknown_project_directory_and_foreign_marker_are_not_adopted(self):
        key = self.identity()["project_key"][7:]
        folder = self.namespace / key
        folder.mkdir(mode=0o700)
        for content in (None, b"foreign marker"):
            if content is not None:
                (folder / "owner.json").write_bytes(content)
                (folder / "owner.json").chmod(0o600)
            before = sorted(p.name for p in folder.iterdir())
            with self.assertRaises(ProjectRuntimeError):
                self.reserve()
            self.assertEqual(sorted(p.name for p in folder.iterdir()), before)

    def test_lock_contention_refuses_without_wait_or_changes(self):
        fd = os.open(self.namespace, os.O_RDONLY | os.O_DIRECTORY)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            with self.assertRaisesRegex(ProjectRuntimeError, "BUSY"):
                self.reserve()
            self.assertEqual(list(self.namespace.iterdir()), [])
        finally:
            os.close(fd)

    def test_write_failure_never_reports_ready_or_reuses_unknown_state(self):
        with mock.patch("sos.platforms.project_runtime_posix.os.write", side_effect=OSError("synthetic disk full")):
            with self.assertRaisesRegex(ProjectRuntimeError, "RESERVATION_FAILED"):
                self.reserve()
        with self.assertRaises(ProjectRuntimeError):
            self.reserve()
        self.assertEqual(list(self.project.iterdir()), [])
        self.assertEqual((self.legacy / "sentinel").read_bytes(), b"legacy runtime remains unchanged")

    def test_payload_digest_mismatch_executes_nothing(self):
        uv = self.base / "uv"
        uv.write_bytes(b"synthetic")
        with mock.patch("sos.platforms.project_runtime_posix.subprocess.run") as run:
            with self.assertRaises(ProjectRuntimeError):
                install_reserved_wheel(
                    self.namespace, self.project, self.identity(), repository_digest=self.repo,
                    confirmed_plan_digest=self.plan, uv=uv, uv_sha256="0" * 64,
                    wheel=uv, wheelhouse=self.base,
                )
            run.assert_not_called()
        self.assertEqual(list(self.namespace.iterdir()), [])

    def test_payload_failure_is_retained_and_no_retry_or_shared_environment(self):
        uv = self.base / "uv"
        wheel = self.base / "synthetic.whl"
        uv.write_bytes(b"synthetic uv")
        wheel.write_bytes(b"synthetic wheel")
        old = self.identity()
        identity = runtime_identity(
            **observe_project(self.project, self.repo),
            maintenance_binding=old["maintenance_binding"],
            wheel_digest="sha256:" + hashlib.sha256(wheel.read_bytes()).hexdigest(),
            interpreter_digest=old["interpreter_digest"],
        )
        target = self.reserve(identity=identity)
        args = dict(repository_digest=self.repo, confirmed_plan_digest=self.plan,
                    uv=uv, uv_sha256=hashlib.sha256(uv.read_bytes()).hexdigest(),
                    wheel=wheel, wheelhouse=self.base)
        with mock.patch("sos.platforms.project_runtime_posix.subprocess.run",
                        return_value=mock.Mock(returncode=1)) as run:
            with self.assertRaises(ProjectRuntimeError):
                install_reserved_wheel(self.namespace, self.project, identity, **args)
            self.assertEqual(run.call_count, 1)
            call = run.call_args
            self.assertIn("--offline", call.args[0])
            self.assertEqual(call.kwargs["env"]["UV_TOOL_DIR"], str(target / "tools"))
            self.assertEqual(call.kwargs["env"]["UV_PYTHON_INSTALL_DIR"], str(target / "python"))
            with self.assertRaises(ProjectRuntimeError):
                install_reserved_wheel(self.namespace, self.project, identity, **args)
            self.assertEqual(run.call_count, 1)
        self.assertTrue((target / "payload-attempt.json").exists())
        self.assertFalse((target / "payload-installed.json").exists())
        self.assertEqual(list(self.project.iterdir()), [])
        self.assertEqual((self.legacy / "sentinel").read_bytes(), b"legacy runtime remains unchanged")
