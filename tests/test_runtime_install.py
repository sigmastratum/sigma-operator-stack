"""Fresh isolated-runtime planning and confirmation regressions."""

import hashlib
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from sos.maintenance_binding import MaintenanceLauncherBinding
from sos.result import Status, TerminalResult
from sos.runtime_install import prepare_native_install, execute_native_install, recover_native_install
from sos.contracts import digest_value
from sos.platforms.project_runtime_posix import prepare_runtime_namespace
from sos.platforms.runtime_install_intent import read_install_intent, write_install_intent, install_intent_lock
from sos.project_runtime import ProjectRuntimeError
import test_p106_lifecycle as lifecycle_fixtures


class NativeRuntimeInstallTests(unittest.TestCase):
    def test_malformed_recovery_intent_is_typed_and_read_only(self):
        plan = self.make_plan()
        prepare_runtime_namespace(plan.namespace)
        original = {"contract": "sos_native_install_intent_v1", "plan": plan.payload,
                    "confirmation_seed": "a"*64, "primary_authority_id": None,
                    "client": "codex", "state": "preparing"}
        for identity in (None, [], {}, {"repository_digest": []}):
            with self.subTest(identity=identity):
                material = {**plan.payload, "identity": identity}
                material["plan_digest"] = digest_value({k:v for k,v in material.items() if k != "plan_digest"})
                intent = {**original, "plan": material}
                with install_intent_lock(plan.namespace, plan.root):
                    write_install_intent(plan.namespace, plan.root, intent)
                with self.assertRaisesRegex(ProjectRuntimeError, "INSTALL_INTENT_INVALID"):
                    recover_native_install(plan.root, namespace=plan.namespace,
                        maintenance_binding=plan.maintenance_binding.payload(), uv=plan.uv,
                        uv_sha256=plan.payload["uv_sha256"], wheel=plan.wheel, wheels=plan.wheels,
                        controller_command=plan.controller_command, interpreter_digest=plan.interpreter_digest)
                self.assertEqual(read_install_intent(plan.namespace, plan.root), intent)
                self.assertFalse((plan.root / ".sigma").exists())

    def make_plan(self):
        fixture = lifecycle_fixtures.P106LifecycleTests()
        temporary, root = fixture.make_project(agents=None, config=None)
        self.addCleanup(temporary.cleanup)
        payload = tempfile.TemporaryDirectory()
        self.addCleanup(payload.cleanup)
        bundle = Path(payload.name)
        uv = bundle / "uv"; uv.write_bytes(b"uv")
        wheel = bundle / "sigma_operator_stack-0.1.0a7-py3-none-any.whl"
        wheel.write_bytes(b"wheel")
        wheels = ((wheel, hashlib.sha256(b"wheel").hexdigest()),)
        release = MaintenanceLauncherBinding("0.1.0a7", "v0.1.0a7", "1"*40, "2"*40,
            "SOS-Linux-0.1.0a7.zip", "3"*64, "4"*64, "linux", "x86_64",
            "linux-alpha", "Install-SOS.command", "5"*64)
        executable = Path(sys.executable).resolve()
        digest = "sha256:" + hashlib.sha256(executable.read_bytes()).hexdigest()
        namespace = bundle / "project-runtimes"
        plan = prepare_native_install(root, namespace=namespace,
            maintenance_binding=release.payload(), uv=uv,
            uv_sha256=hashlib.sha256(b"uv").hexdigest(), wheel=wheel, wheels=wheels,
            controller_command=str(executable), interpreter_digest=digest,
            confirmation_seed="a"*64)
        return plan

    def test_two_pass_plan_is_stable_and_refusal_does_not_provision(self):
        plan = self.make_plan()
        namespace = plan.namespace
        self.assertEqual(plan.bootstrap.confirmation_seed, "a"*64)
        self.assertEqual(execute_native_install(plan).status, Status.OWNER_REQUIRED)
        self.assertFalse(namespace.exists())
        success = TerminalResult("synthetic", Status.SUCCESS, (), {})
        with patch("sos.runtime_install.prepare_runtime_namespace", wraps=prepare_runtime_namespace) as prepare, \
             patch("sos.runtime_install.reserve_generation"), \
             patch("sos.runtime_install.install_reserved_wheel"), \
             patch("sos.runtime_install.observe_verified_generation_launcher"), \
             patch("sos.runtime_install.execute_one_command_init", return_value=success), \
             patch("sos.runtime_install.publish_installed_runtime") as publish:
            result = execute_native_install(plan,
                confirmed_plan_digest=plan.payload["plan_digest"],
                controlling_tty_observed=True)
        self.assertEqual(result.status, Status.SUCCESS)
        prepare.assert_called_once_with(namespace)
        publish.assert_called_once()
        self.assertEqual(read_install_intent(namespace, plan.root)["state"], "committed")

    def test_provisioning_crash_retains_exact_intent_and_normal_retry_refuses(self):
        plan = self.make_plan()
        with patch("sos.runtime_install.reserve_generation", side_effect=RuntimeError("synthetic crash")):
            with self.assertRaisesRegex(RuntimeError, "synthetic crash"):
                execute_native_install(plan, confirmed_plan_digest=plan.payload["plan_digest"],
                                       controlling_tty_observed=True)
        intent = read_install_intent(plan.namespace, plan.root)
        self.assertEqual(intent["state"], "preparing")
        self.assertEqual(intent["plan"], plan.payload)
        self.assertFalse((plan.root / ".sigma").exists())
        with self.assertRaisesRegex(ProjectRuntimeError, "RECOVERY_REQUIRED"):
            execute_native_install(plan, confirmed_plan_digest=plan.payload["plan_digest"],
                                   controlling_tty_observed=True)

    def test_intent_lock_is_exclusive_and_symlink_is_rejected(self):
        plan = self.make_plan()
        prepare_runtime_namespace(plan.namespace)
        with install_intent_lock(plan.namespace, plan.root):
            with self.assertRaisesRegex(ProjectRuntimeError, "BUSY"):
                with install_intent_lock(plan.namespace, plan.root):
                    self.fail("second writer admitted")
            write_install_intent(plan.namespace, plan.root, {"synthetic": True})
        path = next((plan.namespace / "install-intents").glob("*.json"))
        path.unlink()
        path.symlink_to(plan.wheel)
        with self.assertRaises((OSError, ProjectRuntimeError)):
            read_install_intent(plan.namespace, plan.root)


if __name__ == "__main__":
    unittest.main()
