"""Short real-process regressions for human wait and owned process teardown."""

import os
import pty
import signal
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest.mock import patch

from test_native_alpha_bundles import alpha


class NativeControllerSupervisionTests(unittest.TestCase):
    def test_uncooperative_owned_process_is_force_terminated_and_reaped(self):
        source = ("import signal,time; signal.signal(signal.SIGTERM,signal.SIG_IGN); "
                  "print('ready',flush=True); time.sleep(30)")
        process = subprocess.Popen([sys.executable, "-c", source], start_new_session=True,
                                   stdout=subprocess.PIPE, text=True)
        try:
            self.assertEqual(process.stdout.readline(), "ready\n")
            self.assertTrue(alpha._stop_controller_group(process, grace=0.1))
            self.assertEqual(process.returncode, -signal.SIGKILL)
            self.assertFalse(alpha._controller_group_exists(process.pid))
        finally:
            if process.poll() is None:
                os.killpg(process.pid, signal.SIGKILL)
                process.wait()
            process.stdout.close()

    def test_real_shell_background_handoff_preserves_tty_input(self):
        from test_native_alpha_bundles import ROOT
        shell = (ROOT / "installers/Install-SOS.command").read_text()
        dispatch = shell[shell.rindex("set +e\nCONTROLLER_RUNNING=1"):]
        master, slave = pty.openpty()
        thread = threading.Thread(target=lambda: (time.sleep(0.2), os.write(master, b"yes\n")))
        thread.start()
        try:
            result = subprocess.run(["/bin/sh", "-c", dispatch, "synthetic", sys.executable, "-c",
                "import sys; assert sys.stdin.isatty(); assert input() == 'yes'"],
                stdin=slave, capture_output=True, timeout=5)
            self.assertEqual(result.returncode, 0, result.stderr)
        finally:
            thread.join()
            os.close(master)
            os.close(slave)

    def test_interruption_during_spawn_retains_unregistered_child_preparation(self):
        def interrupted_spawn(*args, **kwargs):
            raise KeyboardInterrupt
        with self.assertRaises(alpha.StartError) as raised:
            alpha._supervise_controller([sys.executable], env={}, popen=interrupted_spawn)
        self.assertEqual(raised.exception.code, "SOS_ALPHA_CONTROLLER_PROCESSES_UNRESOLVED")

    def test_progress_failure_cannot_change_product_control_flow(self):
        from sos.result import report_progress
        from unittest.mock import Mock
        for error in (BrokenPipeError(), OSError(), ValueError()):
            with patch("sos.result.sys.stderr", Mock(write=Mock(side_effect=error))):
                report_progress("committed")

    def test_prepared_controller_retained_only_if_process_stop_unverified(self):
        from unittest.mock import Mock
        for unresolved in (False, True):
            with self.subTest(unresolved=unresolved), tempfile.TemporaryDirectory() as base:
                temporary = Path(base) / "controller"
                temporary.mkdir()
                names = alpha.UNIVERSAL_WHEELS | alpha.PLATFORM_WHEELS[alpha.platform.system()] | {alpha.WHEEL}
                manifest = {"artifacts": [{"filename": n, "sha256": "a"*64} for n in names]}
                with patch.object(alpha, "verify_bundle", return_value=manifest), \
                     patch.object(alpha, "_maintenance_binding"), \
                     patch.object(alpha, "_sha256", return_value="a"*64), \
                     patch.object(alpha, "_extract_controller_wheels"), \
                     patch.object(alpha, "_controller_inventory", return_value={}), \
                     patch.object(alpha.tempfile, "mkdtemp", return_value=str(temporary)):
                    code = ("SOS_ALPHA_CONTROLLER_PROCESSES_UNRESOLVED" if unresolved
                            else "SOS_ALPHA_CONTROLLER_INTERRUPTED")
                    with self.assertRaises(alpha.StartError):
                        with alpha.prepare_controller(Path(base), python=Path(sys.executable),
                                interpreter_sha256="a"*64, maintenance_handoff_json="{}",
                                runner=Mock(return_value=subprocess.CompletedProcess([], 0, "Python 3.12.14\n"))):
                            self.assertTrue(temporary.exists())
                            raise alpha._fail(code, "synthetic", "synthetic")
                self.assertEqual(temporary.exists(), unresolved)

    def test_legacy_deadline_includes_wait_for_confirmation(self):
        master, slave = pty.openpty()
        try:
            with self.assertRaises(subprocess.TimeoutExpired):
                subprocess.run([sys.executable, "-c", "input('Apply? ')"] ,
                    stdin=slave, stdout=subprocess.DEVNULL, timeout=0.1)
        finally:
            os.close(master)
            os.close(slave)

    def test_delayed_tty_confirmation_outlives_teardown_grace(self):
        master, slave = pty.openpty()
        failures = []
        def reply():
            time.sleep(0.3)
            try:
                os.write(master, b"yes\n")
            except OSError as error:
                failures.append(error)
        thread = threading.Thread(target=reply)
        thread.start()
        def popen(command, **kwargs):
            return subprocess.Popen(command, stdin=slave, stdout=subprocess.DEVNULL, **kwargs)
        try:
            result = alpha._supervise_controller([sys.executable, "-c",
                "import sys; assert sys.stdin.isatty(); assert input() == 'yes'"],
                env=dict(os.environ), popen=popen, grace=0.05)
            self.assertEqual(result.returncode, 0)
        finally:
            thread.join()
            os.close(master)
            os.close(slave)
        self.assertEqual(failures, [])

    def test_cancellation_reaps_owned_descendant_not_unrelated_process(self):
        unrelated = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(30)"])
        children = []
        source = (
            "import subprocess,sys,signal,time\n"
            "child=subprocess.Popen([sys.executable,'-c','import time; time.sleep(30)'])\n"
            "def stop(*args):\n child.wait(); sys.exit(0)\n"
            "signal.signal(signal.SIGTERM,stop)\n"
            "print('ready',flush=True)\n"
            "time.sleep(30)\n"
        )
        class InterruptingProcess:
            def __init__(self, command, **kwargs):
                self.child = subprocess.Popen(command, stdout=subprocess.PIPE, text=True, **kwargs)
                children.append(self.child)
                self.pid = self.child.pid
                self.first = True
            def wait(self):
                if self.first:
                    self.first = False
                    if self.child.stdout.readline() != "ready\n":
                        raise AssertionError("child did not start")
                    raise KeyboardInterrupt
                return self.child.wait()
            def poll(self):
                return self.child.poll()
        try:
            with self.assertRaisesRegex(alpha.StartError, "SOS_ALPHA_CONTROLLER_INTERRUPTED"):
                alpha._supervise_controller([sys.executable, "-c", source], env=dict(os.environ),
                                            popen=InterruptingProcess, grace=1)
            self.assertIsNone(unrelated.poll())
            self.assertIsNotNone(children[0].poll())
            self.assertFalse(alpha._controller_group_exists(children[0].pid))
        finally:
            unrelated.terminate()
            unrelated.wait()
            for child in children:
                if child.poll() is None:
                    os.killpg(child.pid, signal.SIGKILL)
                    child.wait()
                child.stdout.close()

    def test_unresolved_group_has_distinct_retention_result_and_restores_handlers(self):
        original = signal.getsignal(signal.SIGTERM)
        class Process:
            pid = 123
            def wait(self):
                raise KeyboardInterrupt
        with patch.object(alpha, "_stop_controller_group", return_value=False):
            with self.assertRaisesRegex(alpha.StartError, "SOS_ALPHA_CONTROLLER_PROCESSES_UNRESOLVED"):
                alpha._supervise_controller(["synthetic"], env={}, popen=lambda *a, **k: Process())
        self.assertIs(signal.getsignal(signal.SIGTERM), original)

    def test_controller_dispatch_has_no_whole_session_timeout(self):
        # Regression inspects the actual injected process call, not a text match.
        from unittest.mock import Mock
        controller = Mock(interpreter_sha256="a" * 64)
        controller.command.return_value = ["synthetic"]
        calls = []
        def runner(command, **kwargs):
            calls.append(kwargs)
            return subprocess.CompletedProcess(command, 0)
        with tempfile.TemporaryDirectory() as temporary, patch.object(alpha, "prepare_controller") as prepare:
            prepare.return_value.__enter__.return_value = controller
            alpha._run_isolated_maintenance_controller(Path(temporary), Path("project"), {},
                                                       mode="update", runner=runner)
        self.assertEqual(len(calls), 1)
        self.assertNotIn("timeout", calls[0])
