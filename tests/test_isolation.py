from __future__ import annotations

import os
import subprocess
import tempfile
import unittest
from contextlib import redirect_stdout
from io import StringIO
from pathlib import Path

from sos.checks import discover_checks, qualify_supported
from sos.cli import main as cli_main
from sos.isolation import run_isolated_unittest
from sos.workspace import initialize_workspace, qualify_once


def git(root: Path, *args: str) -> None:
    subprocess.run(["git", "-C", str(root), *args], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)


class IsolatedQualificationTests(unittest.TestCase):
    def make_project(self, test_source: str) -> tuple[tempfile.TemporaryDirectory[str], Path]:
        temporary = tempfile.TemporaryDirectory()
        root = Path(temporary.name)
        git(root, "init", "-q")
        git(root, "config", "user.name", "Synthetic Operator")
        git(root, "config", "user.email", "synthetic@example.invalid")
        (root / "README.md").write_text("Synthetic isolated project.\n", encoding="utf-8")
        (root / "pyproject.toml").write_text(
            "[build-system]\nrequires = []\nbuild-backend = 'synthetic.backend'\n",
            encoding="utf-8",
        )
        (root / "tests").mkdir()
        (root / "tests" / "test_profile.py").write_text(test_source, encoding="utf-8")
        git(root, "add", ".")
        git(root, "commit", "-qm", "synthetic isolated fixture")
        return temporary, root

    def test_profile_denies_network_process_canonical_source_and_inherited_env(self) -> None:
        source_template = '''
import os
import socket
import subprocess
import unittest
from pathlib import Path

CANONICAL = Path({canonical!r})

class IsolationContract(unittest.TestCase):
    def test_canonical_source_is_not_visible(self):
        with self.assertRaises(PermissionError):
            (CANONICAL / "README.md").read_text()
        with self.assertRaises(PermissionError):
            (CANONICAL / "escape.tmp").write_text("blocked")

    def test_network_is_denied(self):
        with self.assertRaises(PermissionError):
            socket.socket()

    def test_process_creation_is_denied(self):
        with self.assertRaises(PermissionError):
            subprocess.run(["/bin/true"], check=True)

    def test_environment_is_closed(self):
        self.assertIsNone(os.environ.get("SYNTHETIC_PRIVATE_VALUE"))

    def test_disposable_write_is_local(self):
        Path("generated.tmp").write_text("synthetic")
        self.assertTrue(Path("generated.tmp").is_file())

    def test_source_snapshot_is_read_only(self):
        with self.assertRaises(PermissionError):
            Path(__file__).write_text("blocked")
'''
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        canonical = Path(temporary.name) / "canonical"
        canonical.mkdir()
        fixture, root = self.make_project(source_template.format(canonical=str(canonical)))
        self.addCleanup(fixture.cleanup)
        (canonical / "README.md").write_text("Synthetic canonical marker.\n", encoding="utf-8")
        before = (root / "README.md").read_bytes()
        os.environ["SYNTHETIC_PRIVATE_VALUE"] = "must-not-cross"
        try:
            plan = discover_checks(str(root))
            family = next(item for item in plan.families if item.family_id == "python.stdlib-unittest")
            self.assertEqual(family.status, "configured")
            receipt = qualify_supported(str(root), family_id="python.stdlib-unittest")
        finally:
            os.environ.pop("SYNTHETIC_PRIVATE_VALUE", None)
        self.assertEqual(receipt.status, "passed_local")
        self.assertEqual(receipt.isolation, "linux-landlock-seccomp-snapshot-v1")
        self.assertEqual(receipt.exit_code, 0)
        self.assertFalse(receipt.raw_output_serialized)
        self.assertEqual((root / "README.md").read_bytes(), before)
        self.assertFalse((root / "generated.tmp").exists())

    def test_check_discovery_never_executes_project_code(self) -> None:
        fixture, root = self.make_project(
            "from pathlib import Path\n"
            "Path('discovery-executed.tmp').write_text('bad')\n"
            "import unittest\n\nclass Pass(unittest.TestCase):\n"
            "    def test_pass(self):\n        self.assertTrue(True)\n"
        )
        self.addCleanup(fixture.cleanup)
        plan = discover_checks(str(root))
        self.assertEqual(plan.families[1].status, "configured")
        self.assertFalse((root / "discovery-executed.tmp").exists())

    def test_project_failure_never_becomes_green(self) -> None:
        fixture, root = self.make_project(
            "import unittest\n\nclass Failure(unittest.TestCase):\n"
            "    def test_failure(self):\n        self.assertEqual(1, 2)\n"
        )
        self.addCleanup(fixture.cleanup)
        receipt = qualify_supported(str(root), family_id="python.stdlib-unittest")
        self.assertEqual(receipt.status, "failed")
        self.assertEqual(receipt.reasons, ("SOS_QUALIFICATION_FAILED",))
        self.assertNotEqual(receipt.exit_code, 0)

    def test_skipped_and_empty_suites_never_become_green(self) -> None:
        fixtures = (
            (
                "import unittest\n\nclass Skipped(unittest.TestCase):\n"
                "    @unittest.skip('synthetic')\n"
                "    def test_skip(self):\n        pass\n",
                "skipped",
                ("SOS_QUALIFICATION_SKIPPED",),
            ),
            ("import unittest\n", "not_verified", ("SOS_QUALIFICATION_NO_TESTS",)),
        )
        for source, expected_status, expected_reasons in fixtures:
            with self.subTest(status=expected_status):
                fixture, root = self.make_project(source)
                try:
                    receipt = qualify_supported(str(root), family_id="python.stdlib-unittest")
                    self.assertEqual(receipt.status, expected_status)
                    self.assertEqual(receipt.reasons, expected_reasons)
                finally:
                    fixture.cleanup()

    def test_execution_receipt_does_not_mutate_accepted_p101_records(self) -> None:
        fixture, root = self.make_project(
            "import unittest\n\nclass Pass(unittest.TestCase):\n"
            "    def test_pass(self):\n        self.assertTrue(True)\n"
        )
        self.addCleanup(fixture.cleanup)
        self.assertEqual(
            initialize_workspace(str(root), confirmed=True, controlling_tty_observed=True).status,
            "success",
        )
        record_root = root / ".sigma" / "records"
        before = {path.name: path.read_bytes() for path in record_root.glob("*.json")}
        _, _, receipt = qualify_once(
            str(root), family_id="python.stdlib-unittest", confirmed=True
        )
        self.assertEqual(receipt["status"], "passed_local")
        after = {path.name: path.read_bytes() for path in record_root.glob("*.json")}
        self.assertEqual(after, before)

    def test_timeout_kills_the_complete_single_process_group(self) -> None:
        fixture, root = self.make_project(
            "import unittest\n\nclass Timeout(unittest.TestCase):\n"
            "    def test_timeout(self):\n        while True:\n            pass\n"
        )
        self.addCleanup(fixture.cleanup)
        plan = discover_checks(str(root))
        tracked = tuple(
            item.decode("utf-8")
            for item in subprocess.run(
                ["git", "-C", str(root), "ls-files", "-z"],
                check=True,
                stdout=subprocess.PIPE,
            ).stdout.split(b"\0")
            if item
        )
        result = run_isolated_unittest(root, tracked, timeout_seconds=1)
        self.assertEqual(plan.families[1].status, "configured")
        self.assertEqual(result.status, "failed")
        self.assertEqual(result.reasons, ("SOS_QUALIFICATION_TIMEOUT",))

    def test_output_limit_is_typed_and_never_green(self) -> None:
        fixture, root = self.make_project(
            "import unittest\n\nclass Output(unittest.TestCase):\n"
            "    def test_output(self):\n        print('x' * (1024 * 1024 + 1))\n"
        )
        self.addCleanup(fixture.cleanup)
        receipt = qualify_supported(str(root), family_id="python.stdlib-unittest")
        self.assertEqual(receipt.status, "failed")
        self.assertEqual(receipt.reasons, ("SOS_QUALIFICATION_OUTPUT_LIMIT_EXCEEDED",))
        self.assertFalse(receipt.raw_output_serialized)

    def test_writable_budget_is_typed_and_never_green(self) -> None:
        fixture, root = self.make_project(
            "import unittest\nfrom pathlib import Path\n\nclass WritableLimit(unittest.TestCase):\n"
            "    def test_writable_limit(self):\n"
            "        payload = b'x' * (1024 * 1024)\n"
            "        for index in range(18):\n"
            "            Path(f'generated-{index}.bin').write_bytes(payload)\n"
        )
        self.addCleanup(fixture.cleanup)
        receipt = qualify_supported(str(root), family_id="python.stdlib-unittest")
        self.assertEqual(receipt.status, "failed")
        self.assertEqual(receipt.reasons, ("SOS_QUALIFICATION_WRITABLE_LIMIT_EXCEEDED",))
        self.assertFalse(receipt.raw_output_serialized)

    def test_protected_tracked_path_blocks_before_project_execution(self) -> None:
        fixture, root = self.make_project(
            "import unittest\n\nclass Pass(unittest.TestCase):\n"
            "    def test_pass(self):\n        self.assertTrue(True)\n"
        )
        self.addCleanup(fixture.cleanup)
        (root / ".env").write_text("SYNTHETIC_PRIVATE_VALUE=must-not-copy\n", encoding="utf-8")
        git(root, "add", ".env")
        git(root, "commit", "-qm", "add synthetic protected path")
        receipt = qualify_supported(str(root), family_id="python.stdlib-unittest")
        self.assertEqual(receipt.status, "blocked")
        self.assertEqual(receipt.reasons, ("SOS_QUALIFICATION_PROTECTED_PATH_PRESENT",))
        self.assertIsNone(receipt.output_digest)

    def test_tracked_symlink_is_blocked_before_project_execution(self) -> None:
        fixture, root = self.make_project(
            "import unittest\n\nclass Pass(unittest.TestCase):\n"
            "    def test_pass(self):\n        self.assertTrue(True)\n"
        )
        self.addCleanup(fixture.cleanup)
        (root / "linked.py").symlink_to("README.md")
        git(root, "add", "linked.py")
        git(root, "commit", "-qm", "add synthetic symlink")
        receipt = qualify_supported(str(root), family_id="python.stdlib-unittest")
        self.assertEqual(receipt.status, "blocked")
        self.assertEqual(receipt.reasons, ("SOS_TRACKED_FILE_TYPE_UNSUPPORTED",))
        self.assertIsNone(receipt.output_digest)

    def test_cli_runs_only_the_exact_selected_family_and_stores_no_raw_output(self) -> None:
        fixture, root = self.make_project(
            "import unittest\n\nclass Pass(unittest.TestCase):\n"
            "    def test_pass(self):\n"
            "        print('SYNTHETIC_OUTPUT_MUST_NOT_BE_SERIALIZED')\n"
            "        self.assertTrue(True)\n"
        )
        self.addCleanup(fixture.cleanup)
        self.assertEqual(
            initialize_workspace(str(root), confirmed=True, controlling_tty_observed=True).status,
            "success",
        )
        output = StringIO()
        with redirect_stdout(output):
            exit_code = cli_main(
                ["qualify", str(root), "--family", "python.stdlib-unittest", "--yes", "--json"]
            )
        self.assertEqual(exit_code, 0)
        serialized = output.getvalue()
        self.assertIn('"family_id":"python.stdlib-unittest"', serialized)
        self.assertIn('"status":"passed_local"', serialized)
        self.assertNotIn("SYNTHETIC_OUTPUT_MUST_NOT_BE_SERIALIZED", serialized)

    def test_cli_preserves_typed_stale_source_instead_of_masking_it(self) -> None:
        fixture, root = self.make_project(
            "import unittest\n\nclass Pass(unittest.TestCase):\n"
            "    def test_pass(self):\n        self.assertTrue(True)\n"
        )
        self.addCleanup(fixture.cleanup)
        self.assertEqual(
            initialize_workspace(str(root), confirmed=True, controlling_tty_observed=True).status,
            "success",
        )
        (root / "README.md").write_text("Synthetic dirty source.\n", encoding="utf-8")
        output = StringIO()
        with redirect_stdout(output):
            exit_code = cli_main(
                ["qualify", str(root), "--family", "python.stdlib-unittest", "--yes", "--json"]
            )
        self.assertEqual(exit_code, 2)
        self.assertIn('"status":"stale"', output.getvalue())
        self.assertIn("SOS_QUALIFICATION_STALE", output.getvalue())
        self.assertFalse((root / ".sigma" / "views" / "qualification.json").exists())

    def test_unknown_family_fails_closed(self) -> None:
        fixture, root = self.make_project(
            "import unittest\n\nclass Pass(unittest.TestCase):\n"
            "    def test_pass(self):\n        self.assertTrue(True)\n"
        )
        self.addCleanup(fixture.cleanup)
        with self.assertRaisesRegex(RuntimeError, "SOS_CHECK_FAMILY_UNKNOWN"):
            qualify_supported(str(root), family_id="synthetic.unknown")


if __name__ == "__main__":
    unittest.main()
