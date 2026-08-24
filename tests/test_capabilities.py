from __future__ import annotations

import json
import os
import subprocess
import tempfile
import unittest
from contextlib import redirect_stdout
from io import StringIO
from pathlib import Path
from unittest.mock import patch

from sos import _isolation_worker
from sos.agent_api import project_tool
from sos.capabilities import (
    LANDLOCK_ABI_TOO_OLD,
    LANDLOCK_SYSCALL_UNAVAILABLE,
    NO_NEW_PRIVS_UNAVAILABLE,
    PLATFORM_UNSUPPORTED,
    PROFILE_AVAILABLE,
    SECCOMP_FILTER_UNAVAILABLE,
    CapabilityComponent,
    _run_component,
    _seal_report,
    clear_capability_cache,
    probe_isolation_capabilities,
)
from sos.checks import discover_checks
from sos.cli import main as cli_main
from sos.isolation import IsolatedRun, _capability_failure_reason
from sos.workspace import doctor_workspace, initialize_workspace, qualify_once, workspace_status


def git(root: Path, *args: str) -> None:
    subprocess.run(
        ["git", "-C", str(root), *args],
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )


def component(
    status: str = "supported",
    *,
    reason: str | None = None,
    observed_abi: int | None = None,
) -> dict[str, object]:
    return {"status": status, "reason": reason, "observed_abi": observed_abi}


class IsolationCapabilityTests(unittest.TestCase):
    def tearDown(self) -> None:
        clear_capability_cache()

    def report(self, results: dict[str, dict[str, object]]):
        with (
            patch("sos.capabilities.platform.system", return_value="Linux"),
            patch("sos.capabilities.platform.machine", return_value="x86_64"),
            patch("sos.capabilities.platform.release", return_value="6.8.0-synthetic"),
            patch("sos.capabilities._run_component", side_effect=lambda name: results[name]),
        ):
            clear_capability_cache()
            return probe_isolation_capabilities()

    def test_supported_report_is_deterministic_and_content_safe(self) -> None:
        results = {
            "landlock": component(observed_abi=4),
            "no_new_privs": component(),
            "seccomp": component(),
        }
        os.environ["SYNTHETIC_PRIVATE_VALUE"] = "must-not-cross"
        try:
            first = self.report(results)
            clear_capability_cache()
            second = self.report(results)
        finally:
            os.environ.pop("SYNTHETIC_PRIVATE_VALUE", None)
        self.assertEqual(first, second)
        self.assertEqual(first.status, "supported")
        self.assertEqual(first.reasons, (PROFILE_AVAILABLE,))
        self.assertEqual(first.landlock.observed_abi, 4)
        serialized = json.dumps(first.to_dict(), sort_keys=True)
        self.assertNotIn("must-not-cross", serialized)
        self.assertNotIn(str(Path.cwd()), serialized)

    def test_failure_matrix_and_reason_precedence(self) -> None:
        fixtures = (
            (
                {
                    "landlock": component("unsupported", reason=LANDLOCK_SYSCALL_UNAVAILABLE),
                    "no_new_privs": component(),
                    "seccomp": component(),
                },
                (LANDLOCK_SYSCALL_UNAVAILABLE,),
            ),
            (
                {
                    "landlock": component(
                        "unsupported", reason=LANDLOCK_ABI_TOO_OLD, observed_abi=2
                    ),
                    "no_new_privs": component(),
                    "seccomp": component(),
                },
                (LANDLOCK_ABI_TOO_OLD,),
            ),
            (
                {
                    "landlock": component(observed_abi=4),
                    "no_new_privs": component("unsupported", reason=NO_NEW_PRIVS_UNAVAILABLE),
                    "seccomp": component("unsupported", reason=SECCOMP_FILTER_UNAVAILABLE),
                },
                (NO_NEW_PRIVS_UNAVAILABLE, SECCOMP_FILTER_UNAVAILABLE),
            ),
        )
        for results, expected in fixtures:
            with self.subTest(reasons=expected):
                report = self.report(results)
                self.assertEqual(report.status, "unsupported")
                self.assertEqual(report.reasons, expected)

    def test_platform_failure_runs_no_component_probe(self) -> None:
        with (
            patch("sos.capabilities.platform.system", return_value="Windows"),
            patch("sos.capabilities.platform.machine", return_value="AMD64"),
            patch("sos.capabilities.platform.release", return_value="synthetic"),
            patch("sos.capabilities._run_component") as runner,
        ):
            report = probe_isolation_capabilities()
        runner.assert_not_called()
        self.assertEqual(report.status, "unsupported")
        self.assertEqual(report.reasons, (PLATFORM_UNSUPPORTED,))

    def test_component_child_has_fixed_argv_closed_environment_and_bounded_contract(self) -> None:
        payload = {
            "component": "landlock",
            "status": "supported",
            "reason": None,
            "observed_abi": 4,
        }
        completed = subprocess.CompletedProcess(
            args=[],
            returncode=0,
            stdout=b"SOS_CAPABILITY_COMPONENT="
            + json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
            + b"\n",
            stderr=b"",
        )
        os.environ["SYNTHETIC_PRIVATE_VALUE"] = "must-not-cross"
        try:
            with patch("sos.capabilities.subprocess.run", return_value=completed) as runner:
                result = _run_component("landlock")
        finally:
            os.environ.pop("SYNTHETIC_PRIVATE_VALUE", None)
        self.assertEqual(result, component(observed_abi=4))
        args, kwargs = runner.call_args
        self.assertEqual(args[0][1], "-I")
        self.assertEqual(args[0][-2:], ["--probe", "landlock"])
        self.assertIs(kwargs["stdin"], subprocess.DEVNULL)
        self.assertFalse(kwargs["shell"])
        self.assertEqual(
            set(kwargs["env"]),
            {"HOME", "LANG", "LC_ALL", "PATH", "PYTHONDONTWRITEBYTECODE", "PYTHONHASHSEED"},
        )
        self.assertNotIn("SYNTHETIC_PRIVATE_VALUE", kwargs["env"])

    def test_cli_exit_and_json_match_report(self) -> None:
        supported = _seal_report(
            system="linux",
            architecture="x86_64",
            kernel_release="6.8.0-synthetic",
            landlock=CapabilityComponent("supported", 4),
            no_new_privs=CapabilityComponent("supported"),
            seccomp=CapabilityComponent("supported"),
            failures=[],
        )
        unsupported = _seal_report(
            system="linux",
            architecture="x86_64",
            kernel_release="5.15.0-synthetic",
            landlock=CapabilityComponent("unsupported", 1),
            no_new_privs=CapabilityComponent("supported"),
            seccomp=CapabilityComponent("supported"),
            failures=[LANDLOCK_ABI_TOO_OLD],
        )
        for report, expected_exit in ((supported, 0), (unsupported, 2)):
            with self.subTest(status=report.status):
                output = StringIO()
                with patch("sos.cli.probe_isolation_capabilities", return_value=report), redirect_stdout(output):
                    observed_exit = cli_main(["capabilities", "--json"])
                self.assertEqual(observed_exit, expected_exit)
                self.assertEqual(json.loads(output.getvalue()), report.to_dict())

    def test_check_uses_same_unsupported_decision_without_project_execution(self) -> None:
        temporary, root = self.make_project()
        self.addCleanup(temporary.cleanup)
        marker = root / "project-executed.tmp"
        (root / "tests" / "test_profile.py").write_text(
            "from pathlib import Path\nPath('project-executed.tmp').write_text('bad')\n",
            encoding="utf-8",
        )
        git(root, "add", ".")
        git(root, "commit", "-qm", "synthetic hostile discovery")
        report = _seal_report(
            system="linux",
            architecture="x86_64",
            kernel_release="5.15.0-synthetic",
            landlock=CapabilityComponent("unsupported", 1),
            no_new_privs=CapabilityComponent("supported"),
            seccomp=CapabilityComponent("supported"),
            failures=[LANDLOCK_ABI_TOO_OLD],
        )
        with patch("sos.checks.probe_isolation_capabilities", return_value=report):
            plan = discover_checks(str(root))
        family = plan.families[1]
        self.assertEqual(family.status, "unsupported")
        self.assertEqual(family.reasons, (LANDLOCK_ABI_TOO_OLD,))
        self.assertFalse(marker.exists())

    def test_worker_component_and_parent_reason_are_exact(self) -> None:
        output = StringIO()
        with (
            patch("sos._isolation_worker.platform.system", return_value="Linux"),
            patch("sos._isolation_worker.platform.machine", return_value="x86_64"),
            patch("sos._isolation_worker._query_landlock_abi", return_value=2),
            redirect_stdout(output),
        ):
            exit_code = _isolation_worker._probe_component("landlock")
        self.assertEqual(exit_code, 78)
        payload = json.loads(output.getvalue().removeprefix("SOS_CAPABILITY_COMPONENT="))
        self.assertEqual(payload["reason"], LANDLOCK_ABI_TOO_OLD)
        self.assertEqual(
            _capability_failure_reason({"reason": LANDLOCK_ABI_TOO_OLD}),
            LANDLOCK_ABI_TOO_OLD,
        )
        self.assertEqual(
            _capability_failure_reason({"reason": "foreign"}),
            "SOS_ISOLATION_PROFILE_UNAVAILABLE",
        )

    def test_landlock_ruleset_failure_is_not_misreported_as_abi_support(self) -> None:
        output = StringIO()
        with (
            patch("sos._isolation_worker.platform.system", return_value="Linux"),
            patch("sos._isolation_worker.platform.machine", return_value="x86_64"),
            patch("sos._isolation_worker._query_landlock_abi", return_value=4),
            patch(
                "sos._isolation_worker._probe_landlock_ruleset",
                side_effect=_isolation_worker._CapabilityUnavailable(
                    LANDLOCK_SYSCALL_UNAVAILABLE
                ),
            ),
            redirect_stdout(output),
        ):
            exit_code = _isolation_worker._probe_component("landlock")
        self.assertEqual(exit_code, 78)
        payload = json.loads(output.getvalue().removeprefix("SOS_CAPABILITY_COMPONENT="))
        self.assertEqual(payload["observed_abi"], 4)
        self.assertEqual(payload["reason"], LANDLOCK_SYSCALL_UNAVAILABLE)

    def test_unsupported_receipt_keeps_integrity_surfaces_valid(self) -> None:
        temporary, root = self.make_project()
        self.addCleanup(temporary.cleanup)
        self.assertEqual(
            initialize_workspace(str(root), confirmed=True, controlling_tty_observed=True).status,
            "success",
        )
        unsupported = IsolatedRun(
            status="unsupported",
            reasons=(LANDLOCK_ABI_TOO_OLD,),
            exit_code=78,
            output_digest="sha256:" + "a" * 64,
            output_bytes=0,
            tests_run=0,
            failures=0,
            errors=0,
            skipped=0,
        )
        with patch("sos.checks._run_admitted_isolated_unittest", return_value=unsupported):
            _plan, _admission, receipt = qualify_once(
                str(root), family_id="python.stdlib-unittest", confirmed=True
            )
        self.assertEqual(receipt["status"], "unsupported")
        self.assertEqual(receipt["reasons"], [LANDLOCK_ABI_TOO_OLD])
        self.assertEqual(receipt["exit_code"], 78)
        status = workspace_status(str(root))
        self.assertEqual(status.status.value, "success")
        self.assertEqual(status.details["qualification_integrity"], "valid")
        doctor = doctor_workspace(str(root))
        preflight = project_tool(str(root), "sos_preflight")
        self.assertNotEqual(doctor.status.value, "invalid")
        self.assertNotEqual(preflight.status.value, "invalid")

    def make_project(self) -> tuple[tempfile.TemporaryDirectory[str], Path]:
        temporary = tempfile.TemporaryDirectory()
        root = Path(temporary.name)
        git(root, "init", "-q")
        git(root, "config", "user.name", "Synthetic Operator")
        git(root, "config", "user.email", "synthetic@example.invalid")
        (root / "README.md").write_text("Synthetic capability project.\n", encoding="utf-8")
        (root / "pyproject.toml").write_text(
            "[build-system]\nrequires = []\nbuild-backend = 'synthetic.backend'\n",
            encoding="utf-8",
        )
        (root / "tests").mkdir()
        (root / "tests" / "test_profile.py").write_text(
            "import unittest\n\nclass Pass(unittest.TestCase):\n"
            "    def test_pass(self):\n        self.assertTrue(True)\n",
            encoding="utf-8",
        )
        git(root, "add", ".")
        git(root, "commit", "-qm", "synthetic capability fixture")
        return temporary, root


if __name__ == "__main__":
    unittest.main()
