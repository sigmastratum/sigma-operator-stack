from __future__ import annotations

import contextlib
import io
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from sos import entrypoint
from sos.platform_admission import (
    FilesystemAdmissionError,
    admit_host,
    admit_project_filesystem,
)
from sos.result import Status, TerminalResult


class PlatformAdmissionTests(unittest.TestCase):
    def test_native_windows_returns_typed_linux_substrate_requirement(self) -> None:
        result = admit_host(platform_name="win32")
        self.assertEqual(result.status, Status.UNSUPPORTED)
        self.assertEqual(result.reasons, ("SOS_LINUX_SUBSTRATE_REQUIRED",))
        self.assertEqual(result.details["host_platform"], "windows")
        self.assertFalse(result.details["absolute_paths_serialized"])

    def test_unsupported_entrypoint_does_not_import_posix_implementation(self) -> None:
        script = """
import json
import sys
from unittest import mock
from sos import entrypoint
from sos.platform_admission import admit_host
assert 'sos.cli' not in sys.modules
assert 'sos.managed_files' not in sys.modules
with mock.patch.object(entrypoint, 'admit_host', return_value=admit_host(platform_name='win32')):
    code = entrypoint.main(['status', '--json'])
assert code == 2
assert 'sos.cli' not in sys.modules
assert 'sos.managed_files' not in sys.modules
"""
        completed = subprocess.run(
            [sys.executable, "-c", script],
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        self.assertEqual(
            json.loads(completed.stdout)["reasons"],
            ["SOS_LINUX_SUBSTRATE_REQUIRED"],
        )

    def test_version_is_available_without_loading_linux_implementation(self) -> None:
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            exit_code = entrypoint.main(["--version"])
        self.assertEqual(exit_code, 0)
        self.assertEqual(output.getvalue().strip(), "sos 0.1.0a1")

    def test_native_linux_filesystem_is_admitted(self) -> None:
        mountinfo = "36 25 0:32 / / rw,relatime - ext4 /dev/root rw\n"
        result = admit_project_filesystem(
            "/project", platform_name="linux", mountinfo_text=mountinfo
        )
        self.assertEqual(result.status, Status.SUCCESS)
        self.assertEqual(result.details["filesystem_type"], "ext4")

    def test_most_specific_windows_backed_mount_is_rejected(self) -> None:
        mountinfo = (
            "36 25 0:32 / / rw,relatime - ext4 /dev/root rw\n"
            "37 36 0:45 / /mnt/c rw,relatime - 9p drvfs rw\n"
        )
        result = admit_project_filesystem(
            "/mnt/c/project", platform_name="linux", mountinfo_text=mountinfo
        )
        self.assertEqual(result.status, Status.UNSUPPORTED)
        self.assertEqual(result.reasons, ("SOS_FILESYSTEM_PROFILE_UNSUPPORTED",))
        self.assertEqual(result.details["filesystem_type"], "9p")

    def test_vm_shared_and_overlay_profiles_fail_closed(self) -> None:
        for filesystem_type, expected_status in (
            ("virtiofs", Status.UNSUPPORTED),
            ("overlay", Status.UNSUPPORTED),
            ("newfs", Status.NOT_VERIFIED),
        ):
            with self.subTest(filesystem_type=filesystem_type):
                mountinfo = f"36 25 0:32 / / rw - {filesystem_type} source rw\n"
                result = admit_project_filesystem(
                    "/project", platform_name="linux", mountinfo_text=mountinfo
                )
                self.assertEqual(result.status, expected_status)

    def test_malformed_mount_inventory_fails_closed(self) -> None:
        result = admit_project_filesystem(
            "/project", platform_name="linux", mountinfo_text="malformed\n"
        )
        self.assertEqual(result.status, Status.NOT_VERIFIED)
        self.assertEqual(result.reasons, ("SOS_FILESYSTEM_PROFILE_NOT_VERIFIED",))

    def test_malformed_more_specific_escape_cannot_fall_back_to_parent(self) -> None:
        parent = "36 25 0:32 / /project rw,relatime - ext4 /dev/root rw\n"
        for malformed in ("\\999", "\\04", "\\"):
            with self.subTest(malformed=malformed):
                mountinfo = (
                    parent
                    + f"37 36 0:45 / /project{malformed}shared rw,relatime - 9p drvfs rw\n"
                )
                result = admit_project_filesystem(
                    "/project/shared",
                    platform_name="linux",
                    mountinfo_text=mountinfo,
                )
                self.assertEqual(result.status, Status.NOT_VERIFIED)
                self.assertEqual(
                    result.reasons,
                    ("SOS_FILESYSTEM_PROFILE_NOT_VERIFIED",),
                )

    def test_cli_rejects_before_confirmation_or_project_write(self) -> None:
        from sos import cli

        rejected = TerminalResult(
            "sos_filesystem_admission_v1",
            Status.UNSUPPORTED,
            ("SOS_FILESYSTEM_PROFILE_UNSUPPORTED",),
            {"absolute_paths_serialized": False},
        )
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            output = io.StringIO()
            with (
                mock.patch.object(cli, "admit_project_filesystem", return_value=rejected),
                mock.patch.object(cli, "_ask_confirmation") as confirmation,
                contextlib.redirect_stdout(output),
            ):
                exit_code = cli.main(["init", "--with-codex", str(root), "--json"])
            self.assertEqual(exit_code, 2)
            confirmation.assert_not_called()
            self.assertFalse((root / ".sigma").exists())
            self.assertEqual(
                json.loads(output.getvalue())["reasons"],
                ["SOS_FILESYSTEM_PROFILE_UNSUPPORTED"],
            )

    def test_transaction_rechecks_before_creating_staging(self) -> None:
        from sos import transaction

        rejected = TerminalResult(
            "sos_filesystem_admission_v1",
            Status.UNSUPPORTED,
            ("SOS_FILESYSTEM_PROFILE_UNSUPPORTED",),
            {},
        )
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            transaction_id = "a" * 64
            with (
                mock.patch.object(
                    transaction,
                    "require_project_filesystem",
                    side_effect=FilesystemAdmissionError(rejected),
                ),
                self.assertRaises(transaction.TransactionError) as raised,
            ):
                transaction.create_bootstrap_staging(
                    root, transaction_id, {"manifest.json": b"{}"}
                )
            self.assertEqual(str(raised.exception), "SOS_FILESYSTEM_PROFILE_UNSUPPORTED")
            self.assertFalse((root / f".sigma.init.{transaction_id}").exists())


if __name__ == "__main__":
    unittest.main()
