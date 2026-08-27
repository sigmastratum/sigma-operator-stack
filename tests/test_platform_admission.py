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
    def test_native_windows_control_plane_is_admitted(self) -> None:
        result = admit_host(platform_name="win32")
        self.assertEqual(result.status, Status.SUCCESS)
        self.assertEqual(result.reasons, ("SOS_WINDOWS_CONTROL_PLANE_ADMITTED",))
        self.assertEqual(result.details["host_platform"], "windows")
        self.assertEqual(result.details["execution_substrate"], "windows")
        self.assertFalse(result.details["absolute_paths_serialized"])

    def test_macos_control_plane_is_admitted(self) -> None:
        result = admit_host(platform_name="darwin")
        self.assertEqual(result.status, Status.SUCCESS)
        self.assertEqual(result.reasons, ("SOS_MACOS_CONTROL_PLANE_ADMITTED",))
        self.assertEqual(result.details["host_platform"], "macos")
        self.assertEqual(result.details["execution_substrate"], "macos")

    def test_actual_windows_and_macos_version_boundaries_fail_closed(self) -> None:
        with (
            mock.patch("sos.platform_admission.process_platform_name", return_value="win32"),
            mock.patch("sos.platform_admission.host_platform.machine", return_value="AMD64"),
            mock.patch(
                "sos.platform_admission.host_platform.version",
                return_value="10.0.19045",
            ),
        ):
            result = admit_host()
        self.assertEqual(result.status, Status.UNSUPPORTED)
        self.assertEqual(result.reasons, ("SOS_PLATFORM_UNSUPPORTED",))

        with (
            mock.patch("sos.platform_admission.process_platform_name", return_value="darwin"),
            mock.patch("sos.platform_admission.host_platform.machine", return_value="arm64"),
            mock.patch(
                "sos.platform_admission.host_platform.mac_ver",
                return_value=("13.7.1", ("", "", ""), ""),
            ),
        ):
            result = admit_host()
        self.assertEqual(result.status, Status.UNSUPPORTED)
        self.assertEqual(result.reasons, ("SOS_PLATFORM_UNSUPPORTED",))

    def test_admitted_entrypoint_routes_to_shared_cli(self) -> None:
        admitted = admit_host(platform_name="win32")
        with (
            mock.patch.object(entrypoint, "admit_host", return_value=admitted),
            mock.patch("sos.cli.main", return_value=7) as shared_main,
        ):
            code = entrypoint.main(["status", "--json"])
        self.assertEqual(code, 7)
        shared_main.assert_called_once_with(["status", "--json"])

    def test_native_filesystem_profiles_use_selected_service(self) -> None:
        windows = mock.Mock()
        windows.inspect_host.return_value = {
            "filesystem_type": "ntfs",
            "filesystem_observation_status": "observed",
        }
        observed = admit_project_filesystem(
            "C:/project", platform_name="win32", service=windows
        )
        self.assertEqual(observed.status, Status.SUCCESS)
        self.assertEqual(observed.details["filesystem_profile"], "windows_local_ntfs")

        macos = mock.Mock()
        macos.inspect_host.return_value = {
            "filesystem_type": "apfs",
            "filesystem_observation_status": "observed",
        }
        observed = admit_project_filesystem(
            "/project", platform_name="darwin", service=macos
        )
        self.assertEqual(observed.status, Status.SUCCESS)
        self.assertEqual(observed.details["filesystem_profile"], "macos_local_apfs")

    def test_version_is_available_without_loading_linux_implementation(self) -> None:
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            exit_code = entrypoint.main(["--version"])
        self.assertEqual(exit_code, 0)
        self.assertEqual(output.getvalue().strip(), "sos 0.1.0a2")

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
