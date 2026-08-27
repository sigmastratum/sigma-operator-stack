from __future__ import annotations

import ctypes
import json
import os
import struct
import tempfile
import threading
import unittest
from contextlib import ExitStack
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from sos.platform_services import (
    FilePublicationOperation,
    PlatformServiceError,
    PlatformServices,
    TreePublicationOperation,
)
from sos.platforms.macos import MacOSPlatformServices


_CASE_SENSITIVE_PAYLOAD = bytes.fromhex(
    "24000000 00010000 00000000 00000000 00000000"
    " 00010000 00000000 00000000 00000000"
)
_CASE_INSENSITIVE_PAYLOAD = bytes.fromhex(
    "24000000 00000000 00000000 00000000 00000000"
    " 00010000 00000000 00000000 00000000"
)
_UNKNOWN_PAYLOAD = bytes.fromhex(
    "24000000 00010000 00000000 00000000 00000000"
    " 00000000 00000000 00000000 00000000"
)


class _FakeFGetAttrList:
    def __init__(self, payload: bytes) -> None:
        self.payload = payload
        self.request: tuple[int, int, int, int, int, int, int] | None = None
        self.options: int | None = None
        self.argtypes: object = None
        self.restype: object = None

    def __call__(
        self,
        descriptor: int,
        attributes_pointer: object,
        output_pointer: object,
        output_size: int,
        options: int,
    ) -> int:
        attributes = attributes_pointer._obj
        self.request = (
            attributes.bitmapcount,
            attributes.commonattr,
            attributes.volattr,
            attributes.dirattr,
            attributes.fileattr,
            attributes.forkattr,
            output_size,
        )
        self.options = options
        struct.pack_into(f"={len(self.payload)}s", output_pointer._obj, 0, self.payload)
        return 0


class _HermeticMacOSPlatformServices(MacOSPlatformServices):
    def __init__(
        self,
        *,
        host: tuple[str, str, int] = ("darwin", "arm64", 14),
        filesystem: tuple[str, bool, bool, bool] = ("apfs", True, False, True),
    ) -> None:
        self._test_host = host
        self._test_filesystem = filesystem[:3]
        self._test_case_sensitive = filesystem[3]

    def _host_facts(self) -> tuple[str, str, int]:
        return self._test_host

    def _filesystem_facts(self, path: Path) -> tuple[str, bool, bool]:
        del path
        return self._test_filesystem

    def _read_volume_capability_payload(self, descriptor: int) -> bytes:
        del descriptor
        return (
            _CASE_SENSITIVE_PAYLOAD
            if self._test_case_sensitive
            else _CASE_INSENSITIVE_PAYLOAD
        )

    def _rename_noreplace(
        self, source_fd: int, source: str, target_fd: int, target: str
    ) -> None:
        try:
            os.stat(target, dir_fd=target_fd, follow_symlinks=False)
        except FileNotFoundError:
            os.rename(source, target, src_dir_fd=source_fd, dst_dir_fd=target_fd)
            return
        raise PlatformServiceError("collision")

    def _rename_exchange(self, directory: int, source: str, target: str) -> None:
        temporary = ".sos-test-swap"
        os.rename(source, temporary, src_dir_fd=directory, dst_dir_fd=directory)
        os.rename(target, source, src_dir_fd=directory, dst_dir_fd=directory)
        os.rename(temporary, target, src_dir_fd=directory, dst_dir_fd=directory)


def _service(*, case_sensitive: bool = True) -> MacOSPlatformServices:
    return _HermeticMacOSPlatformServices(
        filesystem=("apfs", True, False, case_sensitive)
    )


class MacOSPlatformServicesTests(unittest.TestCase):
    def test_native_volume_capability_parser_binds_apfs_case_mode(self) -> None:
        self.assertTrue(
            MacOSPlatformServices._parse_volume_capabilities(
                _CASE_SENSITIVE_PAYLOAD
            )
        )
        self.assertFalse(
            MacOSPlatformServices._parse_volume_capabilities(
                _CASE_INSENSITIVE_PAYLOAD
            )
        )
        with self.assertRaisesRegex(PlatformServiceError, "filesystem_not_verified"):
            MacOSPlatformServices._parse_volume_capabilities(_UNKNOWN_PAYLOAD)

        wrong_index = bytes.fromhex(
            "24000000 00000000 00010000 00000000 00000000"
            " 00000000 00010000 00000000 00000000"
        )
        with self.assertRaisesRegex(PlatformServiceError, "filesystem_not_verified"):
            MacOSPlatformServices._parse_volume_capabilities(wrong_index)

        old_bit = bytes.fromhex(
            "24000000 01000000 00000000 00000000 00000000"
            " 01000000 00000000 00000000 00000000"
        )
        with self.assertRaisesRegex(PlatformServiceError, "filesystem_not_verified"):
            MacOSPlatformServices._parse_volume_capabilities(old_bit)

        with self.assertRaisesRegex(PlatformServiceError, "filesystem_not_verified"):
            MacOSPlatformServices._parse_volume_capabilities(
                _CASE_SENSITIVE_PAYLOAD[:-1]
            )
        overdeclared = b"\x28\x00\x00\x00" + _CASE_SENSITIVE_PAYLOAD[4:]
        with self.assertRaisesRegex(PlatformServiceError, "filesystem_not_verified"):
            MacOSPlatformServices._parse_volume_capabilities(overdeclared)
        malformed = b"\x00\x00\x00\x00" + _CASE_SENSITIVE_PAYLOAD[4:]
        with self.assertRaisesRegex(PlatformServiceError, "filesystem_not_verified"):
            MacOSPlatformServices._parse_volume_capabilities(malformed)

    def test_native_volume_capability_request_uses_exact_darwin_mask(self) -> None:
        native_call = _FakeFGetAttrList(_CASE_SENSITIVE_PAYLOAD)
        with mock.patch(
            "sos.platforms.macos.ctypes.CDLL",
            return_value=SimpleNamespace(fgetattrlist=native_call),
        ):
            payload = MacOSPlatformServices._read_volume_capability_payload(17)

        self.assertEqual(payload, _CASE_SENSITIVE_PAYLOAD)
        self.assertEqual(native_call.request, (5, 0, 0x80020000, 0, 0, 0, 4096))
        self.assertEqual(native_call.options, 0)

    def test_admission_is_fail_closed_and_report_is_content_safe(self) -> None:
        unsupported = [
            (("linux", "x86_64", 6), ("apfs", True, False, True)),
            (("darwin", "x86_64", 14), ("apfs", True, False, True)),
            (("darwin", "arm64", 13), ("apfs", True, False, True)),
            (("darwin", "arm64", 14), ("hfs", True, False, True)),
            (("darwin", "arm64", 14), ("apfs", False, False, True)),
            (("darwin", "arm64", 14), ("apfs", True, True, True)),
        ]
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for host, filesystem in unsupported:
                with self.subTest(host=host, filesystem=filesystem):
                    service = _HermeticMacOSPlatformServices(
                        host=host, filesystem=filesystem
                    )
                    with self.assertRaises(PlatformServiceError):
                        service.open_repository(root)
            report = _service(case_sensitive=False).inspect_host(root)
            rendered = json.dumps(report, sort_keys=True)
            self.assertEqual(report["filesystem_case_mode"], "case_insensitive")
            self.assertNotIn(str(root), rendered)
            self.assertFalse(report["absolute_paths_serialized"])

    def test_all_nine_services_use_bound_apfs_root(self) -> None:
        service = _service()
        self.assertIsInstance(service, PlatformServices)
        with tempfile.TemporaryDirectory() as temporary:
            root_path = Path(temporary)
            (root_path / "input.txt").write_bytes(b"private")
            with service.open_repository(root_path) as root:
                self.assertEqual(root.platform_profile_id, "macos-apfs-repository-services-v1")
                self.assertEqual(
                    root.filesystem_profile_id, "macos-local-apfs-case-sensitive-v1"
                )
                observed = service.observe_object(root, "input.txt")
                self.assertEqual(observed.kind, "regular")
                read = service.read_regular_file_bounded(root, "input.txt", 7)
                self.assertEqual(read.payload, b"private")
                self.assertNotIn("private", json.dumps(read.safe_projection()))
                listing = service.enumerate_directory_bounded(root, ".", 8)
                self.assertEqual(listing.entry_count, 1)
                with service.acquire_repository_lock(
                    root, 2.0, relative_lock_path=".sigma/lock"
                ):
                    created = service.publish_file(
                        FilePublicationOperation(root, "state", b"one", None, False, 0o600)
                    )
                self.assertEqual(
                    created.profile_id, "macos-apfs-same-volume-fsync-rename-v1"
                )
                staged = service.publish_tree(
                    TreePublicationOperation(
                        root,
                        ".sigma.init." + "a" * 64,
                        "control",
                        "create",
                        (("record", b"bound"),),
                        recovery_binding_digest="sha256:" + "1" * 64,
                    )
                )
                committed = service.publish_tree(
                    TreePublicationOperation(
                        root,
                        ".sigma.init." + "a" * 64,
                        "control",
                        capability=staged.capability,
                    )
                )
                self.assertEqual(committed.operation, "create_tree")
                fake_distribution = mock.Mock(version="0.1.0a2")
                fake_distribution.read_text.return_value = None
                with ExitStack() as stack:
                    stack.enter_context(
                        mock.patch(
                            "sos.platforms.macos.metadata.distribution",
                            return_value=fake_distribution,
                        )
                    )
                    stack.enter_context(
                        mock.patch.object(
                            service, "_canonical_python_executable", return_value=Path("/bin/sh")
                        )
                    )
                    stack.enter_context(
                        mock.patch.object(
                            service,
                            "_sha256_file",
                            return_value="sha256:" + "2" * 64,
                        )
                    )
                    launcher = service.observe_launcher("codex")
                self.assertEqual(launcher.package_version, "0.1.0a2")
                self.assertFalse(launcher.safe_projection()["absolute_paths_serialized"])

    def test_case_and_unicode_lookup_collisions_fail_before_mutation(self) -> None:
        service = _service(case_sensitive=False)
        with tempfile.TemporaryDirectory() as temporary:
            root_path = Path(temporary)
            (root_path / "Readme").write_text("existing")
            with service.open_repository(root_path) as root:
                with self.assertRaisesRegex(PlatformServiceError, "path_collision"):
                    service.publish_file(
                        FilePublicationOperation(root, "README", b"new", None, False, 0o600)
                    )
                self.assertFalse((root_path / "README").exists())
                composed = "caf\N{LATIN SMALL LETTER E WITH ACUTE}"
                decomposed = "cafe\N{COMBINING ACUTE ACCENT}"
                (root_path / composed).write_text("existing")
                with self.assertRaisesRegex(PlatformServiceError, "path_collision"):
                    service.observe_object(root, decomposed)

    def test_symlink_and_bounded_reads_fail_closed(self) -> None:
        service = _service()
        with tempfile.TemporaryDirectory() as temporary:
            root_path = Path(temporary)
            (root_path / "large").write_bytes(b"12345")
            (root_path / "real").mkdir()
            (root_path / "alias").symlink_to("real", target_is_directory=True)
            with service.open_repository(root_path) as root:
                with self.assertRaisesRegex(PlatformServiceError, "file_limit_exceeded"):
                    service.read_regular_file_bounded(root, "large", 4)
                with self.assertRaises(PlatformServiceError):
                    service.observe_object(root, "alias/child")
            linked_root = root_path.parent / (root_path.name + "-alias")
            linked_root.symlink_to(root_path, target_is_directory=True)
            try:
                with self.assertRaisesRegex(PlatformServiceError, "invalid_root"):
                    service.open_repository(linked_root)
            finally:
                linked_root.unlink()

    def test_alias_and_cloud_metadata_fail_closed(self) -> None:
        service = _service()
        with tempfile.TemporaryFile() as stream:
            descriptor = stream.fileno()
            finder = b"\x00" * 8 + b"\x80\x00" + b"\x00" * 22
            with mock.patch(
                "sos.platforms.macos.MacOSPlatformServices._list_xattrs_fd",
                return_value=(b"com.apple.FinderInfo",),
            ), mock.patch(
                "sos.platforms.macos.MacOSPlatformServices._get_xattr_fd",
                return_value=finder,
            ):
                with self.assertRaisesRegex(PlatformServiceError, "alias_unsupported"):
                    service._reject_unsafe_fd(descriptor)
            with mock.patch(
                "sos.platforms.macos.MacOSPlatformServices._list_xattrs_fd",
                return_value=(b"com.apple.fileprovider.placeholder",),
            ):
                with self.assertRaisesRegex(
                    PlatformServiceError, "cloud_placeholder_unsupported"
                ):
                    service._reject_unsafe_fd(descriptor)

    def test_descriptor_xattr_abi_does_not_require_python_os_helpers(self) -> None:
        service = _service()
        source = (
            Path(__file__).resolve().parents[1] / "src/sos/platforms/macos.py"
        ).read_text(encoding="utf-8")
        self.assertNotIn("os.listxattr", source)
        self.assertNotIn("os.getxattr", source)
        names = b"com.apple.FinderInfo\0"
        finder = b"\x00" * 8 + b"\x80\x00" + b"\x00" * 22

        def list_call(_descriptor, output, length, _options):
            if output is None:
                return len(names)
            self.assertEqual(length, len(names))
            ctypes.memmove(output, names, len(names))
            return len(names)

        def get_call(_descriptor, _name, output, length, _position, _options):
            if output is None:
                return len(finder)
            self.assertEqual(length, len(finder))
            ctypes.memmove(output, finder, len(finder))
            return len(finder)

        libc = SimpleNamespace(
            flistxattr=mock.Mock(side_effect=list_call),
            fgetxattr=mock.Mock(side_effect=get_call),
        )
        with tempfile.TemporaryFile() as stream, mock.patch(
            "sos.platforms.macos.ctypes.CDLL", return_value=libc
        ), mock.patch.object(os, "listxattr", create=True) as python_helper:
            with self.assertRaisesRegex(PlatformServiceError, "alias_unsupported"):
                service._reject_unsafe_fd(stream.fileno())
        python_helper.assert_not_called()

    def test_lock_contention_and_identity_drift_fail_closed(self) -> None:
        service = _service()
        with tempfile.TemporaryDirectory() as temporary:
            root_path = Path(temporary)
            (root_path / "state").write_bytes(b"one")
            with service.open_repository(root_path) as root:
                entered = threading.Event()
                release = threading.Event()

                def holder() -> None:
                    with service.acquire_repository_lock(
                        root, 2.0, relative_lock_path=".sigma/lock"
                    ):
                        entered.set()
                        release.wait(2.0)

                thread = threading.Thread(target=holder)
                thread.start()
                self.assertTrue(entered.wait(1.0))
                try:
                    with self.assertRaisesRegex(PlatformServiceError, "lock_timeout"):
                        with service.acquire_repository_lock(
                            root, 0.01, relative_lock_path=".sigma/lock"
                        ):
                            self.fail("contended lock admitted")
                finally:
                    release.set()
                    thread.join(2.0)
                with self.assertRaisesRegex(PlatformServiceError, "identity_changed"):
                    service.publish_file(
                        FilePublicationOperation(root, "state", b"two", b"stale", True, 0o600)
                    )
                self.assertEqual((root_path / "state").read_bytes(), b"one")

    def test_staging_capability_is_identity_bound_and_single_use(self) -> None:
        service = _service()
        staging_name = ".sigma.init." + "b" * 64
        with tempfile.TemporaryDirectory() as temporary:
            root_path = Path(temporary)
            with service.open_repository(root_path) as root:
                staged = service.publish_tree(
                    TreePublicationOperation(
                        root,
                        staging_name,
                        ".sigma",
                        "create",
                        (("one", b"1"),),
                        recovery_binding_digest="sha256:" + "3" * 64,
                    )
                )
                capability = staged.capability
                self.assertIsNotNone(capability)
                service.publish_tree(
                    TreePublicationOperation(
                        root, staging_name, ".sigma", "extend", (("two", b"2"),), capability
                    )
                )
                service.publish_tree(
                    TreePublicationOperation(root, staging_name, ".sigma", capability=capability)
                )
                self.assertTrue(capability.consumed)
                with self.assertRaisesRegex(PlatformServiceError, "staging_recovery_required"):
                    service.publish_tree(
                        TreePublicationOperation(
                            root, staging_name, ".sigma", capability=capability
                        )
                    )

    def test_shared_corpus_keeps_macos_execution_unsupported(self) -> None:
        corpus_path = Path(__file__).with_name("platform_conformance_corpus_v1.json")
        corpus = json.loads(corpus_path.read_text(encoding="utf-8"))
        family = next(
            item for item in corpus["families"] if item["family_id"] == "qualification_profile"
        )
        expected = family["cases"][0]["platform_expected"]["macos"]
        self.assertEqual(expected["status"], "unsupported")
        self.assertEqual(
            expected["primary_reason"], "SOS_EXECUTABLE_QUALIFICATION_UNSUPPORTED"
        )
        self.assertEqual(expected["project_process_count"], 0)


if __name__ == "__main__":
    unittest.main()
