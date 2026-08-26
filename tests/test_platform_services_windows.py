from __future__ import annotations

import contextlib
import ctypes
import hashlib
import json
import sys
import unittest
from pathlib import Path

from sos.platform_services import (
    EphemeralDirectoryEntry,
    EphemeralLauncherObservation,
    FilePublicationOperation,
    PlatformServiceError,
    PlatformServices,
    PublicationReceipt,
    TreePublicationOperation,
    TreeStagingCapability,
)
from sos.platforms.windows import (
    WindowsPlatformServices,
    _NativeObject,
    _NativeRoot,
    _NativeStaging,
    _Kernel32,
    _Win32NativeBoundary,
    _binding_digest,
)


def _digest(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


class _FakeWindowsNative:
    """Deterministic mechanism double; it is never native-Windows evidence."""

    def __init__(self) -> None:
        self.host = {
            "system": "windows",
            "architecture": "amd64",
            "windows_build": 22631,
            "filesystem_type": "NTFS",
            "drive_type": "fixed",
            "volume_flags": frozenset(),
        }
        self.files = {"input.txt": b"private payload"}
        self.directories = {".", ".sigma"}
        self.calls: list[tuple[object, ...]] = []
        self.lock_error: str | None = None
        self.bad_receipt = False
        self.forced_object: _NativeObject | None = None
        self.staging_error: str | None = None

    def inspect_host(self, repository_path: Path | None) -> dict[str, object]:
        self.calls.append(("inspect_host", repository_path is not None))
        return dict(self.host)

    def open_repository(self, path: Path) -> _NativeRoot:
        self.calls.append(("open_repository", str(path)))
        return _NativeRoot(101, r"C:\repo", "C:\\", _digest(b"root"))

    def close_root(self, token: _NativeRoot) -> None:
        self.calls.append(("close_root", token.handle))
        token.closed = True

    def observe_object(self, root: _NativeRoot, relative_path: str) -> _NativeObject:
        self.calls.append(("observe_object", relative_path))
        if self.forced_object is not None:
            return self.forced_object
        if relative_path in self.files:
            payload = self.files[relative_path]
            identity = _digest(b"file:" + relative_path.encode())
            return _NativeObject("regular", len(payload), 0o644, identity, identity, _digest(payload))
        if relative_path in self.directories:
            identity = _digest(b"directory:" + relative_path.encode())
            return _NativeObject("directory", 0, 0o755, identity, identity)
        absent = _digest(b"absent")
        return _NativeObject("absent", 0, 0, absent, absent)

    def read_regular_file(self, root: _NativeRoot, relative_path: str, limit: int) -> tuple[_NativeObject, bytes]:
        self.calls.append(("read_regular_file", relative_path, limit))
        if relative_path not in self.files:
            raise PlatformServiceError("not_found")
        payload = self.files[relative_path]
        if len(payload) > limit:
            raise PlatformServiceError("file_limit_exceeded")
        return self.observe_object(root, relative_path), payload

    def enumerate_directory(self, root: _NativeRoot, relative_path: str, limit: int) -> tuple[tuple[EphemeralDirectoryEntry, ...], str]:
        self.calls.append(("enumerate_directory", relative_path, limit))
        names = sorted(name for name in self.files if "/" not in name)
        if len(names) > limit:
            raise PlatformServiceError("directory_limit_exceeded")
        entries = tuple(
            EphemeralDirectoryEntry(name, "regular", _digest(b"file:" + name.encode()))
            for name in names
        )
        material = json.dumps(names, separators=(",", ":")).encode()
        return entries, _digest(material)

    @contextlib.contextmanager
    def acquire_lock(self, root: _NativeRoot, relative_path: str, deadline: float, exclusive_create: bool):
        self.calls.append(("acquire_lock", relative_path, deadline, exclusive_create))
        if self.lock_error is not None:
            raise PlatformServiceError(self.lock_error)
        yield

    def publish_file(self, operation: FilePublicationOperation, root: _NativeRoot) -> PublicationReceipt:
        self.calls.append(("publish_file", operation.relative_path, operation.parent_policy))
        current = self.files.get(operation.relative_path)
        if (current is not None) != operation.expected_existed or current != operation.expected_payload:
            raise PlatformServiceError("identity_changed")
        before = _digest(current) if current is not None else None
        if operation.payload is None:
            self.files.pop(operation.relative_path, None)
            action = "delete"
        else:
            self.files[operation.relative_path] = operation.payload
            action = "replace" if operation.expected_existed else "create"
        profile = "wrong-profile" if self.bad_receipt else "windows-ntfs-handle-flush-v1"
        return PublicationReceipt(profile, action, operation.relative_path, before, _digest(operation.payload) if operation.payload is not None else None)

    def publish_tree(self, operation: TreePublicationOperation, root: _NativeRoot) -> PublicationReceipt:
        self.calls.append(("publish_tree", operation.action, operation.staging_name, operation.target_name))
        if self.staging_error is not None and operation.action in {"recover", "extend", "commit", "discard"}:
            raise PlatformServiceError(self.staging_error)
        capability = operation.capability
        if operation.action in {"create", "recover"}:
            transaction = operation.staging_name.removeprefix(".sigma.init.")
            token = object()
            capability = TreeStagingCapability(
                root.identity_digest,
                transaction,
                operation.staging_name,
                operation.target_name,
                _digest(b"staging"),
                operation.recovery_binding_digest or "none",
                _digest(b"binding"),
                token,
                lambda _token: None,
            )
        elif capability is None:
            raise PlatformServiceError("staging_recovery_required")
        if operation.action == "extend":
            verb = "extend_tree"
        elif operation.action == "commit":
            capability.consume("commit")
            capability = None
            verb = "create_tree"
        elif operation.action == "discard":
            capability.consume("discard")
            capability = None
            verb = "discard_tree"
        else:
            verb = "stage_tree" if operation.action == "create" else "recover_tree"
        profile = "wrong-profile" if self.bad_receipt else "windows-ntfs-handle-flush-v1"
        return PublicationReceipt(profile, verb, operation.target_name, None, None, capability)

    def observe_launcher(self, client_id: str) -> EphemeralLauncherObservation:
        self.calls.append(("observe_launcher", client_id))
        return EphemeralLauncherObservation(Path(r"C:\Program Files\SOS\sos.exe"), "0.1.0a1", _digest(b"launcher"))


class _IdentityBoundKernel:
    """Injectable kernel model that makes any staging-name rebind terminal."""

    def __init__(self, staging_name: str, marker_payload: bytes) -> None:
        self.staging_name = staging_name
        self.marker_payload = marker_payload
        self.calls: list[tuple[object, ...]] = []
        self._next_handle = 20
        self._objects: dict[int, tuple[str, int, str, bool, int, bool, int]] = {
            1: ("directory", 0, _digest(b"root"), False, 0o755, False, 1),
            2: ("directory", 0, _digest(b"staging"), False, 0o755, False, 1),
            3: ("regular", len(marker_payload), _digest(b"marker"), False, 0o600, False, 1),
        }

    def object_info(self, handle: int):
        return self._objects[handle]

    def final_path(self, handle: int) -> str:
        if handle == 1:
            return r"C:\repo"
        if handle == 2:
            return r"C:\repo\.renamed-original-staging"
        return r"C:\repo\.renamed-original-staging\object"

    def open_beneath(self, root: _NativeRoot, relative: str, **kwargs) -> int:
        self.calls.append(("open_beneath", root.handle, relative))
        if root.handle == 1 and relative == self.staging_name:
            raise AssertionError("staging name was rebound after capability admission")
        if root.handle == 2 and relative == _STAGING_MARKER:
            return 3
        self._next_handle += 1
        self._objects[self._next_handle] = (
            "regular",
            0,
            _digest(f"handle:{self._next_handle}".encode()),
            False,
            0o600,
            False,
            1,
        )
        return self._next_handle

    def read_bounded(self, handle: int, limit: int) -> bytes:
        if handle != 3 or len(self.marker_payload) > limit:
            raise AssertionError("unexpected marker read")
        return self.marker_payload

    def write_new_beneath(self, root: _NativeRoot, relative: str, payload: bytes) -> None:
        self.calls.append(("write_new_beneath", root.handle, relative, payload))

    def create_directory_chain_beneath(self, root: _NativeRoot, relative: str) -> None:
        self.calls.append(("create_directory_chain_beneath", root.handle, relative))

    def flush_parent(self, root: _NativeRoot, relative: str) -> None:
        self.calls.append(("flush_parent", root.handle, relative))

    def flush(self, handle: int) -> None:
        self.calls.append(("flush", handle))

    def delete_beneath(self, root: _NativeRoot, relative: str, expected_identity: str | None) -> None:
        self.calls.append(("delete_beneath", root.handle, relative))

    def rename_open_beneath(self, root: _NativeRoot, source_handle: int, target: str, **kwargs) -> None:
        self.calls.append(("rename_open_beneath", root.handle, source_handle, target, kwargs["replace"]))

    def enumerate_beneath(self, root: _NativeRoot, relative: str, limit: int) -> list[str]:
        self.calls.append(("enumerate_beneath", root.handle, relative, limit))
        return []

    def discard_open_tree(self, root: _NativeRoot, expected_identity: str) -> None:
        self.calls.append(("discard_open_tree", root.handle, expected_identity))

    def close(self, handle: int) -> None:
        self.calls.append(("close", handle))


class _InjectedWin32Boundary(_Win32NativeBoundary):
    def __init__(self, kernel: _IdentityBoundKernel) -> None:
        super().__init__()
        self._injected_kernel = kernel

    def _kernel(self):
        return self._injected_kernel


class WindowsPlatformServicesContractTests(unittest.TestCase):
    def setUp(self) -> None:
        self.native = _FakeWindowsNative()
        self.service = WindowsPlatformServices(self.native)

    def _open(self):
        return self.service.open_repository(Path(r"C:\repo"))

    @staticmethod
    def _identity_bound_lifecycle(staging: str):
        root = _NativeRoot(1, r"C:\repo", "C:\\", _digest(b"root"))
        marker = {
            "contract": "sos_staging_binding_v1",
            "root_identity_digest": root.identity_digest,
            "transaction_id": staging.removeprefix(".sigma.init."),
            "staging_name": staging,
            "target_name": ".sigma",
            "staging_identity_digest": _digest(b"staging"),
            "recovery_binding_digest": "none",
            "binding_nonce": "ab" * 32,
        }
        marker["binding_digest"] = _binding_digest(marker)
        kernel = _IdentityBoundKernel(
            staging,
            json.dumps(marker, sort_keys=True, separators=(",", ":")).encode(),
        )
        boundary = _InjectedWin32Boundary(kernel)
        token = _NativeStaging(
            2,
            root,
            staging,
            ".sigma",
            _digest(b"staging"),
            str(marker["binding_digest"]),
            staging.removeprefix(".sigma.init."),
            "none",
        )
        return root, boundary, boundary._capability(token), kernel

    def test_all_nine_services_conform_to_protocol_with_injected_boundary(self) -> None:
        self.assertIsInstance(self.service, PlatformServices)
        report = self.service.inspect_host(Path(r"C:\repo"))
        self.assertEqual(report["platform_profile_id"], "windows-11-x86_64-local-ntfs-v1")
        self.assertEqual(report["filesystem_profile_id"], "windows-local-ntfs-v1")
        self.assertEqual(report["qualification_execution_profile_id"], "windows-project-execution-unavailable-v1")
        self.assertFalse(report["project_execution_supported"])
        self.assertEqual(report["project_process_count"], 0)
        self.assertFalse(report["absolute_paths_serialized"])

    def test_admission_is_windows_11_x86_64_fixed_local_ntfs_only(self) -> None:
        mutations = [
            ("system", "linux", "platform_unsupported"),
            ("architecture", "arm64", "platform_unsupported"),
            ("windows_build", 19045, "platform_unsupported"),
            ("filesystem_type", "ReFS", "filesystem_unsupported"),
            ("drive_type", "network", "filesystem_unsupported"),
            ("volume_flags", frozenset({"wsl"}), "filesystem_unsupported"),
            ("volume_flags", frozenset({"placeholder"}), "filesystem_unsupported"),
        ]
        for field, value, reason in mutations:
            with self.subTest(field=field, value=value):
                original = self.native.host[field]
                self.native.host[field] = value
                with self.assertRaisesRegex(PlatformServiceError, reason):
                    self.service.inspect_host(Path(r"C:\repo"))
                self.native.host[field] = original

    def test_repository_and_relative_path_grammar_fail_before_native_access(self) -> None:
        for path in [r"repo", r"C:repo", r"\\server\share\repo", r"\\?\C:\repo", r"C:\repo\CON", r"C:\repo\name.", r"C:\repo\file:ads"]:
            with self.subTest(path=path), self.assertRaises(PlatformServiceError):
                self.service.open_repository(Path(path))
        self.assertFalse(any(call[0] == "open_repository" for call in self.native.calls))
        with self._open() as root:
            for relative in ["../escape", "NUL", "name.", "name ", "file:ads", "a\\b", "a//b", "a/./b", "bad\ud800"]:
                with self.subTest(relative=relative), self.assertRaises(PlatformServiceError):
                    self.service.observe_object(root, relative)

    def test_observation_read_and_enumeration_are_bounded_and_content_safe(self) -> None:
        with self._open() as root:
            observed = self.service.observe_object(root, "input.txt")
            self.assertEqual(observed.kind, "regular")
            read = self.service.read_regular_file_bounded(root, "input.txt", 64)
            self.assertEqual(read.payload, b"private payload")
            with self.assertRaisesRegex(PlatformServiceError, "file_limit_exceeded"):
                self.service.read_regular_file_bounded(root, "input.txt", 3)
            listing = self.service.enumerate_directory_bounded(root, ".", 4)
            self.assertEqual([entry.name for entry in listing.entries], ["input.txt"])
            rendered = json.dumps(read.safe_projection(), sort_keys=True)
            self.assertNotIn("private payload", rendered)
            self.assertNotIn(r"C:\repo", rendered)

    def test_reparse_placeholder_special_and_hardlink_objects_fail_closed(self) -> None:
        identity = _digest(b"object")
        cases = [
            (_NativeObject("reparse", 0, 0, identity, identity), "object_kind_unsupported"),
            (_NativeObject("special", 0, 0, identity, identity), "object_kind_unsupported"),
            (_NativeObject("placeholder", 0, 0, identity, identity), "cloud_placeholder_unsupported"),
            (_NativeObject("regular", 1, 0o644, identity, identity, link_count=2), "object_kind_unsupported"),
        ]
        with self._open() as root:
            for observed, reason in cases:
                with self.subTest(kind=observed.kind, links=observed.link_count):
                    self.native.forced_object = observed
                    with self.assertRaisesRegex(PlatformServiceError, reason):
                        self.service.observe_object(root, "object")
            self.native.forced_object = None

    def test_case_collision_in_directory_listing_fails_closed(self) -> None:
        self.native.files["INPUT.TXT"] = b"other"
        with self._open() as root, self.assertRaisesRegex(PlatformServiceError, "path_collision"):
            self.service.enumerate_directory_bounded(root, ".", 8)

    def test_lock_uses_kernel_boundary_and_caps_deadline_at_two_seconds(self) -> None:
        with self._open() as root:
            with self.service.acquire_repository_lock(root, 99.0, relative_lock_path=".sigma/lock"):
                pass
            self.assertIn(("acquire_lock", ".sigma/lock", 2.0, False), self.native.calls)
            self.native.lock_error = "lock_timeout"
            with self.assertRaisesRegex(PlatformServiceError, "lock_timeout"):
                with self.service.acquire_repository_lock(root, 1.0, relative_lock_path=".sigma/lock"):
                    pass

    def test_file_publication_binds_expected_bytes_and_exact_durability_profile(self) -> None:
        with self._open() as root:
            receipt = self.service.publish_file(FilePublicationOperation(root, "created.txt", b"one", None, False, 0o600))
            self.assertEqual(receipt.profile_id, "windows-ntfs-handle-flush-v1")
            replaced = self.service.publish_file(FilePublicationOperation(root, "created.txt", b"two", b"one", True, 0o600))
            self.assertEqual(replaced.operation, "replace")
            with self.assertRaisesRegex(PlatformServiceError, "identity_changed"):
                self.service.publish_file(FilePublicationOperation(root, "created.txt", b"three", b"one", True, 0o600))
            self.native.bad_receipt = True
            with self.assertRaisesRegex(PlatformServiceError, "durability_profile_unavailable"):
                self.service.publish_file(FilePublicationOperation(root, "other.txt", b"x", None, False, 0o600))

    def test_tree_lifecycle_requires_closed_actions_capability_and_reserved_marker(self) -> None:
        staging = ".sigma.init." + "a" * 64
        with self._open() as root:
            with self.assertRaisesRegex(PlatformServiceError, "publication_failed"):
                self.service.publish_tree(TreePublicationOperation(root, staging, ".sigma", "unknown"))
            with self.assertRaisesRegex(PlatformServiceError, "collision"):
                self.service.publish_tree(TreePublicationOperation(root, staging, ".sigma", "create", ((_STAGING_MARKER, b"bad"),)))
            created = self.service.publish_tree(TreePublicationOperation(root, staging, ".sigma", "create", (("record", b"one"),), recovery_binding_digest="none"))
            self.assertIsNotNone(created.capability)
            extended = self.service.publish_tree(TreePublicationOperation(root, staging, ".sigma", "extend", (("second", b"two"),), capability=created.capability))
            self.assertIs(extended.capability, created.capability)
            committed = self.service.publish_tree(TreePublicationOperation(root, staging, ".sigma", "commit", capability=created.capability))
            self.assertEqual(committed.operation, "create_tree")
            self.assertTrue(created.capability.consumed)

    def test_identity_or_marker_drift_blocks_every_post_create_tree_action(self) -> None:
        staging = ".sigma.init." + "b" * 64
        with self._open() as root:
            created = self.service.publish_tree(
                TreePublicationOperation(root, staging, ".sigma", "create", recovery_binding_digest=_digest(b"pending"))
            )
            for action in ("extend", "commit", "discard"):
                with self.subTest(action=action):
                    self.native.staging_error = "staging_identity_changed"
                    with self.assertRaisesRegex(PlatformServiceError, "staging_identity_changed"):
                        self.service.publish_tree(
                            TreePublicationOperation(root, staging, ".sigma", action, capability=created.capability)
                        )
            self.native.staging_error = "staging_recovery_required"
            with self.assertRaisesRegex(PlatformServiceError, "staging_recovery_required"):
                self.service.publish_tree(
                    TreePublicationOperation(root, staging, ".sigma", "recover", recovery_binding_digest=_digest(b"other"))
                )

    def test_extend_stays_on_retained_staging_handle_after_name_substitution(self) -> None:
        staging = ".sigma.init." + "c" * 64
        root, boundary, capability, kernel = self._identity_bound_lifecycle(staging)
        receipt = boundary.publish_tree(
            TreePublicationOperation(
                root,
                staging,
                ".sigma",
                "extend",
                (("nested/record", b"new"),),
                capability=capability,
            ),
            root,
        )
        self.assertEqual(receipt.operation, "extend_tree")
        self.assertIn(("write_new_beneath", 2, "nested/record", b"new"), kernel.calls)
        self.assertFalse(
            any(call[:3] == ("open_beneath", 1, staging) for call in kernel.calls)
        )

    def test_commit_and_discard_use_retained_handles_after_name_substitution(self) -> None:
        staging = ".sigma.init." + "d" * 64
        root, boundary, capability, kernel = self._identity_bound_lifecycle(staging)
        committed = boundary.publish_tree(
            TreePublicationOperation(
                root,
                staging,
                ".sigma",
                "commit",
                capability=capability,
            ),
            root,
        )
        self.assertEqual(committed.operation, "create_tree")
        self.assertIn(("delete_beneath", 2, _STAGING_MARKER), kernel.calls)
        self.assertIn(("rename_open_beneath", 1, 2, ".sigma", False), kernel.calls)
        self.assertFalse(
            any(call[:3] == ("open_beneath", 1, staging) for call in kernel.calls)
        )

    def test_native_create_and_rename_primitives_are_handle_relative(self) -> None:
        api = object.__new__(_Kernel32)
        create_calls: list[tuple[object, ...]] = []
        api.open_beneath = lambda root, relative, **kwargs: (
            create_calls.append((root.handle, relative, kwargs)),
            77,
        )[1]
        root = _NativeRoot(41, r"C:\repo", "C:\\", _digest(b"root"))
        self.assertEqual(api.create_directory_handle_beneath(root, "managed"), 77)
        self.assertEqual(create_calls[0][0:2], (41, "managed"))
        self.assertEqual(create_calls[0][2]["create"], "new")

        class RenameRecorder:
            def __init__(self) -> None:
                self.observed: tuple[int, int, int, int, int, bytes] | None = None

            def SetFileInformationByHandle(self, source, info_class, buffer, size):
                address = ctypes.addressof(buffer)
                flags = ctypes.c_uint32.from_address(address).value
                root_handle = ctypes.c_void_p.from_address(address + 8).value
                name_length = ctypes.c_uint32.from_address(address + 16).value
                name = bytes((ctypes.c_ubyte * name_length).from_address(address + 20))
                self.observed = (
                    source,
                    info_class,
                    size,
                    flags,
                    int(root_handle or 0),
                    name,
                )
                return 1

        recorder = RenameRecorder()
        api.kernel32 = recorder
        identity = _digest(b"source")
        api.object_info = lambda handle: (
            "regular",
            0,
            identity,
            False,
            0o600,
            False,
            1,
        )
        api.rename_open_beneath(
            root,
            77,
            "nested/target",
            replace=False,
            expected_source_identity=identity,
        )
        self.assertIsNotNone(recorder.observed)
        source, info_class, _size, flags, root_handle, name = recorder.observed
        self.assertEqual((source, info_class, flags, root_handle), (77, 22, 0, 41))
        self.assertEqual(name.decode("utf-16-le"), r"nested\target")

        staging = ".sigma.init." + "e" * 64
        root, boundary, capability, kernel = self._identity_bound_lifecycle(staging)
        discarded = boundary.publish_tree(
            TreePublicationOperation(
                root,
                staging,
                ".sigma",
                "discard",
                capability=capability,
            ),
            root,
        )
        self.assertEqual(discarded.operation, "discard_tree")
        self.assertIn(("discard_open_tree", 2, _digest(b"staging")), kernel.calls)
        self.assertFalse(
            any(call[:3] == ("open_beneath", 1, staging) for call in kernel.calls)
        )

    def test_launcher_is_bounded_to_codex_and_git_and_content_safe(self) -> None:
        observed = self.service.observe_launcher("codex")
        self.assertEqual(observed.package_version, "0.1.0a1")
        self.assertNotIn("C:\\", json.dumps(observed.safe_projection()))
        self.assertEqual(self.service.observe_launcher("git").package_version, "0.1.0a1")
        with self.assertRaisesRegex(PlatformServiceError, "launcher_unsupported"):
            self.service.observe_launcher("claude")

    def test_shared_corpus_keeps_windows_project_execution_typed_unsupported(self) -> None:
        corpus = json.loads((Path(__file__).parent / "platform_conformance_corpus_v1.json").read_text())
        qualification = next(family for family in corpus["families"] if family["family_id"] == "qualification_profile")
        expected = qualification["cases"][0]["platform_expected"]["windows"]
        self.assertEqual(expected["status"], "unsupported")
        self.assertEqual(expected["primary_reason"], "SOS_EXECUTABLE_QUALIFICATION_UNSUPPORTED")
        self.assertEqual(expected["project_process_count"], 0)
        self.assertFalse(self.service.inspect_host()["project_execution_supported"])

    def test_default_native_boundary_fails_closed_off_windows_without_io(self) -> None:
        if sys.platform == "win32":
            self.skipTest("non-Windows fail-closed check")
        service = WindowsPlatformServices()
        with self.assertRaisesRegex(PlatformServiceError, "platform_unsupported"):
            service.inspect_host()

    def test_native_mechanism_surface_is_handle_relative_and_has_no_execution_adapter(self) -> None:
        source = (Path(__file__).parents[1] / "src/sos/platforms/windows.py").read_text()
        for required in (
            "NtCreateFile",
            "OBJ_DONT_REPARSE",
            "CompareStringOrdinal",
            "FILE_RENAME_INFO_EX",
            "DuplicateHandle",
            "SetFileInformationByHandle",
            "GetFileInformationByHandleEx",
            "FlushFileBuffers",
            "windows-project-execution-unavailable-v1",
        ):
            self.assertIn(required, source)
        for forbidden in (
            "subprocess",
            "os.system",
            "os.walk",
            "os.scandir",
            "shell=True",
            "ReplaceFileW",
            "MoveFileExW",
            "CreateDirectoryW",
        ):
            self.assertNotIn(forbidden, source)


_STAGING_MARKER = ".sos-staging-binding-v1"


if __name__ == "__main__":
    unittest.main()
