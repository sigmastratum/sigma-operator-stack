"""Windows 11/local-NTFS mechanisms behind the PlatformServices boundary.

Tests on non-Windows hosts use an injected native boundary and therefore make
no claim about native execution.
"""

from __future__ import annotations

import contextlib
import ctypes
import functools
import hashlib
import json
import os
import platform
import re
import shutil
import sys
import time
from dataclasses import dataclass
from importlib import metadata
from pathlib import Path, PurePosixPath, PureWindowsPath
from typing import ContextManager, Iterator, Protocol

from ..platform_services import (
    EphemeralDirectoryEntry,
    EphemeralDirectoryRead,
    EphemeralFileRead,
    EphemeralLauncherObservation,
    FilePublicationOperation,
    ObjectObservation,
    PlatformServiceError,
    PublicationReceipt,
    RepositoryRootHandle,
    TreePublicationOperation,
    TreeStagingCapability,
)


_PROFILE = "windows-11-x86_64-local-ntfs-v1"
_FILESYSTEM = "windows-local-ntfs-v1"
_DURABILITY = "windows-ntfs-handle-flush-v1"
_UNSUPPORTED_EXECUTION = "windows-project-execution-unavailable-v1"
_STAGING_MARKER = ".sos-staging-binding-v1"
_NONE_RECOVERY_BINDING = "none"
_MAX_LAUNCHER_BYTES = 64 * 1024 * 1024
_LOCK_DEADLINE_SECONDS = 2.0

_RESERVED_DOS_NAMES = frozenset(
    {"CON", "PRN", "AUX", "NUL"}
    | {f"COM{index}" for index in range(1, 10)}
    | {f"LPT{index}" for index in range(1, 10)}
)


@dataclass(frozen=True)
class _NativeObject:
    kind: str
    byte_count: int
    mode: int
    identity_digest: str
    stable_identity_digest: str
    content_digest: str | None = None
    link_count: int = 1


@dataclass
class _NativeRoot:
    handle: int
    final_path: str
    volume_root: str
    identity_digest: str
    closed: bool = False


@dataclass
class _NativeStaging:
    handle: int
    root: _NativeRoot
    staging_name: str
    target_name: str
    identity_digest: str
    binding_digest: str
    transaction_id: str
    recovery_binding_digest: str
    closed: bool = False


class _NativeBoundary(Protocol):
    """Adapter-private Win32 boundary used by deterministic contract tests."""

    def inspect_host(self, repository_path: Path | None) -> dict[str, object]: ...

    def open_repository(self, path: Path) -> _NativeRoot: ...

    def close_root(self, token: _NativeRoot) -> None: ...

    def observe_object(self, root: _NativeRoot, relative_path: str) -> _NativeObject: ...

    def read_regular_file(self, root: _NativeRoot, relative_path: str, limit: int) -> tuple[_NativeObject, bytes]: ...

    def enumerate_directory(self, root: _NativeRoot, relative_path: str, limit: int) -> tuple[tuple[EphemeralDirectoryEntry, ...], str]: ...

    def acquire_lock(self, root: _NativeRoot, relative_path: str, deadline: float, exclusive_create: bool) -> ContextManager[None]: ...

    def publish_file(self, operation: FilePublicationOperation, root: _NativeRoot) -> PublicationReceipt: ...

    def publish_tree(self, operation: TreePublicationOperation, root: _NativeRoot) -> PublicationReceipt: ...

    def observe_launcher(self, client_id: str) -> EphemeralLauncherObservation: ...


class WindowsPlatformServices:
    """Windows implementation of all nine frozen PlatformServices methods."""

    profile_id = _PROFILE

    def __init__(self, native: _NativeBoundary | None = None) -> None:
        self._native: _NativeBoundary = native if native is not None else _Win32NativeBoundary()

    def inspect_host(self, repository_path: Path | None = None) -> dict[str, object]:
        report = dict(self._native.inspect_host(repository_path))
        required = {
            "system",
            "architecture",
            "windows_build",
            "filesystem_type",
            "drive_type",
            "volume_flags",
        }
        if set(report) != required:
            raise PlatformServiceError("platform_unsupported")
        system = str(report["system"]).lower()
        architecture = str(report["architecture"]).lower()
        try:
            windows_build = int(report["windows_build"])
        except (TypeError, ValueError) as exc:
            raise PlatformServiceError("platform_unsupported") from exc
        raw_flags = report["volume_flags"]
        if not isinstance(raw_flags, (list, tuple, set, frozenset)):
            raise PlatformServiceError("filesystem_unsupported")
        flags = frozenset(str(value).lower() for value in raw_flags)
        if system != "windows" or architecture not in {"amd64", "x86_64"} or windows_build < 22000:
            raise PlatformServiceError("platform_unsupported")
        if str(report["filesystem_type"]).lower() != "ntfs" or str(report["drive_type"]).lower() != "fixed":
            raise PlatformServiceError("filesystem_unsupported")
        if flags & {"network", "removable", "wsl", "placeholder", "remote"}:
            raise PlatformServiceError("filesystem_unsupported")
        return {
            "platform_profile_id": _PROFILE,
            "filesystem_profile_id": _FILESYSTEM,
            "system": "windows",
            "architecture": "x86_64",
            "windows_build": windows_build,
            "filesystem_type": "ntfs",
            "drive_type": "fixed",
            "qualification_execution_profile_id": _UNSUPPORTED_EXECUTION,
            "project_execution_supported": False,
            "project_process_count": 0,
            "absolute_paths_serialized": False,
        }

    def open_repository(self, path: Path) -> RepositoryRootHandle:
        self._validate_repository_input(path)
        self.inspect_host(path)
        try:
            token = self._native.open_repository(path)
        except PlatformServiceError:
            raise
        except OSError as exc:
            raise PlatformServiceError("invalid_root") from exc
        return RepositoryRootHandle(
            _PROFILE,
            _FILESYSTEM,
            token.identity_digest,
            token,
            self._close_root_token,
        )

    def observe_object(self, root: RepositoryRootHandle, relative_path: str) -> ObjectObservation:
        relative = _validate_relative_path(relative_path)
        observed = self._native.observe_object(self._root_token(root), relative)
        if observed.kind == "placeholder":
            raise PlatformServiceError("cloud_placeholder_unsupported")
        if observed.kind in {"reparse", "symlink", "special"} or observed.link_count > 1:
            raise PlatformServiceError("object_kind_unsupported")
        return ObjectObservation(
            relative,
            observed.kind,
            observed.byte_count,
            observed.mode,
            observed.identity_digest,
            observed.stable_identity_digest,
            observed.content_digest,
        )

    def read_regular_file_bounded(self, root: RepositoryRootHandle, relative_path: str, limit: int) -> EphemeralFileRead:
        if limit < 0:
            raise PlatformServiceError("limit_invalid")
        relative = _validate_relative_path(relative_path)
        observed, payload = self._native.read_regular_file(self._root_token(root), relative, limit)
        if observed.kind != "regular":
            raise PlatformServiceError("not_regular")
        if len(payload) > limit or observed.byte_count > limit:
            raise PlatformServiceError("file_limit_exceeded")
        digest = _payload_digest(payload)
        if observed.content_digest is not None and observed.content_digest != digest:
            raise PlatformServiceError("identity_changed")
        return EphemeralFileRead(
            ObjectObservation(
                relative,
                "regular",
                len(payload),
                observed.mode,
                observed.identity_digest,
                observed.stable_identity_digest,
                digest,
            ),
            payload,
            digest or "",
        )

    def enumerate_directory_bounded(self, root: RepositoryRootHandle, relative_path: str, limit: int) -> EphemeralDirectoryRead:
        if limit < 0:
            raise PlatformServiceError("limit_invalid")
        relative = _validate_relative_path(relative_path, allow_root=True)
        entries, names_digest = self._native.enumerate_directory(self._root_token(root), relative, limit)
        if len(entries) > limit:
            raise PlatformServiceError("directory_limit_exceeded")
        names = [entry.name for entry in entries]
        if names != sorted(names, key=functools.cmp_to_key(_windows_compare)) or any(
            _windows_equal(left, right)
            for index, left in enumerate(names)
            for right in names[index + 1 :]
        ):
            raise PlatformServiceError("path_collision")
        for entry in entries:
            _validate_component(entry.name)
        return EphemeralDirectoryRead(entries, len(entries), names_digest)

    @contextlib.contextmanager
    def acquire_repository_lock(
        self,
        root: RepositoryRootHandle,
        deadline_seconds: float | None,
        *,
        relative_lock_path: str,
        exclusive_create: bool = False,
    ) -> Iterator[None]:
        relative = _validate_relative_path(relative_lock_path)
        requested = _LOCK_DEADLINE_SECONDS if deadline_seconds is None else max(0.0, deadline_seconds)
        deadline = min(requested, _LOCK_DEADLINE_SECONDS)
        with self._native.acquire_lock(self._root_token(root), relative, deadline, exclusive_create):
            yield

    def publish_file(self, operation: FilePublicationOperation) -> PublicationReceipt:
        _validate_relative_path(operation.relative_path)
        if operation.parent_policy not in {"preserve_existing", "create_managed_and_prune_if_empty_on_abort"}:
            raise PlatformServiceError("parent_policy_invalid")
        receipt = self._native.publish_file(operation, self._root_token(operation.root))
        if receipt.profile_id != _DURABILITY or receipt.relative_target != operation.relative_path:
            raise PlatformServiceError("durability_profile_unavailable")
        return receipt

    def publish_tree(self, operation: TreePublicationOperation) -> PublicationReceipt:
        if operation.action not in {"create", "recover", "extend", "commit", "discard"}:
            raise PlatformServiceError("publication_failed")
        _validate_component(operation.staging_name)
        _validate_component(operation.target_name)
        if operation.staging_name == operation.target_name:
            raise PlatformServiceError("collision")
        for relative, _payload in operation.files:
            relative = _validate_relative_path(relative)
            if relative == _STAGING_MARKER or relative.startswith(_STAGING_MARKER + "/"):
                raise PlatformServiceError("collision")
        receipt = self._native.publish_tree(operation, self._root_token(operation.root))
        if receipt.profile_id != _DURABILITY or receipt.relative_target != operation.target_name:
            raise PlatformServiceError("durability_profile_unavailable")
        return receipt

    def observe_launcher(self, client_id: str) -> EphemeralLauncherObservation:
        if client_id not in {"codex", "git"}:
            raise PlatformServiceError("launcher_unsupported")
        observed = self._native.observe_launcher(client_id)
        if not PureWindowsPath(os.fspath(observed.executable)).is_absolute() or observed.editable_install:
            raise PlatformServiceError("launcher_invalid")
        return observed

    def _close_root_token(self, token: object) -> None:
        if not isinstance(token, _NativeRoot):
            raise PlatformServiceError("invalid_root")
        self._native.close_root(token)

    @staticmethod
    def _root_token(root: RepositoryRootHandle) -> _NativeRoot:
        token = root._platform_token()
        if not isinstance(token, _NativeRoot) or token.closed:
            raise PlatformServiceError("invalid_root")
        return token

    @staticmethod
    def _validate_repository_input(path: Path) -> None:
        raw = os.fspath(path)
        pure = PureWindowsPath(raw)
        if not pure.is_absolute() or not pure.drive or pure.drive.startswith("\\"):
            raise PlatformServiceError("invalid_root")
        if raw.startswith(("\\\\", "\\?\\", "\\.\\")) or ":" in raw[len(pure.drive) :]:
            raise PlatformServiceError("invalid_root")
        for component in pure.parts[1:]:
            _validate_component(component)


class _Win32NativeBoundary:
    """Small ctypes-only native layer; construction is safe on non-Windows."""

    def __init__(self) -> None:
        self._api: _Kernel32 | None = None

    def _kernel(self) -> "_Kernel32":
        if os.name != "nt" or sys.platform != "win32":
            raise PlatformServiceError("platform_unsupported")
        if self._api is None:
            self._api = _Kernel32()
        return self._api

    def inspect_host(self, repository_path: Path | None) -> dict[str, object]:
        api = self._kernel()
        build = int(platform.version().split(".")[-1])
        path = Path.cwd() if repository_path is None else repository_path
        volume = api.volume_for_path(os.fspath(path))
        return {
            "system": platform.system().lower(),
            "architecture": platform.machine().lower(),
            "windows_build": build,
            "filesystem_type": volume[1].lower(),
            "drive_type": volume[2],
            "volume_flags": volume[3],
        }

    def open_repository(self, path: Path) -> _NativeRoot:
        api = self._kernel()
        handle = api.open_path(os.fspath(path), directory=True, write=True, create="open")
        try:
            info = api.object_info(handle)
            if info[0] != "directory" or info[3]:
                raise PlatformServiceError("invalid_root")
            final_path = api.final_path(handle)
            volume_root, filesystem, drive_type, flags = api.volume_for_path(final_path)
            if filesystem.lower() != "ntfs" or drive_type != "fixed" or flags:
                raise PlatformServiceError("filesystem_unsupported")
            return _NativeRoot(handle, final_path.rstrip("\\"), volume_root, info[2])
        except BaseException:
            api.close(handle)
            raise

    def close_root(self, token: _NativeRoot) -> None:
        if not token.closed:
            self._kernel().close(token.handle)
            token.closed = True

    def observe_object(self, root: _NativeRoot, relative_path: str) -> _NativeObject:
        api = self._kernel()
        self._assert_root(root)
        try:
            handle = api.open_beneath(root, relative_path, directory=None, write=False, create="open")
        except FileNotFoundError:
            absent = _digest_text("absent")
            return _NativeObject("absent", 0, 0, absent, absent)
        try:
            info = api.object_info(handle)
            if info[3]:
                kind = "reparse"
            else:
                kind = info[0]
            return _NativeObject(kind, info[1], info[4], info[2], info[2], link_count=info[6])
        finally:
            api.close(handle)

    def read_regular_file(self, root: _NativeRoot, relative_path: str, limit: int) -> tuple[_NativeObject, bytes]:
        api = self._kernel()
        self._assert_root(root)
        handle = api.open_beneath(root, relative_path, directory=False, write=False, create="open")
        try:
            before = api.object_info(handle)
            if before[0] != "regular" or before[3] or before[6] > 1:
                raise PlatformServiceError("not_regular")
            if before[1] > limit:
                raise PlatformServiceError("file_limit_exceeded")
            payload = api.read_bounded(handle, limit)
            after = api.object_info(handle)
            if before[2] != after[2] or before[1] != after[1]:
                raise PlatformServiceError("identity_changed")
            digest = _payload_digest(payload)
            return _NativeObject("regular", len(payload), before[4], before[2], before[2], digest), payload
        finally:
            api.close(handle)

    def enumerate_directory(self, root: _NativeRoot, relative_path: str, limit: int) -> tuple[tuple[EphemeralDirectoryEntry, ...], str]:
        api = self._kernel()
        self._assert_root(root)
        names = api.enumerate_beneath(root, relative_path, limit)
        entries: list[EphemeralDirectoryEntry] = []
        prefix = "" if relative_path == "." else relative_path + "/"
        for name in sorted(names, key=functools.cmp_to_key(_windows_compare)):
            observed = self.observe_object(root, prefix + name)
            if observed.kind == "reparse":
                raise PlatformServiceError("object_kind_unsupported")
            entries.append(EphemeralDirectoryEntry(name, observed.kind, observed.identity_digest))
        material = json.dumps([entry.name for entry in entries], ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        return tuple(entries), "sha256:" + hashlib.sha256(material).hexdigest()

    @contextlib.contextmanager
    def acquire_lock(self, root: _NativeRoot, relative_path: str, deadline: float, exclusive_create: bool) -> Iterator[None]:
        api = self._kernel()
        self._assert_root(root)
        parent = str(PurePosixPath(relative_path).parent)
        if parent != ".":
            api.create_directory_chain_beneath(root, parent)
        handle: int | None = None
        expires = time.monotonic() + deadline
        while handle is None:
            try:
                handle = api.open_beneath(root, relative_path, directory=False, write=True, create="new" if exclusive_create else "open_or_create", share=0)
            except FileExistsError as exc:
                raise PlatformServiceError("lock_timeout") from exc
            except PermissionError as exc:
                if time.monotonic() >= expires:
                    raise PlatformServiceError("lock_timeout") from exc
                time.sleep(0.01)
        try:
            api.flush(handle)
            yield
        finally:
            api.close(handle)
            if exclusive_create:
                api.delete_beneath(root, relative_path, expected_identity=None)
                api.flush(root.handle)

    def publish_file(self, operation: FilePublicationOperation, root: _NativeRoot) -> PublicationReceipt:
        api = self._kernel()
        self._assert_root(root)
        relative = _validate_relative_path(operation.relative_path)
        parent = str(PurePosixPath(relative).parent)
        target_name = PurePosixPath(relative).name
        created_parent: str | None = None
        if parent != ".":
            parent_observed = self.observe_object(root, parent)
            if operation.parent_policy == "create_managed_and_prune_if_empty_on_abort":
                if parent_observed.kind != operation.expected_parent_kind or parent_observed.stable_identity_digest != operation.expected_parent_identity:
                    raise PlatformServiceError("identity_changed")
            if parent_observed.kind == "absent":
                if operation.parent_policy != "create_managed_and_prune_if_empty_on_abort":
                    raise PlatformServiceError("not_directory")
                api.create_directory_beneath(root, parent)
                created_parent = parent
            elif parent_observed.kind != "directory":
                raise PlatformServiceError("not_directory")
        parent_handle = api.open_beneath(
            root,
            parent,
            directory=True,
            write=True,
            create="open",
        )
        parent_info = api.object_info(parent_handle)
        parent_root = _NativeRoot(
            parent_handle,
            api.final_path(parent_handle).rstrip("\\"),
            root.volume_root,
            parent_info[2],
        )
        temporary = ".sos-platform." + os.urandom(12).hex()
        temporary_handle: int | None = None
        temporary_identity: str | None = None
        source_published = False
        try:
            quarantine = _quarantine_name(target_name, operation.expected_payload)
            self._recover_file_quarantine(
                parent_root,
                target_name,
                quarantine,
                operation.expected_payload if operation.expected_existed else None,
            )

            initial_observation = self.observe_object(parent_root, target_name)
            current = self._read_optional(parent_root, target_name)
            if (current is not None) != operation.expected_existed or current != operation.expected_payload:
                raise PlatformServiceError("identity_changed")
            initial_identity = (
                initial_observation.stable_identity_digest
                if initial_observation.kind != "absent"
                else None
            )
            before = _payload_digest(current)
            if operation.payload is None:
                if current is not None:
                    api.delete_beneath(parent_root, target_name, initial_identity)
                    api.flush(parent_root.handle)
                return PublicationReceipt(_DURABILITY, "delete", relative, before, None)

            api.write_new_beneath(parent_root, temporary, operation.payload)
            temporary_handle = api.open_beneath(
                parent_root,
                temporary,
                directory=False,
                write=True,
                create="open",
            )
            target_handle: int | None = None
            try:
                staged_before = api.object_info(temporary_handle)
                temporary_identity = staged_before[2]
                if staged_before[0] != "regular" or staged_before[3] or staged_before[6] != 1:
                    raise PlatformServiceError("identity_changed")
                if api.read_bounded(temporary_handle, len(operation.payload)) != operation.payload:
                    raise PlatformServiceError("identity_changed")
                if api.object_info(temporary_handle)[2] != staged_before[2]:
                    raise PlatformServiceError("identity_changed")
                if operation.expected_existed:
                    target_handle = api.open_beneath(
                        parent_root,
                        target_name,
                        directory=False,
                        write=True,
                        create="open",
                    )
                    target_info = api.object_info(target_handle)
                    if target_info[2] != initial_identity:
                        raise PlatformServiceError("identity_changed")
                    if api.read_bounded(target_handle, len(operation.expected_payload or b"")) != operation.expected_payload:
                        raise PlatformServiceError("identity_changed")
                    try:
                        api.rename_open_beneath(
                            parent_root,
                            target_handle,
                            quarantine,
                            expected_source_identity=target_info[2],
                        )
                    except BaseException as quarantine_error:
                        self._stabilize_failed_quarantine_transition(
                            parent_root,
                            target_name,
                            quarantine,
                            target_handle,
                            target_info[2],
                        )
                        raise quarantine_error
                    try:
                        api.rename_open_beneath(
                            parent_root,
                            temporary_handle,
                            target_name,
                            expected_source_identity=staged_before[2],
                        )
                    except BaseException as publication_error:
                        try:
                            api.rename_open_beneath(
                                parent_root,
                                target_handle,
                                target_name,
                                expected_source_identity=target_info[2],
                            )
                            api.flush(parent_root.handle)
                        except BaseException as rollback_error:
                            raise PlatformServiceError("recovery_required") from rollback_error
                        raise publication_error
                    source_published = True
                    try:
                        api.flush(temporary_handle)
                        api.rewind(temporary_handle)
                        if api.object_info(temporary_handle)[2] != staged_before[2]:
                            raise PlatformServiceError("identity_changed")
                        if api.read_bounded(temporary_handle, len(operation.payload)) != operation.payload:
                            raise PlatformServiceError("identity_changed")
                        api.flush(parent_root.handle)
                        api.delete_open_handle(target_handle, target_info[2])
                        api.close(target_handle)
                        target_handle = None
                        api.flush(parent_root.handle)
                    except BaseException as cleanup_error:
                        raise PlatformServiceError("recovery_required") from cleanup_error
                    verb = "replace"
                else:
                    if self.observe_object(parent_root, target_name).kind != "absent":
                        raise PlatformServiceError("collision")
                    api.rename_open_beneath(
                        parent_root,
                        temporary_handle,
                        target_name,
                        expected_source_identity=staged_before[2],
                    )
                    source_published = True
                    api.flush(temporary_handle)
                    api.rewind(temporary_handle)
                    if api.object_info(temporary_handle)[2] != staged_before[2]:
                        raise PlatformServiceError("identity_changed")
                    if api.read_bounded(temporary_handle, len(operation.payload)) != operation.payload:
                        raise PlatformServiceError("identity_changed")
                    api.flush(parent_root.handle)
                    verb = "create"
            finally:
                if target_handle is not None:
                    api.close(target_handle)
                if temporary_handle is not None:
                    api.close(temporary_handle)
                    temporary_handle = None
            return PublicationReceipt(_DURABILITY, verb, relative, before, _payload_digest(operation.payload))
        except BaseException as primary_error:
            if not source_published:
                try:
                    if temporary_handle is not None and temporary_identity is not None:
                        api.delete_open_handle(temporary_handle, temporary_identity)
                        api.close(temporary_handle)
                        temporary_handle = None
                    elif temporary_identity is not None:
                        api.delete_beneath(
                            parent_root,
                            temporary,
                            expected_identity=temporary_identity,
                        )
                    api.flush(parent_root.handle)
                except FileNotFoundError:
                    pass
                except BaseException as cleanup_error:
                    raise PlatformServiceError("recovery_required") from cleanup_error
            if created_parent is not None:
                try:
                    api.prune_empty_beneath(root, created_parent)
                except BaseException as cleanup_error:
                    raise PlatformServiceError("recovery_required") from cleanup_error
            raise primary_error
        finally:
            if temporary_handle is not None:
                api.close(temporary_handle)
            api.close(parent_handle)

    def _stabilize_failed_quarantine_transition(
        self,
        parent_root: _NativeRoot,
        target_name: str,
        quarantine: str,
        target_handle: int,
        expected_identity: str,
    ) -> None:
        """Restore a completed rename or fail closed with its residue intact."""

        api = self._kernel()
        try:
            if api.object_info(target_handle)[2] != expected_identity:
                raise PlatformServiceError("recovery_required")
            target = self.observe_object(parent_root, target_name)
            residue = self.observe_object(parent_root, quarantine)
            target_matches = (
                target.kind == "regular"
                and target.stable_identity_digest == expected_identity
            )
            residue_matches = (
                residue.kind == "regular"
                and residue.stable_identity_digest == expected_identity
            )
            if target_matches and residue.kind == "absent":
                return
            if target.kind != "absent" or not residue_matches:
                raise PlatformServiceError("recovery_required")
            api.rename_open_beneath(
                parent_root,
                target_handle,
                target_name,
                expected_source_identity=expected_identity,
            )
            api.flush(parent_root.handle)
            restored = self.observe_object(parent_root, target_name)
            remaining = self.observe_object(parent_root, quarantine)
            if (
                api.object_info(target_handle)[2] != expected_identity
                or restored.kind != "regular"
                or restored.stable_identity_digest != expected_identity
                or remaining.kind != "absent"
            ):
                raise PlatformServiceError("recovery_required")
        except PlatformServiceError as exc:
            if exc.kind == "recovery_required":
                raise
            raise PlatformServiceError("recovery_required") from exc
        except BaseException as exc:
            raise PlatformServiceError("recovery_required") from exc

    def _recover_file_quarantine(
        self,
        parent_root: _NativeRoot,
        target_name: str,
        quarantine: str,
        expected_payload: bytes | None,
    ) -> None:
        api = self._kernel()
        try:
            residues = tuple(
                name
                for name in api.enumerate_beneath(parent_root, ".", 8192)
                if name.lower().startswith(".sos-quarantine.")
            )
        except BaseException as exc:
            raise PlatformServiceError("recovery_required") from exc
        if not residues:
            return
        if (
            len(residues) != 1
            or not _windows_equal(residues[0], quarantine)
            or residues[0] != quarantine
            or expected_payload is None
            or self.observe_object(parent_root, target_name).kind != "absent"
        ):
            raise PlatformServiceError("recovery_required")
        handle: int | None = None
        try:
            handle = api.open_beneath(
                parent_root,
                quarantine,
                directory=False,
                write=True,
                create="open",
            )
            observed = api.object_info(handle)
            if observed[0] != "regular" or observed[3] or observed[6] != 1:
                raise PlatformServiceError("recovery_required")
            if api.read_bounded(handle, len(expected_payload)) != expected_payload:
                raise PlatformServiceError("recovery_required")
            if api.object_info(handle)[2] != observed[2]:
                raise PlatformServiceError("recovery_required")
            api.rename_open_beneath(
                parent_root,
                handle,
                target_name,
                expected_source_identity=observed[2],
            )
            api.flush(handle)
            api.flush(parent_root.handle)
            api.rewind(handle)
            if api.object_info(handle)[2] != observed[2]:
                raise PlatformServiceError("recovery_required")
            if api.read_bounded(handle, len(expected_payload)) != expected_payload:
                raise PlatformServiceError("recovery_required")
        except PlatformServiceError as exc:
            if exc.kind == "recovery_required":
                raise
            raise PlatformServiceError("recovery_required") from exc
        except BaseException as exc:
            raise PlatformServiceError("recovery_required") from exc
        finally:
            if handle is not None:
                api.close(handle)

    def publish_tree(self, operation: TreePublicationOperation, root: _NativeRoot) -> PublicationReceipt:
        self._assert_root(root)
        if operation.action == "create":
            capability = self._create_staging(root, operation)
            verb = "stage_tree"
        elif operation.action == "recover":
            capability = self._recover_staging(root, operation)
            verb = "recover_tree"
        else:
            capability = self._require_staging(root, operation)
            token = capability._platform_token()
            if not isinstance(token, _NativeStaging):
                raise PlatformServiceError("staging_recovery_required")
            staging_root = self._staging_root(token)
            if operation.action == "extend":
                self._write_tree_files(staging_root, operation.files)
                self._kernel().flush(token.handle)
                verb = "extend_tree"
            elif operation.action == "commit":
                self._kernel().delete_beneath(
                    staging_root,
                    _STAGING_MARKER,
                    expected_identity=None,
                )
                self._kernel().flush(token.handle)
                self._assert_staging_identity(capability)
                self._kernel().rename_open_beneath(
                    root,
                    token.handle,
                    operation.target_name,
                    expected_source_identity=token.identity_digest,
                )
                self._kernel().flush(root.handle)
                capability.consume("commit")
                capability = None
                verb = "create_tree"
            elif operation.action == "discard":
                self._discard_staging(staging_root, token)
                self._kernel().flush(root.handle)
                capability.consume("discard")
                capability = None
                verb = "discard_tree"
            else:
                raise PlatformServiceError("publication_failed")
        return PublicationReceipt(_DURABILITY, verb, operation.target_name, None, None, capability)

    def observe_launcher(self, client_id: str) -> EphemeralLauncherObservation:
        if client_id == "git":
            executable_text = shutil.which("git")
            if executable_text is None:
                raise PlatformServiceError("launcher_unsupported")
            executable = Path(executable_text)
            return EphemeralLauncherObservation(
                executable,
                "system",
                self._sha256_file(executable, _MAX_LAUNCHER_BYTES),
            )
        if client_id != "codex":
            raise PlatformServiceError("launcher_unsupported")
        executable = self._canonical_python_executable()
        digest = self._sha256_file(executable, _MAX_LAUNCHER_BYTES)
        try:
            version = metadata.version("sigma-operator-stack")
            distribution = metadata.distribution("sigma-operator-stack")
        except metadata.PackageNotFoundError as exc:
            raise PlatformServiceError("launcher_invalid") from exc
        direct_url = distribution.read_text("direct_url.json")
        editable = False
        if direct_url:
            try:
                direct = json.loads(direct_url)
            except json.JSONDecodeError as exc:
                raise PlatformServiceError("package_identity_invalid") from exc
            editable = (
                isinstance(direct, dict)
                and isinstance(direct.get("dir_info"), dict)
                and direct["dir_info"].get("editable") is True
            )
        return EphemeralLauncherObservation(executable, version, digest, editable)

    def _create_staging(self, root: _NativeRoot, operation: TreePublicationOperation) -> TreeStagingCapability:
        if self.observe_object(root, operation.target_name).kind != "absent" or self.observe_object(root, operation.staging_name).kind != "absent":
            raise PlatformServiceError("collision")
        recovery = operation.recovery_binding_digest or _NONE_RECOVERY_BINDING
        transaction = _transaction_id(operation.staging_name)
        api = self._kernel()
        handle = api.create_directory_handle_beneath(root, operation.staging_name)
        try:
            staging = _NativeStaging(handle, root, operation.staging_name, operation.target_name, api.object_info(handle)[2], "", transaction, recovery)
            staging_root = self._staging_root(staging)
            marker = {
                "contract": "sos_staging_binding_v1",
                "root_identity_digest": root.identity_digest,
                "transaction_id": transaction,
                "staging_name": operation.staging_name,
                "target_name": operation.target_name,
                "staging_identity_digest": staging.identity_digest,
                "recovery_binding_digest": recovery,
                "binding_nonce": os.urandom(32).hex(),
            }
            marker["binding_digest"] = _binding_digest(marker)
            staging.binding_digest = str(marker["binding_digest"])
            api.write_new_beneath(staging_root, _STAGING_MARKER, _canonical_json(marker))
            self._write_tree_files(staging_root, operation.files)
            api.flush(handle)
            return self._capability(staging)
        except BaseException:
            api.close(handle)
            raise

    def _recover_staging(self, root: _NativeRoot, operation: TreePublicationOperation) -> TreeStagingCapability:
        recovery = operation.recovery_binding_digest
        if recovery is None:
            raise PlatformServiceError("staging_recovery_required")
        api = self._kernel()
        handle = api.open_beneath(root, operation.staging_name, directory=True, write=True, create="open")
        try:
            identity = api.object_info(handle)[2]
            staging = _NativeStaging(
                handle,
                root,
                operation.staging_name,
                operation.target_name,
                identity,
                "",
                _transaction_id(operation.staging_name),
                recovery,
            )
            marker_payload = self.read_regular_file(
                self._staging_root(staging),
                _STAGING_MARKER,
                64 * 1024,
            )[1]
            marker = json.loads(marker_payload.decode("utf-8"))
            expected = {
                "contract": "sos_staging_binding_v1",
                "root_identity_digest": root.identity_digest,
                "transaction_id": _transaction_id(operation.staging_name),
                "staging_name": operation.staging_name,
                "target_name": operation.target_name,
                "staging_identity_digest": identity,
                "recovery_binding_digest": recovery,
                "binding_nonce": marker.get("binding_nonce"),
            }
            expected["binding_digest"] = _binding_digest(expected)
            if marker != expected:
                raise PlatformServiceError("staging_recovery_required")
            staging.binding_digest = str(expected["binding_digest"])
            return self._capability(staging)
        except (UnicodeError, json.JSONDecodeError, TypeError, ValueError) as exc:
            api.close(handle)
            raise PlatformServiceError("staging_recovery_required") from exc
        except BaseException:
            api.close(handle)
            raise

    def _require_staging(self, root: _NativeRoot, operation: TreePublicationOperation) -> TreeStagingCapability:
        capability = operation.capability
        if capability is None:
            raise PlatformServiceError("staging_recovery_required")
        token = capability._platform_token()
        if not isinstance(token, _NativeStaging) or token.closed or token.root is not root:
            raise PlatformServiceError("staging_recovery_required")
        if token.staging_name != operation.staging_name or token.target_name != operation.target_name or capability.root_identity_digest != root.identity_digest:
            raise PlatformServiceError("staging_identity_changed")
        self._assert_staging(capability)
        return capability

    def _assert_staging(self, capability: TreeStagingCapability) -> None:
        token = capability._platform_token()
        if not isinstance(token, _NativeStaging) or token.closed:
            raise PlatformServiceError("staging_recovery_required")
        api = self._kernel()
        if api.object_info(token.handle)[2] != token.identity_digest:
            raise PlatformServiceError("staging_identity_changed")
        try:
            marker = json.loads(
                self.read_regular_file(
                    self._staging_root(token),
                    _STAGING_MARKER,
                    64 * 1024,
                )[1].decode("utf-8")
            )
        except (UnicodeError, json.JSONDecodeError, TypeError, ValueError) as exc:
            raise PlatformServiceError("staging_identity_changed") from exc
        if marker.get("binding_digest") != token.binding_digest or _binding_digest({key: value for key, value in marker.items() if key != "binding_digest"}) != token.binding_digest:
            raise PlatformServiceError("staging_identity_changed")

    def _assert_staging_identity(self, capability: TreeStagingCapability) -> None:
        token = capability._platform_token()
        if not isinstance(token, _NativeStaging) or token.closed:
            raise PlatformServiceError("staging_recovery_required")
        if self._kernel().object_info(token.handle)[2] != token.identity_digest:
            raise PlatformServiceError("staging_identity_changed")

    def _write_tree_files(self, staging_root: _NativeRoot, files: tuple[tuple[str, bytes], ...]) -> None:
        api = self._kernel()
        for relative, payload in files:
            parent = str(PurePosixPath(relative).parent)
            if parent != ".":
                api.create_directory_chain_beneath(staging_root, parent)
            api.write_new_beneath(staging_root, relative, payload)
            api.flush_parent(staging_root, relative)
        api.flush(staging_root.handle)

    def _staging_root(self, token: _NativeStaging) -> _NativeRoot:
        if token.closed:
            raise PlatformServiceError("staging_recovery_required")
        return _NativeRoot(
            token.handle,
            self._kernel().final_path(token.handle).rstrip("\\"),
            token.root.volume_root,
            token.identity_digest,
        )

    def _discard_staging(self, staging_root: _NativeRoot, token: _NativeStaging) -> None:
        api = self._kernel()
        if api.object_info(token.handle)[2] != token.identity_digest:
            raise PlatformServiceError("staging_identity_changed")
        api.discard_open_tree(staging_root, token.identity_digest)

    def _capability(self, token: _NativeStaging) -> TreeStagingCapability:
        return TreeStagingCapability(
            token.root.identity_digest,
            token.transaction_id,
            token.staging_name,
            token.target_name,
            token.identity_digest,
            token.recovery_binding_digest,
            token.binding_digest,
            token,
            self._close_staging,
        )

    def _close_staging(self, token: object) -> None:
        if not isinstance(token, _NativeStaging):
            raise PlatformServiceError("staging_recovery_required")
        if not token.closed:
            self._kernel().close(token.handle)
            token.closed = True

    def _assert_root(self, root: _NativeRoot) -> None:
        if root.closed or self._kernel().object_info(root.handle)[2] != root.identity_digest:
            raise PlatformServiceError("invalid_root")

    def _read_optional(self, root: _NativeRoot, relative: str) -> bytes | None:
        try:
            return self.read_regular_file(root, relative, 16 * 1024 * 1024)[1]
        except FileNotFoundError:
            return None
        except PlatformServiceError as exc:
            if exc.kind == "not_found":
                return None
            raise

    @staticmethod
    def _canonical_python_executable() -> Path:
        return Path(sys.executable)

    @staticmethod
    def _sha256_file(path: Path, limit: int) -> str:
        observed = path.stat()
        if observed.st_size > limit:
            raise PlatformServiceError("launcher_invalid")
        hasher = hashlib.sha256()
        with path.open("rb") as stream:
            for chunk in iter(lambda: stream.read(64 * 1024), b""):
                hasher.update(chunk)
        return "sha256:" + hasher.hexdigest()


class _Kernel32:
    """Minimal fail-closed Win32 primitives used only inside the adapter."""

    INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value
    GENERIC_READ = 0x80000000
    GENERIC_WRITE = 0x40000000
    SYNCHRONIZE = 0x00100000
    FILE_READ_DATA = 0x0001
    FILE_WRITE_DATA = 0x0002
    FILE_APPEND_DATA = 0x0004
    FILE_READ_ATTRIBUTES = 0x0080
    FILE_WRITE_ATTRIBUTES = 0x0100
    DELETE = 0x00010000
    FILE_SHARE_READ = 1
    FILE_SHARE_WRITE = 2
    FILE_SHARE_DELETE = 4
    OPEN_EXISTING = 3
    OPEN_ALWAYS = 4
    CREATE_NEW = 1
    FILE_OPEN = 1
    FILE_CREATE = 2
    FILE_OPEN_IF = 3
    FILE_DIRECTORY_FILE = 0x00000001
    FILE_SYNCHRONOUS_IO_NONALERT = 0x00000020
    FILE_NON_DIRECTORY_FILE = 0x00000040
    OBJ_CASE_INSENSITIVE = 0x00000040
    OBJ_DONT_REPARSE = 0x00001000
    FILE_FLAG_BACKUP_SEMANTICS = 0x02000000
    FILE_FLAG_OPEN_REPARSE_POINT = 0x00200000
    FILE_FLAG_WRITE_THROUGH = 0x80000000
    FILE_ATTRIBUTE_NORMAL = 0x80
    FILE_ATTRIBUTE_DIRECTORY = 0x10
    FILE_ATTRIBUTE_REPARSE_POINT = 0x400
    FILE_ATTRIBUTE_OFFLINE = 0x1000
    FILE_ATTRIBUTE_RECALL_ON_OPEN = 0x00040000
    FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS = 0x00400000
    FILE_DISPOSITION_INFO_EX = 21
    FILE_DISPOSITION_FLAG_DELETE = 0x00000001
    FILE_DISPOSITION_FLAG_POSIX_SEMANTICS = 0x00000002
    FILE_DISPOSITION_FLAG_ON_CLOSE = 0x00000008
    FILE_DISPOSITION_FLAG_IGNORE_READONLY_ATTRIBUTE = 0x00000010
    FILE_RENAME_INFO_EX = 22
    FILE_ID_BOTH_DIRECTORY_INFO = 10
    FILE_ID_BOTH_DIRECTORY_RESTART_INFO = 11
    DRIVE_FIXED = 3

    def __init__(self) -> None:
        loader = getattr(ctypes, "WinDLL", None)
        if loader is None:
            raise PlatformServiceError("platform_unsupported")
        self.kernel32 = loader("kernel32", use_last_error=True)
        self.ntdll = loader("ntdll")
        self.kernel32.CreateFileW.restype = ctypes.c_void_p
        self.kernel32.CreateFileW.argtypes = [
            ctypes.c_wchar_p,
            ctypes.c_uint32,
            ctypes.c_uint32,
            ctypes.c_void_p,
            ctypes.c_uint32,
            ctypes.c_uint32,
            ctypes.c_void_p,
        ]
        self.kernel32.CloseHandle.restype = ctypes.c_int
        self.kernel32.CloseHandle.argtypes = [ctypes.c_void_p]
        self.kernel32.FlushFileBuffers.restype = ctypes.c_int
        self.kernel32.FlushFileBuffers.argtypes = [ctypes.c_void_p]
        self.kernel32.GetFileInformationByHandle.restype = ctypes.c_int
        self.kernel32.GetFileInformationByHandle.argtypes = [ctypes.c_void_p, ctypes.c_void_p]
        self.kernel32.GetFileInformationByHandleEx.restype = ctypes.c_int
        self.kernel32.GetFileInformationByHandleEx.argtypes = [
            ctypes.c_void_p,
            ctypes.c_int,
            ctypes.c_void_p,
            ctypes.c_uint32,
        ]
        self.kernel32.GetFinalPathNameByHandleW.restype = ctypes.c_uint32
        self.kernel32.GetFinalPathNameByHandleW.argtypes = [
            ctypes.c_void_p,
            ctypes.c_wchar_p,
            ctypes.c_uint32,
            ctypes.c_uint32,
        ]
        self.kernel32.ReadFile.restype = ctypes.c_int
        self.kernel32.ReadFile.argtypes = [
            ctypes.c_void_p,
            ctypes.c_void_p,
            ctypes.c_uint32,
            ctypes.c_void_p,
            ctypes.c_void_p,
        ]
        self.kernel32.WriteFile.restype = ctypes.c_int
        self.kernel32.WriteFile.argtypes = list(self.kernel32.ReadFile.argtypes)
        self.kernel32.SetFilePointerEx.restype = ctypes.c_int
        self.kernel32.SetFilePointerEx.argtypes = [
            ctypes.c_void_p,
            ctypes.c_int64,
            ctypes.c_void_p,
            ctypes.c_uint32,
        ]
        self.kernel32.GetCurrentProcess.restype = ctypes.c_void_p
        self.kernel32.DuplicateHandle.restype = ctypes.c_int
        self.kernel32.DuplicateHandle.argtypes = [
            ctypes.c_void_p,
            ctypes.c_void_p,
            ctypes.c_void_p,
            ctypes.c_void_p,
            ctypes.c_uint32,
            ctypes.c_int,
            ctypes.c_uint32,
        ]
        self.kernel32.SetFileInformationByHandle.restype = ctypes.c_int
        self.kernel32.SetFileInformationByHandle.argtypes = [
            ctypes.c_void_p,
            ctypes.c_int,
            ctypes.c_void_p,
            ctypes.c_uint32,
        ]
        self.kernel32.GetVolumePathNameW.restype = ctypes.c_int
        self.kernel32.GetVolumePathNameW.argtypes = [
            ctypes.c_wchar_p,
            ctypes.c_wchar_p,
            ctypes.c_uint32,
        ]
        self.kernel32.GetVolumeInformationW.restype = ctypes.c_int
        self.kernel32.GetVolumeInformationW.argtypes = [
            ctypes.c_wchar_p,
            ctypes.c_wchar_p,
            ctypes.c_uint32,
            ctypes.c_void_p,
            ctypes.c_void_p,
            ctypes.c_void_p,
            ctypes.c_wchar_p,
            ctypes.c_uint32,
        ]
        self.kernel32.GetDriveTypeW.restype = ctypes.c_uint32
        self.kernel32.GetDriveTypeW.argtypes = [ctypes.c_wchar_p]
        self.ntdll.NtCreateFile.restype = ctypes.c_long

    def open_path(self, path: str, *, directory: bool | None, write: bool, create: str, share: int | None = None) -> int:
        desired = self.GENERIC_READ | (self.GENERIC_WRITE if write else 0)
        disposition = {"open": self.OPEN_EXISTING, "new": self.CREATE_NEW, "open_or_create": self.OPEN_ALWAYS}[create]
        flags = self.FILE_FLAG_OPEN_REPARSE_POINT | (self.FILE_FLAG_BACKUP_SEMANTICS if directory is not False else 0)
        share_mode = self.FILE_SHARE_READ | self.FILE_SHARE_WRITE | self.FILE_SHARE_DELETE if share is None else share
        handle = self.kernel32.CreateFileW(path, desired, share_mode, None, disposition, flags, None)
        if handle == self.INVALID_HANDLE_VALUE:
            error = ctypes.get_last_error()
            if error in {2, 3}:
                raise FileNotFoundError(path)
            if error in {5, 32, 33}:
                raise PermissionError(path)
            if error in {80, 183}:
                raise FileExistsError(path)
            raise PlatformServiceError("publication_failed" if write else "read_failed")
        return int(handle)

    def open_beneath(self, root: _NativeRoot, relative: str, *, directory: bool | None, write: bool, create: str, share: int | None = None) -> int:
        if relative == ".":
            if create != "open":
                raise PlatformServiceError("publication_failed")
            handle = self.duplicate(root.handle)
        else:
            handle = self._nt_open_relative(
                root.handle,
                relative.replace("/", "\\"),
                directory=directory,
                write=write,
                create=create,
                share=share,
            )
        try:
            final = self.final_path(handle)
            if relative != "." and not _windows_path_is_beneath(root.final_path, final):
                raise PlatformServiceError("object_kind_unsupported")
            info = self.object_info(handle)
            if info[3]:
                raise PlatformServiceError("object_kind_unsupported")
            if info[5]:
                raise PlatformServiceError("cloud_placeholder_unsupported")
            return handle
        except BaseException:
            self.close(handle)
            raise

    def _nt_open_relative(
        self,
        root_handle: int,
        relative: str,
        *,
        directory: bool | None,
        write: bool,
        create: str,
        share: int | None,
    ) -> int:
        class UNICODE_STRING(ctypes.Structure):
            _fields_ = [
                ("Length", ctypes.c_ushort),
                ("MaximumLength", ctypes.c_ushort),
                ("Buffer", ctypes.c_wchar_p),
            ]

        class OBJECT_ATTRIBUTES(ctypes.Structure):
            _fields_ = [
                ("Length", ctypes.c_uint32),
                ("RootDirectory", ctypes.c_void_p),
                ("ObjectName", ctypes.POINTER(UNICODE_STRING)),
                ("Attributes", ctypes.c_uint32),
                ("SecurityDescriptor", ctypes.c_void_p),
                ("SecurityQualityOfService", ctypes.c_void_p),
            ]

        class IO_STATUS_BLOCK(ctypes.Structure):
            _fields_ = [("Status", ctypes.c_void_p), ("Information", ctypes.c_size_t)]

        buffer = ctypes.create_unicode_buffer(relative)
        name = UNICODE_STRING(
            len(relative.encode("utf-16-le")),
            len(relative.encode("utf-16-le")) + 2,
            ctypes.cast(buffer, ctypes.c_wchar_p),
        )
        attributes = OBJECT_ATTRIBUTES(
            ctypes.sizeof(OBJECT_ATTRIBUTES),
            ctypes.c_void_p(root_handle),
            ctypes.pointer(name),
            self.OBJ_CASE_INSENSITIVE | self.OBJ_DONT_REPARSE,
            None,
            None,
        )
        io_status = IO_STATUS_BLOCK()
        handle = ctypes.c_void_p()
        access = self.SYNCHRONIZE | self.FILE_READ_ATTRIBUTES | self.FILE_READ_DATA
        if write:
            access |= self.FILE_WRITE_DATA | self.FILE_APPEND_DATA | self.FILE_WRITE_ATTRIBUTES | self.DELETE
        share_mode = self.FILE_SHARE_READ | self.FILE_SHARE_WRITE | self.FILE_SHARE_DELETE if share is None else share
        disposition = {"open": self.FILE_OPEN, "new": self.FILE_CREATE, "open_or_create": self.FILE_OPEN_IF}[create]
        options = self.FILE_OPEN_REPARSE_POINT | self.FILE_SYNCHRONOUS_IO_NONALERT
        if directory is True:
            options |= self.FILE_DIRECTORY_FILE
        elif directory is False:
            options |= self.FILE_NON_DIRECTORY_FILE
        status = self.ntdll.NtCreateFile(
            ctypes.byref(handle),
            access,
            ctypes.byref(attributes),
            ctypes.byref(io_status),
            None,
            self.FILE_ATTRIBUTE_NORMAL,
            share_mode,
            disposition,
            options,
            None,
            0,
        )
        unsigned = ctypes.c_uint32(status).value
        if unsigned & 0x80000000:
            if unsigned in {0xC0000034, 0xC000003A}:
                raise FileNotFoundError(relative)
            if unsigned == 0xC0000035:
                raise FileExistsError(relative)
            if unsigned in {0xC0000022, 0xC0000043}:
                raise PermissionError(relative)
            if unsigned in {0xC000050B, 0xC0000275}:
                raise PlatformServiceError("object_kind_unsupported")
            raise PlatformServiceError("publication_failed" if write else "read_failed")
        if not handle.value:
            raise PlatformServiceError("publication_failed" if write else "read_failed")
        return int(handle.value)

    def duplicate(self, handle: int) -> int:
        process = self.kernel32.GetCurrentProcess()
        duplicate = ctypes.c_void_p()
        if not self.kernel32.DuplicateHandle(
            process,
            ctypes.c_void_p(handle),
            process,
            ctypes.byref(duplicate),
            0,
            False,
            0x00000002,
        ) or not duplicate.value:
            raise PlatformServiceError("observation_failed")
        return int(duplicate.value)

    def object_info(self, handle: int) -> tuple[str, int, str, bool, int, bool, int]:
        class FILETIME(ctypes.Structure):
            _fields_ = [("dwLowDateTime", ctypes.c_uint32), ("dwHighDateTime", ctypes.c_uint32)]

        class BY_HANDLE_FILE_INFORMATION(ctypes.Structure):
            _fields_ = [
                ("dwFileAttributes", ctypes.c_uint32),
                ("ftCreationTime", FILETIME),
                ("ftLastAccessTime", FILETIME),
                ("ftLastWriteTime", FILETIME),
                ("dwVolumeSerialNumber", ctypes.c_uint32),
                ("nFileSizeHigh", ctypes.c_uint32),
                ("nFileSizeLow", ctypes.c_uint32),
                ("nNumberOfLinks", ctypes.c_uint32),
                ("nFileIndexHigh", ctypes.c_uint32),
                ("nFileIndexLow", ctypes.c_uint32),
            ]
        info = BY_HANDLE_FILE_INFORMATION()
        if not self.kernel32.GetFileInformationByHandle(handle, ctypes.byref(info)):
            raise PlatformServiceError("observation_failed")
        attributes = info.dwFileAttributes
        kind = "directory" if attributes & self.FILE_ATTRIBUTE_DIRECTORY else "regular"
        size = (info.nFileSizeHigh << 32) | info.nFileSizeLow
        identity = self.file_identity(handle)
        reparse = bool(attributes & self.FILE_ATTRIBUTE_REPARSE_POINT)
        placeholder = bool(attributes & (self.FILE_ATTRIBUTE_OFFLINE | self.FILE_ATTRIBUTE_RECALL_ON_OPEN | self.FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS))
        mode = 0o755 if kind == "directory" else 0o644
        return kind, size, identity, reparse, mode, placeholder, info.nNumberOfLinks

    def file_identity(self, handle: int) -> str:
        class FILE_ID_128(ctypes.Structure):
            _fields_ = [("Identifier", ctypes.c_ubyte * 16)]

        class FILE_ID_INFO(ctypes.Structure):
            _fields_ = [("VolumeSerialNumber", ctypes.c_uint64), ("FileId", FILE_ID_128)]

        info = FILE_ID_INFO()
        if not self.kernel32.GetFileInformationByHandleEx(
            handle, 18, ctypes.byref(info), ctypes.sizeof(info)
        ):
            raise PlatformServiceError("observation_failed")
        material = info.VolumeSerialNumber.to_bytes(8, "little") + bytes(info.FileId.Identifier)
        return "sha256:" + hashlib.sha256(material).hexdigest()

    def final_path(self, handle: int) -> str:
        required = self.kernel32.GetFinalPathNameByHandleW(handle, None, 0, 0)
        if not required or required > 32768:
            raise PlatformServiceError("observation_failed")
        buffer = ctypes.create_unicode_buffer(required + 1)
        written = self.kernel32.GetFinalPathNameByHandleW(handle, buffer, len(buffer), 0)
        if not written or written >= len(buffer):
            raise PlatformServiceError("observation_failed")
        value = buffer.value
        return value[4:] if value.startswith("\\\\?\\") else value

    def volume_for_path(self, path: str) -> tuple[str, str, str, frozenset[str]]:
        volume_buffer = ctypes.create_unicode_buffer(32768)
        if not self.kernel32.GetVolumePathNameW(path, volume_buffer, len(volume_buffer)):
            raise PlatformServiceError("filesystem_unsupported")
        volume = volume_buffer.value
        fs_buffer = ctypes.create_unicode_buffer(64)
        flags = ctypes.c_uint32()
        if not self.kernel32.GetVolumeInformationW(volume, None, 0, None, None, ctypes.byref(flags), fs_buffer, len(fs_buffer)):
            raise PlatformServiceError("filesystem_unsupported")
        drive = self.kernel32.GetDriveTypeW(volume)
        drive_type = "fixed" if drive == self.DRIVE_FIXED else "unsupported"
        return volume, fs_buffer.value, drive_type, frozenset()

    def read_bounded(self, handle: int, limit: int) -> bytes:
        chunks: list[bytes] = []
        total = 0
        while True:
            buffer = ctypes.create_string_buffer(min(64 * 1024, limit + 1 - total))
            read = ctypes.c_uint32()
            if not self.kernel32.ReadFile(handle, buffer, len(buffer), ctypes.byref(read), None):
                raise PlatformServiceError("read_failed")
            if read.value == 0:
                break
            total += read.value
            if total > limit:
                raise PlatformServiceError("file_limit_exceeded")
            chunks.append(buffer.raw[: read.value])
        return b"".join(chunks)

    def rewind(self, handle: int) -> None:
        if not self.kernel32.SetFilePointerEx(handle, 0, None, 0):
            raise PlatformServiceError("read_failed")

    def enumerate_beneath(self, root: _NativeRoot, relative: str, limit: int) -> list[str]:
        handle = self.open_beneath(root, relative, directory=True, write=False, create="open")
        try:
            before = self.object_info(handle)[2]
            names = self.enumerate_handle(handle, limit)
            if self.object_info(handle)[2] != before:
                raise PlatformServiceError("identity_changed")
            return names
        finally:
            self.close(handle)

    def enumerate_handle(self, handle: int, limit: int) -> list[str]:
        names: list[str] = []
        restart = True
        while True:
            buffer = ctypes.create_string_buffer(64 * 1024)
            information_class = (
                self.FILE_ID_BOTH_DIRECTORY_RESTART_INFO
                if restart
                else self.FILE_ID_BOTH_DIRECTORY_INFO
            )
            if not self.kernel32.GetFileInformationByHandleEx(
                handle,
                information_class,
                buffer,
                len(buffer),
            ):
                error = ctypes.get_last_error()
                if error == 18:
                    break
                raise PlatformServiceError("observation_failed")
            restart = False
            offset = 0
            while True:
                next_offset = ctypes.c_uint32.from_buffer(buffer, offset).value
                name_length = ctypes.c_uint32.from_buffer(buffer, offset + 60).value
                if name_length > len(buffer) - offset - 104 or name_length % 2:
                    raise PlatformServiceError("observation_failed")
                name = bytes(buffer[offset + 104 : offset + 104 + name_length]).decode(
                    "utf-16-le",
                    errors="strict",
                )
                if name not in {".", ".."}:
                    names.append(name)
                    if len(names) > limit:
                        raise PlatformServiceError("directory_limit_exceeded")
                if next_offset == 0:
                    break
                if next_offset < 104 or offset + next_offset >= len(buffer):
                    raise PlatformServiceError("observation_failed")
                offset += next_offset
        return names

    def write_new_beneath(self, root: _NativeRoot, relative: str, payload: bytes) -> None:
        handle = self.open_beneath(root, relative, directory=False, write=True, create="new")
        try:
            offset = 0
            while offset < len(payload):
                written = ctypes.c_uint32()
                chunk = payload[offset : offset + 64 * 1024]
                buffer = ctypes.create_string_buffer(chunk)
                if not self.kernel32.WriteFile(handle, buffer, len(chunk), ctypes.byref(written), None) or written.value == 0:
                    raise PlatformServiceError("publication_failed")
                offset += written.value
            self.flush(handle)
        finally:
            self.close(handle)

    def rename_open_beneath(
        self,
        root: _NativeRoot,
        source_handle: int,
        target: str,
        *,
        expected_source_identity: str,
    ) -> None:
        if self.object_info(source_handle)[2] != expected_source_identity:
            raise PlatformServiceError("identity_changed")
        encoded = target.replace("/", "\\").encode("utf-16-le")

        class FILE_RENAME_INFO_HEADER(ctypes.Structure):
            _fields_ = [
                ("Flags", ctypes.c_uint32),
                ("RootDirectory", ctypes.c_void_p),
                ("FileNameLength", ctypes.c_uint32),
            ]

        name_offset = FILE_RENAME_INFO_HEADER.FileNameLength.offset + ctypes.sizeof(
            ctypes.c_uint32
        )
        buffer = ctypes.create_string_buffer(name_offset + len(encoded))
        header = FILE_RENAME_INFO_HEADER.from_buffer(buffer)
        header.Flags = 0
        header.RootDirectory = ctypes.c_void_p(root.handle)
        header.FileNameLength = len(encoded)
        ctypes.memmove(ctypes.addressof(buffer) + name_offset, encoded, len(encoded))
        if not self.kernel32.SetFileInformationByHandle(
            source_handle,
            self.FILE_RENAME_INFO_EX,
            buffer,
            len(buffer),
        ):
            error = ctypes.get_last_error()
            if error in {80, 183}:
                raise PlatformServiceError("collision")
            raise PlatformServiceError("publication_failed")
        if self.object_info(source_handle)[2] != expected_source_identity:
            raise PlatformServiceError("identity_changed")

    def delete_beneath(self, root: _NativeRoot, relative: str, expected_identity: str | None) -> None:
        try:
            handle = self.open_beneath(root, relative, directory=False, write=True, create="open")
        except FileNotFoundError:
            raise
        try:
            if expected_identity is not None and self.object_info(handle)[2] != expected_identity:
                raise PlatformServiceError("identity_changed")
            self._delete_handle(handle)
        finally:
            self.close(handle)

    def delete_open_handle(self, handle: int, expected_identity: str) -> None:
        if self.object_info(handle)[2] != expected_identity:
            raise PlatformServiceError("identity_changed")
        self._delete_handle(handle)

    def create_directory_handle_beneath(self, root: _NativeRoot, relative: str) -> int:
        try:
            return self.open_beneath(
                root,
                relative,
                directory=True,
                write=True,
                create="new",
            )
        except FileExistsError as exc:
            raise PlatformServiceError("collision") from exc

    def create_directory_beneath(self, root: _NativeRoot, relative: str) -> None:
        handle = self.create_directory_handle_beneath(root, relative)
        self.close(handle)

    def create_directory_chain_beneath(self, root: _NativeRoot, relative: str) -> None:
        current: list[str] = []
        for part in PurePosixPath(relative).parts:
            current.append(part)
            candidate = "/".join(current)
            if self.observe_path_absent(root, candidate):
                self.create_directory_beneath(root, candidate)
            else:
                handle = self.open_beneath(root, candidate, directory=True, write=True, create="open")
                self.close(handle)

    def prune_empty_beneath(self, root: _NativeRoot, relative: str) -> None:
        handle = self.open_beneath(root, relative, directory=True, write=True, create="open")
        try:
            if self.enumerate_beneath(root, relative, 1):
                return
            self._delete_handle(handle)
        finally:
            self.close(handle)
        self.flush_parent(root, relative)

    def discard_tree_beneath(self, root: _NativeRoot, relative: str) -> None:
        handle = self.open_beneath(root, relative, directory=True, write=True, create="open")
        try:
            identity = self.object_info(handle)[2]
            child_root = _NativeRoot(
                handle,
                self.final_path(handle).rstrip("\\"),
                root.volume_root,
                identity,
            )
            self.discard_open_tree(child_root, identity)
        finally:
            self.close(handle)

    def discard_open_tree(self, root: _NativeRoot, expected_identity: str) -> None:
        if self.object_info(root.handle)[2] != expected_identity:
            raise PlatformServiceError("identity_changed")
        for name in self.enumerate_beneath(root, ".", 8192):
            _validate_component(name)
            handle = self.open_beneath(
                root,
                name,
                directory=None,
                write=True,
                create="open",
            )
            try:
                info = self.object_info(handle)
                if info[0] == "directory":
                    child_root = _NativeRoot(
                        handle,
                        self.final_path(handle).rstrip("\\"),
                        root.volume_root,
                        info[2],
                    )
                    self.discard_open_tree(child_root, info[2])
                elif info[0] == "regular" and info[6] == 1:
                    self.delete_open_handle(handle, info[2])
                else:
                    raise PlatformServiceError("object_kind_unsupported")
            finally:
                self.close(handle)
        self.delete_open_handle(root.handle, expected_identity)

    def _delete_handle(self, handle: int) -> None:
        class FILE_DISPOSITION_INFO_EX(ctypes.Structure):
            _fields_ = [("Flags", ctypes.c_uint32)]

        disposition = FILE_DISPOSITION_INFO_EX(
            self.FILE_DISPOSITION_FLAG_DELETE
            | self.FILE_DISPOSITION_FLAG_POSIX_SEMANTICS
            | self.FILE_DISPOSITION_FLAG_ON_CLOSE
            | self.FILE_DISPOSITION_FLAG_IGNORE_READONLY_ATTRIBUTE
        )
        if not self.kernel32.SetFileInformationByHandle(
            handle,
            self.FILE_DISPOSITION_INFO_EX,
            ctypes.byref(disposition),
            ctypes.sizeof(disposition),
        ):
            raise PlatformServiceError("publication_failed")

    def flush_parent(self, root: _NativeRoot, relative: str) -> None:
        parent = str(PurePosixPath(relative).parent)
        handle = root.handle if parent == "." else self.open_beneath(root, parent, directory=True, write=True, create="open")
        try:
            self.flush(handle)
        finally:
            if handle != root.handle:
                self.close(handle)

    def flush(self, handle: int) -> None:
        if not self.kernel32.FlushFileBuffers(handle):
            raise PlatformServiceError("durability_profile_unavailable")

    def close(self, handle: int) -> None:
        if not self.kernel32.CloseHandle(handle):
            raise PlatformServiceError("publication_failed")

    def observe_path_absent(self, root: _NativeRoot, relative: str) -> bool:
        try:
            handle = self.open_beneath(root, relative, directory=None, write=False, create="open")
        except FileNotFoundError:
            return True
        else:
            self.close(handle)
            return False

def _validate_relative_path(value: str, *, allow_root: bool = False) -> str:
    if allow_root and value == ".":
        return value
    if not isinstance(value, str) or not value:
        raise PlatformServiceError("path_encoding_unsupported")
    try:
        encoded = value.encode("utf-8")
    except UnicodeEncodeError as exc:
        raise PlatformServiceError("path_encoding_unsupported") from exc
    if len(encoded) > 240:
        raise PlatformServiceError("path_encoding_unsupported")
    if value.startswith(("/", "\\")) or "\\" in value or "\x00" in value:
        raise PlatformServiceError("path_encoding_unsupported")
    raw_parts = value.split("/")
    if any(part in {"", ".", ".."} for part in raw_parts):
        raise PlatformServiceError("path_encoding_unsupported")
    pure = PurePosixPath(value)
    if pure.is_absolute() or len(raw_parts) > 100:
        raise PlatformServiceError("path_encoding_unsupported")
    for component in raw_parts:
        _validate_component(component)
    return pure.as_posix()


def _validate_component(value: str) -> None:
    if not value or value in {".", ".."} or value[-1:] in {" ", "."}:
        raise PlatformServiceError("path_collision")
    if any(ord(character) < 32 for character in value) or any(character in '<>:"/\\|?*' for character in value):
        raise PlatformServiceError("path_collision")
    try:
        value.encode("utf-8")
    except UnicodeEncodeError as exc:
        raise PlatformServiceError("path_encoding_unsupported") from exc
    basename = value.split(".", 1)[0].upper()
    if basename in _RESERVED_DOS_NAMES:
        raise PlatformServiceError("path_collision")


def _windows_lookup_key(value: str) -> str:
    # Non-Windows contract tests use this deterministic fallback.  Native
    # collision equality is delegated to CompareStringOrdinal below.
    return value.upper()


def _windows_equal(left: str, right: str) -> bool:
    return _windows_compare(left, right) == 0


def _windows_compare(left: str, right: str) -> int:
    if os.name == "nt" and sys.platform == "win32":
        loader = getattr(ctypes, "WinDLL", None)
        if loader is None:
            raise PlatformServiceError("platform_unsupported")
        kernel32 = loader("kernel32", use_last_error=True)
        kernel32.CompareStringOrdinal.restype = ctypes.c_int
        kernel32.CompareStringOrdinal.argtypes = [
            ctypes.c_wchar_p,
            ctypes.c_int,
            ctypes.c_wchar_p,
            ctypes.c_int,
            ctypes.c_int,
        ]
        result = kernel32.CompareStringOrdinal(left, -1, right, -1, True)
        if result == 0:
            raise PlatformServiceError("observation_failed")
        return result - 2
    left_key = _windows_lookup_key(left)
    right_key = _windows_lookup_key(right)
    return (left_key > right_key) - (left_key < right_key)


def _windows_path_is_beneath(root: str, candidate: str) -> bool:
    root_parts = PureWindowsPath(root).parts
    candidate_parts = PureWindowsPath(candidate).parts
    return (
        len(candidate_parts) > len(root_parts)
        and all(_windows_equal(left, right) for left, right in zip(root_parts, candidate_parts))
    )


def _transaction_id(staging_name: str) -> str:
    prefix = ".sigma.init."
    suffix = staging_name[len(prefix) :] if staging_name.startswith(prefix) else ""
    if len(suffix) != 64 or re.fullmatch(r"[0-9a-f]{64}", suffix) is None:
        raise PlatformServiceError("staging_recovery_required")
    return suffix


def _canonical_json(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(",", ":")).encode("utf-8")


def _binding_digest(marker: dict[str, object]) -> str:
    material = {key: value for key, value in marker.items() if key != "binding_digest"}
    return "sha256:" + hashlib.sha256(_canonical_json(material)).hexdigest()


def _quarantine_name(target_name: str, expected_payload: bytes | None) -> str:
    material = _canonical_json(
        {
            "contract": "sos_windows_file_quarantine_v1",
            "target_name": target_name,
            "expected_payload_digest": _payload_digest(expected_payload),
        }
    )
    return ".sos-quarantine." + hashlib.sha256(material).hexdigest()


def _payload_digest(payload: bytes | None) -> str | None:
    if payload is None:
        return None
    return "sha256:" + hashlib.sha256(payload).hexdigest()


def _digest_text(value: str) -> str:
    return "sha256:" + hashlib.sha256(value.encode("utf-8")).hexdigest()
