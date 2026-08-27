"""Native macOS mechanisms behind the frozen platform boundary."""

from __future__ import annotations

import contextlib
import ctypes
import errno
import fcntl
import functools
import hashlib
import json
import os
import platform
import plistlib
import shutil
import stat
import struct
import subprocess
import sys
import time
import unicodedata
from dataclasses import dataclass
from importlib import metadata
from pathlib import Path, PurePosixPath
from typing import Iterator

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
    TreeStagingCapability,
    TreePublicationOperation,
)


_PROFILE = "macos-apfs-repository-services-v1"
_DURABILITY = "macos-apfs-same-volume-fsync-rename-v1"
_RENAME_EXCL = 0x00000004
_RENAME_SWAP = 0x00000002
_MNT_LOCAL = 0x00001000
_UF_DATALESS = 0x40000000
_ATTR_BIT_MAP_COUNT = 5
_ATTR_VOL_INFO = 0x80000000
_ATTR_VOL_CAPABILITIES = 0x00020000
_VOL_CAPABILITIES_FORMAT = 0
_VOL_CAP_FMT_CASE_SENSITIVE = 0x00000100
_VOLUME_CAPABILITY_PAYLOAD_SIZE = 36
_MAX_XATTR_LIST_BYTES = 64 * 1024
_MAX_XATTR_VALUE_BYTES = 64 * 1024
_STAGING_MARKER = ".sos-staging-binding-v1"


@dataclass(frozen=True)
class _MacRootToken:
    descriptor: int
    case_sensitive: bool


class _DarwinStatFS(ctypes.Structure):
    _fields_ = [
        ("f_bsize", ctypes.c_uint32),
        ("f_iosize", ctypes.c_int32),
        ("f_blocks", ctypes.c_uint64),
        ("f_bfree", ctypes.c_uint64),
        ("f_bavail", ctypes.c_uint64),
        ("f_files", ctypes.c_uint64),
        ("f_ffree", ctypes.c_uint64),
        ("f_fsid", ctypes.c_int32 * 2),
        ("f_owner", ctypes.c_uint32),
        ("f_type", ctypes.c_uint32),
        ("f_flags", ctypes.c_uint32),
        ("f_fssubtype", ctypes.c_uint32),
        ("f_fstypename", ctypes.c_char * 16),
        ("f_mntonname", ctypes.c_char * 1024),
        ("f_mntfromname", ctypes.c_char * 1024),
        ("f_reserved", ctypes.c_uint32 * 8),
    ]


class _DarwinAttrList(ctypes.Structure):
    _fields_ = [
        ("bitmapcount", ctypes.c_uint16),
        ("reserved", ctypes.c_uint16),
        ("commonattr", ctypes.c_uint32),
        ("volattr", ctypes.c_uint32),
        ("dirattr", ctypes.c_uint32),
        ("fileattr", ctypes.c_uint32),
        ("forkattr", ctypes.c_uint32),
    ]


class MacOSPlatformServices:
    profile_id = _PROFILE

    def inspect_host(self, repository_path: Path | None = None) -> dict[str, object]:
        system, architecture, major = self._host_facts()
        report: dict[str, object] = {
            "platform_profile_id": _PROFILE,
            "system": system,
            "architecture": architecture,
            "kernel_release": platform.release(),
            "macos_major": major,
            "absolute_paths_serialized": False,
        }
        if repository_path is not None:
            descriptor = -1
            try:
                self._admit_host()
                descriptor = self._open_root_without_symlinks(repository_path)
                filesystem, local, removable = self._filesystem_facts(repository_path)
                case_sensitive = self._observe_apfs_case_mode(descriptor)
                report["filesystem_type"] = filesystem
                report["filesystem_local"] = local
                report["filesystem_removable"] = removable
                report["filesystem_case_mode"] = (
                    "case_sensitive" if case_sensitive else "case_insensitive"
                )
                report["filesystem_observation_status"] = "observed"
            except (OSError, ValueError, PlatformServiceError):
                report["filesystem_type"] = "unknown"
                report["filesystem_observation_status"] = "not_verified"
            finally:
                if descriptor >= 0:
                    os.close(descriptor)
        return report

    def _host_facts(self) -> tuple[str, str, int]:
        system = platform.system().lower()
        architecture = platform.machine().lower()
        try:
            major = int(platform.mac_ver()[0].split(".", 1)[0])
        except (TypeError, ValueError):
            major = 0
        return system, architecture, major

    def _filesystem_facts(self, path: Path) -> tuple[str, bool, bool]:
        if platform.system() != "Darwin":
            raise PlatformServiceError("platform_unsupported")
        statfs_value = _DarwinStatFS()
        libc = ctypes.CDLL(None, use_errno=True)
        if libc.statfs(os.fsencode(path), ctypes.byref(statfs_value)) != 0:
            raise PlatformServiceError("filesystem_not_verified")
        filesystem = bytes(statfs_value.f_fstypename).split(b"\0", 1)[0].decode("ascii")
        local = bool(statfs_value.f_flags & _MNT_LOCAL)
        mount_point_bytes = bytes(statfs_value.f_mntonname).split(b"\0", 1)[0]
        if (
            not mount_point_bytes
            or len(mount_point_bytes) > 1024
            or not mount_point_bytes.startswith(b"/")
        ):
            raise PlatformServiceError("filesystem_not_verified")
        try:
            mount_point = os.fsdecode(mount_point_bytes)
        except UnicodeError as exc:
            raise PlatformServiceError("filesystem_not_verified") from exc
        # diskutil is a bounded local inventory read.  It is used only to
        # distinguish removable media. It accepts a device or mount point,
        # not an arbitrary repository descendant. The statfs-derived mount
        # point and raw plist never escape this adapter.
        try:
            result = subprocess.run(
                ["/usr/sbin/diskutil", "info", "-plist", mount_point],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                env={"PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "LC_ALL": "C"},
                timeout=2.0,
                check=False,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise PlatformServiceError("filesystem_not_verified") from exc
        if result.returncode != 0 or len(result.stdout) > 256 * 1024:
            raise PlatformServiceError("filesystem_not_verified")
        try:
            inventory = plistlib.loads(result.stdout)
        except (plistlib.InvalidFileException, ValueError) as exc:
            raise PlatformServiceError("filesystem_not_verified") from exc
        removable = inventory.get("RemovableMedia")
        internal = inventory.get("Internal")
        if not isinstance(removable, bool) or not isinstance(internal, bool):
            raise PlatformServiceError("filesystem_not_verified")
        return filesystem.lower(), local and internal, removable

    def _admit_host(self) -> None:
        system, architecture, major = self._host_facts()
        if system != "darwin" or architecture not in {"arm64", "aarch64"} or major < 14:
            raise PlatformServiceError("platform_unsupported")

    def _admit_environment(self, path: Path, descriptor: int) -> tuple[bool, str]:
        self._admit_host()
        filesystem, local, removable = self._filesystem_facts(path)
        if filesystem != "apfs" or not local or removable:
            raise PlatformServiceError("filesystem_unsupported")
        case_sensitive = self._observe_apfs_case_mode(descriptor)
        return case_sensitive, (
            "macos-local-apfs-case-sensitive-v1"
            if case_sensitive
            else "macos-local-apfs-case-insensitive-v1"
        )

    def open_repository(self, path: Path) -> RepositoryRootHandle:
        descriptor = -1
        try:
            self._admit_host()
            descriptor = self._open_root_without_symlinks(path)
            self._reject_unsafe_fd(descriptor)
            case_sensitive, filesystem_profile = self._admit_environment(path, descriptor)
            identity_digest = self._stable_identity(os.fstat(descriptor))
        except PlatformServiceError:
            if descriptor >= 0:
                os.close(descriptor)
            raise
        except OSError as exc:
            if descriptor >= 0:
                os.close(descriptor)
            raise PlatformServiceError("invalid_root") from exc
        return RepositoryRootHandle(
            _PROFILE,
            filesystem_profile,
            identity_digest,
            _MacRootToken(descriptor, case_sensitive),
            self._close_repository_token,
        )

    def _observe_apfs_case_mode(self, descriptor: int) -> bool:
        return self._parse_volume_capabilities(
            self._read_volume_capability_payload(descriptor)
        )

    @staticmethod
    def _read_volume_capability_payload(descriptor: int) -> bytes:
        attributes = _DarwinAttrList()
        attributes.bitmapcount = _ATTR_BIT_MAP_COUNT
        attributes.volattr = _ATTR_VOL_INFO | _ATTR_VOL_CAPABILITIES
        output = ctypes.create_string_buffer(4096)
        libc = ctypes.CDLL(None, use_errno=True)
        fgetattrlist = getattr(libc, "fgetattrlist", None)
        if fgetattrlist is None:
            raise PlatformServiceError("filesystem_not_verified")
        fgetattrlist.argtypes = [
            ctypes.c_int,
            ctypes.POINTER(_DarwinAttrList),
            ctypes.c_void_p,
            ctypes.c_size_t,
            ctypes.c_ulong,
        ]
        fgetattrlist.restype = ctypes.c_int
        if fgetattrlist(
            descriptor,
            ctypes.byref(attributes),
            ctypes.byref(output),
            ctypes.sizeof(output),
            0,
        ) != 0:
            raise PlatformServiceError("filesystem_not_verified")
        length = struct.unpack_from("=I", output.raw, 0)[0]
        if length != _VOLUME_CAPABILITY_PAYLOAD_SIZE or length > len(output.raw):
            raise PlatformServiceError("filesystem_not_verified")
        return output.raw[:length]

    @staticmethod
    def _parse_volume_capabilities(payload: bytes) -> bool:
        if len(payload) < _VOLUME_CAPABILITY_PAYLOAD_SIZE:
            raise PlatformServiceError("filesystem_not_verified")
        declared = struct.unpack_from("=I", payload, 0)[0]
        if declared != _VOLUME_CAPABILITY_PAYLOAD_SIZE or declared > len(payload):
            raise PlatformServiceError("filesystem_not_verified")
        values = struct.unpack_from("=8I", payload, 4)
        capabilities = values[_VOL_CAPABILITIES_FORMAT]
        valid = values[4 + _VOL_CAPABILITIES_FORMAT]
        if not valid & _VOL_CAP_FMT_CASE_SENSITIVE:
            raise PlatformServiceError("filesystem_not_verified")
        return bool(capabilities & _VOL_CAP_FMT_CASE_SENSITIVE)

    def _open_root_without_symlinks(self, path: Path) -> int:
        absolute = Path(os.path.abspath(path))
        descriptor = os.open(
            "/", os.O_RDONLY | os.O_DIRECTORY | getattr(os, "O_CLOEXEC", 0)
        )
        try:
            for component in absolute.parts[1:]:
                child = os.open(
                    component,
                    os.O_RDONLY
                    | os.O_DIRECTORY
                    | getattr(os, "O_CLOEXEC", 0)
                    | os.O_NOFOLLOW,
                    dir_fd=descriptor,
                )
                self._reject_unsafe_fd(child)
                os.close(descriptor)
                descriptor = child
            return descriptor
        except BaseException:
            os.close(descriptor)
            raise

    def observe_object(
        self, root: RepositoryRootHandle, relative_path: str
    ) -> ObjectObservation:
        try:
            parent, name = self._open_parent(root, relative_path)
        except FileNotFoundError:
            return ObjectObservation(relative_path, "absent", 0, 0, _digest_identity("absent"))
        except NotADirectoryError as exc:
            raise PlatformServiceError("not_directory") from exc
        except OSError as exc:
            raise PlatformServiceError("read_failed") from exc
        try:
            try:
                observed = os.stat(name, dir_fd=parent, follow_symlinks=False)
            except FileNotFoundError:
                return ObjectObservation(relative_path, "absent", 0, 0, _digest_identity("absent"))
            kind = self._kind(observed.st_mode)
            content_digest = None
            byte_count = observed.st_size
            if kind == "symlink":
                target = os.readlink(name, dir_fd=parent)
                target_bytes = os.fsencode(target)
                verified = os.stat(name, dir_fd=parent, follow_symlinks=False)
                if self._signature(observed) != self._signature(verified):
                    raise PlatformServiceError("identity_changed")
                byte_count = len(target_bytes)
                content_digest = "sha256:" + hashlib.sha256(target_bytes).hexdigest()
            elif kind in {"regular", "directory"}:
                flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | os.O_NOFOLLOW
                if kind == "directory":
                    flags |= os.O_DIRECTORY
                descriptor = os.open(name, flags, dir_fd=parent)
                try:
                    self._reject_unsafe_fd(descriptor)
                    verified = os.fstat(descriptor)
                    if self._signature(observed) != self._signature(verified):
                        raise PlatformServiceError("identity_changed")
                finally:
                    os.close(descriptor)
            return ObjectObservation(
                relative_path=relative_path,
                kind=kind,
                byte_count=byte_count,
                mode=stat.S_IMODE(observed.st_mode),
                identity_digest=self._identity(observed),
                stable_identity_digest=self._stable_identity(observed),
                content_digest=content_digest,
            )
        except OSError as exc:
            raise PlatformServiceError("observation_failed") from exc
        finally:
            os.close(parent)

    def read_regular_file_bounded(
        self, root: RepositoryRootHandle, relative_path: str, limit: int
    ) -> EphemeralFileRead:
        if limit < 0:
            raise PlatformServiceError("limit_invalid")
        try:
            parent, name = self._open_parent(root, relative_path)
        except (FileNotFoundError, NotADirectoryError) as exc:
            raise PlatformServiceError("not_found") from exc
        except OSError as exc:
            raise PlatformServiceError("read_failed") from exc
        try:
            try:
                descriptor = os.open(
                    name,
                    os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | os.O_NOFOLLOW,
                    dir_fd=parent,
                )
            except FileNotFoundError as exc:
                raise PlatformServiceError("not_found") from exc
            except OSError as exc:
                raise PlatformServiceError("read_failed") from exc
            try:
                before = os.fstat(descriptor)
                self._reject_unsafe_fd(descriptor)
                if not stat.S_ISREG(before.st_mode):
                    raise PlatformServiceError("not_regular")
                if before.st_size > limit:
                    raise PlatformServiceError("file_limit_exceeded")
                payload = self._read_bounded(descriptor, limit)
                after = os.fstat(descriptor)
                if self._signature(before) != self._signature(after):
                    raise PlatformServiceError("identity_changed")
            finally:
                os.close(descriptor)
        finally:
            os.close(parent)
        observation = ObjectObservation(
            relative_path,
            "regular",
            len(payload),
            stat.S_IMODE(after.st_mode),
            self._identity(after),
        )
        return EphemeralFileRead(
            observation,
            payload,
            "sha256:" + hashlib.sha256(payload).hexdigest(),
        )

    def enumerate_directory_bounded(
        self, root: RepositoryRootHandle, relative_path: str, limit: int
    ) -> EphemeralDirectoryRead:
        if limit < 0:
            raise PlatformServiceError("limit_invalid")
        try:
            descriptor = self._open_directory(root, relative_path)
        except (FileNotFoundError, NotADirectoryError) as exc:
            raise PlatformServiceError("not_found") from exc
        except OSError as exc:
            raise PlatformServiceError("enumeration_failed") from exc
        try:
            names = sorted(os.listdir(descriptor))
            if len(names) > limit:
                raise PlatformServiceError("directory_limit_exceeded")
            entries: list[EphemeralDirectoryEntry] = []
            for name in names:
                observed = os.stat(name, dir_fd=descriptor, follow_symlinks=False)
                if stat.S_ISLNK(observed.st_mode):
                    raise PlatformServiceError("symlink_unsupported")
                child = os.open(
                    name,
                    os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | os.O_NOFOLLOW,
                    dir_fd=descriptor,
                )
                try:
                    self._reject_unsafe_fd(child)
                finally:
                    os.close(child)
                entries.append(
                    EphemeralDirectoryEntry(name, self._kind(observed.st_mode), self._identity(observed))
                )
        except PlatformServiceError:
            raise
        except OSError as exc:
            raise PlatformServiceError("enumeration_failed") from exc
        finally:
            os.close(descriptor)
        material = json.dumps(names, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        return EphemeralDirectoryRead(
            tuple(entries), len(entries), "sha256:" + hashlib.sha256(material).hexdigest()
        )

    @contextlib.contextmanager
    def acquire_repository_lock(
        self,
        root: RepositoryRootHandle,
        deadline_seconds: float | None,
        *,
        relative_lock_path: str,
        exclusive_create: bool = False,
    ) -> Iterator[None]:
        parts = self._parts(relative_lock_path)
        descriptor = self._open_or_create_directory_chain(root, "/".join(parts[:-1]))
        lock = -1
        try:
            flags = os.O_RDWR | os.O_CREAT | getattr(os, "O_CLOEXEC", 0) | os.O_NOFOLLOW
            lock = os.open(parts[-1], flags, 0o600, dir_fd=descriptor)
            observed = os.fstat(lock)
            if not stat.S_ISREG(observed.st_mode):
                raise PlatformServiceError("lock_invalid")
            deadline = (
                None
                if deadline_seconds is None and not exclusive_create
                else time.monotonic() + min(2.0, max(0.0, deadline_seconds or 2.0))
            )
            while True:
                try:
                    flags = fcntl.LOCK_EX if deadline is None else fcntl.LOCK_EX | fcntl.LOCK_NB
                    fcntl.flock(lock, flags)
                    break
                except BlockingIOError as exc:
                    if deadline is not None and time.monotonic() >= deadline:
                        raise PlatformServiceError("lock_timeout") from exc
                    time.sleep(0.01)
            try:
                if exclusive_create:
                    os.ftruncate(lock, 0)
                    self._write_all(lock, b"sos_acceptance_lock_v1\n")
                    os.fsync(lock)
                    os.fsync(descriptor)
                yield
            finally:
                fcntl.flock(lock, fcntl.LOCK_UN)
        except PlatformServiceError:
            raise
        except OSError as exc:
            raise PlatformServiceError("lock_failed") from exc
        finally:
            if lock >= 0:
                os.close(lock)
            os.close(descriptor)

    def publish_file(self, operation: FilePublicationOperation) -> PublicationReceipt:
        if operation.parent_policy not in {"preserve_existing", "create_managed_and_prune_if_empty_on_abort"}:
            raise PlatformServiceError("parent_policy_invalid")
        parent_relative = "/".join(self._parts(operation.relative_path)[:-1])
        parent_created_identity: str | None = None
        try:
            before_parent = (
                self.observe_object(operation.root, parent_relative)
                if parent_relative
                else None
            )
            if operation.parent_policy == "create_managed_and_prune_if_empty_on_abort":
                if before_parent is None or (
                    operation.expected_parent_kind != before_parent.kind
                    or operation.expected_parent_identity != before_parent.stable_identity_digest
                ):
                    raise PlatformServiceError("identity_changed")
            parent, name = self._open_parent(operation.root, operation.relative_path, create=True)
            if (
                parent_relative
                and before_parent is not None
                and before_parent.kind == "absent"
            ):
                parent_created_identity = self.observe_object(
                    operation.root, parent_relative
                ).stable_identity_digest
        except OSError as exc:
            raise PlatformServiceError("publication_failed") from exc
        before_digest = _payload_digest(operation.expected_payload) if operation.expected_existed else None
        temporary = f".sos-platform.{os.getpid()}.{os.urandom(8).hex()}"
        preserve_temporary = False
        publication_failed = True
        try:
            current = self._read_relative(parent, name)
            if (current is not None) != operation.expected_existed or current != operation.expected_payload:
                raise PlatformServiceError("identity_changed")
            if operation.payload is None:
                if current is not None:
                    self._rename_noreplace(parent, name, parent, temporary)
                    moved = self._read_relative(parent, temporary)
                    if moved != operation.expected_payload:
                        try:
                            self._rename_noreplace(parent, temporary, parent, name)
                        except PlatformServiceError as exc:
                            preserve_temporary = True
                            raise PlatformServiceError("recovery_required") from exc
                        raise PlatformServiceError("identity_changed")
                    os.unlink(temporary, dir_fd=parent)
                    os.fsync(parent)
                publication_failed = False
                return PublicationReceipt(_DURABILITY, "delete", operation.relative_path, before_digest, None)
            descriptor = os.open(
                temporary,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                operation.mode,
                dir_fd=parent,
            )
            try:
                self._write_all(descriptor, operation.payload)
                os.fsync(descriptor)
                replacement_identity = self._file_identity(os.fstat(descriptor))
            finally:
                os.close(descriptor)
            if operation.expected_existed:
                self._rename_exchange(parent, temporary, name)
                replaced = self._read_relative(parent, temporary)
                target_identity = self._relative_identity(parent, name)
                if replaced != operation.expected_payload or target_identity != replacement_identity:
                    try:
                        self._rename_exchange(parent, temporary, name)
                    except PlatformServiceError as exc:
                        preserve_temporary = True
                        raise PlatformServiceError("recovery_required") from exc
                    raise PlatformServiceError("identity_changed")
                os.unlink(temporary, dir_fd=parent)
            else:
                os.link(temporary, name, src_dir_fd=parent, dst_dir_fd=parent, follow_symlinks=False)
                os.unlink(temporary, dir_fd=parent)
            os.fsync(parent)
            publication_failed = False
            return PublicationReceipt(
                _DURABILITY,
                "replace" if operation.expected_existed else "create",
                operation.relative_path,
                before_digest,
                _payload_digest(operation.payload),
            )
        except PlatformServiceError:
            raise
        except FileExistsError as exc:
            raise PlatformServiceError("collision") from exc
        except OSError as exc:
            raise PlatformServiceError("publication_failed") from exc
        finally:
            if not preserve_temporary:
                try:
                    os.unlink(temporary, dir_fd=parent)
                except FileNotFoundError:
                    pass
            os.close(parent)
            if (
                operation.parent_policy == "create_managed_and_prune_if_empty_on_abort"
                and (parent_created_identity is not None or operation.expected_parent_identity is not None)
                and (operation.payload is None or publication_failed)
            ):
                self._prune_empty_managed_parent(
                    operation.root,
                    parent_relative,
                    parent_created_identity or operation.expected_parent_identity or "",
                )

    def _prune_empty_managed_parent(
        self,
        root: RepositoryRootHandle,
        relative_path: str,
        expected_identity: str,
    ) -> None:
        parts = self._parts(relative_path)
        parent = os.dup(self._root_descriptor(root))
        try:
            for part in parts[:-1]:
                child = os.open(
                    part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent
                )
                os.close(parent)
                parent = child
            child = os.open(
                parts[-1], os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent
            )
            try:
                if self._stable_identity(os.fstat(child)) != expected_identity or os.listdir(child):
                    return
            finally:
                os.close(child)
            os.rmdir(parts[-1], dir_fd=parent)
            os.fsync(parent)
        except (FileNotFoundError, NotADirectoryError):
            return
        finally:
            os.close(parent)

    def publish_tree(self, operation: TreePublicationOperation) -> PublicationReceipt:
        self._validate_component(operation.staging_name)
        self._validate_component(operation.target_name)
        root_descriptor = self._root_descriptor(operation.root)
        try:
            if operation.action == "create":
                capability = self._create_staging(root_descriptor, operation)
                verb = "stage_tree"
            elif operation.action == "recover":
                capability = self._recover_staging(root_descriptor, operation)
                verb = "recover_tree"
            elif operation.action == "extend":
                capability = self._require_staging_capability(root_descriptor, operation)
                self._write_tree_files(self._staging_descriptor(capability), operation.files)
                verb = "extend_tree"
            elif operation.action == "discard":
                capability = operation.capability
                capability = self._require_staging_capability(root_descriptor, operation)
                self._discard_tree(root_descriptor, operation.staging_name)
                capability.consume("discard")
                verb = "discard_tree"
            elif operation.action == "commit":
                capability = self._require_staging_capability(root_descriptor, operation)
                staging = self._staging_descriptor(capability)
                try:
                    os.unlink(_STAGING_MARKER, dir_fd=staging)
                    os.fsync(staging)
                except OSError as exc:
                    raise PlatformServiceError("staging_identity_changed") from exc
                self._assert_named_staging_identity(root_descriptor, capability)
                self._rename_noreplace(
                    root_descriptor,
                    operation.staging_name,
                    root_descriptor,
                    operation.target_name,
                )
                os.fsync(root_descriptor)
                capability.consume("commit")
                verb = "create_tree"
            else:
                raise PlatformServiceError("publication_failed")
        except (FileNotFoundError, NotADirectoryError) as exc:
            raise PlatformServiceError("staging_missing") from exc
        except PlatformServiceError:
            raise
        except OSError as exc:
            raise PlatformServiceError("publication_failed") from exc
        return PublicationReceipt(
            _DURABILITY,
            verb,
            operation.target_name,
            None,
            None,
            capability if operation.action in {"create", "recover", "extend"} else None,
        )

    @staticmethod
    def _close_repository_token(token: object) -> None:
        if not isinstance(token, _MacRootToken):
            raise PlatformServiceError("invalid_root")
        os.close(token.descriptor)

    @staticmethod
    def _root_descriptor(root: RepositoryRootHandle) -> int:
        token = root._platform_token()
        if not isinstance(token, _MacRootToken):
            raise PlatformServiceError("invalid_root")
        return token.descriptor

    @staticmethod
    def _root_case_sensitive(root: RepositoryRootHandle) -> bool:
        token = root._platform_token()
        if not isinstance(token, _MacRootToken):
            raise PlatformServiceError("invalid_root")
        return token.case_sensitive

    def _create_staging(
        self, root_descriptor: int, operation: TreePublicationOperation
    ) -> TreeStagingCapability:
        try:
            os.stat(operation.target_name, dir_fd=root_descriptor, follow_symlinks=False)
        except FileNotFoundError:
            pass
        else:
            raise PlatformServiceError("collision")
        try:
            os.mkdir(operation.staging_name, 0o700, dir_fd=root_descriptor)
        except FileExistsError as exc:
            raise PlatformServiceError("collision") from exc
        try:
            staging = os.open(
                operation.staging_name,
                os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                dir_fd=root_descriptor,
            )
        except (FileNotFoundError, NotADirectoryError) as exc:
            raise PlatformServiceError("staging_missing") from exc
        try:
            observed = os.fstat(staging)
            transaction_id = self._transaction_id(operation.staging_name)
            recovery_digest = operation.recovery_binding_digest or "none"
            nonce = os.urandom(32).hex()
            marker = {
                "contract": "sos_staging_binding_v1",
                "root_identity_digest": operation.root.identity_digest,
                "transaction_id": transaction_id,
                "staging_name": operation.staging_name,
                "target_name": operation.target_name,
                "staging_identity_digest": self._stable_identity(observed),
                "recovery_binding_digest": recovery_digest,
                "binding_nonce": nonce,
            }
            marker["binding_digest"] = self._binding_digest(marker)
            descriptor = os.open(
                _STAGING_MARKER,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                0o600,
                dir_fd=staging,
            )
            try:
                self._write_all(
                    descriptor,
                    json.dumps(marker, sort_keys=True, separators=(",", ":")).encode("utf-8"),
                )
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
            self._write_tree_files(staging, operation.files)
            os.fsync(staging)
            return TreeStagingCapability(
                operation.root.identity_digest,
                transaction_id,
                operation.staging_name,
                operation.target_name,
                marker["staging_identity_digest"],
                recovery_digest,
                marker["binding_digest"],
                staging,
                self._close_staging_token,
            )
        except BaseException:
            os.close(staging)
            raise

    def _recover_staging(
        self, root_descriptor: int, operation: TreePublicationOperation
    ) -> TreeStagingCapability:
        if not operation.recovery_binding_digest:
            raise PlatformServiceError("staging_recovery_required")
        staging = os.open(
            operation.staging_name,
            os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
            dir_fd=root_descriptor,
        )
        try:
            marker = self._read_staging_marker(staging)
            expected = {
                "root_identity_digest": operation.root.identity_digest,
                "transaction_id": self._transaction_id(operation.staging_name),
                "staging_name": operation.staging_name,
                "target_name": operation.target_name,
                "recovery_binding_digest": operation.recovery_binding_digest,
                "staging_identity_digest": self._stable_identity(os.fstat(staging)),
            }
            if any(marker.get(key) != value for key, value in expected.items()):
                raise PlatformServiceError("staging_identity_changed")
            return TreeStagingCapability(
                expected["root_identity_digest"],
                expected["transaction_id"],
                expected["staging_name"],
                expected["target_name"],
                expected["staging_identity_digest"],
                expected["recovery_binding_digest"],
                str(marker["binding_digest"]),
                staging,
                self._close_staging_token,
            )
        except BaseException:
            os.close(staging)
            raise

    def _require_staging_capability(
        self, root_descriptor: int, operation: TreePublicationOperation
    ) -> TreeStagingCapability:
        capability = operation.capability
        if capability is None or capability.consumed:
            raise PlatformServiceError("staging_recovery_required")
        if (
            capability.root_identity_digest != operation.root.identity_digest
            or capability.staging_name != operation.staging_name
            or capability.target_name != operation.target_name
        ):
            raise PlatformServiceError("staging_identity_changed")
        self._assert_named_staging_identity(root_descriptor, capability)
        marker = self._read_staging_marker(self._staging_descriptor(capability))
        if marker.get("binding_digest") != capability.binding_digest:
            raise PlatformServiceError("staging_identity_changed")
        return capability

    def _assert_named_staging_identity(
        self, root_descriptor: int, capability: TreeStagingCapability
    ) -> None:
        named = os.open(
            capability.staging_name,
            os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
            dir_fd=root_descriptor,
        )
        try:
            if self._stable_identity(os.fstat(named)) != capability.staging_identity_digest:
                raise PlatformServiceError("staging_identity_changed")
            if self._stable_identity(os.fstat(self._staging_descriptor(capability))) != capability.staging_identity_digest:
                raise PlatformServiceError("staging_identity_changed")
        finally:
            os.close(named)

    def _read_staging_marker(self, staging: int) -> dict[str, object]:
        try:
            payload = self._read_relative(staging, _STAGING_MARKER)
            if payload is None or len(payload) > 4096:
                raise PlatformServiceError("staging_identity_changed")
            marker = json.loads(payload.decode("utf-8"))
        except (OSError, UnicodeError, json.JSONDecodeError) as exc:
            raise PlatformServiceError("staging_identity_changed") from exc
        if not isinstance(marker, dict) or marker.get("contract") != "sos_staging_binding_v1":
            raise PlatformServiceError("staging_identity_changed")
        supplied = marker.get("binding_digest")
        material = dict(marker)
        material.pop("binding_digest", None)
        if supplied != self._binding_digest(material):
            raise PlatformServiceError("staging_identity_changed")
        return marker

    def _write_tree_files(
        self, staging: int, files: tuple[tuple[str, bytes], ...]
    ) -> None:
        for relative, payload in files:
            if relative == _STAGING_MARKER:
                raise PlatformServiceError("path_invalid")
            parts = self._parts(relative)
            parent = os.dup(staging)
            try:
                for part in parts[:-1]:
                    try:
                        os.mkdir(part, 0o700, dir_fd=parent)
                    except FileExistsError:
                        pass
                    child = os.open(
                        part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent
                    )
                    os.close(parent)
                    parent = child
                descriptor = os.open(
                    parts[-1],
                    os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                    0o600,
                    dir_fd=parent,
                )
                try:
                    self._write_all(descriptor, payload)
                    os.fsync(descriptor)
                finally:
                    os.close(descriptor)
                os.fsync(parent)
            finally:
                os.close(parent)
        os.fsync(staging)

    @staticmethod
    def _binding_digest(marker: dict[str, object]) -> str:
        material = json.dumps(marker, sort_keys=True, separators=(",", ":")).encode("utf-8")
        return "sha256:" + hashlib.sha256(material).hexdigest()

    @staticmethod
    def _transaction_id(staging_name: str) -> str:
        prefix = ".sigma.init."
        value = staging_name.removeprefix(prefix)
        if not staging_name.startswith(prefix) or len(value) != 64 or any(
            char not in "0123456789abcdef" for char in value
        ):
            raise PlatformServiceError("path_invalid")
        return value

    @staticmethod
    def _close_staging_token(token: object) -> None:
        if not isinstance(token, int):
            raise PlatformServiceError("staging_identity_changed")
        os.close(token)

    @staticmethod
    def _staging_descriptor(capability: TreeStagingCapability) -> int:
        token = capability._platform_token()
        if not isinstance(token, int):
            raise PlatformServiceError("staging_identity_changed")
        return token

    def _discard_tree(self, root_descriptor: int, name: str) -> None:
        try:
            staging = os.open(
                name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=root_descriptor
            )
        except FileNotFoundError:
            return
        try:
            self._discard_directory_contents(staging)
        finally:
            os.close(staging)
        os.rmdir(name, dir_fd=root_descriptor)
        os.fsync(root_descriptor)

    def _discard_directory_contents(self, directory: int) -> None:
        for name in os.listdir(directory):
            observed = os.stat(name, dir_fd=directory, follow_symlinks=False)
            if stat.S_ISDIR(observed.st_mode):
                child = os.open(
                    name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=directory
                )
                try:
                    self._discard_directory_contents(child)
                finally:
                    os.close(child)
                os.rmdir(name, dir_fd=directory)
            else:
                os.unlink(name, dir_fd=directory)

    @functools.lru_cache(maxsize=4)
    def observe_launcher(self, client_id: str) -> EphemeralLauncherObservation:
        if client_id == "git":
            executable_text = shutil.which("git", path="/usr/local/bin:/opt/homebrew/bin:/usr/bin:/bin")
            if executable_text is None:
                raise PlatformServiceError("launcher_unsupported")
            executable = Path(executable_text)
            try:
                observed = executable.stat()
                if not executable.is_absolute() or not stat.S_ISREG(observed.st_mode):
                    raise PlatformServiceError("launcher_invalid")
                digest = self._sha256_file(executable, 128 * 1024 * 1024)
            except PlatformServiceError:
                raise
            except OSError as exc:
                raise PlatformServiceError("launcher_invalid") from exc
            return EphemeralLauncherObservation(executable, "system", digest)
        if client_id != "codex":
            raise PlatformServiceError("launcher_unsupported")
        try:
            distribution = metadata.distribution("sigma-operator-stack")
            executable = self._canonical_python_executable()
            observed = executable.stat()
            if not executable.is_absolute() or not stat.S_ISREG(observed.st_mode):
                raise PlatformServiceError("launcher_invalid")
            digest = self._sha256_file(executable, 128 * 1024 * 1024)
        except metadata.PackageNotFoundError as exc:
            raise PlatformServiceError("package_not_installed") from exc
        except PlatformServiceError:
            raise
        except OSError as exc:
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
        return EphemeralLauncherObservation(executable, distribution.version, digest, editable)

    def _open_parent(
        self, root: RepositoryRootHandle, relative_path: str, *, create: bool = False
    ) -> tuple[int, str]:
        parts = self._parts(relative_path)
        descriptor = os.dup(self._root_descriptor(root))
        try:
            for part in parts[:-1]:
                self._require_canonical_component(
                    descriptor, part, self._root_case_sensitive(root), allow_absent=create
                )
                if create:
                    try:
                        os.mkdir(part, 0o700, dir_fd=descriptor)
                    except FileExistsError:
                        pass
                child = os.open(
                    part,
                    os.O_RDONLY | os.O_DIRECTORY | getattr(os, "O_CLOEXEC", 0) | os.O_NOFOLLOW,
                    dir_fd=descriptor,
                )
                self._reject_unsafe_fd(child)
                os.close(descriptor)
                descriptor = child
            self._require_canonical_component(
                descriptor, parts[-1], self._root_case_sensitive(root), allow_absent=True
            )
            return descriptor, parts[-1]
        except BaseException:
            os.close(descriptor)
            raise

    def _open_directory(self, root: RepositoryRootHandle, relative_path: str) -> int:
        if relative_path in {"", "."}:
            return os.dup(self._root_descriptor(root))
        descriptor = os.dup(self._root_descriptor(root))
        try:
            for part in self._parts(relative_path):
                self._require_canonical_component(
                    descriptor, part, self._root_case_sensitive(root), allow_absent=False
                )
                child = os.open(
                    part,
                    os.O_RDONLY | os.O_DIRECTORY | getattr(os, "O_CLOEXEC", 0) | os.O_NOFOLLOW,
                    dir_fd=descriptor,
                )
                self._reject_unsafe_fd(child)
                os.close(descriptor)
                descriptor = child
            return descriptor
        except BaseException:
            os.close(descriptor)
            raise

    def _open_or_create_directory_chain(self, root: RepositoryRootHandle, relative_path: str) -> int:
        descriptor = os.dup(self._root_descriptor(root))
        try:
            if not relative_path:
                return descriptor
            for part in self._parts(relative_path):
                self._require_canonical_component(
                    descriptor, part, self._root_case_sensitive(root), allow_absent=True
                )
                try:
                    os.mkdir(part, 0o700, dir_fd=descriptor)
                except FileExistsError:
                    pass
                child = os.open(
                    part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=descriptor
                )
                self._reject_unsafe_fd(child)
                os.close(descriptor)
                descriptor = child
            return descriptor
        except BaseException:
            os.close(descriptor)
            raise

    @staticmethod
    def _collision_key(name: str, case_sensitive: bool) -> str:
        normalized = unicodedata.normalize("NFC", name)
        return normalized if case_sensitive else normalized.casefold()

    def _require_canonical_component(
        self, directory: int, requested: str, case_sensitive: bool, *, allow_absent: bool
    ) -> None:
        try:
            names = os.listdir(directory)
        except OSError as exc:
            raise PlatformServiceError("enumeration_failed") from exc
        if len(names) > 100_000:
            raise PlatformServiceError("directory_limit_exceeded")
        requested_key = self._collision_key(requested, case_sensitive)
        matches = [name for name in names if self._collision_key(name, case_sensitive) == requested_key]
        if len(matches) > 1 or (matches and matches[0] != requested):
            raise PlatformServiceError("path_collision")
        if not matches and not allow_absent:
            raise FileNotFoundError(requested)

    @staticmethod
    def _reject_unsafe_fd(descriptor: int) -> None:
        observed = os.fstat(descriptor)
        if getattr(observed, "st_flags", 0) & _UF_DATALESS:
            raise PlatformServiceError("cloud_placeholder_unsupported")
        names = MacOSPlatformServices._list_xattrs_fd(descriptor)
        lowered = {name.lower() for name in names}
        if any(b"fileprovider" in name or b"icloud" in name for name in lowered):
            raise PlatformServiceError("cloud_placeholder_unsupported")
        if b"com.apple.finderinfo" in lowered:
            finder = MacOSPlatformServices._get_xattr_fd(
                descriptor, b"com.apple.FinderInfo"
            )
            if len(finder) >= 10 and int.from_bytes(finder[8:10], "big") & 0x8000:
                raise PlatformServiceError("alias_unsupported")

    @staticmethod
    def _list_xattrs_fd(descriptor: int) -> tuple[bytes, ...]:
        """Return bounded xattr names through Darwin's descriptor ABI."""
        libc = ctypes.CDLL(None, use_errno=True)
        flistxattr = getattr(libc, "flistxattr", None)
        if flistxattr is None:
            raise PlatformServiceError("object_type_not_verified")
        flistxattr.argtypes = [ctypes.c_int, ctypes.c_void_p, ctypes.c_size_t, ctypes.c_int]
        flistxattr.restype = ctypes.c_ssize_t
        length = flistxattr(descriptor, None, 0, 0)
        if length < 0 or length > _MAX_XATTR_LIST_BYTES:
            raise PlatformServiceError("object_type_not_verified")
        if length == 0:
            return ()
        output = ctypes.create_string_buffer(length)
        observed = flistxattr(descriptor, output, length, 0)
        if observed != length:
            raise PlatformServiceError("object_type_not_verified")
        payload = output.raw[:observed]
        if not payload.endswith(b"\0"):
            raise PlatformServiceError("object_type_not_verified")
        names = tuple(payload[:-1].split(b"\0"))
        if any(not name or len(name) > 255 for name in names):
            raise PlatformServiceError("object_type_not_verified")
        return names

    @staticmethod
    def _get_xattr_fd(descriptor: int, name: bytes) -> bytes:
        """Read one bounded xattr through Darwin's descriptor ABI."""
        libc = ctypes.CDLL(None, use_errno=True)
        fgetxattr = getattr(libc, "fgetxattr", None)
        if fgetxattr is None:
            raise PlatformServiceError("object_type_not_verified")
        fgetxattr.argtypes = [
            ctypes.c_int,
            ctypes.c_char_p,
            ctypes.c_void_p,
            ctypes.c_size_t,
            ctypes.c_uint32,
            ctypes.c_int,
        ]
        fgetxattr.restype = ctypes.c_ssize_t
        length = fgetxattr(descriptor, name, None, 0, 0, 0)
        if length < 0 or length > _MAX_XATTR_VALUE_BYTES:
            raise PlatformServiceError("object_type_not_verified")
        if length == 0:
            return b""
        output = ctypes.create_string_buffer(length)
        observed = fgetxattr(descriptor, name, output, length, 0, 0)
        if observed != length:
            raise PlatformServiceError("object_type_not_verified")
        return output.raw[:observed]

    @staticmethod
    def _parts(relative_path: str) -> tuple[str, ...]:
        try:
            relative_path.encode("utf-8", errors="strict")
        except UnicodeEncodeError as exc:
            raise PlatformServiceError("path_encoding_unsupported") from exc
        path = PurePosixPath(relative_path)
        parts = path.parts
        if not parts or path.is_absolute() or any(part in {"", ".", ".."} for part in parts):
            raise PlatformServiceError("path_invalid")
        return tuple(parts)

    @staticmethod
    def _validate_component(value: str) -> None:
        if not value or "/" in value or value in {".", ".."}:
            raise PlatformServiceError("path_invalid")

    @staticmethod
    def _kind(mode: int) -> str:
        if stat.S_ISREG(mode):
            return "regular"
        if stat.S_ISDIR(mode):
            return "directory"
        if stat.S_ISLNK(mode):
            return "symlink"
        return "special"

    @staticmethod
    def _signature(value: os.stat_result) -> tuple[int, int, int, int, int]:
        return value.st_dev, value.st_ino, value.st_mode, value.st_size, value.st_mtime_ns

    def _identity(self, value: os.stat_result) -> str:
        material = ":".join(str(item) for item in self._signature(value)).encode("ascii")
        return "sha256:" + hashlib.sha256(material).hexdigest()

    @staticmethod
    def _stable_identity(value: os.stat_result) -> str:
        material = f"{value.st_dev}:{value.st_ino}:{value.st_mode}".encode("ascii")
        return "sha256:" + hashlib.sha256(material).hexdigest()

    @staticmethod
    def _read_bounded(descriptor: int, limit: int) -> bytes:
        payload = bytearray()
        while True:
            chunk = os.read(descriptor, min(64 * 1024, limit + 1 - len(payload)))
            if not chunk:
                return bytes(payload)
            payload.extend(chunk)
            if len(payload) > limit:
                raise PlatformServiceError("file_limit_exceeded")

    def _read_relative(self, directory: int, name: str) -> bytes | None:
        try:
            descriptor = os.open(name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=directory)
        except FileNotFoundError:
            return None
        try:
            observed = os.fstat(descriptor)
            if not stat.S_ISREG(observed.st_mode):
                raise PlatformServiceError("not_regular")
            return self._read_bounded(descriptor, 16 * 1024 * 1024)
        finally:
            os.close(descriptor)

    @staticmethod
    def _write_all(descriptor: int, payload: bytes) -> None:
        view = memoryview(payload)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise PlatformServiceError("publication_failed")
            view = view[written:]

    def _rename_noreplace(self, source_fd: int, source: str, target_fd: int, target: str) -> None:
        libc = ctypes.CDLL(None, use_errno=True)
        renameatx_np = getattr(libc, "renameatx_np", None)
        if renameatx_np is None:
            raise PlatformServiceError("noreplace_unsupported")
        result = renameatx_np(
            source_fd,
            os.fsencode(source),
            target_fd,
            os.fsencode(target),
            _RENAME_EXCL,
        )
        if result != 0:
            error = ctypes.get_errno()
            if error in (errno.EEXIST, errno.ENOTEMPTY):
                raise PlatformServiceError("collision")
            if error in (errno.ENOSYS, errno.EINVAL, errno.ENOTSUP):
                raise PlatformServiceError("noreplace_unsupported")
            if error == errno.ENOENT:
                raise PlatformServiceError("identity_changed")
            raise PlatformServiceError("publication_failed")

    def _rename_exchange(self, directory: int, source: str, target: str) -> None:
        libc = ctypes.CDLL(None, use_errno=True)
        renameatx_np = getattr(libc, "renameatx_np", None)
        if renameatx_np is None:
            raise PlatformServiceError("noreplace_unsupported")
        result = renameatx_np(
            directory, os.fsencode(source), directory, os.fsencode(target), _RENAME_SWAP
        )
        if result != 0:
            error = ctypes.get_errno()
            if error in (errno.ENOSYS, errno.EINVAL, errno.ENOTSUP):
                raise PlatformServiceError("noreplace_unsupported")
            if error == errno.ENOENT:
                raise PlatformServiceError("identity_changed")
            raise PlatformServiceError("publication_failed")

    @staticmethod
    def _file_identity(observed: os.stat_result) -> tuple[int, int]:
        return observed.st_dev, observed.st_ino

    def _relative_identity(self, directory: int, name: str) -> tuple[int, int] | None:
        try:
            return self._file_identity(os.stat(name, dir_fd=directory, follow_symlinks=False))
        except FileNotFoundError:
            return None
        except OSError as exc:
            raise PlatformServiceError("publication_failed") from exc

    @staticmethod
    def _canonical_python_executable() -> Path:
        current = Path(sys.executable)
        tool_bin = Path(sys.prefix) / "bin"
        for name in ("python3", "python"):
            candidate = tool_bin / name
            try:
                if candidate.is_absolute() and candidate.samefile(current):
                    return candidate
            except OSError:
                continue
        return current

    @staticmethod
    def _sha256_file(path: Path, limit: int) -> str:
        observed = path.stat()
        if observed.st_size > limit:
            raise PlatformServiceError("launcher_invalid")
        hasher = hashlib.sha256()
        with path.open("rb") as stream:
            while True:
                chunk = stream.read(64 * 1024)
                if not chunk:
                    break
                hasher.update(chunk)
        return "sha256:" + hasher.hexdigest()


def _payload_digest(payload: bytes | None) -> str | None:
    if payload is None:
        return None
    return "sha256:" + hashlib.sha256(payload).hexdigest()


def _digest_identity(value: str) -> str:
    return "sha256:" + hashlib.sha256(value.encode("ascii")).hexdigest()
