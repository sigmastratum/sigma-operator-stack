"""Disposable-only bootstrap transaction primitive; not exposed by the CLI."""

from __future__ import annotations

import json
import os
import re
import ctypes
import errno
import stat
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path

from .platform_admission import FilesystemAdmissionError, require_project_filesystem


_TX = re.compile(r"^[0-9a-f]{64}$")
_DISPOSABLE_MARKER = ".sos-disposable-root"


class TransactionError(RuntimeError):
    pass


_RENAME_NOREPLACE = 1
_MAX_BOOTSTRAP_BYTES = 4 * 1024 * 1024


def _rename_noreplace(source_directory_fd: int, source: str, target_directory_fd: int, target: str) -> None:
    libc = ctypes.CDLL(None, use_errno=True)
    renameat2 = getattr(libc, "renameat2", None)
    if renameat2 is None:
        raise TransactionError("SOS_NOREPLACE_RENAME_UNSUPPORTED")
    renameat2.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint]
    renameat2.restype = ctypes.c_int
    result = renameat2(
        source_directory_fd,
        os.fsencode(source),
        target_directory_fd,
        os.fsencode(target),
        _RENAME_NOREPLACE,
    )
    if result == 0:
        return
    error = ctypes.get_errno()
    if error in (errno.EEXIST, errno.ENOTEMPTY):
        raise TransactionError("SOS_CONTROL_PLANE_COLLISION")
    if error in (errno.ENOSYS, errno.EINVAL, errno.ENOTSUP):
        raise TransactionError("SOS_NOREPLACE_RENAME_UNSUPPORTED")
    raise TransactionError("SOS_ATOMIC_RENAME_FAILED")


def _write_all(descriptor: int, payload: bytes) -> None:
    offset = 0
    while offset < len(payload):
        written = os.write(descriptor, payload[offset:])
        if written <= 0:
            raise TransactionError("SOS_BOOTSTRAP_WRITE_FAILED")
        offset += written


@dataclass(frozen=True, slots=True)
class BootstrapPlan:
    transaction_id: str
    repository_id: str
    plan_digest: str

    def __post_init__(self) -> None:
        if not _TX.fullmatch(self.transaction_id):
            raise ValueError("SOS_TRANSACTION_ID_INVALID")
        if not self.repository_id.startswith("sha256:") or len(self.repository_id) != 71:
            raise ValueError("SOS_REPOSITORY_ID_INVALID")
        if not self.plan_digest.startswith("sha256:") or len(self.plan_digest) != 71:
            raise ValueError("SOS_PLAN_DIGEST_INVALID")


def execute_disposable_bootstrap(root: Path, plan: BootstrapPlan, records: dict[str, dict], *, allow_disposable: bool) -> Path:
    """Atomically create `.sigma` only in an explicitly marked disposable root."""
    if not allow_disposable or not (root / _DISPOSABLE_MARKER).is_file():
        raise TransactionError("SOS_DISPOSABLE_AUTHORITY_REQUIRED")
    if root.is_symlink() or not root.is_dir():
        raise TransactionError("SOS_REPOSITORY_ROOT_INVALID")
    _require_admitted_filesystem(root)
    target = root / ".sigma"
    staging = root / f".sigma.init.{plan.transaction_id}"
    if target.exists() or target.is_symlink() or staging.exists() or staging.is_symlink():
        raise TransactionError("SOS_CONTROL_PLANE_COLLISION")
    root_descriptor = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.mkdir(staging.name, mode=0o700, dir_fd=root_descriptor)
        staging_descriptor = os.open(
            staging.name,
            os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
            dir_fd=root_descriptor,
        )
        try:
            manifest = {
                "contract": "sos_disposable_bootstrap_v1",
                "repository_id": plan.repository_id,
                "plan_digest": plan.plan_digest,
                "records": records,
            }
            payload = json.dumps(manifest, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
            if len(payload) > _MAX_BOOTSTRAP_BYTES:
                raise TransactionError("SOS_BOOTSTRAP_OUTPUT_LIMIT_EXCEEDED")
            descriptor = os.open(
                "bootstrap.json",
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                0o600,
                dir_fd=staging_descriptor,
            )
            try:
                _write_all(descriptor, payload)
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
            os.fsync(staging_descriptor)
        finally:
            os.close(staging_descriptor)
        _rename_noreplace(root_descriptor, staging.name, root_descriptor, target.name)
        os.fsync(root_descriptor)
        return target
    except BaseException:
        if staging.exists() and not target.exists():
            for child in staging.iterdir():
                child.unlink()
            staging.rmdir()
        raise
    finally:
        os.close(root_descriptor)


def execute_bootstrap_files(
    root: Path,
    transaction_id: str,
    files: Mapping[str, bytes],
    *,
    confirmed: bool,
) -> Path:
    """Create a new `.sigma` tree atomically without replacing existing state."""
    if not confirmed:
        raise TransactionError("SOS_BOOTSTRAP_CONFIRMATION_REQUIRED")
    if not _TX.fullmatch(transaction_id):
        raise TransactionError("SOS_TRANSACTION_ID_INVALID")
    if root.is_symlink() or not root.is_dir():
        raise TransactionError("SOS_REPOSITORY_ROOT_INVALID")
    target_name = ".sigma"
    staging_name = f".sigma.init.{transaction_id}"
    if not files:
        raise TransactionError("SOS_BOOTSTRAP_PLAN_EMPTY")
    total = 0
    normalized: dict[tuple[str, ...], bytes] = {}
    for relative, payload in files.items():
        path = Path(relative)
        parts = path.parts
        if path.is_absolute() or not parts or any(part in ("", ".", "..") for part in parts):
            raise TransactionError("SOS_BOOTSTRAP_PATH_INVALID")
        if any("/" in part or "\\" in part or "\x00" in part for part in parts):
            raise TransactionError("SOS_BOOTSTRAP_PATH_INVALID")
        total += len(payload)
        if total > _MAX_BOOTSTRAP_BYTES:
            raise TransactionError("SOS_BOOTSTRAP_OUTPUT_LIMIT_EXCEEDED")
        normalized[parts] = payload

    create_bootstrap_staging(root, transaction_id, normalized)
    return commit_bootstrap_staging(root, transaction_id)


def create_bootstrap_staging(
    root: Path,
    transaction_id: str,
    files: Mapping[str | tuple[str, ...], bytes],
) -> Path:
    """Create one exact sibling staging tree without making it canonical."""
    if not _TX.fullmatch(transaction_id):
        raise TransactionError("SOS_TRANSACTION_ID_INVALID")
    if root.is_symlink() or not root.is_dir():
        raise TransactionError("SOS_REPOSITORY_ROOT_INVALID")
    _require_admitted_filesystem(root)
    normalized = _normalize_files(files)
    if not normalized:
        raise TransactionError("SOS_BOOTSTRAP_PLAN_EMPTY")
    target_name = ".sigma"
    staging_name = f".sigma.init.{transaction_id}"
    root_descriptor = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        if _entry_exists(root_descriptor, target_name):
            raise TransactionError("SOS_CONTROL_PLANE_COLLISION")
        try:
            os.mkdir(staging_name, mode=0o700, dir_fd=root_descriptor)
        except FileExistsError as exc:
            raise TransactionError("SOS_CONTROL_PLANE_COLLISION") from exc
        staging_descriptor = os.open(
            staging_name,
            os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
            dir_fd=root_descriptor,
        )
        try:
            directories = sorted({parts[:depth] for parts in normalized for depth in range(1, len(parts))})
            for directory_parts in directories:
                _mkdir_relative(staging_descriptor, directory_parts)
            for parts, payload in sorted(normalized.items()):
                _write_relative(staging_descriptor, parts, payload)
            os.fsync(staging_descriptor)
        finally:
            os.close(staging_descriptor)
        return root / staging_name
    finally:
        os.close(root_descriptor)


def extend_bootstrap_staging(
    root: Path,
    transaction_id: str,
    files: Mapping[str | tuple[str, ...], bytes],
) -> Path:
    """Append non-colliding files to one exact staging tree."""
    if not _TX.fullmatch(transaction_id):
        raise TransactionError("SOS_TRANSACTION_ID_INVALID")
    _require_admitted_filesystem(root)
    normalized = _normalize_files(files)
    staging_name = f".sigma.init.{transaction_id}"
    root_descriptor = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        staging_descriptor = os.open(
            staging_name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=root_descriptor
        )
        try:
            directories = sorted({parts[:depth] for parts in normalized for depth in range(1, len(parts))})
            for directory_parts in directories:
                _mkdir_relative(staging_descriptor, directory_parts)
            for parts, payload in sorted(normalized.items()):
                _write_relative(staging_descriptor, parts, payload)
            os.fsync(staging_descriptor)
        finally:
            os.close(staging_descriptor)
        return root / staging_name
    except (FileNotFoundError, NotADirectoryError) as exc:
        raise TransactionError("SOS_STAGING_RECOVERY_REQUIRED") from exc
    finally:
        os.close(root_descriptor)


def commit_bootstrap_staging(root: Path, transaction_id: str) -> Path:
    """Atomically admit one fully prepared sibling tree as canonical `.sigma`."""
    if not _TX.fullmatch(transaction_id):
        raise TransactionError("SOS_TRANSACTION_ID_INVALID")
    _require_admitted_filesystem(root)
    staging_name = f".sigma.init.{transaction_id}"
    root_descriptor = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        staging_descriptor = os.open(
            staging_name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=root_descriptor
        )
        os.fsync(staging_descriptor)
        os.close(staging_descriptor)
        _rename_noreplace(root_descriptor, staging_name, root_descriptor, ".sigma")
        os.fsync(root_descriptor)
        return root / ".sigma"
    except (FileNotFoundError, NotADirectoryError) as exc:
        raise TransactionError("SOS_STAGING_RECOVERY_REQUIRED") from exc
    finally:
        os.close(root_descriptor)


def discard_bootstrap_staging(root: Path, transaction_id: str) -> None:
    """Remove only one validated sibling staging tree; never follow symlinks."""
    if not _TX.fullmatch(transaction_id):
        raise TransactionError("SOS_TRANSACTION_ID_INVALID")
    staging_name = f".sigma.init.{transaction_id}"
    root_descriptor = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        try:
            staging_descriptor = os.open(
                staging_name,
                os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                dir_fd=root_descriptor,
            )
        except FileNotFoundError:
            return
        try:
            _discard_directory_contents(staging_descriptor)
        finally:
            os.close(staging_descriptor)
        os.rmdir(staging_name, dir_fd=root_descriptor)
        os.fsync(root_descriptor)
    except (NotADirectoryError, OSError) as exc:
        raise TransactionError("SOS_STAGING_RECOVERY_REQUIRED") from exc
    finally:
        os.close(root_descriptor)


def _discard_directory_contents(directory_fd: int) -> None:
    for name in os.listdir(directory_fd):
        observed = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
        if stat.S_ISDIR(observed.st_mode):
            child = os.open(
                name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=directory_fd
            )
            try:
                _discard_directory_contents(child)
            finally:
                os.close(child)
            os.rmdir(name, dir_fd=directory_fd)
        else:
            os.unlink(name, dir_fd=directory_fd)


def _require_admitted_filesystem(root: Path) -> None:
    try:
        require_project_filesystem(root)
    except FilesystemAdmissionError as exc:
        raise TransactionError(exc.reason) from exc


def _normalize_files(
    files: Mapping[str | tuple[str, ...], bytes],
) -> dict[tuple[str, ...], bytes]:
    total = 0
    normalized: dict[tuple[str, ...], bytes] = {}
    for relative, payload in files.items():
        path = Path(*relative) if isinstance(relative, tuple) else Path(relative)
        parts = path.parts
        if not isinstance(payload, bytes):
            raise TransactionError("SOS_BOOTSTRAP_PAYLOAD_INVALID")
        if path.is_absolute() or not parts or any(part in ("", ".", "..") for part in parts):
            raise TransactionError("SOS_BOOTSTRAP_PATH_INVALID")
        if any("/" in part or "\\" in part or "\x00" in part for part in parts):
            raise TransactionError("SOS_BOOTSTRAP_PATH_INVALID")
        total += len(payload)
        if total > _MAX_BOOTSTRAP_BYTES:
            raise TransactionError("SOS_BOOTSTRAP_OUTPUT_LIMIT_EXCEEDED")
        normalized[parts] = payload
    return normalized


def _entry_exists(directory_fd: int, name: str) -> bool:
    try:
        os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
    except FileNotFoundError:
        return False
    return True


def _open_directory_chain(root_descriptor: int, parts: tuple[str, ...]) -> int:
    descriptor = os.dup(root_descriptor)
    try:
        for part in parts:
            next_descriptor = os.open(
                part,
                os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                dir_fd=descriptor,
            )
            os.close(descriptor)
            descriptor = next_descriptor
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def _mkdir_relative(root_descriptor: int, parts: tuple[str, ...]) -> None:
    parent = _open_directory_chain(root_descriptor, parts[:-1])
    try:
        try:
            os.mkdir(parts[-1], mode=0o700, dir_fd=parent)
        except FileExistsError:
            existing = os.open(
                parts[-1],
                os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                dir_fd=parent,
            )
            os.close(existing)
    finally:
        os.close(parent)


def _write_relative(root_descriptor: int, parts: tuple[str, ...], payload: bytes) -> None:
    parent = _open_directory_chain(root_descriptor, parts[:-1])
    try:
        descriptor = os.open(
            parts[-1],
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
            0o600,
            dir_fd=parent,
        )
        try:
            _write_all(descriptor, payload)
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        os.fsync(parent)
    finally:
        os.close(parent)
