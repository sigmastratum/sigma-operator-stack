"""Complete, content-safe P101-v2 application dirty observation."""

from __future__ import annotations

import hashlib
import os
import re
import shutil
import stat
import subprocess
from collections.abc import Mapping
from dataclasses import asdict, dataclass
from pathlib import Path


MAX_PATHS = 10_000
MAX_FILE_BYTES = 16_777_216
MAX_TOTAL_BYTES = 268_435_456
MAX_PATH_BYTES = 4096
MAX_SUBMODULES = 256
_COMMAND_TIMEOUT_SECONDS = 10
_MAX_GIT_OUTPUT_BYTES = 32 * 1024 * 1024
_SAFE_PATH = "/usr/local/bin:/opt/homebrew/bin:/usr/bin:/bin"
_GIT_EXECUTABLE = shutil.which("git", path=_SAFE_PATH)
_STAGING_ROOT = re.compile(r"^\.sigma\.init\.[0-9a-f]{64}(?:/|$)")
_PUBLIC_ENV_TEMPLATE_BASENAMES = frozenset(
    {".env.dist", ".env.example", ".env.sample", ".env.template"}
)
_PROTECTED_SQL_TOKENS = frozenset(
    {"backup", "dump", "export", "prod", "production", "snapshot"}
)

_INDEX = 0x01
_WORKTREE = 0x02
_UNTRACKED = 0x03
_SUBMODULE = 0x04
_PROTECTED_IGNORED = 0x05
_GIT_OID = 0x01
_FILE_SHA256 = 0x02
_SYMLINK_TARGET_SHA256 = 0x03
_DELETION = 0x04
_SUBMODULE_STATE = 0x05
_SENSITIVE_PRESENCE = 0x07


@dataclass(frozen=True, slots=True)
class ApplicationObservation:
    state: str
    fingerprint: str | None
    entry_count: int
    bytes_hashed: int
    complete: bool
    content_completeness: str
    exclusion_policy_ref: str
    protected_presence: tuple[dict[str, object], ...]
    reasons: tuple[str, ...]

    def to_dict(self) -> dict[str, object]:
        value = asdict(self)
        value["protected_presence"] = [dict(item) for item in self.protected_presence]
        value["reasons"] = list(self.reasons)
        return value


@dataclass(frozen=True, slots=True)
class _RawChange:
    path: str
    old_mode: int
    new_mode: int
    old_oid: str
    new_oid: str
    status: str


@dataclass(frozen=True, slots=True)
class _Entry:
    path: str
    category: int
    mode: int
    stage: int
    content_kind: int
    content_identity: bytes


@dataclass(frozen=True, slots=True)
class _IndexStage:
    path: str
    mode: int
    oid: str
    stage: int


class _ObservationFailure(RuntimeError):
    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


def observe_application(
    root: Path,
    repository_id: str,
    fingerprint_head: str,
    exclusion_policy_ref: str,
    *,
    overlays: Mapping[str, bytes] | None = None,
) -> ApplicationObservation:
    """Observe all Git application changes, optionally projecting exact file overlays."""
    bytes_hashed = 0
    try:
        before = _candidate_snapshot(root)
        staged, worktree, untracked, ignored, unmerged = before
        projected = _validated_overlays(overlays)
        staged_by_path: dict[str, list[_RawChange]] = {}
        for change in staged:
            staged_by_path.setdefault(change.path, []).append(change)
        worktree_by_path: dict[str, list[_RawChange]] = {}
        for change in worktree:
            worktree_by_path.setdefault(change.path, []).append(change)
        projected_untracked = set(untracked)
        projected_ignored = set(ignored)
        for path, payload in projected.items():
            index_payload = _index_payload(root, path)
            if index_payload is None:
                if path not in projected_ignored:
                    projected_untracked.add(path)
                worktree_by_path.pop(path, None)
            elif payload == index_payload:
                worktree_by_path.pop(path, None)
                projected_untracked.discard(path)
            else:
                mode = _projected_git_mode(root, path)
                worktree_by_path[path] = [_RawChange(path, mode, mode, "0" * 40, "0" * 40, "M")]
                projected_untracked.discard(path)
        candidate_paths = {
            change.path for change in staged
        } | set(worktree_by_path) | projected_untracked | projected_ignored | {item.path for item in unmerged}
        if len(candidate_paths) > MAX_PATHS:
            raise _ObservationFailure("SOS_DIRTY_PATH_LIMIT_EXCEEDED")
        protected_by_path = {
            path: sensitive
            for path in candidate_paths
            if (sensitive := _sensitive_class(path)) is not None
        }
        entries: list[_Entry] = []
        protected: dict[str, dict[str, object]] = {}
        signatures: dict[tuple[str, int], tuple[int, ...] | None] = {}

        submodule_paths = {
            change.path for change in staged
            if change.old_mode == 0o160000 or change.new_mode == 0o160000
        } | {
            change.path
            for changes in worktree_by_path.values()
            for change in changes
            if change.old_mode == 0o160000 or change.new_mode == 0o160000
        } | {item.path for item in unmerged if item.mode == 0o160000}
        if len(submodule_paths) > MAX_SUBMODULES:
            raise _ObservationFailure("SOS_SUBMODULE_LIMIT_EXCEEDED")
        unmerged_by_path: dict[str, list[_IndexStage]] = {}
        for item in unmerged:
            unmerged_by_path.setdefault(item.path, []).append(item)
        submodule_identities: dict[str, bytes] = {}

        for path in sorted(candidate_paths, key=lambda item: item.encode("utf-8")):
            _validate_path(path)
            sensitive = protected_by_path.get(path)
            if path in submodule_paths:
                if sensitive is not None:
                    entry, presence, signature = _protected_entry(root, path, _SUBMODULE, 0o160000, sensitive)
                    entries.append(entry)
                    protected[path] = presence
                    signatures[(path, _SUBMODULE)] = signature
                else:
                    submodule = _submodule_entry(root, path, staged_by_path.get(path, ()))
                    entries.append(submodule)
                    submodule_identities[path] = submodule.content_identity
                continue

            staged_changes = staged_by_path.get(path, ())
            index_stages = unmerged_by_path.get(path, ())
            if index_stages:
                for item in index_stages:
                    entries.append(_Entry(path, _INDEX, item.mode, item.stage, _GIT_OID, _oid(item.oid)))
            for change in (() if index_stages else staged_changes):
                if sensitive is not None and change.new_mode != 0:
                    entry, presence, signature = _protected_entry(
                        root, path, _INDEX, change.new_mode, sensitive
                    )
                    entries.append(entry)
                    protected[path] = presence
                    signatures[(path, _INDEX)] = signature
                elif change.new_mode == 0 or change.status.startswith("D"):
                    entries.append(_Entry(path, _INDEX, change.old_mode, 0, _DELETION, b""))
                else:
                    entries.append(
                        _Entry(path, _INDEX, change.new_mode, 0, _GIT_OID, _oid(change.new_oid))
                    )

            for change in worktree_by_path.get(path, ()):
                if change.status.startswith("D"):
                    entries.append(_Entry(path, _WORKTREE, change.old_mode, 0, _DELETION, b""))
                elif sensitive is not None:
                    entry, presence, signature = _protected_entry(
                        root, path, _WORKTREE, change.new_mode, sensitive
                    )
                    entries.append(entry)
                    protected[path] = presence
                    signatures[(path, _WORKTREE)] = signature
                else:
                    if path in projected:
                        entry, count = _overlay_entry(root, path, _WORKTREE, projected[path])
                        signature = None
                    else:
                        entry, count, signature = _filesystem_entry(root, path, _WORKTREE)
                    bytes_hashed = _add_bytes(bytes_hashed, count)
                    entries.append(entry)
                    if signature is not None:
                        signatures[(path, _WORKTREE)] = signature

            if path in projected_untracked:
                if sensitive is not None:
                    entry, presence, signature = _protected_entry(
                        root, path, _UNTRACKED, 0, sensitive
                    )
                    entries.append(entry)
                    protected[path] = presence
                    signatures[(path, _UNTRACKED)] = signature
                else:
                    if path in projected:
                        entry, count = _overlay_entry(root, path, _UNTRACKED, projected[path])
                        signature = None
                    else:
                        entry, count, signature = _filesystem_entry(root, path, _UNTRACKED)
                    bytes_hashed = _add_bytes(bytes_hashed, count)
                    entries.append(entry)
                    if signature is not None:
                        signatures[(path, _UNTRACKED)] = signature

            if path in projected_ignored and sensitive is not None:
                entry, presence, signature = _protected_entry(
                    root, path, _PROTECTED_IGNORED, 0, sensitive
                )
                entries.append(entry)
                protected[path] = presence
                signatures[(path, _PROTECTED_IGNORED)] = signature

        if len(entries) > MAX_PATHS:
            raise _ObservationFailure("SOS_DIRTY_PATH_LIMIT_EXCEEDED")
        _verify_signatures(root, signatures)
        for path, identity in submodule_identities.items():
            if _submodule_entry(root, path, staged_by_path.get(path, ())).content_identity != identity:
                raise _ObservationFailure("SOS_DIRTY_SNAPSHOT_RACE")
        if before != _candidate_snapshot(root):
            raise _ObservationFailure("SOS_DIRTY_SNAPSHOT_RACE")
        entries.sort(key=lambda item: (item.path.encode("utf-8"), item.category, item.stage))
        material = _stream(repository_id, fingerprint_head, exclusion_policy_ref, entries)
        reasons = ("SOS_PROTECTED_CONTENT_NOT_OBSERVED",) if protected else ()
        return ApplicationObservation(
            state="dirty" if entries else "clean",
            fingerprint="sha256:" + hashlib.sha256(material).hexdigest(),
            entry_count=len(entries),
            bytes_hashed=bytes_hashed,
            complete=True,
            content_completeness=("protected_content_not_observed" if protected else "byte_complete"),
            exclusion_policy_ref=exclusion_policy_ref,
            protected_presence=tuple(protected[path] for path in sorted(protected, key=lambda item: item.encode("utf-8"))),
            reasons=reasons,
        )
    except (_ObservationFailure, OSError, UnicodeError, ValueError) as exc:
        reason = exc.reason if isinstance(exc, _ObservationFailure) else "SOS_DIRTY_OBSERVATION_FAILED"
        return ApplicationObservation(
            state="not_verified",
            fingerprint=None,
            entry_count=0,
            bytes_hashed=min(bytes_hashed, MAX_TOTAL_BYTES),
            complete=False,
            content_completeness="not_verified",
            exclusion_policy_ref=exclusion_policy_ref,
            protected_presence=(),
            reasons=(reason,),
        )


def _validated_overlays(overlays: Mapping[str, bytes] | None) -> dict[str, bytes]:
    if overlays is None:
        return {}
    if not isinstance(overlays, Mapping) or len(overlays) > MAX_PATHS:
        raise _ObservationFailure("SOS_DIRTY_PATH_LIMIT_EXCEEDED")
    projected: dict[str, bytes] = {}
    total = 0
    for path, payload in overlays.items():
        if not isinstance(path, str) or not isinstance(payload, bytes):
            raise _ObservationFailure("SOS_DIRTY_OVERLAY_INVALID")
        _validate_path(path)
        if _excluded(path) or _sensitive_class(path) is not None:
            raise _ObservationFailure("SOS_DIRTY_OVERLAY_INVALID")
        if len(payload) > MAX_FILE_BYTES:
            raise _ObservationFailure("SOS_DIRTY_FILE_LIMIT_EXCEEDED")
        total = _add_bytes(total, len(payload))
        projected[path] = payload
    return projected


def _index_payload(root: Path, path: str) -> bytes | None:
    stages = _parse_index_stages(_git(root, "ls-files", "--stage", "-z", "--", path))
    stage = next((item for item in stages if item.path == path and item.stage == 0), None)
    if stage is None:
        return None
    if stage.mode == 0o160000:
        raise _ObservationFailure("SOS_DIRTY_OVERLAY_INVALID")
    payload = _git(root, "show", f":{path}")
    if len(payload) > MAX_FILE_BYTES:
        raise _ObservationFailure("SOS_DIRTY_FILE_LIMIT_EXCEEDED")
    return payload


def _projected_git_mode(root: Path, path: str) -> int:
    try:
        observed = (root / path).lstat()
    except FileNotFoundError:
        return 0o100644
    if not stat.S_ISREG(observed.st_mode):
        raise _ObservationFailure("SOS_DIRTY_FILESYSTEM_TYPE_UNSUPPORTED")
    return _git_mode(observed.st_mode)


def _overlay_entry(root: Path, path: str, category: int, payload: bytes) -> tuple[_Entry, int]:
    return (
        _Entry(path, category, _projected_git_mode(root, path), 0, _FILE_SHA256, hashlib.sha256(payload).digest()),
        len(payload),
    )


def _candidate_snapshot(
    root: Path,
) -> tuple[
    tuple[_RawChange, ...],
    tuple[_RawChange, ...],
    tuple[str, ...],
    tuple[str, ...],
    tuple[_IndexStage, ...],
]:
    staged = tuple(_parse_raw(_git(root, "diff-index", "--cached", "--raw", "-z", "--no-renames", "HEAD", "--")))
    worktree = tuple(_parse_raw(_git(root, "diff-files", "--raw", "-z", "--no-renames", "--")))
    untracked_files = _parse_paths(_git(root, "ls-files", "--others", "--exclude-standard", "-z"))
    untracked_directories = _parse_directory_paths(
        _git(root, "ls-files", "--others", "--exclude-standard", "--directory", "-z")
    )
    untracked = tuple(sorted(set(untracked_files) | set(untracked_directories), key=lambda item: item.encode("utf-8")))
    ignored_files = _parse_paths(
        _git(root, "ls-files", "--others", "--ignored", "--exclude-standard", "-z")
    )
    ignored_directories = _parse_directory_paths(
        _git(
            root,
            "ls-files",
            "--others",
            "--ignored",
            "--exclude-standard",
            "--directory",
            "-z",
        )
    )
    ignored = tuple(
        sorted(
            {path for path in (*ignored_files, *ignored_directories) if _sensitive_class(path) is not None},
            key=lambda item: item.encode("utf-8"),
        )
    )
    unmerged = tuple(_parse_index_stages(_git(root, "ls-files", "--unmerged", "-z")))
    return staged, worktree, untracked, ignored, unmerged


def _git(root: Path, *args: str) -> bytes:
    if _GIT_EXECUTABLE is None:
        raise _ObservationFailure("SOS_DIRTY_GIT_INSPECTION_FAILED")
    environment = {
        "PATH": _SAFE_PATH,
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_TERMINAL_PROMPT": "0",
        "GIT_OPTIONAL_LOCKS": "0",
        "GIT_PAGER": "cat",
        "GIT_EXTERNAL_DIFF": "",
    }
    try:
        completed = subprocess.run(
            [
                _GIT_EXECUTABLE,
                "-c",
                "core.fsmonitor=false",
                "-c",
                "core.hooksPath=/dev/null",
                "-c",
                "diff.external=",
                "-C",
                os.fspath(root),
                *args,
            ],
            check=False,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=_COMMAND_TIMEOUT_SECONDS,
            env=environment,
            shell=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise _ObservationFailure("SOS_DIRTY_GIT_INSPECTION_FAILED") from exc
    if completed.returncode != 0:
        raise _ObservationFailure("SOS_DIRTY_GIT_INSPECTION_FAILED")
    if len(completed.stdout) > _MAX_GIT_OUTPUT_BYTES:
        raise _ObservationFailure("SOS_DIRTY_GIT_OUTPUT_LIMIT_EXCEEDED")
    return completed.stdout


def _parse_raw(raw: bytes) -> list[_RawChange]:
    parts = raw.split(b"\0")
    if parts and parts[-1] == b"":
        parts.pop()
    if len(parts) % 2:
        raise _ObservationFailure("SOS_DIRTY_GIT_OUTPUT_MALFORMED")
    changes: list[_RawChange] = []
    for offset in range(0, len(parts), 2):
        header, path_raw = parts[offset], parts[offset + 1]
        fields = header.split(b" ")
        if len(fields) != 5 or not fields[0].startswith(b":"):
            raise _ObservationFailure("SOS_DIRTY_GIT_OUTPUT_MALFORMED")
        try:
            path = path_raw.decode("utf-8", errors="strict")
            if _excluded(path):
                continue
            changes.append(
                _RawChange(
                    path,
                    int(fields[0][1:], 8),
                    int(fields[1], 8),
                    fields[2].decode("ascii"),
                    fields[3].decode("ascii"),
                    fields[4].decode("ascii"),
                )
            )
        except (UnicodeError, ValueError) as exc:
            raise _ObservationFailure("SOS_DIRTY_GIT_OUTPUT_MALFORMED") from exc
    return changes


def _parse_paths(raw: bytes) -> list[str]:
    values: list[str] = []
    for path_raw in raw.split(b"\0"):
        if not path_raw:
            continue
        try:
            path = path_raw.decode("utf-8", errors="strict")
        except UnicodeDecodeError as exc:
            raise _ObservationFailure("SOS_DIRTY_PATH_ENCODING_UNSUPPORTED") from exc
        if _excluded(path):
            continue
        values.append(path)
    return values


def _parse_directory_paths(raw: bytes) -> list[str]:
    values: list[str] = []
    for path_raw in raw.split(b"\0"):
        if not path_raw:
            continue
        try:
            path = path_raw.decode("utf-8", errors="strict")
        except UnicodeDecodeError as exc:
            raise _ObservationFailure("SOS_DIRTY_PATH_ENCODING_UNSUPPORTED") from exc
        if not path.endswith("/"):
            continue
        path = path[:-1]
        if not _excluded(path) and _sensitive_class(path) is not None:
            values.append(path)
    return values


def _parse_index_stages(raw: bytes) -> list[_IndexStage]:
    values: list[_IndexStage] = []
    for record in raw.split(b"\0"):
        if not record:
            continue
        try:
            metadata, path_raw = record.split(b"\t", 1)
            mode_raw, oid_raw, stage_raw = metadata.split(b" ")
            path = path_raw.decode("utf-8", errors="strict")
            if _excluded(path):
                continue
            values.append(
                _IndexStage(path, int(mode_raw, 8), oid_raw.decode("ascii"), int(stage_raw))
            )
        except (ValueError, UnicodeError) as exc:
            raise _ObservationFailure("SOS_DIRTY_GIT_OUTPUT_MALFORMED") from exc
    return values


def _excluded(path: str) -> bool:
    return path == ".sigma" or path.startswith(".sigma/") or bool(_STAGING_ROOT.match(path))


def _validate_path(path: str) -> None:
    encoded = path.encode("utf-8")
    if (
        not path
        or len(encoded) > MAX_PATH_BYTES
        or path.startswith("/")
        or path.endswith("/")
        or "//" in path
        or "\\" in path
        or any(part in {"", ".", ".."} for part in path.split("/"))
        or any(ord(character) < 32 or ord(character) == 127 for character in path)
    ):
        raise _ObservationFailure(
            "SOS_PATH_LIMIT_EXCEEDED" if len(encoded) > MAX_PATH_BYTES else "SOS_DIRTY_PATH_INVALID"
        )


def _filesystem_entry(root: Path, path: str, category: int) -> tuple[_Entry, int, tuple[int, int, int, int, int]]:
    parent_fd, name = _open_parent(root, path)
    try:
        before = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
        mode = _git_mode(before.st_mode)
        signature = _signature(before)
        if stat.S_ISLNK(before.st_mode):
            target = os.readlink(name, dir_fd=parent_fd)
            target_bytes = os.fsencode(target)
            if len(target_bytes) > MAX_FILE_BYTES:
                raise _ObservationFailure("SOS_DIRTY_FILE_LIMIT_EXCEEDED")
            after = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
            if _signature(after) != signature:
                raise _ObservationFailure("SOS_DIRTY_SNAPSHOT_RACE")
            return _Entry(path, category, mode, 0, _SYMLINK_TARGET_SHA256, hashlib.sha256(target_bytes).digest()), len(target_bytes), signature
        if not stat.S_ISREG(before.st_mode):
            raise _ObservationFailure("SOS_DIRTY_FILESYSTEM_TYPE_UNSUPPORTED")
        flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(name, flags, dir_fd=parent_fd)
        try:
            opened = os.fstat(descriptor)
            if _signature(opened) != signature:
                raise _ObservationFailure("SOS_DIRTY_SNAPSHOT_RACE")
            digest = hashlib.sha256()
            total = 0
            while True:
                chunk = os.read(descriptor, min(1024 * 1024, MAX_FILE_BYTES + 1 - total))
                if not chunk:
                    break
                total += len(chunk)
                if total > MAX_FILE_BYTES:
                    raise _ObservationFailure("SOS_DIRTY_FILE_LIMIT_EXCEEDED")
                digest.update(chunk)
            after = os.fstat(descriptor)
            if _signature(after) != signature:
                raise _ObservationFailure("SOS_DIRTY_SNAPSHOT_RACE")
        finally:
            os.close(descriptor)
        return _Entry(path, category, mode, 0, _FILE_SHA256, digest.digest()), total, signature
    finally:
        os.close(parent_fd)


def _protected_entry(
    root: Path,
    path: str,
    category: int,
    mode: int,
    sensitive_class: str,
) -> tuple[_Entry, dict[str, object], tuple[int]]:
    parent_fd, name = _open_parent(root, path)
    try:
        observed = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
    finally:
        os.close(parent_fd)
    filesystem_type, type_code = _filesystem_type(observed.st_mode)
    effective_mode = mode or _git_mode(observed.st_mode)
    identity = _text(path) + bytes((type_code,)) + hashlib.sha256(sensitive_class.encode("utf-8")).digest()
    presence = {
        "path_projection": path,
        "filesystem_type": filesystem_type,
        "sensitive_class_id": sensitive_class,
        "content_opened": False,
        "content_hashed": False,
    }
    return _Entry(path, category, effective_mode, 0, _SENSITIVE_PRESENCE, identity), presence, (_type_bits(observed.st_mode),)


def _submodule_entry(root: Path, path: str, staged: tuple[_RawChange, ...] | list[_RawChange]) -> _Entry:
    index_oid = next((change.new_oid for change in staged if change.new_mode == 0o160000), None)
    if index_oid is None:
        index_entries = _parse_index_stages(_git(root, "ls-files", "--stage", "-z", "--", path))
        index_oid = next(
            (item.oid for item in index_entries if item.mode == 0o160000 and item.stage == 0),
            None,
        )
    module = root / path
    initialized = module.is_dir() and (module / ".git").exists()
    worktree_head: str | None = None
    tracked_dirty = False
    untracked_dirty = False
    if initialized:
        head = _git(module, "rev-parse", "--verify", "HEAD").strip().decode("ascii")
        status_raw = _git(module, "status", "--porcelain=v1", "-z", "--untracked-files=all", "--ignored=no")
        worktree_head = head
        for record in (item for item in status_raw.split(b"\0") if item):
            if record.startswith(b"?? "):
                untracked_dirty = True
            else:
                tracked_dirty = True
    identity = (
        _maybe_oid(index_oid)
        + bytes((int(initialized),))
        + _maybe_oid(worktree_head)
        + bytes((int(tracked_dirty), int(untracked_dirty)))
    )
    return _Entry(path, _SUBMODULE, 0o160000, 0, _SUBMODULE_STATE, identity)


def _verify_signatures(
    root: Path,
    signatures: dict[tuple[str, int], tuple[int, ...] | None],
) -> None:
    for path, _category in signatures:
        parent_fd, name = _open_parent(root, path)
        try:
            try:
                observed = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
                expected = signatures[(path, _category)]
                current = (_type_bits(observed.st_mode),) if expected is not None and len(expected) == 1 else _signature(observed)
            except FileNotFoundError:
                current = None
        finally:
            os.close(parent_fd)
        if current != signatures[(path, _category)]:
            raise _ObservationFailure("SOS_DIRTY_SNAPSHOT_RACE")


def _open_parent(root: Path, path: str) -> tuple[int, str]:
    parts = path.split("/")
    descriptor = os.open(root, os.O_RDONLY | os.O_DIRECTORY | getattr(os, "O_CLOEXEC", 0))
    try:
        for component in parts[:-1]:
            next_descriptor = os.open(
                component,
                os.O_RDONLY | os.O_DIRECTORY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0),
                dir_fd=descriptor,
            )
            os.close(descriptor)
            descriptor = next_descriptor
        return descriptor, parts[-1]
    except BaseException:
        os.close(descriptor)
        raise


def _signature(value: os.stat_result) -> tuple[int, int, int, int, int]:
    return (value.st_dev, value.st_ino, value.st_mode, value.st_size, value.st_mtime_ns)


def _type_bits(mode: int) -> int:
    return stat.S_IFMT(mode)


def _git_mode(mode: int) -> int:
    if stat.S_ISREG(mode):
        return 0o100755 if mode & stat.S_IXUSR else 0o100644
    if stat.S_ISLNK(mode):
        return 0o120000
    if stat.S_ISDIR(mode):
        return 0o040000
    return 0


def _filesystem_type(mode: int) -> tuple[str, int]:
    if stat.S_ISREG(mode):
        return "regular", 0x01
    if stat.S_ISDIR(mode):
        return "directory", 0x02
    if stat.S_ISLNK(mode):
        return "symlink", 0x03
    return "other", 0x04


def _sensitive_class(path: str) -> str | None:
    basename = path.rsplit("/", 1)[-1]
    parts = path.split("/")
    if (
        basename == ".env"
        or (
            basename.startswith(".env.")
            and basename not in _PUBLIC_ENV_TEMPLATE_BASENAMES
        )
        or basename.endswith(".secret")
        or basename.endswith(".secrets")
        or any(
            part == ".env" or part.startswith(".env.")
            for part in parts[:-1]
        )
    ):
        return "environment_or_secret"
    if basename in {"id_rsa", "id_dsa", "id_ecdsa", "id_ed25519"} or basename.endswith((".pem", ".key", ".p12", ".pfx")):
        return "private_key"
    if basename in {"credentials", "credentials.json", ".netrc", ".git-credentials"} or ".aws" in parts or ".ssh" in parts:
        return "credential_store"
    if any(marker in basename for marker in ("conversation", "transcript", "chat_export", "messages_export")):
        return "raw_conversation_export"
    sql_tokens = (
        frozenset(re.split(r"[._-]", basename[:-4]))
        if basename.endswith(".sql")
        else frozenset()
    )
    if basename.endswith((".db", ".sqlite", ".sqlite3", ".dump")) or sql_tokens.intersection(
        _PROTECTED_SQL_TOKENS
    ):
        return "production_or_database_dump"
    if basename in {".npmrc", ".pypirc", "settings.xml", "pip.conf"} or parts[:2] == [".config", "gcloud"]:
        return "authenticated_remote_configuration"
    return None


def sensitive_path_class(path: str) -> str | None:
    """Return the frozen public sensitive-path class without opening the path."""
    return _sensitive_class(path)


def _add_bytes(current: int, added: int) -> int:
    result = current + added
    if result > MAX_TOTAL_BYTES:
        raise _ObservationFailure("SOS_DIRTY_TOTAL_LIMIT_EXCEEDED")
    return result


def _oid(value: str) -> bytes:
    try:
        raw = bytes.fromhex(value)
    except ValueError as exc:
        raise _ObservationFailure("SOS_DIRTY_GIT_OUTPUT_MALFORMED") from exc
    if not raw or len(raw) > 255:
        raise _ObservationFailure("SOS_DIRTY_GIT_OUTPUT_MALFORMED")
    return bytes((len(raw),)) + raw


def _maybe_oid(value: str | None) -> bytes:
    return b"\0" if value is None else _oid(value)


def _text(value: str) -> bytes:
    raw = value.encode("utf-8")
    return len(raw).to_bytes(4, "big") + raw


def _entry_bytes(entry: _Entry) -> bytes:
    return (
        b"\x01"
        + _text(entry.path)
        + bytes((entry.category,))
        + entry.mode.to_bytes(4, "big")
        + bytes((entry.stage, entry.content_kind))
        + len(entry.content_identity).to_bytes(4, "big")
        + entry.content_identity
    )


def _stream(repository_id: str, head: str, exclusion_policy_ref: str, entries: list[_Entry]) -> bytes:
    repository_hash = bytes.fromhex(repository_id.removeprefix("sha256:"))
    head_oid = _oid(head)
    policy_hash = bytes.fromhex(exclusion_policy_ref.removeprefix("sha256:"))
    if len(repository_hash) != 32 or len(policy_hash) != 32:
        raise _ObservationFailure("SOS_DIRTY_BINDING_INVALID")
    return (
        b"sos_dirty_v1"
        + b"\0"
        + repository_hash
        + head_oid
        + policy_hash
        + len(entries).to_bytes(4, "big")
        + b"".join(_entry_bytes(entry) for entry in entries)
    )
