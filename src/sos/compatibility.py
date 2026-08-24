"""Bounded, content-safe discovery of existing project control surfaces."""

from __future__ import annotations

import hashlib
import os
import stat
import tomllib
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any, Iterable

from .contracts import digest_value
from .repository import RepositoryError, discover_repository_root
from .result import Status, TerminalResult


_MAX_DISCOVERY_ENTRIES = 20_000
_MAX_NESTED_AGENTS = 128
_MAX_DEPTH = 8
_MAX_FILE_BYTES = 1024 * 1024
_MAX_AUTHORITY_TREE_ENTRIES = 4096
_MAX_AUTHORITY_TREE_BYTES = 8 * 1024 * 1024
_IGNORED_DIRECTORY_NAMES = frozenset(
    {
        ".git",
        ".sigma",
        ".venv",
        ".tox",
        ".mypy_cache",
        ".pytest_cache",
        "node_modules",
        "dist",
        "build",
        "venv",
    }
)
_AUTHORITY_ROOTS = (
    ("openspec:openspec", "openspec", "openspec"),
    ("openspec:.openspec", ".openspec", "openspec"),
    ("bmad:_bmad", "_bmad", "bmad"),
    ("bmad:.bmad-core", ".bmad-core", "bmad"),
    ("bmad:bmad", "bmad", "bmad"),
    ("spec-kit:.specify", ".specify", "spec-kit"),
    ("governance:governance", "governance", "governance"),
    ("governance:docs/governance", "docs/governance", "governance"),
    ("governance:docs/00-governance", "docs/00-governance", "governance"),
)
_INSTRUCTION_BEGIN = b"<!-- >>> SOS managed project recovery (sos_codex_first_v1) -->"
_INSTRUCTION_END = b"<!-- <<< SOS managed project recovery (sos_codex_first_v1) -->"
_CONFIG_BEGIN = b"# >>> SOS managed Codex MCP (sos_codex_mcp_v1)"
_CONFIG_END = b"# <<< SOS managed Codex MCP (sos_codex_mcp_v1)"


class CompatibilityError(RuntimeError):
    def __init__(self, reason: str, status: Status = Status.INVALID) -> None:
        super().__init__(reason)
        self.reason = reason
        self.status = status


@dataclass(frozen=True, slots=True)
class CompatibilityProjection:
    root: Path
    status: Status
    reasons: tuple[str, ...]
    observations: tuple[dict[str, Any], ...]
    authority_candidates: tuple[dict[str, str], ...]
    primary_authority_id: str | None
    discovery_digest: str

    @property
    def authority_paths(self) -> tuple[str, ...]:
        return tuple(candidate["path"] for candidate in self.authority_candidates)

    def details(self, managed_plans: Iterable[dict[str, Any]] = ()) -> dict[str, Any]:
        managed_diff = tuple(_managed_diff(plan) for plan in managed_plans)
        if self.status == Status.OWNER_REQUIRED:
            next_action = (
                "sos init --with-codex --primary-authority "
                "<discovered-id> PATH"
            )
        elif self.status == Status.SUCCESS:
            next_action = "sos init --with-codex PATH"
        else:
            next_action = "resolve the reported compatibility blocker"
        return {
            "discovery_digest": self.discovery_digest,
            "primary_authority_id": self.primary_authority_id,
            "authority_candidates": [
                dict(value) for value in self.authority_candidates
            ],
            "observations": [dict(value) for value in self.observations],
            "managed_diff": list(managed_diff),
            "next_action": next_action,
            "actions": ["preserve", "append", "create", "block"],
            "writes_performed": False,
            "raw_project_content_serialized": False,
            "absolute_paths_serialized": False,
            "path_grammar": "repository_relative_posix_exact_case_v1",
            "limits": {
                "max_discovery_entries": _MAX_DISCOVERY_ENTRIES,
                "max_nested_agents": _MAX_NESTED_AGENTS,
                "max_depth": _MAX_DEPTH,
                "max_file_bytes": _MAX_FILE_BYTES,
                "max_authority_tree_entries": _MAX_AUTHORITY_TREE_ENTRIES,
                "max_authority_tree_bytes": _MAX_AUTHORITY_TREE_BYTES,
            },
        }


def discover_compatibility(
    path: str | Path = ".", *, primary_authority_id: str | None = None
) -> CompatibilityProjection:
    root = discover_repository_root(os.fspath(path))
    observations: list[dict[str, Any]] = []
    candidates: list[dict[str, str]] = []
    blocked: list[str] = []

    agents = _observe_managed_file(root, "AGENTS.md", authority=True)
    observations.append(agents)
    if agents["state"] == "present" and agents["action"] != "block":
        candidates.append(
            {"authority_id": "agents:AGENTS.md", "path": "AGENTS.md", "family": "agents"}
        )
    if agents["action"] == "block":
        blocked.append(agents["reason"])

    codex_directory = _observe_directory(
        root, ".codex", authority_id=None, family="codex"
    )
    if codex_directory is None:
        codex_directory = _observation(
            ".codex", "directory", "absent", "create", None, None, family="codex"
        )
    observations.append(codex_directory)
    if codex_directory["action"] == "block":
        blocked.append(codex_directory["reason"])
        config = _observation(
            ".codex/config.toml",
            "managed_file",
            "parent_blocked",
            "block",
            None,
            codex_directory["reason"],
        )
    else:
        config = _observe_managed_file(root, ".codex/config.toml", authority=False)
    observations.append(config)
    if config["action"] == "block":
        blocked.append(config["reason"])

    sigma = _observe_sigma(root)
    observations.append(sigma)
    if sigma["action"] == "block":
        blocked.append(sigma["reason"])

    for authority_id, relative, family in _AUTHORITY_ROOTS:
        observed = _observe_directory(
            root, relative, authority_id=authority_id, family=family
        )
        if observed is None:
            continue
        observations.append(observed)
        if observed["action"] == "block":
            blocked.append(observed["reason"])
        else:
            candidates.append(
                {"authority_id": authority_id, "path": relative, "family": family}
            )

    nested, nested_blocked = _discover_nested_agents(root)
    observations.extend(nested)
    blocked.extend(nested_blocked)
    observations.sort(key=lambda item: item["path"])
    candidates.sort(key=lambda item: item["authority_id"])

    selected: str | None = None
    if primary_authority_id is not None:
        valid_ids = {candidate["authority_id"] for candidate in candidates}
        if primary_authority_id not in valid_ids:
            blocked.append("SOS_PRIMARY_AUTHORITY_INVALID")
        else:
            selected = primary_authority_id
    elif len(candidates) == 1:
        selected = candidates[0]["authority_id"]

    discovery_value = {
        "contract": "sos_compatibility_discovery_v1",
        "observations": observations,
        "authority_candidates": candidates,
        "primary_authority_id": selected,
        "raw_project_content_serialized": False,
        "absolute_paths_serialized": False,
    }
    discovery_digest = digest_value(discovery_value)
    if blocked:
        reason = (
            "SOS_PRIMARY_AUTHORITY_INVALID"
            if "SOS_PRIMARY_AUTHORITY_INVALID" in blocked
            else blocked[0]
        )
        status = (
            Status.INVALID
            if reason == "SOS_PRIMARY_AUTHORITY_INVALID"
            else Status.BLOCKED
        )
        reasons = (reason,)
    elif len(candidates) > 1 and selected is None:
        status = Status.OWNER_REQUIRED
        reasons = ("SOS_PRIMARY_AUTHORITY_REQUIRED",)
    else:
        status = Status.SUCCESS
        reasons = ("SOS_COMPATIBILITY_READY",)
    return CompatibilityProjection(
        root=root,
        status=status,
        reasons=reasons,
        observations=tuple(observations),
        authority_candidates=tuple(candidates),
        primary_authority_id=selected,
        discovery_digest=discovery_digest,
    )


def compatibility_status(
    path: str | Path = ".", *, primary_authority_id: str | None = None
) -> TerminalResult:
    try:
        projection = discover_compatibility(
            path, primary_authority_id=primary_authority_id
        )
        return TerminalResult(
            "sos_compatibility_projection_v1",
            projection.status,
            projection.reasons,
            projection.details(),
        )
    except RepositoryError as exc:
        return TerminalResult(
            "sos_compatibility_projection_v1", Status.INVALID, (exc.reason,), {}
        )
    except CompatibilityError as exc:
        return TerminalResult(
            "sos_compatibility_projection_v1", exc.status, (exc.reason,), {}
        )


def _observe_managed_file(
    root: Path, relative: str, *, authority: bool
) -> dict[str, Any]:
    path = root / relative
    try:
        observed = path.lstat()
    except FileNotFoundError:
        return _observation(relative, "managed_file", "absent", "create", None, None)
    except OSError as exc:
        raise CompatibilityError(
            "SOS_COMPATIBILITY_OBSERVATION_FAILED", Status.NOT_VERIFIED
        ) from exc
    if stat.S_ISLNK(observed.st_mode):
        return _observation(
            relative,
            "managed_file",
            "symlink",
            "block",
            None,
            "SOS_COMPATIBILITY_SYMLINK_BLOCKED",
        )
    if not stat.S_ISREG(observed.st_mode):
        return _observation(
            relative,
            "managed_file",
            "non_regular",
            "block",
            None,
            "SOS_COMPATIBILITY_NON_REGULAR_BLOCKED",
        )
    try:
        payload = _read_regular_bytes(path)
    except CompatibilityError as exc:
        return _observation(
            relative,
            "authority_file" if authority else "managed_file",
            "invalid",
            "block",
            None,
            exc.reason,
        )
    digest = "sha256:" + hashlib.sha256(payload).hexdigest()
    if relative == "AGENTS.md" and (
        _INSTRUCTION_BEGIN in payload or _INSTRUCTION_END in payload
    ):
        return _observation(
            relative,
            "authority_file",
            "collision",
            "block",
            digest,
            "SOS_CODEX_SETUP_INSTRUCTION_COLLISION",
            byte_count=len(payload),
        )
    if relative == ".codex/config.toml":
        if _CONFIG_BEGIN in payload or _CONFIG_END in payload:
            return _observation(
                relative,
                "managed_file",
                "collision",
                "block",
                digest,
                "SOS_CODEX_SETUP_SERVER_COLLISION",
                byte_count=len(payload),
            )
        try:
            config = tomllib.loads(payload.decode("utf-8"))
        except (UnicodeDecodeError, tomllib.TOMLDecodeError):
            return _observation(
                relative,
                "managed_file",
                "invalid",
                "block",
                digest,
                "SOS_CODEX_CONFIG_INVALID",
                byte_count=len(payload),
            )
        servers = config.get("mcp_servers")
        if isinstance(servers, dict) and "sigma_operator_stack" in servers:
            return _observation(
                relative,
                "managed_file",
                "collision",
                "block",
                digest,
                "SOS_CODEX_SETUP_SERVER_COLLISION",
                byte_count=len(payload),
            )
    return _observation(
        relative,
        "authority_file" if authority else "managed_file",
        "present",
        "append",
        digest,
        None,
        byte_count=len(payload),
    )


def _observe_sigma(root: Path) -> dict[str, Any]:
    path = root / ".sigma"
    try:
        observed = path.lstat()
    except FileNotFoundError:
        return _observation(".sigma", "control_plane", "absent", "create", None, None)
    except OSError as exc:
        raise CompatibilityError(
            "SOS_COMPATIBILITY_OBSERVATION_FAILED", Status.NOT_VERIFIED
        ) from exc
    state = "symlink" if stat.S_ISLNK(observed.st_mode) else "present"
    return _observation(
        ".sigma",
        "control_plane",
        state,
        "block",
        None,
        "SOS_CONTROL_PLANE_COLLISION",
    )


def _observe_directory(
    root: Path, relative: str, *, authority_id: str | None, family: str
) -> dict[str, Any] | None:
    component_reason = _path_component_reason(root, relative)
    if component_reason is not None:
        return _observation(
            relative,
            "authority_directory" if authority_id else "directory",
            "invalid_path",
            "block",
            None,
            component_reason,
            family=family,
        )
    path = root / relative
    try:
        observed = path.lstat()
    except FileNotFoundError:
        return None
    except OSError as exc:
        raise CompatibilityError("SOS_COMPATIBILITY_OBSERVATION_FAILED", Status.NOT_VERIFIED) from exc
    if stat.S_ISLNK(observed.st_mode):
        return _observation(relative, "directory", "symlink", "block", None, "SOS_COMPATIBILITY_SYMLINK_BLOCKED", family=family)
    if not stat.S_ISDIR(observed.st_mode):
        return _observation(relative, "directory", "non_directory", "block", None, "SOS_COMPATIBILITY_NON_DIRECTORY_BLOCKED", family=family)
    try:
        digest, entries, byte_count = _directory_digest(path, root)
    except CompatibilityError as exc:
        return _observation(relative, "authority_directory" if authority_id else "directory", "invalid", "block", None, exc.reason, family=family)
    return _observation(
        relative,
        "authority_directory" if authority_id else "directory",
        "present",
        "preserve",
        digest,
        None,
        family=family,
        entry_count=entries,
        byte_count=byte_count,
    )


def _discover_nested_agents(root: Path) -> tuple[list[dict[str, Any]], list[str]]:
    observations: list[dict[str, Any]] = []
    blocked: list[str] = []
    entries = 0
    stack: list[tuple[Path, int]] = [(root, 0)]
    while stack:
        directory, depth = stack.pop()
        try:
            with os.scandir(directory) as iterator:
                children = sorted(iterator, key=lambda item: item.name)
        except OSError as exc:
            raise CompatibilityError("SOS_COMPATIBILITY_OBSERVATION_FAILED", Status.NOT_VERIFIED) from exc
        for child in children:
            entries += 1
            if entries > _MAX_DISCOVERY_ENTRIES:
                raise CompatibilityError("SOS_COMPATIBILITY_DISCOVERY_LIMIT_EXCEEDED", Status.UNSUPPORTED)
            relative = Path(child.path).relative_to(root).as_posix()
            if relative == "AGENTS.md":
                continue
            try:
                if child.is_symlink():
                    if child.name == "AGENTS.md":
                        observations.append(_observation(relative, "scoped_authority_file", "symlink", "block", None, "SOS_COMPATIBILITY_SYMLINK_BLOCKED"))
                        blocked.append("SOS_COMPATIBILITY_SYMLINK_BLOCKED")
                    continue
                if child.is_dir(follow_symlinks=False):
                    if depth < _MAX_DEPTH and child.name not in _IGNORED_DIRECTORY_NAMES and not child.name.startswith(".sigma.init."):
                        stack.append((Path(child.path), depth + 1))
                    continue
                if child.name != "AGENTS.md":
                    continue
                if not child.is_file(follow_symlinks=False):
                    observations.append(_observation(relative, "scoped_authority_file", "non_regular", "block", None, "SOS_COMPATIBILITY_NON_REGULAR_BLOCKED"))
                    blocked.append("SOS_COMPATIBILITY_NON_REGULAR_BLOCKED")
                    continue
                digest, size = _file_digest(Path(child.path))
                observations.append(_observation(relative, "scoped_authority_file", "present", "preserve", digest, None, byte_count=size))
                if len(observations) > _MAX_NESTED_AGENTS:
                    raise CompatibilityError("SOS_COMPATIBILITY_NESTED_AGENTS_LIMIT_EXCEEDED", Status.UNSUPPORTED)
            except OSError as exc:
                raise CompatibilityError("SOS_COMPATIBILITY_OBSERVATION_FAILED", Status.NOT_VERIFIED) from exc
    return observations, blocked


def _directory_digest(path: Path, root: Path) -> tuple[str, int, int]:
    hasher = hashlib.sha256()
    entries = 0
    byte_count = 0
    stack = [path]
    while stack:
        directory = stack.pop()
        try:
            with os.scandir(directory) as iterator:
                children = sorted(iterator, key=lambda item: item.name)
        except OSError as exc:
            raise CompatibilityError("SOS_COMPATIBILITY_OBSERVATION_FAILED", Status.NOT_VERIFIED) from exc
        for child in children:
            entries += 1
            if entries > _MAX_AUTHORITY_TREE_ENTRIES:
                raise CompatibilityError("SOS_COMPATIBILITY_AUTHORITY_TREE_LIMIT_EXCEEDED", Status.UNSUPPORTED)
            relative = Path(child.path).relative_to(root).as_posix()
            _require_relative(relative)
            hasher.update(relative.encode("utf-8") + b"\0")
            try:
                if child.is_symlink():
                    raise CompatibilityError("SOS_COMPATIBILITY_SYMLINK_BLOCKED")
                if child.is_dir(follow_symlinks=False):
                    hasher.update(b"d\0")
                    stack.append(Path(child.path))
                elif child.is_file(follow_symlinks=False):
                    digest, size = _file_digest(Path(child.path))
                    byte_count += size
                    if byte_count > _MAX_AUTHORITY_TREE_BYTES:
                        raise CompatibilityError("SOS_COMPATIBILITY_AUTHORITY_TREE_LIMIT_EXCEEDED", Status.UNSUPPORTED)
                    hasher.update(b"f\0" + str(size).encode("ascii") + b"\0" + digest.encode("ascii") + b"\0")
                else:
                    raise CompatibilityError("SOS_COMPATIBILITY_NON_REGULAR_BLOCKED")
            except OSError as exc:
                raise CompatibilityError("SOS_COMPATIBILITY_OBSERVATION_FAILED", Status.NOT_VERIFIED) from exc
    return "sha256:" + hasher.hexdigest(), entries, byte_count


def _file_digest(path: Path) -> tuple[str, int]:
    payload = _read_regular_bytes(path)
    return "sha256:" + hashlib.sha256(payload).hexdigest(), len(payload)


def _read_regular_bytes(path: Path) -> bytes:
    flags = os.O_RDONLY | os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise CompatibilityError("SOS_COMPATIBILITY_OBSERVATION_FAILED", Status.NOT_VERIFIED) from exc
    try:
        observed = os.fstat(descriptor)
        if not stat.S_ISREG(observed.st_mode):
            raise CompatibilityError("SOS_COMPATIBILITY_NON_REGULAR_BLOCKED")
        if observed.st_size > _MAX_FILE_BYTES:
            raise CompatibilityError("SOS_COMPATIBILITY_FILE_LIMIT_EXCEEDED", Status.UNSUPPORTED)
        remaining = observed.st_size
        payload = bytearray()
        while remaining:
            chunk = os.read(descriptor, min(remaining, 64 * 1024))
            if not chunk:
                raise CompatibilityError("SOS_COMPATIBILITY_OBSERVATION_FAILED", Status.NOT_VERIFIED)
            payload.extend(chunk)
            remaining -= len(chunk)
        if os.read(descriptor, 1):
            raise CompatibilityError("SOS_COMPATIBILITY_PREVIEW_STALE", Status.STALE)
        return bytes(payload)
    finally:
        os.close(descriptor)


def _observation(
    path: str,
    kind: str,
    state: str,
    action: str,
    content_digest: str | None,
    reason: str | None,
    **extra: Any,
) -> dict[str, Any]:
    _require_relative(path)
    value: dict[str, Any] = {
        "path": path,
        "kind": kind,
        "state": state,
        "action": action,
        "content_digest": content_digest,
        "reason": reason,
    }
    value.update(extra)
    return value


def _managed_diff(plan: dict[str, Any]) -> dict[str, Any]:
    required = (
        "target",
        "patch_kind",
        "before_exists",
        "before_byte_count",
        "before_digest",
        "patch_byte_count",
        "patch_digest",
        "after_byte_count",
        "after_digest",
        "plan_digest",
    )
    if any(key not in plan for key in required):
        raise CompatibilityError("SOS_COMPATIBILITY_MANAGED_DIFF_INVALID")
    return {
        "target": plan["target"],
        "action": "append" if plan["patch_kind"] == "append_suffix" else "create",
        "patch_kind": plan["patch_kind"],
        "before_exists": plan["before_exists"],
        "before_byte_count": plan["before_byte_count"],
        "before_digest": plan["before_digest"],
        "patch_byte_count": plan["patch_byte_count"],
        "patch_digest": plan["patch_digest"],
        "after_byte_count": plan["after_byte_count"],
        "after_digest": plan["after_digest"],
        "plan_digest": plan["plan_digest"],
        "raw_content_serialized": False,
        "absolute_paths_serialized": False,
    }


def _require_relative(value: str) -> None:
    pure = PurePosixPath(value)
    if not value or pure.is_absolute() or ".." in pure.parts or "\\" in value:
        raise CompatibilityError("SOS_COMPATIBILITY_PATH_INVALID")


def _path_component_reason(root: Path, relative: str) -> str | None:
    _require_relative(relative)
    current = root
    parts = PurePosixPath(relative).parts
    for index, part in enumerate(parts):
        current = current / part
        try:
            observed = current.lstat()
        except FileNotFoundError:
            return None
        except OSError as exc:
            raise CompatibilityError(
                "SOS_COMPATIBILITY_OBSERVATION_FAILED", Status.NOT_VERIFIED
            ) from exc
        if stat.S_ISLNK(observed.st_mode):
            return "SOS_COMPATIBILITY_SYMLINK_BLOCKED"
        if index < len(parts) - 1 and not stat.S_ISDIR(observed.st_mode):
            return "SOS_COMPATIBILITY_NON_DIRECTORY_BLOCKED"
    return None
