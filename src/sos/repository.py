"""Read-only, bounded Git repository discovery and status projection."""

from __future__ import annotations

import hashlib
import os
import re
import subprocess
from dataclasses import asdict, dataclass
from pathlib import Path
from urllib.parse import urlsplit


_STAGING_ROOT = re.compile(r"^\.sigma\.init\.[0-9a-f]{64}(?:/|$)")
_STAGING_ROOT_NAME = re.compile(r"^\.sigma\.init\.[0-9a-f]{64}$")
_COMMAND_TIMEOUT_SECONDS = 5
_MAX_GIT_OUTPUT_BYTES = 8 * 1024 * 1024


class RepositoryError(RuntimeError):
    """A typed, content-safe repository inspection failure."""

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


@dataclass(frozen=True, slots=True)
class RepositoryInspection:
    contract: str
    root: str
    root_path_serialized: bool
    repository_id: str
    head: str | None
    branch: str | None
    detached: bool
    object_format: str
    application_state: str
    application_entry_count: int
    application_status_digest: str
    application_tree_digest: str
    control_plane_state: str
    staging_roots: tuple[str, ...]
    reasons: tuple[str, ...]

    def to_dict(self) -> dict[str, object]:
        value = asdict(self)
        value["staging_roots"] = list(self.staging_roots)
        value["reasons"] = list(self.reasons)
        return value


@dataclass(frozen=True, slots=True)
class RepositoryIdentity:
    contract: str
    repository_id: str
    identity_mode: str
    object_format: str
    root_commit_ids: tuple[str, ...]
    identity_remote_hashes: tuple[dict[str, str], ...]
    local_nonce_commitment: str | None
    remote_url_serialized: bool = False

    def to_dict(self) -> dict[str, object]:
        return {
            "contract": self.contract,
            "repository_id": self.repository_id,
            "identity_mode": self.identity_mode,
            "object_format": self.object_format,
            "root_commit_ids": list(self.root_commit_ids),
            "identity_remote_hashes": [dict(item) for item in self.identity_remote_hashes],
            "local_nonce_commitment": self.local_nonce_commitment,
            "remote_url_serialized": self.remote_url_serialized,
        }


def _bounded_git(root: Path, *args: str) -> bytes:
    environment = {
        "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_TERMINAL_PROMPT": "0",
    }
    try:
        completed = subprocess.run(
            ["git", "-C", os.fspath(root), *args],
            check=False,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=_COMMAND_TIMEOUT_SECONDS,
            env=environment,
            shell=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise RepositoryError("SOS_GIT_INSPECTION_FAILED") from exc
    if completed.returncode != 0:
        raise RepositoryError("SOS_NOT_A_GIT_REPOSITORY")
    if len(completed.stdout) > _MAX_GIT_OUTPUT_BYTES:
        raise RepositoryError("SOS_GIT_OUTPUT_LIMIT_EXCEEDED")
    return completed.stdout


def _optional_git(root: Path, *args: str) -> bytes | None:
    environment = {
        "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_TERMINAL_PROMPT": "0",
    }
    try:
        completed = subprocess.run(
            ["git", "-C", os.fspath(root), *args],
            check=False,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=_COMMAND_TIMEOUT_SECONDS,
            env=environment,
            shell=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise RepositoryError("SOS_GIT_INSPECTION_FAILED") from exc
    if len(completed.stdout) > _MAX_GIT_OUTPUT_BYTES:
        raise RepositoryError("SOS_GIT_OUTPUT_LIMIT_EXCEEDED")
    if completed.returncode == 0:
        return completed.stdout
    if completed.returncode in (1, 128):
        return None
    raise RepositoryError("SOS_GIT_INSPECTION_FAILED")


def _discover_root(candidate: Path) -> Path:
    if candidate.is_symlink():
        raise RepositoryError("SOS_REPOSITORY_ROOT_SYMLINK")
    try:
        resolved = candidate.resolve(strict=True)
    except OSError as exc:
        raise RepositoryError("SOS_REPOSITORY_ROOT_NOT_FOUND") from exc
    if not resolved.is_dir():
        raise RepositoryError("SOS_REPOSITORY_ROOT_NOT_DIRECTORY")
    raw = _bounded_git(resolved, "rev-parse", "--show-toplevel")
    try:
        discovered = Path(os.fsdecode(raw.rstrip(b"\n"))).resolve(strict=True)
    except (OSError, UnicodeError) as exc:
        raise RepositoryError("SOS_REPOSITORY_ROOT_INVALID") from exc
    if not discovered.is_dir() or discovered.is_symlink():
        raise RepositoryError("SOS_REPOSITORY_ROOT_INVALID")
    return discovered


def _status_entries(raw: bytes) -> tuple[list[bytes], set[str]]:
    parts = raw.split(b"\0")
    if parts and parts[-1] == b"":
        parts.pop()
    entries: list[bytes] = []
    staging: set[str] = set()
    index = 0
    while index < len(parts):
        record = parts[index]
        if len(record) < 4:
            raise RepositoryError("SOS_GIT_STATUS_MALFORMED")
        status = record[:2]
        path = record[3:]
        paths = [path]
        if b"R" in status or b"C" in status:
            index += 1
            if index >= len(parts):
                raise RepositoryError("SOS_GIT_STATUS_MALFORMED")
            paths.append(parts[index])
        decoded: list[str] = []
        for item in paths:
            try:
                decoded.append(item.decode("utf-8", errors="strict"))
            except UnicodeDecodeError as exc:
                raise RepositoryError("SOS_GIT_PATH_ENCODING_UNSUPPORTED") from exc
        excluded = True
        for path_text in decoded:
            if path_text == ".sigma" or path_text.startswith(".sigma/"):
                continue
            match = _STAGING_ROOT.match(path_text)
            if match:
                staging.add(match.group(0).rstrip("/"))
                continue
            excluded = False
        if not excluded:
            entries.append(record)
            if len(paths) == 2:
                entries.append(paths[1])
        index += 1
    return entries, staging


def _control_plane_state(root: Path) -> str:
    control = root / ".sigma"
    try:
        mode = control.lstat().st_mode
    except FileNotFoundError:
        return "absent"
    if control.is_symlink():
        return "invalid_symlink"
    if not control.is_dir():
        return "invalid_type"
    del mode
    return "present_unverified"


def _staging_inventory(root: Path) -> tuple[set[str], bool]:
    staging: set[str] = set()
    collision = False
    try:
        entries = list(os.scandir(root))
    except OSError as exc:
        raise RepositoryError("SOS_REPOSITORY_INVENTORY_FAILED") from exc
    for entry in entries:
        if not entry.name.startswith(".sigma.init."):
            continue
        if _STAGING_ROOT_NAME.fullmatch(entry.name) and entry.is_dir(follow_symlinks=False) and not entry.is_symlink():
            staging.add(entry.name)
        else:
            collision = True
    return staging, collision


def inspect_repository(
    path: str | os.PathLike[str] = ".",
    *,
    local_repository_nonce: str | None = None,
) -> RepositoryInspection:
    candidate = Path(path)
    root = _discover_root(candidate)
    head_raw = _optional_git(root, "rev-parse", "--verify", "HEAD")
    head = os.fsdecode(head_raw.strip()) if head_raw else None
    object_format = os.fsdecode(_bounded_git(root, "rev-parse", "--show-object-format").strip())
    branch_raw = _bounded_git(root, "symbolic-ref", "--quiet", "--short", "HEAD") if _is_attached(root) else b""
    branch = os.fsdecode(branch_raw.strip()) if branch_raw else None
    detached = branch is None
    status_raw = _bounded_git(root, "status", "--porcelain=v1", "-z", "--untracked-files=all", "--ignored=no")
    entries, status_staging = _status_entries(status_raw)
    inventory_staging, staging_collision = _staging_inventory(root)
    staging = status_staging | inventory_staging
    digest = hashlib.sha256(b"\0".join(entries)).hexdigest()
    tree_digest = _application_tree_digest(root)
    repository_id = _repository_identity(root, object_format, local_repository_nonce).repository_id
    application_state = "clean" if not entries else "dirty"
    control_state = _control_plane_state(root)
    reasons: list[str] = []
    if control_state.startswith("invalid") or staging_collision:
        reasons.append("SOS_CONTROL_PLANE_COLLISION")
    if staging:
        reasons.append("SOS_STAGING_RECOVERY_REQUIRED")
    if head is None:
        reasons.append("SOS_REPOSITORY_UNBORN")
    return RepositoryInspection(
        contract="sos_repository_inspection_v1",
        root=".",
        root_path_serialized=False,
        repository_id=repository_id,
        head=head,
        branch=branch,
        detached=detached,
        object_format=object_format,
        application_state=application_state,
        application_entry_count=len(entries),
        application_status_digest="sha256:" + digest,
        application_tree_digest=tree_digest,
        control_plane_state=control_state,
        staging_roots=tuple(sorted(staging)),
        reasons=tuple(reasons),
    )


def _is_attached(root: Path) -> bool:
    try:
        _bounded_git(root, "symbolic-ref", "--quiet", "HEAD")
    except RepositoryError:
        return False
    return True


def discover_repository_root(path: str | os.PathLike[str] = ".") -> Path:
    """Return the local root for internal operations without serializing it."""
    return _discover_root(Path(path))


def repository_identity_contract(
    path: str | os.PathLike[str] = ".",
    *,
    local_repository_nonce: str | None = None,
) -> RepositoryIdentity:
    root = _discover_root(Path(path))
    object_format = os.fsdecode(_bounded_git(root, "rev-parse", "--show-object-format").strip())
    return _repository_identity(root, object_format, local_repository_nonce)


def worktree_identity(repository_id: str) -> str:
    material = b"sos_worktree_v1\0" + bytes.fromhex(repository_id.removeprefix("sha256:")) + b"\0."
    return "sha256:" + hashlib.sha256(material).hexdigest()


def _application_tree_digest(root: Path) -> str:
    raw = _bounded_git(root, "ls-files", "-s", "-z")
    records: list[bytes] = []
    for record in raw.split(b"\0"):
        if not record:
            continue
        try:
            _metadata, path_raw = record.split(b"\t", 1)
            path_text = path_raw.decode("utf-8", errors="strict")
        except (ValueError, UnicodeDecodeError) as exc:
            raise RepositoryError("SOS_GIT_INDEX_MALFORMED") from exc
        if path_text == ".sigma" or path_text.startswith(".sigma/"):
            continue
        if _STAGING_ROOT.match(path_text):
            continue
        records.append(record)
    return "sha256:" + hashlib.sha256(b"\0".join(records)).hexdigest()


def _repository_identity(
    root: Path,
    object_format: str,
    local_repository_nonce: str | None,
) -> RepositoryIdentity:
    raw = _bounded_git(root, "rev-list", "--max-parents=0", "--all")
    roots_raw = sorted(item for item in raw.splitlines() if item)
    roots = tuple(os.fsdecode(item) for item in roots_raw)
    if not roots:
        provisional = hashlib.sha256(("unborn:" + object_format).encode("ascii")).hexdigest()
        return RepositoryIdentity(
            "sos_repository_identity_v1",
            "sha256:" + provisional,
            "local_nonce_bound",
            object_format,
            (),
            (),
            "sha256:" + provisional,
        )
    remotes = _identity_remotes(root)
    if remotes:
        remote_material = b"\0".join(
            label.encode("utf-8") + b":" + digest.removeprefix("sha256:").encode("ascii")
            for label, digest in remotes
        )
        material = (
            b"sos_repo_v1\0remote\0"
            + object_format.encode("ascii")
            + b"\0"
            + remote_material
            + b"\0"
            + b"\0".join(roots_raw)
        )
        repository_id = "sha256:" + hashlib.sha256(material).hexdigest()
        return RepositoryIdentity(
            "sos_repository_identity_v1",
            repository_id,
            "remote_bound",
            object_format,
            roots,
            tuple(
                {"remote_label": label, "normalized_remote_sha256": digest}
                for label, digest in remotes
            ),
            None,
        )
    if local_repository_nonce is None:
        # Pre-bootstrap discovery has no accepted local nonce and therefore no
        # P101 identity authority.  This provisional value is never written to
        # a P101 record.
        provisional = hashlib.sha256(
            b"sos_repo_v1\0uninitialized\0" + object_format.encode("ascii") + b"\0" + b"\0".join(roots_raw)
        ).hexdigest()
        nonce = provisional
    else:
        if not re.fullmatch(r"[0-9a-f]{32}", local_repository_nonce):
            raise RepositoryError("SOS_REPOSITORY_IDENTITY_AMBIGUOUS")
        nonce = local_repository_nonce
    nonce_bytes = bytes.fromhex(nonce)
    material = (
        b"sos_repo_v1\0local\0"
        + object_format.encode("ascii")
        + b"\0"
        + nonce_bytes
        + b"\0"
        + b"\0".join(roots_raw)
    )
    repository_id = "sha256:" + hashlib.sha256(material).hexdigest()
    commitment = "sha256:" + hashlib.sha256(nonce_bytes).hexdigest()
    return RepositoryIdentity(
        "sos_repository_identity_v1",
        repository_id,
        "local_nonce_bound",
        object_format,
        roots,
        (),
        commitment,
    )


def _identity_remotes(root: Path) -> tuple[tuple[str, str], ...]:
    raw = _optional_git(root, "config", "--null", "--get-regexp", r"^remote\..*\.url$")
    if not raw:
        return ()
    values = [item for item in raw.split(b"\0") if item]
    remotes: list[tuple[str, str]] = []
    for value in values:
        try:
            key_raw, url_raw = value.split(b"\n", 1)
            key = key_raw.decode("utf-8", errors="strict")
            url = url_raw.decode("utf-8", errors="strict")
        except (ValueError, UnicodeDecodeError) as exc:
            raise RepositoryError("SOS_REPOSITORY_IDENTITY_AMBIGUOUS") from exc
        match = re.fullmatch(r"remote\.([^\x00-\x1f\x7f]+)\.url", key)
        if not match:
            raise RepositoryError("SOS_REPOSITORY_IDENTITY_AMBIGUOUS")
        normalized = _normalize_remote(url)
        digest = "sha256:" + hashlib.sha256(normalized.encode("utf-8")).hexdigest()
        remotes.append((match.group(1), digest))
    if len(remotes) > 16 or len({label for label, _digest in remotes}) != len(remotes):
        raise RepositoryError("SOS_REPOSITORY_IDENTITY_AMBIGUOUS")
    return tuple(sorted(remotes))


def _normalize_remote(value: str) -> str:
    candidate = value.strip()
    if re.fullmatch(r"[^/@:\s]+@[^/:\s]+:[^\s]+", candidate):
        _user, remainder = candidate.split("@", 1)
        host, path = remainder.split(":", 1)
        port = None
    else:
        parsed = urlsplit(candidate)
        if parsed.scheme not in {"ssh", "https"} or not parsed.hostname:
            raise RepositoryError("SOS_REPOSITORY_IDENTITY_AMBIGUOUS")
        host = parsed.hostname
        port = parsed.port
        path = parsed.path
    normalized_path = path.strip("/")
    if normalized_path.endswith(".git"):
        normalized_path = normalized_path[:-4]
    if not normalized_path or any(part in ("", ".", "..") for part in normalized_path.split("/")):
        raise RepositoryError("SOS_REPOSITORY_IDENTITY_AMBIGUOUS")
    authority = host.lower() + (f":{port}" if port is not None else "")
    # Transport and userinfo are not repository identity.  SSH scp syntax,
    # ssh:// and https:// for the same host/path therefore converge.
    return f"{authority}/{normalized_path}"
