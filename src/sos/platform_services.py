"""Portable mechanism boundary for repository-local SOS operations.

Operational values may contain local bytes or paths while in memory.  Only the
explicit ``safe_projection`` methods are suitable for records, receipts, logs,
or evidence.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Callable, ContextManager, Protocol, runtime_checkable


class PlatformServiceError(RuntimeError):
    """Typed mechanism failure; shared callers map ``kind`` to SOS reasons."""

    def __init__(self, kind: str) -> None:
        super().__init__(kind)
        self.kind = kind


@dataclass
class RepositoryRootHandle:
    """Opaque, process-local repository capability."""

    platform_profile_id: str
    filesystem_profile_id: str
    identity_digest: str
    _token: object
    _closer: Callable[[object], None]
    _closed: bool = False

    def close(self) -> None:
        if not self._closed:
            self._closer(self._token)
            self._closed = True

    def _platform_token(self) -> object:
        """Return the adapter-private capability without interpreting it."""

        if self._closed:
            raise PlatformServiceError("invalid_root")
        return self._token

    def __enter__(self) -> "RepositoryRootHandle":
        return self

    def __exit__(self, *_: object) -> None:
        self.close()

    def safe_projection(self) -> dict[str, object]:
        return {
            "platform_profile_id": self.platform_profile_id,
            "filesystem_profile_id": self.filesystem_profile_id,
            "identity_digest": self.identity_digest,
            "absolute_paths_serialized": False,
        }


@dataclass(frozen=True)
class ObjectObservation:
    relative_path: str
    kind: str
    byte_count: int
    mode: int
    identity_digest: str
    stable_identity_digest: str | None = None
    content_digest: str | None = None

    def safe_projection(self) -> dict[str, object]:
        return {
            "relative_path": self.relative_path,
            "kind": self.kind,
            "byte_count": self.byte_count,
            "mode": self.mode,
            "identity_digest": self.identity_digest,
            "stable_identity_digest": self.stable_identity_digest,
            "content_digest": self.content_digest,
            "raw_content_serialized": False,
            "absolute_paths_serialized": False,
        }


@dataclass(frozen=True)
class EphemeralFileRead:
    observation: ObjectObservation
    payload: bytes
    content_digest: str

    def safe_projection(self) -> dict[str, object]:
        return {
            **self.observation.safe_projection(),
            "content_digest": self.content_digest,
        }


@dataclass(frozen=True)
class EphemeralDirectoryEntry:
    name: str
    kind: str
    identity_digest: str


@dataclass(frozen=True)
class EphemeralDirectoryRead:
    entries: tuple[EphemeralDirectoryEntry, ...]
    entry_count: int
    names_digest: str

    def safe_projection(self) -> dict[str, object]:
        return {
            "entry_count": self.entry_count,
            "names_digest": self.names_digest,
            "raw_names_serialized": False,
            "absolute_paths_serialized": False,
        }


@dataclass(frozen=True)
class EphemeralLauncherObservation:
    executable: Path
    package_version: str
    executable_digest: str
    editable_install: bool = False

    def safe_projection(self) -> dict[str, object]:
        return {
            "package_version": self.package_version,
            "executable_digest": self.executable_digest,
            "editable_install": self.editable_install,
            "absolute_paths_serialized": False,
        }


@dataclass(frozen=True)
class FilePublicationOperation:
    root: RepositoryRootHandle
    relative_path: str
    payload: bytes | None
    expected_payload: bytes | None
    expected_existed: bool
    mode: int
    parent_policy: str = "preserve_existing"
    expected_parent_kind: str | None = None
    expected_parent_identity: str | None = None


@dataclass(frozen=True)
class TreePublicationOperation:
    root: RepositoryRootHandle
    staging_name: str
    target_name: str
    action: str = "commit"
    files: tuple[tuple[str, bytes], ...] = ()
    capability: "TreeStagingCapability | None" = None
    recovery_binding_digest: str | None = None


@dataclass
class TreeStagingCapability:
    """Opaque, single-use staging authority retained only in process memory."""

    root_identity_digest: str
    transaction_id: str
    staging_name: str
    target_name: str
    staging_identity_digest: str
    recovery_binding_digest: str
    binding_digest: str
    _token: object
    _closer: Callable[[object], None]
    consumed: bool = False
    terminal_action: str | None = None

    def _platform_token(self) -> object:
        if self.consumed:
            raise PlatformServiceError("staging_capability_consumed")
        return self._token

    def consume(self, action: str) -> None:
        if self.consumed:
            raise PlatformServiceError("staging_capability_consumed")
        self._closer(self._token)
        self.consumed = True
        self.terminal_action = action

    def safe_projection(self) -> dict[str, object]:
        return {
            "binding_digest": self.binding_digest,
            "consumed": self.consumed,
            "raw_content_serialized": False,
            "absolute_paths_serialized": False,
        }


@dataclass(frozen=True)
class PublicationReceipt:
    profile_id: str
    operation: str
    relative_target: str
    before_digest: str | None
    after_digest: str | None
    capability: TreeStagingCapability | None = None

    def safe_projection(self) -> dict[str, object]:
        return {
            "profile_id": self.profile_id,
            "operation": self.operation,
            "relative_target": self.relative_target,
            "before_digest": self.before_digest,
            "after_digest": self.after_digest,
            "raw_content_serialized": False,
            "absolute_paths_serialized": False,
        }


@runtime_checkable
class PlatformServices(Protocol):
    profile_id: str

    def inspect_host(self, repository_path: Path | None = None) -> dict[str, object]: ...

    def open_repository(self, path: Path) -> RepositoryRootHandle: ...

    def observe_object(
        self, root: RepositoryRootHandle, relative_path: str
    ) -> ObjectObservation: ...

    def read_regular_file_bounded(
        self, root: RepositoryRootHandle, relative_path: str, limit: int
    ) -> EphemeralFileRead: ...

    def enumerate_directory_bounded(
        self, root: RepositoryRootHandle, relative_path: str, limit: int
    ) -> EphemeralDirectoryRead: ...

    def acquire_repository_lock(
        self,
        root: RepositoryRootHandle,
        deadline_seconds: float | None,
        *,
        relative_lock_path: str,
        exclusive_create: bool = False,
    ) -> ContextManager[None]: ...

    def publish_file(self, operation: FilePublicationOperation) -> PublicationReceipt: ...

    def publish_tree(self, operation: TreePublicationOperation) -> PublicationReceipt: ...

    def observe_launcher(self, client_id: str) -> EphemeralLauncherObservation: ...


def current_platform_services() -> PlatformServices:
    """Select once from the process host; repository input has no influence."""

    from .platforms import current_platform_services as selected

    return selected()
