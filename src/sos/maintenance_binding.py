"""Content-safe binding for an exact public maintenance launcher."""

from __future__ import annotations

import re
from dataclasses import dataclass

from .contracts import digest_value


_HEX_40 = re.compile(r"^[0-9a-f]{40}$")
_HEX_64 = re.compile(r"^[0-9a-f]{64}$")
_VERSION = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+a[0-9]+$")
_SAFE_NAME = re.compile(r"^[A-Za-z0-9._-]+$")
_PROFILE = re.compile(r"^[a-z0-9][a-z0-9._-]{0,79}$")


class MaintenanceBindingError(RuntimeError):
    def __init__(self, reason: str = "SOS_MAINTENANCE_RELEASE_BINDING_INVALID") -> None:
        super().__init__(reason)
        self.reason = reason


@dataclass(frozen=True, slots=True)
class MaintenanceLauncherBinding:
    """Release and archive provenance for the outer maintenance launcher.

    This binding is intentionally distinct from ``LauncherBinding`` in
    ``client_integration``.  The latter authenticates the Python executable
    used by the project-local MCP server; this record authenticates the
    release archive and its platform maintenance launcher.
    """

    version: str
    release_tag: str
    candidate: str
    tree: str
    archive_filename: str
    archive_sha256: str
    inner_manifest_sha256: str
    system: str
    architecture: str
    profile_id: str
    platform_launcher: str
    platform_launcher_sha256: str

    @property
    def digest(self) -> str:
        return digest_value(self.payload(include_digest=False))

    def payload(self, *, include_digest: bool = True) -> dict[str, object]:
        value: dict[str, object] = {
            "contract": "sos_maintenance_launcher_binding_v1",
            "version": self.version,
            "release_tag": self.release_tag,
            "candidate": self.candidate,
            "tree": self.tree,
            "archive_filename": self.archive_filename,
            "archive_sha256": self.archive_sha256,
            "inner_manifest_sha256": self.inner_manifest_sha256,
            "system": self.system,
            "architecture": self.architecture,
            "profile_id": self.profile_id,
            "platform_launcher": self.platform_launcher,
            "platform_launcher_sha256": self.platform_launcher_sha256,
            "raw_content_serialized": False,
            "absolute_paths_serialized": False,
        }
        if include_digest:
            value["binding_digest"] = self.digest
        return value

    @classmethod
    def from_payload(cls, value: object) -> "MaintenanceLauncherBinding":
        required = {
            "contract",
            "version",
            "release_tag",
            "candidate",
            "tree",
            "archive_filename",
            "archive_sha256",
            "inner_manifest_sha256",
            "system",
            "architecture",
            "profile_id",
            "platform_launcher",
            "platform_launcher_sha256",
            "raw_content_serialized",
            "absolute_paths_serialized",
        }
        if not isinstance(value, dict) or set(value) not in (required, required | {"binding_digest"}):
            raise MaintenanceBindingError()
        if value.get("contract") != "sos_maintenance_launcher_binding_v1":
            raise MaintenanceBindingError()
        if value.get("raw_content_serialized") is not False or value.get("absolute_paths_serialized") is not False:
            raise MaintenanceBindingError()
        strings = {key: value.get(key) for key in required - {"contract", "raw_content_serialized", "absolute_paths_serialized"}}
        if any(not isinstance(item, str) for item in strings.values()):
            raise MaintenanceBindingError()
        binding = cls(**strings)  # type: ignore[arg-type]
        binding._validate()
        supplied_digest = value.get("binding_digest")
        if supplied_digest is not None and supplied_digest != binding.digest:
            raise MaintenanceBindingError("SOS_MAINTENANCE_RELEASE_BINDING_DIGEST_MISMATCH")
        return binding

    def _validate(self) -> None:
        if not _VERSION.fullmatch(self.version) or self.release_tag != f"v{self.version}":
            raise MaintenanceBindingError()
        if not _HEX_40.fullmatch(self.candidate) or not _HEX_40.fullmatch(self.tree):
            raise MaintenanceBindingError()
        if not _HEX_64.fullmatch(self.archive_sha256) or not _HEX_64.fullmatch(self.inner_manifest_sha256):
            raise MaintenanceBindingError()
        if not _HEX_64.fullmatch(self.platform_launcher_sha256):
            raise MaintenanceBindingError()
        if self.system not in {"darwin", "linux", "windows"}:
            raise MaintenanceBindingError()
        if self.architecture not in {"arm64", "x86_64"}:
            raise MaintenanceBindingError()
        if not _PROFILE.fullmatch(self.profile_id):
            raise MaintenanceBindingError()
        if not _SAFE_NAME.fullmatch(self.archive_filename) or not _SAFE_NAME.fullmatch(self.platform_launcher):
            raise MaintenanceBindingError()
        if not self.archive_filename.startswith("SOS-") or not self.archive_filename.endswith((".zip", ".tar.gz")):
            raise MaintenanceBindingError()


def mcp_launcher_binding_payload(*, package_version: str, executable_sha256: str, binding_digest: str) -> dict[str, object]:
    """Render the separately named MCP launcher identity for lifecycle evidence."""
    return {
        "contract": "sos_mcp_launcher_binding_v1",
        "package": "sigma-operator-stack",
        "package_version": package_version,
        "executable_sha256": executable_sha256,
        "invocation": ["-m", "sos", "mcp"],
        "binding_digest": binding_digest,
    }
