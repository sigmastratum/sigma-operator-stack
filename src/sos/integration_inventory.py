"""Shared, non-executing admission of project integration entry names/types."""

from .platform_services import PlatformServiceError, current_platform_services
from .repository import discover_repository_root


_KINDS = {
    "codex-mcp.json": "regular", "codex-first.json": "regular",
    "claude-code.json": "regular", "atomic-switches": "directory",
}


def unknown_integration_files(path: str) -> list[str]:
    root = discover_repository_root(path)
    service = current_platform_services()
    with service.open_repository(root) as repository:
        observed = service.observe_object(repository, ".sigma/integrations")
        if observed.kind == "absent":
            return []
        if observed.kind != "directory":
            raise PlatformServiceError("invalid_integrations_directory")
        listing = service.enumerate_directory_bounded(repository, ".sigma/integrations", 64)
    unknown = []
    for entry in listing.entries:
        expected = _KINDS.get(entry.name)
        if expected is None:
            unknown.append(entry.name)
        elif entry.kind != expected:
            raise PlatformServiceError("invalid_integration_entry")
    return sorted(unknown)
