"""Process-host platform adapter selection."""

from __future__ import annotations

import sys
from functools import lru_cache

from ..platform_services import PlatformServices


@lru_cache(maxsize=1)
def current_platform_services() -> PlatformServices:
    return _select_platform_services(process_platform_name())


def process_platform_name(override: str | None = None) -> str:
    """Return the process selector input; tests may supply an explicit observation."""

    return sys.platform if override is None else override


def _select_platform_services(platform_name: str) -> PlatformServices:
    """Select from the process platform value, never repository input."""

    if platform_name.startswith("linux"):
        from .linux import LinuxPlatformServices

        return LinuxPlatformServices()
    raise RuntimeError("SOS_PLATFORM_ADAPTER_UNAVAILABLE")
