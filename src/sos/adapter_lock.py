"""Shared per-project lock for adapter writers and qualified runtime deletion."""

import os
from contextlib import contextmanager
from contextvars import ContextVar
from threading import get_ident
from functools import wraps

from .platform_services import current_platform_services
from .platform_services import PlatformServiceError
from .repository import discover_repository_root, RepositoryError
from .result import Status, TerminalResult

_HELD = ContextVar("sos_adapter_lock", default=frozenset())


def serialized_setup(function):
    """Preview/no-TTY stays write-free; admitted writers share deletion's lock."""
    @wraps(function)
    def wrapped(path=".", *args, **kwargs):
        if "confirmed" in kwargs and (not kwargs["confirmed"] or not kwargs.get("controlling_tty_observed", False)):
            return function(path, *args, **kwargs)
        try:
            root = discover_repository_root(path)
        except RepositoryError:
            return function(path, *args, **kwargs)
        try:
            service = current_platform_services()
            with service.open_repository(root) as repository:
                if service.observe_object(repository, ".sigma").kind != "directory":
                    return function(path, *args, **kwargs)
            with adapter_mutation_lock(root):
                if function.__name__.startswith(("install_", "update_")):
                    # A partially detached generation is never reattached while
                    # its confirmed removal transaction remains authoritative.
                    from .client_integration import read_integration_control_file
                    if read_integration_control_file(root, "lifecycle/native-removal.json") is not None:
                        return TerminalResult("sos_client_integration_result_v1", Status.BLOCKED,
                            ("SOS_NATIVE_REMOVAL_RECOVERY_REQUIRED",), {"recovery_required": True})
                return function(path, *args, **kwargs)
        except PlatformServiceError:
            return TerminalResult("sos_client_integration_result_v1", Status.BLOCKED,
                ("SOS_ADAPTER_MUTATION_LOCK_UNAVAILABLE",), {})
    return wrapped


@contextmanager
def adapter_mutation_lock(root):
    key = (os.getpid(), get_ident(), str(root))
    held = _HELD.get()
    if key in held:
        yield
        return
    service = current_platform_services()
    with service.open_repository(root) as repository:
        with service.acquire_repository_lock(repository, None,
                relative_lock_path=".sigma/integrations/atomic-switches/coordinator.lock"):
            token = _HELD.set(held | {key})
            try:
                yield
            finally:
                _HELD.reset(token)
