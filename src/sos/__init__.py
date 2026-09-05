"""Sigma Operator Stack public package.

The package root intentionally avoids importing the POSIX implementation. This
lets the host-facing entry point return a typed Linux-substrate requirement on
unsupported hosts before modules such as :mod:`fcntl` are loaded.
"""

from importlib import import_module
from typing import Any

__all__ = [
    "RepositoryInspection",
    "doctor_workspace",
    "initialize_workspace",
    "inspect_repository",
    "recover_workspace",
]
__version__ = "0.1.0a3"

_LAZY_EXPORTS = {
    "RepositoryInspection": ("sos.repository", "RepositoryInspection"),
    "doctor_workspace": ("sos.workspace", "doctor_workspace"),
    "initialize_workspace": ("sos.workspace", "initialize_workspace"),
    "inspect_repository": ("sos.repository", "inspect_repository"),
    "recover_workspace": ("sos.workspace", "recover_workspace"),
}


def __getattr__(name: str) -> Any:
    target = _LAZY_EXPORTS.get(name)
    if target is None:
        raise AttributeError(name)
    module_name, attribute_name = target
    value = getattr(import_module(module_name), attribute_name)
    globals()[name] = value
    return value
