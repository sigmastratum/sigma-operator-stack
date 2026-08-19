"""Project-local, reversible MCP client integration for one exact Codex profile."""

from __future__ import annotations

import hashlib
import json
import os
import re
import stat
import sys
import tomllib
from dataclasses import dataclass
from importlib import metadata
from pathlib import Path
from typing import Any

from . import __version__
from .contracts import digest_value
from .repository import RepositoryError, discover_repository_root
from .result import Status, TerminalResult
from .workspace import WorkspaceError, workspace_status


_CLIENT = "codex"
_CONTRACT = "sos_client_integration_manifest_v1"
_RESULT_CONTRACT = "sos_client_integration_result_v1"
_TARGET = ".codex/config.toml"
_MANIFEST = "integrations/codex-mcp.json"
_SERVER = "sigma_operator_stack"
_MAX_CONFIG_BYTES = 1024 * 1024
_MAX_EXECUTABLE_BYTES = 128 * 1024 * 1024
_BEGIN = "# >>> SOS managed Codex MCP (sos_codex_mcp_v1)"
_END = "# <<< SOS managed Codex MCP (sos_codex_mcp_v1)"
_TOOLS = ("sos_status", "sos_doctor", "sos_recover", "sos_check")


class ClientIntegrationError(RuntimeError):
    def __init__(self, reason: str, status: Status = Status.INVALID) -> None:
        super().__init__(reason)
        self.reason = reason
        self.status = status


@dataclass(frozen=True, slots=True)
class LauncherBinding:
    """Observed installed-package launcher. Raw paths never enter receipts."""

    command: str
    package_version: str
    executable_sha256: str

    @property
    def digest(self) -> str:
        return digest_value(
            {
                "contract": "sos_mcp_launcher_binding_v1",
                "package": "sigma-operator-stack",
                "package_version": self.package_version,
                "executable_sha256": self.executable_sha256,
                "invocation": ["-m", "sos", "mcp"],
            }
        )


def observe_installed_launcher() -> LauncherBinding:
    try:
        distribution = metadata.distribution("sigma-operator-stack")
    except metadata.PackageNotFoundError as exc:
        raise ClientIntegrationError("SOS_CLIENT_PACKAGE_NOT_INSTALLED", Status.UNSUPPORTED) from exc
    if distribution.version != __version__:
        raise ClientIntegrationError("SOS_CLIENT_PACKAGE_VERSION_MISMATCH", Status.STALE)
    direct_url = distribution.read_text("direct_url.json")
    if direct_url:
        try:
            direct = json.loads(direct_url)
        except json.JSONDecodeError as exc:
            raise ClientIntegrationError("SOS_CLIENT_PACKAGE_IDENTITY_INVALID") from exc
        if isinstance(direct, dict) and isinstance(direct.get("dir_info"), dict):
            if direct["dir_info"].get("editable") is True:
                raise ClientIntegrationError("SOS_CLIENT_EDITABLE_PACKAGE_UNSUPPORTED", Status.UNSUPPORTED)
    try:
        executable = Path(sys.executable)
        if not executable.is_absolute():
            raise ClientIntegrationError("SOS_CLIENT_LAUNCHER_INVALID", Status.UNSUPPORTED)
        observed = executable.stat()
        if not stat.S_ISREG(observed.st_mode) or observed.st_size > _MAX_EXECUTABLE_BYTES:
            raise ClientIntegrationError("SOS_CLIENT_LAUNCHER_INVALID", Status.UNSUPPORTED)
        executable_digest = _sha256_file(executable, _MAX_EXECUTABLE_BYTES)
    except OSError as exc:
        raise ClientIntegrationError("SOS_CLIENT_LAUNCHER_INVALID", Status.UNSUPPORTED) from exc
    return LauncherBinding(os.fspath(executable), distribution.version, executable_digest)


def preview_client_install(
    path: str = ".", client: str = _CLIENT, *, launcher: LauncherBinding | None = None
) -> TerminalResult:
    if client != _CLIENT:
        return _result(Status.UNSUPPORTED, "SOS_CLIENT_UNSUPPORTED")
    try:
        root, repository_id = _ready_root(path, allow_stale_installed=True)
        binding = launcher or observe_installed_launcher()
        manifest = _read_manifest(root)
        if manifest is not None:
            state = manifest["state"]
            if state == "installed":
                _verify_installed(root, manifest, binding)
                return _result(Status.SUCCESS, "SOS_CLIENT_ALREADY_INSTALLED", manifest)
            if state in {"install_prepared", "remove_prepared"}:
                return _result(Status.BLOCKED, "SOS_CLIENT_RECOVERY_REQUIRED", manifest)
        current = workspace_status(os.fspath(root))
        if current.status != Status.SUCCESS:
            return TerminalResult(_RESULT_CONTRACT, current.status, current.reasons, _safe_details(None))
        original, existed, parent_existed = _read_target(root)
        addition = _render_addition(root, binding, original)
        updated = original + addition
        _validate_toml(updated)
        prepared = _manifest(
            state="install_prepared",
            repository_id=repository_id,
            binding=binding,
            original=original,
            original_existed=existed,
            parent_existed=parent_existed,
            addition=addition,
            updated=updated,
        )
        return _result(Status.OWNER_REQUIRED, "SOS_CLIENT_INSTALL_CONFIRMATION_REQUIRED", prepared)
    except (ClientIntegrationError, RepositoryError, WorkspaceError, OSError) as exc:
        return _error_result(exc)


def install_client(
    path: str = ".",
    client: str = _CLIENT,
    *,
    confirmed: bool,
    controlling_tty_observed: bool = False,
    launcher: LauncherBinding | None = None,
) -> TerminalResult:
    if client != _CLIENT:
        return _result(Status.UNSUPPORTED, "SOS_CLIENT_UNSUPPORTED")
    if not confirmed:
        return preview_client_install(path, client, launcher=launcher)
    if not controlling_tty_observed:
        return _result(Status.OWNER_REQUIRED, "SOS_CLIENT_TTY_REQUIRED")
    try:
        root, repository_id = _ready_root(path, allow_stale_installed=True)
        binding = launcher or observe_installed_launcher()
        existing = _read_manifest(root)
        if existing is not None and existing["state"] == "installed":
            _verify_installed(root, existing, binding)
            return _result(Status.SUCCESS, "SOS_CLIENT_ALREADY_INSTALLED", existing)
        if existing is not None and existing["state"] == "remove_prepared":
            raise ClientIntegrationError("SOS_CLIENT_REMOVE_RECOVERY_REQUIRED", Status.BLOCKED)
        if existing is not None and existing["state"] == "install_prepared":
            prepared = existing
            _verify_manifest_binding(prepared, repository_id, binding)
            original, existed, _ = _read_target(root)
            if _bytes_digest(original) == prepared["configured_digest"] and existed:
                installed = _with_state(prepared, "installed")
                _write_manifest(root, installed)
                return _result(Status.SUCCESS, "SOS_CLIENT_INSTALL_RECOVERED", installed)
            if _bytes_digest(original) != prepared["original_digest"] or existed != prepared["original_existed"]:
                raise ClientIntegrationError("SOS_CLIENT_CONFIG_DRIFT", Status.STALE)
            addition = _render_addition(root, binding, original)
            updated = original + addition
            if _bytes_digest(addition) != prepared["managed_addition_digest"] or _bytes_digest(updated) != prepared["configured_digest"]:
                raise ClientIntegrationError("SOS_CLIENT_PLAN_STALE", Status.STALE)
        else:
            current = workspace_status(os.fspath(root))
            if current.status != Status.SUCCESS:
                return TerminalResult(_RESULT_CONTRACT, current.status, current.reasons, _safe_details(None))
            original, existed, parent_existed = _read_target(root)
            addition = _render_addition(root, binding, original)
            updated = original + addition
            _validate_toml(updated)
            prepared = _manifest(
                state="install_prepared",
                repository_id=repository_id,
                binding=binding,
                original=original,
                original_existed=existed,
                parent_existed=parent_existed,
                addition=addition,
                updated=updated,
            )
            _write_manifest(root, prepared)
        _replace_target(root, updated, expected=original, expected_existed=existed)
        installed = _with_state(prepared, "installed")
        _write_manifest(root, installed)
        return _result(Status.SUCCESS, "SOS_CLIENT_INSTALLED", installed)
    except (ClientIntegrationError, RepositoryError, WorkspaceError, OSError) as exc:
        return _error_result(exc)


def client_status(
    path: str = ".", client: str = _CLIENT, *, launcher: LauncherBinding | None = None
) -> TerminalResult:
    if client != _CLIENT:
        return _result(Status.UNSUPPORTED, "SOS_CLIENT_UNSUPPORTED")
    try:
        root = discover_repository_root(path)
        workspace = workspace_status(os.fspath(root))
        manifest = _read_manifest(root)
        if manifest is None or manifest["state"] == "removed":
            return _result(Status.SUCCESS, "SOS_CLIENT_NOT_INSTALLED", manifest)
        if manifest["state"] != "installed":
            return _result(Status.BLOCKED, "SOS_CLIENT_RECOVERY_REQUIRED", manifest)
        if workspace.status == Status.INVALID or workspace.details.get("repository_id") != manifest["repository_id"]:
            raise ClientIntegrationError("SOS_CLIENT_REPOSITORY_MISMATCH", Status.STALE)
        binding = launcher or observe_installed_launcher()
        _verify_installed(root, manifest, binding)
        return _result(Status.SUCCESS, "SOS_CLIENT_INSTALLED", manifest)
    except (ClientIntegrationError, RepositoryError, WorkspaceError, OSError) as exc:
        return _error_result(exc)


def remove_client(
    path: str = ".",
    client: str = _CLIENT,
    *,
    confirmed: bool,
    controlling_tty_observed: bool = False,
    launcher: LauncherBinding | None = None,
) -> TerminalResult:
    if client != _CLIENT:
        return _result(Status.UNSUPPORTED, "SOS_CLIENT_UNSUPPORTED")
    if not confirmed:
        status = client_status(path, client, launcher=launcher)
        if status.status != Status.SUCCESS or "SOS_CLIENT_NOT_INSTALLED" in status.reasons:
            return status
        return TerminalResult(
            _RESULT_CONTRACT,
            Status.OWNER_REQUIRED,
            ("SOS_CLIENT_REMOVE_CONFIRMATION_REQUIRED",),
            status.details,
        )
    if not controlling_tty_observed:
        return _result(Status.OWNER_REQUIRED, "SOS_CLIENT_TTY_REQUIRED")
    try:
        root, repository_id = _ready_root(path, allow_stale_installed=True)
        manifest = _read_manifest(root)
        if manifest is None or manifest["state"] == "removed":
            return _result(Status.SUCCESS, "SOS_CLIENT_ALREADY_REMOVED", manifest)
        if manifest["repository_id"] != repository_id:
            raise ClientIntegrationError("SOS_CLIENT_REPOSITORY_MISMATCH", Status.STALE)
        if manifest["state"] == "install_prepared":
            raise ClientIntegrationError("SOS_CLIENT_INSTALL_RECOVERY_REQUIRED", Status.BLOCKED)
        if manifest["state"] == "installed":
            _verify_removable(root, manifest)
            removing = _with_state(manifest, "remove_prepared")
            _write_manifest(root, removing)
        elif manifest["state"] == "remove_prepared":
            removing = manifest
        else:
            raise ClientIntegrationError("SOS_CLIENT_MANIFEST_INVALID")
        current, exists, _ = _read_target(root)
        if exists and _bytes_digest(current) == removing["configured_digest"]:
            original_length = removing["original_byte_count"]
            original = current[:original_length]
            addition = current[original_length:]
            if _bytes_digest(original) != removing["original_digest"] or _bytes_digest(addition) != removing["managed_addition_digest"]:
                raise ClientIntegrationError("SOS_CLIENT_CONFIG_DRIFT", Status.STALE)
            _restore_target(
                root,
                original,
                original_existed=removing["original_existed"],
                parent_existed=removing["parent_existed"],
                expected=current,
            )
        else:
            expected_removed = not removing["original_existed"] and not exists
            expected_restored = removing["original_existed"] and exists and _bytes_digest(current) == removing["original_digest"]
            if not (expected_removed or expected_restored):
                raise ClientIntegrationError("SOS_CLIENT_CONFIG_DRIFT", Status.STALE)
        removed = _with_state(removing, "removed")
        _write_manifest(root, removed)
        return _result(Status.SUCCESS, "SOS_CLIENT_REMOVED", removed)
    except (ClientIntegrationError, RepositoryError, WorkspaceError, OSError) as exc:
        return _error_result(exc)


def launcher_config(root: Path, binding: LauncherBinding) -> dict[str, Any]:
    """Return the exact supported Codex configuration without receipt paths."""
    return {
        "command": binding.command,
        "args": [
            "-m",
            "sos",
            "mcp",
            "--root",
            os.fspath(root),
            "--expected-package-version",
            binding.package_version,
        ],
        "cwd": os.fspath(root),
        "enabled": True,
        "required": False,
        "enabled_tools": list(_TOOLS),
        "default_tools_approval_mode": "writes",
    }


def _ready_root(path: str, *, allow_stale_installed: bool) -> tuple[Path, str]:
    root = discover_repository_root(path)
    status = workspace_status(os.fspath(root))
    if status.status == Status.SUCCESS:
        return root, status.details["repository_id"]
    if allow_stale_installed:
        manifest = _read_manifest(root)
        observed_repository = status.details.get("repository_id")
        if manifest is not None and isinstance(observed_repository, str):
            if observed_repository != manifest["repository_id"]:
                raise ClientIntegrationError("SOS_CLIENT_REPOSITORY_MISMATCH", Status.STALE)
            return root, observed_repository
    raise ClientIntegrationError(status.reasons[0] if status.reasons else "SOS_WORKSPACE_NOT_READY", status.status)


def _render_addition(root: Path, binding: LauncherBinding, original: bytes) -> bytes:
    if _BEGIN.encode() in original or _END.encode() in original:
        raise ClientIntegrationError("SOS_CLIENT_MANAGED_BLOCK_COLLISION", Status.BLOCKED)
    try:
        parsed = tomllib.loads(original.decode("utf-8")) if original else {}
    except (UnicodeDecodeError, tomllib.TOMLDecodeError) as exc:
        raise ClientIntegrationError("SOS_CLIENT_CONFIG_INVALID") from exc
    servers = parsed.get("mcp_servers", {})
    if not isinstance(servers, dict) or _SERVER in servers:
        raise ClientIntegrationError("SOS_CLIENT_SERVER_COLLISION", Status.BLOCKED)
    config = launcher_config(root, binding)
    separator = b"" if not original else (b"\n" if original.endswith(b"\n") else b"\n\n")
    lines = [
        _BEGIN,
        f"[mcp_servers.{_SERVER}]",
        f"command = {_toml_string(config['command'])}",
        f"args = {_toml_array(config['args'])}",
        f"cwd = {_toml_string(config['cwd'])}",
        "enabled = true",
        "required = false",
        f"enabled_tools = {_toml_array(config['enabled_tools'])}",
        'default_tools_approval_mode = "writes"',
        _END,
        "",
    ]
    try:
        return separator + "\n".join(lines).encode("utf-8")
    except UnicodeEncodeError as exc:
        raise ClientIntegrationError("SOS_CLIENT_PATH_ENCODING_UNSUPPORTED", Status.UNSUPPORTED) from exc


def _validate_toml(updated: bytes) -> None:
    if len(updated) > _MAX_CONFIG_BYTES:
        raise ClientIntegrationError("SOS_CLIENT_CONFIG_LIMIT_EXCEEDED", Status.UNSUPPORTED)
    try:
        parsed = tomllib.loads(updated.decode("utf-8"))
    except (UnicodeDecodeError, tomllib.TOMLDecodeError) as exc:
        raise ClientIntegrationError("SOS_CLIENT_CONFIG_INVALID") from exc
    server = parsed.get("mcp_servers", {}).get(_SERVER)
    if not isinstance(server, dict) or set(server) != {
        "command", "args", "cwd", "enabled", "required", "enabled_tools", "default_tools_approval_mode"
    }:
        raise ClientIntegrationError("SOS_CLIENT_CONFIG_INVALID")


def _manifest(
    *,
    state: str,
    repository_id: str,
    binding: LauncherBinding,
    original: bytes,
    original_existed: bool,
    parent_existed: bool,
    addition: bytes,
    updated: bytes,
) -> dict[str, Any]:
    value = {
        "contract": _CONTRACT,
        "client": _CLIENT,
        "state": state,
        "repository_id": repository_id,
        "target": _TARGET,
        "original_existed": original_existed,
        "parent_existed": parent_existed,
        "original_byte_count": len(original),
        "original_digest": _bytes_digest(original),
        "managed_addition_digest": _bytes_digest(addition),
        "configured_digest": _bytes_digest(updated),
        "launcher_digest": binding.digest,
        "package_version": binding.package_version,
        "absolute_paths_serialized": False,
        "raw_config_serialized": False,
        "manifest_digest": "sha256:" + "0" * 64,
    }
    value["manifest_digest"] = _manifest_digest(value)
    return value


def _with_state(manifest: dict[str, Any], state: str) -> dict[str, Any]:
    updated = dict(manifest)
    updated["state"] = state
    updated["manifest_digest"] = "sha256:" + "0" * 64
    updated["manifest_digest"] = _manifest_digest(updated)
    return updated


def _read_manifest(root: Path) -> dict[str, Any] | None:
    try:
        descriptor = _open_control_directory(root, ("integrations",), create=False)
    except ClientIntegrationError as exc:
        if exc.reason == "SOS_CLIENT_MANIFEST_MISSING":
            return None
        raise
    try:
        try:
            file_descriptor = os.open("codex-mcp.json", os.O_RDONLY | os.O_NOFOLLOW, dir_fd=descriptor)
        except FileNotFoundError:
            return None
        try:
            payload = _read_bounded(file_descriptor, _MAX_CONFIG_BYTES)
        finally:
            os.close(file_descriptor)
    except OSError as exc:
        raise ClientIntegrationError("SOS_CLIENT_MANIFEST_INVALID") from exc
    finally:
        os.close(descriptor)
    if len(payload) > _MAX_CONFIG_BYTES:
        raise ClientIntegrationError("SOS_CLIENT_MANIFEST_INVALID")
    try:
        value = json.loads(payload.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ClientIntegrationError("SOS_CLIENT_MANIFEST_INVALID") from exc
    _validate_manifest(value)
    return value


def _validate_manifest(value: object) -> None:
    required = {
        "contract", "client", "state", "repository_id", "target", "original_existed", "parent_existed",
        "original_byte_count", "original_digest", "managed_addition_digest", "configured_digest",
        "launcher_digest", "package_version", "absolute_paths_serialized", "raw_config_serialized",
        "manifest_digest",
    }
    if not isinstance(value, dict) or set(value) != required:
        raise ClientIntegrationError("SOS_CLIENT_MANIFEST_INVALID")
    if value["contract"] != _CONTRACT or value["client"] != _CLIENT or value["target"] != _TARGET:
        raise ClientIntegrationError("SOS_CLIENT_MANIFEST_INVALID")
    if value["state"] not in {"install_prepared", "installed", "remove_prepared", "removed"}:
        raise ClientIntegrationError("SOS_CLIENT_MANIFEST_INVALID")
    if value["absolute_paths_serialized"] is not False or value["raw_config_serialized"] is not False:
        raise ClientIntegrationError("SOS_CLIENT_MANIFEST_INVALID")
    if not isinstance(value["original_existed"], bool) or not isinstance(value["parent_existed"], bool):
        raise ClientIntegrationError("SOS_CLIENT_MANIFEST_INVALID")
    if not isinstance(value["package_version"], str) or not value["package_version"]:
        raise ClientIntegrationError("SOS_CLIENT_MANIFEST_INVALID")
    if not isinstance(value["original_byte_count"], int) or value["original_byte_count"] < 0:
        raise ClientIntegrationError("SOS_CLIENT_MANIFEST_INVALID")
    for field in ("repository_id", "original_digest", "managed_addition_digest", "configured_digest", "launcher_digest", "manifest_digest"):
        item = value[field]
        if not isinstance(item, str) or re.fullmatch(r"sha256:[0-9a-f]{64}", item) is None:
            raise ClientIntegrationError("SOS_CLIENT_MANIFEST_INVALID")
    if value["manifest_digest"] != _manifest_digest(value):
        raise ClientIntegrationError("SOS_CLIENT_MANIFEST_INVALID")


def _verify_manifest_binding(manifest: dict[str, Any], repository_id: str, binding: LauncherBinding) -> None:
    if manifest["repository_id"] != repository_id:
        raise ClientIntegrationError("SOS_CLIENT_REPOSITORY_MISMATCH", Status.STALE)
    if manifest["launcher_digest"] != binding.digest or manifest["package_version"] != binding.package_version:
        raise ClientIntegrationError("SOS_CLIENT_LAUNCHER_STALE", Status.STALE)


def _verify_installed(root: Path, manifest: dict[str, Any], binding: LauncherBinding) -> None:
    _verify_manifest_binding(manifest, manifest["repository_id"], binding)
    current, exists, _ = _read_target(root)
    if not exists or _bytes_digest(current) != manifest["configured_digest"]:
        raise ClientIntegrationError("SOS_CLIENT_CONFIG_DRIFT", Status.STALE)
    original_length = manifest["original_byte_count"]
    if _bytes_digest(current[:original_length]) != manifest["original_digest"]:
        raise ClientIntegrationError("SOS_CLIENT_CONFIG_DRIFT", Status.STALE)
    if _bytes_digest(current[original_length:]) != manifest["managed_addition_digest"]:
        raise ClientIntegrationError("SOS_CLIENT_CONFIG_DRIFT", Status.STALE)
    expected_addition = _render_addition(root, binding, current[:original_length])
    if current != current[:original_length] + expected_addition:
        raise ClientIntegrationError("SOS_CLIENT_CONFIG_DRIFT", Status.STALE)


def _verify_removable(root: Path, manifest: dict[str, Any]) -> None:
    current, exists, _ = _read_target(root)
    if not exists or _bytes_digest(current) != manifest["configured_digest"]:
        raise ClientIntegrationError("SOS_CLIENT_CONFIG_DRIFT", Status.STALE)
    original_length = manifest["original_byte_count"]
    original = current[:original_length]
    addition = current[original_length:]
    if _bytes_digest(original) != manifest["original_digest"] or _bytes_digest(addition) != manifest["managed_addition_digest"]:
        raise ClientIntegrationError("SOS_CLIENT_CONFIG_DRIFT", Status.STALE)
    if _BEGIN.encode() not in addition or _END.encode() not in addition:
        raise ClientIntegrationError("SOS_CLIENT_CONFIG_DRIFT", Status.STALE)
    try:
        server = tomllib.loads(current.decode("utf-8"))["mcp_servers"][_SERVER]
    except (UnicodeDecodeError, tomllib.TOMLDecodeError, KeyError, TypeError) as exc:
        raise ClientIntegrationError("SOS_CLIENT_CONFIG_DRIFT", Status.STALE) from exc
    expected_tail = ["--root", os.fspath(root), "--expected-package-version", manifest["package_version"]]
    if (
        not isinstance(server, dict)
        or not isinstance(server.get("command"), str)
        or not Path(server["command"]).is_absolute()
        or server.get("args", [])[-4:] != expected_tail
        or server.get("enabled_tools") != list(_TOOLS)
        or server.get("default_tools_approval_mode") != "writes"
    ):
        raise ClientIntegrationError("SOS_CLIENT_CONFIG_DRIFT", Status.STALE)


def _read_target(root: Path) -> tuple[bytes, bool, bool]:
    root_descriptor = _open_root(root)
    try:
        try:
            parent = os.open(".codex", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=root_descriptor)
        except FileNotFoundError:
            return b"", False, False
        except OSError as exc:
            raise ClientIntegrationError("SOS_CLIENT_CONFIG_PARENT_INVALID") from exc
        try:
            try:
                descriptor = os.open("config.toml", os.O_RDONLY | os.O_NOFOLLOW, dir_fd=parent)
            except FileNotFoundError:
                return b"", False, True
            except OSError as exc:
                raise ClientIntegrationError("SOS_CLIENT_CONFIG_INVALID") from exc
            try:
                observed = os.fstat(descriptor)
                if not stat.S_ISREG(observed.st_mode) or observed.st_size > _MAX_CONFIG_BYTES:
                    raise ClientIntegrationError("SOS_CLIENT_CONFIG_INVALID")
                payload = _read_bounded(descriptor, _MAX_CONFIG_BYTES)
            finally:
                os.close(descriptor)
            if len(payload) > _MAX_CONFIG_BYTES:
                raise ClientIntegrationError("SOS_CLIENT_CONFIG_LIMIT_EXCEEDED", Status.UNSUPPORTED)
            return payload, True, True
        finally:
            os.close(parent)
    finally:
        os.close(root_descriptor)


def _replace_target(root: Path, payload: bytes, *, expected: bytes, expected_existed: bool) -> None:
    root_descriptor = _open_root(root)
    parent_created = False
    try:
        try:
            os.mkdir(".codex", mode=0o700, dir_fd=root_descriptor)
            parent_created = True
        except FileExistsError:
            pass
        try:
            parent = os.open(".codex", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=root_descriptor)
        except OSError as exc:
            raise ClientIntegrationError("SOS_CLIENT_CONFIG_PARENT_INVALID") from exc
        try:
            current = _read_relative_file(parent, "config.toml")
            if (current is not None) != expected_existed or (current or b"") != expected:
                raise ClientIntegrationError("SOS_CLIENT_CONFIG_DRIFT", Status.STALE)
            temporary = f".sos-config.{os.getpid()}.{os.urandom(8).hex()}"
            descriptor = os.open(
                temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=parent
            )
            try:
                _write_all(descriptor, payload)
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
            try:
                if expected_existed:
                    os.replace(temporary, "config.toml", src_dir_fd=parent, dst_dir_fd=parent)
                else:
                    os.link(temporary, "config.toml", src_dir_fd=parent, dst_dir_fd=parent, follow_symlinks=False)
                    os.unlink(temporary, dir_fd=parent)
                os.fsync(parent)
            finally:
                try:
                    os.unlink(temporary, dir_fd=parent)
                except FileNotFoundError:
                    pass
        finally:
            os.close(parent)
    except BaseException:
        if parent_created:
            try:
                os.rmdir(".codex", dir_fd=root_descriptor)
            except OSError:
                pass
        raise
    finally:
        os.close(root_descriptor)


def _restore_target(
    root: Path, original: bytes, *, original_existed: bool, parent_existed: bool, expected: bytes
) -> None:
    root_descriptor = _open_root(root)
    try:
        try:
            parent = os.open(".codex", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=root_descriptor)
        except OSError as exc:
            raise ClientIntegrationError("SOS_CLIENT_CONFIG_PARENT_INVALID") from exc
        try:
            current = _read_relative_file(parent, "config.toml")
            if current != expected:
                raise ClientIntegrationError("SOS_CLIENT_CONFIG_DRIFT", Status.STALE)
            if original_existed:
                temporary = f".sos-config.{os.getpid()}.{os.urandom(8).hex()}"
                descriptor = os.open(
                    temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=parent
                )
                try:
                    _write_all(descriptor, original)
                    os.fsync(descriptor)
                finally:
                    os.close(descriptor)
                os.replace(temporary, "config.toml", src_dir_fd=parent, dst_dir_fd=parent)
            else:
                os.unlink("config.toml", dir_fd=parent)
            os.fsync(parent)
        finally:
            os.close(parent)
        if not parent_existed:
            try:
                os.rmdir(".codex", dir_fd=root_descriptor)
                os.fsync(root_descriptor)
            except OSError:
                pass
    finally:
        os.close(root_descriptor)


def _write_manifest(root: Path, manifest: dict[str, Any]) -> None:
    _validate_manifest(manifest)
    descriptor = _open_control_directory(root, ("integrations",), create=True)
    temporary = f".codex-mcp.{os.getpid()}.{os.urandom(8).hex()}"
    try:
        file_descriptor = os.open(
            temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=descriptor
        )
        try:
            payload = json.dumps(manifest, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
            _write_all(file_descriptor, payload)
            os.fsync(file_descriptor)
        finally:
            os.close(file_descriptor)
        os.replace(temporary, "codex-mcp.json", src_dir_fd=descriptor, dst_dir_fd=descriptor)
        os.fsync(descriptor)
    finally:
        try:
            os.unlink(temporary, dir_fd=descriptor)
        except FileNotFoundError:
            pass
        os.close(descriptor)


def _open_root(root: Path) -> int:
    try:
        return os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    except OSError as exc:
        raise ClientIntegrationError("SOS_REPOSITORY_ROOT_INVALID") from exc


def _open_control_directory(root: Path, parts: tuple[str, ...], *, create: bool) -> int:
    try:
        descriptor = os.open(root / ".sigma", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    except FileNotFoundError as exc:
        raise ClientIntegrationError("SOS_CLIENT_MANIFEST_MISSING") from exc
    except OSError as exc:
        raise ClientIntegrationError("SOS_CONTROL_PLANE_INTEGRITY_INVALID") from exc
    try:
        for part in parts:
            if create:
                try:
                    os.mkdir(part, mode=0o700, dir_fd=descriptor)
                except FileExistsError:
                    pass
            try:
                child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=descriptor)
            except FileNotFoundError as exc:
                raise ClientIntegrationError("SOS_CLIENT_MANIFEST_MISSING") from exc
            except OSError as exc:
                raise ClientIntegrationError("SOS_CONTROL_PLANE_INTEGRITY_INVALID") from exc
            os.close(descriptor)
            descriptor = child
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def _read_relative_file(directory: int, name: str) -> bytes | None:
    try:
        descriptor = os.open(name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=directory)
    except FileNotFoundError:
        return None
    except OSError as exc:
        raise ClientIntegrationError("SOS_CLIENT_CONFIG_INVALID") from exc
    try:
        observed = os.fstat(descriptor)
        if not stat.S_ISREG(observed.st_mode) or observed.st_size > _MAX_CONFIG_BYTES:
            raise ClientIntegrationError("SOS_CLIENT_CONFIG_INVALID")
        return _read_bounded(descriptor, _MAX_CONFIG_BYTES)
    finally:
        os.close(descriptor)


def _safe_details(manifest: dict[str, Any] | None) -> dict[str, Any]:
    details: dict[str, Any] = {
        "client": _CLIENT,
        "target": _TARGET,
        "absolute_paths_serialized": False,
        "raw_config_serialized": False,
        "acceptance_tools_exposed": False,
        "arbitrary_shell_exposed": False,
        "external_action_tools_exposed": False,
        "client_project_trust_required": True,
        "client_restart_required": True,
    }
    if manifest is not None:
        details.update(
            {
                "integration_state": manifest["state"],
                "manifest_digest": manifest["manifest_digest"],
                "launcher_digest": manifest["launcher_digest"],
                "package_version": manifest["package_version"],
                "configured_digest": manifest["configured_digest"],
                "currentness_after_install": "stale_until_successor_acceptance",
            }
        )
    return details


def _result(status: Status, reason: str, manifest: dict[str, Any] | None = None) -> TerminalResult:
    return TerminalResult(_RESULT_CONTRACT, status, (reason,), _safe_details(manifest))


def _error_result(exc: BaseException) -> TerminalResult:
    if isinstance(exc, ClientIntegrationError):
        return _result(exc.status, exc.reason)
    if isinstance(exc, RepositoryError):
        return _result(Status.INVALID, exc.reason)
    if isinstance(exc, OSError):
        return _result(Status.BLOCKED, "SOS_CLIENT_IO_FAILED")
    return _result(Status.INVALID, str(exc))


def _manifest_digest(value: dict[str, Any]) -> str:
    material = dict(value)
    material["manifest_digest"] = "sha256:" + "0" * 64
    return digest_value(material)


def _bytes_digest(payload: bytes) -> str:
    return "sha256:" + hashlib.sha256(payload).hexdigest()


def _sha256_file(path: Path, limit: int) -> str:
    digest = hashlib.sha256()
    total = 0
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            total += len(chunk)
            if total > limit:
                raise ClientIntegrationError("SOS_CLIENT_LAUNCHER_INVALID", Status.UNSUPPORTED)
            digest.update(chunk)
    return "sha256:" + digest.hexdigest()


def _toml_string(value: str) -> str:
    return json.dumps(value, ensure_ascii=False)


def _toml_array(values: list[str]) -> str:
    return "[" + ", ".join(_toml_string(value) for value in values) + "]"


def _write_all(descriptor: int, payload: bytes) -> None:
    offset = 0
    while offset < len(payload):
        written = os.write(descriptor, payload[offset:])
        if written <= 0:
            raise ClientIntegrationError("SOS_CLIENT_WRITE_FAILED", Status.BLOCKED)
        offset += written


def _read_bounded(descriptor: int, limit: int) -> bytes:
    chunks: list[bytes] = []
    total = 0
    while True:
        chunk = os.read(descriptor, min(64 * 1024, limit + 1 - total))
        if not chunk:
            return b"".join(chunks)
        chunks.append(chunk)
        total += len(chunk)
        if total > limit:
            raise ClientIntegrationError("SOS_CLIENT_CONFIG_LIMIT_EXCEEDED", Status.UNSUPPORTED)
