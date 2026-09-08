"""Inactive POSIX reservation and payload mechanisms for project-owned runtimes.

The namespace must already be explicitly provisioned as a private directory.
Reservation never installs packages. Explicit payload installation remains
separate; neither mechanism marks a runtime ready or removes anything.
"""

from __future__ import annotations

import contextlib
import fcntl
import hashlib
import os
import platform
import stat
import sys
import subprocess
from pathlib import Path
from typing import Iterator

from ..contracts import canonical_json, digest_value
from ..project_runtime import ProjectRuntimeError, validate_runtime_identity


_DIR_FLAGS = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
_FILE_FLAGS = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC


def _private(fd: int) -> None:
    observed = os.fstat(fd)
    if not stat.S_ISDIR(observed.st_mode) or observed.st_uid != os.geteuid() or observed.st_mode & 0o077:
        raise ProjectRuntimeError("SOS_PROJECT_RUNTIME_DIRECTORY_UNSAFE")


@contextlib.contextmanager
def _open_absolute(path: Path, *, private: bool) -> Iterator[int]:
    """Walk every ancestor by descriptor without following symbolic links."""
    if not path.is_absolute() or ".." in path.parts:
        raise ProjectRuntimeError("SOS_PROJECT_RUNTIME_PATH_INVALID")
    fd = os.open("/", _DIR_FLAGS)
    try:
        for component in path.parts[1:]:
            current = os.fstat(fd)
            # Root-owned sticky temporary ancestors are allowed; private leaf
            # checks still apply. Same-user malicious renames are not authenticated.
            if current.st_uid not in (0, os.geteuid()) or (
                current.st_mode & 0o022 and not (current.st_uid == 0 and current.st_mode & stat.S_ISVTX)
            ):
                raise ProjectRuntimeError("SOS_PROJECT_RUNTIME_DIRECTORY_UNSAFE")
            child = os.open(component, _DIR_FLAGS, dir_fd=fd)
            os.close(fd)
            fd = child
        if private:
            _private(fd)
        elif os.fstat(fd).st_uid != os.geteuid() or os.fstat(fd).st_mode & 0o022:
            raise ProjectRuntimeError("SOS_PROJECT_RUNTIME_DIRECTORY_UNSAFE")
        yield fd
    finally:
        os.close(fd)


def observe_project(path: Path, repository_digest: str) -> dict[str, str]:
    """Observe local root/user anchors; repository identity is independently supplied."""
    if sys.platform not in {"linux", "darwin"}:
        raise ProjectRuntimeError("SOS_PROJECT_RUNTIME_PLATFORM_UNSUPPORTED")
    try:
        with _open_absolute(path, private=False):
            return {
                "owner_digest": digest_value({"domain": "sos_posix_user_v1", "uid": os.geteuid()}),
                "root_digest": digest_value({"domain": "sos_canonical_root_v1", "root": os.fspath(path)}),
                "repository_digest": repository_digest,
            }
    except OSError:
        raise ProjectRuntimeError("SOS_PROJECT_RUNTIME_PATH_INVALID") from None


def _write_exclusive(fd: int, name: str, payload: bytes) -> None:
    target = os.open(name, _FILE_FLAGS, 0o600, dir_fd=fd)
    try:
        offset = 0
        while offset < len(payload):
            count = os.write(target, payload[offset:])
            if count <= 0:
                raise OSError("short write")
            offset += count
        os.fsync(target)
    finally:
        os.close(target)
    os.fsync(fd)


def _read_exact(fd: int, name: str, expected: bytes) -> None:
    marker = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK, dir_fd=fd)
    try:
        observed = os.fstat(marker)
        if (not stat.S_ISREG(observed.st_mode) or observed.st_uid != os.geteuid()
                or observed.st_mode & 0o077 or observed.st_nlink != 1 or observed.st_size != len(expected)):
            raise ProjectRuntimeError("SOS_PROJECT_RUNTIME_OWNERSHIP_MISMATCH")
        payload = bytearray()
        while len(payload) <= len(expected):
            block = os.read(marker, len(expected) + 1 - len(payload))
            if not block:
                break
            payload.extend(block)
        if bytes(payload) != expected:
            raise ProjectRuntimeError("SOS_PROJECT_RUNTIME_OWNERSHIP_MISMATCH")
    finally:
        os.close(marker)


def reserve_generation(
    namespace: Path, project: Path, identity: object, *, repository_digest: str,
    confirmed_plan_digest: str,
) -> Path:
    """Reserve a final, inactive location after caller-side exact confirmation.

    The plan digest records the caller's admission, it does not manufacture or
    independently prove human confirmation. No public launcher calls this yet.
    Failed reservations are retained and cannot be silently reused.
    """
    if (not isinstance(confirmed_plan_digest, str) or len(confirmed_plan_digest) != 71
            or not confirmed_plan_digest.startswith("sha256:")
            or any(c not in "0123456789abcdef" for c in confirmed_plan_digest[7:])):
        raise ProjectRuntimeError("SOS_PROJECT_RUNTIME_PLAN_INVALID")
    observed = observe_project(project, repository_digest)
    record = validate_runtime_identity(identity, **observed)
    host_architecture = {"amd64": "x86_64", "aarch64": "arm64"}.get(
        platform.machine().lower(), platform.machine().lower()
    )
    if (record["maintenance_binding"]["system"] != sys.platform
            or record["maintenance_binding"]["architecture"] != host_architecture):
        raise ProjectRuntimeError("SOS_PROJECT_RUNTIME_PLATFORM_UNSUPPORTED")
    if namespace.name != "project-runtimes":
        raise ProjectRuntimeError("SOS_PROJECT_RUNTIME_NAMESPACE_INVALID")
    if namespace == project or namespace.is_relative_to(project):
        raise ProjectRuntimeError("SOS_PROJECT_RUNTIME_NAMESPACE_IN_PROJECT")
    project_key = record["project_key"][7:]
    generation_key = record["generation_key"][7:]
    marker = canonical_json({
        "contract": "sos_project_runtime_namespace_owner_v1", **observed,
        "project_key": record["project_key"], "absolute_paths_serialized": False,
    })
    try:
        with _open_absolute(namespace, private=True) as base:
            # Descriptor locks avoid a replaceable lockfile. All future writers
            # must use the same namespace lock before project/generation changes.
            try:
                fcntl.flock(base, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                raise ProjectRuntimeError("SOS_PROJECT_RUNTIME_BUSY") from None
            try:
                created = False
                try:
                    os.mkdir(project_key, mode=0o700, dir_fd=base)
                    created = True
                except FileExistsError:
                    pass
                child = os.open(project_key, _DIR_FLAGS, dir_fd=base)
                try:
                    _private(child)
                    if created:
                        _write_exclusive(child, "owner.json", marker)
                        os.fsync(base)
                    else:
                        _read_exact(child, "owner.json", marker)
                    # Each project directory contains digest-named generations;
                    # no current symlink and no mutable active environment.
                    try:
                        os.mkdir(generation_key, mode=0o700, dir_fd=child)
                    except FileExistsError:
                        raise ProjectRuntimeError("SOS_PROJECT_RUNTIME_GENERATION_EXISTS") from None
                    generation = os.open(generation_key, _DIR_FLAGS, dir_fd=child)
                    try:
                        _private(generation)
                        _write_exclusive(generation, "reservation.json", canonical_json({
                            "contract": "sos_project_runtime_reservation_v1", "state": "reserved",
                            "identity": record, "confirmed_plan_digest": confirmed_plan_digest,
                            "runtime_ready": False,
                        }))
                        os.fsync(child)
                    finally:
                        os.close(generation)
                finally:
                    os.close(child)
            finally:
                fcntl.flock(base, fcntl.LOCK_UN)
    except OSError:
        raise ProjectRuntimeError("SOS_PROJECT_RUNTIME_RESERVATION_FAILED") from None
    return namespace / project_key / generation_key


def install_reserved_wheel(
    namespace: Path, project: Path, identity: object, *, repository_digest: str,
    confirmed_plan_digest: str, uv: Path, uv_sha256: str, wheel: Path,
    wheelhouse: Path, python_network_allowed: bool = False,
) -> Path:
    """Populate one reservation using caller-verified acquisition inputs.

    The caller must verify the release manifest and complete wheelhouse first.
    This low-level mechanism checks uv, wheel and resulting interpreter digests;
    it is not public archive admission. It never marks adapters/runtime ready.
    Failed attempts are retained and cannot be repeated implicitly.
    """
    record = validate_runtime_identity(identity, **observe_project(project, repository_digest))
    if namespace.name != "project-runtimes" or namespace.is_relative_to(project):
        raise ProjectRuntimeError("SOS_PROJECT_RUNTIME_NAMESPACE_INVALID")
    if type(python_network_allowed) is not bool:
        raise ProjectRuntimeError("SOS_PROJECT_RUNTIME_PLAN_INVALID")
    if (not isinstance(uv_sha256, str) or len(uv_sha256) != 64
            or any(c not in "0123456789abcdef" for c in uv_sha256)):
        raise ProjectRuntimeError("SOS_PROJECT_RUNTIME_RELEASE_INVALID")
    for path, expected in ((uv, uv_sha256), (wheel, record["wheel_digest"][7:])):
        if _regular_digest(path) != expected:
            raise ProjectRuntimeError("SOS_PROJECT_RUNTIME_PAYLOAD_MISMATCH")
    target = namespace / record["project_key"][7:] / record["generation_key"][7:]
    reservation = canonical_json({
        "contract": "sos_project_runtime_reservation_v1", "state": "reserved",
        "identity": record, "confirmed_plan_digest": confirmed_plan_digest,
        "runtime_ready": False,
    })
    try:
        with _open_absolute(namespace, private=True) as base:
            try:
                fcntl.flock(base, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                raise ProjectRuntimeError("SOS_PROJECT_RUNTIME_BUSY") from None
            with _open_absolute(target, private=True) as generation:
                _read_exact(generation, "reservation.json", reservation)
                _write_exclusive(generation, "payload-attempt.json", canonical_json({
                    "contract": "sos_project_runtime_payload_attempt_v1",
                    "identity_digest": record["identity_digest"],
                    "python_network_allowed": python_network_allowed,
                }))
                for name in ("python", "tools", "bin", "cache", "tmp"):
                    os.mkdir(name, mode=0o700, dir_fd=generation)
                environment = {
                    "PATH": "/usr/bin:/bin", "LANG": "C.UTF-8",
                    "UV_NO_CONFIG": "1", "UV_PYTHON_INSTALL_DIR": os.fspath(target / "python"),
                    "UV_TOOL_DIR": os.fspath(target / "tools"),
                    "UV_TOOL_BIN_DIR": os.fspath(target / "bin"),
                    "UV_CACHE_DIR": os.fspath(target / "cache"),
                    "TMPDIR": os.fspath(target / "tmp"), "PYTHONNOUSERSITE": "1",
                }
                def run(arguments: list[str]) -> str:
                    result = subprocess.run(arguments, env=environment, cwd=target,
                                            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                            stderr=subprocess.PIPE, text=True, timeout=180, check=False)
                    if result.returncode != 0:
                        raise ProjectRuntimeError("SOS_PROJECT_RUNTIME_PAYLOAD_INSTALL_FAILED")
                    return result.stdout.strip()

                acquisition = [os.fspath(uv), "python", "install", "3.12.14", "--no-bin",
                               "--no-registry", "--no-config", "--no-progress"]
                if not python_network_allowed:
                    acquisition.append("--offline")
                run(acquisition)
                selected = run([os.fspath(uv), "python", "find", "3.12.14", "--managed-python",
                                "--no-python-downloads", "--no-config"])
                python = Path(selected).resolve(strict=True)
                if not python.is_relative_to(target / "python"):
                    raise ProjectRuntimeError("SOS_PROJECT_RUNTIME_INTERPRETER_MISMATCH")
                if "sha256:" + _regular_digest(python) != record["interpreter_digest"]:
                    raise ProjectRuntimeError("SOS_PROJECT_RUNTIME_INTERPRETER_MISMATCH")
                if run([os.fspath(python), "-I", "--version"]) != "Python 3.12.14":
                    raise ProjectRuntimeError("SOS_PROJECT_RUNTIME_INTERPRETER_MISMATCH")
                run([os.fspath(uv), "tool", "install", "--offline", "--no-index",
                     "--find-links", os.fspath(wheelhouse), "--no-config", "--no-sources",
                     "--no-build", "--no-python-downloads", "--python", os.fspath(python),
                     os.fspath(wheel)])
                launcher = (target / "bin" / "sos").resolve(strict=True)
                if not launcher.is_relative_to(target / "tools"):
                    raise ProjectRuntimeError("SOS_PROJECT_RUNTIME_LAUNCHER_MISMATCH")
                if run([os.fspath(launcher), "--version"]) != "sos " + record["maintenance_binding"]["version"]:
                    raise ProjectRuntimeError("SOS_PROJECT_RUNTIME_LAUNCHER_MISMATCH")
                _write_exclusive(generation, "payload-installed.json", canonical_json({
                    "contract": "sos_project_runtime_payload_installed_v1",
                    "identity_digest": record["identity_digest"], "runtime_ready": False,
                    "adapter_switch_performed": False,
                }))
    except (OSError, subprocess.TimeoutExpired, UnicodeError):
        raise ProjectRuntimeError("SOS_PROJECT_RUNTIME_PAYLOAD_INSTALL_FAILED") from None
    return launcher


def _regular_digest(path: Path) -> str:
    try:
        with _open_absolute(path.parent, private=False) as parent:
            fd = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK, dir_fd=parent)
            try:
                observed = os.fstat(fd)
                if not stat.S_ISREG(observed.st_mode) or observed.st_size > 128 * 1024 * 1024:
                    raise ProjectRuntimeError("SOS_PROJECT_RUNTIME_PAYLOAD_MISMATCH")
                hasher = hashlib.sha256()
                remaining = observed.st_size
                while remaining:
                    block = os.read(fd, min(remaining, 1024 * 1024))
                    if not block:
                        raise ProjectRuntimeError("SOS_PROJECT_RUNTIME_PAYLOAD_MISMATCH")
                    hasher.update(block)
                    remaining -= len(block)
                if os.read(fd, 1):
                    raise ProjectRuntimeError("SOS_PROJECT_RUNTIME_PAYLOAD_MISMATCH")
                return hasher.hexdigest()
            finally:
                os.close(fd)
    except OSError:
        raise ProjectRuntimeError("SOS_PROJECT_RUNTIME_PAYLOAD_MISMATCH") from None
