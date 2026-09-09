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


def controller_executable():
    return str(Path(sys.executable).resolve(strict=True))


def run_checked_native_smoke(script, script_digest, launcher, project, clients=("codex",)):
    if _regular_digest(script) != script_digest:
        raise ProjectRuntimeError("SOS_PROJECT_RUNTIME_PAYLOAD_MISMATCH")
    if "sha256:" + observed_executable_digest(launcher.command) != launcher.executable_sha256:
        raise ProjectRuntimeError("SOS_PROJECT_RUNTIME_LAUNCHER_MISMATCH")
    return subprocess.run([sys.executable, "-I", "-S", "-B", str(script),
        "--python", launcher.command, "--python-sha256", launcher.executable_sha256[7:],
        *[arg for client in clients for arg in ("--client", client)],
        str(project)], stdin=subprocess.DEVNULL, check=False, timeout=180,
        env={"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8", "PYTHONDONTWRITEBYTECODE": "1"}).returncode


def prepare_runtime_namespace(namespace: Path) -> None:
    """Create the dedicated private namespace only after carrier confirmation.

    The existing user-data parent is walked without following links. Never
    chmod, replace, or adopt a foreign/unsafe existing namespace.
    """
    if namespace.name != "project-runtimes":
        raise ProjectRuntimeError("SOS_PROJECT_RUNTIME_NAMESPACE_INVALID")
    try:
        with _open_absolute(namespace.parent, private=False) as parent:
            try:
                os.mkdir(namespace.name, mode=0o700, dir_fd=parent)
                os.fsync(parent)
            except FileExistsError:
                pass
            child = os.open(namespace.name, _DIR_FLAGS, dir_fd=parent)
            try:
                _private(child)
            finally:
                os.close(child)
    except OSError:
        raise ProjectRuntimeError("SOS_PROJECT_RUNTIME_DIRECTORY_UNSAFE") from None


@contextlib.contextmanager
def runtime_namespace_lock(namespace: Path):
    """Hold after the outer project lock and before the P107 adapter lock."""
    if namespace.name != "project-runtimes":
        raise ProjectRuntimeError("SOS_PROJECT_RUNTIME_NAMESPACE_INVALID")
    with _open_absolute(namespace, private=True) as fd:
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise ProjectRuntimeError("SOS_PROJECT_RUNTIME_BUSY") from None
        try:
            yield
        finally:
            fcntl.flock(fd, fcntl.LOCK_UN)


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
    wheel_inventory: tuple[tuple[str, str], ...] = (),
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
    from .project_runtime_inventory import checked_wheel_sources, verify_installed_wheels
    if (not isinstance(wheel_inventory, tuple) or not 1 <= len(wheel_inventory) <= 16
            or any(not isinstance(row, tuple) or len(row) != 2 for row in wheel_inventory)
            or any(not isinstance(name, str) or Path(name).name != name or not name.endswith(".whl")
                   for name, digest in wheel_inventory)):
        raise ProjectRuntimeError("SOS_PROJECT_RUNTIME_INVENTORY_INVALID")
    if dict(wheel_inventory).get(wheel.name) != record["wheel_digest"][7:]:
        raise ProjectRuntimeError("SOS_PROJECT_RUNTIME_PAYLOAD_MISMATCH")
    try:
        actual_wheels = {p.name for p in wheelhouse.iterdir() if p.name.endswith(".whl")}
    except OSError:
        raise ProjectRuntimeError("SOS_PROJECT_RUNTIME_INVENTORY_INVALID") from None
    if actual_wheels != {name for name, digest in wheel_inventory}:
        raise ProjectRuntimeError("SOS_PROJECT_RUNTIME_INVENTORY_EXTRA")
    wheels = tuple((wheelhouse / name, digest) for name, digest in wheel_inventory)
    checked_wheel_sources(wheels, record["maintenance_binding"]["version"])
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
                    "PYTHONDONTWRITEBYTECODE": "1",
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
                # Derive import-hook reference bytes from the independently
                # checked installer, never from the environment under test.
                reference = target / "tmp" / "installer-reference"
                run([os.fspath(uv), "venv", "--offline", "--no-config",
                     "--no-python-downloads", "--python", os.fspath(python), os.fspath(reference)])
                hook_root = reference / "lib/python3.12/site-packages"
                hooks = {name: _regular_digest(hook_root / name)
                         for name in ("_virtualenv.py", "_virtualenv.pth")}
                inventory = verify_installed_wheels(
                    target / "tools/sigma-operator-stack/lib/python3.12/site-packages", wheels,
                    expected_sos_version=record["maintenance_binding"]["version"],
                    installer_hook_digests=hooks,
                )
                launcher = (target / "bin" / "sos").resolve(strict=True)
                if not launcher.is_relative_to(target / "tools"):
                    raise ProjectRuntimeError("SOS_PROJECT_RUNTIME_LAUNCHER_MISMATCH")
                if run([os.fspath(launcher), "--version"]) != "sos " + record["maintenance_binding"]["version"]:
                    raise ProjectRuntimeError("SOS_PROJECT_RUNTIME_LAUNCHER_MISMATCH")
                after = verify_installed_wheels(
                    target / "tools/sigma-operator-stack/lib/python3.12/site-packages", wheels,
                    expected_sos_version=record["maintenance_binding"]["version"],
                    installer_hook_digests=hooks,
                )
                if after != inventory:
                    raise ProjectRuntimeError("SOS_PROJECT_RUNTIME_INVENTORY_DRIFT")
                _write_exclusive(generation, "payload-installed.json", canonical_json({
                    "contract": "sos_project_runtime_payload_installed_v1",
                    "identity_digest": record["identity_digest"], "runtime_ready": False,
                    "adapter_switch_performed": False,
                    "wheel_inventory_digest": inventory["wheel_inventory_digest"],
                    "installed_inventory_digest": inventory["installed_inventory_digest"],
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


def resolve_runtime_reference(path: Path) -> Path:
    """Observe a configured executable link without executing the target."""
    return path.resolve()


def observed_executable_digest(command: str) -> str:
    """Observe an existing interpreter, retaining normal venv link resolution."""
    try:
        return _regular_digest(Path(command).resolve(strict=True))
    except (OSError, RuntimeError):
        raise ProjectRuntimeError("SOS_PROJECT_RUNTIME_PREDECESSOR_MISMATCH") from None


def observe_verified_generation_launcher(
    namespace: Path, project: Path, identity: object, *, repository_digest: str,
    confirmed_plan_digest: str, wheels: tuple[tuple[Path, str], ...],
    active: bool = False,
) -> tuple[Path, str, str]:
    """Read-only executable observation for the later P107 handoff.

    Returns an ephemeral venv Python path, version and executable SHA-256, not
    activation or mutation authority. The caller must revalidate under its
    transaction locks immediately before switching. No package command is run.
    """
    from .project_runtime_inventory import _read, verify_installed_wheels
    record = validate_runtime_identity(identity, **observe_project(project, repository_digest))
    if namespace.name != "project-runtimes" or namespace.is_relative_to(project):
        raise ProjectRuntimeError("SOS_PROJECT_RUNTIME_NAMESPACE_INVALID")
    target = namespace / record["project_key"][7:] / record["generation_key"][7:]
    if type(active) is not bool:
        raise ProjectRuntimeError("SOS_PROJECT_RUNTIME_PLAN_INVALID")
    try:
        with _open_absolute(namespace, private=True), _open_absolute(target, private=True) as generation:
            _read_exact(generation, "reservation.json", canonical_json({
                "contract": "sos_project_runtime_reservation_v1", "state": "reserved",
                "identity": record, "confirmed_plan_digest": confirmed_plan_digest,
                "runtime_ready": False,
            }))
            reference = target / "tmp/installer-reference/lib/python3.12/site-packages"
            hooks = {name: _regular_digest(reference / name) for name in ("_virtualenv.py", "_virtualenv.pth")}
            executable = target / "tools/sigma-operator-stack/bin/python3"
            with _open_absolute(executable.parent, private=False):
                resolved = executable.resolve(strict=True)
            if not resolved.is_relative_to(target / "python"):
                raise ProjectRuntimeError("SOS_PROJECT_RUNTIME_INTERPRETER_MISMATCH")
            digest = _regular_digest(resolved)
            if "sha256:" + digest != record["interpreter_digest"]:
                raise ProjectRuntimeError("SOS_PROJECT_RUNTIME_INTERPRETER_MISMATCH")
            inventory = verify_installed_wheels(
                target / "tools/sigma-operator-stack/lib/python3.12/site-packages", wheels,
                expected_sos_version=record["maintenance_binding"]["version"], installer_hook_digests=hooks,
                cache_python=resolved if active else None,
                cache_python_sha256=digest if active else None,
            )
            sos_wheel = next(c for c in inventory["components"] if c["name"] == "sigma-operator-stack")
            if "sha256:" + sos_wheel["wheel_sha256"] != record["wheel_digest"]:
                raise ProjectRuntimeError("SOS_PROJECT_RUNTIME_PAYLOAD_MISMATCH")
            _read_exact(generation, "payload-installed.json", canonical_json({
                "contract": "sos_project_runtime_payload_installed_v1",
                "identity_digest": record["identity_digest"], "runtime_ready": False,
                "adapter_switch_performed": False,
                "wheel_inventory_digest": inventory["wheel_inventory_digest"],
                "installed_inventory_digest": inventory["installed_inventory_digest"],
            }))
            executable = target / "tools/sigma-operator-stack/bin/python3"
            with _open_absolute(executable.parent, private=False):
                resolved = executable.resolve(strict=True)
            if not resolved.is_relative_to(target / "python"):
                raise ProjectRuntimeError("SOS_PROJECT_RUNTIME_INTERPRETER_MISMATCH")
            config = {}
            for line in _read(executable.parent.parent / "pyvenv.cfg", 16384).decode("utf-8").splitlines():
                key, separator, value = line.partition("=")
                key, value = key.strip(), value.strip()
                if not separator or key in config:
                    raise ProjectRuntimeError("SOS_PROJECT_RUNTIME_INTERPRETER_MISMATCH")
                config[key] = value
            if (set(config) != {"home", "implementation", "uv", "version_info", "include-system-site-packages"}
                    or config["home"] != os.fspath(resolved.parent)
                    or config["implementation"] != "CPython" or config["version_info"] != "3.12.14"
                    or config["include-system-site-packages"] != "false"):
                raise ProjectRuntimeError("SOS_PROJECT_RUNTIME_INTERPRETER_MISMATCH")
            digest = _regular_digest(resolved)
            if "sha256:" + digest != record["interpreter_digest"]:
                raise ProjectRuntimeError("SOS_PROJECT_RUNTIME_INTERPRETER_MISMATCH")
            return executable, record["maintenance_binding"]["version"], digest
    except (OSError, RuntimeError, UnicodeError) as exc:
        if isinstance(exc, ProjectRuntimeError):
            raise
        raise ProjectRuntimeError("SOS_PROJECT_RUNTIME_PAYLOAD_MISMATCH") from None
