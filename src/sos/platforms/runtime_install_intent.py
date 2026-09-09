"""Private, root-bound fresh-install intent retained across controller crashes."""

import contextlib
import fcntl
import json
import os
import stat
import uuid
from pathlib import Path

from ..contracts import canonical_json, digest_value
from ..project_runtime import ProjectRuntimeError
from .project_runtime_posix import _DIR_FLAGS, _open_absolute, _private, _write_exclusive, observe_project


def prepare_namespace_parents(namespace):
    """After confirmation only; create missing ancestors without following links."""
    namespace = Path(namespace)
    if namespace.name != "project-runtimes" or not namespace.is_absolute() or ".." in namespace.parts:
        raise ProjectRuntimeError("SOS_PROJECT_RUNTIME_NAMESPACE_INVALID")
    missing = []
    parent = namespace.parent
    while True:
        try:
            with _open_absolute(parent, private=False):
                break
        except FileNotFoundError:
            missing.append(parent.name)
            parent = parent.parent
    for name in reversed(missing):
        with _open_absolute(parent, private=False) as fd:
            try:
                os.mkdir(name, 0o700, dir_fd=fd)
                os.fsync(fd)
            except FileExistsError:
                pass
        parent = parent / name
        with _open_absolute(parent, private=False):
            pass


def _key(project):
    observed = observe_project(project, "sha256:" + "0" * 64)
    return digest_value({k: observed[k] for k in ("owner_digest", "root_digest")})[7:]


@contextlib.contextmanager
def install_intent_lock(namespace, project):
    """Independent project lock; never holds the generation namespace flock."""
    with _open_absolute(namespace, private=True) as base:
        try:
            os.mkdir("install-intents", 0o700, dir_fd=base)
            os.fsync(base)
        except FileExistsError:
            pass
        directory = os.open("install-intents", _DIR_FLAGS, dir_fd=base)
        try:
            _private(directory)
            fd = os.open(_key(project) + ".lock", os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_NONBLOCK, 0o600, dir_fd=directory)
            try:
                info = os.fstat(fd)
                if not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o077 or info.st_nlink != 1:
                    raise ProjectRuntimeError("SOS_PROJECT_RUNTIME_DIRECTORY_UNSAFE")
                try:
                    fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                except BlockingIOError:
                    raise ProjectRuntimeError("SOS_PROJECT_RUNTIME_BUSY") from None
                yield
            finally:
                os.close(fd)
        finally:
            os.close(directory)


def read_install_intent(namespace, project):
    try:
        with _open_absolute(namespace / "install-intents", private=True) as directory:
            fd = os.open(_key(project) + ".json", os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory)
            try:
                info = os.fstat(fd)
                if not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o077 or info.st_nlink != 1 or info.st_size > 1024 * 1024:
                    raise ProjectRuntimeError("SOS_PROJECT_RUNTIME_INSTALL_INTENT_INVALID")
                chunks = bytearray()
                while len(chunks) <= 1024 * 1024:
                    block = os.read(fd, min(65536, 1024 * 1024 + 1 - len(chunks)))
                    if not block:
                        break
                    chunks.extend(block)
                value = json.loads(chunks)
                if canonical_json(value) != bytes(chunks):
                    raise ValueError()
                return value
            finally:
                os.close(fd)
    except FileNotFoundError:
        return None
    except (ValueError, TypeError, RecursionError):
        raise ProjectRuntimeError("SOS_PROJECT_RUNTIME_INSTALL_INTENT_INVALID") from None


def write_install_intent(namespace, project, value):
    """Caller holds intent lock. Atomic publication retains the old record on error."""
    with _open_absolute(namespace / "install-intents", private=True) as directory:
        temporary = "pending-" + uuid.uuid4().hex
        try:
            _write_exclusive(directory, temporary, canonical_json(value))
            os.replace(temporary, _key(project) + ".json", src_dir_fd=directory, dst_dir_fd=directory)
            os.fsync(directory)
        finally:
            try:
                os.unlink(temporary, dir_fd=directory)
            except FileNotFoundError:
                pass
