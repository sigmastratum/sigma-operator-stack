"""Bounded, descriptor-relative deletion of an exact owned runtime snapshot.

The caller must establish terminal transition and adapter/reference admission.
No arbitrary path, legacy environment or unrecorded retry is admitted here.
"""

import hashlib
import contextlib
import json
import os
import stat
from pathlib import Path

from ..contracts import canonical_json, digest_value
from ..project_runtime import ProjectRuntimeError, validate_runtime_identity
from .project_runtime_posix import (_open_absolute, _DIR_FLAGS, _read_exact,
    _write_exclusive, observe_project, runtime_namespace_lock)
from .project_runtime_inventory import _read


def _entry(fd, name):
    info = os.stat(name, dir_fd=fd, follow_symlinks=False)
    if info.st_uid != os.geteuid():
        raise ProjectRuntimeError("SOS_PROJECT_RUNTIME_REMOVAL_FOREIGN")
    base = {"device": info.st_dev, "inode": info.st_ino, "mode": stat.S_IMODE(info.st_mode)}
    if stat.S_ISDIR(info.st_mode):
        return base | {"kind": "directory"}
    if stat.S_ISLNK(info.st_mode):
        return base | {"kind": "symlink", "digest": digest_value(os.readlink(name, dir_fd=fd))}
    if not stat.S_ISREG(info.st_mode) or info.st_size > 128 * 1024 * 1024:
        raise ProjectRuntimeError("SOS_PROJECT_RUNTIME_REMOVAL_FOREIGN")
    child = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=fd)
    try:
        before = os.fstat(child)
        if (before.st_dev, before.st_ino) != (info.st_dev, info.st_ino):
            raise ProjectRuntimeError("SOS_PROJECT_RUNTIME_REMOVAL_DRIFT")
        hasher = hashlib.sha256()
        size = 0
        while True:
            data = os.read(child, 1024 * 1024)
            if not data:
                break
            size += len(data)
            if size > 128 * 1024 * 1024:
                raise ProjectRuntimeError("SOS_PROJECT_RUNTIME_REMOVAL_DRIFT")
            hasher.update(data)
        after = os.fstat(child)
        if (size != before.st_size or before.st_mtime_ns != after.st_mtime_ns
                or before.st_ctime_ns != after.st_ctime_ns):
            raise ProjectRuntimeError("SOS_PROJECT_RUNTIME_REMOVAL_DRIFT")
        return base | {"kind": "regular", "size": size, "digest": "sha256:" + hasher.hexdigest()}
    finally:
        os.close(child)


def _snapshot(fd):
    entries = {}
    total = 0
    device = os.fstat(fd).st_dev
    def walk(directory, prefix, depth):
        nonlocal total
        if depth > 32:
            raise ProjectRuntimeError("SOS_PROJECT_RUNTIME_REMOVAL_LIMIT")
        for name in sorted(os.listdir(directory)):
            relative = prefix + name
            value = _entry(directory, name)
            total += value.get("size", 0)
            if len(entries) >= 30000 or total > 2 * 1024**3 or value["device"] != device:
                raise ProjectRuntimeError("SOS_PROJECT_RUNTIME_REMOVAL_LIMIT")
            entries[relative] = value
            if value["kind"] == "directory":
                child = os.open(name, _DIR_FLAGS, dir_fd=directory)
                try:
                    observed = os.fstat(child)
                    if observed.st_ino != value["inode"] or observed.st_dev != value["device"]:
                        raise ProjectRuntimeError("SOS_PROJECT_RUNTIME_REMOVAL_DRIFT")
                    walk(child, relative + "/", depth + 1)
                finally:
                    os.close(child)
    walk(fd, "", 0)
    return entries


def _location(namespace, project, identity):
    record = validate_runtime_identity(identity, **observe_project(project, identity["repository_digest"]))
    if namespace.name != "project-runtimes" or namespace.is_relative_to(project):
        raise ProjectRuntimeError("SOS_PROJECT_RUNTIME_NAMESPACE_INVALID")
    return record, namespace / record["project_key"][7:], record["generation_key"][7:]


def snapshot_owned_generation(namespace, project, identity, reservation_plan_digest):
    record, parent, name = _location(namespace, project, identity)
    with _open_absolute(parent, private=True) as directory:
        root_entry = _entry(directory, name)
        if root_entry["kind"] != "directory":
            raise ProjectRuntimeError("SOS_PROJECT_RUNTIME_REMOVAL_FOREIGN")
        with _open_absolute(parent / name, private=True) as generation:
            _read_exact(generation, "reservation.json", canonical_json({
                "contract": "sos_project_runtime_reservation_v1", "state": "reserved",
                "identity": record, "confirmed_plan_digest": reservation_plan_digest, "runtime_ready": False}))
            entries = _snapshot(generation)
    return {"root": root_entry, "entries": entries}


def read_removal_snapshot(namespace, project, identity, *, plan_digest, snapshot_digest, reservation_plan_digest):
    record, parent, name = _location(namespace, project, identity)
    path = parent / ("removal-" + name + ".json")
    with _open_absolute(parent, private=True) as directory:
        try:
            os.stat(path.name, dir_fd=directory, follow_symlinks=False)
        except FileNotFoundError:
            value = snapshot_owned_generation(namespace, project, identity, reservation_plan_digest)
            if digest_value(value) != snapshot_digest:
                raise ProjectRuntimeError("SOS_PROJECT_RUNTIME_REMOVAL_DRIFT")
            return value
    try:
        raw = _read(path, 16 * 1024 * 1024)
        value = json.loads(raw)
        if (not isinstance(value, dict) or set(value) != {"contract", "identity_digest", "plan_digest", "snapshot"}
                or canonical_json(value) != raw or value["contract"] != "sos_project_runtime_removal_manifest_v1"
                or value["identity_digest"] != record["identity_digest"] or value["plan_digest"] != plan_digest
                or digest_value(value["snapshot"]) != snapshot_digest):
            raise ValueError()
        return value["snapshot"]
    except (ValueError, TypeError, RecursionError):
        raise ProjectRuntimeError("SOS_PROJECT_RUNTIME_REMOVAL_DRIFT") from None


def delete_owned_generation(namespace, project, identity, *, snapshot, confirmed_plan_digest, fault=None,
                            namespace_locked=False):
    """Resume only the exact snapshot journal; new/drifted entries stop deletion.

    Directory/file names are private local mechanism data; callers expose only
    the aggregate snapshot digest. Symbolic links are unlinked, never followed.
    Already deleted bytes cannot be rolled back; failed deletion is resumable,
    not advertised as restored. Same-user malicious races are not authenticated.
    """
    record, parent, name = _location(namespace, project, identity)
    expected = {"contract": "sos_project_runtime_removal_manifest_v1",
                "identity_digest": record["identity_digest"], "plan_digest": confirmed_plan_digest,
                "snapshot": snapshot}
    raw = canonical_json(expected)
    if len(raw) > 16 * 1024 * 1024:
        raise ProjectRuntimeError("SOS_PROJECT_RUNTIME_REMOVAL_LIMIT")
    journal = "removal-" + name + ".json"
    finished = "removed-" + name + ".json"
    lock = contextlib.nullcontext() if namespace_locked else runtime_namespace_lock(namespace)
    with lock, _open_absolute(parent, private=True) as directory:
        try:
            _read_exact(directory, journal, raw)
        except FileNotFoundError:
            with _open_absolute(parent / name, private=True) as generation:
                if _entry(directory, name) != snapshot["root"] or _snapshot(generation) != snapshot["entries"]:
                    raise ProjectRuntimeError("SOS_PROJECT_RUNTIME_REMOVAL_DRIFT")
            _write_exclusive(directory, journal, raw)
        try:
            root_entry = _entry(directory, name)
        except FileNotFoundError:
            root_entry = None
        if root_entry is not None:
            if root_entry != snapshot["root"]:
                raise ProjectRuntimeError("SOS_PROJECT_RUNTIME_REMOVAL_DRIFT")
            with _open_absolute(parent / name, private=True) as generation:
                current = _snapshot(generation)
                if any(snapshot["entries"].get(key) != value for key, value in current.items()):
                    raise ProjectRuntimeError("SOS_PROJECT_RUNTIME_REMOVAL_DRIFT")
                for relative in sorted(current, key=lambda p: (-len(Path(p).parts), p)):
                    if fault:
                        fault("before_runtime_entry")
                    parts = Path(relative).parts
                    child = os.dup(generation)
                    try:
                        for component in parts[:-1]:
                            next_fd = os.open(component, _DIR_FLAGS, dir_fd=child)
                            os.close(child)
                            child = next_fd
                        if _entry(child, parts[-1]) != current[relative]:
                            raise ProjectRuntimeError("SOS_PROJECT_RUNTIME_REMOVAL_DRIFT")
                        if current[relative]["kind"] == "directory":
                            os.rmdir(parts[-1], dir_fd=child)
                        else:
                            os.unlink(parts[-1], dir_fd=child)
                        os.fsync(child)
                    finally:
                        os.close(child)
                if _entry(directory, name) != snapshot["root"]:
                    raise ProjectRuntimeError("SOS_PROJECT_RUNTIME_REMOVAL_DRIFT")
                os.rmdir(name, dir_fd=directory)
                os.fsync(directory)
        completion = canonical_json({"contract": "sos_project_runtime_removed_v1",
            "identity_digest": record["identity_digest"], "plan_digest": confirmed_plan_digest})
        try:
            _read_exact(directory, finished, completion)
        except FileNotFoundError:
            _write_exclusive(directory, finished, completion)
