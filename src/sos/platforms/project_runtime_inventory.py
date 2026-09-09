"""Offline installed-wheel verification; not runtime activation or ownership admission.

Inputs must come from independently verified release metadata. Generated import
hooks require independently obtained installer-template digests, never hashes
learned from the installation being verified. Active caches require separate
verification against recompilation of checked sources, never header-only trust.
"""

from __future__ import annotations

import hashlib
import base64
import io
import json
import os
import re
import stat
import subprocess
import zipfile
from email.parser import BytesParser
from pathlib import Path, PurePosixPath

from ..contracts import digest_value
from ..project_runtime import ProjectRuntimeError
from .project_runtime_posix import _open_absolute, observed_executable_digest


_HEX = re.compile(r"[0-9a-f]{64}\Z")
_GENERATED = {"INSTALLER", "REQUESTED", "RECORD", "direct_url.json", "uv_cache.json"}
_HOOKS = {"_virtualenv.py", "_virtualenv.pth"}
_LIMIT = 128 * 1024 * 1024
_CACHE = re.compile(r"(.+)\.cpython-(311|312)(?:\.opt-([12]))?\.pyc\Z")
_CACHE_CHECK = """import base64, hashlib, importlib.util, json, marshal, sys
if sys.implementation.cache_tag not in ('cpython-311', 'cpython-312'):
    raise SystemExit(2)
for item in json.load(sys.stdin):
    if item['tag'] != sys.implementation.cache_tag:
        raise SystemExit(2)
    cache = base64.b64decode(item['cache'], validate=True)
    source = base64.b64decode(item['source'], validate=True)
    if len(cache) < 16 or cache[:4] != importlib.util.MAGIC_NUMBER:
        raise SystemExit(2)
    if int.from_bytes(cache[4:8], 'little') not in (0, 1, 3):
        raise SystemExit(2)
    code = compile(source, item['filename'], 'exec', dont_inherit=True, optimize=item['optimize'])
    if cache[16:] != marshal.dumps(code):
        raise SystemExit(2)
print('verified')
"""


def _verify_caches(rows, python, expected_digest):
    if observed_executable_digest(str(python)) != expected_digest:
        raise ProjectRuntimeError("SOS_PROJECT_RUNTIME_INTERPRETER_MISMATCH")
    try:
        result = subprocess.run([str(python), "-I", "-S", "-B", "-c", _CACHE_CHECK],
            input=json.dumps(rows).encode(), stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            env={"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8"}, timeout=30, check=False)
    except (OSError, subprocess.TimeoutExpired):
        raise ProjectRuntimeError("SOS_PROJECT_RUNTIME_CACHE_INVALID") from None
    if result.returncode != 0 or result.stdout != b"verified\n":
        raise ProjectRuntimeError("SOS_PROJECT_RUNTIME_CACHE_INVALID")
    if observed_executable_digest(str(python)) != expected_digest:
        raise ProjectRuntimeError("SOS_PROJECT_RUNTIME_INTERPRETER_MISMATCH")


def _read(path: Path, limit: int = _LIMIT) -> bytes:
    try:
        with _open_absolute(path.parent, private=False) as parent:
            fd = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
            try:
                before = os.fstat(fd)
                if (not stat.S_ISREG(before.st_mode) or before.st_size > limit
                        or before.st_uid not in {0, os.geteuid()} or before.st_mode & 0o022):
                    raise ProjectRuntimeError("SOS_PROJECT_RUNTIME_INVENTORY_INVALID")
                data = bytearray()
                while len(data) <= limit:
                    block = os.read(fd, min(1024 * 1024, limit + 1 - len(data)))
                    if not block:
                        break
                    data.extend(block)
                after = os.fstat(fd)
                if (len(data) != before.st_size or
                        (before.st_size, before.st_mtime_ns, before.st_ctime_ns) !=
                        (after.st_size, after.st_mtime_ns, after.st_ctime_ns)):
                    raise ProjectRuntimeError("SOS_PROJECT_RUNTIME_INVENTORY_DRIFT")
                return bytes(data)
            finally:
                os.close(fd)
    except OSError:
        raise ProjectRuntimeError("SOS_PROJECT_RUNTIME_INVENTORY_INVALID") from None


def _hash(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _members(path: Path, expected_digest: str) -> tuple[dict[str, bytes], str, str, str]:
    raw = _read(path)
    if not isinstance(expected_digest, str) or not _HEX.fullmatch(expected_digest) or _hash(raw) != expected_digest:
        raise ProjectRuntimeError("SOS_PROJECT_RUNTIME_WHEEL_DIGEST_MISMATCH")
    files = {}
    seen = set()
    total = 0
    try:
        with zipfile.ZipFile(io.BytesIO(raw)) as archive:
            infos = archive.infolist()
            if not 1 <= len(infos) <= 10000:
                raise ValueError()
            for entry in infos:
                name = entry.filename
                parts = PurePosixPath(name).parts
                mode = entry.external_attr >> 16
                if (not parts or name.startswith("/") or "\\" in name or "\x00" in name
                        or any(p in {".", ".."} or p.endswith(".data") for p in parts)
                        or name.rstrip("/") != str(PurePosixPath(name))
                        or name in seen or stat.S_ISLNK(mode)
                        or (stat.S_IFMT(mode) not in {0, stat.S_IFREG, stat.S_IFDIR})):
                    raise ValueError()
                seen.add(name)
                if entry.is_dir():
                    continue
                total += entry.file_size
                if total > _LIMIT or entry.file_size > 32 * 1024 * 1024:
                    raise ValueError()
                files[name] = archive.read(entry)
    except (ValueError, OSError, zipfile.BadZipFile, RuntimeError):
        raise ProjectRuntimeError("SOS_PROJECT_RUNTIME_WHEEL_INVALID") from None
    metadata = [n for n in files if len(PurePosixPath(n).parts) == 2 and n.endswith(".dist-info/METADATA")]
    if len(metadata) != 1:
        raise ProjectRuntimeError("SOS_PROJECT_RUNTIME_WHEEL_INVALID")
    directory = metadata[0].split("/")[0]
    if any(directory + "/" + required not in files for required in ("WHEEL", "RECORD")):
        raise ProjectRuntimeError("SOS_PROJECT_RUNTIME_WHEEL_INVALID")
    message = BytesParser().parsebytes(files[metadata[0]])
    names, versions = message.get_all("Name", []), message.get_all("Version", [])
    if len(names) != 1 or len(versions) != 1 or not names[0] or not versions[0]:
        raise ProjectRuntimeError("SOS_PROJECT_RUNTIME_WHEEL_INVALID")
    name = re.sub(r"[-_.]+", "-", names[0]).lower()
    if not re.fullmatch(r"[a-z0-9][a-z0-9-]*", name) or not re.fullmatch(r"[A-Za-z0-9.+!-]+", versions[0]):
        raise ProjectRuntimeError("SOS_PROJECT_RUNTIME_WHEEL_INVALID")
    for member in files:
        if ".dist-info" in member.split("/")[0] and member.split("/")[0] != directory:
            raise ProjectRuntimeError("SOS_PROJECT_RUNTIME_WHEEL_INVALID")
    return files, directory, name, versions[0]


def checked_wheel_sources(wheels: tuple[tuple[Path, str], ...], expected_sos_version: str):
    """Read and admit release-bound wheel sources before any package-manager call."""
    if (not isinstance(wheels, tuple) or not 1 <= len(wheels) <= 16
            or any(not isinstance(row, tuple) or len(row) != 2 or not isinstance(row[0], Path)
                   for row in wheels)):
        raise ProjectRuntimeError("SOS_PROJECT_RUNTIME_INVENTORY_INVALID")
    expected = {}
    distributions = {}
    components = []
    total_size = 0
    for path, digest in wheels:
        files, directory, name, version = _members(path, digest)
        total_size += sum(len(payload) for payload in files.values())
        if total_size > _LIMIT or len(expected) + len(files) > 20000:
            raise ProjectRuntimeError("SOS_PROJECT_RUNTIME_INVENTORY_INVALID")
        if name in distributions or directory in distributions.values():
            raise ProjectRuntimeError("SOS_PROJECT_RUNTIME_INVENTORY_DUPLICATE")
        distributions[name] = directory
        components.append({"name": name, "version": version, "wheel_sha256": digest})
        for relative, payload in files.items():
            if relative in expected:
                raise ProjectRuntimeError("SOS_PROJECT_RUNTIME_INVENTORY_DUPLICATE")
            expected[relative] = _hash(payload)
    sos = [c for c in components if c["name"] == "sigma-operator-stack"]
    if len(sos) != 1 or sos[0]["version"] != expected_sos_version:
        raise ProjectRuntimeError("SOS_PROJECT_RUNTIME_VERSION_MISMATCH")
    return expected, distributions, components


def verify_installed_wheels(
    site_packages: Path, wheels: tuple[tuple[Path, str], ...], *,
    expected_sos_version: str, installer_hook_digests: dict[str, str] | None = None,
    cache_python: Path | None = None, cache_python_sha256: str | None = None,
) -> dict[str, object]:
    """Verify exact wheel payloads and a closed installed site-packages inventory.

    Does not execute Python, import installed packages, write files, download,
    confirm mutation or mark a generation ready. RECORD/install metadata may be
    rewritten by the installer; those files are non-executing and bounded.
    Unverified bytecode or other executable extras fail closed.
    """
    hooks = dict(installer_hook_digests or {})
    if ((cache_python is None) != (cache_python_sha256 is None)
            or (cache_python_sha256 is not None and not _HEX.fullmatch(cache_python_sha256))):
        raise ProjectRuntimeError("SOS_PROJECT_RUNTIME_INVENTORY_INVALID")
    if set(hooks) - _HOOKS or any(not isinstance(v, str) or not _HEX.fullmatch(v) for v in hooks.values()):
        raise ProjectRuntimeError("SOS_PROJECT_RUNTIME_INVENTORY_INVALID")
    expected, distributions, components = checked_wheel_sources(wheels, expected_sos_version)
    expected_directories = {str(parent) for name in expected
                            for parent in PurePosixPath(name).parents if str(parent) != "."}
    sources = {name: digest for name, digest in (expected | hooks).items() if name.endswith(".py")}
    if cache_python is not None:
        expected_directories.update(str(PurePosixPath(name).parent / "__pycache__") for name in sources)
    observed = {}
    cache_rows = []
    cache_bytes = 0
    entry_count = 0
    try:
        with _open_absolute(site_packages, private=False):
            for directory, children, files in os.walk(site_packages, followlinks=False):
                entry_count += len(children) + len(files)
                if entry_count > 20000:
                    raise ProjectRuntimeError("SOS_PROJECT_RUNTIME_INVENTORY_INVALID")
                for name in children:
                    target = Path(directory) / name
                    if target.is_symlink():
                        raise ProjectRuntimeError("SOS_PROJECT_RUNTIME_INVENTORY_INVALID")
                    if target.relative_to(site_packages).as_posix() not in expected_directories:
                        raise ProjectRuntimeError("SOS_PROJECT_RUNTIME_INVENTORY_EXTRA")
                for name in files:
                    target = Path(directory) / name
                    relative = target.relative_to(site_packages).as_posix()
                    parts = PurePosixPath(relative).parts
                    generated = len(parts) == 2 and parts[0] in distributions.values() and parts[1] in _GENERATED
                    payload = _read(target, 1024 * 1024 if generated else 32 * 1024 * 1024)
                    actual = _hash(payload)
                    if cache_python is not None and len(parts) >= 2 and parts[-2] == "__pycache__":
                        match = _CACHE.fullmatch(parts[-1])
                        source_name = str(PurePosixPath(*parts[:-2]) / (match[1] + ".py")) if match else ""
                        if source_name not in sources:
                            raise ProjectRuntimeError("SOS_PROJECT_RUNTIME_CACHE_INVALID")
                        source_path = site_packages / source_name
                        source = _read(source_path, 32 * 1024 * 1024)
                        if _hash(source) != sources[source_name]:
                            raise ProjectRuntimeError("SOS_PROJECT_RUNTIME_INSTALLED_FILE_MISMATCH")
                        cache_bytes += len(payload) + len(source)
                        if cache_bytes > _LIMIT:
                            raise ProjectRuntimeError("SOS_PROJECT_RUNTIME_CACHE_INVALID")
                        cache_rows.append({"filename": str(source_path),
                            "source": base64.b64encode(source).decode(),
                            "cache": base64.b64encode(payload).decode(), "tag": "cpython-" + match[2],
                            "optimize": int(match[3] or 0)})
                        continue
                    if relative in expected and not (generated and parts[1] == "RECORD"):
                        if actual != expected[relative]:
                            raise ProjectRuntimeError("SOS_PROJECT_RUNTIME_INSTALLED_FILE_MISMATCH")
                    elif relative in hooks:
                        if actual != hooks[relative]:
                            raise ProjectRuntimeError("SOS_PROJECT_RUNTIME_INSTALLER_HOOK_MISMATCH")
                    elif not generated:
                        raise ProjectRuntimeError("SOS_PROJECT_RUNTIME_INVENTORY_EXTRA")
                    observed[relative] = actual
    except OSError:
        raise ProjectRuntimeError("SOS_PROJECT_RUNTIME_INVENTORY_INVALID") from None
    if set(expected) - set(observed) or set(hooks) - set(observed):
        raise ProjectRuntimeError("SOS_PROJECT_RUNTIME_INVENTORY_MISSING")
    if cache_rows:
        _verify_caches(cache_rows, cache_python, cache_python_sha256)
    return {
        "contract": "sos_project_runtime_wheel_inventory_v1",
        "status": "passed", "component_count": len(components),
        "components": sorted(components, key=lambda c: c["name"]),
        "installed_inventory_digest": digest_value(observed),
        "wheel_inventory_digest": digest_value(sorted(components, key=lambda c: c["name"])),
        "runtime_ready": False, "network_performed": False,
        "raw_content_serialized": False, "absolute_paths_serialized": False,
    }
