"""Bounded parent-side runner for the Linux Landlock/seccomp profile."""

from __future__ import annotations

import hashlib
import json
import os
import platform
import signal
import stat
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path, PurePosixPath

from .dirty import observe_application, sensitive_path_class
from .repository import RepositoryError, RepositoryInspection, inspect_repository


PROFILE_ID = "linux-landlock-seccomp-snapshot-v1"
_REPORT_PREFIX = b"SOS_ISOLATION_RESULT="
_MAX_FILES = 5000
_MAX_FILE_BYTES = 2 * 1024 * 1024
_MAX_TOTAL_BYTES = 16 * 1024 * 1024
_MAX_OUTPUT_BYTES = 1024 * 1024
_MAX_WRITABLE_BYTES = 16 * 1024 * 1024
_MAX_WRITABLE_ENTRIES = 4096
_TIMEOUT_SECONDS = 30


@dataclass(frozen=True, slots=True)
class IsolatedRun:
    status: str
    reasons: tuple[str, ...]
    exit_code: int | None
    output_digest: str | None
    output_bytes: int
    tests_run: int
    failures: int
    errors: int
    skipped: int


@dataclass(frozen=True, slots=True)
class _AdmittedSourceBinding:
    repository_id: str
    source_tree_digest: str
    source_status_digest: str
    fingerprint_head: str
    exclusion_policy_ref: str
    application_fingerprint: str


def profile_declared_available() -> bool:
    """Return a zero-execution platform declaration; runtime still probes fail-closed."""
    return sys.platform == "linux" and platform.machine() == "x86_64"


def run_isolated_unittest(
    root: Path,
    tracked_paths: tuple[str, ...],
    *,
    timeout_seconds: int = _TIMEOUT_SECONDS,
) -> IsolatedRun:
    """Run the public check path, which never admits dirty source."""
    return _run_isolated_unittest(
        root,
        tracked_paths,
        timeout_seconds=timeout_seconds,
        admitted_source_binding=None,
    )


def _run_admitted_isolated_unittest(
    root: Path,
    tracked_paths: tuple[str, ...],
    admitted_source_binding: _AdmittedSourceBinding,
    *,
    timeout_seconds: int = _TIMEOUT_SECONDS,
) -> IsolatedRun:
    """Run only after workspace admission and exclusive claim consumption."""
    return _run_isolated_unittest(
        root,
        tracked_paths,
        timeout_seconds=timeout_seconds,
        admitted_source_binding=admitted_source_binding,
    )


def _run_isolated_unittest(
    root: Path,
    tracked_paths: tuple[str, ...],
    *,
    timeout_seconds: int,
    admitted_source_binding: _AdmittedSourceBinding | None,
) -> IsolatedRun:
    before = inspect_repository(root)
    if admitted_source_binding is None and before.application_state != "clean":
        return _result("blocked", "SOS_QUALIFICATION_DIRTY_SOURCE")
    if admitted_source_binding is not None and not _source_binding_current(
        root, before, admitted_source_binding
    ):
        return _result("stale", "SOS_QUALIFICATION_SOURCE_CHANGED")
    with tempfile.TemporaryDirectory(prefix="sos-qualify-") as temporary:
        disposable = Path(temporary) / "execution"
        source = disposable / "source"
        output = disposable / "output"
        source.mkdir(mode=0o700, parents=True)
        output.mkdir(mode=0o700)
        try:
            _copy_snapshot(root, source, tracked_paths)
        except RepositoryError as exc:
            return _result("blocked", exc.reason)
        after_copy = inspect_repository(root)
        if _source_changed(before, after_copy) or (
            admitted_source_binding is not None
            and not _source_binding_current(root, after_copy, admitted_source_binding)
        ):
            return _result("stale", "SOS_QUALIFICATION_SOURCE_CHANGED")
        worker = Path(__file__).with_name("_isolation_worker.py")
        command = [sys.executable, "-I", os.fspath(worker), os.fspath(disposable)]
        environment = {
            "HOME": os.fspath(output / "home"),
            "LANG": "C.UTF-8",
            "LC_ALL": "C.UTF-8",
            "PATH": "/usr/bin:/bin",
            "PYTHONDONTWRITEBYTECODE": "1",
            "PYTHONHASHSEED": "0",
            "TMPDIR": os.fspath(output / "tmp"),
        }
        (output / "home").mkdir(mode=0o700)
        output_path = Path(temporary) / "worker.stdout"
        error_path = Path(temporary) / "worker.stderr"
        timed_out = False
        writable_limit_exceeded = False
        with output_path.open("wb") as stdout, error_path.open("wb") as stderr:
            process = subprocess.Popen(
                command,
                cwd=disposable,
                env=environment,
                stdin=subprocess.DEVNULL,
                stdout=stdout,
                stderr=stderr,
                close_fds=True,
                start_new_session=True,
                shell=False,
            )
            deadline = time.monotonic() + timeout_seconds
            while process.poll() is None:
                if time.monotonic() >= deadline:
                    timed_out = True
                    os.killpg(process.pid, signal.SIGKILL)
                    break
                if _writable_budget_exceeded(output):
                    writable_limit_exceeded = True
                    os.killpg(process.pid, signal.SIGKILL)
                    break
                time.sleep(0.02)
            exit_code = process.wait(timeout=5)
            if not timed_out and not writable_limit_exceeded:
                writable_limit_exceeded = _writable_budget_exceeded(output)
        after_run = inspect_repository(root)
        if _source_changed(before, after_run) or (
            admitted_source_binding is not None
            and not _source_binding_current(root, after_run, admitted_source_binding)
        ):
            return _result("stale", "SOS_QUALIFICATION_SOURCE_CHANGED", exit_code=exit_code)
        output_size = output_path.stat().st_size + error_path.stat().st_size
        if output_size > _MAX_OUTPUT_BYTES:
            return _result(
                "failed",
                "SOS_QUALIFICATION_OUTPUT_LIMIT_EXCEEDED",
                exit_code=exit_code,
                output_bytes=output_size,
            )
        captured = output_path.read_bytes() + error_path.read_bytes()
        output_digest = "sha256:" + hashlib.sha256(captured).hexdigest()
        if writable_limit_exceeded:
            return _result(
                "failed",
                "SOS_QUALIFICATION_WRITABLE_LIMIT_EXCEEDED",
                exit_code=exit_code,
                output_digest=output_digest,
                output_bytes=output_size,
            )
        if timed_out:
            return _result(
                "failed",
                "SOS_QUALIFICATION_TIMEOUT",
                exit_code=exit_code,
                output_digest=output_digest,
                output_bytes=output_size,
            )
        if exit_code == -signal.SIGXFSZ:
            return _result(
                "failed",
                "SOS_QUALIFICATION_OUTPUT_LIMIT_EXCEEDED",
                exit_code=exit_code,
                output_digest=output_digest,
                output_bytes=output_size,
            )
        report = _parse_report(output_path.read_bytes())
        if report is None:
            return _result(
                "failed",
                "SOS_QUALIFICATION_RUNNER_FAILED",
                exit_code=exit_code,
                output_digest=output_digest,
                output_bytes=output_size,
            )
        if report.get("status") == "unsupported" and exit_code == 78:
            return _result(
                "unsupported",
                "SOS_ISOLATION_PROFILE_UNAVAILABLE",
                exit_code=exit_code,
                output_digest=output_digest,
                output_bytes=output_size,
            )
        reported_status = report.get("status")
        if reported_status == "passed_local" and exit_code == 0:
            status = "passed_local"
            reason = "SOS_QUALIFICATION_PASSED"
        elif reported_status == "skipped" and exit_code == 2:
            status = "skipped"
            reason = "SOS_QUALIFICATION_SKIPPED"
        elif reported_status == "not_verified" and exit_code == 2:
            status = "not_verified"
            reason = "SOS_QUALIFICATION_NO_TESTS"
        elif (
            reported_status == "failed"
            and report.get("reason") == "SOS_QUALIFICATION_OUTPUT_LIMIT_EXCEEDED"
        ):
            status = "failed"
            reason = "SOS_QUALIFICATION_OUTPUT_LIMIT_EXCEEDED"
        else:
            status = "failed"
            reason = "SOS_QUALIFICATION_FAILED"
        return IsolatedRun(
            status=status,
            reasons=(reason,),
            exit_code=exit_code,
            output_digest=output_digest,
            output_bytes=output_size,
            tests_run=_bounded_count(report.get("tests_run")),
            failures=_bounded_count(report.get("failures")),
            errors=_bounded_count(report.get("errors")),
            skipped=_bounded_count(report.get("skipped")),
        )


def isolation_limits() -> dict[str, int]:
    return {
        "tracked_files": _MAX_FILES,
        "tracked_bytes": _MAX_TOTAL_BYTES,
        "source_file_bytes": _MAX_FILE_BYTES,
        "timeout_seconds": _TIMEOUT_SECONDS,
        "output_bytes": _MAX_OUTPUT_BYTES,
        "processes": 1,
        "cpu_seconds": 20,
        "address_space_bytes": 512 * 1024 * 1024,
        "open_files": 64,
        "file_write_bytes": 1024 * 1024,
        "writable_bytes": _MAX_WRITABLE_BYTES,
        "writable_entries": _MAX_WRITABLE_ENTRIES,
    }


def _copy_snapshot(root: Path, destination: Path, tracked_paths: tuple[str, ...]) -> None:
    if len(tracked_paths) > _MAX_FILES:
        raise RepositoryError("SOS_FILE_COUNT_LIMIT_EXCEEDED")
    total = 0
    for relative in tracked_paths:
        if sensitive_path_class(relative) is not None:
            raise RepositoryError("SOS_QUALIFICATION_PROTECTED_PATH_PRESENT")
        pure = PurePosixPath(relative)
        if pure.is_absolute() or not pure.parts or any(part in {"", ".", ".."} for part in pure.parts):
            raise RepositoryError("SOS_GIT_PATH_INVALID")
        try:
            descriptor, before = _open_regular_beneath(root, pure.parts)
        except OSError as exc:
            raise RepositoryError("SOS_TRACKED_FILE_UNAVAILABLE") from exc
        if not stat.S_ISREG(before.st_mode):
            os.close(descriptor)
            raise RepositoryError("SOS_TRACKED_FILE_TYPE_UNSUPPORTED")
        if before.st_size > _MAX_FILE_BYTES:
            os.close(descriptor)
            raise RepositoryError("SOS_SOURCE_FILE_BYTES_LIMIT_EXCEEDED")
        try:
            opened = os.fstat(descriptor)
            if _signature(opened) != _signature(before):
                raise RepositoryError("SOS_QUALIFICATION_SNAPSHOT_RACE")
            chunks: list[bytes] = []
            size = 0
            while True:
                chunk = os.read(descriptor, min(1024 * 1024, _MAX_FILE_BYTES + 1 - size))
                if not chunk:
                    break
                chunks.append(chunk)
                size += len(chunk)
                if size > _MAX_FILE_BYTES:
                    raise RepositoryError("SOS_SOURCE_FILE_BYTES_LIMIT_EXCEEDED")
            if _signature(os.fstat(descriptor)) != _signature(before):
                raise RepositoryError("SOS_QUALIFICATION_SNAPSHOT_RACE")
        finally:
            os.close(descriptor)
        total += size
        if total > _MAX_TOTAL_BYTES:
            raise RepositoryError("SOS_TRACKED_BYTES_LIMIT_EXCEEDED")
        target = destination.joinpath(*pure.parts)
        target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        with target.open("xb") as stream:
            for chunk in chunks:
                stream.write(chunk)
        target.chmod(0o500 if before.st_mode & stat.S_IXUSR else 0o400)


def _parse_report(payload: bytes) -> dict[str, object] | None:
    lines = [line for line in payload.splitlines() if line.startswith(_REPORT_PREFIX)]
    if len(lines) != 1:
        return None
    try:
        value = json.loads(lines[0][len(_REPORT_PREFIX) :].decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError):
        return None
    if not isinstance(value, dict) or value.get("contract") != "sos_isolated_unittest_result_v1":
        return None
    digest = value.get("result_digest")
    if not isinstance(digest, str):
        return None
    material = dict(value)
    material.pop("result_digest", None)
    expected_digest = "sha256:" + hashlib.sha256(
        json.dumps(material, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    if digest != expected_digest or value.get("raw_output_serialized") is not False:
        return None
    if value.get("isolation_profile") != PROFILE_ID:
        return None
    status = value.get("status")
    if status in {"unsupported"} or (
        status == "failed" and "reason" in value
    ):
        if set(value) != {
            "contract",
            "status",
            "reason",
            "isolation_profile",
            "raw_output_serialized",
            "result_digest",
        }:
            return None
        return value
    if set(value) != {
        "contract",
        "status",
        "tests_run",
        "failures",
        "errors",
        "skipped",
        "raw_output_serialized",
        "isolation_profile",
        "landlock_abi",
        "result_digest",
    }:
        return None
    counts = tuple(value.get(key) for key in ("tests_run", "failures", "errors", "skipped"))
    if any(not isinstance(item, int) or isinstance(item, bool) or item < 0 for item in counts):
        return None
    tests_run, failures, errors, skipped = counts
    if not isinstance(value.get("landlock_abi"), int) or value["landlock_abi"] < 3:
        return None
    if status == "passed_local" and not (tests_run > 0 and failures == errors == skipped == 0):
        return None
    if status == "skipped" and not (tests_run > 0 and skipped > 0):
        return None
    if status == "not_verified" and tests_run != 0:
        return None
    if status == "failed" and failures + errors == 0:
        return None
    if status not in {"passed_local", "skipped", "not_verified", "failed"}:
        return None
    return value


def _writable_budget_exceeded(root: Path) -> bool:
    entries = 0
    total = 0
    pending = [root]
    try:
        while pending:
            directory = pending.pop()
            with os.scandir(directory) as iterator:
                for entry in iterator:
                    entries += 1
                    if entries > _MAX_WRITABLE_ENTRIES:
                        return True
                    value = entry.stat(follow_symlinks=False)
                    if stat.S_ISDIR(value.st_mode):
                        pending.append(Path(entry.path))
                    elif stat.S_ISREG(value.st_mode):
                        total += value.st_size
                        if total > _MAX_WRITABLE_BYTES:
                            return True
    except OSError:
        return True
    return False


def _source_changed(before: object, after: object) -> bool:
    return (
        before.application_tree_digest != after.application_tree_digest
        or before.application_status_digest != after.application_status_digest
    )


def _source_binding_current(
    root: Path,
    inspection: RepositoryInspection,
    binding: _AdmittedSourceBinding,
) -> bool:
    if (
        inspection.application_tree_digest != binding.source_tree_digest
        or inspection.application_status_digest != binding.source_status_digest
    ):
        return False
    observed = observe_application(
        root,
        binding.repository_id,
        binding.fingerprint_head,
        binding.exclusion_policy_ref,
    )
    return (
        observed.complete
        and observed.fingerprint == binding.application_fingerprint
    )


def _signature(value: os.stat_result) -> tuple[int, int, int, int, int]:
    return (value.st_dev, value.st_ino, value.st_mode, value.st_size, value.st_mtime_ns)


def _open_regular_beneath(root: Path, parts: tuple[str, ...]) -> tuple[int, os.stat_result]:
    directory = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        for component in parts[:-1]:
            next_directory = os.open(
                component,
                os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
                dir_fd=directory,
            )
            os.close(directory)
            directory = next_directory
        before = os.stat(parts[-1], dir_fd=directory, follow_symlinks=False)
        if not stat.S_ISREG(before.st_mode):
            raise RepositoryError("SOS_TRACKED_FILE_TYPE_UNSUPPORTED")
        descriptor = os.open(
            parts[-1],
            os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW,
            dir_fd=directory,
        )
        return descriptor, before
    finally:
        os.close(directory)


def _bounded_count(value: object) -> int:
    return value if isinstance(value, int) and not isinstance(value, bool) and 0 <= value <= 1_000_000 else 0


def _result(
    status: str,
    reason: str,
    *,
    exit_code: int | None = None,
    output_digest: str | None = None,
    output_bytes: int = 0,
) -> IsolatedRun:
    return IsolatedRun(status, (reason,), exit_code, output_digest, output_bytes, 0, 0, 0, 0)
