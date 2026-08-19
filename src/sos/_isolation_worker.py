"""Linux-only worker for the closed SOS unittest qualification profile."""

from __future__ import annotations

import contextlib
import ctypes
import errno
import hashlib
import io
import json
import os
import platform
import resource
import sys
import tempfile
import unittest
from pathlib import Path


_REPORT_PREFIX = "SOS_ISOLATION_RESULT="
_LANDLOCK_CREATE_RULESET_VERSION = 1
_LANDLOCK_RULE_PATH_BENEATH = 1
_PR_SET_NO_NEW_PRIVS = 38
_SECCOMP_SET_MODE_FILTER = 1
_SECCOMP_RET_ALLOW = 0x7FFF0000
_SECCOMP_RET_ERRNO = 0x00050000
_AUDIT_ARCH_X86_64 = 0xC000003E
_BPF_LD_W_ABS = 0x20
_BPF_JMP_JEQ_K = 0x15
_BPF_RET_K = 0x06

_LL_EXECUTE = 1 << 0
_LL_WRITE_FILE = 1 << 1
_LL_READ_FILE = 1 << 2
_LL_READ_DIR = 1 << 3
_LL_REMOVE_DIR = 1 << 4
_LL_REMOVE_FILE = 1 << 5
_LL_MAKE_CHAR = 1 << 6
_LL_MAKE_DIR = 1 << 7
_LL_MAKE_REG = 1 << 8
_LL_MAKE_SOCK = 1 << 9
_LL_MAKE_FIFO = 1 << 10
_LL_MAKE_BLOCK = 1 << 11
_LL_MAKE_SYM = 1 << 12
_LL_REFER = 1 << 13
_LL_TRUNCATE = 1 << 14
_LL_ABI1 = (1 << 13) - 1

_DENIED_SYSCALLS_X86_64 = (
    41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 52, 53, 54, 55,
    56, 57, 58, 59, 101, 165, 166, 248, 249, 250, 272, 288, 298,
    308, 321, 322, 435,
)
_MAX_CAPTURED_OUTPUT_BYTES = 1024 * 1024


class _OutputLimitExceeded(RuntimeError):
    pass


class _BoundedTextSink(io.TextIOBase):
    def __init__(self) -> None:
        self.bytes_written = 0

    def writable(self) -> bool:
        return True

    def write(self, value: str) -> int:
        encoded = value.encode("utf-8", errors="replace")
        self.bytes_written += len(encoded)
        if self.bytes_written > _MAX_CAPTURED_OUTPUT_BYTES:
            raise _OutputLimitExceeded()
        return len(value)

    def flush(self) -> None:
        return None


class _RulesetAttr(ctypes.Structure):
    _fields_ = [("handled_access_fs", ctypes.c_uint64)]


class _PathBeneathAttr(ctypes.Structure):
    _fields_ = [("allowed_access", ctypes.c_uint64), ("parent_fd", ctypes.c_int32)]


class _SockFilter(ctypes.Structure):
    _fields_ = [
        ("code", ctypes.c_ushort),
        ("jt", ctypes.c_ubyte),
        ("jf", ctypes.c_ubyte),
        ("k", ctypes.c_uint32),
    ]


class _SockFprog(ctypes.Structure):
    _fields_ = [("length", ctypes.c_ushort), ("filter", ctypes.POINTER(_SockFilter))]


def _syscall(number: int, *arguments: object) -> int:
    libc = ctypes.CDLL(None, use_errno=True)
    libc.syscall.restype = ctypes.c_long
    result = int(libc.syscall(number, *arguments))
    if result < 0:
        error = ctypes.get_errno()
        raise OSError(error, os.strerror(error))
    return result


def _landlock_access(abi: int) -> int:
    access = _LL_ABI1
    if abi >= 2:
        access |= _LL_REFER
    if abi >= 3:
        access |= _LL_TRUNCATE
    return access


def _add_landlock_path(ruleset_fd: int, path: Path, access: int) -> None:
    if not path.exists():
        return
    descriptor = os.open(path, os.O_PATH | os.O_CLOEXEC)
    try:
        attribute = _PathBeneathAttr(access, descriptor)
        _syscall(445, ruleset_fd, _LANDLOCK_RULE_PATH_BENEATH, ctypes.byref(attribute), 0)
    finally:
        os.close(descriptor)


def _restrict_filesystem(source: Path, output: Path) -> int:
    abi = _syscall(444, 0, 0, _LANDLOCK_CREATE_RULESET_VERSION)
    if abi < 3:
        raise OSError(errno.ENOSYS, "Landlock ABI 3 is required")
    handled = _landlock_access(abi)
    ruleset_attr = _RulesetAttr(handled)
    ruleset_fd = _syscall(444, ctypes.byref(ruleset_attr), ctypes.sizeof(ruleset_attr), 0)
    try:
        read_execute = _LL_EXECUTE | _LL_READ_FILE | _LL_READ_DIR
        for system_root in (Path("/usr"), Path("/bin"), Path("/lib"), Path("/lib64")):
            _add_landlock_path(ruleset_fd, system_root, read_execute & handled)
        _add_landlock_path(ruleset_fd, Path("/etc/ld.so.cache"), _LL_READ_FILE & handled)
        _add_landlock_path(
            ruleset_fd,
            Path("/dev/null"),
            (_LL_READ_FILE | _LL_WRITE_FILE) & handled,
        )
        source_access = (_LL_READ_FILE | _LL_READ_DIR) & handled
        _add_landlock_path(ruleset_fd, source, source_access)
        output_access = handled & ~(
            _LL_EXECUTE | _LL_MAKE_CHAR | _LL_MAKE_SOCK | _LL_MAKE_BLOCK
        )
        _add_landlock_path(ruleset_fd, output, output_access)
        libc = ctypes.CDLL(None, use_errno=True)
        if libc.prctl(_PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0:
            error = ctypes.get_errno()
            raise OSError(error, os.strerror(error))
        _syscall(446, ruleset_fd, 0)
    finally:
        os.close(ruleset_fd)
    return abi


def _deny_network_process_and_namespace_syscalls() -> None:
    if platform.machine() != "x86_64":
        raise OSError(errno.ENOSYS, "unsupported architecture")
    instructions: list[_SockFilter] = [
        _SockFilter(_BPF_LD_W_ABS, 0, 0, 4),
        _SockFilter(_BPF_JMP_JEQ_K, 1, 0, _AUDIT_ARCH_X86_64),
        _SockFilter(_BPF_RET_K, 0, 0, _SECCOMP_RET_ERRNO | errno.EPERM),
        _SockFilter(_BPF_LD_W_ABS, 0, 0, 0),
    ]
    for syscall_number in _DENIED_SYSCALLS_X86_64:
        instructions.extend(
            (
                _SockFilter(_BPF_JMP_JEQ_K, 0, 1, syscall_number),
                _SockFilter(_BPF_RET_K, 0, 0, _SECCOMP_RET_ERRNO | errno.EPERM),
            )
        )
    instructions.append(_SockFilter(_BPF_RET_K, 0, 0, _SECCOMP_RET_ALLOW))
    array_type = _SockFilter * len(instructions)
    filters = array_type(*instructions)
    program = _SockFprog(len(instructions), filters)
    _syscall(317, _SECCOMP_SET_MODE_FILTER, 0, ctypes.byref(program))


def _apply_limits(output: Path) -> None:
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    resource.setrlimit(resource.RLIMIT_CPU, (20, 20))
    resource.setrlimit(resource.RLIMIT_AS, (512 * 1024 * 1024, 512 * 1024 * 1024))
    resource.setrlimit(resource.RLIMIT_FSIZE, (1024 * 1024, 1024 * 1024))
    resource.setrlimit(resource.RLIMIT_NOFILE, (64, 64))
    os.chdir(output)
    temporary = output / "tmp"
    temporary.mkdir(mode=0o700, exist_ok=True)
    tempfile.tempdir = os.fspath(temporary)
    sys.dont_write_bytecode = True


def _run_tests(source: Path) -> dict[str, object]:
    sys.path.insert(0, os.fspath(source))
    loader = unittest.TestLoader()
    suite = loader.discover(os.fspath(source / "tests"), pattern="test*.py")
    runner_output = _BoundedTextSink()
    with contextlib.redirect_stdout(runner_output), contextlib.redirect_stderr(runner_output):
        result = unittest.TextTestRunner(stream=runner_output, verbosity=0).run(suite)
    if result.testsRun == 0:
        status = "not_verified"
    elif result.skipped:
        status = "skipped"
    else:
        status = "passed_local" if result.wasSuccessful() else "failed"
    summary = {
        "contract": "sos_isolated_unittest_result_v1",
        "status": status,
        "tests_run": result.testsRun,
        "failures": len(result.failures),
        "errors": len(result.errors),
        "skipped": len(result.skipped),
        "raw_output_serialized": False,
    }
    return summary


def _seal(payload: dict[str, object]) -> dict[str, object]:
    result = dict(payload)
    result["result_digest"] = "sha256:" + hashlib.sha256(
        json.dumps(result, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    return result


def _emit(report_fd: int, payload: dict[str, object]) -> None:
    serialized = (_REPORT_PREFIX + json.dumps(payload, sort_keys=True, separators=(",", ":")) + "\n").encode()
    os.write(report_fd, serialized)


def main(argv: list[str] | None = None) -> int:
    arguments = sys.argv[1:] if argv is None else argv
    if len(arguments) != 1:
        return 64
    execution_root = Path(arguments[0]).resolve()
    source = execution_root / "source"
    output = execution_root / "output"
    if not source.is_dir() or not output.is_dir():
        return 64
    report_fd = os.dup(1)
    sink_path = output / ".sos-worker-output"
    sink_fd = os.open(sink_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    os.unlink(sink_path)
    os.dup2(sink_fd, 1)
    os.dup2(sink_fd, 2)
    os.close(sink_fd)
    try:
        _apply_limits(output)
        abi = _restrict_filesystem(source, output)
        _deny_network_process_and_namespace_syscalls()
        report = _run_tests(source)
        report["isolation_profile"] = "linux-landlock-seccomp-snapshot-v1"
        report["landlock_abi"] = abi
        _emit(report_fd, _seal(report))
        if report["status"] == "passed_local":
            return 0
        if report["status"] in {"skipped", "not_verified"}:
            return 2
        return 1
    except _OutputLimitExceeded:
        _emit(
            report_fd,
            _seal({
                "contract": "sos_isolated_unittest_result_v1",
                "status": "failed",
                "reason": "SOS_QUALIFICATION_OUTPUT_LIMIT_EXCEEDED",
                "isolation_profile": "linux-landlock-seccomp-snapshot-v1",
                "raw_output_serialized": False,
            }),
        )
        return 1
    except OSError as exc:
        if exc.errno == errno.EFBIG:
            _emit(
                report_fd,
                _seal({
                    "contract": "sos_isolated_unittest_result_v1",
                    "status": "failed",
                    "reason": "SOS_QUALIFICATION_OUTPUT_LIMIT_EXCEEDED",
                    "isolation_profile": "linux-landlock-seccomp-snapshot-v1",
                    "raw_output_serialized": False,
                }),
            )
            return 1
        _emit(
            report_fd,
            _seal({
                "contract": "sos_isolated_unittest_result_v1",
                "status": "unsupported",
                "reason": "SOS_ISOLATION_PROFILE_UNAVAILABLE",
                "isolation_profile": "linux-landlock-seccomp-snapshot-v1",
                "raw_output_serialized": False,
            }),
        )
        return 78
    except (ValueError, unittest.SkipTest):
        _emit(
            report_fd,
            _seal({
                "contract": "sos_isolated_unittest_result_v1",
                "status": "unsupported",
                "reason": "SOS_ISOLATION_PROFILE_UNAVAILABLE",
                "isolation_profile": "linux-landlock-seccomp-snapshot-v1",
                "raw_output_serialized": False,
            }),
        )
        return 78
    finally:
        os.close(report_fd)


if __name__ == "__main__":
    raise SystemExit(main())
