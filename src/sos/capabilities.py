"""Content-safe isolation capability discovery with no repository access."""

from __future__ import annotations

import hashlib
import json
import os
import platform
import re
import selectors
import subprocess
import sys
import time
from dataclasses import asdict, dataclass
from functools import lru_cache
from pathlib import Path


PROFILE_ID = "linux-landlock-seccomp-snapshot-v1"
REPORT_CONTRACT = "sos_isolation_capability_report_v1"
_COMPONENT_PREFIX = b"SOS_CAPABILITY_COMPONENT="
_MAX_COMPONENT_OUTPUT = 16 * 1024
_PROBE_TIMEOUT_SECONDS = 5
_SAFE_PLATFORM_VALUE = re.compile(r"^[A-Za-z0-9._+:-]{1,128}$")

PLATFORM_UNSUPPORTED = "SOS_CAPABILITY_PLATFORM_UNSUPPORTED"
LANDLOCK_SYSCALL_UNAVAILABLE = "SOS_LANDLOCK_SYSCALL_UNAVAILABLE"
LANDLOCK_ABI_TOO_OLD = "SOS_LANDLOCK_ABI_TOO_OLD"
NO_NEW_PRIVS_UNAVAILABLE = "SOS_NO_NEW_PRIVS_UNAVAILABLE"
SECCOMP_FILTER_UNAVAILABLE = "SOS_SECCOMP_FILTER_UNAVAILABLE"
PROFILE_AVAILABLE = "SOS_ISOLATION_PROFILE_AVAILABLE"

_REASON_PRECEDENCE = (
    PLATFORM_UNSUPPORTED,
    LANDLOCK_SYSCALL_UNAVAILABLE,
    LANDLOCK_ABI_TOO_OLD,
    NO_NEW_PRIVS_UNAVAILABLE,
    SECCOMP_FILTER_UNAVAILABLE,
)


@dataclass(frozen=True, slots=True)
class CapabilityComponent:
    status: str
    observed_abi: int | None = None


@dataclass(frozen=True, slots=True)
class _BoundedProcessResult:
    returncode: int
    stdout: bytes
    stderr: bytes


class _BoundedOutputExceeded(subprocess.SubprocessError):
    pass


@dataclass(frozen=True, slots=True)
class IsolationCapabilityReport:
    contract: str
    status: str
    profile_id: str
    system: str
    architecture: str
    kernel_release: str
    required_landlock_abi: int
    landlock: CapabilityComponent
    no_new_privs: CapabilityComponent
    seccomp: CapabilityComponent
    reasons: tuple[str, ...]
    report_digest: str

    def to_dict(self) -> dict[str, object]:
        value = asdict(self)
        value["reasons"] = list(self.reasons)
        return value


@lru_cache(maxsize=1)
def probe_isolation_capabilities() -> IsolationCapabilityReport:
    """Probe only kernel security capabilities; never inspect a repository."""
    system = _safe_platform_value(platform.system().lower())
    architecture = _safe_platform_value(platform.machine())
    kernel_release = _safe_platform_value(platform.release())
    failures: list[str] = []
    if system != "linux" or architecture != "x86_64":
        failures.append(PLATFORM_UNSUPPORTED)
        unavailable = CapabilityComponent(status="unsupported")
        return _seal_report(
            system=system,
            architecture=architecture,
            kernel_release=kernel_release,
            landlock=unavailable,
            no_new_privs=unavailable,
            seccomp=unavailable,
            failures=failures,
        )

    landlock_result = _run_component("landlock")
    no_new_privs_result = _run_component("no_new_privs")
    seccomp_result = _run_component("seccomp")
    components = (landlock_result, no_new_privs_result, seccomp_result)
    for reason in _REASON_PRECEDENCE:
        if any(item.get("reason") == reason for item in components):
            failures.append(reason)
    landlock = CapabilityComponent(
        status=str(landlock_result["status"]),
        observed_abi=landlock_result.get("observed_abi"),
    )
    return _seal_report(
        system=system,
        architecture=architecture,
        kernel_release=kernel_release,
        landlock=landlock,
        no_new_privs=CapabilityComponent(status=str(no_new_privs_result["status"])),
        seccomp=CapabilityComponent(status=str(seccomp_result["status"])),
        failures=failures,
    )


def clear_capability_cache() -> None:
    probe_isolation_capabilities.cache_clear()


def _run_component(component: str) -> dict[str, object]:
    worker = Path(__file__).with_name("_isolation_worker.py")
    command = [sys.executable, "-I", os.fspath(worker), "--probe", component]
    try:
        completed = _run_bounded_process(
            command,
            env={
                "HOME": "/nonexistent",
                "LANG": "C.UTF-8",
                "LC_ALL": "C.UTF-8",
                "PATH": "/usr/bin:/bin",
                "PYTHONDONTWRITEBYTECODE": "1",
                "PYTHONHASHSEED": "0",
            },
        )
    except (OSError, subprocess.SubprocessError):
        return _component_failure(component)
    if len(completed.stdout) > _MAX_COMPONENT_OUTPUT or completed.stderr:
        return _component_failure(component)
    line = next(
        (item for item in completed.stdout.splitlines() if item.startswith(_COMPONENT_PREFIX)),
        None,
    )
    if line is None:
        return _component_failure(component)
    try:
        result = json.loads(line[len(_COMPONENT_PREFIX) :])
    except (json.JSONDecodeError, UnicodeDecodeError):
        return _component_failure(component)
    if not isinstance(result, dict) or result.get("component") != component:
        return _component_failure(component)
    status = result.get("status")
    reason = result.get("reason")
    expected_reason = {
        "landlock": {None, LANDLOCK_SYSCALL_UNAVAILABLE, LANDLOCK_ABI_TOO_OLD},
        "no_new_privs": {None, NO_NEW_PRIVS_UNAVAILABLE},
        "seccomp": {None, SECCOMP_FILTER_UNAVAILABLE},
    }[component]
    if status not in {"supported", "unsupported"} or reason not in expected_reason:
        return _component_failure(component)
    if (status == "supported") != (reason is None):
        return _component_failure(component)
    expected_exit = 0 if status == "supported" else 78
    if completed.returncode != expected_exit:
        return _component_failure(component)
    observed_abi = result.get("observed_abi")
    if observed_abi is not None and (not isinstance(observed_abi, int) or observed_abi < 0):
        return _component_failure(component)
    return {
        "status": status,
        "reason": reason,
        "observed_abi": observed_abi,
    }


def _run_bounded_process(
    command: list[str],
    *,
    env: dict[str, str],
) -> _BoundedProcessResult:
    """Capture at most the declared aggregate output while the child runs."""
    process = subprocess.Popen(
        command,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=env,
        shell=False,
    )
    if process.stdout is None or process.stderr is None:  # pragma: no cover
        process.kill()
        process.wait()
        raise subprocess.SubprocessError("capability probe pipes unavailable")
    selector = selectors.DefaultSelector()
    streams = {process.stdout: bytearray(), process.stderr: bytearray()}
    selector.register(process.stdout, selectors.EVENT_READ)
    selector.register(process.stderr, selectors.EVENT_READ)
    deadline = time.monotonic() + _PROBE_TIMEOUT_SECONDS
    try:
        while selector.get_map():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise subprocess.TimeoutExpired(command, _PROBE_TIMEOUT_SECONDS)
            events = selector.select(remaining)
            if not events:
                raise subprocess.TimeoutExpired(command, _PROBE_TIMEOUT_SECONDS)
            for key, _ in events:
                stream = key.fileobj
                captured = sum(len(value) for value in streams.values())
                chunk = os.read(
                    stream.fileno(),
                    min(4096, _MAX_COMPONENT_OUTPUT - captured + 1),
                )
                if not chunk:
                    selector.unregister(stream)
                    continue
                streams[stream].extend(chunk)
                if sum(len(value) for value in streams.values()) > _MAX_COMPONENT_OUTPUT:
                    raise _BoundedOutputExceeded("capability probe output exceeded limit")
        remaining = max(0.0, deadline - time.monotonic())
        returncode = process.wait(timeout=remaining)
    except (subprocess.SubprocessError, OSError):
        process.kill()
        process.wait()
        raise
    finally:
        selector.close()
        process.stdout.close()
        process.stderr.close()
    return _BoundedProcessResult(
        returncode=returncode,
        stdout=bytes(streams[process.stdout]),
        stderr=bytes(streams[process.stderr]),
    )


def _component_failure(component: str) -> dict[str, object]:
    reason = {
        "landlock": LANDLOCK_SYSCALL_UNAVAILABLE,
        "no_new_privs": NO_NEW_PRIVS_UNAVAILABLE,
        "seccomp": SECCOMP_FILTER_UNAVAILABLE,
    }[component]
    return {"status": "unsupported", "reason": reason, "observed_abi": None}


def _seal_report(
    *,
    system: str,
    architecture: str,
    kernel_release: str,
    landlock: CapabilityComponent,
    no_new_privs: CapabilityComponent,
    seccomp: CapabilityComponent,
    failures: list[str],
) -> IsolationCapabilityReport:
    reasons = tuple(failures) if failures else (PROFILE_AVAILABLE,)
    status = "unsupported" if failures else "supported"
    material = {
        "contract": REPORT_CONTRACT,
        "status": status,
        "profile_id": PROFILE_ID,
        "system": system,
        "architecture": architecture,
        "kernel_release": kernel_release,
        "required_landlock_abi": 3,
        "landlock": asdict(landlock),
        "no_new_privs": asdict(no_new_privs),
        "seccomp": asdict(seccomp),
        "reasons": list(reasons),
    }
    digest = "sha256:" + hashlib.sha256(
        json.dumps(material, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    return IsolationCapabilityReport(
        contract=REPORT_CONTRACT,
        status=status,
        profile_id=PROFILE_ID,
        system=system,
        architecture=architecture,
        kernel_release=kernel_release,
        required_landlock_abi=3,
        landlock=landlock,
        no_new_privs=no_new_privs,
        seccomp=seccomp,
        reasons=reasons,
        report_digest=digest,
    )


def _safe_platform_value(value: str) -> str:
    return value if _SAFE_PLATFORM_VALUE.fullmatch(value) else "unknown"
