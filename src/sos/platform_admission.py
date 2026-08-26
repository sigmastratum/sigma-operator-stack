"""Read-only host and filesystem admission for the Linux execution substrate."""

from __future__ import annotations

import os
from pathlib import Path, PurePosixPath

from .platforms import process_platform_name
from .platform_services import current_platform_services
from .result import Status, TerminalResult


_MAX_MOUNTS = 8192
_ADMITTED_FILESYSTEMS = frozenset({"ext2", "ext3", "ext4", "xfs", "btrfs"})
_KNOWN_UNSUPPORTED_FILESYSTEMS = frozenset(
    {
        "9p",
        "cifs",
        "drvfs",
        "exfat",
        "fuse",
        "fuseblk",
        "fuse.grpcfuse",
        "fuse.portal",
        "hgfs",
        "msdos",
        "nfs",
        "nfs4",
        "ntfs",
        "ntfs3",
        "overlay",
        "smb3",
        "vboxsf",
        "vfat",
        "virtiofs",
    }
)


def admit_host(*, platform_name: str | None = None) -> TerminalResult:
    observed = process_platform_name(platform_name)
    if observed == "linux":
        return TerminalResult(
            "sos_host_admission_v2",
            Status.SUCCESS,
            ("SOS_LINUX_SUBSTRATE_ADMITTED",),
            _details(host_platform="linux"),
        )
    host = "windows" if observed.startswith("win") else "macos" if observed == "darwin" else "other"
    if host == "windows":
        reason = "SOS_WINDOWS_NATIVE_SUPPORT_UNDER_DEVELOPMENT"
        support_status = "under_development"
        next_action = "Use a qualified native Linux x86_64 runner for this alpha."
    elif host == "macos":
        reason = "SOS_MACOS_DEMAND_GATED"
        support_status = "demand_gated"
        next_action = "Use a qualified native Linux x86_64 runner for this alpha."
    else:
        reason = "SOS_LINUX_SUBSTRATE_REQUIRED"
        support_status = "unsupported"
        next_action = "Use a qualified native Linux x86_64 runner."
    return TerminalResult(
        "sos_host_admission_v2",
        Status.UNSUPPORTED,
        (reason,),
        _details(
            host_platform=host,
            native_support_status=support_status,
            next_action=next_action,
        ),
    )


def admit_project_filesystem(
    path: str | os.PathLike[str],
    *,
    platform_name: str | None = None,
    mountinfo_text: str | None = None,
) -> TerminalResult:
    host = admit_host(platform_name=platform_name)
    if host.status != Status.SUCCESS:
        return TerminalResult(
            "sos_filesystem_admission_v1", host.status, host.reasons, host.details
        )
    try:
        if mountinfo_text is None:
            report = current_platform_services().inspect_host(Path(path))
            filesystem_type = str(report.get("filesystem_type", "unknown"))
            if report.get("filesystem_observation_status") != "observed":
                raise ValueError("filesystem observation unavailable")
        else:
            filesystem_type = _filesystem_for_path(PurePosixPath(path), mountinfo_text)
    except (OSError, UnicodeError, ValueError):
        return TerminalResult(
            "sos_filesystem_admission_v1",
            Status.NOT_VERIFIED,
            ("SOS_FILESYSTEM_PROFILE_NOT_VERIFIED",),
            _details(filesystem_profile="unknown"),
        )
    if filesystem_type in _ADMITTED_FILESYSTEMS:
        return TerminalResult(
            "sos_filesystem_admission_v1",
            Status.SUCCESS,
            ("SOS_FILESYSTEM_PROFILE_ADMITTED",),
            _details(
                filesystem_profile="native_linux",
                filesystem_type=filesystem_type,
            ),
        )
    reason = (
        "SOS_FILESYSTEM_PROFILE_UNSUPPORTED"
        if filesystem_type in _KNOWN_UNSUPPORTED_FILESYSTEMS
        or filesystem_type.startswith("fuse.")
        else "SOS_FILESYSTEM_PROFILE_NOT_VERIFIED"
    )
    status = Status.UNSUPPORTED if reason.endswith("UNSUPPORTED") else Status.NOT_VERIFIED
    return TerminalResult(
        "sos_filesystem_admission_v1",
        status,
        (reason,),
        _details(filesystem_profile="unsupported_or_unknown", filesystem_type=filesystem_type),
    )


def require_project_filesystem(path: str | os.PathLike[str]) -> None:
    admission = admit_project_filesystem(path)
    if admission.status != Status.SUCCESS:
        raise FilesystemAdmissionError(admission)


class FilesystemAdmissionError(RuntimeError):
    def __init__(self, result: TerminalResult) -> None:
        super().__init__(result.reasons[0])
        self.result = result
        self.reason = result.reasons[0]
        self.status = result.status
        self.details = result.details


def _filesystem_for_path(path: PurePosixPath, mountinfo_text: str) -> str:
    target = path
    best: tuple[int, str] | None = None
    lines = mountinfo_text.splitlines()
    if not lines or len(lines) > _MAX_MOUNTS:
        raise ValueError("mount inventory invalid")
    for line in lines:
        left, separator, right = line.partition(" - ")
        if not separator:
            raise ValueError("mount record invalid")
        left_fields = left.split()
        right_fields = right.split()
        if len(left_fields) < 6 or len(right_fields) < 3:
            raise ValueError("mount record invalid")
        mount_point = PurePosixPath(_unescape_mount_field(left_fields[4]))
        try:
            target.relative_to(mount_point)
        except ValueError:
            continue
        candidate = (len(mount_point.parts), right_fields[0].lower())
        if best is None or candidate[0] > best[0]:
            best = candidate
    if best is None:
        raise ValueError("mount not found")
    return best[1]


def _unescape_mount_field(value: str) -> str:
    escapes = {"040": " ", "011": "\t", "012": "\n", "134": "\\"}
    decoded: list[str] = []
    cursor = 0
    while cursor < len(value):
        escape = value.find("\\", cursor)
        if escape < 0:
            decoded.append(value[cursor:])
            break
        decoded.append(value[cursor:escape])
        code = value[escape + 1 : escape + 4]
        if len(code) != 3 or code not in escapes:
            raise ValueError("mount field escape invalid")
        decoded.append(escapes[code])
        cursor = escape + 4
    return "".join(decoded)


def _details(**values: object) -> dict[str, object]:
    return {
        "execution_substrate": "linux",
        "canonical_state_location": "native_linux_filesystem_required",
        "raw_project_content_serialized": False,
        "absolute_paths_serialized": False,
        "network_performed": False,
        **values,
    }
