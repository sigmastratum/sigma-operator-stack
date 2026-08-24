"""Read-only host and filesystem admission for the Linux execution substrate."""

from __future__ import annotations

import os
import sys
from pathlib import Path

from .result import Status, TerminalResult


_MOUNTINFO = Path("/proc/self/mountinfo")
_MAX_MOUNTINFO_BYTES = 2 * 1024 * 1024
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
    observed = sys.platform if platform_name is None else platform_name
    if observed == "linux":
        return TerminalResult(
            "sos_host_admission_v1",
            Status.SUCCESS,
            ("SOS_LINUX_SUBSTRATE_ADMITTED",),
            _details(host_platform="linux"),
        )
    host = "windows" if observed.startswith("win") else "macos" if observed == "darwin" else "other"
    next_action = (
        "Install or open SOS through WSL2 with the project in the WSL native Linux filesystem."
        if host == "windows"
        else "Install or open SOS through the qualified Linux execution substrate."
    )
    return TerminalResult(
        "sos_host_admission_v1",
        Status.UNSUPPORTED,
        ("SOS_LINUX_SUBSTRATE_REQUIRED",),
        _details(host_platform=host, next_action=next_action),
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
        text = _read_mountinfo() if mountinfo_text is None else mountinfo_text
        filesystem_type = _filesystem_for_path(Path(path), text)
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


def _read_mountinfo() -> str:
    payload = _MOUNTINFO.read_bytes()
    if len(payload) > _MAX_MOUNTINFO_BYTES:
        raise ValueError("mount inventory limit exceeded")
    return payload.decode("utf-8", errors="strict")


def _filesystem_for_path(path: Path, mountinfo_text: str) -> str:
    target = path.resolve(strict=False)
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
        mount_point = Path(_unescape_mount_field(left_fields[4])).resolve(strict=False)
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
