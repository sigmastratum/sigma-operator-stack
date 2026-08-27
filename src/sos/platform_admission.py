"""Read-only host and filesystem admission for supported control planes."""

from __future__ import annotations

import os
from pathlib import Path, PurePosixPath

from .platforms import process_platform_name
from .platform_services import PlatformServiceError, PlatformServices, current_platform_services
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
    if observed == "win32":
        return TerminalResult(
            "sos_host_admission_v2",
            Status.SUCCESS,
            ("SOS_WINDOWS_CONTROL_PLANE_ADMITTED",),
            _details(host_platform="windows", execution_substrate="windows"),
        )
    if observed == "darwin":
        return TerminalResult(
            "sos_host_admission_v2",
            Status.SUCCESS,
            ("SOS_MACOS_CONTROL_PLANE_ADMITTED",),
            _details(host_platform="macos", execution_substrate="macos"),
        )
    return TerminalResult(
        "sos_host_admission_v2",
        Status.UNSUPPORTED,
        ("SOS_PLATFORM_UNSUPPORTED",),
        _details(
            host_platform="other",
            native_support_status="unsupported",
            next_action="Use Linux, Windows 11 x86_64, or macOS 14+ Apple Silicon.",
        ),
    )


def admit_project_filesystem(
    path: str | os.PathLike[str],
    *,
    platform_name: str | None = None,
    mountinfo_text: str | None = None,
    service: PlatformServices | None = None,
) -> TerminalResult:
    host = admit_host(platform_name=platform_name)
    if host.status != Status.SUCCESS:
        return TerminalResult(
            "sos_filesystem_admission_v1", host.status, host.reasons, host.details
        )
    observed_platform = process_platform_name(platform_name)
    try:
        if mountinfo_text is None:
            selected = current_platform_services() if service is None else service
            report = selected.inspect_host(Path(path))
            filesystem_type = str(report.get("filesystem_type", "unknown"))
            if report.get("filesystem_observation_status") != "observed":
                if observed_platform == "win32" and filesystem_type == "ntfs":
                    pass
                else:
                    raise ValueError("filesystem observation unavailable")
        else:
            if observed_platform != "linux":
                raise ValueError("mountinfo is Linux-only")
            filesystem_type = _filesystem_for_path(PurePosixPath(path), mountinfo_text)
    except PlatformServiceError as error:
        reason = (
            "SOS_FILESYSTEM_PROFILE_UNSUPPORTED"
            if error.kind in {"filesystem_unsupported", "platform_unsupported"}
            else "SOS_FILESYSTEM_PROFILE_NOT_VERIFIED"
        )
        return TerminalResult(
            "sos_filesystem_admission_v1",
            Status.UNSUPPORTED if reason.endswith("UNSUPPORTED") else Status.NOT_VERIFIED,
            (reason,),
            _details(filesystem_profile="unsupported_or_unknown"),
        )
    except (OSError, UnicodeError, ValueError):
        return TerminalResult(
            "sos_filesystem_admission_v1",
            Status.NOT_VERIFIED,
            ("SOS_FILESYSTEM_PROFILE_NOT_VERIFIED",),
            _details(filesystem_profile="unknown"),
        )
    filesystem_type = filesystem_type.lower()
    if observed_platform == "linux" and filesystem_type in _ADMITTED_FILESYSTEMS:
        return TerminalResult(
            "sos_filesystem_admission_v1",
            Status.SUCCESS,
            ("SOS_FILESYSTEM_PROFILE_ADMITTED",),
            _details(
                filesystem_profile="native_linux",
                filesystem_type=filesystem_type,
            ),
        )
    if observed_platform == "win32" and filesystem_type == "ntfs":
        return TerminalResult(
            "sos_filesystem_admission_v1",
            Status.SUCCESS,
            ("SOS_FILESYSTEM_PROFILE_ADMITTED",),
            _details(
                execution_substrate="windows",
                canonical_state_location="native_windows_filesystem_required",
                filesystem_profile="windows_local_ntfs",
                filesystem_type="ntfs",
            ),
        )
    if observed_platform == "darwin" and filesystem_type == "apfs":
        return TerminalResult(
            "sos_filesystem_admission_v1",
            Status.SUCCESS,
            ("SOS_FILESYSTEM_PROFILE_ADMITTED",),
            _details(
                execution_substrate="macos",
                canonical_state_location="native_macos_filesystem_required",
                filesystem_profile="macos_local_apfs",
                filesystem_type="apfs",
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
