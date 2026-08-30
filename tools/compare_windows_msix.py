#!/usr/bin/env python3
"""Compare two unsigned MSIX packages without trusting container timestamps."""

from __future__ import annotations

import argparse
import hashlib
import json
import struct
import sys
import zipfile
from pathlib import Path, PurePosixPath


REQUIRED_PACKAGE_ENTRIES = {
    "AppxManifest.xml",
    "AppxBlockMap.xml",
    "[Content_Types].xml",
    "payload-manifest.json",
    "sos.exe",
    "runtime/python.exe",
}
TIMESTAMP_EXTRA_FIELD_IDS = {0x000A, 0x5455}
LOCAL_HEADER = b"PK\x03\x04"
CENTRAL_HEADER = b"PK\x01\x02"
END_OF_CENTRAL_DIRECTORY = b"PK\x05\x06"
ZIP64_END_OF_CENTRAL_DIRECTORY = b"PK\x06\x06"
ZIP64_END_OF_CENTRAL_DIRECTORY_LOCATOR = b"PK\x06\x07"
ZIP16_SENTINEL = 0xFFFF
ZIP32_SENTINEL = 0xFFFFFFFF


class ComparisonError(ValueError):
    """An MSIX pair cannot be admitted as content-equivalent."""


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def sha256(path: Path) -> str:
    return sha256_bytes(path.read_bytes())


def normalize_timestamp_payload(field_id: int, payload: bytes) -> bytes:
    normalized = bytearray(payload)
    if field_id == 0x5455:
        if not payload or payload[0] & ~0x07:
            raise ComparisonError("malformed extended timestamp extra field")
        expected = 1 + 4 * sum(bool(payload[0] & bit) for bit in (0x01, 0x02, 0x04))
        if len(payload) != expected:
            raise ComparisonError("malformed extended timestamp extra field")
        normalized[1:] = b"\0" * (len(payload) - 1)
    elif field_id == 0x000A:
        if len(payload) < 4 or payload[:4] != b"\0\0\0\0":
            raise ComparisonError("malformed NTFS timestamp extra field")
        position = 4
        while position < len(payload):
            if len(payload) - position < 4:
                raise ComparisonError("malformed NTFS timestamp extra field")
            tag, length = struct.unpack_from("<HH", payload, position)
            end = position + 4 + length
            if end > len(payload) or (tag == 0x0001 and length != 24):
                raise ComparisonError("malformed NTFS timestamp extra field")
            if tag == 0x0001:
                normalized[position + 4 : end] = b"\0" * length
            position = end
    return bytes(normalized)


def normalized_extra(value: bytes) -> bytes:
    """Zero only timestamp values while preserving all flags and tag structure."""
    position = 0
    retained = bytearray()
    while position < len(value):
        if len(value) - position < 4:
            raise ComparisonError("malformed ZIP extra field")
        field_id, length = struct.unpack_from("<HH", value, position)
        end = position + 4 + length
        if end > len(value):
            raise ComparisonError("malformed ZIP extra field")
        retained.extend(value[position : position + 4])
        retained.extend(
            normalize_timestamp_payload(field_id, value[position + 4 : end])
            if field_id in TIMESTAMP_EXTRA_FIELD_IDS
            else value[position + 4 : end]
        )
        position = end
    return bytes(retained)


def normalize_extra_in_place(buffer: bytearray, start: int, length: int) -> None:
    end = start + length
    position = start
    while position < end:
        if end - position < 4:
            raise ComparisonError("malformed ZIP extra field")
        field_id, field_length = struct.unpack_from("<HH", buffer, position)
        field_end = position + 4 + field_length
        if field_end > end:
            raise ComparisonError("malformed ZIP extra field")
        if field_id in TIMESTAMP_EXTRA_FIELD_IDS:
            buffer[position + 4 : field_end] = normalize_timestamp_payload(
                field_id, bytes(buffer[position + 4 : field_end])
            )
        position = field_end


def validate_entry_boundaries(
    buffer: bytearray, infos: tuple[zipfile.ZipInfo, ...], central_offset: int
) -> None:
    ordered = sorted(infos, key=lambda info: info.header_offset)
    for index, info in enumerate(ordered):
        offset = info.header_offset
        name_length, extra_length = struct.unpack_from("<HH", buffer, offset + 26)
        data_start = offset + 30 + name_length + extra_length
        data_end = data_start + info.compress_size
        boundary = ordered[index + 1].header_offset if index + 1 < len(ordered) else central_offset
        if data_end > boundary:
            raise ComparisonError("ZIP entry overlaps the next package structure")
        descriptor = bytes(buffer[data_end:boundary])
        if info.flag_bits & 0x08:
            if len(descriptor) == 16 and descriptor[:4] == b"PK\x07\x08":
                descriptor = descriptor[4:]
            if len(descriptor) != 12:
                raise ComparisonError("invalid ZIP data descriptor shape")
            crc, compressed_size, file_size = struct.unpack("<LLL", descriptor)
            if (crc, compressed_size, file_size) != (
                info.CRC,
                info.compress_size,
                info.file_size,
            ):
                raise ComparisonError("ZIP data descriptor binding failed")
        elif descriptor:
            raise ComparisonError("unexpected bytes between ZIP entries")


def resolve_central_directory(
    buffer: bytearray, eocd: int, expected_entries: int | None
) -> tuple[int, int]:
    """Resolve a bounded single-disk classic or ZIP64 central directory."""
    (
        signature,
        disk,
        central_disk,
        disk_entries,
        total_entries,
        central_size,
        central_offset,
        comment_length,
    ) = struct.unpack_from("<4s4H2LH", buffer, eocd)
    if signature != END_OF_CENTRAL_DIRECTORY or comment_length != 0:
        raise ComparisonError("ZIP trailer or comment is forbidden")
    locator = eocd - 20
    has_zip64_locator = (
        locator >= 0
        and bytes(buffer[locator : locator + 4])
        == ZIP64_END_OF_CENTRAL_DIRECTORY_LOCATOR
    )
    classic_uses_zip64 = (
        disk == ZIP16_SENTINEL
        or central_disk == ZIP16_SENTINEL
        or disk_entries == ZIP16_SENTINEL
        or total_entries == ZIP16_SENTINEL
        or central_size == ZIP32_SENTINEL
        or central_offset == ZIP32_SENTINEL
    )
    if not has_zip64_locator:
        if classic_uses_zip64:
            raise ComparisonError("ZIP64 locator is missing")
        if disk != 0 or central_disk != 0:
            raise ComparisonError("multi-disk ZIP package is forbidden")
        if disk_entries != total_entries or (
            expected_entries is not None and total_entries != expected_entries
        ):
            raise ComparisonError("ZIP central entry count is inconsistent")
        if central_offset + central_size != eocd:
            raise ComparisonError("ZIP central directory bounds are inconsistent")
        return central_offset, central_size

    locator_signature, locator_disk, zip64_offset, total_disks = struct.unpack_from(
        "<4sLQL", buffer, locator
    )
    if locator_signature != ZIP64_END_OF_CENTRAL_DIRECTORY_LOCATOR:
        raise ComparisonError("malformed ZIP64 locator")
    if locator_disk != 0 or total_disks != 1:
        raise ComparisonError("multi-disk ZIP64 package is forbidden")
    if zip64_offset + 56 > locator:
        raise ComparisonError("malformed ZIP64 end record bounds")
    if bytes(buffer[zip64_offset : zip64_offset + 4]) != ZIP64_END_OF_CENTRAL_DIRECTORY:
        raise ComparisonError("ZIP64 end record is missing")
    zip64_size = struct.unpack_from("<Q", buffer, zip64_offset + 4)[0]
    if zip64_size != 44 or zip64_offset + 12 + zip64_size != locator:
        raise ComparisonError("unsupported ZIP64 end record shape")
    (
        zip64_signature,
        resolved_size,
        _version_made_by,
        _version_needed,
        zip64_disk,
        zip64_central_disk,
        zip64_disk_entries,
        zip64_total_entries,
        zip64_central_size,
        zip64_central_offset,
    ) = struct.unpack_from("<4sQ2H2L4Q", buffer, zip64_offset)
    if zip64_signature != ZIP64_END_OF_CENTRAL_DIRECTORY or resolved_size != 44:
        raise ComparisonError("malformed ZIP64 end record")
    if zip64_disk != 0 or zip64_central_disk != 0:
        raise ComparisonError("multi-disk ZIP64 package is forbidden")
    if zip64_disk_entries != zip64_total_entries or (
        expected_entries is not None and zip64_total_entries != expected_entries
    ):
        raise ComparisonError("ZIP64 central entry count is inconsistent")
    if zip64_central_offset + zip64_central_size != zip64_offset:
        raise ComparisonError("ZIP64 central directory bounds are inconsistent")

    for observed, resolved, sentinel, label in (
        (disk, zip64_disk, ZIP16_SENTINEL, "disk number"),
        (central_disk, zip64_central_disk, ZIP16_SENTINEL, "central disk number"),
        (disk_entries, zip64_disk_entries, ZIP16_SENTINEL, "disk entry count"),
        (total_entries, zip64_total_entries, ZIP16_SENTINEL, "entry count"),
        (central_size, zip64_central_size, ZIP32_SENTINEL, "central size"),
        (central_offset, zip64_central_offset, ZIP32_SENTINEL, "central offset"),
    ):
        if observed not in (resolved, sentinel):
            raise ComparisonError(f"classic and ZIP64 {label} differ")
    return zip64_central_offset, zip64_central_size


def normalized_container(path: Path, infos: tuple[zipfile.ZipInfo, ...]) -> bytes:
    """Return raw package bytes with only admitted timestamp fields neutralized."""
    buffer = bytearray(path.read_bytes())
    eocd = bytes(buffer).rfind(END_OF_CENTRAL_DIRECTORY)
    if eocd < 0 or eocd + 22 != len(buffer):
        raise ComparisonError("ZIP trailer or comment is forbidden")
    central_offset, central_size = resolve_central_directory(buffer, eocd, len(infos))
    central_end = central_offset + central_size

    for info in infos:
        offset = info.header_offset
        if bytes(buffer[offset : offset + 4]) != LOCAL_HEADER or offset + 30 > len(buffer):
            raise ComparisonError("invalid ZIP local header")
        flags = struct.unpack_from("<H", buffer, offset + 6)[0]
        if flags != info.flag_bits:
            raise ComparisonError("local and central ZIP flags differ")
        if flags & 0x1:
            raise ComparisonError("encrypted package entry is forbidden")
        name_length, extra_length = struct.unpack_from("<HH", buffer, offset + 26)
        extra_start = offset + 30 + name_length
        if extra_start + extra_length > len(buffer):
            raise ComparisonError("invalid ZIP local extra field")
        buffer[offset + 10 : offset + 14] = b"\0" * 4
        normalize_extra_in_place(buffer, extra_start, extra_length)

    position = central_offset
    central_names: list[str] = []
    while position < central_end:
        if (
            bytes(buffer[position : position + 4]) != CENTRAL_HEADER
            or position + 46 > central_end
        ):
            raise ComparisonError("invalid ZIP central header")
        name_length, extra_length, entry_comment_length = struct.unpack_from(
            "<HHH", buffer, position + 28
        )
        end = position + 46 + name_length + extra_length + entry_comment_length
        if end > central_end:
            raise ComparisonError("invalid ZIP central entry")
        name = bytes(buffer[position + 46 : position + 46 + name_length]).decode("utf-8")
        central_names.append(safe_name(name))
        central_flags = struct.unpack_from("<H", buffer, position + 8)[0]
        if central_flags != infos[len(central_names) - 1].flag_bits:
            raise ComparisonError("central ZIP flags are inconsistent")
        if central_flags & 0x1:
            raise ComparisonError("encrypted package entry is forbidden")
        buffer[position + 12 : position + 16] = b"\0" * 4
        normalize_extra_in_place(buffer, position + 46 + name_length, extra_length)
        position = end
    if position != central_end or central_names != [info.filename for info in infos]:
        raise ComparisonError("ZIP central inventory is inconsistent")
    validate_entry_boundaries(buffer, infos, central_offset)
    return bytes(buffer)


def validate_container_directory(path: Path) -> None:
    """Reject malformed directory framing before a generic ZIP reader handles it."""
    buffer = bytearray(path.read_bytes())
    eocd = bytes(buffer).rfind(END_OF_CENTRAL_DIRECTORY)
    if eocd < 0 or eocd + 22 != len(buffer):
        raise ComparisonError("ZIP trailer or comment is forbidden")
    resolve_central_directory(buffer, eocd, None)


def safe_name(value: str) -> str:
    if "\\" in value or value.startswith("/"):
        raise ComparisonError("unsafe package entry name")
    name = PurePosixPath(value)
    if name.is_absolute() or ".." in name.parts or value in {"", "."}:
        raise ComparisonError("unsafe package entry name")
    return value


def read_package(
    path: Path,
) -> tuple[dict[str, tuple[zipfile.ZipInfo, bytes]], bytes, bytes]:
    entries: dict[str, tuple[zipfile.ZipInfo, bytes]] = {}
    validate_container_directory(path)
    with zipfile.ZipFile(path) as package:
        if package.comment:
            raise ComparisonError("package comment is forbidden")
        infos = tuple(package.infolist())
        for info in infos:
            name = safe_name(info.filename)
            if name in entries:
                raise ComparisonError("duplicate package entry")
            if info.is_dir() or info.flag_bits & 0x1:
                raise ComparisonError("directory or encrypted package entry is forbidden")
            entries[name] = (info, package.read(info))
    if not REQUIRED_PACKAGE_ENTRIES.issubset(entries):
        raise ComparisonError("required package entry is missing")
    inventory = [
        {"path": name, "sha256": sha256_bytes(content), "size": len(content)}
        for name, (_, content) in sorted(entries.items())
    ]
    canonical = json.dumps(inventory, sort_keys=True, separators=(",", ":")).encode()
    return entries, canonical, normalized_container(path, infos)


def stable_metadata(info: zipfile.ZipInfo) -> tuple[object, ...]:
    return (
        info.compress_type,
        info.CRC,
        info.file_size,
        info.compress_size,
        info.flag_bits,
        info.create_system,
        info.create_version,
        info.extract_version,
        info.internal_attr,
        info.external_attr,
        info.volume,
        normalized_extra(info.extra),
        info.comment,
    )


def compare(first: Path, second: Path) -> dict[str, object]:
    first_entries, first_inventory, first_container = read_package(first)
    second_entries, second_inventory, second_container = read_package(second)
    if set(first_entries) != set(second_entries):
        raise ComparisonError("package entry inventory differs")
    if first_inventory != second_inventory:
        raise ComparisonError("package entry content differs")

    timestamp_drift: list[str] = []
    for name in sorted(first_entries):
        first_info, first_content = first_entries[name]
        second_info, second_content = second_entries[name]
        if first_content != second_content:
            raise ComparisonError("package entry content differs")
        if stable_metadata(first_info) != stable_metadata(second_info):
            raise ComparisonError("package entry metadata differs beyond timestamps")
        if first_info.date_time != second_info.date_time or first_info.extra != second_info.extra:
            timestamp_drift.append(name)
    if first_container != second_container:
        raise ComparisonError("package container differs beyond timestamps")

    first_digest = sha256(first)
    second_digest = sha256(second)
    return {
        "byte_identical": first_digest == second_digest,
        "content_digest": f"sha256:{sha256_bytes(first_inventory)}",
        "contract": "sos_windows_msix_content_comparison_v1",
        "entry_count": len(first_entries),
        "first_msix_sha256": first_digest,
        "second_msix_sha256": second_digest,
        "status": "passed",
        "timestamp_drift_entry_count": len(timestamp_drift),
        "timestamp_drift_only": first_digest != second_digest,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("first", type=Path)
    parser.add_argument("second", type=Path)
    arguments = parser.parse_args()
    try:
        report = compare(arguments.first.resolve(strict=True), arguments.second.resolve(strict=True))
    except (ComparisonError, OSError, zipfile.BadZipFile) as error:
        print(f"SOS_MSIX_CONTENT_COMPARISON_FAILED: {error}", file=sys.stderr)
        return 2
    print(json.dumps(report, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
