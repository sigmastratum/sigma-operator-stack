#!/usr/bin/env python3
"""Build and verify the exact SOS Windows application-manifest resource."""

from __future__ import annotations

import argparse
import hashlib
import json
import struct
from pathlib import Path


RT_MANIFEST = 24
RESOURCE_ID = 1
RESOURCE_LANGUAGE = 0x0409
IMAGE_FILE_MACHINE_AMD64 = 0x8664
IMAGE_REL_AMD64_ADDR32NB = 0x0003
MAX_PE_BYTES = 8 * 1024 * 1024
MAX_RESOURCE_ENTRIES = 64


class ManifestResourceError(ValueError):
    pass


def _bounded(data: bytes, offset: int, size: int) -> memoryview:
    if offset < 0 or size < 0 or offset + size > len(data):
        raise ManifestResourceError("bounded PE read failed")
    return memoryview(data)[offset : offset + size]


def _unpack(data: bytes, fmt: str, offset: int) -> tuple[int, ...]:
    size = struct.calcsize(fmt)
    return struct.unpack(fmt, _bounded(data, offset, size))


def build_manifest_coff(manifest: bytes) -> bytes:
    """Return one deterministic AMD64 COFF object containing RT_MANIFEST/1."""
    if not manifest or len(manifest) > 64 * 1024:
        raise ManifestResourceError("manifest size is invalid")
    if manifest.count(b"requestedExecutionLevel") != 1:
        raise ManifestResourceError("manifest execution-level cardinality is invalid")
    if b'level="asInvoker"' not in manifest or b'uiAccess="false"' not in manifest:
        raise ManifestResourceError("manifest execution-level contract is invalid")
    if (
        manifest.count(b"<dpiAware ") != 1
        or manifest.count(b"<dpiAwareness ") != 1
        or b">true/pm</dpiAware>" not in manifest
        or b">PerMonitorV2, PerMonitor</dpiAwareness>" not in manifest
    ):
        raise ManifestResourceError("manifest DPI-awareness contract is invalid")

    # IMAGE_RESOURCE_DIRECTORY hierarchy: type -> id -> language -> data.
    data_offset = 88
    raw = bytearray()
    raw.extend(struct.pack("<IIHHHH", 0, 0, 0, 0, 0, 1))
    raw.extend(struct.pack("<II", RT_MANIFEST, 0x80000000 | 24))
    raw.extend(struct.pack("<IIHHHH", 0, 0, 0, 0, 0, 1))
    raw.extend(struct.pack("<II", RESOURCE_ID, 0x80000000 | 48))
    raw.extend(struct.pack("<IIHHHH", 0, 0, 0, 0, 0, 1))
    raw.extend(struct.pack("<II", RESOURCE_LANGUAGE, 72))
    raw.extend(struct.pack("<IIII", data_offset, len(manifest), 0, 0))
    raw.extend(manifest)
    raw.extend(b"\0" * (-len(manifest) & 7))

    file_header_size = 20
    section_header_size = 40
    raw_pointer = file_header_size + section_header_size
    relocation_pointer = raw_pointer + len(raw)
    symbol_pointer = relocation_pointer + 10
    file_header = struct.pack(
        "<HHIIIHH",
        IMAGE_FILE_MACHINE_AMD64,
        1,
        0,
        symbol_pointer,
        1,
        0,
        0x0104,
    )
    section_header = struct.pack(
        "<8sIIIIIIHHI",
        b".rsrc\0\0\0",
        0,
        0,
        len(raw),
        raw_pointer,
        relocation_pointer,
        0,
        1,
        0,
        0x40000040,
    )
    relocation = struct.pack("<IIH", data_offset - 16, 0, IMAGE_REL_AMD64_ADDR32NB)
    symbol = struct.pack("<8sIhHBB", b".rsrc\0\0\0", 0, 1, 0, 3, 0)
    return file_header + section_header + raw + relocation + symbol + struct.pack("<I", 4)


def _pe_sections(data: bytes) -> tuple[int, list[tuple[int, int, int, int]], int, int]:
    if len(data) > MAX_PE_BYTES or _bounded(data, 0, 2).tobytes() != b"MZ":
        raise ManifestResourceError("input is not one bounded PE executable")
    pe_offset = _unpack(data, "<I", 0x3C)[0]
    if _bounded(data, pe_offset, 4).tobytes() != b"PE\0\0":
        raise ManifestResourceError("PE signature is invalid")
    machine, section_count, _, _, _, optional_size, _ = _unpack(
        data, "<HHIIIHH", pe_offset + 4
    )
    if machine != IMAGE_FILE_MACHINE_AMD64 or not 1 <= section_count <= 32:
        raise ManifestResourceError("PE machine or section count is unsupported")
    optional = pe_offset + 24
    magic = _unpack(data, "<H", optional)[0]
    if magic == 0x20B:
        directory_count_offset, directory_offset = 108, 112
    elif magic == 0x10B:
        directory_count_offset, directory_offset = 92, 96
    else:
        raise ManifestResourceError("PE optional header is unsupported")
    if optional_size < directory_offset + 24:
        raise ManifestResourceError("PE optional header is truncated")
    directory_count = _unpack(data, "<I", optional + directory_count_offset)[0]
    if directory_count <= 2:
        raise ManifestResourceError("PE resource directory is absent")
    resource_rva, resource_size = _unpack(data, "<II", optional + directory_offset + 16)
    section_offset = optional + optional_size
    sections: list[tuple[int, int, int, int]] = []
    for index in range(section_count):
        header = section_offset + index * 40
        virtual_size, virtual_address, raw_size, raw_pointer = _unpack(
            data, "<IIII", header + 8
        )
        _bounded(data, raw_pointer, raw_size)
        sections.append((virtual_address, virtual_size, raw_pointer, raw_size))
    return resource_rva, sections, resource_size, machine


def _rva_to_offset(rva: int, sections: list[tuple[int, int, int, int]]) -> int:
    for virtual_address, virtual_size, raw_pointer, raw_size in sections:
        span = max(virtual_size, raw_size)
        if virtual_address <= rva < virtual_address + span:
            delta = rva - virtual_address
            if delta >= raw_size:
                break
            return raw_pointer + delta
    raise ManifestResourceError("PE RVA is outside admitted section data")


def extract_manifest_resources(data: bytes) -> list[bytes]:
    resource_rva, sections, resource_size, _ = _pe_sections(data)
    if resource_rva == 0 or resource_size == 0:
        raise ManifestResourceError("PE resource directory is absent")
    base = _rva_to_offset(resource_rva, sections)
    _bounded(data, base, resource_size)

    def directory(relative: int) -> list[tuple[int, int]]:
        if relative < 0 or relative + 16 > resource_size:
            raise ManifestResourceError("resource directory offset is invalid")
        named, identified = _unpack(data, "<HH", base + relative + 12)
        count = named + identified
        if count > MAX_RESOURCE_ENTRIES or relative + 16 + count * 8 > resource_size:
            raise ManifestResourceError("resource directory cardinality is invalid")
        return [
            _unpack(data, "<II", base + relative + 16 + index * 8)
            for index in range(count)
        ]

    manifests: list[bytes] = []
    for kind, kind_target in directory(0):
        if kind & 0x80000000 or kind != RT_MANIFEST:
            continue
        if not kind_target & 0x80000000:
            raise ManifestResourceError("manifest type does not target a directory")
        for resource_id, id_target in directory(kind_target & 0x7FFFFFFF):
            if resource_id & 0x80000000:
                raise ManifestResourceError("named manifest resources are unsupported")
            if not id_target & 0x80000000:
                raise ManifestResourceError("manifest id does not target a directory")
            for language, leaf in directory(id_target & 0x7FFFFFFF):
                if language & 0x80000000 or leaf & 0x80000000:
                    raise ManifestResourceError("manifest language leaf is invalid")
                if leaf + 16 > resource_size:
                    raise ManifestResourceError("manifest data entry is invalid")
                payload_rva, size, _, _ = _unpack(data, "<IIII", base + leaf)
                payload_offset = _rva_to_offset(payload_rva, sections)
                manifests.append(_bounded(data, payload_offset, size).tobytes())
    return manifests


def verify_pe_manifest(pe: bytes, expected: bytes) -> dict[str, object]:
    manifests = extract_manifest_resources(pe)
    if len(manifests) != 1:
        raise ManifestResourceError("PE must contain exactly one manifest resource")
    if manifests[0] != expected:
        raise ManifestResourceError("embedded PE manifest differs from canonical bytes")
    return {
        "contract": "sos_windows_pe_manifest_verification_v1",
        "dpi_awareness": "PerMonitorV2, PerMonitor",
        "manifest_count": 1,
        "manifest_sha256": hashlib.sha256(expected).hexdigest(),
        "requested_execution_level": "asInvoker",
        "status": "passed",
        "ui_access": False,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="command", required=True)
    build = subparsers.add_parser("build-resource")
    build.add_argument("--manifest", type=Path, required=True)
    build.add_argument("--output", type=Path, required=True)
    verify = subparsers.add_parser("verify-pe")
    verify.add_argument("--manifest", type=Path, required=True)
    verify.add_argument("--pe", type=Path, required=True)
    args = parser.parse_args()
    manifest = args.manifest.read_bytes()
    if args.command == "build-resource":
        payload = build_manifest_coff(manifest)
        args.output.write_bytes(payload)
        report = {
            "contract": "sos_windows_manifest_resource_build_v1",
            "manifest_sha256": hashlib.sha256(manifest).hexdigest(),
            "resource_sha256": hashlib.sha256(payload).hexdigest(),
            "status": "passed",
        }
    else:
        report = verify_pe_manifest(args.pe.read_bytes(), manifest)
    print(json.dumps(report, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
