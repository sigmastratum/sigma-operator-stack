#!/usr/bin/env python3
"""Build a deterministic, closed offline Windows MSIX build packet.

This is a release-engineering tool, not a user installer.  Git is permitted
only on the trusted build host and is supplied by absolute path plus SHA-256.
The resulting Windows packet contains a native runner, an exact source
snapshot and immutable payload inputs; the Windows runner itself needs no Git,
shell, PATH lookup or network access.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import stat
import struct
import subprocess
import sys
import tempfile
import zipfile
from pathlib import Path, PurePosixPath


PACKET_CONTRACT = "sos_windows_msix_build_packet_v1"
SOURCE_CONTRACT = "sos_windows_msix_source_manifest_v1"
INPUT_LOCK_CONTRACT = "sos_windows_msix_input_lock_v1"
GO_VERSION = "go1.27.0"
COMMAND_LAUNCHER_CONTRACT = b"sos_windows_msix_command_launcher_v1"
SOURCE_FILES = (
    "installers/windows-msix/AppxManifest.xml.in",
    "installers/windows-msix/assets/Square44x44Logo.png",
    "installers/windows-msix/assets/Square50x50Logo.png",
    "installers/windows-msix/assets/Square150x150Logo.png",
    "installers/windows-msix/store-identity.json",
    "installers/windows-msix-entrypoint/go.mod",
    "installers/windows-msix-entrypoint/main_windows.go",
    "installers/windows-msix-entrypoint/model.go",
    "tools/build_windows_msix.py",
    "tools/build_windows_msix_entrypoint.py",
    "tools/build_windows_msix_pipeline.py",
    "tools/check_windows_msix_content.py",
    "tools/compare_windows_msix.py",
    "tools/prepare_windows_msix_payload.py",
    "tools/verify_windows_msix_source.py",
)
WHEELS = (
    "attrs-26.1.0-py3-none-any.whl",
    "jsonschema-4.26.0-py3-none-any.whl",
    "jsonschema_specifications-2025.9.1-py3-none-any.whl",
    "referencing-0.37.0-py3-none-any.whl",
    "rpds_py-2026.6.3-cp312-cp312-win_amd64.whl",
    "sigma_operator_stack-0.1.0a2-py3-none-any.whl",
    "typing_extensions-4.16.0-py3-none-any.whl",
)
MAX_FILE_SIZE = 1024 * 1024 * 1024
MAX_PACKET_SIZE = 3 * 1024 * 1024 * 1024
MAX_FILES = 25_000
FIXED_ZIP_TIME = (1980, 1, 1, 0, 0, 0)
WINDOWS_RESERVED = {
    "CON",
    "CONIN$",
    "CONOUT$",
    "PRN",
    "AUX",
    "NUL",
    *(f"COM{number}" for number in range(1, 10)),
    *(f"LPT{number}" for number in range(1, 10)),
}


class PacketError(ValueError):
    """The exact packet cannot be admitted."""


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for block in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def is_reparse(observed: os.stat_result) -> bool:
    return bool(
        getattr(observed, "st_file_attributes", 0)
        & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
    )


def plain_file(path: Path, label: str) -> os.stat_result:
    try:
        observed = path.lstat()
    except OSError as error:
        raise PacketError(f"{label} is unavailable") from error
    if (
        not stat.S_ISREG(observed.st_mode)
        or stat.S_ISLNK(observed.st_mode)
        or is_reparse(observed)
    ):
        raise PacketError(f"{label} is not a plain regular file")
    if observed.st_size <= 0 or observed.st_size > MAX_FILE_SIZE:
        raise PacketError(f"{label} size is invalid")
    return observed


def plain_directory(path: Path, label: str) -> None:
    try:
        observed = path.lstat()
    except OSError as error:
        raise PacketError(f"{label} is unavailable") from error
    if (
        not stat.S_ISDIR(observed.st_mode)
        or stat.S_ISLNK(observed.st_mode)
        or is_reparse(observed)
    ):
        raise PacketError(f"{label} is not a plain directory")


def safe_relative(value: str) -> str:
    if (
        not value
        or "\\" in value
        or "\0" in value
        or any(ord(character) < 32 or character in '<>"|?*' for character in value)
    ):
        raise PacketError("packet path is unsafe")
    relative = PurePosixPath(value)
    if relative.is_absolute() or any(part in ("", ".", "..") for part in relative.parts):
        raise PacketError("packet path is unsafe")
    for part in relative.parts:
        if part.endswith((" ", ".")) or ":" in part:
            raise PacketError("packet path is unsafe on Windows")
        if part.split(".", 1)[0].upper() in WINDOWS_RESERVED:
            raise PacketError("packet path is reserved on Windows")
    return relative.as_posix()


def entry(path: str, value: bytes) -> dict[str, object]:
    return {
        "path": safe_relative(path),
        "sha256": hashlib.sha256(value).hexdigest(),
        "size": len(value),
    }


def inventory_digest(files: list[dict[str, object]]) -> str:
    digest = hashlib.sha256()
    previous = ""
    folded: dict[str, str] = {}
    total = 0
    for item in files:
        if set(item) != {"path", "sha256", "size"}:
            raise PacketError("inventory entry contract is not closed")
        path = safe_relative(item["path"] if isinstance(item["path"], str) else "")
        size = item["size"]
        checksum = item["sha256"]
        if path <= previous:
            raise PacketError("packet inventory is not strictly ordered")
        previous = path
        folded_path = path.casefold()
        if folded_path in folded and folded[folded_path] != path:
            raise PacketError("packet inventory contains a case-fold collision")
        folded[folded_path] = path
        if (
            not isinstance(size, int)
            or isinstance(size, bool)
            or size < 0
            or size > MAX_FILE_SIZE
        ):
            raise PacketError("packet inventory size is invalid")
        if not isinstance(checksum, str) or not re.fullmatch(r"[0-9a-f]{64}", checksum):
            raise PacketError("packet inventory digest is invalid")
        total += size
        if total > MAX_PACKET_SIZE or len(folded) > MAX_FILES:
            raise PacketError("packet inventory exceeds bounded limits")
        digest.update(path.encode("utf-8"))
        digest.update(b"\0")
        digest.update(str(size).encode("ascii"))
        digest.update(b"\0")
        digest.update(checksum.encode("ascii"))
        digest.update(b"\n")
    return f"sha256:{digest.hexdigest()}"


def canonical_json(record: dict[str, object]) -> bytes:
    return (json.dumps(record, sort_keys=True, separators=(",", ":")) + "\n").encode(
        "utf-8"
    )


def run_git(
    executable: Path,
    expected_digest: str,
    repository: Path,
    arguments: list[str],
    *,
    binary: bool = False,
) -> bytes | str:
    if sha256(executable) != expected_digest:
        raise PacketError("Git digest drifted before source observation")
    completed = subprocess.run(
        [os.fspath(executable), "-C", os.fspath(repository), *arguments],
        check=False,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env={"LANG": "C.UTF-8", "LC_ALL": "C.UTF-8", "PATH": ""},
    )
    if sha256(executable) != expected_digest:
        raise PacketError("Git digest drifted during source observation")
    if completed.returncode != 0:
        raise PacketError("exact Git source observation failed")
    if len(completed.stdout) > MAX_FILE_SIZE or len(completed.stderr) > 1024 * 1024:
        raise PacketError("Git source observation exceeded bounded output")
    if binary:
        return completed.stdout
    try:
        return completed.stdout.decode("utf-8").strip()
    except UnicodeDecodeError as error:
        raise PacketError("Git source observation was not UTF-8") from error


def observed_tool_version(
    executable: Path,
    expected_digest: str,
    arguments: list[str],
    label: str,
) -> str:
    if sha256(executable) != expected_digest:
        raise PacketError(f"{label} digest drifted before version observation")
    completed = subprocess.run(
        [os.fspath(executable), *arguments],
        check=False,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=30,
        env={
            "GOTOOLCHAIN": "local",
            "LANG": "C.UTF-8",
            "LC_ALL": "C.UTF-8",
            "PATH": "",
        },
    )
    if sha256(executable) != expected_digest:
        raise PacketError(f"{label} digest drifted during version observation")
    if (
        completed.returncode != 0
        or completed.stderr
        or not completed.stdout
        or len(completed.stdout) > 4096
    ):
        raise PacketError(f"{label} version observation failed")
    try:
        value = completed.stdout.decode("ascii").strip()
    except UnicodeDecodeError as error:
        raise PacketError(f"{label} version observation was not ASCII") from error
    if not value or any(
        ord(character) < 0x20 or ord(character) > 0x7E for character in value
    ):
        raise PacketError(f"{label} version observation is not content-safe")
    return value


def read_bound_input(path: Path, label: str) -> bytes:
    before = plain_file(path, label)
    identity = (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
    value = path.read_bytes()
    after = plain_file(path, label)
    if identity != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns):
        raise PacketError(f"{label} changed while it was read")
    if len(value) != before.st_size:
        raise PacketError(f"{label} read was incomplete")
    return value


def pe_subsystem(value: bytes, label: str) -> int:
    if len(value) < 0x40 or value[:2] != b"MZ":
        raise PacketError(f"{label} is not a PE image")
    offset = struct.unpack_from("<I", value, 0x3C)[0]
    if offset + 94 > len(value) or value[offset : offset + 4] != b"PE\0\0":
        raise PacketError(f"{label} PE header is invalid")
    optional = offset + 24
    magic = struct.unpack_from("<H", value, optional)[0]
    if magic not in (0x10B, 0x20B):
        raise PacketError(f"{label} optional header is invalid")
    return struct.unpack_from("<H", value, optional + 68)[0]


def source_snapshot(
    git: Path,
    git_digest: str,
    repository: Path,
    candidate: str,
    tree: str,
) -> tuple[dict[str, bytes], bytes]:
    values: dict[str, bytes] = {}
    for relative in SOURCE_FILES:
        mode = run_git(
            git,
            git_digest,
            repository,
            ["ls-tree", candidate, "--", relative],
        )
        if not isinstance(mode, str) or not re.fullmatch(
            rf"100(?:644|755) blob [0-9a-f]{{40}}\t{re.escape(relative)}", mode
        ):
            raise PacketError("reviewed source snapshot contains an unsupported object")
        value = run_git(
            git,
            git_digest,
            repository,
            ["show", f"{candidate}:{relative}"],
            binary=True,
        )
        if not isinstance(value, bytes) or not value:
            raise PacketError("reviewed source snapshot file is empty")
        values[f"source/{relative}"] = value
    source_files = [
        entry(path.removeprefix("source/"), value)
        for path, value in sorted(values.items())
    ]
    source_record: dict[str, object] = {
        "candidate": candidate,
        "contract": SOURCE_CONTRACT,
        "file_count": len(source_files),
        "files": source_files,
        "inventory_digest": inventory_digest(source_files),
        "tree": tree,
    }
    return values, canonical_json(source_record)


def build_native_runner(
    git: Path,
    git_digest: str,
    repository: Path,
    candidate: str,
    tree: str,
    go: Path,
    go_digest: str,
    input_lock_digest: str,
) -> bytes:
    relative = "tools/build_windows_msix_builder.py"
    builder = run_git(
        git,
        git_digest,
        repository,
        ["show", f"{candidate}:{relative}"],
        binary=True,
    )
    if not isinstance(builder, bytes) or not builder:
        raise PacketError("exact native runner builder is unavailable")
    with tempfile.TemporaryDirectory(prefix="sos-msix-native-runner-") as temporary:
        root = Path(temporary)
        tool = root / "build_windows_msix_builder.py"
        tool.write_bytes(builder)
        output = root / "Build-SOS-MSIX.exe"
        completed = subprocess.run(
            [
                os.fspath(Path(sys.executable).resolve(strict=True)),
                "-I",
                "-B",
                os.fspath(tool),
                "--repository",
                os.fspath(repository),
                "--candidate",
                candidate,
                "--git",
                os.fspath(git),
                "--git-sha256",
                git_digest,
                "--go",
                os.fspath(go),
                "--go-sha256",
                go_digest,
                "--input-lock-sha256",
                input_lock_digest,
                "--output",
                os.fspath(output),
            ],
            check=False,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=1200,
            env={
                "LANG": "C.UTF-8",
                "LC_ALL": "C.UTF-8",
                "PATH": "",
                "PYTHONDONTWRITEBYTECODE": "1",
                "PYTHONNOUSERSITE": "1",
                "PYTHONSAFEPATH": "1",
            },
        )
        if (
            completed.returncode != 0
            or len(completed.stdout) > 1024 * 1024
            or len(completed.stderr) > 1024 * 1024
        ):
            raise PacketError("exact native runner build failed")
        try:
            receipt = json.loads(completed.stdout.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise PacketError("native runner build receipt is invalid") from error
        expected_keys = {
            "candidate",
            "contract",
            "go_sha256",
            "go_version",
            "input_lock_sha256",
            "manifest_sha256",
            "runner_sha256",
            "status",
            "tree",
        }
        if (
            not isinstance(receipt, dict)
            or set(receipt) != expected_keys
            or receipt["contract"] != "sos_windows_msix_builder_build_v1"
            or receipt["candidate"] != candidate
            or receipt["tree"] != tree
            or receipt["go_version"] != "go1.27.0"
            or receipt["go_sha256"] != f"sha256:{go_digest}"
            or receipt["input_lock_sha256"] != f"sha256:{input_lock_digest}"
            or receipt["status"] != "passed"
        ):
            raise PacketError("native runner build receipt binding is invalid")
        value = read_bound_input(output, "native packet runner")
        if (
            not value.startswith(b"MZ")
            or receipt["runner_sha256"]
            != f"sha256:{hashlib.sha256(value).hexdigest()}"
            or candidate.encode("ascii") not in value
            or tree.encode("ascii") not in value
            or input_lock_digest.encode("ascii") not in value
        ):
            raise PacketError("native runner artifact binding is invalid")
        return value


def build_input_lock(
    *,
    candidate: str,
    tree: str,
    git_digest: str,
    git_version: str,
    go_digest: str,
    go_version: str,
    makeappx_path: str,
    makeappx_digest: str,
    makeappx_size: int,
    source_manifest: bytes,
    sos_launcher: bytes,
    store_entrypoint: bytes,
    uv: bytes,
    python_runtime: bytes,
    wheels: dict[str, bytes],
) -> bytes:
    if go_version != GO_VERSION:
        raise PacketError("pinned Go toolchain version mismatch")
    wheel_bindings = [
        entry(f"wheelhouse/{name}", wheels[name]) for name in sorted(wheels)
    ]
    record: dict[str, object] = {
        "candidate": candidate,
        "contract": INPUT_LOCK_CONTRACT,
        "git": {
            "sha256": git_digest,
            "version": git_version,
        },
        "go": {
            "sha256": go_digest,
            "version": go_version,
        },
        "makeappx": {
            "program_files_x86_relative_path": makeappx_path,
            "sha256": makeappx_digest,
            "size": makeappx_size,
        },
        "python_runtime": entry(
            "windows-python-runtime-3.12.14.zip", python_runtime
        ),
        "sos_launcher": entry("sos.exe", sos_launcher),
        "store_entrypoint": entry("sos-launcher.exe", store_entrypoint),
        "source_manifest": entry("source-manifest.json", source_manifest),
        "tree": tree,
        "uv": entry("uv.exe", uv),
        "wheelhouse": wheel_bindings,
    }
    return canonical_json(record)


def start_here(candidate: str, tree: str) -> bytes:
    return (
        "# SOS Windows Store build packet\n\n"
        "This is a reviewed offline release-engineering packet, not the SOS user installer.\n"
        "Verify the separately supplied complete ZIP SHA-256 before extraction.\n"
        "Run `Build-SOS-MSIX.exe` as the ordinary signed-in Windows user.\n"
        "Do not use Administrator, disable TLS or antivirus, or modify ACLs.\n"
        "The runner uses only the exact packet files and the digest-bound Windows SDK tool.\n\n"
        f"Candidate: `{candidate}`\n"
        f"Tree: `{tree}`\n"
    ).encode("utf-8")


def write_zip(path: Path, root_name: str, files: dict[str, bytes]) -> None:
    with zipfile.ZipFile(path, "x", compression=zipfile.ZIP_STORED, allowZip64=True) as archive:
        for relative, value in sorted(files.items()):
            information = zipfile.ZipInfo(f"{root_name}/{safe_relative(relative)}")
            information.date_time = FIXED_ZIP_TIME
            information.create_system = 0
            information.compress_type = zipfile.ZIP_STORED
            information.external_attr = 0
            information.flag_bits = 0x800
            archive.writestr(information, value)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repository", required=True, type=Path)
    parser.add_argument("--candidate", required=True)
    parser.add_argument("--git", required=True, type=Path)
    parser.add_argument("--git-sha256", required=True)
    parser.add_argument("--go", required=True, type=Path)
    parser.add_argument("--go-sha256", required=True)
    parser.add_argument("--sos-launcher", required=True, type=Path)
    parser.add_argument("--store-entrypoint", required=True, type=Path)
    parser.add_argument("--uv", required=True, type=Path)
    parser.add_argument("--python-runtime", required=True, type=Path)
    parser.add_argument("--wheelhouse", required=True, type=Path)
    parser.add_argument("--sdk-version", required=True)
    parser.add_argument("--makeappx-sha256", required=True)
    parser.add_argument("--makeappx-size", required=True, type=int)
    parser.add_argument("--output", required=True, type=Path)
    arguments = parser.parse_args()

    if not re.fullmatch(r"[0-9a-f]{40}", arguments.candidate):
        raise PacketError("candidate binding is invalid")
    if not re.fullmatch(r"[0-9a-f]{64}", arguments.git_sha256):
        raise PacketError("Git digest binding is invalid")
    if not re.fullmatch(r"[0-9a-f]{64}", arguments.go_sha256):
        raise PacketError("Go digest binding is invalid")
    if not re.fullmatch(r"[0-9a-f]{64}", arguments.makeappx_sha256) or len(
        set(arguments.makeappx_sha256)
    ) < 8:
        raise PacketError("MakeAppx digest binding is invalid or placeholder-like")
    if not re.fullmatch(r"10\.0\.[0-9]+\.0", arguments.sdk_version):
        raise PacketError("Windows SDK version binding is invalid")
    if arguments.makeappx_size <= 0 or arguments.makeappx_size > MAX_FILE_SIZE:
        raise PacketError("MakeAppx size binding is invalid")
    if not arguments.git.is_absolute():
        raise PacketError("Git must be supplied by absolute path")
    if not arguments.go.is_absolute():
        raise PacketError("Go must be supplied by absolute path")
    git = arguments.git.resolve(strict=True)
    go = arguments.go.resolve(strict=True)
    plain_file(git, "Git executable")
    plain_file(go, "Go executable")
    if sha256(git) != arguments.git_sha256:
        raise PacketError("Git executable digest mismatch")
    if sha256(go) != arguments.go_sha256:
        raise PacketError("Go executable digest mismatch")
    git_version = observed_tool_version(
        git, arguments.git_sha256, ["--version"], "Git"
    )
    if not re.fullmatch(r"git version [0-9A-Za-z.+_-]+(?: \([ -~]+\))?", git_version):
        raise PacketError("Git version observation is invalid")
    observed_go_version = observed_tool_version(
        go, arguments.go_sha256, ["version"], "Go"
    )
    go_match = re.fullmatch(
        r"go version (go[0-9]+\.[0-9]+(?:\.[0-9]+)?) [^ ]+",
        observed_go_version,
    )
    if go_match is None or go_match.group(1) != GO_VERSION:
        raise PacketError("pinned Go toolchain version mismatch")
    go_version = go_match.group(1)
    repository = arguments.repository.resolve(strict=True)
    plain_directory(repository, "repository")
    if run_git(git, arguments.git_sha256, repository, ["status", "--porcelain"]):
        raise PacketError("repository must be clean")
    candidate = run_git(
        git,
        arguments.git_sha256,
        repository,
        ["rev-parse", "--verify", f"{arguments.candidate}^{{commit}}"],
    )
    head = run_git(git, arguments.git_sha256, repository, ["rev-parse", "HEAD"])
    if candidate != arguments.candidate or head != candidate:
        raise PacketError("candidate does not match exact repository HEAD")
    tree = run_git(
        git, arguments.git_sha256, repository, ["show", "-s", "--format=%T", candidate]
    )
    if not isinstance(tree, str) or not re.fullmatch(r"[0-9a-f]{40}", tree):
        raise PacketError("candidate tree binding is invalid")
    exact_packet_tool = run_git(
        git,
        arguments.git_sha256,
        repository,
        ["show", f"{candidate}:tools/build_windows_msix_packet.py"],
        binary=True,
    )
    if (
        not isinstance(exact_packet_tool, bytes)
        or exact_packet_tool != Path(__file__).resolve(strict=True).read_bytes()
    ):
        raise PacketError("executing packet builder is not the exact candidate tool")

    output = arguments.output.resolve()
    if output.exists() or output.suffix.lower() != ".zip":
        raise PacketError("packet output must be a new ZIP")
    if output == repository or repository in output.parents:
        raise PacketError("packet output must be external to the repository")
    output.parent.mkdir(parents=True, exist_ok=True)
    wheelhouse = arguments.wheelhouse.resolve(strict=True)
    plain_directory(wheelhouse, "wheelhouse")
    observed_wheels = {
        path.name
        for path in wheelhouse.iterdir()
        if path.is_file() and not path.is_symlink()
    }
    if observed_wheels != set(WHEELS) or any(path.is_dir() for path in wheelhouse.iterdir()):
        raise PacketError("wheelhouse inventory is not exact")

    files, source_manifest = source_snapshot(
        git, arguments.git_sha256, repository, candidate, tree
    )
    files["source-manifest.json"] = source_manifest
    files["START-HERE.md"] = start_here(candidate, tree)
    inputs = (
        ("sos.exe", arguments.sos_launcher, "SOS launcher", b"MZ"),
        (
            "sos-launcher.exe",
            arguments.store_entrypoint,
            "SOS Store entrypoint",
            b"MZ",
        ),
        ("uv.exe", arguments.uv, "uv executable", b"MZ"),
        (
            "windows-python-runtime-3.12.14.zip",
            arguments.python_runtime,
            "managed Python runtime",
            b"PK",
        ),
    )
    bound_inputs: dict[str, bytes] = {}
    for relative, supplied, label, magic in inputs:
        path = supplied.resolve(strict=True)
        value = read_bound_input(path, label)
        if not value.startswith(magic):
            raise PacketError(f"{label} magic is invalid")
        bound_inputs[relative] = value
        files[relative] = value
    if pe_subsystem(bound_inputs["sos.exe"], "SOS command launcher") != 3:
        raise PacketError("SOS command launcher is not a console PE")
    if COMMAND_LAUNCHER_CONTRACT not in bound_inputs["sos.exe"]:
        raise PacketError("SOS command launcher contract is invalid")
    if pe_subsystem(bound_inputs["sos-launcher.exe"], "SOS Store entrypoint") != 2:
        raise PacketError("SOS Store entrypoint is not a GUI PE")
    for label, value in (
        ("SOS command launcher", bound_inputs["sos.exe"]),
        ("SOS Store entrypoint", bound_inputs["sos-launcher.exe"]),
    ):
        if candidate.encode("ascii") not in value:
            raise PacketError(f"{label} is not bound to the exact candidate")
    bound_wheels: dict[str, bytes] = {}
    for name in WHEELS:
        value = read_bound_input(wheelhouse / name, "wheelhouse artifact")
        if not value.startswith(b"PK"):
            raise PacketError("wheelhouse artifact magic is invalid")
        bound_wheels[name] = value
        files[f"wheelhouse/{name}"] = value

    makeappx_path = (
        f"Windows Kits/10/bin/{arguments.sdk_version}/x64/MakeAppx.exe"
    )
    input_lock = build_input_lock(
        candidate=candidate,
        tree=tree,
        git_digest=arguments.git_sha256,
        git_version=git_version,
        go_digest=arguments.go_sha256,
        go_version=go_version,
        makeappx_path=makeappx_path,
        makeappx_digest=arguments.makeappx_sha256,
        makeappx_size=arguments.makeappx_size,
        source_manifest=source_manifest,
        sos_launcher=bound_inputs["sos.exe"],
        store_entrypoint=bound_inputs["sos-launcher.exe"],
        uv=bound_inputs["uv.exe"],
        python_runtime=bound_inputs["windows-python-runtime-3.12.14.zip"],
        wheels=bound_wheels,
    )
    input_lock_digest = hashlib.sha256(input_lock).hexdigest()
    files["input-lock.json"] = input_lock
    files["Build-SOS-MSIX.exe"] = build_native_runner(
        git,
        arguments.git_sha256,
        repository,
        candidate,
        tree,
        go,
        arguments.go_sha256,
        input_lock_digest,
    )

    packet_files = [entry(path, value) for path, value in sorted(files.items())]
    runner_path = "Build-SOS-MSIX.exe"
    input_lock_path = "input-lock.json"
    source_root = "source"
    source_manifest_path = "source-manifest.json"
    runtime_path = "windows-python-runtime-3.12.14.zip"
    sos_path = "sos.exe"
    store_entrypoint_path = "sos-launcher.exe"
    uv_path = "uv.exe"
    wheels = [f"wheelhouse/{name}" for name in WHEELS]
    packet_record: dict[str, object] = {
        "candidate": candidate,
        "contract": PACKET_CONTRACT,
        "file_count": len(packet_files),
        "files": packet_files,
        "inventory_digest": inventory_digest(packet_files),
        "input_lock": input_lock_path,
        "makeappx": {
            "program_files_x86_relative_path": makeappx_path,
            "sha256": arguments.makeappx_sha256,
            "size": arguments.makeappx_size,
        },
        "python_runtime": runtime_path,
        "runner": runner_path,
        "sos_launcher": sos_path,
        "store_entrypoint": store_entrypoint_path,
        "source_manifest": source_manifest_path,
        "source_root": source_root,
        "tree": tree,
        "uv": uv_path,
        "wheelhouse": wheels,
    }
    files["packet-manifest.json"] = canonical_json(packet_record)
    root_name = f"SOS-Windows-Store-Build-{candidate[:7]}"
    with tempfile.TemporaryDirectory(prefix="sos-msix-packet-") as temporary:
        first = Path(temporary) / "first.zip"
        second = Path(temporary) / "second.zip"
        write_zip(first, root_name, files)
        write_zip(second, root_name, files)
        first_digest = sha256(first)
        if first_digest != sha256(second) or first.read_bytes() != second.read_bytes():
            raise PacketError("two packet builds are not byte-identical")
        shutil.copyfile(first, output)
    if sha256(output) != first_digest:
        raise PacketError("final packet drifted during publication")
    if run_git(git, arguments.git_sha256, repository, ["status", "--porcelain"]):
        raise PacketError("repository changed during packet construction")
    if run_git(git, arguments.git_sha256, repository, ["rev-parse", "HEAD"]) != candidate:
        raise PacketError("repository candidate changed during packet construction")
    report = {
        "candidate": candidate,
        "contract": "sos_windows_msix_build_packet_result_v1",
        "file_count": len(files),
        "input_lock_sha256": f"sha256:{input_lock_digest}",
        "makeappx_sha256": f"sha256:{arguments.makeappx_sha256}",
        "packet_sha256": f"sha256:{first_digest}",
        "raw_content_serialized": False,
        "status": "passed",
        "tree": tree,
    }
    print(json.dumps(report, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (PacketError, OSError, subprocess.SubprocessError, zipfile.BadZipFile) as error:
        print(f"SOS_MSIX_PACKET_BUILD_FAILED: {error}", file=sys.stderr)
        raise SystemExit(2)
