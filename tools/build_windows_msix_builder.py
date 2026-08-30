#!/usr/bin/env python3
"""Build the exact native Windows MSIX build runner twice, offline."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import stat
import subprocess
import sys
import tempfile
from pathlib import Path, PurePosixPath


GO_VERSION = "go1.27.0"
MAX_SOURCE_BYTES = 8 * 1024 * 1024
SOURCE_FILES = (
    "installers/windows-installer/application.manifest",
    "installers/windows-msix-builder/archive.go",
    "installers/windows-msix-builder/go.mod",
    "installers/windows-msix-builder/job_other.go",
    "installers/windows-msix-builder/job_windows.go",
    "installers/windows-msix-builder/main.go",
    "installers/windows-msix-builder/main_test.go",
    "installers/windows-msix-builder/manifest.go",
    "installers/windows-msix-builder/output.go",
    "installers/windows-msix-builder/platform_other.go",
    "installers/windows-msix-builder/platform_windows.go",
    "installers/windows-msix-builder/reparse_other.go",
    "installers/windows-msix-builder/reparse_windows.go",
    "tools/build_windows_msix_builder.py",
    "tools/windows_pe_manifest.py",
)


class BuilderError(ValueError):
    """The exact native runner cannot be built safely."""


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for block in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def plain_file(path: Path, label: str) -> None:
    observed = path.lstat()
    if (
        not stat.S_ISREG(observed.st_mode)
        or stat.S_ISLNK(observed.st_mode)
        or getattr(observed, "st_file_attributes", 0) & 0x400
        or observed.st_size <= 0
    ):
        raise BuilderError(f"{label} is not a plain regular file")


def run(
    command: list[str],
    *,
    cwd: Path | None = None,
    environment: dict[str, str],
    binary: bool = False,
) -> bytes | str:
    completed = subprocess.run(
        command,
        cwd=cwd,
        env=environment,
        check=False,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=600,
    )
    if (
        completed.returncode != 0
        or len(completed.stdout) > MAX_SOURCE_BYTES
        or len(completed.stderr) > MAX_SOURCE_BYTES
    ):
        executable = Path(command[0]).name
        operation = (
            command[1]
            if len(command) > 1 and not command[1].startswith(("/", "\\"))
            else "run"
        )
        diagnostic = hashlib.sha256(completed.stderr).hexdigest()
        raise BuilderError(
            f"bounded {executable} {operation} failed with exit "
            f"{completed.returncode} (diagnostic sha256:{diagnostic})"
        )
    if binary:
        return completed.stdout
    try:
        return completed.stdout.decode("utf-8").strip()
    except UnicodeDecodeError as error:
        raise BuilderError("build subprocess output was not UTF-8") from error


def git_read(
    git: Path,
    expected_digest: str,
    repository: Path,
    arguments: list[str],
    *,
    binary: bool = False,
) -> bytes | str:
    if sha256(git) != expected_digest:
        raise BuilderError("Git digest drifted before source read")
    value = run(
        [os.fspath(git), "-C", os.fspath(repository), *arguments],
        environment={"LANG": "C.UTF-8", "LC_ALL": "C.UTF-8", "PATH": ""},
        binary=binary,
    )
    if sha256(git) != expected_digest:
        raise BuilderError("Git digest drifted during source read")
    return value


def write_exact_source(
    git: Path,
    git_digest: str,
    repository: Path,
    candidate: str,
    destination: Path,
) -> None:
    for relative in SOURCE_FILES:
        listing = git_read(
            git,
            git_digest,
            repository,
            ["ls-tree", candidate, "--", relative],
        )
        if not isinstance(listing, str) or not re.fullmatch(
            rf"100(?:644|755) blob [0-9a-f]{{40}}\t{re.escape(relative)}",
            listing,
        ):
            raise BuilderError("runner source contains an unsupported Git object")
        value = git_read(
            git,
            git_digest,
            repository,
            ["show", f"{candidate}:{relative}"],
            binary=True,
        )
        if not isinstance(value, bytes) or not value or len(value) > MAX_SOURCE_BYTES:
            raise BuilderError("runner source file is empty or oversized")
        target = destination / PurePosixPath(relative)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(value)


def build_once(
    source: Path,
    go: Path,
    candidate: str,
    tree: str,
    input_lock_digest: str,
    destination: Path,
    build_root: Path,
) -> dict[str, object]:
    project = source / "installers/windows-msix-builder"
    manifest = source / "installers/windows-installer/application.manifest"
    manifest_tool = source / "tools/windows_pe_manifest.py"
    resource = project / "rsrc_windows_amd64.syso"
    python_environment = {
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "PATH": "",
        "PYTHONDONTWRITEBYTECODE": "1",
        "PYTHONNOUSERSITE": "1",
        "PYTHONSAFEPATH": "1",
    }
    run(
        [
            os.fspath(Path(sys.executable).resolve(strict=True)),
            "-I",
            "-B",
            os.fspath(manifest_tool),
            "build-resource",
            "--manifest",
            os.fspath(manifest),
            "--output",
            os.fspath(resource),
        ],
        environment=python_environment,
    )
    go_environment = {
        "CGO_ENABLED": "0",
        "GO111MODULE": "on",
        "GOARCH": "amd64",
        "GOENV": "off",
        "GOOS": "windows",
        "GOCACHE": os.fspath(build_root / "gocache"),
        "GOMODCACHE": os.fspath(build_root / "gomodcache"),
        "GOPATH": os.fspath(build_root / "gopath"),
        "GOPROXY": "off",
        "GOSUMDB": "off",
        "GOTOOLCHAIN": "local",
        "HOME": os.fspath(build_root / "home"),
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "PATH": "",
        "SOURCE_DATE_EPOCH": "315532800",
        "TZ": "UTC",
    }
    for directory in ("gocache", "gomodcache", "gopath", "home"):
        (build_root / directory).mkdir(parents=True, exist_ok=True)
    modules = run(
        [os.fspath(go), "list", "-mod=readonly", "-m", "all"],
        cwd=project,
        environment=go_environment,
    )
    if modules != "github.com/sigmastratum/sigma-operator-stack/windows-msix-builder":
        raise BuilderError("runner module graph is not closed and dependency-free")
    native_test_environment = dict(go_environment)
    native_test_environment["GOOS"] = "linux"
    native_test_environment["GOARCH"] = "amd64"
    run(
        [
            os.fspath(go),
            "test",
            "-mod=readonly",
            "-count=1",
            "./...",
        ],
        cwd=project,
        environment=native_test_environment,
    )
    run(
        [
            os.fspath(go),
            "test",
            "-mod=readonly",
            "-c",
            "-o",
            os.fspath(build_root / "windows-tests.exe"),
            ".",
        ],
        cwd=project,
        environment=go_environment,
    )
    run(
        [
            os.fspath(go),
            "build",
            "-mod=readonly",
            "-buildvcs=false",
            "-trimpath",
            "-ldflags",
            (
                "-buildid= -s -w "
                f"-X main.candidate={candidate} -X main.tree={tree} "
                f"-X main.inputLockDigest={input_lock_digest}"
            ),
            "-o",
            os.fspath(destination),
            ".",
        ],
        cwd=project,
        environment=go_environment,
    )
    verification = run(
        [
            os.fspath(Path(sys.executable).resolve(strict=True)),
            "-I",
            "-B",
            os.fspath(manifest_tool),
            "verify-pe",
            "--manifest",
            os.fspath(manifest),
            "--pe",
            os.fspath(destination),
        ],
        environment=python_environment,
    )
    if not isinstance(verification, str):
        raise BuilderError("PE manifest verification output is invalid")
    record = json.loads(verification)
    payload = destination.read_bytes()
    if (
        not payload.startswith(b"MZ")
        or candidate.encode("ascii") not in payload
        or tree.encode("ascii") not in payload
        or input_lock_digest.encode("ascii") not in payload
        or record.get("status") != "passed"
        or record.get("requested_execution_level") != "asInvoker"
    ):
        raise BuilderError("native runner binary binding is invalid")
    return record


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repository", required=True, type=Path)
    parser.add_argument("--candidate", required=True)
    parser.add_argument("--git", required=True, type=Path)
    parser.add_argument("--git-sha256", required=True)
    parser.add_argument("--go", required=True, type=Path)
    parser.add_argument("--go-sha256", required=True)
    parser.add_argument("--input-lock-sha256", required=True)
    parser.add_argument("--output", required=True, type=Path)
    arguments = parser.parse_args()
    if not re.fullmatch(r"[0-9a-f]{40}", arguments.candidate):
        raise BuilderError("candidate binding is invalid")
    if not re.fullmatch(r"[0-9a-f]{64}", arguments.git_sha256):
        raise BuilderError("Git digest binding is invalid")
    if not re.fullmatch(r"[0-9a-f]{64}", arguments.go_sha256):
        raise BuilderError("Go digest binding is invalid")
    if not re.fullmatch(r"[0-9a-f]{64}", arguments.input_lock_sha256):
        raise BuilderError("input lock digest binding is invalid")
    for executable, expected, label in (
        (arguments.git, arguments.git_sha256, "Git"),
        (arguments.go, arguments.go_sha256, "Go"),
    ):
        if not executable.is_absolute():
            raise BuilderError(f"{label} executable path must be absolute")
        resolved = executable.resolve(strict=True)
        plain_file(resolved, f"{label} executable")
        if sha256(resolved) != expected:
            raise BuilderError(f"{label} executable digest mismatch")
    git = arguments.git.resolve(strict=True)
    go = arguments.go.resolve(strict=True)
    repository = arguments.repository.resolve(strict=True)
    output = arguments.output.resolve()
    if output.exists() or output.name != "Build-SOS-MSIX.exe":
        raise BuilderError("output must be a new Build-SOS-MSIX.exe")
    if repository == output or repository in output.parents:
        raise BuilderError("output must be external to the repository")
    if git_read(git, arguments.git_sha256, repository, ["status", "--porcelain"]):
        raise BuilderError("repository must be clean")
    candidate = git_read(
        git,
        arguments.git_sha256,
        repository,
        ["rev-parse", "--verify", f"{arguments.candidate}^{{commit}}"],
    )
    head = git_read(git, arguments.git_sha256, repository, ["rev-parse", "HEAD"])
    tree = git_read(
        git,
        arguments.git_sha256,
        repository,
        ["show", "-s", "--format=%T", arguments.candidate],
    )
    if (
        candidate != arguments.candidate
        or head != candidate
        or not isinstance(tree, str)
        or not re.fullmatch(r"[0-9a-f]{40}", tree)
    ):
        raise BuilderError("repository candidate/tree binding is invalid")
    go_version = run(
        [os.fspath(go), "version"],
        environment={"GOTOOLCHAIN": "local", "PATH": ""},
    )
    if not isinstance(go_version, str) or not go_version.startswith(
        f"go version {GO_VERSION} "
    ):
        raise BuilderError("pinned Go toolchain version mismatch")
    output.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="sos-msix-builder-") as temporary:
        root = Path(temporary)
        first_source = root / "first-source"
        second_source = root / "second-source"
        first_source.mkdir()
        second_source.mkdir()
        write_exact_source(
            git, arguments.git_sha256, repository, arguments.candidate, first_source
        )
        write_exact_source(
            git, arguments.git_sha256, repository, arguments.candidate, second_source
        )
        executing_tool = Path(__file__).resolve(strict=True).read_bytes()
        for exact_source in (first_source, second_source):
            if (
                exact_source / "tools/build_windows_msix_builder.py"
            ).read_bytes() != executing_tool:
                raise BuilderError("executing builder is not the exact candidate tool")
        first = root / "first.exe"
        second = root / "second.exe"
        first_manifest = build_once(
            first_source,
            go,
            arguments.candidate,
            tree,
            arguments.input_lock_sha256,
            first,
            root / "first-build",
        )
        second_manifest = build_once(
            second_source,
            go,
            arguments.candidate,
            tree,
            arguments.input_lock_sha256,
            second,
            root / "second-build",
        )
        first_bytes = first.read_bytes()
        second_bytes = second.read_bytes()
        if first_bytes != second_bytes or first_manifest != second_manifest:
            raise BuilderError("two native runner builds are not byte-identical")
        temporary_output = output.parent / f".{output.name}.tmp"
        if temporary_output.exists():
            raise BuilderError("temporary output collision")
        temporary_output.write_bytes(first_bytes)
        if temporary_output.read_bytes() != first_bytes:
            raise BuilderError("native runner output copy failed")
        temporary_output.replace(output)
        if output.read_bytes() != first_bytes:
            raise BuilderError("native runner output drifted after publication")
    if git_read(git, arguments.git_sha256, repository, ["status", "--porcelain"]):
        raise BuilderError("repository changed during native runner construction")
    if git_read(git, arguments.git_sha256, repository, ["rev-parse", "HEAD"]) != candidate:
        raise BuilderError("repository candidate changed during native runner construction")
    report = {
        "candidate": arguments.candidate,
        "contract": "sos_windows_msix_builder_build_v1",
        "go_sha256": f"sha256:{arguments.go_sha256}",
        "go_version": GO_VERSION,
        "input_lock_sha256": f"sha256:{arguments.input_lock_sha256}",
        "manifest_sha256": first_manifest["manifest_sha256"],
        "runner_sha256": f"sha256:{sha256(output)}",
        "status": "passed",
        "tree": tree,
    }
    print(json.dumps(report, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (BuilderError, OSError, subprocess.SubprocessError, json.JSONDecodeError) as error:
        print(f"SOS_MSIX_BUILDER_BUILD_FAILED: {error}", file=sys.stderr)
        raise SystemExit(2)
