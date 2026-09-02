#!/usr/bin/env python3
"""Build the exact candidate-bound SOS MSIX Start-menu entrypoint."""

from __future__ import annotations

import argparse
import hashlib
import io
import json
import os
import struct
import subprocess
import sys
import tarfile
import tempfile
from pathlib import Path


GO_VERSION = "go1.27.0"
WINDOWS_GUI_SUBSYSTEM = 2


def run(argv: list[str], *, cwd: Path | None = None, env: dict[str, str] | None = None) -> str:
    return subprocess.run(
        argv,
        cwd=cwd,
        env=env,
        check=True,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    ).stdout.strip()


def pe_subsystem(payload: bytes) -> int:
    if len(payload) < 0x40 or payload[:2] != b"MZ":
        raise SystemExit("Store entrypoint is not a PE image")
    pe_offset = struct.unpack_from("<I", payload, 0x3C)[0]
    if pe_offset + 24 > len(payload) or payload[pe_offset : pe_offset + 4] != b"PE\0\0":
        raise SystemExit("Store entrypoint PE header is invalid")
    optional = pe_offset + 24
    if optional + 70 > len(payload):
        raise SystemExit("Store entrypoint optional header is truncated")
    return struct.unpack_from("<H", payload, optional + 68)[0]


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repository", type=Path, default=Path.cwd())
    parser.add_argument("--candidate", required=True)
    parser.add_argument("--go", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    repository = args.repository.resolve(strict=True)
    if run(["git", "-C", os.fspath(repository), "status", "--porcelain"]):
        raise SystemExit("repository must be clean")
    candidate = run(
        ["git", "-C", os.fspath(repository), "rev-parse", "--verify", f"{args.candidate}^{{commit}}"]
    )
    if candidate != run(["git", "-C", os.fspath(repository), "rev-parse", "HEAD"]):
        raise SystemExit("candidate does not match repository HEAD")
    tree = run(["git", "-C", os.fspath(repository), "show", "-s", "--format=%T", candidate])
    if not run([os.fspath(args.go), "version"]).startswith(f"go version {GO_VERSION} "):
        raise SystemExit("pinned Go toolchain mismatch")
    output = args.output.resolve()
    output.parent.mkdir(parents=True, exist_ok=True)
    archive = subprocess.run(
        [
            "git",
            "-C",
            os.fspath(repository),
            "archive",
            "--format=tar",
            candidate,
            "--",
            "installers/windows-msix-entrypoint",
            "installers/windows-installer/application.manifest",
            "tools/windows_pe_manifest.py",
        ],
        check=True,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
    ).stdout
    with tempfile.TemporaryDirectory(prefix="sos-msix-entrypoint-") as temporary:
        source = Path(temporary)
        with tarfile.open(fileobj=io.BytesIO(archive), mode="r:") as bundle:
            bundle.extractall(source, filter="data")
        project = source / "installers" / "windows-msix-entrypoint"
        manifest = source / "installers" / "windows-installer" / "application.manifest"
        manifest_tool = source / "tools" / "windows_pe_manifest.py"
        resource = project / "rsrc_windows_amd64.syso"
        run(
            [
                sys.executable,
                os.fspath(manifest_tool),
                "build-resource",
                "--manifest",
                os.fspath(manifest),
                "--output",
                os.fspath(resource),
            ]
        )
        environment = {
            "CGO_ENABLED": "0",
            "GO111MODULE": "on",
            "GOARCH": "amd64",
            "GOENV": "off",
            "GOOS": "windows",
            "GOCACHE": os.fspath(output.parent / ".entrypoint-gocache"),
            "GOPATH": os.fspath(output.parent / ".entrypoint-gopath"),
            "HOME": os.fspath(output.parent / ".entrypoint-home"),
            "LANG": "C.UTF-8",
            "LC_ALL": "C.UTF-8",
            "PATH": os.environ.get("PATH", ""),
            "TZ": "UTC",
        }
        run(
            [
                os.fspath(args.go),
                "build",
                "-buildvcs=false",
                "-trimpath",
                "-ldflags",
                f"-buildid= -s -w -H=windowsgui -X main.candidate={candidate}",
                "-o",
                os.fspath(output),
                ".",
            ],
            cwd=project,
            env=environment,
        )
        verification = json.loads(
            run(
                [
                    sys.executable,
                    os.fspath(manifest_tool),
                    "verify-pe",
                    "--manifest",
                    os.fspath(manifest),
                    "--pe",
                    os.fspath(output),
                ]
            )
        )
    payload = output.read_bytes()
    if candidate.encode("ascii") not in payload:
        raise SystemExit("Store entrypoint is not bound to the exact candidate")
    if pe_subsystem(payload) != WINDOWS_GUI_SUBSYSTEM:
        raise SystemExit("Store entrypoint is not a Windows GUI executable")
    print(
        json.dumps(
            {
                "candidate": candidate,
                "contract": "sos_windows_msix_entrypoint_build_v1",
                "manifest_sha256": verification["manifest_sha256"],
                "sha256": hashlib.sha256(payload).hexdigest(),
                "status": "passed",
                "subsystem": "windows_gui",
                "tree": tree,
            },
            sort_keys=True,
            separators=(",", ":"),
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
