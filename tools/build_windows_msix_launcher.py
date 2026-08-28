#!/usr/bin/env python3
"""Build the exact immutable-payload SOS MSIX command alias."""

from __future__ import annotations

import argparse
import hashlib
import io
import json
import os
import subprocess
import sys
import tarfile
import tempfile
from pathlib import Path

GO_VERSION = "go1.27.0"


def run(argv: list[str], *, cwd: Path | None = None, env: dict[str, str] | None = None) -> str:
    return subprocess.run(
        argv, cwd=cwd, env=env, check=True, stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
    ).stdout.strip()


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
    candidate = run(["git", "-C", os.fspath(repository), "rev-parse", "--verify", f"{args.candidate}^{{commit}}"])
    if candidate != run(["git", "-C", os.fspath(repository), "rev-parse", "HEAD"]):
        raise SystemExit("candidate does not match repository HEAD")
    tree = run(["git", "-C", os.fspath(repository), "show", "-s", "--format=%T", candidate])
    if not run([os.fspath(args.go), "version"]).startswith(f"go version {GO_VERSION} "):
        raise SystemExit("pinned Go toolchain mismatch")
    output = args.output.resolve()
    output.parent.mkdir(parents=True, exist_ok=True)
    archive = subprocess.run(
        ["git", "-C", os.fspath(repository), "archive", "--format=tar", candidate, "--", "installers/windows-msix", "installers/windows-installer/application.manifest", "tools/windows_pe_manifest.py"],
        check=True, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
    ).stdout
    with tempfile.TemporaryDirectory(prefix="sos-msix-launcher-") as temporary:
        source = Path(temporary)
        with tarfile.open(fileobj=io.BytesIO(archive), mode="r:") as bundle:
            bundle.extractall(source, filter="data")
        project = source / "installers" / "windows-msix"
        manifest = source / "installers" / "windows-installer" / "application.manifest"
        manifest_tool = source / "tools" / "windows_pe_manifest.py"
        resource = project / "rsrc_windows_amd64.syso"
        run([sys.executable, os.fspath(manifest_tool), "build-resource", "--manifest", os.fspath(manifest), "--output", os.fspath(resource)])
        environment = {
            "CGO_ENABLED": "0", "GO111MODULE": "on", "GOARCH": "amd64", "GOENV": "off", "GOOS": "windows",
            "GOCACHE": os.fspath(output.parent / ".gocache"), "GOPATH": os.fspath(output.parent / ".gopath"),
            "HOME": os.fspath(output.parent / ".home"), "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8",
            "PATH": os.environ.get("PATH", ""), "TZ": "UTC",
        }
        run([os.fspath(args.go), "build", "-buildvcs=false", "-trimpath", "-ldflags", f"-buildid= -s -w -X main.candidate={candidate}", "-o", os.fspath(output), "."], cwd=project, env=environment)
        verification = json.loads(run([sys.executable, os.fspath(manifest_tool), "verify-pe", "--manifest", os.fspath(manifest), "--pe", os.fspath(output)]))
    payload = output.read_bytes()
    if not payload.startswith(b"MZ") or candidate.encode("ascii") not in payload:
        raise SystemExit("MSIX launcher is not bound to the exact candidate")
    print(json.dumps({
        "candidate": candidate, "contract": "sos_windows_msix_launcher_build_v1",
        "manifest_sha256": verification["manifest_sha256"], "sha256": hashlib.sha256(payload).hexdigest(),
        "status": "passed", "tree": tree,
    }, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
