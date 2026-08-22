#!/usr/bin/env python3
"""Build one digest-reproducible SOS wheel from an exact Git commit."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tarfile
import tempfile
from pathlib import Path


def _run(argv: list[str], *, cwd: Path, env: dict[str, str] | None = None) -> str:
    completed = subprocess.run(
        argv,
        cwd=cwd,
        env=env,
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    return completed.stdout.strip()


def _git(repo: Path, *args: str) -> str:
    return _run(["git", "-C", os.fspath(repo), *args], cwd=repo)


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _outside_repository(repo: Path, output_dir: Path) -> None:
    if output_dir == repo or repo in output_dir.parents:
        raise ValueError("output directory must be outside the Git repository")


def _publish_once(source: Path, destination: Path) -> None:
    digest = _sha256(source)
    if destination.exists():
        if not destination.is_file() or _sha256(destination) != digest:
            raise FileExistsError("output wheel already exists with different bytes")
        return
    destination.parent.mkdir(parents=True, exist_ok=True)
    descriptor = os.open(
        destination,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL,
        0o644,
    )
    try:
        with source.open("rb") as reader, os.fdopen(descriptor, "wb") as writer:
            descriptor = -1
            shutil.copyfileobj(reader, writer, length=1024 * 1024)
            writer.flush()
            os.fsync(writer.fileno())
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def build_release_wheel(repo: Path, candidate_ref: str, output_dir: Path) -> dict[str, object]:
    repo = repo.resolve(strict=True)
    output_dir = output_dir.resolve()
    _outside_repository(repo, output_dir)

    candidate = _git(repo, "rev-parse", "--verify", f"{candidate_ref}^{{commit}}")
    if len(candidate) != 40 or any(character not in "0123456789abcdef" for character in candidate):
        raise ValueError("Git did not return a canonical commit identifier")
    tree = _git(repo, "show", "-s", "--format=%T", candidate)
    source_date_epoch_text = _git(repo, "show", "-s", "--format=%ct", candidate)
    source_date_epoch = int(source_date_epoch_text)
    if source_date_epoch < 315532800:
        raise ValueError("candidate timestamp predates the wheel ZIP epoch")

    with tempfile.TemporaryDirectory(prefix="sos-release-wheel-") as temporary:
        temporary_root = Path(temporary)
        archive = temporary_root / "source.tar"
        source_root = temporary_root / "source"
        wheel_root = temporary_root / "wheel"
        source_root.mkdir()
        wheel_root.mkdir()

        _run(
            [
                "git",
                "-C",
                os.fspath(repo),
                "archive",
                "--format=tar",
                f"--output={archive}",
                candidate,
            ],
            cwd=repo,
        )
        with tarfile.open(archive, mode="r:") as bundle:
            bundle.extractall(source_root, filter="data")

        environment = {
            "HOME": os.fspath(temporary_root / "home"),
            "LANG": "C.UTF-8",
            "LC_ALL": "C.UTF-8",
            "PATH": os.environ.get("PATH", ""),
            "PIP_DISABLE_PIP_VERSION_CHECK": "1",
            "PIP_NO_INDEX": "1",
            "PYTHONHASHSEED": "0",
            "SOURCE_DATE_EPOCH": str(source_date_epoch),
            "TZ": "UTC",
        }
        (temporary_root / "home").mkdir()
        _run(
            [
                sys.executable,
                "-m",
                "pip",
                "--isolated",
                "--disable-pip-version-check",
                "wheel",
                "--no-cache-dir",
                "--no-index",
                "--no-deps",
                "--no-build-isolation",
                "--wheel-dir",
                os.fspath(wheel_root),
                ".",
            ],
            cwd=source_root,
            env=environment,
        )
        wheels = tuple(wheel_root.glob("*.whl"))
        if len(wheels) != 1:
            raise RuntimeError("build must produce exactly one wheel")
        wheel = wheels[0]
        destination = output_dir / wheel.name
        _publish_once(wheel, destination)

    return {
        "candidate": candidate,
        "filename": destination.name,
        "network_allowed": False,
        "sha256": _sha256(destination),
        "source_date_epoch": source_date_epoch,
        "tree": tree,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Build a deterministic SOS wheel from an exact Git commit."
    )
    parser.add_argument("--candidate", required=True, help="Exact Git commit or ref")
    parser.add_argument("--output-dir", required=True, type=Path)
    parser.add_argument("--repository", type=Path, default=Path.cwd())
    arguments = parser.parse_args(argv)
    try:
        result = build_release_wheel(
            arguments.repository,
            arguments.candidate,
            arguments.output_dir,
        )
    except (FileExistsError, OSError, RuntimeError, ValueError, subprocess.CalledProcessError) as error:
        print(
            json.dumps(
                {
                    "failure_code": "SOS_WHEEL_BUILD_FAILED",
                    "message": str(error),
                    "status": "failed",
                },
                sort_keys=True,
                separators=(",", ":"),
            )
        )
        return 1
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
