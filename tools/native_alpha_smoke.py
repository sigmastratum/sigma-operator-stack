#!/usr/bin/env python3
"""Read-only, content-safe smoke report for an initialized native alpha project."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import shutil
import subprocess
from pathlib import Path


def _run(sos: str, arguments: list[str]) -> tuple[int, dict[str, object]]:
    completed = subprocess.run(
        [sos, *arguments, "--json"],
        check=False,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        timeout=30,
        env={
            "LANG": "C.UTF-8",
            "LC_ALL": "C.UTF-8",
            "PATH": os.environ.get("PATH", ""),
            "PYTHONHASHSEED": "0",
        },
    )
    if len(completed.stdout.encode("utf-8")) > 1024 * 1024:
        raise RuntimeError("SOS_NATIVE_SMOKE_OUTPUT_LIMIT")
    try:
        payload = json.loads(completed.stdout)
    except json.JSONDecodeError as exc:
        raise RuntimeError("SOS_NATIVE_SMOKE_OUTPUT_INVALID") from exc
    if not isinstance(payload, dict):
        raise RuntimeError("SOS_NATIVE_SMOKE_OUTPUT_INVALID")
    return completed.returncode, payload


def smoke(project: Path) -> dict[str, object]:
    sos = shutil.which("sos")
    if sos is None:
        raise RuntimeError("SOS_NATIVE_SMOKE_COMMAND_MISSING")
    observations: list[dict[str, object]] = []
    for name, arguments in (
        ("status", ["status", str(project)]),
        ("setup_status", ["setup", "status", "codex", str(project)]),
        ("preflight", ["preflight", str(project)]),
        ("check", ["check", str(project)]),
    ):
        exit_code, payload = _run(sos, arguments)
        observations.append(
            {
                "name": name,
                "exit_code": exit_code,
                "contract": payload.get("contract", "unknown"),
                "status": payload.get("status", "unknown"),
                "reasons": payload.get("reasons", []),
            }
        )
    material = json.dumps(observations, sort_keys=True, separators=(",", ":")).encode()
    return {
        "contract": "sos_native_private_alpha_smoke_v1",
        "system": platform.system().lower(),
        "architecture": platform.machine().lower(),
        "observations": observations,
        "report_digest": "sha256:" + hashlib.sha256(material).hexdigest(),
        "absolute_paths_serialized": False,
        "raw_content_serialized": False,
        "network_performed": False,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("project", nargs="?", type=Path, default=Path.cwd())
    args = parser.parse_args()
    try:
        report = smoke(args.project)
    except (OSError, RuntimeError, subprocess.SubprocessError) as error:
        report = {
            "contract": "sos_native_private_alpha_smoke_v1",
            "status": "failed",
            "reason": str(error),
            "absolute_paths_serialized": False,
            "raw_content_serialized": False,
            "network_performed": False,
        }
        print(json.dumps(report, sort_keys=True, separators=(",", ":")))
        return 2
    report["status"] = "passed"
    print(json.dumps(report, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
