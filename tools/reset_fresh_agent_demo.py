#!/usr/bin/env python3
"""Create or reset only a marker-owned disposable SOS demo repository."""

from __future__ import annotations

import argparse
import shutil
import subprocess
from pathlib import Path


MARKER = ".sos-demo-root"
MARKER_VALUE = "sos_fresh_agent_recovery_demo_v1\n"


def reset(target: Path) -> None:
    target = target.expanduser().resolve(strict=False)
    template = Path(__file__).resolve().parents[1] / "examples" / "fresh-agent-recovery"
    if target == template or template in target.parents:
        raise SystemExit("SOS_DEMO_TARGET_FORBIDDEN")
    if target.exists():
        marker = target / MARKER
        if not target.is_dir() or not marker.is_file():
            raise SystemExit("SOS_DEMO_TARGET_NOT_MARKER_OWNED")
        if marker.read_text(encoding="utf-8") != MARKER_VALUE:
            raise SystemExit("SOS_DEMO_TARGET_MARKER_INVALID")
        shutil.rmtree(target)
    target.parent.mkdir(parents=True, exist_ok=True)
    shutil.copytree(template, target, symlinks=False)
    subprocess.run(["git", "-C", str(target), "init", "-q"], check=True)
    subprocess.run(
        ["git", "-C", str(target), "config", "user.name", "Synthetic Operator"],
        check=True,
    )
    subprocess.run(
        ["git", "-C", str(target), "config", "user.email", "synthetic@example.invalid"],
        check=True,
    )
    subprocess.run(["git", "-C", str(target), "add", "."], check=True)
    subprocess.run(
        ["git", "-C", str(target), "commit", "-qm", "synthetic demo baseline"],
        check=True,
    )
    print("SOS_DEMO_RESET_READY")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("target", type=Path)
    args = parser.parse_args()
    reset(args.target)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
