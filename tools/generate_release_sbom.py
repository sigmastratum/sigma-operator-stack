#!/usr/bin/env python3
"""Generate a deterministic, content-safe CycloneDX SBOM from an installed wheel environment."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
import tempfile
import uuid
from pathlib import Path


def generate(
    candidate: str,
    wheel: Path,
    pyproject: Path,
    environment_python: Path | None = None,
) -> dict[str, object]:
    if not re.fullmatch(r"[0-9a-f]{40}", candidate):
        raise ValueError("candidate must be an exact SHA-1 commit")
    wheel_bytes = wheel.resolve(strict=True).read_bytes()
    wheel_digest = hashlib.sha256(wheel_bytes).hexdigest()
    pyproject = pyproject.resolve(strict=True)
    tool_python = Path(sys.executable).absolute()
    executable = tool_python.with_name("cyclonedx-py")
    if not executable.is_file():
        raise RuntimeError("cyclonedx-py is not installed in the exact wheel environment")
    # Preserve the virtual-environment entry point.  Resolving this symlink
    # selects the base interpreter and makes CycloneDX observe the host
    # environment instead of the exact installed-wheel environment.
    python = (environment_python or tool_python).absolute()
    if not python.is_file():
        raise RuntimeError("installed-wheel environment Python is unavailable")
    with tempfile.TemporaryDirectory(prefix="sos-cyclonedx-") as temporary:
        temporary_root = Path(temporary)
        raw_output = temporary_root / "raw.json"
        home = temporary_root / "home"
        home.mkdir()
        subprocess.run(
            [
                os.fspath(executable),
                "environment",
                "--pyproject",
                os.fspath(pyproject),
                "--mc-type",
                "application",
                "--sv",
                "1.6",
                "--output-reproducible",
                "--of",
                "JSON",
                "--output-file",
                os.fspath(raw_output),
                "--validate",
                os.fspath(python),
            ],
            check=True,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env={"HOME": os.fspath(home), "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8", "PYTHONHASHSEED": "0"},
        )
        document = json.loads(raw_output.read_text(encoding="utf-8"))
    root = document.get("metadata", {}).get("component", {})
    if root.get("name") != "sigma-operator-stack" or root.get("version") != "0.1.0a3":
        raise RuntimeError("CycloneDX root component does not match the installed alpha")
    properties = [
        item
        for item in document.get("metadata", {}).get("properties", [])
        if item.get("name") not in {"sos:candidate", "sos:wheel:sha256"}
    ]
    properties.extend(
        [
            {"name": "sos:candidate", "value": candidate},
            {"name": "sos:wheel:sha256", "value": wheel_digest},
        ]
    )
    document["metadata"]["properties"] = sorted(properties, key=lambda item: item["name"])
    serial_seed = f"{candidate}:{wheel_digest}:" + ",".join(
        f"{component.get('name')}={component.get('version')}" for component in document.get("components", [])
    )
    document["serialNumber"] = f"urn:uuid:{uuid.uuid5(uuid.NAMESPACE_URL, serial_seed)}"
    return document


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--candidate", required=True)
    parser.add_argument("--wheel", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--pyproject", type=Path, default=Path("pyproject.toml"))
    parser.add_argument("--environment-python", type=Path)
    arguments = parser.parse_args(argv)
    try:
        document = generate(
            arguments.candidate,
            arguments.wheel,
            arguments.pyproject,
            arguments.environment_python,
        )
        encoded = (json.dumps(document, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")
        output = arguments.output.resolve()
        output.parent.mkdir(parents=True, exist_ok=True)
        if output.exists() and output.read_bytes() != encoded:
            raise FileExistsError("SBOM output exists with different bytes")
        output.write_bytes(encoded)
    except (FileExistsError, json.JSONDecodeError, OSError, RuntimeError, ValueError, subprocess.CalledProcessError) as error:
        print(json.dumps({"failure_code": "SOS_SBOM_FAILED", "message": str(error), "status": "failed"}, sort_keys=True))
        return 1
    print(json.dumps({"filename": output.name, "sha256": hashlib.sha256(encoded).hexdigest(), "status": "passed"}, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
