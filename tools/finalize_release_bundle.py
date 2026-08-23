#!/usr/bin/env python3
"""Bind an exact wheel and SBOM to one canonical public release manifest."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
import zipfile
from pathlib import Path


VERSION = "0.1.0a1"


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _git(repository: Path, *arguments: str) -> str:
    return subprocess.run(
        ["git", "-C", os.fspath(repository), *arguments],
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    ).stdout.strip()


def _verify_wheel(wheel: Path) -> None:
    expected = f"sigma_operator_stack-{VERSION}-py3-none-any.whl"
    if wheel.name != expected:
        raise ValueError("wheel filename does not match the frozen alpha")
    with zipfile.ZipFile(wheel) as archive:
        names = archive.namelist()
        metadata_name = f"sigma_operator_stack-{VERSION}.dist-info/METADATA"
        if metadata_name not in names or f"sigma_operator_stack-{VERSION}.dist-info/LICENSE" not in names:
            raise ValueError("wheel metadata or license is missing")
        value = archive.read(metadata_name).decode("utf-8")
        for required in ("Version: 0.1.0a1", "Requires-Python: <3.13,>=3.11", "License: Apache-2.0"):
            if required not in value:
                raise ValueError(f"wheel metadata mismatch: {required}")
        allowed = (
            "sos/",
            f"sigma_operator_stack-{VERSION}.dist-info/",
        )
        if any(not name.startswith(allowed) for name in names):
            raise ValueError("wheel contains a file outside the package inventory")


def finalize(repository: Path, candidate: str, wheel: Path, sbom: Path, output: Path) -> dict[str, object]:
    repository = repository.resolve(strict=True)
    output = output.resolve()
    if output == repository or repository in output.parents:
        raise ValueError("release output must be outside the repository")
    candidate = _git(repository, "rev-parse", "--verify", f"{candidate}^{{commit}}")
    if not re.fullmatch(r"[0-9a-f]{40}", candidate):
        raise ValueError("candidate is not exact")
    tree = _git(repository, "show", "-s", "--format=%T", candidate)
    epoch = int(_git(repository, "show", "-s", "--format=%ct", candidate))
    wheel = wheel.resolve(strict=True)
    sbom = sbom.resolve(strict=True)
    _verify_wheel(wheel)
    sbom_document = json.loads(sbom.read_text(encoding="utf-8"))
    if sbom_document.get("bomFormat") != "CycloneDX" or sbom_document.get("specVersion") != "1.6":
        raise ValueError("SBOM contract is invalid")
    root_component = sbom_document.get("metadata", {}).get("component", {})
    if root_component.get("name") != "sigma-operator-stack" or root_component.get("version") != VERSION:
        raise ValueError("SBOM root component does not match the frozen alpha")
    properties = {item["name"]: item["value"] for item in sbom_document["metadata"]["properties"]}
    if properties.get("sos:candidate") != candidate or properties.get("sos:wheel:sha256") != _sha256(wheel):
        raise ValueError("SBOM binding does not match candidate and wheel")

    artifacts = [
        {"filename": wheel.name, "media_type": "application/zip", "sha256": _sha256(wheel)},
        {"filename": sbom.name, "media_type": "application/vnd.cyclonedx+json", "sha256": _sha256(sbom)},
    ]
    manifest = {
        "artifacts": artifacts,
        "build": {"network_allowed": False, "source_date_epoch": epoch, "wheel_builds_equal": True},
        "candidate": candidate,
        "contract": "sos_public_release_manifest_v1",
        "tree": tree,
        "version": VERSION,
    }
    output.mkdir(parents=True, exist_ok=True)
    manifest_path = output / "release-manifest.json"
    encoded = (json.dumps(manifest, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")
    if manifest_path.exists() and manifest_path.read_bytes() != encoded:
        raise FileExistsError("release manifest exists with different bytes")
    manifest_path.write_bytes(encoded)
    sums = artifacts + [{"filename": manifest_path.name, "sha256": _sha256(manifest_path)}]
    sums_text = "".join(f"{item['sha256']}  {item['filename']}\n" for item in sorted(sums, key=lambda item: item["filename"]))
    sums_path = output / "SHA256SUMS"
    if sums_path.exists() and sums_path.read_text(encoding="utf-8") != sums_text:
        raise FileExistsError("SHA256SUMS exists with different bytes")
    sums_path.write_text(sums_text, encoding="utf-8")
    return {
        "candidate": candidate,
        "manifest_sha256": _sha256(manifest_path),
        "sbom_sha256": _sha256(sbom),
        "sha256sums_sha256": _sha256(sums_path),
        "status": "passed",
        "tree": tree,
        "wheel_sha256": _sha256(wheel),
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repository", type=Path, default=Path.cwd())
    parser.add_argument("--candidate", required=True)
    parser.add_argument("--wheel", required=True, type=Path)
    parser.add_argument("--sbom", required=True, type=Path)
    parser.add_argument("--output-dir", required=True, type=Path)
    arguments = parser.parse_args(argv)
    try:
        result = finalize(arguments.repository, arguments.candidate, arguments.wheel, arguments.sbom, arguments.output_dir)
    except (FileExistsError, KeyError, OSError, RuntimeError, ValueError, zipfile.BadZipFile, subprocess.CalledProcessError) as error:
        result = {"failure_code": "SOS_RELEASE_BUNDLE_FAILED", "message": str(error), "status": "failed"}
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0 if result["status"] == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
