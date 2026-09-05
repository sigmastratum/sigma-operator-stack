#!/usr/bin/env python3
"""Read-only, content-safe smoke report for an initialized native alpha project."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import subprocess
from pathlib import Path


VERSION = "0.1.0a2"
_MAX_OUTPUT_BYTES = 1024 * 1024
_EXPECTED_STATUS_REASONS = [
    "SOS_WORKSPACE_CURRENT",
    "SOS_ACCEPTANCE_ASSURANCE_WEAK_LOCAL",
]


def _closed_environment(uv: Path | None = None) -> dict[str, str]:
    environment = {
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "PATH": os.environ.get("PATH", ""),
        "PYTHONHASHSEED": "0",
    }
    if uv is not None:
        runtime_root = uv.absolute().parent.parent
        environment.update(
            {
                "UV_NO_CONFIG": "1",
                "UV_PYTHON_INSTALL_DIR": os.fspath(runtime_root / "python"),
                "UV_TOOL_BIN_DIR": os.fspath(runtime_root / "bin"),
                "UV_TOOL_DIR": os.fspath(runtime_root / "tools"),
            }
        )
    return environment


def _exact_sos(uv: Path) -> str:
    completed = subprocess.run(
        [os.fspath(uv), "tool", "dir", "--bin"],
        check=False,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        timeout=30,
        env=_closed_environment(uv),
    )
    if completed.returncode != 0 or not completed.stdout.strip():
        raise RuntimeError("SOS_NATIVE_SMOKE_TOOL_BINDING_MISSING")
    if len(completed.stdout.encode("utf-8")) > 16 * 1024:
        raise RuntimeError("SOS_NATIVE_SMOKE_TOOL_BINDING_INVALID")
    tool_dir = Path(completed.stdout.strip())
    candidates = (tool_dir / "sos.exe", tool_dir / "sos") if os.name == "nt" else (tool_dir / "sos",)
    sos = next((candidate for candidate in candidates if candidate.is_file()), None)
    if sos is None:
        raise RuntimeError("SOS_NATIVE_SMOKE_TOOL_BINDING_MISSING")
    version = subprocess.run(
        [os.fspath(sos), "--version"],
        check=False,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        timeout=30,
        env=_closed_environment(),
    )
    if version.returncode != 0 or version.stdout.strip() != f"sos {VERSION}":
        raise RuntimeError("SOS_NATIVE_SMOKE_VERSION_MISMATCH")
    return os.fspath(sos)


def _run(sos: str, arguments: list[str]) -> tuple[int, dict[str, object]]:
    completed = subprocess.run(
        [sos, *arguments, "--json"],
        check=False,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        timeout=30,
        env=_closed_environment(),
    )
    if len(completed.stdout.encode("utf-8")) > _MAX_OUTPUT_BYTES:
        raise RuntimeError("SOS_NATIVE_SMOKE_OUTPUT_LIMIT")
    try:
        payload = json.loads(completed.stdout)
    except json.JSONDecodeError as exc:
        raise RuntimeError("SOS_NATIVE_SMOKE_OUTPUT_INVALID") from exc
    if not isinstance(payload, dict):
        raise RuntimeError("SOS_NATIVE_SMOKE_OUTPUT_INVALID")
    return completed.returncode, payload


def _check_family_projection(payload: dict[str, object]) -> list[dict[str, object]]:
    families = payload.get("families")
    if not isinstance(families, list) or len(families) != 2:
        raise RuntimeError("SOS_NATIVE_SMOKE_CHECK_PLAN_INVALID")
    projected: list[dict[str, object]] = []
    expected_ids = ("python.syntax", "python.stdlib-unittest")
    for family_id, family in zip(expected_ids, families, strict=True):
        if not isinstance(family, dict) or family.get("family_id") != family_id:
            raise RuntimeError("SOS_NATIVE_SMOKE_CHECK_PLAN_INVALID")
        status = family.get("status")
        reasons = family.get("reasons")
        command_id = family.get("command_id")
        isolation = family.get("isolation")
        if family_id == "python.syntax":
            allowed = {
                ("configured", "python.compile.v1", "non-executing-structural-v1", ("SOS_CHECK_CONFIGURED",)),
                ("not_configured", None, "not_applicable", ("SOS_CHECK_NOT_CONFIGURED",)),
            }
        else:
            allowed = {
                ("unsupported", None, "unavailable", ("SOS_CAPABILITY_PLATFORM_UNSUPPORTED",)),
                ("not_configured", None, "not_applicable", ("SOS_CHECK_NOT_CONFIGURED",)),
            }
            if platform.system() == "Linux":
                allowed.add(
                    (
                        "configured",
                        "python.unittest.v1",
                        "linux-landlock-seccomp-snapshot-v1",
                        ("SOS_CHECK_CONFIGURED",),
                    )
                )
        observed = (
            status,
            command_id,
            isolation,
            tuple(reasons) if isinstance(reasons, list) else (),
        )
        if observed not in allowed:
            raise RuntimeError("SOS_NATIVE_SMOKE_CHECK_PLAN_INVALID")
        projected.append(
            {
                "family_id": family_id,
                "status": status,
                "reasons": reasons,
                "command_id": command_id,
                "isolation": isolation,
            }
        )
    return projected


def _validate_observation(
    name: str, exit_code: int, payload: dict[str, object]
) -> dict[str, object]:
    contract = payload.get("contract")
    status = payload.get("status")
    reasons = payload.get("reasons")
    expected = {
        "status": (0, "sos_workspace_status_v1", "success", _EXPECTED_STATUS_REASONS),
        "setup_status": (
            0,
            "sos_client_integration_result_v1",
            "success",
            ["SOS_CODEX_SETUP_INSTALLED"],
        ),
    }
    if name == "check":
        if exit_code != 0 or contract != "sos_check_plan_v1":
            raise RuntimeError("SOS_NATIVE_SMOKE_OBSERVATION_INVALID")
        return {
            "name": name,
            "exit_code": exit_code,
            "contract": contract,
            "families": _check_family_projection(payload),
        }
    if name == "preflight":
        allowed_preflight = {
            (2, "not_verified", ("SOS_QUALIFICATION_NOT_RUN",)),
            (2, "owner_required", ("SOS_CURRENT_WORK_NOT_CONFIGURED",)),
            (0, "success", ("SOS_READY_FOR_AGENT",)),
        }
        observed = (
            exit_code,
            status,
            tuple(reasons) if isinstance(reasons, list) else (),
        )
        if contract != "sos_preflight_result_v1" or observed not in allowed_preflight:
            raise RuntimeError("SOS_NATIVE_SMOKE_OBSERVATION_INVALID")
        return {
            "name": name,
            "exit_code": exit_code,
            "contract": contract,
            "status": status,
            "reasons": reasons,
        }
    expected_exit, expected_contract, expected_status, expected_reasons = expected[name]
    if (
        exit_code != expected_exit
        or contract != expected_contract
        or status != expected_status
        or reasons != expected_reasons
    ):
        raise RuntimeError("SOS_NATIVE_SMOKE_OBSERVATION_INVALID")
    return {
        "name": name,
        "exit_code": exit_code,
        "contract": contract,
        "status": status,
        "reasons": reasons,
    }


def smoke(project: Path, uv: Path) -> dict[str, object]:
    sos = _exact_sos(uv)
    observations: list[dict[str, object]] = []
    for name, arguments in (
        ("status", ["status", str(project)]),
        ("setup_status", ["setup", "status", "codex", str(project)]),
        ("preflight", ["preflight", str(project)]),
        ("check", ["check", str(project)]),
    ):
        exit_code, payload = _run(sos, arguments)
        observations.append(_validate_observation(name, exit_code, payload))
    material = json.dumps(observations, sort_keys=True, separators=(",", ":")).encode()
    return {
        "contract": "sos_native_alpha_smoke_v1",
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
    parser.add_argument("--uv", required=True, type=Path)
    parser.add_argument("project", nargs="?", type=Path, default=Path.cwd())
    args = parser.parse_args()
    try:
        report = smoke(args.project, args.uv)
    except (OSError, RuntimeError, subprocess.SubprocessError) as error:
        report = {
            "contract": "sos_native_alpha_smoke_v1",
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
