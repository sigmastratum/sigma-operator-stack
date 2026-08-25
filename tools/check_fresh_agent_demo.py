#!/usr/bin/env python3
"""Replay the synthetic SOS tutorial without network or provider calls."""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, os.fspath(ROOT / "src"))

from sos.agent_api import project_tool
from sos.client_integration import LauncherBinding
from sos.compatibility import compatibility_status
from sos.lifecycle import execute_one_command_init, prepare_one_command_init
from sos.workspace import qualify_once

from reset_fresh_agent_demo import reset


EXPECTED = ROOT / "examples" / "fresh-agent-recovery" / "expected.json"


def _reason(payload: dict[str, object]) -> str:
    reasons = payload.get("reasons")
    if isinstance(reasons, list) and reasons:
        return str(reasons[0])
    return ""


def _cli(root: Path, command: str) -> tuple[int, dict[str, object]]:
    environment = {
        "PATH": os.environ.get("PATH", ""),
        "PYTHONPATH": os.fspath(ROOT / "src"),
        "PYTHONHASHSEED": "0",
    }
    completed = subprocess.run(
        [sys.executable, "-m", "sos", command, os.fspath(root), "--json"],
        cwd=os.fspath(ROOT),
        env=environment,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        timeout=30,
        check=False,
    )
    return completed.returncode, json.loads(completed.stdout)


def main() -> int:
    expected = json.loads(EXPECTED.read_text(encoding="utf-8"))
    wanted = {step["name"]: step for step in expected["steps"]}
    observed: list[dict[str, object]] = []
    with tempfile.TemporaryDirectory(prefix="sos-public-demo-") as directory:
        project = Path(directory) / "project"
        reset(project)

        compatibility = compatibility_status(project).to_dict()
        observed.append(
            {
                "name": "compatibility",
                "exit_code": 2,
                "status": compatibility["status"],
                "reason": _reason(compatibility),
            }
        )

        binding = LauncherBinding(
            os.fspath(Path(sys.executable)), "0.1.0a1", "sha256:" + "d" * 64
        )
        plan = prepare_one_command_init(
            project,
            launcher=binding,
            primary_authority_id="agents:AGENTS.md",
        )
        installed = execute_one_command_init(
            plan, confirmed=True, controlling_tty_observed=True
        ).to_dict()
        observed.append(
            {
                "name": "init",
                "exit_code": 0,
                "status": installed["status"],
                "reason": _reason(installed),
            }
        )

        preflight = project_tool(project, "sos_preflight").to_dict()
        observed.append(
            {
                "name": "preflight_before_qualification",
                "exit_code": 2,
                "status": preflight["status"],
                "reason": _reason(preflight),
            }
        )

        _, _, receipt = qualify_once(
            project,
            family_id="python.stdlib-unittest",
            confirmed=True,
            controlling_tty_observed=True,
        )
        observed.append(
            {
                "name": "qualify_python_unittest",
                "exit_code": 0 if receipt["status"] == "passed_local" else 2,
                "status": receipt["status"],
                "reason": receipt["reasons"][0],
            }
        )

        exit_code, fresh = _cli(project, "status")
        observed.append(
            {
                "name": "fresh_recovery",
                "exit_code": exit_code,
                "status": fresh["status"],
                "reason": _reason(fresh),
            }
        )

        source = project / "src" / "demo_app.py"
        source.write_text(source.read_text(encoding="utf-8") + "\n# synthetic source change\n", encoding="utf-8")
        exit_code, stale = _cli(project, "status")
        observed.append(
            {
                "name": "source_change",
                "exit_code": exit_code,
                "status": stale["status"],
                "reason": _reason(stale),
            }
        )
        exit_code, next_action = _cli(project, "next-action")
        observed.append(
            {
                "name": "safe_next_action",
                "exit_code": exit_code,
                "status": next_action["status"],
                "reason": _reason(next_action),
            }
        )

    failures = [item for item in observed if item != wanted[item["name"]]]
    report = {
        "contract": "sos_fresh_agent_recovery_replay_v1",
        "failures": failures,
        "provider_calls": 0,
        "network_calls": 0,
        "steps": observed,
        "status": "passed" if not failures else "failed",
    }
    print(json.dumps(report, sort_keys=True, separators=(",", ":")))
    return 0 if not failures else 1


if __name__ == "__main__":
    raise SystemExit(main())
