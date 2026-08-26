#!/usr/bin/env python3
"""Run one approved ephemeral Codex recovery and retain no raw conversation."""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import tempfile
import tomllib
from pathlib import Path

from verify_fresh_codex_capture import verify


TOOLS = (
    "sos_status",
    "sos_preflight",
    "sos_active_task",
    "sos_next_action",
    "sos_qualification_plan",
    "sos_recover",
    "sos_propose_qualification_receipt",
    "sos_propose_update",
)
CLIENT = re.compile(r"^codex-cli [0-9]+\.[0-9]+\.[0-9]+$")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--project", required=True, type=Path)
    parser.add_argument("--task-file", required=True, type=Path)
    parser.add_argument("--codex", required=True, type=Path)
    parser.add_argument("--model", required=True)
    parser.add_argument("--candidate", required=True)
    parser.add_argument("--tree", required=True)
    parser.add_argument("--wheel-sha256", required=True)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    if os.environ.get("SOS_FRESH_CODEX_PROVIDER_APPROVED") != "1":
        raise SystemExit("SOS_DEMO_PROVIDER_APPROVAL_REQUIRED")

    project = args.project.resolve(strict=True)
    task_file = args.task_file.resolve(strict=True)
    codex = args.codex.resolve(strict=True)
    config = tomllib.loads((project / ".codex" / "config.toml").read_text(encoding="utf-8"))
    server = config.get("mcp_servers", {}).get("sigma_operator_stack")
    if not isinstance(server, dict) or server.get("enabled_tools") != list(TOOLS):
        raise SystemExit("SOS_DEMO_MCP_CONFIG_INVALID")
    command = server.get("command")
    server_args = server.get("args")
    cwd = server.get("cwd")
    if not isinstance(command, str) or not isinstance(server_args, list) or cwd != os.fspath(project):
        raise SystemExit("SOS_DEMO_MCP_CONFIG_INVALID")

    client = subprocess.run(
        [os.fspath(codex), "--version"],
        check=True,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        timeout=10,
    ).stdout.strip()
    if not CLIENT.fullmatch(client):
        raise SystemExit("SOS_DEMO_CODEX_VERSION_INVALID")

    schema = Path(__file__).with_name("fresh-codex-output.schema.json").resolve(strict=True)
    with tempfile.TemporaryDirectory(prefix="sos-fresh-codex-capture-") as directory:
        temporary = Path(directory)
        events = temporary / "events.jsonl"
        response = temporary / "response.json"
        argv = [
            os.fspath(codex),
            "exec",
            "--ignore-user-config",
            "--strict-config",
            "--model",
            args.model,
            "--sandbox",
            "read-only",
            "--cd",
            os.fspath(project),
            "--ephemeral",
            "--json",
            "--output-schema",
            os.fspath(schema),
            "--output-last-message",
            os.fspath(response),
            "--config",
            f'mcp_servers.sigma_operator_stack.command="{command}"',
            "--config",
            "mcp_servers.sigma_operator_stack.args=" + json.dumps(server_args),
            "--config",
            f'mcp_servers.sigma_operator_stack.cwd="{cwd}"',
            "--config",
            "mcp_servers.sigma_operator_stack.enabled=true",
            "--config",
            "mcp_servers.sigma_operator_stack.required=true",
            "--config",
            "mcp_servers.sigma_operator_stack.enabled_tools=" + json.dumps(list(TOOLS)),
            "-",
        ]
        with task_file.open("rb") as task, events.open("wb") as event_output:
            completed = subprocess.run(
                argv,
                check=False,
                stdin=task,
                stdout=event_output,
                stderr=subprocess.PIPE,
                timeout=120,
            )
        if completed.returncode != 0:
            raise SystemExit("SOS_DEMO_FRESH_CODEX_FAILED")
        receipt = verify(
            events,
            response,
            candidate=args.candidate,
            tree=args.tree,
            wheel_sha256=args.wheel_sha256,
            client=client,
            model=args.model,
        )
    args.output.write_text(
        json.dumps(receipt, sort_keys=True, separators=(",", ":")) + "\n",
        encoding="utf-8",
    )
    print("SOS_FRESH_CODEX_CAPTURE_VERIFIED")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
