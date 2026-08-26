#!/usr/bin/env python3
"""Project a raw ephemeral Codex run into one public-safe receipt."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
from pathlib import Path


EXPECTED_OUTPUT = {
    "contract": "sos_fresh_codex_recovery_v1",
    "authority_state": "accepted_local_weak_evidence",
    "current_work_path": "tasks/current.md",
    "external_actions": "owner_required",
    "qualification_state": "passed_local",
    "safe_next_action": "review-and-qualify",
}
REQUIRED_TOOLS = {
    "sos_status",
    "sos_preflight",
    "sos_active_task",
    "sos_next_action",
}
ALLOWED_TOOLS = REQUIRED_TOOLS | {
    "sos_qualification_plan",
    "sos_recover",
    "sos_propose_qualification_receipt",
    "sos_propose_update",
}
SHA = re.compile(r"^[0-9a-f]{40}$")
DIGEST = re.compile(r"^[0-9a-f]{64}$")
CLIENT = re.compile(r"^codex-cli [0-9]+\.[0-9]+\.[0-9]+$")
MODEL = re.compile(r"^[a-z0-9][a-z0-9._-]{1,63}$")


def _digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def verify(
    events_path: Path,
    response_path: Path,
    *,
    candidate: str,
    tree: str,
    wheel_sha256: str,
    client: str,
    model: str,
) -> dict[str, object]:
    if not SHA.fullmatch(candidate) or not SHA.fullmatch(tree):
        raise ValueError("SOS_DEMO_SOURCE_BINDING_INVALID")
    if not DIGEST.fullmatch(wheel_sha256):
        raise ValueError("SOS_DEMO_WHEEL_BINDING_INVALID")
    if not CLIENT.fullmatch(client) or not MODEL.fullmatch(model):
        raise ValueError("SOS_DEMO_CLIENT_BINDING_INVALID")

    events = [
        json.loads(line)
        for line in events_path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    response = json.loads(response_path.read_text(encoding="utf-8"))
    if response != EXPECTED_OUTPUT:
        raise ValueError("SOS_DEMO_FRESH_RESPONSE_INVALID")
    event_types = [event.get("type") for event in events]
    if event_types.count("thread.started") != 1 or event_types.count("turn.completed") != 1:
        raise ValueError("SOS_DEMO_FRESH_SESSION_INCOMPLETE")
    if any(kind in {"error", "turn.failed"} for kind in event_types):
        raise ValueError("SOS_DEMO_FRESH_SESSION_FAILED")

    completed_tools: list[str] = []
    forbidden_items: list[str] = []
    for event in events:
        item = event.get("item")
        if not isinstance(item, dict):
            continue
        item_type = item.get("type")
        if item_type == "mcp_tool_call":
            if event.get("type") == "item.started":
                continue
            if event.get("type") != "item.completed":
                raise ValueError("SOS_DEMO_MCP_EVENT_INVALID")
            if item.get("server") != "sigma_operator_stack" or item.get("status") != "completed":
                raise ValueError("SOS_DEMO_MCP_CALL_INCOMPLETE")
            name = item.get("tool")
            if not isinstance(name, str) or name not in ALLOWED_TOOLS:
                raise ValueError("SOS_DEMO_MCP_TOOL_FORBIDDEN")
            completed_tools.append(name)
        elif item_type not in {"agent_message", "reasoning"}:
            forbidden_items.append(str(item_type))
    if forbidden_items:
        raise ValueError("SOS_DEMO_NON_MCP_ACTION_FORBIDDEN")
    if not REQUIRED_TOOLS.issubset(completed_tools):
        raise ValueError("SOS_DEMO_REQUIRED_MCP_TOOL_MISSING")

    return {
        "candidate": candidate,
        "client": client,
        "contract": "sos_fresh_codex_capture_receipt_v1",
        "events_sha256": _digest(events_path),
        "fresh_ephemeral_session": True,
        "mcp_server": "sigma_operator_stack",
        "mcp_tools_completed": sorted(set(completed_tools)),
        "model": model,
        "mutation_tool_calls": 0,
        "output_projection": EXPECTED_OUTPUT,
        "provider_calls": 1,
        "raw_prompt_stored": False,
        "raw_response_stored": False,
        "raw_tool_results_stored": False,
        "response_sha256": _digest(response_path),
        "shell_calls": 0,
        "status": "passed",
        "tree": tree,
        "wheel_sha256": wheel_sha256,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--events", required=True, type=Path)
    parser.add_argument("--response", required=True, type=Path)
    parser.add_argument("--candidate", required=True)
    parser.add_argument("--tree", required=True)
    parser.add_argument("--wheel-sha256", required=True)
    parser.add_argument("--client", required=True)
    parser.add_argument("--model", required=True)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    try:
        receipt = verify(
            args.events,
            args.response,
            candidate=args.candidate,
            tree=args.tree,
            wheel_sha256=args.wheel_sha256,
            client=args.client,
            model=args.model,
        )
    except (OSError, UnicodeError, json.JSONDecodeError, ValueError) as error:
        print(str(error))
        return 2
    args.output.write_text(
        json.dumps(receipt, sort_keys=True, separators=(",", ":")) + "\n",
        encoding="utf-8",
    )
    print("SOS_FRESH_CODEX_CAPTURE_VERIFIED")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
