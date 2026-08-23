"""Provider-neutral, read-only MCP stdio adapter over the SOS decision core."""

from __future__ import annotations

import json
import sys
from collections.abc import Iterable
from typing import Any, TextIO

from . import __version__
from .agent_api import project_tool
from .repository import RepositoryError
from .workspace import WorkspaceError


_MAX_MESSAGE_BYTES = 1024 * 1024
_MAX_OUTPUT_BYTES = 1024 * 1024
_TOOLS = (
    {
        "name": "sos_status",
        "description": "Read repository-bound SOS currentness without modifying the project.",
        "inputSchema": {"type": "object", "properties": {}, "additionalProperties": False},
        "annotations": {"readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": False},
    },
    {
        "name": "sos_preflight",
        "description": "Check whether bootstrap, source binding and local qualification are ready for an agent.",
        "inputSchema": {"type": "object", "properties": {}, "additionalProperties": False},
        "annotations": {"readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": False},
    },
    {
        "name": "sos_active_task",
        "description": "Read the accepted current-work reference without returning project content.",
        "inputSchema": {"type": "object", "properties": {}, "additionalProperties": False},
        "annotations": {"readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": False},
    },
    {
        "name": "sos_next_action",
        "description": "Read the accepted bounded next action and stop conditions.",
        "inputSchema": {"type": "object", "properties": {}, "additionalProperties": False},
        "annotations": {"readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": False},
    },
    {
        "name": "sos_qualification_plan",
        "description": "Project one registered qualification family without executing it.",
        "inputSchema": {
            "type": "object",
            "properties": {"family_id": {"type": "string", "minLength": 1, "maxLength": 128}},
            "additionalProperties": False,
        },
        "annotations": {"readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": False},
    },
    {
        "name": "sos_recover",
        "description": "Return authority paths, current work, boundaries, checks and the next safe action.",
        "inputSchema": {"type": "object", "properties": {}, "additionalProperties": False},
        "annotations": {"readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": False},
    },
    {
        "name": "sos_propose_qualification_receipt",
        "description": "Replay the current receipt tip and return a proposal-only projection.",
        "inputSchema": {"type": "object", "properties": {}, "additionalProperties": False},
        "annotations": {"readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": False},
    },
    {
        "name": "sos_propose_update",
        "description": "Read local package binding and propose an exact update without executing it.",
        "inputSchema": {"type": "object", "properties": {}, "additionalProperties": False},
        "annotations": {"readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": False},
    },
)


def handle_message(message: dict[str, Any], root: str) -> dict[str, Any] | None:
    request_id = message.get("id")
    method = message.get("method")
    if request_id is None:
        return None
    if method == "initialize":
        params = message.get("params") if isinstance(message.get("params"), dict) else {}
        requested_version = params.get("protocolVersion")
        version = requested_version if isinstance(requested_version, str) else "2024-11-05"
        return _result(
            request_id,
            {
                "protocolVersion": version,
                "capabilities": {"tools": {"listChanged": False}},
                "serverInfo": {"name": "sigma-operator-stack", "version": __version__},
                "instructions": "Read-only project authority and recovery. No acceptance or action tools are exposed.",
            },
        )
    if method == "ping":
        return _result(request_id, {})
    if method == "tools/list":
        return _result(request_id, {"tools": list(_TOOLS)})
    if method == "tools/call":
        params = message.get("params")
        if not isinstance(params, dict) or not isinstance(params.get("name"), str):
            return _error(request_id, -32602, "Invalid tool call")
        arguments = params.get("arguments", {})
        if not isinstance(arguments, dict):
            return _error(request_id, -32602, "Tool arguments are closed")
        name = params["name"]
        try:
            payload = project_tool(root, name, arguments).to_dict()
        except (RepositoryError, WorkspaceError) as exc:
            reason = exc.reason if isinstance(exc, RepositoryError) else str(exc)
            payload = {"contract": "sos_mcp_tool_result_v1", "status": "invalid", "reasons": [reason]}
        text = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
        if len(text.encode("utf-8")) > _MAX_OUTPUT_BYTES:
            payload = {
                "contract": "sos_mcp_tool_result_v1",
                "status": "invalid",
                "reasons": ["SOS_MCP_OUTPUT_LIMIT_EXCEEDED"],
            }
            text = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
        is_error = payload.get("status") in {"invalid", "blocked"}
        return _result(
            request_id,
            {
                "content": [{"type": "text", "text": text}],
                "structuredContent": payload,
                "isError": is_error,
            },
        )
    return _error(request_id, -32601, "Method not found")


def serve_stdio(root: str, *, stdin: TextIO = sys.stdin, stdout: TextIO = sys.stdout) -> int:
    for line in _bounded_lines(stdin):
        try:
            value = json.loads(line)
        except json.JSONDecodeError:
            response = _error(None, -32700, "Parse error")
        else:
            if not isinstance(value, dict):
                response = _error(None, -32600, "Invalid Request")
            else:
                response = handle_message(value, root)
        if response is not None:
            stdout.write(json.dumps(response, sort_keys=True, separators=(",", ":"), ensure_ascii=False) + "\n")
            stdout.flush()
    return 0


def _bounded_lines(stream: TextIO) -> Iterable[str]:
    while True:
        line = stream.readline(_MAX_MESSAGE_BYTES + 1)
        if not line:
            return
        if len(line.encode("utf-8")) > _MAX_MESSAGE_BYTES or not line.endswith("\n"):
            yield "{"
            return
        yield line


def _result(request_id: object, result: object) -> dict[str, Any]:
    return {"jsonrpc": "2.0", "id": request_id, "result": result}


def _error(request_id: object, code: int, message: str) -> dict[str, Any]:
    return {"jsonrpc": "2.0", "id": request_id, "error": {"code": code, "message": message}}
