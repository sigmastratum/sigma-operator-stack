"""Sigma Operator Stack command-line and local MCP entry point."""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Sequence

from .checks import discover_checks, qualify_supported
from .mcp import serve_stdio
from .repository import RepositoryError, inspect_repository
from .validation import validate_repository
from .workspace import (
    WorkspaceError,
    doctor_workspace,
    initialize_workspace,
    recover_workspace,
    store_qualification,
    workspace_status,
)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="sos")
    subparsers = parser.add_subparsers(dest="command", required=True)
    for command in ("status", "validate", "check", "doctor", "recover"):
        subparser = subparsers.add_parser(command)
        subparser.add_argument("path", nargs="?", default=".")
        subparser.add_argument("--json", action="store_true", dest="as_json")
    for command in ("init", "qualify"):
        subparser = subparsers.add_parser(command)
        subparser.add_argument("path", nargs="?", default=".")
        subparser.add_argument("--yes", action="store_true")
        subparser.add_argument("--json", action="store_true", dest="as_json")
    mcp = subparsers.add_parser("mcp")
    mcp.add_argument("--root", default=".")
    mcp_config = subparsers.add_parser("mcp-config")
    mcp_config.add_argument("--json", action="store_true", dest="as_json")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    if args.command == "mcp":
        return serve_stdio(args.root)
    if args.command == "mcp-config":
        payload = {
            "contract": "sos_mcp_launcher_v1",
            "command": "sos",
            "args": ["mcp", "--root", "."],
            "transport": "stdio",
            "capability": "read_only",
            "absolute_paths_serialized": False,
        }
        _print(payload, args.as_json)
        return 0
    if args.command == "status":
        try:
            inspection = inspect_repository(args.path)
            if inspection.control_plane_state == "present_unverified":
                payload = workspace_status(args.path).to_dict()
                exit_code = 0 if payload["status"] == "success" else 2
            else:
                payload = inspection.to_dict()
                exit_code = 0
        except RepositoryError as exc:
            payload = {"contract": "sos_repository_inspection_v1", "status": "invalid", "reasons": [exc.reason]}
            exit_code = 2
    elif args.command == "validate":
        result = validate_repository(args.path)
        payload = result.to_dict()
        exit_code = 0 if result.status == "success" else 2
    elif args.command == "init":
        confirmed = args.yes or _ask_confirmation("Initialize SOS in this repository?")
        result = initialize_workspace(
            args.path,
            confirmed=confirmed,
            controlling_tty_observed=sys.stdin.isatty(),
        )
        payload = result.to_dict()
        exit_code = 0 if result.status == "success" else 2
    elif args.command == "check":
        try:
            payload = discover_checks(args.path).to_dict()
            exit_code = 0
        except RepositoryError as exc:
            payload = {"contract": "sos_check_plan_v1", "status": "invalid", "reasons": [exc.reason]}
            exit_code = 2
    elif args.command == "qualify":
        if not (args.yes or _ask_confirmation("Run the supported check in an isolated disposable workspace?")):
            payload = {
                "contract": "sos_qualification_receipt_v1",
                "status": "owner_required",
                "reasons": ["SOS_QUALIFICATION_CONFIRMATION_REQUIRED"],
            }
            exit_code = 2
        else:
            try:
                receipt = qualify_supported(args.path)
                store_qualification(args.path, receipt)
                payload = receipt.to_dict()
                exit_code = 0 if receipt.status == "passed_local" else 2
            except (RepositoryError, WorkspaceError) as exc:
                reason = exc.reason if isinstance(exc, RepositoryError) else str(exc)
                payload = {"contract": "sos_qualification_receipt_v1", "status": "invalid", "reasons": [reason]}
                exit_code = 2
    elif args.command == "doctor":
        result = doctor_workspace(args.path)
        payload = result.to_dict()
        exit_code = 0 if result.status == "success" else 2
    else:
        result = recover_workspace(args.path)
        payload = result.to_dict()
        exit_code = 0 if result.status == "success" else 2
    _print(payload, args.as_json)
    return exit_code


def _ask_confirmation(question: str) -> bool:
    if not sys.stdin.isatty():
        return False
    answer = input(question + " [y/N] ").strip().lower()
    return answer in {"y", "yes"}


def _print(payload: object, as_json: bool) -> None:
    if as_json:
        print(json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False))
    else:
        print(json.dumps(payload, sort_keys=True, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    raise SystemExit(main())
