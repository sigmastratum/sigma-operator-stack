"""Read-only P102 command line interface."""

from __future__ import annotations

import argparse
import json
from collections.abc import Sequence

from .repository import RepositoryError, inspect_repository
from .validation import validate_repository


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="sos")
    subparsers = parser.add_subparsers(dest="command", required=True)
    for command in ("status", "validate"):
        subparser = subparsers.add_parser(command)
        subparser.add_argument("path", nargs="?", default=".")
        subparser.add_argument("--json", action="store_true", dest="as_json")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    if args.command == "status":
        try:
            payload = inspect_repository(args.path).to_dict()
            exit_code = 0
        except RepositoryError as exc:
            payload = {"contract": "sos_repository_inspection_v1", "status": "invalid", "reasons": [exc.reason]}
            exit_code = 2
    else:
        result = validate_repository(args.path)
        payload = result.to_dict()
        exit_code = 0 if result.status == "success" else 2
    if args.as_json:
        print(json.dumps(payload, sort_keys=True, separators=(",", ":")))
    else:
        print(json.dumps(payload, sort_keys=True, indent=2))
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())

