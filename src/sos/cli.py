"""Sigma Operator Stack command-line and local MCP entry point."""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Sequence

from . import __version__
from .agent_api import project_tool
from .capabilities import probe_isolation_capabilities
from .checks import discover_checks
from .compatibility import compatibility_status
from .client_integration import (
    client_status,
    codex_setup_status,
    install_client,
    install_codex_setup,
    preview_client_install,
    preview_codex_setup,
    preview_codex_setup_update,
    recover_codex_setup,
    remove_client,
    remove_codex_setup,
    update_codex_setup,
)
from .claude_integration import (
    claude_setup_status,
    install_claude_setup,
    preview_claude_setup,
    recover_claude_setup,
    remove_claude_setup,
    update_claude_setup,
)
from .multi_client_lifecycle import integration_inventory, update_all_setups
from .mcp import serve_stdio
from .lifecycle import (
    LifecycleError,
    execute_one_command_init,
    prepare_one_command_init,
    preview_one_command_init,
    recover_one_command_init,
)
from .maintenance_binding import MaintenanceBindingError, MaintenanceLauncherBinding
from .qualification_contracts import QualificationContractError
from .platform_admission import admit_project_filesystem
from .repository import RepositoryError
from .result import Status, TerminalResult
from .validation import validate_repository
from .workspace import (
    WorkspaceError,
    accept_proposal,
    doctor_workspace,
    initialize_workspace,
    regenerate_workspace,
    recover_workspace,
    admit_qualification_plan,
    execute_admitted_qualification,
    prepare_qualification_plan,
    workspace_status,
)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="sos")
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    subparsers = parser.add_subparsers(dest="command", required=True)
    capabilities = subparsers.add_parser("capabilities")
    capabilities.add_argument("--json", action="store_true", dest="as_json")
    for command in (
        "status",
        "validate",
        "check",
        "doctor",
        "preflight",
        "active-task",
        "next-action",
        "recover",
        "propose-qualification-receipt",
        "propose-update",
    ):
        subparser = subparsers.add_parser(command)
        subparser.add_argument("path", nargs="?", default=".")
        subparser.add_argument("--json", action="store_true", dest="as_json")
    qualification_plan = subparsers.add_parser("qualification-plan")
    qualification_plan.add_argument("path", nargs="?", default=".")
    qualification_plan.add_argument("--family", dest="family_id")
    qualification_plan.add_argument("--json", action="store_true", dest="as_json")
    compatibility = subparsers.add_parser("compatibility")
    compatibility.add_argument("path", nargs="?", default=".")
    compatibility.add_argument("--primary-authority")
    compatibility.add_argument("--json", action="store_true", dest="as_json")
    for command in ("init", "regenerate"):
        subparser = subparsers.add_parser(command)
        subparser.add_argument("path", nargs="?", default=".")
        subparser.add_argument("--yes", action="store_true")
        subparser.add_argument("--json", action="store_true", dest="as_json")
        if command == "init":
            subparser.add_argument("--with-codex", action="store_true")
            subparser.add_argument("--with-client", choices=("codex", "claude-code"))
            subparser.add_argument("--primary-authority")
            subparser.add_argument("--maintenance-release-binding-json")
            subparser.add_argument("--resume-confirmation-seed")
            subparser.add_argument("--expected-plan-digest")
    qualify = subparsers.add_parser("qualify")
    qualify.add_argument("path", nargs="?", default=".")
    qualify.add_argument("--family")
    qualify.add_argument("--yes", action="store_true")
    qualify.add_argument("--json", action="store_true", dest="as_json")
    accept = subparsers.add_parser("accept")
    accept.add_argument("revision")
    accept.add_argument("path", nargs="?", default=".")
    accept.add_argument("--yes", action="store_true")
    accept.add_argument("--json", action="store_true", dest="as_json")
    mcp = subparsers.add_parser("mcp")
    mcp.add_argument("--root", default=".")
    mcp.add_argument("--expected-package-version")
    mcp_config = subparsers.add_parser("mcp-config")
    mcp_config.add_argument("--json", action="store_true", dest="as_json")
    client = subparsers.add_parser("client")
    client_commands = client.add_subparsers(dest="client_command", required=True)
    for operation in ("install", "status", "remove"):
        command = client_commands.add_parser(operation)
        command.add_argument("client", choices=("codex", "claude-code"))
        command.add_argument("path", nargs="?", default=".")
        command.add_argument("--json", action="store_true", dest="as_json")
        if operation != "status":
            command.add_argument("--yes", action="store_true")
    setup = subparsers.add_parser("setup")
    setup_commands = setup.add_subparsers(dest="setup_command", required=True)
    for operation in ("install", "status", "recover", "update", "remove"):
        command = setup_commands.add_parser(operation)
        command.add_argument("client", choices=("codex", "claude-code"))
        command.add_argument("path", nargs="?", default=".")
        command.add_argument("--json", action="store_true", dest="as_json")
        if operation in {"install", "update", "remove"}:
            command.add_argument("--yes", action="store_true")
    update_all = setup_commands.add_parser("update-all")
    update_all.add_argument("path", nargs="?", default=".")
    update_all.add_argument("--yes", action="store_true")
    update_all.add_argument("--json", action="store_true", dest="as_json")
    integrations = subparsers.add_parser("integrations")
    integrations.add_argument("path", nargs="?", default=".")
    integrations.add_argument("--json", action="store_true", dest="as_json")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    if args.command == "capabilities":
        report = probe_isolation_capabilities()
        _print(report.to_dict(), args.as_json)
        return 0 if report.status == "supported" else 2
    filesystem_admission = _filesystem_admission_for_command(args)
    if filesystem_admission is not None and filesystem_admission.status != "success":
        _print(filesystem_admission.to_dict(), getattr(args, "as_json", False))
        return 2
    if args.command == "mcp":
        if args.expected_package_version is not None and args.expected_package_version != __version__:
            print("SOS_MCP_PACKAGE_VERSION_MISMATCH", file=sys.stderr)
            return 8
        return serve_stdio(args.root)
    if args.command == "mcp-config":
        payload = {
            "contract": "sos_mcp_launcher_v1",
            "command": sys.executable,
            "args": ["-m", "sos", "mcp", "--root", ".", "--expected-package-version", __version__],
            "transport": "stdio",
            "capability": "read_only",
            "absolute_paths_serialized": True,
            "persistent_project_install": "sos client install codex PATH",
        }
        _print(payload, args.as_json)
        return 0
    if args.command == "integrations":
        result = integration_inventory(args.path)
        _print(result.to_dict(), args.as_json)
        return 0 if result.status == "success" else 2
    if args.command == "setup":
        if args.setup_command == "update-all":
            confirmed = args.yes or _ask_confirmation("Repair all installed SOS client integrations for this project?")
            result = update_all_setups(args.path, confirmed=confirmed, controlling_tty_observed=sys.stdin.isatty())
            _print(result.to_dict(), args.as_json)
            return 0 if result.status == "success" else 2
        if args.client == "claude-code":
            if args.setup_command == "status":
                result = claude_setup_status(args.path)
            elif args.setup_command == "recover":
                result = recover_claude_setup(args.path)
            elif args.setup_command == "install":
                preview = preview_claude_setup(args.path)
                _print(preview.to_dict(), args.as_json)
                if preview.status != "owner_required":
                    return 0 if preview.status == "success" else 2
                expected_manifest_digest = preview.details.get("manifest_digest")
                confirmed = args.yes or _ask_confirmation("Install the SOS Claude Code recovery adapter?")
                result = install_claude_setup(
                    args.path,
                    confirmed=confirmed,
                    controlling_tty_observed=sys.stdin.isatty(),
                    expected_manifest_digest=expected_manifest_digest,
                )
            elif args.setup_command == "update":
                confirmed = args.yes or _ask_confirmation("Repair the exact same-version Claude Code adapter?")
                result = update_claude_setup(args.path, confirmed=confirmed, controlling_tty_observed=sys.stdin.isatty())
            else:
                confirmed = args.yes or _ask_confirmation("Detach only the exact SOS-managed Claude Code adapter?")
                result = remove_claude_setup(args.path, confirmed=confirmed, controlling_tty_observed=sys.stdin.isatty())
            _print(result.to_dict(), args.as_json)
            return 0 if result.status == "success" else 2
        if args.setup_command == "status":
            result = codex_setup_status(args.path)
        elif args.setup_command == "recover":
            result = recover_codex_setup(args.path)
        elif args.setup_command == "install":
            if not args.yes:
                preview = preview_codex_setup(args.path)
                if preview.status != "owner_required":
                    _print(preview.to_dict(), args.as_json)
                    return 0 if preview.status == "success" else 2
                _print(preview.to_dict(), args.as_json)
            confirmed = args.yes or _ask_confirmation(
                "Install the SOS project-recovery instructions and Codex MCP adapter?"
            )
            result = install_codex_setup(
                args.path,
                confirmed=confirmed,
                controlling_tty_observed=sys.stdin.isatty(),
            )
        elif args.setup_command == "update":
            if not args.yes:
                preview = preview_codex_setup_update(args.path)
                if preview.status != "owner_required":
                    _print(preview.to_dict(), args.as_json)
                    return 0 if preview.status == "success" else 2
                _print(preview.to_dict(), args.as_json)
            confirmed = args.yes or _ask_confirmation(
                "Update the exact SOS-managed Codex integration?"
            )
            result = update_codex_setup(
                args.path,
                confirmed=confirmed,
                controlling_tty_observed=sys.stdin.isatty(),
            )
        else:
            confirmed = args.yes or _ask_confirmation(
                "Remove only the exact SOS-managed Codex-first integration?"
            )
            result = remove_codex_setup(
                args.path,
                confirmed=confirmed,
                controlling_tty_observed=sys.stdin.isatty(),
            )
        _print(result.to_dict(), args.as_json)
        return 0 if result.status == "success" else 2
    if args.command == "client":
        if args.client == "claude-code":
            if args.client_command == "status":
                result = claude_setup_status(args.path)
            elif args.client_command == "install":
                preview = preview_claude_setup(args.path)
                _print(preview.to_dict(), args.as_json)
                if preview.status != "owner_required":
                    return 0 if preview.status == "success" else 2
                expected_manifest_digest = preview.details.get("manifest_digest")
                confirmed = args.yes or _ask_confirmation("Install the SOS Claude Code recovery adapter?")
                result = install_claude_setup(
                    args.path,
                    confirmed=confirmed,
                    controlling_tty_observed=sys.stdin.isatty(),
                    expected_manifest_digest=expected_manifest_digest,
                )
            else:
                confirmed = args.yes or _ask_confirmation("Detach only the SOS Claude Code adapter?")
                result = remove_claude_setup(args.path, confirmed=confirmed, controlling_tty_observed=sys.stdin.isatty())
            _print(result.to_dict(), args.as_json)
            return 0 if result.status == "success" else 2
        if args.client_command == "status":
            result = client_status(args.path, args.client)
        elif args.client_command == "install":
            if not args.yes:
                preview = preview_client_install(args.path, args.client)
                if preview.status != "owner_required":
                    _print(preview.to_dict(), args.as_json)
                    return 0 if preview.status == "success" else 2
                _print(preview.to_dict(), args.as_json)
            confirmed = args.yes or _ask_confirmation("Install the project-local SOS MCP adapter for Codex?")
            result = install_client(
                args.path,
                args.client,
                confirmed=confirmed,
                controlling_tty_observed=sys.stdin.isatty(),
            )
        else:
            if not args.yes:
                preview = remove_client(args.path, args.client, confirmed=False)
                if preview.status != "owner_required":
                    _print(preview.to_dict(), args.as_json)
                    return 0 if preview.status == "success" else 2
                _print(preview.to_dict(), args.as_json)
            confirmed = args.yes or _ask_confirmation("Remove only the exact SOS-managed Codex MCP adapter?")
            result = remove_client(
                args.path,
                args.client,
                confirmed=confirmed,
                controlling_tty_observed=sys.stdin.isatty(),
            )
        _print(result.to_dict(), args.as_json)
        return 0 if result.status == "success" else 2
    if args.command == "status":
        result = project_tool(args.path, "sos_status")
        payload = result.to_dict()
        exit_code = 0 if result.status == "success" else 2
    elif args.command == "validate":
        result = validate_repository(args.path)
        payload = result.to_dict()
        exit_code = 0 if result.status == "success" else 2
    elif args.command == "compatibility":
        result = compatibility_status(
            args.path,
            primary_authority_id=args.primary_authority,
        )
        payload = result.to_dict()
        exit_code = 0 if result.status == "success" else 2
    elif args.command == "init":
        init_client = args.with_client or ("codex" if args.with_codex else None)
        if args.with_codex and args.with_client not in {None, "codex"}:
            payload = {"contract": "sos_init_result_v1", "status": "invalid", "reasons": ["SOS_CLIENT_SELECTION_CONFLICT"]}
            _print(payload, args.as_json)
            return 2
        confirmation_resume_requested = (
            args.resume_confirmation_seed is not None
            or args.expected_plan_digest is not None
        )
        if (
            args.primary_authority is not None
            or args.maintenance_release_binding_json is not None
            or confirmation_resume_requested
        ) and init_client is None:
            payload = {
                "contract": "sos_init_result_v1",
                "status": "invalid",
                "reasons": [
                    "SOS_PRIMARY_AUTHORITY_WITHOUT_CODEX_INIT"
                    if args.primary_authority is not None
                    else (
                        "SOS_MAINTENANCE_BINDING_WITHOUT_CODEX_INIT"
                        if args.maintenance_release_binding_json is not None
                        else "SOS_P106_CONFIRMATION_WITHOUT_CODEX_INIT"
                    )
                ],
            }
            _print(payload, args.as_json)
            return 2
        if init_client is not None:
            if (args.resume_confirmation_seed is None) != (
                args.expected_plan_digest is None
            ):
                payload = {
                    "contract": "sos_p106_init_result_v1",
                    "status": "invalid",
                    "reasons": ["SOS_P106_CONFIRMATION_HANDOFF_INVALID"],
                }
                _print(payload, args.as_json)
                return 2
            if confirmation_resume_requested and args.yes:
                payload = {
                    "contract": "sos_p106_init_result_v1",
                    "status": "invalid",
                    "reasons": ["SOS_P106_CONFIRMATION_HANDOFF_INVALID"],
                }
                _print(payload, args.as_json)
                return 2
            maintenance_binding = None
            if args.maintenance_release_binding_json is not None:
                try:
                    maintenance_binding = MaintenanceLauncherBinding.from_payload(
                        json.loads(args.maintenance_release_binding_json)
                    )
                except (json.JSONDecodeError, MaintenanceBindingError) as exc:
                    reason = getattr(exc, "reason", "SOS_MAINTENANCE_RELEASE_BINDING_INVALID")
                    payload = {
                        "contract": "sos_p106_init_result_v1",
                        "status": "invalid",
                        "reasons": [reason],
                    }
                    _print(payload, args.as_json)
                    return 2
            try:
                one_command_plan = prepare_one_command_init(
                    args.path,
                    primary_authority_id=args.primary_authority,
                    maintenance_binding=maintenance_binding,
                    confirmation_seed=args.resume_confirmation_seed,
                    client=init_client,
                )
            except LifecycleError as exc:
                if exc.reason == "SOS_P106_RECOVERY_REQUIRED":
                    recovered = recover_one_command_init(args.path, client=init_client)
                    if recovered.status != "success":
                        result = recovered
                        payload = result.to_dict()
                        _print(payload, args.as_json)
                        return 2
                    one_command_plan = prepare_one_command_init(
                        args.path,
                        primary_authority_id=args.primary_authority,
                        maintenance_binding=maintenance_binding,
                        confirmation_seed=args.resume_confirmation_seed,
                        client=init_client,
                    )
                else:
                    result = preview_one_command_init(
                        args.path,
                        primary_authority_id=args.primary_authority,
                        maintenance_binding=maintenance_binding,
                        confirmation_seed=args.resume_confirmation_seed,
                        client=init_client,
                    )
                    payload = result.to_dict()
                    _print(payload, args.as_json)
                    return 0 if result.status == "success" else 2
            if args.expected_plan_digest is not None:
                if one_command_plan.aggregate_plan_digest != args.expected_plan_digest:
                    result = TerminalResult(
                        "sos_p106_init_result_v1",
                        Status.STALE,
                        ("SOS_P106_CONFIRMATION_BINDING_MISMATCH",),
                        {
                            "expected_plan_digest": args.expected_plan_digest,
                            "observed_plan_digest": one_command_plan.aggregate_plan_digest,
                        },
                    )
                    _print(result.to_dict(), args.as_json)
                    return 2
            else:
                preview = one_command_plan.preview()
                _print(preview.to_dict(), args.as_json)
            confirmed = args.yes or _ask_confirmation(
                "Apply the exact SOS bootstrap and "
                + ("Codex" if init_client == "codex" else "Claude Code")
                + " integration plan"
                + (
                    f" {one_command_plan.aggregate_plan_digest}?"
                    if args.expected_plan_digest is not None
                    else "?"
                )
            )
            result = execute_one_command_init(
                one_command_plan,
                confirmed=confirmed,
                controlling_tty_observed=sys.stdin.isatty(),
            )
        else:
            confirmed = args.yes or _ask_confirmation("Initialize SOS in this repository?")
            result = initialize_workspace(
                args.path,
                confirmed=confirmed,
                controlling_tty_observed=sys.stdin.isatty(),
            )
        payload = result.to_dict()
        exit_code = 0 if (
            result.status == "success"
            or (
                result.contract == "sos_p107_init_result_v1"
                and "SOS_INTERACTIVE_USER_HANDOFF_REQUIRED" in result.reasons
                and result.details.get("claude_code_setup_state") == "installed"
            )
        ) else 2
    elif args.command == "regenerate":
        confirmed = args.yes or _ask_confirmation("Generate successor proposals for the current source?")
        result = regenerate_workspace(
            args.path,
            confirmed=confirmed,
            controlling_tty_observed=sys.stdin.isatty(),
        )
        payload = result.to_dict()
        exit_code = 0 if result.status == "success" else 2
    elif args.command == "accept":
        confirmed = args.yes or _ask_confirmation(f"Accept exact proposal {args.revision}?")
        result = accept_proposal(
            args.path,
            args.revision,
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
        try:
            plan = prepare_qualification_plan(args.path, args.family)
        except (RepositoryError, WorkspaceError, QualificationContractError) as exc:
            reason = exc.reason if hasattr(exc, "reason") else str(exc)
            terminal_status = "stale" if reason in {"SOS_QUALIFICATION_STALE", "SOS_QUALIFICATION_PLAN_STALE"} else "invalid"
            payload = {"contract": "sos_qualify_result_v1", "status": terminal_status, "reasons": [reason]}
            exit_code = 2
            _print(payload, args.as_json)
            return exit_code
        if not args.yes:
            print(json.dumps(plan, sort_keys=True, indent=2, ensure_ascii=False))
        if not (args.yes or _ask_confirmation(f"Admit and consume exact plan {plan['plan_digest']} once?")):
            payload = {
                "contract": "sos_qualify_result_v1",
                "status": "owner_required",
                "reasons": ["SOS_QUALIFICATION_CONFIRMATION_REQUIRED"],
            }
            exit_code = 2
        else:
            try:
                admission = admit_qualification_plan(
                    args.path,
                    plan,
                    confirmed=True,
                    controlling_tty_observed=sys.stdin.isatty(),
                )
                receipt = execute_admitted_qualification(args.path, plan, admission)
                payload = receipt
                exit_code = 0 if receipt["status"] == "passed_local" else 2
            except (RepositoryError, WorkspaceError, QualificationContractError) as exc:
                reason = exc.reason if hasattr(exc, "reason") else str(exc)
                payload = {"contract": "sos_qualify_result_v1", "status": "invalid", "reasons": [reason]}
                exit_code = 2
    elif args.command == "doctor":
        result = doctor_workspace(args.path)
        payload = result.to_dict()
        exit_code = 0 if result.status == "success" else 2
    elif args.command == "recover":
        result = recover_workspace(args.path)
        payload = result.to_dict()
        exit_code = 0 if result.status == "success" else 2
    else:
        tool_name = {
            "preflight": "sos_preflight",
            "active-task": "sos_active_task",
            "next-action": "sos_next_action",
            "qualification-plan": "sos_qualification_plan",
            "propose-qualification-receipt": "sos_propose_qualification_receipt",
            "propose-update": "sos_propose_update",
        }[args.command]
        arguments = {"family_id": args.family_id} if args.command == "qualification-plan" and args.family_id else {}
        result = project_tool(args.path, tool_name, arguments)
        payload = result.to_dict()
        exit_code = 0 if result.status == "success" else 2
    _print(payload, args.as_json)
    return exit_code


def _ask_confirmation(question: str) -> bool:
    if not sys.stdin.isatty():
        return False
    answer = input(question + " [y/N] ").strip().lower()
    return answer in {"y", "yes"}


def _filesystem_admission_for_command(
    args: argparse.Namespace,
):
    command = args.command
    requires_admission = command in {"init", "regenerate", "accept", "qualify"}
    if command == "setup":
        requires_admission = args.setup_command in {"install", "recover", "update", "remove"}
    elif command == "client":
        requires_admission = args.client_command in {"install", "remove"}
    if not requires_admission:
        return None
    return admit_project_filesystem(args.path)


def _print(payload: object, as_json: bool) -> None:
    if as_json:
        print(json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False))
    else:
        print(json.dumps(payload, sort_keys=True, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    raise SystemExit(main())
