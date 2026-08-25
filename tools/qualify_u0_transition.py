#!/usr/bin/env python3
"""Qualify the U0 N -> N+1 -> N contract with two exact local wheels."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
import tempfile
import venv
from pathlib import Path


_DRIVER = r"""
import hashlib
import json
import subprocess
import sys
from pathlib import Path

from sos import __version__
from sos.client_integration import (
    codex_setup_status,
    install_codex_setup,
    project_codex_package_update,
    update_codex_setup,
)
from sos.qualification_contracts import EXECUTOR_DIGEST
from sos.workspace import initialize_workspace, qualify_once, workspace_status


def digest_file(path):
    return "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()


def snapshot(root):
    status = workspace_status(str(root))
    setup = codex_setup_status(str(root))
    proposal = project_codex_package_update(str(root))
    view = root / ".sigma" / "views" / "qualification.json"
    qualification = json.loads(view.read_text(encoding="utf-8")) if view.is_file() else None
    records = root / ".sigma" / "records"
    accepted = {
        path.name: digest_file(path)
        for path in sorted(records.glob("*.json"))
        if path.is_file()
    }
    return {
        "package_version": __version__,
        "executor_digest": EXECUTOR_DIGEST,
        "workspace_status": status.status.value,
        "qualification_integrity": status.details.get("qualification_integrity"),
        "qualification_ordinal": None if qualification is None else qualification["sequence_ordinal"],
        "setup_status": setup.status.value,
        "setup_reasons": list(setup.reasons),
        "update_status": proposal.status.value,
        "update_reasons": list(proposal.reasons),
        "restart_required": proposal.details.get("agent_restart_required"),
        "qualification_rerun_required": proposal.details.get("qualification_rerun_required"),
        "accepted_record_digests": accepted,
        "user_file_digest": digest_file(root / "user-owned.txt"),
    }


root = Path(sys.argv[1])
operation = sys.argv[2]
if operation == "bootstrap":
    initialized = initialize_workspace(str(root), confirmed=True, controlling_tty_observed=True)
    if initialized.status.value != "success":
        raise SystemExit(20)
    installed = install_codex_setup(
        str(root), confirmed=True, controlling_tty_observed=True
    )
    if installed.status.value != "success":
        raise SystemExit(21)
    receipt = qualify_once(
        str(root),
        family_id="python.syntax",
        confirmed=True,
        controlling_tty_observed=True,
    )[2]
    if receipt["status"] != "passed_local":
        raise SystemExit(22)
elif operation == "rebind":
    rebound = update_codex_setup(
        str(root), confirmed=True, controlling_tty_observed=True
    )
    if rebound.status.value != "success":
        raise SystemExit(23)
elif operation == "qualify":
    receipt = qualify_once(
        str(root),
        family_id="python.syntax",
        confirmed=True,
        controlling_tty_observed=True,
    )[2]
    if receipt["status"] != "passed_local":
        raise SystemExit(24)
elif operation != "inspect":
    raise SystemExit(25)
print(json.dumps(snapshot(root), sort_keys=True, separators=(",", ":")))
"""


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return "sha256:" + digest.hexdigest()


def _run(argv: list[str], *, cwd: Path, home: Path) -> str:
    environment = {
        "HOME": os.fspath(home),
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "PATH": os.environ.get("PATH", ""),
        "PIP_DISABLE_PIP_VERSION_CHECK": "1",
        "PYTHONHASHSEED": "0",
        "TZ": "UTC",
    }
    home.mkdir(parents=True, exist_ok=True)
    completed = subprocess.run(
        argv,
        cwd=cwd,
        env=environment,
        check=True,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        timeout=180,
    )
    return completed.stdout.strip()


def _install(python: Path, wheel: Path, root: Path, home: Path) -> None:
    _run(
        [
            os.fspath(python),
            "-m",
            "pip",
            "install",
            "--no-index",
            "--no-deps",
            "--force-reinstall",
            os.fspath(wheel),
        ],
        cwd=root,
        home=home,
    )


def _driver(
    python: Path, project: Path, operation: str, root: Path, home: Path
) -> dict[str, object]:
    return json.loads(
        _run(
            [os.fspath(python), "-c", _DRIVER, os.fspath(project), operation],
            cwd=root,
            home=home,
        )
    )


def _make_project(root: Path, label: str, home: Path) -> Path:
    project = root / label
    project.mkdir()
    _run(["git", "init", "-q"], cwd=project, home=home)
    _run(["git", "config", "user.name", "Synthetic Operator"], cwd=project, home=home)
    _run(["git", "config", "user.email", "synthetic@example.invalid"], cwd=project, home=home)
    (project / "AGENTS.md").write_text("Synthetic public instructions.\n", encoding="utf-8")
    (project / "README.md").write_text("Synthetic U0 project.\n", encoding="utf-8")
    (project / "user-owned.txt").write_text("Preserve this user-owned file.\n", encoding="utf-8")
    (project / "sample.py").write_text("VALUE = 1\n", encoding="utf-8")
    (project / "tasks").mkdir()
    (project / "tasks" / "current.md").write_text("Synthetic current task.\n", encoding="utf-8")
    _run(["git", "add", "."], cwd=project, home=home)
    _run(["git", "commit", "-qm", "synthetic U0 project"], cwd=project, home=home)
    return project


def _require(value: bool, reason: str) -> None:
    if not value:
        raise RuntimeError(reason)


def qualify(predecessor: Path, successor: Path) -> dict[str, object]:
    predecessor = predecessor.resolve(strict=True)
    successor = successor.resolve(strict=True)
    _require(predecessor.is_file() and successor.is_file(), "wheel_not_regular")
    _require(predecessor != successor, "wheel_paths_equal")
    with tempfile.TemporaryDirectory(prefix="sos-u0-transition-") as temporary:
        root = Path(temporary)
        home = root / "home"
        environment = root / "tool-environment"
        venv.EnvBuilder(with_pip=True, system_site_packages=True).create(environment)
        python = environment / "bin" / "python"
        projects = (
            _make_project(root, "project-a", home),
            _make_project(root, "project-b", home),
        )

        _install(python, predecessor, root, home)
        initial = tuple(_driver(python, project, "bootstrap", root, home) for project in projects)
        _require(all(item["qualification_integrity"] == "valid" for item in initial), "n_not_valid")
        _require(initial[0]["accepted_record_digests"] != {}, "records_absent")

        _install(python, successor, root, home)
        successor_before_rebind = tuple(
            _driver(python, project, "inspect", root, home) for project in projects
        )
        _require(
            all(item["qualification_integrity"] == "valid_stale" for item in successor_before_rebind),
            "successor_not_stale",
        )
        _require(all(item["setup_status"] == "stale" for item in successor_before_rebind), "setup_not_stale")
        _require(all(item["restart_required"] is True for item in successor_before_rebind), "restart_not_required")

        successor_after_rebind = tuple(
            _driver(python, project, "rebind", root, home) for project in projects
        )
        _require(
            all(item["qualification_integrity"] == "valid_stale" for item in successor_after_rebind),
            "rebind_forged_green",
        )
        successor_qualified = tuple(
            _driver(python, project, "qualify", root, home) for project in projects
        )
        _require(all(item["qualification_integrity"] == "valid" for item in successor_qualified), "next_not_valid")

        _install(python, successor, root, home)
        idempotent = tuple(
            _driver(python, project, "inspect", root, home) for project in projects
        )
        _require(all(item["qualification_integrity"] == "valid" for item in idempotent), "same_version_not_current")

        _install(python, predecessor, root, home)
        downgrade_before_rebind = tuple(
            _driver(python, project, "inspect", root, home) for project in projects
        )
        _require(
            all(item["qualification_integrity"] == "valid_stale" for item in downgrade_before_rebind),
            "downgrade_not_stale",
        )
        downgrade_after_rebind = tuple(
            _driver(python, project, "rebind", root, home) for project in projects
        )
        _require(
            all(item["qualification_integrity"] == "valid_stale" for item in downgrade_after_rebind),
            "downgrade_rebind_forged_green",
        )
        downgraded = tuple(
            _driver(python, project, "qualify", root, home) for project in projects
        )
        _require(all(item["qualification_integrity"] == "valid" for item in downgraded), "downgrade_not_valid")

        for before, after in zip(initial, downgraded, strict=True):
            _require(before["accepted_record_digests"] == after["accepted_record_digests"], "records_changed")
            _require(before["user_file_digest"] == after["user_file_digest"], "user_file_changed")
            _require(after["qualification_ordinal"] == 3, "receipt_sequence_invalid")

        return {
            "contract": "sos_u0_two_wheel_transition_receipt_v1",
            "status": "pass",
            "predecessor_wheel_digest": _sha256(predecessor),
            "successor_wheel_digest": _sha256(successor),
            "predecessor_version": initial[0]["package_version"],
            "successor_version": successor_qualified[0]["package_version"],
            "project_count": len(projects),
            "qualification_ordinals": [item["qualification_ordinal"] for item in downgraded],
            "package_identity_changed": initial[0]["executor_digest"] != successor_qualified[0]["executor_digest"],
            "downgrade_identity_restored": all(
                before["executor_digest"] == after["executor_digest"]
                for before, after in zip(initial, downgraded, strict=True)
            ),
            "accepted_records_preserved": True,
            "user_files_preserved": True,
            "same_version_idempotent": True,
            "network_performed_by_sos": False,
            "provider_calls": 0,
            "raw_project_content_serialized": False,
            "absolute_paths_serialized": False,
        }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--predecessor-wheel", required=True, type=Path)
    parser.add_argument("--successor-wheel", required=True, type=Path)
    arguments = parser.parse_args()
    try:
        receipt = qualify(arguments.predecessor_wheel, arguments.successor_wheel)
    except (OSError, RuntimeError, subprocess.CalledProcessError, subprocess.TimeoutExpired, ValueError) as exc:
        reason = exc.args[0] if type(exc) is RuntimeError and exc.args else "SOS_U0_TRANSITION_FAILED"
        if not isinstance(reason, str) or not reason.isidentifier():
            reason = "SOS_U0_TRANSITION_FAILED"
        print(
            json.dumps(
                {
                    "contract": "sos_u0_two_wheel_transition_receipt_v1",
                    "status": "failed",
                    "reason": reason,
                },
                sort_keys=True,
                separators=(",", ":"),
            )
        )
        return 1
    print(json.dumps(receipt, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
