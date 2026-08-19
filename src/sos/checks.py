"""Closed qualification discovery and one supported isolated check family."""

from __future__ import annotations

import hashlib
import json
import os
import stat
import subprocess
from dataclasses import asdict, dataclass
from pathlib import Path

from .isolation import PROFILE_ID, isolation_limits, profile_declared_available, run_isolated_unittest
from .repository import RepositoryError, discover_repository_root, inspect_repository


_MAX_TRACKED_FILES = 5000
_MAX_TRACKED_BYTES = 16 * 1024 * 1024
_MAX_SOURCE_FILE_BYTES = 2 * 1024 * 1024


@dataclass(frozen=True, slots=True)
class CheckFamily:
    family_id: str
    status: str
    command_id: str | None
    isolation: str
    reasons: tuple[str, ...]

    def to_dict(self) -> dict[str, object]:
        value = asdict(self)
        value["reasons"] = list(self.reasons)
        return value


@dataclass(frozen=True, slots=True)
class CheckPlan:
    contract: str
    source_tree_digest: str
    source_status_digest: str
    families: tuple[CheckFamily, ...]
    plan_digest: str

    def to_dict(self) -> dict[str, object]:
        return {
            "contract": self.contract,
            "source_tree_digest": self.source_tree_digest,
            "source_status_digest": self.source_status_digest,
            "families": [family.to_dict() for family in self.families],
            "plan_digest": self.plan_digest,
        }


@dataclass(frozen=True, slots=True)
class QualificationReceipt:
    contract: str
    status: str
    reasons: tuple[str, ...]
    family_id: str
    command_id: str
    plan_digest: str
    source_tree_digest: str
    source_status_digest: str
    isolation: str
    exit_code: int | None
    output_digest: str | None
    output_bytes: int
    raw_output_serialized: bool
    limits: dict[str, int]

    def to_dict(self) -> dict[str, object]:
        value = asdict(self)
        value["reasons"] = list(self.reasons)
        return value


def discover_checks(path: str = ".") -> CheckPlan:
    root = discover_repository_root(path)
    inspection = inspect_repository(root)
    tracked = _tracked_paths(root)
    python_project = any(name in tracked for name in ("pyproject.toml", "setup.py", "setup.cfg"))
    unittest_tests = any(
        name.startswith("tests/") and Path(name).name.startswith("test") and name.endswith(".py")
        for name in tracked
    )
    python_sources = any(name.endswith(".py") for name in tracked)
    if python_project and python_sources:
        structural = CheckFamily(
            family_id="python.syntax",
            status="configured",
            command_id="python.compile.v1",
            isolation="non-executing-structural-v1",
            reasons=("SOS_CHECK_CONFIGURED",),
        )
    else:
        structural = CheckFamily(
            family_id="python.syntax",
            status="not_configured",
            command_id=None,
            isolation="not_applicable",
            reasons=("SOS_CHECK_NOT_CONFIGURED",),
        )
    if python_project and unittest_tests:
        if profile_declared_available():
            unittest_family = CheckFamily(
                family_id="python.stdlib-unittest",
                status="configured",
                command_id="python.unittest.v1",
                isolation=PROFILE_ID,
                reasons=("SOS_CHECK_CONFIGURED",),
            )
        else:
            unittest_family = CheckFamily(
                family_id="python.stdlib-unittest",
                status="unsupported",
                command_id=None,
                isolation="unavailable",
                reasons=("SOS_PROJECT_EXECUTION_PROFILE_NOT_QUALIFIED",),
            )
    else:
        unittest_family = CheckFamily(
            family_id="python.stdlib-unittest",
            status="not_configured",
            command_id=None,
            isolation="not_applicable",
            reasons=("SOS_CHECK_NOT_CONFIGURED",),
        )
    material = {
        "contract": "sos_check_plan_v1",
        "source_tree_digest": inspection.application_tree_digest,
        "source_status_digest": inspection.application_status_digest,
        "families": [structural.to_dict(), unittest_family.to_dict()],
    }
    digest = _digest_json(material)
    return CheckPlan(
        contract="sos_check_plan_v1",
        source_tree_digest=inspection.application_tree_digest,
        source_status_digest=inspection.application_status_digest,
        families=(structural, unittest_family),
        plan_digest=digest,
    )


def qualify_supported(path: str = ".", *, family_id: str | None = None) -> QualificationReceipt:
    root = discover_repository_root(path)
    plan = discover_checks(os.fspath(root))
    if family_id is None:
        family = plan.families[0]
    else:
        family = next((item for item in plan.families if item.family_id == family_id), None)
        if family is None:
            raise RepositoryError("SOS_CHECK_FAMILY_UNKNOWN")
    if family.status != "configured" or family.command_id is None:
        return QualificationReceipt(
            contract="sos_qualification_receipt_v1",
            status="unsupported" if family.status == "unsupported" else "not_verified",
            reasons=family.reasons,
            family_id=family.family_id,
            command_id="none",
            plan_digest=plan.plan_digest,
            source_tree_digest=plan.source_tree_digest,
            source_status_digest=plan.source_status_digest,
            isolation=family.isolation,
            exit_code=None,
            output_digest=None,
            output_bytes=0,
            raw_output_serialized=False,
            limits=_limits(),
        )
    if inspect_repository(root).application_state != "clean":
        return QualificationReceipt(
            contract="sos_qualification_receipt_v1",
            status="blocked",
            reasons=("SOS_QUALIFICATION_DIRTY_SOURCE",),
            family_id=family.family_id,
            command_id=family.command_id,
            plan_digest=plan.plan_digest,
            source_tree_digest=plan.source_tree_digest,
            source_status_digest=plan.source_status_digest,
            isolation=family.isolation,
            exit_code=None,
            output_digest=None,
            output_bytes=0,
            raw_output_serialized=False,
            limits=_limits(),
        )
    if family.command_id == "python.compile.v1":
        return _run_python_syntax(root, plan, family)
    if family.command_id == "python.unittest.v1":
        return _run_python_unittest(root, plan, family)
    raise RepositoryError("SOS_CHECK_COMMAND_UNKNOWN")


def _tracked_paths(root: Path) -> tuple[str, ...]:
    completed = subprocess.run(
        ["git", "-C", os.fspath(root), "ls-files", "-z", "--cached"],
        check=False,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        timeout=5,
        env={"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "GIT_CONFIG_NOSYSTEM": "1", "GIT_TERMINAL_PROMPT": "0"},
        shell=False,
    )
    if completed.returncode != 0 or len(completed.stdout) > 8 * 1024 * 1024:
        raise RepositoryError("SOS_GIT_INSPECTION_FAILED")
    paths: list[str] = []
    for raw in completed.stdout.split(b"\0"):
        if not raw:
            continue
        try:
            path = raw.decode("utf-8", errors="strict")
        except UnicodeDecodeError as exc:
            raise RepositoryError("SOS_GIT_PATH_ENCODING_UNSUPPORTED") from exc
        if path == ".sigma" or path.startswith(".sigma/"):
            continue
        paths.append(path)
    if len(paths) > _MAX_TRACKED_FILES:
        raise RepositoryError("SOS_FILE_COUNT_LIMIT_EXCEEDED")
    return tuple(paths)


def _run_python_syntax(root: Path, plan: CheckPlan, family: CheckFamily) -> QualificationReceipt:
    source_digests: list[str] = []
    total = 0
    failed = False
    for relative in _tracked_paths(root):
        if not relative.endswith(".py"):
            continue
        source = root / relative
        try:
            mode = source.lstat().st_mode
        except OSError as exc:
            raise RepositoryError("SOS_TRACKED_FILE_UNAVAILABLE") from exc
        if not stat.S_ISREG(mode):
            raise RepositoryError("SOS_TRACKED_FILE_TYPE_UNSUPPORTED")
        size = source.stat().st_size
        if size > _MAX_SOURCE_FILE_BYTES:
            raise RepositoryError("SOS_SOURCE_FILE_BYTES_LIMIT_EXCEEDED")
        payload = source.read_bytes()
        total += len(payload)
        if total > _MAX_TRACKED_BYTES:
            raise RepositoryError("SOS_TRACKED_BYTES_LIMIT_EXCEEDED")
        source_digests.append(relative + ":" + hashlib.sha256(payload).hexdigest())
        try:
            compile(payload, relative, "exec", dont_inherit=True, optimize=0)
        except (SyntaxError, ValueError, TypeError):
            failed = True
    summary = "\n".join(source_digests).encode("utf-8")
    status = "failed" if failed else "passed_local"
    reasons = ("SOS_QUALIFICATION_FAILED",) if failed else ("SOS_QUALIFICATION_PASSED",)
    return QualificationReceipt(
        contract="sos_qualification_receipt_v1",
        status=status,
        reasons=reasons,
        family_id=family.family_id,
        command_id=family.command_id or "none",
        plan_digest=plan.plan_digest,
        source_tree_digest=plan.source_tree_digest,
        source_status_digest=plan.source_status_digest,
        isolation=family.isolation,
        exit_code=1 if failed else 0,
        output_digest="sha256:" + hashlib.sha256(summary).hexdigest(),
        output_bytes=0,
        raw_output_serialized=False,
        limits=_limits(),
    )


def _run_python_unittest(root: Path, plan: CheckPlan, family: CheckFamily) -> QualificationReceipt:
    isolated = run_isolated_unittest(root, _tracked_paths(root))
    return QualificationReceipt(
        contract="sos_qualification_receipt_v1",
        status=isolated.status,
        reasons=isolated.reasons,
        family_id=family.family_id,
        command_id=family.command_id or "none",
        plan_digest=plan.plan_digest,
        source_tree_digest=plan.source_tree_digest,
        source_status_digest=plan.source_status_digest,
        isolation=family.isolation,
        exit_code=isolated.exit_code,
        output_digest=isolated.output_digest,
        output_bytes=isolated.output_bytes,
        raw_output_serialized=False,
        limits=isolation_limits(),
    )


def _limits() -> dict[str, int]:
    return {
        "tracked_files": _MAX_TRACKED_FILES,
        "tracked_bytes": _MAX_TRACKED_BYTES,
        "source_file_bytes": _MAX_SOURCE_FILE_BYTES,
    }


def _digest_json(value: object) -> str:
    payload = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    return "sha256:" + hashlib.sha256(payload).hexdigest()
