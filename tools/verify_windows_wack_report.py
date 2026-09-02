#!/usr/bin/env python3
"""Admit one bounded WACK report for the Windows Desktop Store profile.

Microsoft documents the Desktop Bridge "Blocked executables" test as a
Windows S-mode compatibility check and permits an in-package finding to be
ignored when the flagged file is part of the application:
https://learn.microsoft.com/windows/uwp/debug-test-perf/windows-desktop-bridge-app-tests
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
import xml.etree.ElementTree as ET
from pathlib import PurePosixPath


CONTRACT = "sos_windows_wack_disposition_v1"
MAX_REPORT_BYTES = 4 * 1024 * 1024
MAX_TESTS = 256
MAX_MESSAGES = 512
MAX_MESSAGE_BYTES = 4096
BLOCKED_NAME = "Blocked executables"
DPI_NAME = "DPIAwarenessValidation"
BLOCKED_MESSAGE = re.compile(
    r'^File (?P<path>.+?) contains (?:a reference to a "Launch Process" related API .+|a blocked executable reference to ".+")$'
)


class WackDispositionError(ValueError):
    pass


def safe_package_path(value: str) -> str:
    if not value or value.startswith(("/", "\\")) or "\0" in value or ":" in value:
        raise WackDispositionError("WACK finding path is not package-relative")
    normalized = value.replace("\\", "/")
    path = PurePosixPath(normalized)
    if path.is_absolute() or any(part in ("", ".", "..") for part in path.parts):
        raise WackDispositionError("WACK finding path is not package-relative")
    return path.as_posix()


def admit(payload: bytes) -> dict[str, object]:
    if not payload or len(payload) > MAX_REPORT_BYTES:
        raise WackDispositionError("WACK report size is invalid")
    try:
        root = ET.fromstring(payload)
    except ET.ParseError as error:
        raise WackDispositionError("WACK report XML is invalid") from error
    if root.tag != "REPORT":
        raise WackDispositionError("WACK report root is invalid")
    tests = root.findall(".//TEST")
    if not 1 <= len(tests) <= MAX_TESTS:
        raise WackDispositionError("WACK test cardinality is invalid")

    indexes: set[str] = set()
    counts = {"PASS": 0, "WARNING": 0, "FAIL": 0}
    blocked_findings = 0
    blocked_seen = False
    dpi_seen = False
    reasons: list[str] = []
    for test in tests:
        index = test.get("INDEX", "")
        name = test.get("NAME", "")
        optional = test.get("OPTIONAL", "")
        result = (test.findtext("RESULT") or "").strip()
        if not index.isdecimal() or index in indexes or not name or optional not in {"TRUE", "FALSE"}:
            raise WackDispositionError("WACK test identity is invalid")
        if result not in counts:
            raise WackDispositionError("WACK test result is invalid")
        indexes.add(index)
        counts[result] += 1

        if name == DPI_NAME:
            if dpi_seen or optional != "FALSE" or result != "PASS":
                raise WackDispositionError("WACK DPI-awareness test did not pass")
            dpi_seen = True

        if result == "FAIL":
            if name != BLOCKED_NAME or optional != "TRUE" or blocked_seen:
                raise WackDispositionError("WACK contains an inadmissible failure")
            blocked_seen = True
            messages = test.findall("./MESSAGES/MESSAGE")
            if not 1 <= len(messages) <= MAX_MESSAGES:
                raise WackDispositionError("WACK blocked-executable findings are unbounded")
            for message in messages:
                text = message.get("TEXT", "")
                if len(text.encode("utf-8")) > MAX_MESSAGE_BYTES:
                    raise WackDispositionError("WACK finding exceeds the size limit")
                match = BLOCKED_MESSAGE.fullmatch(text)
                if match is None:
                    raise WackDispositionError("WACK blocked-executable finding is malformed")
                safe_package_path(match.group("path"))
            blocked_findings = len(messages)
            reasons.append("SOS_WACK_OPTIONAL_PACKAGE_INTERNAL_PROCESS_LAUNCH_FINDINGS")

    if not dpi_seen:
        raise WackDispositionError("WACK DPI-awareness test is missing")
    if counts["WARNING"]:
        raise WackDispositionError("WACK contains an unresolved warning")

    projection = {
        "admitted_optional_failure_count": 1 if blocked_seen else 0,
        "blocked_executable_finding_count": blocked_findings,
        "contract": CONTRACT,
        "dpi_awareness": "passed",
        "fail_count": counts["FAIL"],
        "pass_count": counts["PASS"],
        "raw_content_serialized": False,
        "reasons": reasons,
        "status": "passed",
        "test_count": len(tests),
        "warning_count": counts["WARNING"],
        "windows_s_mode_claimed": False,
    }
    digest_payload = json.dumps(projection, sort_keys=True, separators=(",", ":")).encode()
    projection["report_digest"] = "sha256:" + hashlib.sha256(digest_payload).hexdigest()
    projection["wack_report_sha256"] = "sha256:" + hashlib.sha256(payload).hexdigest()
    return projection


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--report", required=True)
    arguments = parser.parse_args()
    try:
        payload = open(arguments.report, "rb").read(MAX_REPORT_BYTES + 1)
        report = admit(payload)
    except (OSError, WackDispositionError) as error:
        print(f"SOS_WACK_REPORT_NOT_ADMITTED: {error}", file=sys.stderr)
        return 2
    print(json.dumps(report, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
