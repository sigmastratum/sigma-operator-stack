from __future__ import annotations

import importlib.util
import sys
import unittest
import xml.etree.ElementTree as ET
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
TOOL = ROOT / "tools/verify_windows_wack_report.py"
SPEC = importlib.util.spec_from_file_location("sos_windows_wack_report", TOOL)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)
WackDispositionError = MODULE.WackDispositionError
admit = MODULE.admit


def report(*tests: tuple[str, str, str, tuple[str, ...]]) -> bytes:
    root = ET.Element("REPORT")
    requirements = ET.SubElement(root, "REQUIREMENTS")
    requirement = ET.SubElement(requirements, "REQUIREMENT")
    for index, name, result, messages in tests:
        test = ET.SubElement(
            requirement,
            "TEST",
            INDEX=index,
            NAME=name,
            OPTIONAL="TRUE" if name == "Blocked executables" else "FALSE",
        )
        container = ET.SubElement(test, "MESSAGES")
        for message in messages:
            ET.SubElement(container, "MESSAGE", TEXT=message)
        ET.SubElement(test, "RESULT").text = result
    return ET.tostring(root, encoding="utf-8")


PASS = ("1", "Package sanity", "PASS", ())
DPI = ("92", "DPIAwarenessValidation", "PASS", ())
BLOCKED = (
    "88",
    "Blocked executables",
    "FAIL",
    (
        'File bootstrap\\uv.exe contains a reference to a "Launch Process" related API kernel32.dll!CreateProcessW',
        'File runtime/Lib/subprocess.py contains a blocked executable reference to "cmd"',
    ),
)


class WindowsWackReportTests(unittest.TestCase):
    def test_admits_only_the_documented_package_internal_optional_failure(self) -> None:
        first = admit(report(PASS, BLOCKED, DPI))
        second = admit(report(PASS, BLOCKED, DPI))
        self.assertEqual(first, second)
        self.assertEqual(first["status"], "passed")
        self.assertEqual(first["blocked_executable_finding_count"], 2)
        self.assertEqual(first["admitted_optional_failure_count"], 1)
        self.assertFalse(first["windows_s_mode_claimed"])
        self.assertFalse(first["raw_content_serialized"])

    def test_plain_pass_is_admitted(self) -> None:
        result = admit(report(PASS, DPI))
        self.assertEqual(result["fail_count"], 0)
        self.assertEqual(result["reasons"], [])

    def test_rejects_nonoptional_or_unknown_failure(self) -> None:
        with self.assertRaisesRegex(WackDispositionError, "inadmissible failure"):
            admit(report(PASS, DPI, ("7", "Launch", "FAIL", ())))

    def test_rejects_unresolved_dpi_warning(self) -> None:
        with self.assertRaisesRegex(WackDispositionError, "DPI-awareness"):
            admit(report(PASS, ("92", "DPIAwarenessValidation", "WARNING", ())))

    def test_rejects_unsafe_or_malformed_findings(self) -> None:
        unsafe = (
            "88",
            "Blocked executables",
            "FAIL",
            ('File C:\\private\\tool.exe contains a blocked executable reference to "cmd"',),
        )
        malformed = ("88", "Blocked executables", "FAIL", ("unexpected",))
        for value in (unsafe, malformed):
            with self.subTest(value=value), self.assertRaises(WackDispositionError):
                admit(report(PASS, DPI, value))

    def test_rejects_duplicate_test_identity(self) -> None:
        with self.assertRaisesRegex(WackDispositionError, "identity"):
            admit(report(PASS, PASS, DPI))


if __name__ == "__main__":
    unittest.main()
