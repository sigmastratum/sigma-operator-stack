from __future__ import annotations

import hashlib
import json
import unittest
from pathlib import Path

from jsonschema import Draft202012Validator

from sos.agent_api import TOOL_NAMES


ROOT = Path(__file__).resolve().parents[1]
CORPUS_PATH = ROOT / "tests" / "platform_conformance_corpus_v1.json"
SCHEMA_PATH = ROOT / "tests" / "platform_conformance_corpus_v1.schema.json"

FAMILY_IDS = (
    "repository_state",
    "existing_control_surfaces",
    "ignored_managed_target",
    "primary_authority",
    "unicode_case_collision",
    "platform_path_grammar",
    "object_kind_and_escape",
    "concurrency_and_lock",
    "crash_recovery",
    "package_lifecycle",
    "receipt_integrity",
    "codex_prerequisite",
    "mcp_boundary",
    "qualification_profile",
)


def load_corpus() -> dict[str, object]:
    return json.loads(CORPUS_PATH.read_text(encoding="utf-8"))


class PlatformConformanceCorpusTests(unittest.TestCase):
    def test_schema_and_exact_closed_family_inventory(self) -> None:
        schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
        Draft202012Validator.check_schema(schema)
        corpus = load_corpus()
        Draft202012Validator(schema).validate(corpus)

        families = corpus["families"]
        self.assertEqual(corpus["family_count"], 14)
        self.assertEqual(
            tuple(family["family_id"] for family in families),
            FAMILY_IDS,
        )
        self.assertEqual(
            tuple(family["ordinal"] for family in families),
            tuple(range(1, 15)),
        )

        case_ids = [
            case["case_id"]
            for family in families
            for case in family["cases"]
        ]
        self.assertEqual(len(case_ids), len(set(case_ids)))

    def test_corpus_binds_exact_mcp_and_platform_execution_boundary(self) -> None:
        corpus = load_corpus()
        self.assertEqual(tuple(corpus["mcp_tools"]), TOOL_NAMES)
        self.assertEqual(corpus["platforms"], ["linux", "windows", "macos"])

        qualification = corpus["families"][-1]["cases"][0]
        expected = qualification["platform_expected"]
        self.assertEqual(expected["linux"]["project_process_count"], 1)
        self.assertEqual(expected["windows"]["project_process_count"], 0)
        self.assertEqual(expected["macos"]["project_process_count"], 0)
        self.assertEqual(
            expected["windows"]["primary_reason"],
            "SOS_EXECUTABLE_QUALIFICATION_UNSUPPORTED",
        )
        self.assertEqual(expected["macos"], expected["windows"])

    def test_every_case_has_bounded_mutation_and_is_content_safe(self) -> None:
        corpus = load_corpus()
        serialized = json.dumps(corpus, sort_keys=True, separators=(",", ":"))
        digest = hashlib.sha256(serialized.encode("utf-8")).hexdigest()
        self.assertEqual(len(digest), 64)

        forbidden = (
            "/home/",
            "C:\\Users\\",
            "session_id",
            "customer",
            "credential",
            "password",
            "provider_response",
        )
        lowered = serialized.lower()
        for value in forbidden:
            self.assertNotIn(value.lower(), lowered)

        for family in corpus["families"]:
            for case in family["cases"]:
                outcomes = [case["expected"], *case.get("platform_expected", {}).values()]
                for outcome in outcomes:
                    previewed_lifecycle_rebind = (
                        family["family_id"] == "package_lifecycle"
                        and "setup.rebind_previewed" in case["facts"]
                        and outcome["status"] == "not_verified"
                        and outcome["receipt_effect"] == "append_valid_tip"
                    )
                    if outcome["status"] != "success" and not previewed_lifecycle_rebind:
                        self.assertFalse(outcome["mutation_allowed"])
                    if outcome["project_process_count"]:
                        self.assertEqual(family["family_id"], "qualification_profile")
                        self.assertEqual(outcome["status"], "success")

    def test_platform_overrides_are_narrow_and_adapter_neutral(self) -> None:
        corpus = load_corpus()
        overridden = {
            family["family_id"]
            for family in corpus["families"]
            if any("platform_expected" in case for case in family["cases"])
        }
        self.assertEqual(overridden, {"platform_path_grammar", "qualification_profile"})

        for family in corpus["families"]:
            for case in family["cases"]:
                self.assertNotIn("adapter", case)
                self.assertNotIn("implementation", case)


if __name__ == "__main__":
    unittest.main()
