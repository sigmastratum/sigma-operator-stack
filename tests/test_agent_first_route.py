from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
import unittest
from copy import deepcopy
from pathlib import Path

from jsonschema import Draft202012Validator


ROOT = Path(__file__).resolve().parents[1]
SCHEMAS = ROOT / "src/sos/schemas"
FIXTURES = ROOT / "tests/fixtures/agent-first-release"
TOOL = ROOT / "tools/resolve_agent_first_route.py"
SPEC = importlib.util.spec_from_file_location("sos_agent_first_route", TOOL)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class AgentFirstRouteTests(unittest.TestCase):
    def setUp(self) -> None:
        self.pointer_bytes = (FIXTURES / "current.json").read_bytes()
        self.index_bytes = (FIXTURES / "sos-release-index-v1.json").read_bytes()
        self.index = json.loads(self.index_bytes)
        self.observation = {
            "contract": "sos_windows_store_observation_v1",
            "execution_context": "interactive_user",
            "installed": True,
            "launcher_available": True,
            "package_family_name": "SSRG.SigmaOperatorStack_2358e20nvr064",
            "package_identity_name": "SSRG.SigmaOperatorStack",
            "package_publisher": "CN=D713C275-467D-4A03-9D24-0DC02F1C3031",
            "package_version": "1.0.5.0",
        }

    def resolve(self, system: str, architecture: str, **kwargs: object) -> dict[str, object]:
        return MODULE.resolve(
            schema_root=SCHEMAS,
            pointer_bytes=kwargs.get("pointer_bytes", self.pointer_bytes),
            index_bytes=kwargs.get("index_bytes", self.index_bytes),
            system=system,
            architecture=architecture,
            observation=kwargs.get("observation"),
        )

    def assert_projection(self, result: dict[str, object]) -> None:
        schema = json.loads(
            (SCHEMAS / "sos-agent-first-route-projection-v1.schema.json").read_text()
        )
        Draft202012Validator(schema).validate(result)
        self.assertFalse(result["network_performed"])
        self.assertFalse(result["mutations_performed"])
        self.assertFalse(result["absolute_paths_serialized"])
        self.assertFalse(result["raw_content_serialized"])
        self.assertEqual(result["provider_calls"], 0)

    def test_archive_route_is_exact_and_ready(self) -> None:
        result = self.resolve("linux", "x86_64")
        self.assert_projection(result)
        self.assertEqual(result["status"], "ready")
        self.assertEqual(result["delivery"], "archive")
        self.assertEqual(result["action"]["kind"], "download_archive")
        self.assertEqual(result["reasons"], ["SOS_AGENT_FIRST_ARCHIVE_READY"])

    def test_windows_store_requires_user_action_before_install(self) -> None:
        result = self.resolve("windows", "x86_64")
        self.assert_projection(result)
        self.assertEqual(result["status"], "user_action_required")
        self.assertEqual(result["action"]["kind"], "open_store")
        self.assertEqual(result["action"]["store_product_id"], "9NNZT70C613H")

    def test_exact_installed_store_package_is_ready(self) -> None:
        result = self.resolve("windows", "x86_64", observation=self.observation)
        self.assert_projection(result)
        self.assertEqual(result["status"], "ready")
        self.assertEqual(result["action"]["kind"], "invoke_launcher")
        self.assertEqual(result["reasons"], ["SOS_AGENT_FIRST_LAUNCHER_READY"])

    def test_sandbox_launcher_refusal_requires_interactive_handoff(self) -> None:
        observation = dict(self.observation)
        observation["execution_context"] = "sandbox"
        observation["launcher_available"] = False
        result = self.resolve("windows", "x86_64", observation=observation)
        self.assert_projection(result)
        self.assertEqual(result["status"], "user_action_required")
        self.assertEqual(result["action"]["kind"], "handoff_to_interactive_user")
        self.assertEqual(result["reasons"], ["SOS_INTERACTIVE_USER_HANDOFF_REQUIRED"])

    def test_store_binding_mismatch_blocks(self) -> None:
        observation = dict(self.observation)
        observation["package_version"] = "1.0.2.0"
        result = self.resolve("windows", "x86_64", observation=observation)
        self.assert_projection(result)
        self.assertEqual(result["status"], "blocked")
        self.assertEqual(result["reasons"], ["SOS_WINDOWS_STORE_PACKAGE_BINDING_MISMATCH"])

    def test_withheld_pointer_blocks(self) -> None:
        pointer = json.loads(self.pointer_bytes)
        pointer["availability"] = "withheld"
        result = self.resolve(
            "linux",
            "x86_64",
            pointer_bytes=json.dumps(pointer, sort_keys=True).encode(),
        )
        self.assert_projection(result)
        self.assertEqual(result["status"], "blocked")
        self.assertEqual(result["reasons"], ["SOS_PUBLIC_RELEASE_WITHHELD"])

    def test_ambiguous_and_unknown_platforms_fail_closed(self) -> None:
        ambiguous = deepcopy(self.index)
        ambiguous["platforms"].append(deepcopy(ambiguous["platforms"][0]))
        ambiguous_bytes = json.dumps(ambiguous, sort_keys=True, separators=(",", ":")).encode()
        pointer = json.loads(self.pointer_bytes)
        import hashlib

        pointer["index_sha256"] = hashlib.sha256(ambiguous_bytes).hexdigest()
        result = self.resolve(
            "linux",
            "x86_64",
            pointer_bytes=json.dumps(pointer, sort_keys=True).encode(),
            index_bytes=ambiguous_bytes,
        )
        self.assert_projection(result)
        self.assertEqual(result["status"], "blocked")
        self.assertEqual(result["reasons"], ["SOS_PUBLIC_RELEASE_PLATFORM_AMBIGUOUS"])
        unknown = self.resolve("darwin", "arm64")
        self.assert_projection(unknown)
        self.assertEqual(unknown["status"], "unsupported")

    def test_projection_digest_is_deterministic(self) -> None:
        first = self.resolve("windows", "x86_64")
        second = self.resolve("windows", "x86_64")
        self.assertEqual(first, second)

    def test_cli_stops_for_user_action(self) -> None:
        completed = subprocess.run(
            [
                sys.executable,
                str(TOOL),
                "--pointer",
                str(FIXTURES / "current.json"),
                "--index",
                str(FIXTURES / "sos-release-index-v1.json"),
                "--schemas",
                str(SCHEMAS),
                "--system",
                "windows",
                "--architecture",
                "x86_64",
            ],
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        self.assertEqual(completed.returncode, 2)
        self.assertEqual(json.loads(completed.stdout)["status"], "user_action_required")
        self.assertEqual(completed.stderr, "")


if __name__ == "__main__":
    unittest.main()
