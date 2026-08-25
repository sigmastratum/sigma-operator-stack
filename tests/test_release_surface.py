from __future__ import annotations

import json
import importlib.util
import io
import subprocess
import sys
import unittest
from pathlib import Path

import yaml
from PIL import Image, PngImagePlugin


class PublicReleaseSurfaceTests(unittest.TestCase):
    def test_repository_content_is_public_safe(self) -> None:
        root = Path(__file__).resolve().parents[1]
        result = self.run_tool(root, "check_public_release.py")
        self.assertEqual(result["status"], "passed", result)

    def test_ci_and_release_workflows_are_fail_closed(self) -> None:
        root = Path(__file__).resolve().parents[1]
        result = self.run_tool(root, "check_workflows.py")
        self.assertEqual(result["status"], "passed", result)

    def test_release_bundle_retains_checked_first_run_assets(self) -> None:
        root = Path(__file__).resolve().parents[1]
        finalizer = (root / "tools" / "finalize_release_bundle.py").read_text(encoding="utf-8")
        release = (root / ".github" / "workflows" / "release.yml").read_text(encoding="utf-8")
        for name in ("START-HERE.md", "start-sos-alpha", "start-sos-windows.ps1"):
            self.assertIn(name, finalizer)
            self.assertIn(name, release)

    def test_public_readme_orders_outcome_before_detail(self) -> None:
        root = Path(__file__).resolve().parents[1]
        readme = (root / "README.md").read_text(encoding="utf-8")
        headings = [
            "## See the recovery loop",
            "## Quickstart",
            "## Three failures SOS prevents",
            "## Support matrix",
            "## Coexistence with an existing project",
            "## Trust boundary",
            "## Contributing and support",
        ]
        positions = [readme.index(heading) for heading in headings]
        self.assertEqual(positions, sorted(positions))

    def test_issue_forms_are_typed_and_public_safe(self) -> None:
        root = Path(__file__).resolve().parents[1]
        forms = sorted((root / ".github" / "ISSUE_TEMPLATE").glob("*.yml"))
        forms = [path for path in forms if path.name != "config.yml"]
        self.assertEqual(len(forms), 7)
        required = {"version", "os_profile", "command", "reason_code", "reproducer", "privacy"}
        for path in forms:
            value = yaml.load(path.read_text(encoding="utf-8"), Loader=yaml.BaseLoader)
            ids = {item.get("id") for item in value["body"] if isinstance(item, dict)}
            self.assertTrue(required.issubset(ids), path.name)
            serialized = json.dumps(value, sort_keys=True).lower()
            for phrase in ("secrets", "private source", "prompts", "raw .sigma", "customer data"):
                self.assertIn(phrase, serialized, path.name)

    def test_demo_media_and_good_first_issue_bounds(self) -> None:
        root = Path(__file__).resolve().parents[1]
        for name in ("recovery-loop.png",):
            self.assertLess((root / "demo" / name).stat().st_size, 2 * 1024 * 1024)
        drafts = sorted((root / "docs" / "good-first-issues").glob("*.md"))
        self.assertEqual(len(drafts), 5)
        for draft in drafts:
            text = draft.read_text(encoding="utf-8")
            for heading in ("## Files", "## Acceptance", "## Test", "## Non-goals"):
                self.assertIn(heading, text, draft.name)

    def test_media_scanner_rejects_metadata_and_visible_text_drift(self) -> None:
        root = Path(__file__).resolve().parents[1]
        specification = importlib.util.spec_from_file_location(
            "sos_public_scan", root / "tools" / "check_public_release.py"
        )
        self.assertIsNotNone(specification)
        self.assertIsNotNone(specification.loader)
        module = importlib.util.module_from_spec(specification)
        specification.loader.exec_module(module)
        original = (root / "demo" / "recovery-loop.png").read_bytes()

        with Image.open(io.BytesIO(original)) as image:
            metadata = PngImagePlugin.PngInfo()
            metadata.add_text("Comment", "forbidden synthetic metadata")
            encoded = io.BytesIO()
            image.save(encoded, format="PNG", pnginfo=metadata)
        failures: list[str] = []
        module._check_media_bytes("demo/recovery-loop.png", encoded.getvalue(), failures)
        self.assertIn(
            "SOS_PUBLIC_MEDIA_METADATA_FORBIDDEN:demo/recovery-loop.png",
            failures,
        )

        changed = bytearray(original)
        changed[-16] ^= 1
        failures = []
        module._check_media_bytes("demo/recovery-loop.png", bytes(changed), failures)
        self.assertTrue(
            any(
                failure.startswith((
                    "SOS_PUBLIC_MEDIA_PARSE_FAILED:",
                    "SOS_PUBLIC_MEDIA_RENDERED_TEXT_UNVERIFIED:",
                ))
                for failure in failures
            ),
            failures,
        )

    def run_tool(self, root: Path, name: str) -> dict[str, object]:
        completed = subprocess.run(
            [sys.executable, str(root / "tools" / name), "--repository", str(root)],
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        return json.loads(completed.stdout)


if __name__ == "__main__":
    unittest.main()
