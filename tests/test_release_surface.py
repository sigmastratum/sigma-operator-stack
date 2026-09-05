from __future__ import annotations

import json
import importlib.util
import io
import hashlib
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

import yaml
from PIL import Image, PngImagePlugin


class PublicReleaseSurfaceTests(unittest.TestCase):
    def test_repository_content_is_public_safe(self) -> None:
        root = Path(__file__).resolve().parents[1]
        result = self.run_tool(root, "check_public_release.py")
        self.assertEqual(result["status"], "passed", result)

    def test_public_scanner_checks_links_in_every_markdown_file(self) -> None:
        root = Path(__file__).resolve().parents[1]
        specification = importlib.util.spec_from_file_location(
            "sos_public_scan_links", root / "tools" / "check_public_release.py"
        )
        self.assertIsNotNone(specification)
        self.assertIsNotNone(specification.loader)
        module = importlib.util.module_from_spec(specification)
        specification.loader.exec_module(module)
        with self.subTest("non_readme_path"):
            import tempfile

            with tempfile.TemporaryDirectory() as temporary:
                repository = Path(temporary).resolve()
                (repository / "docs").mkdir()
                (repository / "README.md").write_text("# Safe\n", encoding="utf-8")
                (repository / "docs" / "guide.md").write_text(
                    "# Guide\n[missing](missing.md)\n", encoding="utf-8"
                )
                failures: list[str] = []
                module._check_markdown_links(
                    repository,
                    ["README.md", "docs/guide.md"],
                    failures,
                )
                self.assertEqual(
                    failures,
                    ["SOS_PUBLIC_MARKDOWN_LINK_BROKEN:docs/guide.md"],
                )

    def test_public_scanner_rejects_forbidden_content_removed_from_head(self) -> None:
        root = Path(__file__).resolve().parents[1]
        specification = importlib.util.spec_from_file_location(
            "sos_public_scan_history", root / "tools" / "check_public_release.py"
        )
        self.assertIsNotNone(specification)
        self.assertIsNotNone(specification.loader)
        module = importlib.util.module_from_spec(specification)
        specification.loader.exec_module(module)
        with tempfile.TemporaryDirectory() as temporary:
            repository = Path(temporary).resolve()
            subprocess.run(["git", "init", "-q", repository], check=True)
            subprocess.run(
                ["git", "-C", repository, "config", "user.name", "Synthetic Reviewer"],
                check=True,
            )
            subprocess.run(
                ["git", "-C", repository, "config", "user.email", "reviewer@example.invalid"],
                check=True,
            )
            leaked = repository / "removed.txt"
            forbidden_path = "/" + "home" + "/example/private-project"
            leaked.write_text(f"private path: {forbidden_path}\n", encoding="utf-8")
            subprocess.run(["git", "-C", repository, "add", "removed.txt"], check=True)
            subprocess.run(["git", "-C", repository, "commit", "-qm", "synthetic root"], check=True)
            leaked.unlink()
            subprocess.run(["git", "-C", repository, "add", "-u"], check=True)
            subprocess.run(["git", "-C", repository, "commit", "-qm", "remove fixture"], check=True)
            failures: list[str] = []
            commit_count, scanned = module._check_git_history(repository, failures)
            self.assertEqual(commit_count, 2)
            self.assertGreater(scanned, 0)
            self.assertIn("SOS_PUBLIC_HISTORY_CONTENT_FORBIDDEN", failures)

    def test_ci_and_release_workflows_are_fail_closed(self) -> None:
        root = Path(__file__).resolve().parents[1]
        result = self.run_tool(root, "check_workflows.py")
        self.assertEqual(result["status"], "passed", result)

    def test_release_workflow_requires_complete_pre_staged_native_assets(self) -> None:
        root = Path(__file__).resolve().parents[1]
        workflow = (root / ".github/workflows/release.yml").read_text(encoding="utf-8")
        for required in (
            "Verify complete pre-staged draft GitHub Release",
            'cp tools/check_native_release_assets.py "$RUNNER_TEMP/routing/"',
            'python "$RUNNER_TEMP/routing/check_native_release_assets.py" --index',
            'cd "$RUNNER_TEMP/existing"',
            "sha256sum -c SHA256SUMS",
            "SOS-Linux-0.1.0a3.zip",
            "SOS-macOS-0.1.0a3.tar.gz",
            "--json isDraft",
        ):
            self.assertIn(required, workflow)
        self.assertNotIn("gh release create", workflow)
        self.assertNotIn('cmp "$RUNNER_TEMP/existing/SHA256SUMS"', workflow)

    def test_native_asset_verifier_survives_candidate_checkout(self) -> None:
        root = Path(__file__).resolve().parents[1]
        workflow = (root / ".github/workflows/release.yml").read_text(encoding="utf-8")
        preserve = workflow.index('cp tools/check_native_release_assets.py "$RUNNER_TEMP/routing/"')
        checkout = workflow.index("Check out immutable release candidate")
        initial_execute = workflow.index(
            'python "$RUNNER_TEMP/routing/check_native_release_assets.py" --index'
        )
        final_execute = workflow.rindex(
            'python "$RUNNER_TEMP/routing/check_native_release_assets.py" --index'
        )
        self.assertLess(preserve, checkout)
        self.assertLess(preserve, initial_execute)
        self.assertLess(initial_execute, checkout)
        self.assertLess(checkout, final_execute)
        self.assertNotIn("python tools/check_native_release_assets.py --index", workflow)

    def test_pypi_publication_requires_a_separate_explicit_gate(self) -> None:
        root = Path(__file__).resolve().parents[1]
        workflow = (root / ".github/workflows/release.yml").read_text(encoding="utf-8")
        self.assertIn("publish_pypi:", workflow)
        self.assertIn("default: false", workflow)
        self.assertIn("if: inputs.publish_pypi == true", workflow)
        self.assertIn(
            "if: inputs.publish_pypi == true && steps.pypi.outputs.publish_required == 'true'",
            workflow,
        )
        specification = importlib.util.spec_from_file_location(
            "sos_workflow_pypi_gate", root / "tools" / "check_workflows.py"
        )
        self.assertIsNotNone(specification)
        self.assertIsNotNone(specification.loader)
        module = importlib.util.module_from_spec(specification)
        specification.loader.exec_module(module)
        with tempfile.TemporaryDirectory() as temporary:
            repository = Path(temporary)
            shutil.copytree(root / ".github", repository / ".github")
            (repository / "tools").mkdir()
            shutil.copy2(
                root / "tools" / "check_public_release_pointer.py",
                repository / "tools" / "check_public_release_pointer.py",
            )
            release = repository / ".github/workflows/release.yml"
            release.write_text(
                release.read_text(encoding="utf-8").replace(
                    "        if: inputs.publish_pypi == true\n        run: |",
                    "        run: |",
                    1,
                ),
                encoding="utf-8",
            )
            result = module.inspect(repository)
            self.assertIn("SOS_RELEASE_PYPI_AUTHORITY_NOT_SEPARATED", result["failures"])

    def test_pointer_dependencies_are_installed_before_pointer_verification(self) -> None:
        root = Path(__file__).resolve().parents[1]
        workflow = (root / ".github/workflows/release.yml").read_text(encoding="utf-8")
        dependency_step = workflow.index("Install exact pointer verification dependencies")
        pointer_step = workflow.index("Verify routing pointer and preserve it")
        self.assertLess(dependency_step, pointer_step)
        self.assertIn(
            "python -m pip install --disable-pip-version-check -r requirements/runtime.txt",
            workflow[dependency_step:pointer_step],
        )

    def test_release_build_python_is_exactly_bound(self) -> None:
        root = Path(__file__).resolve().parents[1]
        workflow = (root / ".github/workflows/release.yml").read_text(encoding="utf-8")
        self.assertIn('python-version: "3.12.3"', workflow)
        self.assertNotIn('python-version: "3.12"', workflow)

    def test_release_qualifies_the_exact_staged_wheel(self) -> None:
        root = Path(__file__).resolve().parents[1]
        workflow = (root / ".github/workflows/release.yml").read_text(encoding="utf-8")
        preserve = workflow.index('cp tools/compare_wheel_payloads.py "$RUNNER_TEMP/routing/"')
        checkout = workflow.index("Check out immutable release candidate")
        execute = workflow.index(
            'python "$RUNNER_TEMP/routing/compare_wheel_payloads.py" --rebuilt'
        )
        self.assertLess(preserve, checkout)
        self.assertLess(checkout, execute)
        self.assertIn(
            'cp "$RUNNER_TEMP/existing/sigma_operator_stack-0.1.0a3-py3-none-any.whl" "$RUNNER_TEMP/publish/"',
            workflow,
        )
        self.assertNotIn(
            'cp "$RUNNER_TEMP/a/sigma_operator_stack-0.1.0a3-py3-none-any.whl" "$RUNNER_TEMP/publish/"',
            workflow,
        )

    def test_alpha_release_is_published_as_nonlatest_prerelease(self) -> None:
        root = Path(__file__).resolve().parents[1]
        workflow = (root / ".github/workflows/release.yml").read_text(encoding="utf-8")
        self.assertIn("--draft=false --prerelease --latest=false", workflow)

    def test_ci_fetches_full_history_for_public_pointer_and_history_scan(self) -> None:
        root = Path(__file__).resolve().parents[1]
        specification = importlib.util.spec_from_file_location(
            "sos_workflow_contract", root / "tools" / "check_workflows.py"
        )
        self.assertIsNotNone(specification)
        self.assertIsNotNone(specification.loader)
        module = importlib.util.module_from_spec(specification)
        specification.loader.exec_module(module)
        result = module.inspect(root)
        self.assertFalse(
            [
                failure
                for failure in result["failures"]
                if failure.startswith("SOS_CI_FULL_HISTORY_CHECKOUT_MISSING")
            ],
            result,
        )

    def test_generic_release_bundle_verification_is_explicit_and_fail_closed(self) -> None:
        root = Path(__file__).resolve().parents[1]
        specification = importlib.util.spec_from_file_location(
            "sos_workflow_contract", root / "tools" / "check_workflows.py"
        )
        self.assertIsNotNone(specification)
        self.assertIsNotNone(specification.loader)
        module = importlib.util.module_from_spec(specification)
        specification.loader.exec_module(module)
        for workflow_name in ("ci.yml", "release.yml"):
            workflow = (root / ".github" / "workflows" / workflow_name).read_text(
                encoding="utf-8"
            )
            self.assertIn("verify_bundle", workflow)
            self.assertIn("system='Source'", workflow)
        with tempfile.TemporaryDirectory() as temporary:
            repository = Path(temporary).resolve()
            shutil.copytree(root / ".github", repository / ".github")
            (repository / "tools").mkdir()
            shutil.copy2(
                root / "tools" / "check_public_release_pointer.py",
                repository / "tools" / "check_public_release_pointer.py",
            )
            workflow_path = repository / ".github" / "workflows" / "ci.yml"
            workflow_path.write_text(
                workflow_path.read_text(encoding="utf-8").replace(
                    ", system='Source'", "", 1
                ),
                encoding="utf-8",
            )
            result = module.inspect(repository)
            self.assertIn(
                "SOS_GENERIC_RELEASE_BUNDLE_GATE_INCOMPLETE", result["failures"]
            )

    def test_public_release_pointer_is_present_and_candidate_bound(self) -> None:
        root = Path(__file__).resolve().parents[1]
        result = self.run_tool(root, "check_public_release_pointer.py")
        self.assertEqual(result["status"], "passed", result)
        self.assertTrue((root / "release" / "current.json").is_file())

    def test_installers_directory_is_clearly_build_source_only(self) -> None:
        root = Path(__file__).resolve().parents[1]
        text = " ".join(
            (root / "installers" / "README.md").read_text(encoding="utf-8").split()
        )
        for required in (
            "These files are not a public SOS installer",
            "Do not download or run an individual script",
            "Public availability is determined only",
            "never a supported installation route",
            "canonical install-with-Codex route",
            "not standalone end-user assets",
        ):
            self.assertIn(required, text)

    def test_repository_opening_runbook_separates_remote_gates(self) -> None:
        root = Path(__file__).resolve().parents[1]
        text = (root / "docs" / "repository-opening-runbook.md").read_text(
            encoding="utf-8"
        )
        for required in (
            "full-history public scans",
            "private vulnerability reporting",
            "immediately enable private vulnerability reporting",
            "rollback-bound transaction",
            "Do not create a tag",
            "return the repository to private",
            "Public exposure cannot be",
            "undone historically",
            "PyPI publication",
            "Microsoft Store publication",
        ):
            self.assertIn(required, text)
        self.assertNotIn(
            "private vulnerability reporting can be enabled before visibility changes",
            text,
        )

    def test_windows_signing_is_oidc_only_and_digest_bound(self) -> None:
        root = Path(__file__).resolve().parents[1]
        workflow = (root / ".github" / "workflows" / "windows-sign.yml").read_text(
            encoding="utf-8"
        )
        verifier = (root / "tools" / "verify_windows_signature.ps1").read_text(
            encoding="utf-8"
        )
        for required in (
            "SOS_WINDOWS_APPROVED_CANDIDATE",
            "SOS_WINDOWS_APPROVED_UNSIGNED_SHA256",
            "id-token: write",
            "file-digest: SHA256",
            "timestamp-digest: SHA256",
            "Get-AuthenticodeSignature",
            "TimeStamperCertificate",
            "signed_sha256",
            "unsigned_sha256",
        ):
            self.assertIn(required, workflow + verifier)
        for forbidden in ("client-secret", "AZURE_CREDENTIALS", "-ExecutionPolicy Bypass"):
            self.assertNotIn(forbidden, workflow + verifier)

    def test_release_bundle_retains_checked_first_run_assets(self) -> None:
        root = Path(__file__).resolve().parents[1]
        finalizer = (root / "tools" / "finalize_release_bundle.py").read_text(encoding="utf-8")
        release = (root / ".github" / "workflows" / "release.yml").read_text(encoding="utf-8")
        for name in ("START-HERE.md", "alpha-feedback.md", "start-sos-alpha"):
            self.assertIn(name, finalizer)
            self.assertIn(name, release)
        self.assertNotIn("start-sos-windows.ps1", finalizer)
        self.assertNotIn("start-sos-windows.ps1", release)

    def test_public_readme_orders_outcome_before_detail(self) -> None:
        root = Path(__file__).resolve().parents[1]
        readme = (root / "README.md").read_text(encoding="utf-8")
        headings = [
            "## See the recovery loop",
            "## Install with Codex",
            "## Three failures SOS prevents",
            "## Support matrix",
            "## Coexistence with an existing project",
            "## Trust boundary",
            "## Contributing and support",
        ]
        positions = [readme.index(heading) for heading in headings]
        self.assertEqual(positions, sorted(positions))

    def test_public_update_claim_is_exact_and_bounded(self) -> None:
        root = Path(__file__).resolve().parents[1]
        update = (root / "docs" / "version-update.md").read_text(encoding="utf-8")
        roadmap = (root / "docs" / "roadmap.md").read_text(encoding="utf-8")
        architecture = (root / "docs" / "architecture.md").read_text(encoding="utf-8")
        threat = (root / "docs" / "threat-model.md").read_text(encoding="utf-8")
        readme = (root / "README.md").read_text(encoding="utf-8")
        joined = " ".join("\n".join((update, architecture)).split())
        for phrase in (
            "valid_stale",
            "does not keep a global project inventory",
            "performs no automatic package acquisition or migration",
        ):
            self.assertIn(phrase, joined)
        self.assertIn("qualified package-bound `N -> N+1 -> N`", roadmap)
        self.assertIn("predecessor artifact", threat)
        self.assertIn(
            "setup rebind alone cannot manufacture green",
            " ".join(readme.split()),
        )

    def test_source_opening_truth_and_launch_measurement_are_explicit(self) -> None:
        root = Path(__file__).resolve().parents[1]
        security = " ".join((root / "SECURITY.md").read_text(encoding="utf-8").split())
        changelog = (root / "CHANGELOG.md").read_text(encoding="utf-8")
        checklist = (root / "docs/publication-checklist.md").read_text(encoding="utf-8")
        launch = (root / "docs/launch-operations.md").read_text(encoding="utf-8")
        readme = " ".join((root / "README.md").read_text(encoding="utf-8").split())
        demo = " ".join((root / "demo/README.md").read_text(encoding="utf-8").split())

        self.assertIn("exact alpha artifacts selected by `release/current.json`", security)
        self.assertIn("Security fixes are provided for the latest published", security)
        self.assertIn("## 0.1.0a3 — 2026-09-05", changelog)
        self.assertNotIn("releases/tag/v0.1.0a3", changelog)
        for heading in (
            "## Gate 1: source preview opening",
            "## Gate 2: Linux/macOS installable release",
            "## Gate 3: Windows Store admission",
            "## Gate 4: promotion",
        ):
            self.assertIn(heading, checklist)
        for required in ("@sigmastratum", "D+2", "D+7", "D+14", "D+30", "not adoption"):
            self.assertIn(required, launch)
        for required in ("verified predecessor evidence", "not evidence for the current source HEAD"):
            self.assertIn(required, readme)
        self.assertIn("verified predecessor evidence for the product principle", demo)
        self.assertIn("unsigned/not-notarized", readme.lower())
        self.assertIn("accepted Community Alpha defer", checklist)
        for forbidden in ("xattr -d", "spctl --master-disable"):
            self.assertNotIn(forbidden, readme + checklist)

    def test_alpha_scope_issue_is_local_public_safe_draft(self) -> None:
        root = Path(__file__).resolve().parents[1]
        text = (root / "docs/alpha-scope-issue.md").read_text(encoding="utf-8")
        self.assertIn("Community alpha scope and known limitations — 0.1.0a3", text)
        self.assertIn("Do not create it remotely", text)
        self.assertIn("Stars, clones, views, forks and", text)
        self.assertIn("not adoption", text)

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

    def test_alpha_feedback_contract_is_public_safe(self) -> None:
        root = Path(__file__).resolve().parents[1]
        text = " ".join(
            (root / "docs" / "alpha-feedback.md").read_text(encoding="utf-8").lower().split()
        )
        for required in (
            "sos --version",
            "exit code",
            "reason code",
            "synthetic",
            "do not include",
            "raw `.sigma`",
            "credentials",
            "private vulnerability reporting",
        ):
            self.assertIn(required, text)

    def test_demo_media_and_good_first_issue_bounds(self) -> None:
        root = Path(__file__).resolve().parents[1]
        for name in ("recovery-loop.png", "recovery-terminal.png"):
            self.assertLess((root / "demo" / name).stat().st_size, 2 * 1024 * 1024)
        manifest = json.loads((root / "demo" / "media-manifest.json").read_text(encoding="utf-8"))
        self.assertEqual(manifest["contract"], "sos_demo_media_manifest_v2")
        self.assertTrue(manifest["synthetic_repository"])
        self.assertEqual(manifest["provider_calls"], 2)
        self.assertEqual(manifest["fresh_codex_provider_calls"], 1)
        self.assertGreaterEqual(manifest["duration_seconds"], 60)
        self.assertLessEqual(manifest["duration_seconds"], 120)
        receipt = json.loads((root / "demo" / "fresh-codex-receipt.json").read_text(encoding="utf-8"))
        self.assertEqual(receipt["contract"], "sos_fresh_codex_capture_receipt_v1")
        self.assertEqual(receipt["status"], "passed")
        self.assertEqual(receipt["provider_calls"], 1)
        self.assertEqual(receipt["shell_calls"], 0)
        self.assertEqual(receipt["mutation_tool_calls"], 0)
        voiceover = manifest["voiceover"]
        self.assertEqual(voiceover["provider_calls"], 1)
        self.assertEqual(voiceover["model"], "gpt-4o-mini-tts-2025-12-15")
        self.assertEqual(voiceover["voice"], "marin")
        self.assertEqual(
            voiceover["text_sha256"],
            hashlib.sha256((root / "demo" / "voiceover.txt").read_bytes()).hexdigest(),
        )
        self.assertEqual(
            voiceover["sha256"],
            hashlib.sha256((root / "demo" / "voiceover.mp3").read_bytes()).hexdigest(),
        )
        for field in ("candidate", "tree", "wheel_sha256"):
            self.assertEqual(manifest[field], receipt[field])
        for name in ("recovery-demo.mp4", "recovery-demo.webm"):
            data = (root / "demo" / name).read_bytes()
            self.assertLess(len(data), 2 * 1024 * 1024)
            self.assertEqual(hashlib.sha256(data).hexdigest(), manifest["media"][name]["sha256"])
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
