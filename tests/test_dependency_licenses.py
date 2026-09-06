from __future__ import annotations

import importlib.util
import json
import shutil
import tempfile
import unittest
import zipfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "sos_dependency_license_check",
    ROOT / "tools/check_dependency_licenses.py",
)
assert SPEC is not None and SPEC.loader is not None
CHECKER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CHECKER)


class DependencyLicenseTests(unittest.TestCase):
    def test_sbom_generator_preserves_virtual_environment_entrypoint(self) -> None:
        source = (ROOT / "tools/generate_release_sbom.py").read_text(encoding="utf-8")
        self.assertIn(
            "python = (environment_python or tool_python).absolute()",
            source,
        )
        self.assertNotIn(
            "python = (environment_python or tool_python).resolve",
            source,
        )

    def _repository(self, target: Path) -> Path:
        for relative in (
            "pyproject.toml",
            "requirements/audit.txt",
            "requirements/dependency-licenses.json",
            "requirements/release.txt",
            "requirements/runtime.txt",
            "tools/build_native_alpha_bundles.py",
            "tools/build_windows_msix_packet.py",
        ):
            source = ROOT / relative
            destination = target / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(source, destination)
        return target

    def test_exact_repository_inventory_passes(self) -> None:
        result = CHECKER.inspect(ROOT, [], None)
        self.assertEqual(result["status"], "passed", result)
        self.assertEqual(result["runtime_component_count"], 7)
        self.assertFalse(result["notice_required"])

    def test_missing_extra_duplicate_and_unknown_license_fail_closed(self) -> None:
        mutations = {
            "missing": lambda value: value["runtime"].pop(),
            "extra": lambda value: value["runtime"].append(
                {
                    "license_expression": "MIT",
                    "license_files": ["LICENSE"],
                    "name": "unknown-runtime",
                    "version": "1.0.0",
                }
            ),
            "duplicate": lambda value: value["runtime"].append(dict(value["runtime"][0])),
            "unknown_license": lambda value: value["runtime"][0].update(
                {"license_expression": "UNKNOWN"}
            ),
        }
        for name, mutate in mutations.items():
            with self.subTest(name=name), tempfile.TemporaryDirectory() as temporary:
                repository = self._repository(Path(temporary))
                inventory_path = repository / "requirements/dependency-licenses.json"
                value = json.loads(inventory_path.read_text(encoding="utf-8"))
                mutate(value)
                inventory_path.write_text(json.dumps(value), encoding="utf-8")
                result = CHECKER.inspect(repository, [], None)
                self.assertEqual(result["status"], "failed", result)

    def test_wheel_license_file_is_required(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            wheelhouse = Path(temporary)
            wheel = wheelhouse / "attrs-26.1.0-py3-none-any.whl"
            with zipfile.ZipFile(wheel, "w") as archive:
                archive.writestr(
                    "attrs-26.1.0.dist-info/METADATA",
                    "Metadata-Version: 2.4\nName: attrs\nVersion: 26.1.0\n"
                    "License-Expression: MIT\nLicense-File: LICENSE\n",
                )
            failures: list[str] = []
            CHECKER._check_wheelhouse(
                wheelhouse,
                {
                    "attrs": {
                        "license_expression": "MIT",
                        "license_files": ["LICENSE"],
                        "name": "attrs",
                        "version": "26.1.0",
                    }
                },
                failures,
            )
            self.assertEqual(
                failures,
                ["SOS_DEPENDENCY_WHEEL_LICENSE_FILE_MISSING:attrs"],
            )

    def test_sbom_rejects_unknown_dependency_and_license(self) -> None:
        document = {
            "components": [
                {
                    "bom-ref": "unknown",
                    "licenses": [],
                    "name": "unknown-runtime",
                    "version": "1.0.0",
                }
            ],
            "dependencies": [
                {"dependsOn": ["unknown"], "ref": "root"},
                {"dependsOn": [], "ref": "unknown"},
            ],
            "metadata": {
                "component": {
                    "bom-ref": "root",
                    "licenses": [{"license": {"id": "Apache-2.0"}}],
                    "name": "sigma-operator-stack",
                    "version": "0.1.0a4",
                }
            },
        }
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "sbom.json"
            path.write_text(json.dumps(document), encoding="utf-8")
            failures: list[str] = []
            CHECKER._check_sbom(
                path,
                {
                    "sigma-operator-stack": {
                        "license_expression": "Apache-2.0",
                        "version": "0.1.0a4",
                    }
                },
                failures,
            )
            self.assertIn("SOS_DEPENDENCY_SBOM_COMPONENT_SET_MISMATCH", failures)


if __name__ == "__main__":
    unittest.main()
