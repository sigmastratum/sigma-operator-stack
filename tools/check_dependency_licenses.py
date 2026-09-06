#!/usr/bin/env python3
"""Fail-closed dependency, license, wheelhouse and SBOM inspection."""

from __future__ import annotations

import argparse
import ast
import email
import json
import re
import tomllib
import zipfile
from pathlib import Path

from packaging.requirements import Requirement
from packaging.utils import canonicalize_name, parse_wheel_filename


CONTRACT = "sos_dependency_license_inventory_v1"
KNOWN_LICENSES = {
    "Apache-2.0",
    "Apache-2.0 OR BSD-2-Clause",
    "Apache-2.0 OR MIT",
    "MIT",
    "MIT-CMU",
    "PSF-2.0",
}


def _key(name: str) -> str:
    return canonicalize_name(name)


def _entries(value: object, scope: str, failures: list[str]) -> dict[str, dict[str, object]]:
    if not isinstance(value, list):
        failures.append(f"SOS_DEPENDENCY_LICENSE_SCOPE_INVALID:{scope}")
        return {}
    result: dict[str, dict[str, object]] = {}
    for item in value:
        if not isinstance(item, dict):
            failures.append(f"SOS_DEPENDENCY_LICENSE_ENTRY_INVALID:{scope}")
            continue
        name = item.get("name")
        version = item.get("version")
        expression = item.get("license_expression")
        license_files = item.get("license_files", [])
        if (
            not isinstance(name, str)
            or not isinstance(version, str)
            or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9.+_-]*", version)
            or expression not in KNOWN_LICENSES
            or not isinstance(license_files, list)
            or any(not isinstance(entry, str) or not entry for entry in license_files)
        ):
            failures.append(f"SOS_DEPENDENCY_LICENSE_ENTRY_INVALID:{scope}")
            continue
        normalized = _key(name)
        if normalized in result:
            failures.append(f"SOS_DEPENDENCY_LICENSE_DUPLICATE:{scope}:{normalized}")
        result[normalized] = item
    return result


def _literal(repository: Path, relative: str, symbol: str) -> object:
    tree = ast.parse((repository / relative).read_text(encoding="utf-8"))
    for node in tree.body:
        if isinstance(node, ast.Assign) and any(
            isinstance(target, ast.Name) and target.id == symbol for target in node.targets
        ):
            return ast.literal_eval(node.value)
    raise ValueError(f"missing literal {relative}:{symbol}")


def _wheel_identity(filename: str) -> tuple[str, str]:
    name, version, _, _ = parse_wheel_filename(filename)
    return _key(str(name)), str(version)


def _requirements(repository: Path, relative: str) -> dict[str, str]:
    result: dict[str, str] = {}
    for line in (repository / relative).read_text(encoding="utf-8").splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        requirement = Requirement(stripped)
        specs = list(requirement.specifier)
        if requirement.marker is not None or requirement.extras or len(specs) != 1 or specs[0].operator != "==":
            raise ValueError(f"non-exact release requirement: {relative}")
        normalized = _key(requirement.name)
        if normalized in result:
            raise ValueError(f"duplicate release requirement: {relative}")
        result[normalized] = specs[0].version
    return result


def _licenses(component: dict[str, object]) -> set[str]:
    result: set[str] = set()
    for wrapper in component.get("licenses", []):
        if not isinstance(wrapper, dict) or not isinstance(wrapper.get("license"), dict):
            continue
        license_value = wrapper["license"]
        identifier = license_value.get("id")
        if isinstance(identifier, str):
            result.add(identifier)
    return result


def _check_sbom(
    path: Path,
    expected: dict[str, dict[str, object]],
    failures: list[str],
) -> None:
    document = json.loads(path.resolve(strict=True).read_text(encoding="utf-8"))
    root = document.get("metadata", {}).get("component")
    components = document.get("components")
    dependencies = document.get("dependencies")
    if not isinstance(root, dict) or not isinstance(components, list) or not isinstance(dependencies, list):
        failures.append("SOS_DEPENDENCY_SBOM_INVALID")
        return
    by_ref: dict[str, dict[str, object]] = {}
    for component in [root, *components]:
        if not isinstance(component, dict) or not isinstance(component.get("bom-ref"), str):
            failures.append("SOS_DEPENDENCY_SBOM_INVALID")
            return
        by_ref[component["bom-ref"]] = component
    graph: dict[str, list[str]] = {}
    for item in dependencies:
        if not isinstance(item, dict) or not isinstance(item.get("ref"), str) or not isinstance(item.get("dependsOn", []), list):
            failures.append("SOS_DEPENDENCY_SBOM_INVALID")
            return
        graph[item["ref"]] = list(item.get("dependsOn", []))
    root_ref = root["bom-ref"]
    pending = [root_ref]
    closure: set[str] = set()
    while pending:
        reference = pending.pop()
        if reference in closure:
            continue
        if reference not in by_ref:
            failures.append("SOS_DEPENDENCY_SBOM_REFERENCE_UNKNOWN")
            return
        closure.add(reference)
        pending.extend(graph.get(reference, []))
    observed: dict[str, dict[str, object]] = {}
    for reference in closure:
        component = by_ref[reference]
        name = component.get("name")
        version = component.get("version")
        if not isinstance(name, str) or not isinstance(version, str):
            failures.append("SOS_DEPENDENCY_SBOM_INVALID")
            continue
        observed[_key(name)] = component
    if set(observed) != set(expected):
        failures.append("SOS_DEPENDENCY_SBOM_COMPONENT_SET_MISMATCH")
    for name in set(observed).intersection(expected):
        expected_item = expected[name]
        component = observed[name]
        if component.get("version") != expected_item["version"]:
            failures.append(f"SOS_DEPENDENCY_SBOM_VERSION_MISMATCH:{name}")
        expected_expression = str(expected_item["license_expression"])
        alternatives = {part.strip() for part in expected_expression.split(" OR ")}
        if not alternatives.intersection(_licenses(component)):
            failures.append(f"SOS_DEPENDENCY_SBOM_LICENSE_UNKNOWN:{name}")


def _check_wheelhouse(
    directory: Path,
    expected: dict[str, dict[str, object]],
    failures: list[str],
) -> None:
    wheels = sorted(directory.resolve(strict=True).glob("*.whl"))
    observed: dict[str, tuple[str, Path]] = {}
    for wheel in wheels:
        name, version = _wheel_identity(wheel.name)
        if name in observed:
            failures.append(f"SOS_DEPENDENCY_WHEEL_DUPLICATE:{name}")
        observed[name] = (version, wheel)
    if set(observed) != set(expected):
        failures.append("SOS_DEPENDENCY_WHEELHOUSE_SET_MISMATCH")
    for name in set(observed).intersection(expected):
        version, wheel = observed[name]
        item = expected[name]
        if version != item["version"]:
            failures.append(f"SOS_DEPENDENCY_WHEEL_VERSION_MISMATCH:{name}")
            continue
        with zipfile.ZipFile(wheel) as archive:
            archive_names = set(archive.namelist())
            metadata_names = [entry for entry in archive_names if entry.endswith(".dist-info/METADATA")]
            if len(metadata_names) != 1:
                failures.append(f"SOS_DEPENDENCY_WHEEL_METADATA_INVALID:{name}")
                continue
            metadata = email.message_from_bytes(archive.read(metadata_names[0]))
            expression = metadata.get("License-Expression") or metadata.get("License")
            if expression != item["license_expression"]:
                failures.append(f"SOS_DEPENDENCY_WHEEL_LICENSE_MISMATCH:{name}")
            recorded_files = set(metadata.get_all("License-File", []))
            metadata_root = metadata_names[0].rsplit("/", 1)[0]
            for required in item["license_files"]:
                if required not in recorded_files:
                    failures.append(f"SOS_DEPENDENCY_WHEEL_LICENSE_FILE_MISSING:{name}")
                    continue
                member = f"{metadata_root}/licenses/{required}"
                if member not in archive_names or member.endswith("/"):
                    failures.append(f"SOS_DEPENDENCY_WHEEL_LICENSE_FILE_MISSING:{name}")


def inspect(repository: Path, wheelhouses: list[Path], sbom: Path | None) -> dict[str, object]:
    repository = repository.resolve(strict=True)
    failures: list[str] = []
    value = json.loads((repository / "requirements/dependency-licenses.json").read_text(encoding="utf-8"))
    if not isinstance(value, dict) or value.get("contract") != CONTRACT:
        failures.append("SOS_DEPENDENCY_LICENSE_INVENTORY_INVALID")
        value = {}
    runtime = _entries(value.get("runtime"), "runtime", failures)
    release_tools = _entries(value.get("release_tools"), "release_tools", failures)
    external = _entries(value.get("external_platform_components"), "external", failures)
    product_value = value.get("product")
    product = _entries([product_value], "product", failures)
    notice = value.get("notice")
    if not isinstance(notice, dict) or notice.get("root_notice_required") is not False or (repository / "NOTICE").exists():
        failures.append("SOS_DEPENDENCY_NOTICE_DECISION_INVALID")
    if set(external) != {"cpython", "uv"}:
        failures.append("SOS_DEPENDENCY_EXTERNAL_COMPONENT_SET_MISMATCH")

    declared = tomllib.loads((repository / "pyproject.toml").read_text(encoding="utf-8"))["project"]
    declared_dependencies = declared.get("dependencies", [])
    governed_declared = {
        str(item.get("declared_requirement"))
        for item in runtime.values()
        if item.get("declared_requirement") is not None
    }
    if set(declared_dependencies) != governed_declared:
        failures.append("SOS_DEPENDENCY_DECLARED_REQUIREMENT_MISMATCH")

    expected_tools: dict[str, tuple[str, str]] = {}
    for relative in ("requirements/release.txt", "requirements/audit.txt"):
        for name, version in _requirements(repository, relative).items():
            expected_tools[name] = (version, relative)
    observed_tools = {
        name: (str(item["version"]), str(item.get("requirement_file")))
        for name, item in release_tools.items()
    }
    if expected_tools != observed_tools:
        failures.append("SOS_DEPENDENCY_RELEASE_REQUIREMENT_MISMATCH")

    native_wheels = set(_literal(repository, "tools/build_native_alpha_bundles.py", "UNIVERSAL_WHEELS"))
    native_platforms = _literal(repository, "tools/build_native_alpha_bundles.py", "PLATFORM_WHEELS")
    for names in native_platforms.values():
        native_wheels.update(names)
    windows_wheels = set(_literal(repository, "tools/build_windows_msix_packet.py", "WHEELS"))
    expected_runtime = {(name, str(item["version"])) for name, item in runtime.items()}
    locked_runtime = set(_requirements(repository, "requirements/runtime.txt").items())
    if locked_runtime != expected_runtime:
        failures.append("SOS_DEPENDENCY_RUNTIME_REQUIREMENT_MISMATCH")
    observed_runtime = {_wheel_identity(name) for name in native_wheels | windows_wheels}
    # Platform packages can intentionally lag the source candidate while a
    # Store or notarization gate is still in progress.  Their SOS wheel is the
    # product itself, not a third-party runtime dependency; product-version
    # equality is enforced by each artifact builder and its release binding.
    # Remove every product-name entry here so the license gate compares only
    # the closed third-party runtime dependency set.
    for product_name in product:
        observed_runtime = {
            identity for identity in observed_runtime if identity[0] != product_name
        }
    if observed_runtime != expected_runtime:
        failures.append("SOS_DEPENDENCY_BUILDER_INVENTORY_MISMATCH")

    distributed = {**product, **runtime}
    for wheelhouse in wheelhouses:
        _check_wheelhouse(wheelhouse, distributed, failures)
    if sbom is not None:
        _check_sbom(sbom, distributed, failures)
    return {
        "contract": "sos_dependency_license_check_v1",
        "failures": sorted(set(failures)),
        "notice_required": False,
        "runtime_component_count": len(distributed),
        "status": "passed" if not failures else "failed",
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repository", type=Path, default=Path.cwd())
    parser.add_argument("--wheelhouse", action="append", type=Path, default=[])
    parser.add_argument("--sbom", type=Path)
    arguments = parser.parse_args(argv)
    try:
        result = inspect(arguments.repository, arguments.wheelhouse, arguments.sbom)
    except (KeyError, OSError, TypeError, ValueError, SyntaxError, json.JSONDecodeError, zipfile.BadZipFile) as error:
        result = {
            "contract": "sos_dependency_license_check_v1",
            "failures": ["SOS_DEPENDENCY_LICENSE_CHECK_FAILED"],
            "message": str(error),
            "status": "failed",
        }
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0 if result["status"] == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
