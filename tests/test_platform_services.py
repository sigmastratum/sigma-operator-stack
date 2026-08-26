from __future__ import annotations

import ast
import json
import os
import tempfile
import unittest
import sys
from pathlib import Path
from unittest import mock

from sos.platform_services import (
    FilePublicationOperation,
    PlatformServiceError,
    PlatformServices,
    TreePublicationOperation,
    current_platform_services,
)
from sos.platforms import _select_platform_services
from sos.platforms.linux import LinuxPlatformServices


_FORBIDDEN_ATTRIBUTES = frozenset(
    {
        "exists", "glob", "is_dir", "is_file", "is_symlink", "iterdir",
        "lstat", "mkdir", "open", "read_bytes", "read_text", "resolve",
        "rglob", "rmdir", "stat", "touch", "unlink", "write_bytes",
        "write_text",
    }
)
_FORBIDDEN_OS_CALLS = frozenset(
    {
        "access", "chmod", "chown", "close", "fchmod", "fchown", "fdatasync",
        "fstat", "fsync", "link", "listdir", "lstat", "makedirs", "mkdir",
        "open", "pread", "pwrite", "read", "readlink", "remove", "removedirs",
        "rename", "replace", "rmdir", "scandir", "stat", "symlink", "touch",
        "truncate", "unlink", "walk", "write",
    }
)


def _boundary_violations(source: str, relative: str, rule: dict[str, object]) -> list[str]:
    tree = ast.parse(source, relative)
    module_class = rule["class"]
    if module_class == "platform_mechanism":
        return []
    aliases: dict[str, tuple[str, str | None]] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for name in node.names:
                aliases[name.asname or name.name] = (name.name, None)
        elif isinstance(node, ast.ImportFrom) and node.module:
            for name in node.names:
                aliases[name.asname or name.name] = (node.module, name.name)

    allowed_symbols = set(rule.get("symbols", []))
    proven_non_filesystem = set(rule.get("proven_non_filesystem_symbols", []))
    violations: list[str] = []

    class Visitor(ast.NodeVisitor):
        def __init__(self) -> None:
            self.symbols: list[str] = []

        def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
            self.symbols.append(node.name)
            self.generic_visit(node)
            self.symbols.pop()

        visit_AsyncFunctionDef = visit_FunctionDef

        def visit_Call(self, node: ast.Call) -> None:
            symbol = self.symbols[-1] if self.symbols else "<module>"
            mechanism_allowed = (
                module_class == "qualification_execution_mechanism"
                and symbol in allowed_symbols
            )
            package_read_allowed = (
                module_class == "package_resource_mechanism"
                and symbol == "read_package_resource"
            )
            reason: str | None = None
            if isinstance(node.func, ast.Name):
                name = node.func.id
                origin = aliases.get(name)
                if name in {"eval", "exec", "open"}:
                    reason = f"dynamic_or_builtin:{name}"
                elif origin and origin[0] == "os" and origin[1] in _FORBIDDEN_OS_CALLS:
                    reason = f"aliased_os:{origin[1]}"
                elif origin and origin[0] in {"shutil", "tempfile"}:
                    reason = f"aliased_module:{origin[0]}.{origin[1]}"
            elif isinstance(node.func, ast.Attribute):
                attribute = node.func.attr
                base = node.func.value
                if isinstance(base, ast.Name) and base.id in aliases:
                    origin = aliases[base.id]
                    if origin[0] == "os" and attribute in _FORBIDDEN_OS_CALLS:
                        reason = f"os:{attribute}"
                    elif origin[0] in {"shutil", "tempfile"}:
                        reason = f"module:{origin[0]}.{attribute}"
                if reason is None and attribute in _FORBIDDEN_ATTRIBUTES:
                    reason = f"attribute:{attribute}"
                if (
                    reason is None
                    and isinstance(base, ast.Call)
                    and isinstance(base.func, ast.Name)
                    and base.func.id == "getattr"
                ):
                    reason = "dynamic:getattr"
            elif (
                isinstance(node.func, ast.Call)
                and isinstance(node.func.func, ast.Name)
                and node.func.func.id == "getattr"
            ):
                reason = "dynamic:getattr"
            if reason == "os:read" and symbol in proven_non_filesystem:
                reason = None
            if package_read_allowed and reason == "attribute:read_bytes":
                reason = None
            if reason is not None and not mechanism_allowed:
                violations.append(f"{relative}:{node.lineno}:{reason}")
            self.generic_visit(node)

    Visitor().visit(tree)
    return violations


class PortablePlatformServicesTests(unittest.TestCase):
    def test_shared_repository_paths_have_no_direct_posix_io(self) -> None:
        repository = Path(__file__).resolve().parents[1]
        manifest = json.loads((repository / "tests/platform_boundary_manifest.json").read_text())
        discovered = {
            path.relative_to(repository).as_posix()
            for path in (repository / "src/sos").rglob("*.py")
        }
        self.assertEqual(set(manifest["modules"]), discovered)
        violations: list[str] = []
        for relative, rule in sorted(manifest["modules"].items()):
            source = (repository / relative).read_text(encoding="utf-8")
            if rule["class"] == "qualification_execution_mechanism":
                symbols = rule.get("symbols")
                self.assertIsInstance(symbols, list, relative)
                self.assertTrue(symbols, relative)
                self.assertNotIn("*", symbols, relative)
                declared = {
                    node.name
                    for node in ast.walk(ast.parse(source, relative))
                    if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
                }
                self.assertEqual(len(symbols), len(set(symbols)), relative)
                self.assertLessEqual(set(symbols), declared, relative)
            violations.extend(_boundary_violations(source, relative, rule))
        self.assertEqual(violations, [])

    def test_structural_negative_and_positive_corpus(self) -> None:
        repository = Path(__file__).resolve().parents[1]
        shared = {"class": "shared_core"}
        negatives = sorted((repository / "tests/fixtures/platform_boundary_negative").glob("*.py"))
        self.assertEqual(len(negatives), 13)
        for fixture in negatives:
            with self.subTest(fixture=fixture.name):
                self.assertTrue(
                    _boundary_violations(fixture.read_text(), fixture.name, shared)
                )
        positives = sorted((repository / "tests/fixtures/platform_boundary_positive").glob("*.py"))
        self.assertEqual(len(positives), 1)
        self.assertEqual(
            _boundary_violations(positives[0].read_text(), positives[0].name, shared),
            [],
        )
        wildcard_rule = {
            "class": "qualification_execution_mechanism",
            "symbols": ["*"],
        }
        self.assertTrue(
            _boundary_violations(
                "import os\ndef qualification_worker():\n    os.stat('candidate')\n",
                "whole_module_wildcard.py",
                wildcard_rule,
            )
        )

    def test_selector_uses_process_platform_only_and_linux_conforms(self) -> None:
        selected = _select_platform_services("linux")
        self.assertIsInstance(selected, LinuxPlatformServices)
        self.assertIsInstance(selected, PlatformServices)
        self.assertIsInstance(current_platform_services(), LinuxPlatformServices)
        with self.assertRaisesRegex(RuntimeError, "SOS_PLATFORM_ADAPTER_UNAVAILABLE"):
            _select_platform_services("win32")

    def test_safe_projections_never_serialize_operational_bytes_or_absolute_paths(self) -> None:
        service = LinuxPlatformServices()
        with tempfile.TemporaryDirectory() as temporary:
            root_path = Path(temporary)
            (root_path / "input.txt").write_bytes(b"private operational payload")
            with service.open_repository(root_path) as root:
                observed = service.read_regular_file_bounded(root, "input.txt", 64)
                projection = observed.safe_projection()
                rendered = json.dumps(projection, sort_keys=True)
                self.assertNotIn("private operational payload", rendered)
                self.assertNotIn(str(root_path), rendered)
                self.assertFalse(projection["raw_content_serialized"])
                self.assertFalse(projection["absolute_paths_serialized"])

    def test_bounded_read_and_enumeration_fail_closed(self) -> None:
        service = LinuxPlatformServices()
        with tempfile.TemporaryDirectory() as temporary:
            root_path = Path(temporary)
            (root_path / "small.txt").write_bytes(b"small")
            (root_path / "large.txt").write_bytes(b"too-large")
            (root_path / "alias.txt").symlink_to("small.txt")
            with service.open_repository(root_path) as root:
                self.assertEqual(
                    service.read_regular_file_bounded(root, "small.txt", 5).payload,
                    b"small",
                )
                with self.assertRaisesRegex(PlatformServiceError, "file_limit_exceeded"):
                    service.read_regular_file_bounded(root, "large.txt", 4)
                with self.assertRaises(PlatformServiceError):
                    service.read_regular_file_bounded(root, "alias.txt", 64)
                with self.assertRaisesRegex(PlatformServiceError, "directory_limit_exceeded"):
                    service.enumerate_directory_bounded(root, ".", 2)

    def test_file_publication_is_identity_bound_and_preserves_collision(self) -> None:
        service = LinuxPlatformServices()
        with tempfile.TemporaryDirectory() as temporary:
            root_path = Path(temporary)
            with service.open_repository(root_path) as root:
                created = service.publish_file(
                    FilePublicationOperation(root, "state.json", b"one", None, False, 0o600)
                )
                self.assertEqual(created.operation, "create")
                self.assertEqual((root_path / "state.json").read_bytes(), b"one")
                replaced = service.publish_file(
                    FilePublicationOperation(root, "state.json", b"two", b"one", True, 0o600)
                )
                self.assertEqual(replaced.operation, "replace")
                self.assertEqual((root_path / "state.json").read_bytes(), b"two")
                with self.assertRaisesRegex(PlatformServiceError, "identity_changed"):
                    service.publish_file(
                        FilePublicationOperation(root, "state.json", b"three", b"one", True, 0o600)
                    )
                self.assertEqual((root_path / "state.json").read_bytes(), b"two")

    def test_tree_publication_is_atomic_no_replace(self) -> None:
        service = LinuxPlatformServices()
        with tempfile.TemporaryDirectory() as temporary:
            root_path = Path(temporary)
            with service.open_repository(root_path) as root:
                staged = service.publish_tree(
                    TreePublicationOperation(
                        root,
                        ".sigma.init." + "a" * 64,
                        ".sigma",
                        "create",
                        (("record", b"bound"),),
                        recovery_binding_digest="none",
                    )
                )
                self.assertIsNotNone(staged.capability)
                receipt = service.publish_tree(
                    TreePublicationOperation(
                        root,
                        ".sigma.init." + "a" * 64,
                        ".sigma",
                        capability=staged.capability,
                    )
                )
                self.assertEqual(receipt.operation, "create_tree")
                self.assertEqual((root_path / ".sigma" / "record").read_bytes(), b"bound")
                with self.assertRaisesRegex(PlatformServiceError, "collision"):
                    service.publish_tree(
                        TreePublicationOperation(
                            root,
                            ".sigma.init." + "b" * 64,
                            ".sigma",
                            "create",
                            (("other", b"bound"),),
                            recovery_binding_digest="none",
                        )
                    )

    def test_staging_capability_binds_identity_and_is_single_use(self) -> None:
        service = LinuxPlatformServices()
        staging_name = ".sigma.init." + "c" * 64
        with tempfile.TemporaryDirectory() as temporary:
            root_path = Path(temporary)
            with service.open_repository(root_path) as root:
                staged = service.publish_tree(
                    TreePublicationOperation(
                        root, staging_name, ".sigma", "create", (("one", b"1"),),
                        recovery_binding_digest="sha256:" + "1" * 64,
                    )
                )
                capability = staged.capability
                self.assertIsNotNone(capability)
                service.publish_tree(
                    TreePublicationOperation(
                        root, staging_name, ".sigma", "extend", (("two", b"2"),),
                        capability=capability,
                    )
                )
                service.publish_tree(
                    TreePublicationOperation(root, staging_name, ".sigma", capability=capability)
                )
                self.assertTrue(capability.consumed)
                self.assertFalse((root_path / ".sigma/.sos-staging-binding-v1").exists())
                self.assertEqual((root_path / ".sigma/one").read_bytes(), b"1")
                self.assertEqual((root_path / ".sigma/two").read_bytes(), b"2")
                with self.assertRaisesRegex(PlatformServiceError, "staging_recovery_required"):
                    service.publish_tree(
                        TreePublicationOperation(root, staging_name, ".sigma", capability=capability)
                    )

    def test_same_name_replacement_and_marker_tamper_fail_closed(self) -> None:
        service = LinuxPlatformServices()
        staging_name = ".sigma.init." + "d" * 64
        with tempfile.TemporaryDirectory() as temporary:
            root_path = Path(temporary)
            with service.open_repository(root_path) as root:
                staged = service.publish_tree(
                    TreePublicationOperation(
                        root, staging_name, ".sigma", "create", (("one", b"1"),),
                        recovery_binding_digest="sha256:" + "2" * 64,
                    )
                )
                capability = staged.capability
                self.assertIsNotNone(capability)
                original = root_path / (staging_name + ".original")
                (root_path / staging_name).rename(original)
                (root_path / staging_name).mkdir()
                marker = original / ".sos-staging-binding-v1"
                (root_path / staging_name / marker.name).write_bytes(marker.read_bytes())
                with self.assertRaisesRegex(PlatformServiceError, "staging_identity_changed"):
                    service.publish_tree(
                        TreePublicationOperation(
                            root, staging_name, ".sigma", "extend", (("two", b"2"),),
                            capability=capability,
                        )
                    )
                self.assertEqual((original / "one").read_bytes(), b"1")

    def test_restart_recovery_is_digest_bound_and_discard_consumes(self) -> None:
        service = LinuxPlatformServices()
        staging_name = ".sigma.init." + "e" * 64
        recovery = "sha256:" + "3" * 64
        with tempfile.TemporaryDirectory() as temporary:
            root_path = Path(temporary)
            with service.open_repository(root_path) as root:
                staged = service.publish_tree(
                    TreePublicationOperation(
                        root, staging_name, ".sigma", "create", (("one", b"1"),),
                        recovery_binding_digest=recovery,
                    )
                )
                capability = staged.capability
                self.assertIsNotNone(capability)
                capability.consume("restart")
                with self.assertRaisesRegex(PlatformServiceError, "staging_identity_changed"):
                    service.publish_tree(
                        TreePublicationOperation(
                            root, staging_name, ".sigma", "recover",
                            recovery_binding_digest="sha256:" + "4" * 64,
                        )
                    )
                recovered = service.publish_tree(
                    TreePublicationOperation(
                        root, staging_name, ".sigma", "recover",
                        recovery_binding_digest=recovery,
                    )
                ).capability
                self.assertIsNotNone(recovered)
                service.publish_tree(
                    TreePublicationOperation(
                        root, staging_name, ".sigma", "discard", capability=recovered,
                    )
                )
                self.assertFalse((root_path / staging_name).exists())
                with self.assertRaisesRegex(PlatformServiceError, "staging_recovery_required"):
                    service.publish_tree(
                        TreePublicationOperation(
                            root, staging_name, ".sigma", "discard", capability=recovered,
                        )
                    )

    def test_repository_lock_uses_exact_relative_target_and_times_out(self) -> None:
        service = LinuxPlatformServices()
        relative = ".sigma/managed-files/batch-locks/example.lock"
        with tempfile.TemporaryDirectory() as temporary:
            root_path = Path(temporary)
            (root_path / ".sigma").mkdir()
            with service.open_repository(root_path) as first, service.open_repository(root_path) as second:
                with service.acquire_repository_lock(
                    first, None, relative_lock_path=relative
                ):
                    self.assertTrue((root_path / relative).is_file())
                    with self.assertRaisesRegex(PlatformServiceError, "lock_timeout"):
                        with service.acquire_repository_lock(
                            second, 0.0, relative_lock_path=relative
                        ):
                            self.fail("contended lock was admitted")

    def test_repository_input_cannot_substitute_adapter(self) -> None:
        service = LinuxPlatformServices()
        with tempfile.TemporaryDirectory(prefix="win32-darwin-") as temporary:
            with mock.patch("sys.platform", "linux"):
                with service.open_repository(Path(temporary)) as root:
                    self.assertEqual(root.platform_profile_id, service.profile_id)

    def test_linux_launcher_path_is_stable_across_python_symlink_spellings(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            prefix = Path(temporary)
            binary = prefix / "bin"
            binary.mkdir()
            (binary / "python3").symlink_to(sys.executable)
            (binary / "python").symlink_to("python3")
            with mock.patch.object(sys, "prefix", str(prefix)), mock.patch.object(
                sys, "executable", str(binary / "python")
            ):
                self.assertEqual(
                    LinuxPlatformServices._canonical_python_executable(),
                    binary / "python3",
                )


if __name__ == "__main__":
    unittest.main()
