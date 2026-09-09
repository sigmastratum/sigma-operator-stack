import hashlib
import json
import tempfile
import py_compile
import shutil
import sys
import unittest
import zipfile
from pathlib import Path

from sos.platforms.project_runtime_inventory import verify_installed_wheels
from sos.project_runtime import ProjectRuntimeError


class RuntimeInventoryTests(unittest.TestCase):
    def active_options(self):
        # A managed standalone interpreter needs its adjacent standard library;
        # copying only its executable is not a runnable interpreter fixture.
        python = Path(sys.executable).resolve()
        return {"cache_python": python, "cache_python_sha256": hashlib.sha256(python.read_bytes()).hexdigest()}

    def test_active_cache_matches_recompiled_checked_source_without_execution(self):
        initial = self.verify()
        source = self.site / "sos/__init__.py"
        for optimize in (0, 1, 2):
            py_compile.compile(str(source), doraise=True, optimize=optimize)
        before = {str(p): p.read_bytes() for p in self.site.rglob("*") if p.is_file()}
        result = self.verify(**self.active_options())
        self.assertEqual(result, initial)
        self.assertEqual(before, {str(p): p.read_bytes() for p in self.site.rglob("*") if p.is_file()})
        with self.assertRaisesRegex(ProjectRuntimeError, "EXTRA"):
            self.verify()

    def test_active_cache_body_substitution_and_orphan_cache_refuse(self):
        source = self.site / "sos/__init__.py"
        cache = Path(py_compile.compile(str(source), doraise=True))
        good = cache.read_bytes()
        options = self.active_options()
        # Preserve the valid header; replace the executable body.
        source.write_bytes(b"raise RuntimeError('synthetic foreign bytecode')\n")
        py_compile.compile(str(source), doraise=True)
        foreign = cache.read_bytes()[16:]
        source.write_bytes(self.files["sos/__init__.py"])
        cache.write_bytes(good[:16] + foreign)
        with self.assertRaisesRegex(ProjectRuntimeError, "CACHE_INVALID"):
            self.verify(**options)
        cache.rename(cache.with_name("unknown.cpython-312.pyc"))
        with self.assertRaisesRegex(ProjectRuntimeError, "CACHE_INVALID"):
            self.verify(**options)

    def test_active_cache_wrong_interpreter_and_symlink_refuse(self):
        cache = Path(py_compile.compile(str(self.site / "sos/__init__.py"), doraise=True))
        options = self.active_options()
        with self.assertRaisesRegex(ProjectRuntimeError, "INTERPRETER_MISMATCH"):
            self.verify(**(options | {"cache_python_sha256": "0" * 64}))
        foreign = self.root / "cache.pyc"
        cache.rename(foreign)
        cache.symlink_to(foreign)
        with self.assertRaises(ProjectRuntimeError):
            self.verify(**options)

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name).resolve()
        self.site = self.root / "site-packages"
        self.site.mkdir()
        self.dist = "sigma_operator_stack-0.1.0a6.dist-info"
        self.files = {
            "sos/__init__.py": b"__version__ = '0.1.0a6'\n",
            self.dist + "/METADATA": b"Name: sigma-operator-stack\nVersion: 0.1.0a6\n",
            self.dist + "/WHEEL": b"Wheel-Version: 1.0\n",
            self.dist + "/RECORD": b"synthetic wheel record\n",
        }
        for relative, data in self.files.items():
            path = self.site / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(data)
        self.wheel = self.root / "synthetic.whl"
        with zipfile.ZipFile(self.wheel, "w") as archive:
            for name, data in self.files.items():
                archive.writestr(name, data)
        self.digest = hashlib.sha256(self.wheel.read_bytes()).hexdigest()

    def verify(self, **changes):
        args = dict(site_packages=self.site, wheels=((self.wheel, self.digest),), expected_sos_version="0.1.0a6")
        return verify_installed_wheels(**(args | changes))

    def test_exact_payload_and_rewritten_record_are_read_only(self):
        (self.site / self.dist / "RECORD").write_bytes(b"rewritten installed record\n")
        (self.site / self.dist / "INSTALLER").write_bytes(b"uv")
        before = {str(p): p.read_bytes() for p in self.site.rglob("*") if p.is_file()}
        result = self.verify()
        self.assertEqual(result["status"], "passed")
        self.assertFalse(result["runtime_ready"])
        self.assertNotIn(str(self.root), json.dumps(result))
        self.assertEqual(before, {str(p): p.read_bytes() for p in self.site.rglob("*") if p.is_file()})

    def test_changed_or_missing_payload_refuses(self):
        target = self.site / "sos/__init__.py"
        target.write_bytes(b"changed")
        with self.assertRaisesRegex(ProjectRuntimeError, "FILE_MISMATCH"):
            self.verify()
        target.unlink()
        with self.assertRaisesRegex(ProjectRuntimeError, "MISSING"):
            self.verify()

    def test_extra_package_import_hook_and_bytecode_refuse(self):
        for relative in ("other.py", "inject.pth", "sos/__pycache__/__init__.cpython-312.pyc"):
            with self.subTest(relative=relative):
                target = self.site / relative
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(b"synthetic unexpected code")
                with self.assertRaisesRegex(ProjectRuntimeError, "EXTRA"):
                    self.verify()
                target.unlink()

    def test_unknown_empty_distribution_refuses(self):
        (self.site / "unknown-1.dist-info").mkdir()
        with self.assertRaisesRegex(ProjectRuntimeError, "EXTRA"):
            self.verify()

    def test_wrong_wheel_version_and_duplicate_refuse(self):
        for args in (
            {"wheels": ((self.wheel, "0" * 64),)},
            {"expected_sos_version": "0.1.0a5"},
            {"wheels": ((self.wheel, self.digest), (self.wheel, self.digest))},
        ):
            with self.subTest(args=args), self.assertRaises(ProjectRuntimeError):
                self.verify(**args)

    def test_payload_symlink_refuses_even_with_equal_bytes(self):
        target = self.site / "sos/__init__.py"
        external = self.root / "foreign.py"
        external.write_bytes(target.read_bytes())
        target.unlink()
        target.symlink_to(external)
        with self.assertRaises(ProjectRuntimeError):
            self.verify()

    def test_trusted_installer_hook_requires_exact_external_digest(self):
        hook = self.site / "_virtualenv.pth"
        content = b"import _virtualenv\n"
        hook.write_bytes(content)
        with self.assertRaises(ProjectRuntimeError):
            self.verify()
        self.verify(installer_hook_digests={hook.name: hashlib.sha256(content).hexdigest()})
        hook.write_bytes(b"import synthetic_other\n")
        with self.assertRaisesRegex(ProjectRuntimeError, "HOOK_MISMATCH"):
            self.verify(installer_hook_digests={hook.name: hashlib.sha256(content).hexdigest()})

    def test_archive_traversal_refuses_without_extraction(self):
        with zipfile.ZipFile(self.wheel, "a") as archive:
            archive.writestr("../foreign", b"synthetic")
        digest = hashlib.sha256(self.wheel.read_bytes()).hexdigest()
        with self.assertRaisesRegex(ProjectRuntimeError, "WHEEL_INVALID"):
            self.verify(wheels=((self.wheel, digest),))
        self.assertFalse((self.root / "foreign").exists())
