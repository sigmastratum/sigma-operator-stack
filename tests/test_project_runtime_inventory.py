import hashlib
import base64
import importlib.util
import marshal
import subprocess
import struct
import dis
import json
import tempfile
import py_compile
import shutil
import sys
import unittest
import zipfile
from pathlib import Path
from unittest import mock

from sos.platforms.project_runtime_inventory import verify_installed_wheels, _CACHE_CHECK
from sos.project_runtime import ProjectRuntimeError


class RuntimeInventoryTests(unittest.TestCase):
    def cache_worker(self, source, body):
        header = importlib.util.MAGIC_NUMBER + bytes(12)
        row = dict(source=base64.b64encode(source).decode(),
            cache=base64.b64encode(header + body).decode(), filename='synthetic.py',
            tag=sys.implementation.cache_tag, optimize=0)
        return subprocess.run([sys.executable, '-I', '-S', '-B', '-c', _CACHE_CHECK],
            input=json.dumps([row]), capture_output=True, text=True, timeout=30)

    def test_cache_reference_sharing_is_not_execution_identity(self):
        source = b"values = ('synthetic shared value', 'synthetic shared value')\n"
        code = compile(source, 'synthetic.py', 'exec', dont_inherit=True)
        def distinct(value):
            if type(value) is str:
                return value.encode().decode()
            if type(value) is tuple:
                return tuple(distinct(v) for v in value)
            return value
        other = code.replace(co_consts=distinct(code.co_consts))
        self.assertNotEqual(marshal.dumps(code), marshal.dumps(other))
        for version in (2, 3, 4):
            result = self.cache_worker(source, marshal.dumps(other, version))
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(result.stdout, 'verified\n')

    def test_cache_execution_and_metadata_drift_refuse(self):
        source = b"def f(x):\n    try:\n        return x + 1\n    except Exception:\n        return 0\n"
        code = compile(source, 'synthetic.py', 'exec', dont_inherit=True)
        variants = [code.replace(co_filename='foreign.py'),
                    code.replace(co_firstlineno=9), code.replace(co_name='foreign'),
                    code.replace(co_qualname='foreign'), code.replace(co_linetable=b''),
                    code.replace(co_flags=code.co_flags ^ 1),
                    code.replace(co_code=compile(b'pass', 'synthetic.py', 'exec').co_code)]
        nested = next(v for v in code.co_consts if type(v) is type(code))
        for changed in (nested.replace(co_exceptiontable=b''),
                        nested.replace(co_consts=(None, True, 0)),
                        nested.replace(co_consts=(None, 2, 0)),
                        nested.replace(co_names=('BaseException',))):
            variants.append(code.replace(co_consts=tuple(changed if v is nested else v for v in code.co_consts)))
        for variant in variants:
            self.assertEqual(self.cache_worker(source, marshal.dumps(variant)).returncode, 2)
        for body in (marshal.dumps(code)+b'trailing', b'broken', marshal.dumps((1, 2))):
            self.assertEqual(self.cache_worker(source, body).returncode, 2)

    def test_cache_frozenset_sharing_between_nested_functions(self):
        source = (b"def first(x):\n    return x in {'alpha', 'beta'}\n"
                  b"def second(x):\n    return x in {'alpha', 'beta'}\n")
        code = compile(source, 'synthetic.py', 'exec', dont_inherit=True)
        def copy_sets(value):
            if type(value) is frozenset:
                return frozenset(list(value))
            if type(value) is type(code):
                return value.replace(co_consts=tuple(copy_sets(v) for v in value.co_consts))
            return value
        changed = copy_sets(code)
        self.assertNotEqual(marshal.dumps(code), marshal.dumps(changed))
        self.assertEqual(marshal.dumps(code, 2), marshal.dumps(changed, 2))
        result = self.cache_worker(source, marshal.dumps(changed))
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, 'verified\n')

    def test_cache_constant_types_and_float_bits_are_not_python_equality(self):
        for source, original, replacement in (
                (b'value = -0.0\n', -0.0, 0.0),
                (b'value = 1\n', 1, True),
                (b'value = 1j\n', 1j, complex(-0.0, 1.0)),
                (b'value = x in {1, 2}\n', frozenset({1, 2}), frozenset({True, 2}))):
            with self.subTest(source=source):
                self.assertEqual(original, replacement)
                code = compile(source, 'synthetic.py', 'exec', dont_inherit=True)
                constants = tuple(replacement if type(v) is type(original) and v == original else v
                                  for v in code.co_consts)
                changed = code.replace(co_consts=constants)
                self.assertEqual(self.cache_worker(source, marshal.dumps(changed)).returncode, 2)

    def test_cache_large_integer_does_not_require_decimal_conversion(self):
        source = b'value = 0x' + b'f' * 4000 + b'\n'
        code = compile(source, 'synthetic.py', 'exec', dont_inherit=True)
        result = self.cache_worker(source, marshal.dumps(code))
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, 'verified\n')

    def test_cache_declared_allocation_is_bounded_before_decode(self):
        # A tiny body must not allocate its declared 800 MB tuple in the worker.
        result = self.cache_worker(b'pass\n', b'(' + struct.pack('<i', 100000000))
        self.assertEqual(result.returncode, 2)
        self.assertEqual(result.stdout, '')
        self.assertEqual(result.stderr, '')

    def test_cache_allocation_guard_is_structural_and_platform_independent(self):
        self.assertIn('marshal_preflight(cache[16:])', _CACHE_CHECK)
        self.assertNotIn('RLIMIT_', _CACHE_CHECK)
        self.assertNotIn('import resource', _CACHE_CHECK)
        source = b"value = ({'alpha', 'beta'}, [1, 2], {'key': 3})\n"
        code = compile(source, 'synthetic.py', 'exec', dont_inherit=True)
        result = self.cache_worker(source, marshal.dumps(code))
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, 'verified\n')

    def test_cache_internal_bytecode_is_not_hidden_by_public_projection(self):
        # Pinned CPython's public co_code deoptimizes some encodings. The cache
        # must match fresh compilation internally too; never execute this fixture.
        source = b'value = left + right\n'
        code = compile(source, 'synthetic.py', 'exec', dont_inherit=True)
        body = marshal.dumps(code, 2)
        self.assertEqual(body.count(code.co_code), 1)
        instructions = bytearray(code.co_code)
        offset = next(i for i in range(0, len(instructions), 2)
                      if instructions[i] == dis.opmap['BINARY_OP'])
        instructions[offset] = dis._all_opmap['BINARY_OP_ADD_INT']
        modified = body.replace(code.co_code, bytes(instructions), 1)
        self.assertEqual(self.cache_worker(source, body).returncode, 0)
        self.assertEqual(self.cache_worker(source, modified).returncode, 2)

    def active_options(self):
        # The cache worker needs the complete setup-python installation. Its
        # hosted-runner parent is root-owned, unlike a managed SOS runtime, so
        # cache-specific tests inject only the already computed executable
        # observation. POSIX ownership and symlink checks have separate tests.
        python = Path(sys.executable).resolve()
        return {"cache_python": python, "cache_python_sha256": hashlib.sha256(python.read_bytes()).hexdigest()}

    def verify_active(self, **changes):
        options = self.active_options()
        with mock.patch(
                "sos.platforms.project_runtime_inventory.observed_executable_digest",
                return_value=options["cache_python_sha256"]):
            return self.verify(**(options | changes))

    def test_active_cache_matches_recompiled_checked_source_without_execution(self):
        initial = self.verify()
        source = self.site / "sos/__init__.py"
        for optimize in (0, 1, 2):
            py_compile.compile(str(source), doraise=True, optimize=optimize)
        before = {str(p): p.read_bytes() for p in self.site.rglob("*") if p.is_file()}
        result = self.verify_active()
        self.assertEqual(result, initial)
        self.assertEqual(before, {str(p): p.read_bytes() for p in self.site.rglob("*") if p.is_file()})
        with self.assertRaisesRegex(ProjectRuntimeError, "EXTRA"):
            self.verify()

    def test_active_cache_body_substitution_and_orphan_cache_refuse(self):
        source = self.site / "sos/__init__.py"
        cache = Path(py_compile.compile(str(source), doraise=True))
        good = cache.read_bytes()
        # Preserve the valid header; replace the executable body.
        source.write_bytes(b"raise RuntimeError('synthetic foreign bytecode')\n")
        py_compile.compile(str(source), doraise=True)
        foreign = cache.read_bytes()[16:]
        source.write_bytes(self.files["sos/__init__.py"])
        cache.write_bytes(good[:16] + foreign)
        with self.assertRaisesRegex(ProjectRuntimeError, "CACHE_INVALID"):
            self.verify_active()
        cache.rename(cache.with_name("unknown.cpython-312.pyc"))
        with self.assertRaisesRegex(ProjectRuntimeError, "CACHE_INVALID"):
            self.verify_active()

    def test_active_cache_wrong_interpreter_and_symlink_refuse(self):
        cache = Path(py_compile.compile(str(self.site / "sos/__init__.py"), doraise=True))
        options = self.active_options()
        with mock.patch(
                "sos.platforms.project_runtime_inventory.observed_executable_digest",
                return_value=options["cache_python_sha256"]):
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
