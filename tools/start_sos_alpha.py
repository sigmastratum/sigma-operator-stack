#!/usr/bin/env python3
"""Content-safe, checksum-bound first run for the SOS alpha bundle."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import re
import shutil
import subprocess
import sys
import stat
import tempfile
import signal
import time
import zipfile
from contextlib import contextmanager
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from pathlib import Path, PurePosixPath


VERSION = "0.1.0a6"
UV_VERSION = "0.12.6"
PYTHON_VERSION = "3.12.14"
WHEEL = f"sigma_operator_stack-{VERSION}-py3-none-any.whl"
SBOM = f"sigma-operator-stack-{VERSION}.cdx.json"
UNIVERSAL_WHEELS = frozenset(
    {
        "attrs-26.1.0-py3-none-any.whl",
        "jsonschema-4.26.0-py3-none-any.whl",
        "jsonschema_specifications-2025.9.1-py3-none-any.whl",
        "referencing-0.37.0-py3-none-any.whl",
        "typing_extensions-4.16.0-py3-none-any.whl",
    }
)
PLATFORM_WHEELS = {
    "Linux": frozenset(
        {"rpds_py-2026.6.3-cp312-cp312-manylinux_2_17_x86_64.manylinux2014_x86_64.whl"}
    ),
    "Windows": frozenset({"rpds_py-2026.6.3-cp312-cp312-win_amd64.whl"}),
    "Darwin": frozenset({"rpds_py-2026.6.3-cp312-cp312-macosx_11_0_arm64.whl"}),
}
BOOTSTRAP_UV = {"Linux": "uv", "Windows": "uv.exe", "Darwin": "uv"}
EXPECTED_FILES = frozenset(
    {
        "START-HERE.md",
        "alpha-feedback.md",
        "release-manifest.json",
        SBOM,
        "start-sos-alpha",
        WHEEL,
    }
)
PUBLIC_LICENSE_FILES = frozenset(
    {"LICENSE-CPYTHON.txt", "LICENSE-UV-APACHE", "LICENSE-UV-MIT"}
)
NATIVE_FILES = {
    "Linux": frozenset({"Install-SOS.command", "Test-SOS.command", "native-smoke", "uv"})
    | UNIVERSAL_WHEELS
    | PLATFORM_WHEELS["Linux"],
    "Windows": frozenset({"Install-SOS.ps1", "Test-SOS.ps1", "native-smoke", "uv.exe"})
    | UNIVERSAL_WHEELS
    | PLATFORM_WHEELS["Windows"],
    "Darwin": frozenset({"Install-SOS.command", "Test-SOS.command", "native-smoke", "uv"})
    | UNIVERSAL_WHEELS
    | PLATFORM_WHEELS["Darwin"],
}
MAX_FILE_BYTES = {
    "START-HERE.md": 256 * 1024,
    "alpha-feedback.md": 256 * 1024,
    "release-manifest.json": 1024 * 1024,
    SBOM: 16 * 1024 * 1024,
    "start-sos-alpha": 1024 * 1024,
    WHEEL: 64 * 1024 * 1024,
    "Install-SOS.ps1": 256 * 1024,
    "Test-SOS.ps1": 256 * 1024,
    "Install-SOS.command": 256 * 1024,
    "Test-SOS.command": 256 * 1024,
    "native-smoke": 1024 * 1024,
    "uv": 64 * 1024 * 1024,
    "uv.exe": 64 * 1024 * 1024,
    "LICENSE-CPYTHON.txt": 256 * 1024,
    "LICENSE-UV-APACHE": 256 * 1024,
    "LICENSE-UV-MIT": 256 * 1024,
    **{name: 64 * 1024 * 1024 for name in UNIVERSAL_WHEELS},
    **{
        name: 64 * 1024 * 1024
        for wheels in PLATFORM_WHEELS.values()
        for name in wheels
    },
}
SHA256 = re.compile(r"[0-9a-f]{64}")
GIT_OBJECT = re.compile(r"[0-9a-f]{40}")
UV_VERSION_OUTPUT = re.compile(
    rf"uv {re.escape(UV_VERSION)}(?: \([ -~]{{1,96}}\))?"
)


@dataclass
class StartError(Exception):
    code: str
    problem: str
    correction: str


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _fail(code: str, problem: str, correction: str) -> StartError:
    return StartError(code, problem, correction)


def _maintenance_binding(
    bundle: Path,
    manifest: dict[str, object],
    handoff_json: str,
) -> dict[str, object]:
    """Bind the verified outer release route without confusing it with MCP Python."""
    try:
        handoff = json.loads(handoff_json)
    except (json.JSONDecodeError, TypeError) as error:
        raise _fail(
            "SOS_ALPHA_MAINTENANCE_BINDING_INVALID",
            "The public release maintenance binding is malformed.",
            "Rediscover the canonical release and use its exact binding.",
        ) from error
    required = {
        "contract",
        "version",
        "release_tag",
        "candidate",
        "tree",
        "archive_filename",
        "archive_sha256",
        "inner_manifest_sha256",
        "system",
        "architecture",
        "profile_id",
        "platform_launcher",
    }
    if not isinstance(handoff, dict) or set(handoff) != required:
        raise _fail(
            "SOS_ALPHA_MAINTENANCE_BINDING_INVALID",
            "The public release maintenance binding has an unexpected shape.",
            "Rediscover the canonical release and use its exact binding.",
        )
    strings = {name: handoff.get(name) for name in required}
    if any(not isinstance(value, str) for value in strings.values()):
        raise _fail(
            "SOS_ALPHA_MAINTENANCE_BINDING_INVALID",
            "The public release maintenance binding contains an invalid value.",
            "Rediscover the canonical release and use its exact binding.",
        )
    observed_system = {"Darwin": "darwin", "Linux": "linux", "Windows": "windows"}.get(
        platform.system(), "unknown"
    )
    observed_architecture = platform.machine().lower()
    if observed_architecture in {"amd64", "x86_64"}:
        observed_architecture = "x86_64"
    elif observed_architecture in {"arm64", "aarch64"}:
        observed_architecture = "arm64"
    manifest_path = bundle / "release-manifest.json"
    launcher_name = str(handoff["platform_launcher"])
    launcher_path = bundle / launcher_name
    artifacts = {
        item.get("filename"): item.get("sha256")
        for item in manifest.get("artifacts", [])
        if isinstance(item, dict)
    }
    exact = (
        handoff["contract"] == "sos_public_maintenance_handoff_v1"
        and handoff["version"] == manifest.get("version")
        and handoff["release_tag"] == f"v{manifest.get('version')}"
        and handoff["candidate"] == manifest.get("candidate")
        and handoff["tree"] == manifest.get("tree")
        and handoff["system"] == observed_system
        and handoff["architecture"] == observed_architecture
        and handoff["platform_launcher"] == "Install-SOS.command"
        and SHA256.fullmatch(str(handoff["archive_sha256"])) is not None
        and SHA256.fullmatch(str(handoff["inner_manifest_sha256"])) is not None
        and _sha256(manifest_path) == handoff["inner_manifest_sha256"]
        and launcher_path.is_file()
        and not launcher_path.is_symlink()
        and artifacts.get(launcher_name) == _sha256(launcher_path)
    )
    if not exact:
        raise _fail(
            "SOS_ALPHA_MAINTENANCE_BINDING_MISMATCH",
            "The public release route does not match this exact checked bundle.",
            "Discard the extraction, rediscover the canonical release, and download it again.",
        )
    binding = {
        "contract": "sos_maintenance_launcher_binding_v1",
        "version": handoff["version"],
        "release_tag": handoff["release_tag"],
        "candidate": handoff["candidate"],
        "tree": handoff["tree"],
        "archive_filename": handoff["archive_filename"],
        "archive_sha256": handoff["archive_sha256"],
        "inner_manifest_sha256": handoff["inner_manifest_sha256"],
        "system": handoff["system"],
        "architecture": handoff["architecture"],
        "profile_id": handoff["profile_id"],
        "platform_launcher": launcher_name,
        "platform_launcher_sha256": artifacts[launcher_name],
        "raw_content_serialized": False,
        "absolute_paths_serialized": False,
    }
    binding["binding_digest"] = "sha256:" + hashlib.sha256(
        json.dumps(binding, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    ).hexdigest()
    return binding


def _require_recorded_maintenance_binding(
    root: Path, binding: dict[str, object]
) -> None:
    receipt_path = root / ".sigma" / "lifecycle" / "p106-install.json"
    try:
        if receipt_path.is_symlink() or receipt_path.stat().st_size > 1024 * 1024:
            raise OSError
        receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise _fail(
            "SOS_ALPHA_MAINTENANCE_BINDING_NOT_RECORDED",
            "The project has no readable exact maintenance release binding.",
            "Do not guess a launcher; reinstall through the canonical public route.",
        ) from error
    recorded = receipt.get("maintenance_launcher_binding") if isinstance(receipt, dict) else None
    if not isinstance(recorded, dict):
        raise _fail(
            "SOS_ALPHA_MAINTENANCE_BINDING_NOT_RECORDED",
            "The project predates the separate maintenance release binding.",
            "Do not guess a launcher; reinstall through the canonical public route.",
        )
    if recorded != binding:
        raise _fail(
            "SOS_ALPHA_MAINTENANCE_RELEASE_MISMATCH",
            "The verified maintenance archive does not match the project's recorded release.",
            "Rediscover and download the exact recorded release before continuing.",
        )


def validate_platform(
    system: str | None = None,
    machine: str | None = None,
    python_version: tuple[int, int] | None = None,
    system_version: str | None = None,
) -> None:
    system = platform.system() if system is None else system
    machine = platform.machine() if machine is None else machine
    python_version = sys.version_info[:2] if python_version is None else python_version
    if system_version is None:
        system_version = platform.mac_ver()[0] if system == "Darwin" else platform.version()
    normalized_machine = machine.lower()
    supported = (
        (system == "Linux" and normalized_machine == "x86_64")
        or (system == "Windows" and normalized_machine in {"amd64", "x86_64"})
        or (system == "Darwin" and normalized_machine in {"arm64", "aarch64"})
    )
    if not supported:
        raise _fail(
            "SOS_ALPHA_PLATFORM_UNSUPPORTED",
            f"This private alpha does not support {system or 'unknown'} {machine or 'unknown'}.",
            "Use Linux x86_64, Windows 11 x86_64, or macOS 14+ Apple Silicon.",
        )
    numeric_version = tuple(
        int(value) for value in re.findall(r"\d+", system_version or "")[:3]
    )
    platform_version_supported = (
        system == "Linux"
        or (system == "Windows" and len(numeric_version) >= 3 and numeric_version[2] >= 22000)
        or (system == "Darwin" and bool(numeric_version) and numeric_version[0] >= 14)
    )
    if not platform_version_supported:
        raise _fail(
            "SOS_ALPHA_PLATFORM_UNSUPPORTED",
            "This private alpha requires Windows 11 or macOS 14 or newer.",
            "Upgrade the operating system or use a supported Linux x86_64 host.",
        )
    if python_version not in {(3, 11), (3, 12)}:
        observed = ".".join(str(item) for item in python_version)
        raise _fail(
            "SOS_ALPHA_PYTHON_UNSUPPORTED",
            f"This alpha requires Python 3.11 or 3.12; detected {observed}.",
            "Install Python 3.11 or 3.12, then run the platform launcher again.",
        )


def _required_command(name: str, which: Callable[[str], str | None]) -> str:
    value = which(name)
    if value:
        return value
    raise _fail(
        f"SOS_ALPHA_{name.upper()}_MISSING",
        f"Required command '{name}' was not found.",
        f"Install {name} from its official distribution, then run the launcher again.",
    )


def find_codex(which: Callable[[str], str | None] = shutil.which, home: Path | None = None) -> Path:
    direct = which("codex")
    if direct:
        return Path(direct)
    root = (home or Path.home()).resolve()
    patterns = (
        ".vscode-server/extensions/openai.chatgpt-*/bin/*/codex",
        ".vscode/extensions/openai.chatgpt-*/bin/*/codex",
        "Library/Application Support/Code/User/globalStorage/openai.chatgpt/bin/*/codex",
    )
    for pattern_value in patterns:
        for candidate in sorted(root.glob(pattern_value)):
            if candidate.is_file() and os.access(candidate, os.X_OK):
                return candidate
    raise _fail(
        "SOS_ALPHA_CODEX_MISSING",
        "Codex was not found in PATH or in a supported VS Code extension location.",
        "Install or enable Codex for this user, then run the launcher again.",
    )


def _tool_command(tool_bin: Path) -> Path:
    candidates = (tool_bin / "sos.exe", tool_bin / "sos") if os.name == "nt" else (tool_bin / "sos",)
    for candidate in candidates:
        if candidate.is_file() and (os.name == "nt" or os.access(candidate, os.X_OK)):
            return candidate
    raise _fail(
        "SOS_ALPHA_TOOL_BINDING_MISSING",
        "The installed SOS command was not found in the uv tool directory.",
        "Check 'uv tool dir --bin', then run the launcher again.",
    )


def _installed_sos(
    uv: str,
    runner: Callable[..., subprocess.CompletedProcess[str]],
) -> Path:
    tool_bin = runner(
        [uv, "tool", "dir", "--bin"],
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    if tool_bin.returncode != 0 or not tool_bin.stdout.strip():
        raise _fail(
            "SOS_ALPHA_TOOL_BINDING_MISSING",
            "uv did not report its tool directory.",
            "Run 'uv tool dir --bin', correct the uv setup, then run the launcher again.",
        )
    return _tool_command(Path(tool_bin.stdout.strip()))


def _admit_exact_uv(
    uv: str,
    manifest: dict[str, object],
    runner: Callable[..., subprocess.CompletedProcess[str]],
) -> None:
    try:
        artifacts = {
            item["filename"]: item
            for item in manifest["artifacts"]  # type: ignore[index]
            if isinstance(item, dict) and isinstance(item.get("filename"), str)
        }
        bootstrap_name = BOOTSTRAP_UV[platform.system()]
        expected = artifacts[bootstrap_name]["sha256"]
        observed = _sha256(Path(uv))
    except (KeyError, OSError, TypeError) as error:
        raise _fail(
            "SOS_ALPHA_UV_BINDING_INVALID",
            "The managed uv bootstrap is not bound to this checked bundle.",
            "Do not continue; use the complete replacement bundle.",
        ) from error
    version = runner(
        [uv, "--version"],
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    if (
        observed != expected
        or version.returncode != 0
        or UV_VERSION_OUTPUT.fullmatch(version.stdout.strip()) is None
    ):
        raise _fail(
            "SOS_ALPHA_UV_BINDING_INVALID",
            "The managed uv executable does not match the checked bundle.",
            "Do not continue; use the complete replacement bundle.",
        )


def _offline_tool_install_command(uv: str, bundle: Path, *, force: bool = False) -> list[str]:
    command = [uv, "tool", "install"]
    if force:
        command.append("--force")
    command.extend(
        [
            "--offline",
            "--no-index",
            "--find-links",
            os.fspath(bundle),
            "--no-config",
            "--no-sources",
            "--no-build",
            "--no-python-downloads",
            "--python",
            sys.executable,
            os.fspath(bundle / WHEEL),
        ]
    )
    return command


@dataclass(frozen=True)
class PreparedController:
    """Ephemeral checked wheel import root, never a project's launcher."""

    python: Path
    packages: Path
    interpreter_sha256: str
    inventory: tuple[tuple[str, str], ...]

    def command(self, module: str, arguments: Sequence[str]) -> list[str]:
        if module not in {"sos", "sos.native_maintenance"}:
            raise ValueError("unsupported controller entrypoint")
        if (_sha256(self.python) != self.interpreter_sha256
                or _controller_inventory(self.packages) != self.inventory):
            raise _fail("SOS_ALPHA_CONTROLLER_CHANGED", "Prepared controller changed.",
                        "Repeat verified disposable preparation; keep installed runtimes unchanged.")
        return [os.fspath(self.python), "-I", "-S", "-B", "-c",
                "import runpy,sys; root,module=sys.argv[1:3]; "
                "sys.path.insert(0,root); sys.argv=[module]+sys.argv[3:]; "
                "runpy.run_module(module,run_name='__main__')",
                os.fspath(self.packages), module, *arguments]


def _controller_inventory(packages: Path) -> tuple[tuple[str, str], ...]:
    if packages.is_symlink() or not packages.is_dir():
        raise _fail("SOS_ALPHA_CONTROLLER_CHANGED", "Controller directory changed.",
                    "Repeat verified disposable preparation.")
    result = []
    total = 0
    for count, path in enumerate(packages.rglob("*"), start=1):
        if count > 60000:
            raise _fail("SOS_ALPHA_CONTROLLER_CHANGED", "Controller inventory exceeded its bound.",
                        "Repeat verified disposable preparation.")
        if path.is_symlink() or not (path.is_file() or path.is_dir()):
            raise _fail("SOS_ALPHA_CONTROLLER_CHANGED", "Controller entry changed.",
                        "Repeat verified disposable preparation.")
        if path.is_file():
            size = path.stat().st_size
            total += size
            if size > 32 * 1024 * 1024 or total > 256 * 1024 * 1024:
                raise _fail("SOS_ALPHA_CONTROLLER_CHANGED", "Controller file size changed.",
                            "Repeat verified disposable preparation.")
            result.append((path.relative_to(packages).as_posix(), _sha256(path)))
    return tuple(sorted(result))


def _extract_controller_wheels(bundle: Path, packages: Path, artifacts: dict[str, str]) -> None:
    """Unpack only digest-bound root-layout wheels; never process .pth files."""
    seen: set[str] = set()
    total = 0
    try:
        for filename, expected in sorted(artifacts.items()):
            wheel = bundle / filename
            if wheel.is_symlink() or not wheel.is_file() or _sha256(wheel) != expected:
                raise ValueError("wheel changed")
            with zipfile.ZipFile(wheel) as archive:
                members = archive.infolist()
                if not 1 <= len(members) <= 10000:
                    raise ValueError("wheel inventory")
                wheel_seen = set()
                for item in members:
                    name = item.filename
                    path = PurePosixPath(name)
                    mode = item.external_attr >> 16
                    if (not path.parts or path.is_absolute() or "\\" in name or "\x00" in name
                            or name.rstrip("/") != str(path) or ".." in path.parts
                            or name in wheel_seen or any(p.endswith(".data") for p in path.parts)
                            or stat.S_IFMT(mode) not in {0, stat.S_IFREG, stat.S_IFDIR}):
                        raise ValueError("unsafe wheel member")
                    wheel_seen.add(name)
                    if item.is_dir():
                        continue
                    total += item.file_size
                    if name in seen or len(seen) >= 30000 or total > 256 * 1024 * 1024:
                        raise ValueError("conflicting or oversized wheels")
                    if item.file_size > 32 * 1024 * 1024 or name.endswith((".pth", ".pyc")):
                        raise ValueError("unsupported import hook")
                    seen.add(name)
                    destination = packages.joinpath(*path.parts)
                    destination.parent.mkdir(parents=True, exist_ok=True)
                    with destination.open("xb") as output:
                        output.write(archive.read(item))
                    destination.chmod(0o600)
            if _sha256(wheel) != expected:
                raise ValueError("wheel changed")
    except (OSError, ValueError, RuntimeError, zipfile.BadZipFile):
        raise _fail("SOS_ALPHA_CONTROLLER_WHEEL_INVALID",
                    "The checked wheels cannot form an isolated controller.",
                    "Keep the installed runtime unchanged and obtain the exact complete bundle.") from None


@contextmanager
def prepare_controller(bundle: Path, *, python: Path, interpreter_sha256: str,
                       maintenance_handoff_json: str, runner=subprocess.run):
    """Prepare outside shared/runtime/project state; no package manager or network.

    Python must have been independently acquired and observed by the bootstrap.
    Root-layout wheel files are directly unpacked; entrypoint scripts and .pth
    processing are unnecessary for the isolated module invocation.
    """
    manifest = verify_bundle(bundle)
    _maintenance_binding(bundle, manifest, maintenance_handoff_json)
    python = python.resolve(strict=True)
    if not SHA256.fullmatch(interpreter_sha256) or _sha256(python) != interpreter_sha256:
        raise _fail("SOS_ALPHA_CONTROLLER_PYTHON_INVALID", "Controller Python changed.",
                    "Repeat verified disposable preparation.")
    version = runner([str(python), "-I", "-S", "-B", "--version"],
                     capture_output=True, text=True, check=False, timeout=15)
    if version.returncode != 0 or version.stdout.strip() != "Python " + PYTHON_VERSION:
        raise _fail("SOS_ALPHA_CONTROLLER_PYTHON_INVALID", "Controller Python is not pinned.",
                    "Use the checked managed Python runtime.")
    names = UNIVERSAL_WHEELS | PLATFORM_WHEELS[platform.system()] | {WHEEL}
    wheels = {a["filename"]: a["sha256"] for a in manifest["artifacts"] if a["filename"] in names}
    if set(wheels) != names:
        raise _fail("SOS_ALPHA_CONTROLLER_WHEEL_INVALID", "Controller wheelhouse is incomplete.",
                    "Obtain the complete checked bundle.")
    temporary = tempfile.mkdtemp(prefix="sos-controller-")
    retain = False
    try:
        packages = Path(temporary).resolve() / "packages"
        packages.mkdir(mode=0o700)
        _extract_controller_wheels(bundle, packages, wheels)
        if _sha256(python) != interpreter_sha256:
            raise _fail("SOS_ALPHA_CONTROLLER_PYTHON_INVALID", "Controller Python changed.",
                        "Repeat verified disposable preparation.")
        yield PreparedController(python, packages, interpreter_sha256, _controller_inventory(packages))
    except StartError as error:
        retain = error.code == "SOS_ALPHA_CONTROLLER_PROCESSES_UNRESOLVED"
        raise
    finally:
        if not retain:
            shutil.rmtree(temporary)


def _controller_group_exists(pgid):
    try:
        os.killpg(pgid, 0)
        return True
    except ProcessLookupError:
        return False
    except OSError:
        return True  # Lack of observation is not proof that a group exited.


def _stop_controller_group(process, *, grace=5.0):
    """Only our new session; never match processes by executable or path."""
    for sig in (signal.SIGTERM, signal.SIGKILL):
        try:
            os.killpg(process.pid, sig)
        except ProcessLookupError:
            pass
        except OSError:
            return False
        deadline = time.monotonic() + grace
        while time.monotonic() < deadline:
            process.poll()
            if not _controller_group_exists(process.pid):
                process.wait()
                return True
            time.sleep(0.05)
    process.poll()
    return not _controller_group_exists(process.pid)


def _supervise_controller(command, *, env, popen=subprocess.Popen, grace=5.0):
    """Human wait has no deadline. Individual worker operations remain bounded.

    Inherited stdin is a TTY; the new session isolates cancellation from other
    project MCP servers. A nonzero child result is never a rollback claim.
    """
    process = None
    spawning = False
    previous = {}
    def interrupted(signum, frame):
        raise KeyboardInterrupt
    try:
        for sig in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP):
            previous[sig] = signal.signal(sig, interrupted)
        spawning = True
        process = popen(command, env=env, start_new_session=True)
        spawning = False
        code = process.wait()
        if _controller_group_exists(process.pid):
            if not _stop_controller_group(process, grace=grace):
                raise _fail("SOS_ALPHA_CONTROLLER_PROCESSES_UNRESOLVED",
                    "Controller descendants are not confirmed stopped; preparation is retained.",
                    "Do not repeat maintenance until process termination is verified.")
            raise _fail("SOS_ALPHA_CONTROLLER_DESCENDANTS_INTERRUPTED",
                        "Controller exited with running descendants.",
                        "Inspect the durable transition before further maintenance.")
        return subprocess.CompletedProcess(command, code)
    except (KeyboardInterrupt, subprocess.SubprocessError, OSError):
        # Ignore repeated cancellation while reaping our group. Never write a
        # guessed terminal state into the product journal from the supervisor.
        for sig in previous:
            signal.signal(sig, signal.SIG_IGN)
        if spawning and process is None:
            # Popen can be interrupted after fork but before returning its
            # handle. Without a registered group, termination is unproven.
            raise _fail("SOS_ALPHA_CONTROLLER_PROCESSES_UNRESOLVED",
                "Controller creation was interrupted; preparation is retained.",
                "Verify process termination before repeating maintenance.") from None
        if process is not None and not _stop_controller_group(process, grace=grace):
            raise _fail("SOS_ALPHA_CONTROLLER_PROCESSES_UNRESOLVED",
                "Controller termination is unverified; preparation is retained.",
                "Do not repeat maintenance until process termination is verified.") from None
        raise _fail("SOS_ALPHA_CONTROLLER_INTERRUPTED", "The controller was interrupted.",
                    "Inspect the durable transition; use official recovery if pending.") from None
    finally:
        for sig, handler in previous.items():
            signal.signal(sig, handler)


def _expected_files(system: str) -> frozenset[str]:
    return EXPECTED_FILES | NATIVE_FILES.get(system, frozenset())


def _read_checksums(
    path: Path, expected_file_sets: tuple[frozenset[str], ...]
) -> dict[str, str]:
    try:
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeError) as error:
        raise _fail(
            "SOS_ALPHA_CHECKSUMS_MISSING",
            "SHA256SUMS is missing or unreadable.",
            "Download or copy the complete alpha bundle again.",
        ) from error
    values: dict[str, str] = {}
    for line in text.splitlines():
        parts = line.split("  ", 1)
        if len(parts) != 2 or not SHA256.fullmatch(parts[0]) or "/" in parts[1] or parts[1] in values:
            raise _fail(
                "SOS_ALPHA_CHECKSUMS_INVALID",
                "SHA256SUMS is not in the exact supported format.",
                "Download or copy the complete alpha bundle again.",
            )
        values[parts[1]] = parts[0]
    if not any(set(values) == expected for expected in expected_file_sets):
        raise _fail(
            "SOS_ALPHA_BUNDLE_INCOMPLETE",
            "The bundle file inventory does not match this alpha.",
            "Download or copy the complete alpha bundle again.",
        )
    return values


def verify_bundle(bundle: Path, *, system: str = platform.system()) -> dict[str, object]:
    try:
        bundle = bundle.resolve(strict=True)
    except OSError as error:
        raise _fail(
            "SOS_ALPHA_BUNDLE_MISSING",
            "The alpha bundle directory is missing or unreadable.",
            "Download or copy the complete alpha bundle again.",
        ) from error
    private_files = _expected_files(system)
    public_files = private_files | PUBLIC_LICENSE_FILES
    checksums = _read_checksums(
        bundle / "SHA256SUMS", (private_files, public_files)
    )
    expected_files = frozenset(checksums)
    public_bundle = expected_files == public_files
    for filename in sorted(expected_files):
        path = bundle / filename
        try:
            invalid_type = path.is_symlink() or not path.is_file()
            too_large = not invalid_type and path.stat().st_size > MAX_FILE_BYTES[filename]
        except OSError as error:
            raise _fail(
                "SOS_ALPHA_BUNDLE_FILE_INVALID",
                f"Bundle file '{filename}' is unreadable.",
                "Download or copy the complete alpha bundle again.",
            ) from error
        if invalid_type:
            raise _fail(
                "SOS_ALPHA_BUNDLE_FILE_INVALID",
                f"Bundle file '{filename}' is missing or has an unsupported file type.",
                "Download or copy the complete alpha bundle again.",
            )
        if too_large:
            raise _fail(
                "SOS_ALPHA_BUNDLE_FILE_TOO_LARGE",
                f"Bundle file '{filename}' exceeds its safety limit.",
                "Download or copy the complete alpha bundle again.",
            )
        try:
            observed_digest = _sha256(path)
        except OSError as error:
            raise _fail(
                "SOS_ALPHA_BUNDLE_FILE_INVALID",
                f"Bundle file '{filename}' is unreadable.",
                "Download or copy the complete alpha bundle again.",
            ) from error
        if observed_digest != checksums[filename]:
            raise _fail(
                "SOS_ALPHA_CHECKSUM_MISMATCH",
                f"Checksum verification failed for '{filename}'.",
                "Do not continue; download or copy the complete alpha bundle again.",
            )
    try:
        manifest = json.loads((bundle / "release-manifest.json").read_text(encoding="utf-8"))
        if (
            not isinstance(manifest, dict)
            or not isinstance(manifest.get("artifacts"), list)
            or not isinstance(manifest.get("build"), dict)
        ):
            raise TypeError("manifest shape")
        artifact_items = manifest["artifacts"]
        artifacts = {item["filename"]: item for item in artifact_items}
    except (KeyError, OSError, TypeError, UnicodeError, ValueError, json.JSONDecodeError) as error:
        raise _fail(
            "SOS_ALPHA_MANIFEST_INVALID",
            "The release manifest is malformed.",
            "Download or copy the complete alpha bundle again.",
        ) from error
    expected_artifacts = expected_files.difference({"release-manifest.json"})
    expected_media = {
        "START-HERE.md": "text/markdown",
        "alpha-feedback.md": "text/markdown",
        SBOM: "application/vnd.cyclonedx+json",
        "start-sos-alpha": "text/x-python",
        WHEEL: "application/zip",
        "Install-SOS.ps1": "text/x-powershell",
        "Test-SOS.ps1": "text/x-powershell",
        "Install-SOS.command": "text/x-shellscript",
        "Test-SOS.command": "text/x-shellscript",
        "native-smoke": "text/x-python",
        "uv": "application/octet-stream",
        "uv.exe": "application/vnd.microsoft.portable-executable",
        "LICENSE-CPYTHON.txt": "text/plain",
        "LICENSE-UV-APACHE": "text/plain",
        "LICENSE-UV-MIT": "text/plain",
        **{name: "application/zip" for name in UNIVERSAL_WHEELS},
        **{
            name: "application/zip"
            for wheels in PLATFORM_WHEELS.values()
            for name in wheels
        },
    }
    expected_contract = (
        "sos_native_public_alpha_bundle_v1"
        if public_bundle
        else (
            "sos_native_private_alpha_bundle_v2"
            if system in NATIVE_FILES
            else "sos_public_release_manifest_v1"
        )
    )
    build = manifest.get("build", {})
    build_valid = (
        build.get("acquisition_network_allowed") is True
        and build.get("network_allowed_after_verified_handoff") is False
        and build.get("managed_python") == PYTHON_VERSION
        and build.get("uv") == UV_VERSION
        if system in NATIVE_FILES
        else build.get("network_allowed") is False
    )
    if public_bundle and system == "Darwin":
        build_valid = build_valid and build.get("distribution_trust") == {
            "artifact_signed": False,
            "gatekeeper_user_action": "open_anyway_may_be_required",
            "notarized": False,
            "security_bypass_allowed": False,
        }
    if (
        manifest.get("contract") != expected_contract
        or manifest.get("version") != VERSION
        or not GIT_OBJECT.fullmatch(str(manifest.get("candidate", "")))
        or not GIT_OBJECT.fullmatch(str(manifest.get("tree", "")))
        or not build_valid
        or len(artifact_items) != len(expected_artifacts)
        or set(artifacts) != expected_artifacts
        or any(
            artifacts[name].get("sha256") != checksums[name]
            or artifacts[name].get("media_type") != expected_media[name]
            or set(artifacts[name]) != {"filename", "media_type", "sha256"}
            for name in expected_artifacts
        )
    ):
        raise _fail(
            "SOS_ALPHA_MANIFEST_BINDING_INVALID",
            "The bundle manifest is not bound to the exact checked artifacts.",
            "Do not continue; download or copy the complete alpha bundle again.",
        )
    return manifest


def discover_project_root(
    project: Path,
    git: str,
    runner: Callable[..., subprocess.CompletedProcess[str]] = subprocess.run,
) -> Path:
    try:
        requested = project.resolve(strict=True)
    except OSError as error:
        raise _fail(
            "SOS_ALPHA_PROJECT_MISSING",
            "The selected project directory does not exist.",
            "Open a terminal in an existing Git project, then run the launcher again.",
        ) from error
    if not requested.is_dir():
        raise _fail(
            "SOS_ALPHA_PROJECT_INVALID",
            "The selected project path is not a directory.",
            "Open a terminal in an existing Git project, then run the launcher again.",
        )
    completed = runner(
        [git, "-C", os.fspath(requested), "rev-parse", "--show-toplevel"],
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    if completed.returncode != 0 or not completed.stdout.strip():
        raise _fail(
            "SOS_ALPHA_GIT_REPOSITORY_REQUIRED",
            "The selected directory is not inside a Git repository.",
            "Open a terminal in the root of an existing Git project, then run the launcher again.",
        )
    try:
        root = Path(completed.stdout.strip()).resolve(strict=True)
        requested.relative_to(root)
    except (OSError, ValueError) as error:
        raise _fail(
            "SOS_ALPHA_GIT_ROOT_INVALID",
            "Git returned a project root that does not contain the selected directory.",
            "Check the repository and run the launcher from its root.",
        ) from error
    return root


def run_onboarding(
    bundle: Path,
    project: Path,
    *,
    primary_authority_id: str | None = None,
    maintenance_handoff_json: str | None = None,
    resume_confirmation_seed: str | None = None,
    expected_plan_digest: str | None = None,
    uv_path: str | None = None,
    which: Callable[[str], str | None] = shutil.which,
    runner: Callable[..., subprocess.CompletedProcess[str]] = subprocess.run,
    client: str = "codex",
) -> Path:
    validate_platform()
    git = _required_command("git", which)
    uv = uv_path or _required_command("uv", which)
    if client == "codex":
        find_codex(which=which)
    elif client != "claude-code":
        raise _fail("SOS_ALPHA_CLIENT_UNSUPPORTED", "The requested client is not supported.", "Use codex or claude-code.")
    manifest = verify_bundle(bundle)
    maintenance_binding = (
        _maintenance_binding(bundle, manifest, maintenance_handoff_json)
        if maintenance_handoff_json is not None
        else None
    )
    if uv_path is not None:
        _admit_exact_uv(uv, manifest, runner)
    root = discover_project_root(project, git, runner)
    print("SOS alpha checks passed.")
    print(f"Release: {manifest['version']} ({str(manifest['candidate'])[:12]})")
    print(f"Project: {root}")
    print("Installing the exact checked SOS wheel. Project files are not changed yet.")
    # A previous attempt may have installed the same public version from an
    # older candidate before project admission stopped. Rebind the SOS-owned
    # tool environment to the exact checked wheel on every onboarding retry.
    installed = runner(
        _offline_tool_install_command(uv, bundle, force=True), check=False
    )
    if installed.returncode != 0:
        raise _fail(
            "SOS_ALPHA_INSTALL_FAILED",
            "uv could not install the exact SOS wheel.",
            "Read the uv error above, correct it, then run the launcher again.",
        )
    sos = _installed_sos(uv, runner)
    compatibility_command = [
        os.fspath(sos),
        "compatibility",
        os.fspath(root),
        "--json",
    ]
    if primary_authority_id is not None:
        compatibility_command.extend(["--primary-authority", primary_authority_id])
    compatibility = runner(
        compatibility_command,
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    try:
        compatibility_result = json.loads(compatibility.stdout)
    except (json.JSONDecodeError, TypeError) as error:
        raise _fail(
            "SOS_ALPHA_COMPATIBILITY_INVALID",
            "SOS did not return a valid existing-project compatibility result.",
            "Read the SOS error, correct the named issue, then run the launcher again.",
        ) from error
    if (
        not isinstance(compatibility_result, dict)
        or compatibility_result.get("contract")
        != "sos_compatibility_projection_v1"
    ):
        raise _fail(
            "SOS_ALPHA_COMPATIBILITY_INVALID",
            "SOS returned an unexpected existing-project compatibility contract.",
            "Stop and verify the exact installed SOS package before retrying.",
        )
    compatibility_status = compatibility_result.get("status")
    if compatibility_status == "owner_required":
        details = compatibility_result.get("details")
        candidates = (
            details.get("authority_candidates", [])
            if isinstance(details, dict)
            else []
        )
        candidate_ids = [
            value.get("authority_id")
            for value in candidates
            if isinstance(value, dict)
            and isinstance(value.get("authority_id"), str)
        ]
        choices = ", ".join(candidate_ids) or "no valid IDs returned"
        raise _fail(
            "SOS_ALPHA_PRIMARY_AUTHORITY_REQUIRED",
            f"This project has more than one possible authority: {choices}.",
            "Choose the primary one and rerun: start-sos-alpha "
            "--primary-authority '<exact-discovered-id>' /path/to/project",
        )
    if compatibility.returncode != 0 or compatibility_status != "success":
        reasons = compatibility_result.get("reasons")
        reason = (
            reasons[0]
            if isinstance(reasons, list) and reasons
            else "unknown blocker"
        )
        raise _fail(
            "SOS_ALPHA_COMPATIBILITY_BLOCKED",
            f"SOS stopped before changing project files: {reason}.",
            "Correct the reported compatibility issue, then run the launcher again.",
        )
    print("Existing project compatibility check passed.")
    print("\nSOS will now show one complete project plan and ask once before changing files.")
    init_command = (
        [os.fspath(sos), "init", "--with-codex"]
        if client == "codex"
        else [os.fspath(sos), "init", "--with-client", client]
    )
    if maintenance_binding is not None:
        init_command.extend(
            [
                "--maintenance-release-binding-json",
                json.dumps(maintenance_binding, sort_keys=True, separators=(",", ":")),
            ]
        )
    if primary_authority_id is not None:
        init_command.extend(["--primary-authority", primary_authority_id])
    if resume_confirmation_seed is not None:
        init_command.extend(["--resume-confirmation-seed", resume_confirmation_seed])
    if expected_plan_digest is not None:
        init_command.extend(["--expected-plan-digest", expected_plan_digest])
    init_command.append(os.fspath(root))
    initialized = runner(init_command, check=False)
    if initialized.returncode != 0:
        raise _fail(
            "SOS_ALPHA_INIT_FAILED",
            "SOS did not finish project initialization.",
            "Read the SOS result above, correct the named issue, then run the launcher again.",
        )
    print("\nSOS is installed and connected to this project.")
    print("Next:")
    client_name = "Codex" if client == "codex" else "Claude Code"
    print(f"1. Restart or reopen {client_name} if the SOS tools are not visible.")
    print(f"2. Complete the normal {client_name} project trust prompt.")
    print("3. From the project root, run: sos qualify .")
    print("Qualification is intentionally separate and will ask before running project checks.")
    return root


def run_update(
    bundle: Path,
    project: Path,
    *,
    uv_path: str | None = None,
    maintenance_handoff_json: str | None = None,
    which: Callable[[str], str | None] = shutil.which,
    runner: Callable[..., subprocess.CompletedProcess[str]] = subprocess.run,
) -> Path:
    validate_platform()
    git = _required_command("git", which)
    uv = uv_path or _required_command("uv", which)
    manifest = verify_bundle(bundle)
    maintenance_binding = (
        _maintenance_binding(bundle, manifest, maintenance_handoff_json)
        if maintenance_handoff_json is not None
        else None
    )
    if uv_path is not None:
        _admit_exact_uv(uv, manifest, runner)
    root = discover_project_root(project, git, runner)
    if maintenance_binding is None:
        raise _fail("SOS_ALPHA_MAINTENANCE_BINDING_REQUIRED", "A checked release binding is required.",
                    "Use the canonical verified release route.")
    _run_isolated_maintenance_controller(bundle, root, maintenance_binding, mode="update", runner=runner)
    return root


def _run_isolated_maintenance_controller(bundle, root, maintenance_binding, *, mode, runner,
                                         client="codex", primary_authority_id=None,
                                         confirmation_seed=None, expected_plan_digest=None):
    print("Preparing a disposable checked SOS controller; existing runtimes stay unchanged.", flush=True)
    python = Path(sys.executable).resolve(strict=True)
    binding_json = json.dumps(maintenance_binding, sort_keys=True)
    handoff = {key: value for key, value in maintenance_binding.items()
               if key not in {"platform_launcher_sha256", "binding_digest",
                              "raw_content_serialized", "absolute_paths_serialized"}}
    handoff["contract"] = "sos_public_maintenance_handoff_v1"
    with prepare_controller(bundle, python=python, interpreter_sha256=_sha256(python),
                            maintenance_handoff_json=json.dumps(handoff), runner=runner) as controller:
        arguments = ["--mode", mode, "--project", str(root),
                     "--bundle", str(bundle.resolve(strict=True)),
                     "--namespace", str(Path.home() / ".local/share/sigma-operator-stack/project-runtimes"),
                     "--binding-json", binding_json,
                     "--interpreter-digest", "sha256:" + controller.interpreter_sha256,
                     "--client", client]
        if primary_authority_id is not None:
            arguments.extend(["--primary-authority", primary_authority_id])
        if confirmation_seed is not None:
            arguments.extend(["--confirmation-seed", confirmation_seed])
        if expected_plan_digest is not None:
            arguments.extend(["--expected-plan-digest", expected_plan_digest])
        command = controller.command("sos.native_maintenance", arguments)
        environment = {"PATH": "/usr/bin:/bin", "HOME": str(Path.home()), "LANG": "C.UTF-8"}
        try:
            result = (_supervise_controller(command, env=environment) if runner is subprocess.run
                      else runner(command, check=False, env=environment))
            if result.returncode not in {0, 2}:
                raise _fail("SOS_ALPHA_CONTROLLER_INTERRUPTED", "Controller exited without a normal terminal result.",
                            "Inspect durable state before any further maintenance.")
        except StartError as error:
            # Diagnostics cannot mutate the journal or adopt a different binding.
            observation = {"status": "blocked", "reasons": [error.code],
                           "details": {"transition_state": "unknown"}}
            if error.code != "SOS_ALPHA_CONTROLLER_PROCESSES_UNRESOLVED":
                try:
                    readback = subprocess.run(controller.command("sos.native_maintenance",
                        [*arguments, "--observe-only"]), env=environment, stdin=subprocess.DEVNULL,
                        capture_output=True, text=True, check=False, timeout=30)
                    value = json.loads(readback.stdout)
                    if readback.returncode == 0 and value.get("status") == "blocked":
                        observation["details"] = value["details"]
                except (OSError, ValueError, subprocess.SubprocessError):
                    pass
            print(json.dumps(observation, sort_keys=True), flush=True)
            raise
    if result.returncode != 0:
        raise _fail("SOS_ALPHA_RUNTIME_MAINTENANCE_STOPPED",
                    "SOS did not complete the isolated maintenance operation.",
                    "Read the typed controller result and use recover if requested.")


def run_isolated_install(bundle, project, *, primary_authority_id=None,
                         maintenance_handoff_json=None, resume_confirmation_seed=None,
                         expected_plan_digest=None, uv_path=None, which=shutil.which,
                         runner=subprocess.run, client="codex"):
    validate_platform()
    git = _required_command("git", which)
    if client == "codex":
        find_codex(which=which)
    elif client != "claude-code":
        raise _fail("SOS_ALPHA_CLIENT_UNSUPPORTED", "The requested client is not supported.",
                    "Use codex or claude-code.")
    manifest = verify_bundle(bundle)
    if maintenance_handoff_json is None:
        raise _fail("SOS_ALPHA_MAINTENANCE_BINDING_REQUIRED", "A checked release binding is required.",
                    "Use the canonical verified release route.")
    binding = _maintenance_binding(bundle, manifest, maintenance_handoff_json)
    if uv_path is not None:
        _admit_exact_uv(uv_path, manifest, runner)
    root = discover_project_root(project, git, runner)
    _run_isolated_maintenance_controller(bundle, root, binding, mode="install", runner=runner,
        client=client, primary_authority_id=primary_authority_id,
        confirmation_seed=resume_confirmation_seed, expected_plan_digest=expected_plan_digest)
    return root


def run_remove(
    bundle: Path,
    project: Path,
    *,
    uv_path: str | None = None,
    maintenance_handoff_json: str | None = None,
    which: Callable[[str], str | None] = shutil.which,
    runner: Callable[..., subprocess.CompletedProcess[str]] = subprocess.run,
) -> Path:
    validate_platform()
    git = _required_command("git", which)
    uv = uv_path or _required_command("uv", which)
    manifest = verify_bundle(bundle)
    maintenance_binding = (
        _maintenance_binding(bundle, manifest, maintenance_handoff_json)
        if maintenance_handoff_json is not None
        else None
    )
    if uv_path is not None:
        _admit_exact_uv(uv, manifest, runner)
    root = discover_project_root(project, git, runner)
    if maintenance_binding is None:
        raise _fail("SOS_ALPHA_MAINTENANCE_BINDING_REQUIRED", "A checked release binding is required.",
                    "Use the canonical verified release route.")
    _run_isolated_maintenance_controller(bundle, root, maintenance_binding, mode="remove", runner=runner)
    return root


def run_recover(bundle, project, *, uv_path=None, maintenance_handoff_json=None,
                which=shutil.which, runner=subprocess.run):
    validate_platform()
    git = _required_command("git", which)
    uv = uv_path or _required_command("uv", which)
    manifest = verify_bundle(bundle)
    if uv_path is not None:
        _admit_exact_uv(uv, manifest, runner)
    if maintenance_handoff_json is None:
        raise _fail("SOS_ALPHA_MAINTENANCE_BINDING_REQUIRED", "A checked release binding is required.",
                    "Use the canonical verified release route.")
    binding = _maintenance_binding(bundle, manifest, maintenance_handoff_json)
    root = discover_project_root(project, git, runner)
    _run_isolated_maintenance_controller(bundle, root, binding, mode="recover", runner=runner)
    return root


def run_detach(
    bundle: Path,
    project: Path,
    *,
    client: str,
    uv_path: str | None = None,
    maintenance_handoff_json: str | None = None,
    which: Callable[[str], str | None] = shutil.which,
    runner: Callable[..., subprocess.CompletedProcess[str]] = subprocess.run,
) -> Path:
    validate_platform()
    git = _required_command("git", which)
    uv = uv_path or _required_command("uv", which)
    manifest = verify_bundle(bundle)
    if uv_path is not None: _admit_exact_uv(uv, manifest, runner)
    root = discover_project_root(project, git, runner)
    if maintenance_handoff_json is None:
        raise _fail("SOS_ALPHA_MAINTENANCE_BINDING_REQUIRED", "Verified release binding is required.",
                    "Use the canonical release route.")
    binding = _maintenance_binding(bundle, manifest, maintenance_handoff_json)
    _run_isolated_maintenance_controller(bundle, root, binding, mode="detach", runner=runner, client=client)
    return root


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="start-sos-alpha",
        description="Check and install the exact SOS alpha bundle into one existing Git project.",
    )
    parser.add_argument("project", nargs="?", type=Path, default=Path.cwd())
    parser.add_argument("--primary-authority")
    parser.add_argument("--uv")
    parser.add_argument("--maintenance-release-binding-json")
    parser.add_argument("--resume-confirmation-seed")
    parser.add_argument("--expected-plan-digest")
    parser.add_argument("--client", choices=("codex", "claude-code"), default="codex")
    parser.add_argument("--mode", choices=("install", "detach", "update", "remove", "recover", "test"), default="install")
    arguments = parser.parse_args(argv)
    launcher = Path(__file__).absolute()
    try:
        confirmation_resume_requested = (
            arguments.resume_confirmation_seed is not None
            or arguments.expected_plan_digest is not None
        )
        if confirmation_resume_requested and arguments.mode != "install":
            raise _fail(
                "SOS_ALPHA_CONFIRMATION_HANDOFF_INVALID",
                "Confirmation resume is valid only for project installation.",
                "Rediscover the exact install preview and use both bound resume values.",
            )
        if (arguments.resume_confirmation_seed is None) != (
            arguments.expected_plan_digest is None
        ):
            raise _fail(
                "SOS_ALPHA_CONFIRMATION_HANDOFF_INVALID",
                "The confirmation handoff is incomplete.",
                "Use both the seed and exact plan digest from the same SOS preview.",
            )
        if launcher.is_symlink():
            raise _fail(
                "SOS_ALPHA_LAUNCHER_SYMLINK_FORBIDDEN",
                "The alpha launcher must not be run through a symbolic link.",
                "Run the checked start-sos-alpha file directly from the extracted bundle.",
            )
        if arguments.maintenance_release_binding_json is None:
            raise _fail(
                "SOS_ALPHA_MAINTENANCE_BINDING_REQUIRED",
                "This public launcher requires the exact canonical release binding.",
                "Start from the public GitHub URL so Codex can verify and supply the binding.",
            )
        if arguments.mode == "install":
            run_isolated_install(
                launcher.parent,
                arguments.project,
                primary_authority_id=arguments.primary_authority,
                uv_path=arguments.uv,
                maintenance_handoff_json=arguments.maintenance_release_binding_json,
                resume_confirmation_seed=arguments.resume_confirmation_seed,
                expected_plan_digest=arguments.expected_plan_digest,
                client=arguments.client,
            )
        elif arguments.mode == "detach":
            run_detach(launcher.parent, arguments.project, client=arguments.client, uv_path=arguments.uv, maintenance_handoff_json=arguments.maintenance_release_binding_json)
        elif arguments.mode == "update":
            run_update(
                launcher.parent,
                arguments.project,
                uv_path=arguments.uv,
                maintenance_handoff_json=arguments.maintenance_release_binding_json,
            )
        elif arguments.mode == "remove":
            run_remove(
                launcher.parent,
                arguments.project,
                uv_path=arguments.uv,
                maintenance_handoff_json=arguments.maintenance_release_binding_json,
            )
        elif arguments.mode == "test":
            manifest = verify_bundle(launcher.parent)
            binding = _maintenance_binding(launcher.parent, manifest, arguments.maintenance_release_binding_json)
            root = discover_project_root(arguments.project, _required_command("git", shutil.which), subprocess.run)
            _run_isolated_maintenance_controller(launcher.parent, root, binding, mode="test", runner=subprocess.run)
        else:
            run_recover(launcher.parent, arguments.project, uv_path=arguments.uv,
                        maintenance_handoff_json=arguments.maintenance_release_binding_json)
    except StartError as error:
        print("\nSOS alpha setup stopped.", file=sys.stderr)
        print(f"Code: {error.code}", file=sys.stderr)
        print(f"Problem: {error.problem}", file=sys.stderr)
        print(f"Fix: {error.correction}", file=sys.stderr)
        return 3 if error.code == "SOS_ALPHA_CONTROLLER_PROCESSES_UNRESOLVED" else 2
    except (subprocess.SubprocessError, KeyboardInterrupt):
        print(json.dumps({"status": "blocked", "reasons": ["SOS_ALPHA_CONTROLLER_FAILED"],
                          "details": {"transition_state": "unknown"}}), flush=True)
        return 2
    except OSError:
        print("\nSOS alpha setup stopped.", file=sys.stderr)
        print("Code: SOS_ALPHA_LOCAL_IO_FAILED", file=sys.stderr)
        print("Problem: A required local command or file could not be accessed.", file=sys.stderr)
        print("Fix: Check the displayed project and bundle permissions, then run the launcher again.", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
