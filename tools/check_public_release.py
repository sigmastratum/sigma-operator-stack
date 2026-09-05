#!/usr/bin/env python3
"""Fail-closed public repository and release-contract inspection."""

from __future__ import annotations

import argparse
import hashlib
import io
import json
import os
import re
import subprocess
import sys
from pathlib import Path, PurePosixPath

import yaml
from PIL import Image, ImageDraw, ImageFont


MAX_FILE_BYTES = 2 * 1024 * 1024
MAX_FILES = 4096
MAX_HISTORY_BYTES = 128 * 1024 * 1024
FORBIDDEN_PARTS = {".env", "evidence", "private", "secrets"}
FORBIDDEN_TEXT = (
    re.compile(r"/home/[A-Za-z0-9._-]+/"),
    re.compile(r"-----BEGIN (?:OPENSSH|RSA|EC) PRIVATE KEY-----"),
    re.compile(r"\b(?:ghp|github_pat|sk_live|sk_test)_[A-Za-z0-9_-]{12,}\b"),
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    re.compile(r"\bGTM" + r"-REQ-[0-9]+\b"),
    re.compile(r"\bprod" + r"-SESSION\b", re.IGNORECASE),
    re.compile(r"\bSIGMA" + r"-GTM\b"),
    re.compile(r"\bsigma" + r"_runtime\b"),
)
REQUIRED_FILES = {
    ".github/ISSUE_TEMPLATE/config.yml",
    ".github/pull_request_template.md",
    "CHANGELOG.md",
    "CODE_OF_CONDUCT.md",
    "CONTRIBUTING.md",
    "LICENSE",
    "INSTALL.md",
    "README.md",
    "SECURITY.md",
    "SUPPORT.md",
    "installers/README.md",
    "demo/README.md",
    "demo/capture.sh",
    "demo/capture_fresh_codex.py",
    "demo/fresh-codex-output.schema.json",
    "demo/fresh-codex-receipt.json",
    "demo/media-manifest.json",
    "demo/recovery-demo.mp4",
    "demo/recovery-demo.webm",
    "demo/recovery-loop.png",
    "demo/recovery-loop.svg",
    "demo/recovery-terminal.png",
    "demo/terminal-frame.txt",
    "demo/transcript.md",
    "demo/verify_fresh_codex_capture.py",
    "demo/voiceover.mp3",
    "demo/voiceover.txt",
    "docs/architecture.md",
    "docs/comparison.md",
    "docs/alpha-feedback.md",
    "docs/agent-first-offline-replay.md",
    "docs/agent-first-public-drill.md",
    "docs/alpha-scope-issue.md",
    "docs/dependency-licenses.md",
    "docs/launch-operations.md",
    "docs/publication-checklist.md",
    "docs/repository-opening-runbook.md",
    "docs/roadmap.md",
    "docs/threat-model.md",
    "docs/troubleshooting.md",
    "docs/version-update.md",
    "examples/fresh-agent-recovery/expected.json",
    "pyproject.toml",
    "requirements/audit.txt",
    "requirements/dependency-licenses.json",
    "requirements/runtime.txt",
    "src/sos/schemas/sos-agent-first-route-projection-v1.schema.json",
    "src/sos/schemas/sos-agent-first-offline-replay-v1.schema.json",
    "src/sos/schemas/sos-agent-first-drill-receipt-v1.schema.json",
    "src/sos/schemas/sos-agent-first-terminal-projection-v1.schema.json",
    "src/sos/schemas/sos-agent-first-terminal-snapshot-v1.schema.json",
    "src/sos/schemas/sos-windows-store-observation-v1.schema.json",
    "tests/fixtures/agent-first-release/replay-matrix.json",
    "tools/replay_agent_first_route.py",
    "tools/check_agent_first_drill.py",
    "tools/resolve_agent_first_route.py",
    "tools/check_public_release_pointer.py",
    "tools/check_native_release_assets.py",
    "tools/check_dependency_licenses.py",
}
REQUIRED_ISSUE_FORMS = {
    "bounded-feature-proposal.yml",
    "documentation-mismatch.yml",
    "existing-stack-collision.yml",
    "install-admission.yml",
    "qualification-currentness.yml",
    "recovery-mcp.yml",
    "update-uninstall.yml",
}
REQUIRED_FORM_IDS = {"version", "os_profile", "command", "reason_code", "reproducer", "privacy"}
PRIVACY_WORDS = ("secrets", "private source", "prompts", "raw .sigma", "paths", "hostnames", "customer data")
MEDIA_SUFFIXES = {".gif", ".mp3", ".mp4", ".png", ".webm"}
STORE_ICON_SHAPES = {
    "installers/windows-msix/assets/Square44x44Logo.png": (44, 44),
    "installers/windows-msix/assets/Square50x50Logo.png": (50, 50),
    "installers/windows-msix/assets/Square150x150Logo.png": (150, 150),
}
MARKDOWN_LINK = re.compile(r"(?<!!)\[[^\]]+\]\(([^)]+)\)")


def _inventory(repository: Path) -> list[str]:
    completed = subprocess.run(
        ["git", "-C", os.fspath(repository), "ls-files", "--cached", "--others", "--exclude-standard", "-z"],
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    files = [item.decode("utf-8") for item in completed.stdout.split(b"\0") if item]
    return sorted(files)


def _check_git_history(repository: Path, failures: list[str]) -> tuple[int, int]:
    commit_count_result = subprocess.run(
        ["git", "-C", os.fspath(repository), "rev-list", "--count", "HEAD"],
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    commit_count = int(commit_count_result.stdout.decode("ascii").strip())
    names_result = subprocess.run(
        ["git", "-C", os.fspath(repository), "log", "--format=", "--name-only", "-z", "HEAD"],
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    for item in names_result.stdout.split(b"\0"):
        if not item:
            continue
        try:
            name = item.decode("utf-8")
        except UnicodeDecodeError:
            failures.append("SOS_PUBLIC_HISTORY_PATH_ENCODING_INVALID")
            continue
        path = PurePosixPath(name)
        if path.is_absolute() or ".." in path.parts or FORBIDDEN_PARTS.intersection(path.parts):
            failures.append(f"SOS_PUBLIC_HISTORY_PATH_FORBIDDEN:{name}")

    history_result = subprocess.run(
        [
            "git",
            "-C",
            os.fspath(repository),
            "log",
            "--format=%H%n%B",
            "--no-ext-diff",
            "--binary",
            "HEAD",
        ],
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    history = history_result.stdout
    if len(history) > MAX_HISTORY_BYTES:
        failures.append("SOS_PUBLIC_HISTORY_BYTE_LIMIT_EXCEEDED")
        return commit_count, len(history)
    history_text = history.decode("latin-1")
    for pattern in FORBIDDEN_TEXT:
        if pattern.search(history_text):
            failures.append("SOS_PUBLIC_HISTORY_CONTENT_FORBIDDEN")
            break
    return commit_count, len(history)


def _slug(value: str) -> str:
    value = value.strip().lower()
    value = re.sub(r"[^a-z0-9 _-]", "", value)
    return re.sub(r"[ _]+", "-", value).strip("-")


def _markdown_anchors(path: Path) -> set[str]:
    text = path.read_text(encoding="utf-8")
    return {
        _slug(line.lstrip("#").strip())
        for line in text.splitlines()
        if line.startswith("#")
    }


def _check_markdown_links(
    repository: Path, files: list[str], failures: list[str]
) -> None:
    for name in files:
        if PurePosixPath(name).suffix.lower() != ".md":
            continue
        source = repository / name
        text = source.read_text(encoding="utf-8")
        for raw in MARKDOWN_LINK.findall(text):
            target = raw.strip().split(maxsplit=1)[0].strip("<>")
            if target.startswith(("https://", "http://", "mailto:")):
                continue
            path_text, _, fragment = target.partition("#")
            target_path = source if not path_text else source.parent / path_text
            try:
                resolved = target_path.resolve(strict=True)
            except OSError:
                failures.append(f"SOS_PUBLIC_MARKDOWN_LINK_BROKEN:{name}")
                continue
            if resolved != repository and repository not in resolved.parents:
                failures.append(f"SOS_PUBLIC_MARKDOWN_LINK_OUTSIDE_REPOSITORY:{name}")
                continue
            if not resolved.is_file():
                failures.append(f"SOS_PUBLIC_MARKDOWN_LINK_BROKEN:{name}")
                continue
            if fragment and resolved.suffix.lower() == ".md":
                if _slug(fragment) not in _markdown_anchors(resolved):
                    failures.append(f"SOS_PUBLIC_MARKDOWN_ANCHOR_BROKEN:{name}")


def _check_issue_forms(repository: Path, failures: list[str]) -> None:
    root = repository / ".github" / "ISSUE_TEMPLATE"
    observed = {path.name for path in root.glob("*.yml") if path.name != "config.yml"}
    if observed != REQUIRED_ISSUE_FORMS:
        failures.append("SOS_PUBLIC_ISSUE_FORM_SET_INVALID")
    for name in sorted(REQUIRED_ISSUE_FORMS.intersection(observed)):
        path = root / name
        try:
            form = yaml.load(path.read_text(encoding="utf-8"), Loader=yaml.BaseLoader)
        except yaml.YAMLError:
            failures.append(f"SOS_PUBLIC_ISSUE_FORM_YAML_INVALID:{name}")
            continue
        if not isinstance(form, dict) or not isinstance(form.get("body"), list):
            failures.append(f"SOS_PUBLIC_ISSUE_FORM_SCHEMA_INVALID:{name}")
            continue
        ids = {item.get("id") for item in form["body"] if isinstance(item, dict) and item.get("id")}
        if not REQUIRED_FORM_IDS.issubset(ids):
            failures.append(f"SOS_PUBLIC_ISSUE_FORM_FIELDS_MISSING:{name}")
        serialized = json.dumps(form, sort_keys=True).lower()
        if any(word not in serialized for word in PRIVACY_WORDS):
            failures.append(f"SOS_PUBLIC_ISSUE_FORM_PRIVACY_NOTICE_MISSING:{name}")
        for item in form["body"]:
            if not isinstance(item, dict) or item.get("id") not in REQUIRED_FORM_IDS:
                continue
            if item.get("id") == "privacy":
                options = item.get("attributes", {}).get("options", [])
                if not options or any(option.get("required") != "true" for option in options):
                    failures.append(f"SOS_PUBLIC_ISSUE_FORM_REQUIRED_FIELD_WEAK:{name}:privacy")
                continue
            validations = item.get("validations", {})
            if not isinstance(validations, dict) or validations.get("required") != "true":
                failures.append(f"SOS_PUBLIC_ISSUE_FORM_REQUIRED_FIELD_WEAK:{name}:{item.get('id')}")
    config = yaml.load((root / "config.yml").read_text(encoding="utf-8"), Loader=yaml.BaseLoader)
    if not isinstance(config, dict) or config.get("blank_issues_enabled") != "false":
        failures.append("SOS_PUBLIC_BLANK_ISSUES_ENABLED")


def _expected_demo_png() -> bytes:
    labels = ("discover", "preview", "install", "qualify", "recover", "stale", "safe next")
    image = Image.new("RGB", (1120, 180), "#0b1020")
    draw = ImageDraw.Draw(image)
    font = ImageFont.load_default(size=16)
    for index, label in enumerate(labels):
        left = 20 + index * 160
        right = left + (120 if index == 6 else 130)
        draw.rounded_rectangle(
            (left, 60, right, 118),
            radius=10,
            fill="#18243f",
            outline="#6ea8fe",
            width=2,
        )
        box = draw.textbbox((0, 0), label, font=font)
        width = box[2] - box[0]
        draw.text(
            ((left + right - width) / 2, 80),
            label,
            font=font,
            fill="#e8eefc",
        )
        if index < len(labels) - 1:
            draw.line((right, 89, left + 155, 89), fill="#9cbcff", width=2)
            draw.polygon(
                ((left + 155, 89), (left + 147, 84), (left + 147, 94)),
                fill="#9cbcff",
            )
    buffer = io.BytesIO()
    image.save(buffer, format="PNG", optimize=True)
    return buffer.getvalue()


def _expected_terminal_png(repository: Path) -> bytes:
    lines = (repository / "demo" / "terminal-frame.txt").read_text(encoding="utf-8").splitlines()
    image = Image.new("RGB", (1200, 800), "#090d18")
    draw = ImageDraw.Draw(image)
    font = ImageFont.load_default(size=18)
    draw.rounded_rectangle((24, 24, 1176, 776), radius=14, fill="#111827", outline="#334155", width=2)
    for index, line in enumerate(lines):
        color = "#a7f3d0" if line.startswith(("success", "passed_local")) else "#e5e7eb"
        if line.startswith(("owner_required", "not_verified", "stale")):
            color = "#fbbf24"
        if line.startswith("$"):
            color = "#93c5fd"
        draw.text((52, 48 + index * 34), line, font=font, fill=color)
    buffer = io.BytesIO()
    image.save(buffer, format="PNG", optimize=True)
    return buffer.getvalue()


def _check_media_bytes(
    name: str,
    data: bytes,
    failures: list[str],
    repository: Path | None = None,
    media_manifest: dict[str, object] | None = None,
) -> None:
    suffix = PurePosixPath(name).suffix.lower()
    if name in STORE_ICON_SHAPES:
        try:
            with Image.open(io.BytesIO(data)) as image:
                image.load()
                if (
                    image.format != "PNG"
                    or image.mode != "RGBA"
                    or image.size != STORE_ICON_SHAPES[name]
                ):
                    failures.append(f"SOS_PUBLIC_STORE_ICON_SHAPE_INVALID:{name}")
                if image.info or len(image.getexif()) != 0:
                    failures.append(f"SOS_PUBLIC_MEDIA_METADATA_FORBIDDEN:{name}")
        except (OSError, ValueError):
            failures.append(f"SOS_PUBLIC_MEDIA_PARSE_FAILED:{name}")
        return
    raw_text = data.decode("latin-1", errors="ignore")
    for pattern in FORBIDDEN_TEXT:
        if pattern.search(raw_text):
            failures.append(f"SOS_PUBLIC_MEDIA_METADATA_FORBIDDEN:{name}")
            return
    if name == "demo/recovery-loop.png":
        try:
            with Image.open(io.BytesIO(data)) as image:
                image.load()
                if image.format != "PNG" or image.mode != "RGB" or image.size != (1120, 180):
                    failures.append(f"SOS_PUBLIC_MEDIA_SHAPE_INVALID:{name}")
                if image.info or len(image.getexif()) != 0:
                    failures.append(f"SOS_PUBLIC_MEDIA_METADATA_FORBIDDEN:{name}")
        except (OSError, ValueError):
            failures.append(f"SOS_PUBLIC_MEDIA_PARSE_FAILED:{name}")
            return
        if data != _expected_demo_png():
            failures.append(f"SOS_PUBLIC_MEDIA_RENDERED_TEXT_UNVERIFIED:{name}")
        return
    if name == "demo/recovery-terminal.png" and repository is not None:
        try:
            with Image.open(io.BytesIO(data)) as image:
                image.load()
                if image.format != "PNG" or image.mode != "RGB" or image.size != (1200, 800):
                    failures.append(f"SOS_PUBLIC_MEDIA_SHAPE_INVALID:{name}")
                if image.info or len(image.getexif()) != 0:
                    failures.append(f"SOS_PUBLIC_MEDIA_METADATA_FORBIDDEN:{name}")
        except (OSError, ValueError):
            failures.append(f"SOS_PUBLIC_MEDIA_PARSE_FAILED:{name}")
            return
        if data != _expected_terminal_png(repository):
            failures.append(f"SOS_PUBLIC_MEDIA_RENDERED_TEXT_UNVERIFIED:{name}")
        return
    if suffix in {".mp4", ".webm"}:
        if media_manifest is None:
            failures.append(f"SOS_PUBLIC_MEDIA_MANIFEST_MISSING:{name}")
            return
        media_entries = media_manifest.get("media", {})
        entry = media_entries.get(PurePosixPath(name).name) if isinstance(media_entries, dict) else None
        expected_container = suffix.lstrip(".")
        expected_codec = "h264" if suffix == ".mp4" else "vp9"
        if not isinstance(entry, dict):
            failures.append(f"SOS_PUBLIC_MEDIA_MANIFEST_ENTRY_INVALID:{name}")
            return
        observed = hashlib.sha256(data).hexdigest()
        if (
            entry.get("sha256") != observed
            or entry.get("size") != len(data)
            or entry.get("container") != expected_container
            or entry.get("codec") != expected_codec
        ):
            failures.append(f"SOS_PUBLIC_MEDIA_MANIFEST_MISMATCH:{name}")
        return
    if name == "demo/voiceover.mp3":
        if media_manifest is None:
            failures.append(f"SOS_PUBLIC_MEDIA_MANIFEST_MISSING:{name}")
            return
        voiceover = media_manifest.get("voiceover")
        if not isinstance(voiceover, dict):
            failures.append(f"SOS_PUBLIC_MEDIA_MANIFEST_ENTRY_INVALID:{name}")
            return
        if voiceover.get("sha256") != hashlib.sha256(data).hexdigest() or voiceover.get("size") != len(data):
            failures.append(f"SOS_PUBLIC_MEDIA_MANIFEST_MISMATCH:{name}")
        return
    if suffix in MEDIA_SUFFIXES:
        failures.append(f"SOS_PUBLIC_MEDIA_TEXT_EXTRACTION_UNAVAILABLE:{name}")


def inspect(repository: Path) -> dict[str, object]:
    repository = repository.resolve(strict=True)
    files = _inventory(repository)
    failures: list[str] = []
    history_commit_count, history_bytes_scanned = _check_git_history(repository, failures)
    media_manifest: dict[str, object] | None = None
    try:
        value = json.loads((repository / "demo" / "media-manifest.json").read_text(encoding="utf-8"))
        if (
            not isinstance(value, dict)
            or value.get("contract") != "sos_demo_media_manifest_v2"
            or value.get("synthetic_repository") is not True
            or value.get("provider_calls") != 2
            or value.get("fresh_codex_provider_calls") != 1
            or value.get("duration_seconds") not in range(60, 121)
            or value.get("fresh_codex_receipt_sha256") != hashlib.sha256((repository / "demo" / "fresh-codex-receipt.json").read_bytes()).hexdigest()
            or value.get("terminal_frame_sha256") != hashlib.sha256((repository / "demo" / "terminal-frame.txt").read_bytes()).hexdigest()
            or value.get("transcript_sha256") != hashlib.sha256((repository / "demo" / "transcript.md").read_bytes()).hexdigest()
            or not isinstance(value.get("voiceover"), dict)
            or value["voiceover"].get("provider_calls") != 1
            or value["voiceover"].get("model") != "gpt-4o-mini-tts-2025-12-15"
            or value["voiceover"].get("voice") != "marin"
            or value["voiceover"].get("text_sha256") != hashlib.sha256((repository / "demo" / "voiceover.txt").read_bytes()).hexdigest()
        ):
            failures.append("SOS_PUBLIC_MEDIA_MANIFEST_INVALID")
        else:
            media_manifest = value
    except (OSError, UnicodeError, json.JSONDecodeError):
        failures.append("SOS_PUBLIC_MEDIA_MANIFEST_INVALID")
    try:
        receipt = json.loads((repository / "demo" / "fresh-codex-receipt.json").read_text(encoding="utf-8"))
        if (
            receipt.get("contract") != "sos_fresh_codex_capture_receipt_v1"
            or receipt.get("status") != "passed"
            or receipt.get("provider_calls") != 1
            or receipt.get("shell_calls") != 0
            or receipt.get("mutation_tool_calls") != 0
            or receipt.get("raw_prompt_stored") is not False
            or receipt.get("raw_response_stored") is not False
            or receipt.get("raw_tool_results_stored") is not False
        ):
            failures.append("SOS_PUBLIC_FRESH_CODEX_RECEIPT_INVALID")
    except (OSError, UnicodeError, json.JSONDecodeError, AttributeError):
        failures.append("SOS_PUBLIC_FRESH_CODEX_RECEIPT_INVALID")
        receipt = None
    if media_manifest is not None and isinstance(receipt, dict):
        if any(
            media_manifest.get(field) != receipt.get(field)
            for field in ("candidate", "tree", "wheel_sha256")
        ):
            failures.append("SOS_PUBLIC_MEDIA_RECEIPT_BINDING_INVALID")
    if len(files) > MAX_FILES:
        failures.append("SOS_PUBLIC_FILE_LIMIT_EXCEEDED")
    missing = sorted(REQUIRED_FILES.difference(files))
    if missing:
        failures.append("SOS_PUBLIC_REQUIRED_FILE_MISSING")
    for name in files[: MAX_FILES + 1]:
        path_name = PurePosixPath(name)
        if path_name.is_absolute() or ".." in path_name.parts or FORBIDDEN_PARTS.intersection(path_name.parts):
            failures.append(f"SOS_PUBLIC_PATH_FORBIDDEN:{name}")
            continue
        path = repository / name
        if path.is_symlink() or not path.is_file():
            failures.append(f"SOS_PUBLIC_FILE_TYPE_FORBIDDEN:{name}")
            continue
        data = path.read_bytes()
        if len(data) > MAX_FILE_BYTES:
            failures.append(f"SOS_PUBLIC_FILE_TOO_LARGE:{name}")
            continue
        if path.suffix.lower() in MEDIA_SUFFIXES:
            _check_media_bytes(name, data, failures, repository, media_manifest)
        if b"\0" in data:
            continue
        try:
            text = data.decode("utf-8")
        except UnicodeDecodeError:
            failures.append(f"SOS_PUBLIC_TEXT_ENCODING_INVALID:{name}")
            continue
        for pattern in FORBIDDEN_TEXT:
            if pattern.search(text):
                failures.append(f"SOS_PUBLIC_CONTENT_FORBIDDEN:{name}")
                break
    try:
        _check_markdown_links(repository, files, failures)
        _check_issue_forms(repository, failures)
    except (OSError, TypeError, UnicodeError, yaml.YAMLError):
        failures.append("SOS_PUBLIC_COMMUNITY_SURFACE_INVALID")
    return {
        "contract": "sos_public_release_scan_v2",
        "file_count": len(files),
        "history_bytes_scanned": history_bytes_scanned,
        "history_commit_count": history_commit_count,
        "failures": sorted(set(failures)),
        "status": "passed" if not failures else "failed",
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repository", type=Path, default=Path.cwd())
    arguments = parser.parse_args(argv)
    try:
        result = inspect(arguments.repository)
    except (OSError, subprocess.CalledProcessError, UnicodeError) as error:
        result = {
            "contract": "sos_public_release_scan_v1",
            "failures": ["SOS_PUBLIC_SCAN_FAILED"],
            "message": str(error),
            "status": "failed",
        }
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0 if result["status"] == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
