#!/usr/bin/env python3
"""Fail-closed public repository and release-contract inspection."""

from __future__ import annotations

import argparse
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
    "README.md",
    "SECURITY.md",
    "SUPPORT.md",
    "demo/README.md",
    "demo/capture.sh",
    "demo/recovery-loop.png",
    "demo/recovery-loop.svg",
    "demo/transcript.md",
    "docs/architecture.md",
    "docs/roadmap.md",
    "docs/threat-model.md",
    "docs/troubleshooting.md",
    "examples/fresh-agent-recovery/expected.json",
    "pyproject.toml",
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
MEDIA_SUFFIXES = {".gif", ".mp4", ".png", ".webm"}
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


def _slug(value: str) -> str:
    value = value.strip().lower()
    value = re.sub(r"[^a-z0-9 _-]", "", value)
    return re.sub(r"[ _]+", "-", value).strip("-")


def _check_readme_links(repository: Path, failures: list[str]) -> None:
    readme = repository / "README.md"
    text = readme.read_text(encoding="utf-8")
    anchors = {_slug(line.lstrip("#").strip()) for line in text.splitlines() if line.startswith("#")}
    for raw in MARKDOWN_LINK.findall(text):
        target = raw.strip().split(maxsplit=1)[0].strip("<>")
        if target.startswith(("https://", "http://", "mailto:")):
            continue
        path_text, _, fragment = target.partition("#")
        target_path = readme if not path_text else repository / path_text
        if not target_path.is_file():
            failures.append(f"SOS_PUBLIC_README_LINK_BROKEN:{target}")
            continue
        if fragment and target_path == readme and _slug(fragment) not in anchors:
            failures.append(f"SOS_PUBLIC_README_ANCHOR_BROKEN:{fragment}")


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


def _check_media_bytes(name: str, data: bytes, failures: list[str]) -> None:
    suffix = PurePosixPath(name).suffix.lower()
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
    if suffix in MEDIA_SUFFIXES:
        failures.append(f"SOS_PUBLIC_MEDIA_TEXT_EXTRACTION_UNAVAILABLE:{name}")


def inspect(repository: Path) -> dict[str, object]:
    repository = repository.resolve(strict=True)
    files = _inventory(repository)
    failures: list[str] = []
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
            _check_media_bytes(name, data, failures)
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
        _check_readme_links(repository, failures)
        _check_issue_forms(repository, failures)
    except (OSError, TypeError, UnicodeError, yaml.YAMLError):
        failures.append("SOS_PUBLIC_COMMUNITY_SURFACE_INVALID")
    return {
        "contract": "sos_public_release_scan_v2",
        "file_count": len(files),
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
