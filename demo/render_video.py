#!/usr/bin/env python3
"""Render bounded zero-provider demo media from the canonical terminal frame."""

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import tempfile
from pathlib import Path

from PIL import Image, ImageDraw, ImageFont


ROOT = Path(__file__).resolve().parent
SOURCE = ROOT / "terminal-frame.txt"
TRANSCRIPT = ROOT / "transcript.md"
CAPTURE_RECEIPT = ROOT / "fresh-codex-receipt.json"
MAX_MEDIA_BYTES = 2 * 1024 * 1024


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def render_frame(lines: list[str], path: Path) -> None:
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
    image.save(path, format="PNG", optimize=True)


def run(ffmpeg: Path, argv: list[str]) -> None:
    subprocess.run(
        [str(ffmpeg), "-hide_banner", "-loglevel", "error", "-nostdin", "-y", *argv],
        check=True,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=120,
    )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--ffmpeg", required=True, type=Path)
    args = parser.parse_args()
    ffmpeg = args.ffmpeg.resolve(strict=True)
    if not ffmpeg.is_file():
        raise SystemExit("SOS_DEMO_FFMPEG_INVALID")

    lines = SOURCE.read_text(encoding="utf-8").splitlines()
    boundaries = (2, 4, 6, 8, 10, 14, 18, len(lines))
    with tempfile.TemporaryDirectory(prefix="sos-demo-media-") as temporary:
        frame_root = Path(temporary)
        for index, boundary in enumerate(boundaries):
            render_frame(lines[:boundary], frame_root / f"frame-{index:02d}.png")
        common = [
            "-framerate", "1/10", "-i", str(frame_root / "frame-%02d.png"),
            "-an", "-map_metadata", "-1", "-metadata", "title=",
            "-metadata", "comment=", "-vf", "fps=25,format=yuv420p",
        ]
        run(ffmpeg, [*common, "-c:v", "libx264", "-preset", "veryslow", "-crf", "31", "-movflags", "+faststart", str(ROOT / "recovery-demo.mp4")])
        run(ffmpeg, [*common, "-c:v", "libvpx-vp9", "-b:v", "0", "-crf", "39", "-threads", "1", str(ROOT / "recovery-demo.webm")])

    media = {}
    for name, container, codec in (
        ("recovery-demo.mp4", "mp4", "h264"),
        ("recovery-demo.webm", "webm", "vp9"),
    ):
        path = ROOT / name
        if path.stat().st_size >= MAX_MEDIA_BYTES:
            raise SystemExit("SOS_DEMO_MEDIA_LIMIT_EXCEEDED")
        media[name] = {"codec": codec, "container": container, "sha256": digest(path), "size": path.stat().st_size}
    receipt = json.loads(CAPTURE_RECEIPT.read_text(encoding="utf-8"))
    if receipt.get("contract") != "sos_fresh_codex_capture_receipt_v1" or receipt.get("status") != "passed":
        raise SystemExit("SOS_DEMO_CAPTURE_RECEIPT_INVALID")
    manifest = {
        "candidate": receipt["candidate"],
        "contract": "sos_demo_media_manifest_v2",
        "duration_seconds": len(boundaries) * 10,
        "fresh_codex_receipt_sha256": digest(CAPTURE_RECEIPT),
        "media": media,
        "provider_calls": receipt["provider_calls"],
        "synthetic_repository": True,
        "terminal_frame_sha256": digest(SOURCE),
        "transcript_sha256": digest(TRANSCRIPT),
        "tree": receipt["tree"],
        "wheel_sha256": receipt["wheel_sha256"],
    }
    (ROOT / "media-manifest.json").write_text(json.dumps(manifest, sort_keys=True, separators=(",", ":")) + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
