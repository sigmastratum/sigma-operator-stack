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
VOICEOVER_TEXT = ROOT / "voiceover.txt"
VOICEOVER_AUDIO = ROOT / "voiceover.mp3"
MAX_MEDIA_BYTES = 2 * 1024 * 1024
FRAME_DURATIONS = (2, 8, 8, 8, 9, 10, 10, 13)


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
        draw.text((52, 48 + index * 29), line, font=font, fill=color)
    image.save(path, format="PNG", optimize=True)


def render_hook(path: Path) -> None:
    image = Image.new("RGB", (1200, 800), "#090d18")
    draw = ImageDraw.Draw(image)
    title = ImageFont.load_default(size=42)
    body = ImageFont.load_default(size=24)
    draw.rounded_rectangle((24, 24, 1176, 776), radius=14, fill="#111827", outline="#334155", width=2)
    draw.text((70, 175), "One public link.", font=title, fill="#e5e7eb")
    draw.text((70, 245), "One visible preview.", font=title, fill="#e5e7eb")
    draw.text((70, 315), "A fresh session recovers.", font=title, fill="#a7f3d0")
    draw.text((72, 430), "SOS 0.1.0a5 · Linux", font=body, fill="#93c5fd")
    draw.text((72, 490), "Sigma Operator Stack", font=body, fill="#fbbf24")
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
    boundaries = (4, 6, 8, 10, 13, 17, len(lines))
    if not VOICEOVER_AUDIO.is_file() or VOICEOVER_AUDIO.stat().st_size >= MAX_MEDIA_BYTES:
        raise SystemExit("SOS_DEMO_VOICEOVER_INVALID")
    with tempfile.TemporaryDirectory(prefix="sos-demo-media-") as temporary:
        frame_root = Path(temporary)
        render_hook(frame_root / "frame-00.png")
        for index, boundary in enumerate(boundaries, start=1):
            render_frame(lines[:boundary], frame_root / f"frame-{index:02d}.png")
        concat = frame_root / "frames.txt"
        entries: list[str] = []
        for index, duration in enumerate(FRAME_DURATIONS):
            entries.extend((f"file 'frame-{index:02d}.png'", f"duration {duration}"))
        entries.append(f"file 'frame-{len(FRAME_DURATIONS) - 1:02d}.png'")
        concat.write_text("\n".join(entries) + "\n", encoding="utf-8")
        common = [
            "-f", "concat", "-safe", "0", "-i", str(concat),
            "-i", str(VOICEOVER_AUDIO), "-map", "0:v:0", "-map", "1:a:0",
            "-fflags", "+bitexact",
            "-map_metadata", "-1", "-metadata", "title=", "-metadata", "comment=",
            "-vf", "fps=25,format=yuv420p",
        ]
        run(ffmpeg, [*common, "-c:v", "libx264", "-preset", "veryslow", "-crf", "31", "-flags:v", "+bitexact", "-c:a", "aac", "-b:a", "96k", "-flags:a", "+bitexact", "-movflags", "+faststart", str(ROOT / "recovery-demo.mp4")])
        run(ffmpeg, [*common, "-c:v", "libvpx-vp9", "-b:v", "0", "-crf", "39", "-threads", "1", "-flags:v", "+bitexact", "-c:a", "libopus", "-b:a", "64k", "-flags:a", "+bitexact", str(ROOT / "recovery-demo.webm")])

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
    if receipt.get("contract") != "sos_url_only_codex_capture_receipt_v1" or receipt.get("status") != "passed":
        raise SystemExit("SOS_DEMO_CAPTURE_RECEIPT_INVALID")
    manifest = {
        "candidate": receipt["candidate"],
        "archive_sha256": receipt["archive_sha256"],
        "contract": "sos_demo_media_manifest_v3",
        "duration_seconds": sum(FRAME_DURATIONS),
        "fresh_codex_receipt_sha256": digest(CAPTURE_RECEIPT),
        "fresh_codex_provider_calls": receipt["provider_requests_total"],
        "index_sha256": receipt["index_sha256"],
        "inner_manifest_sha256": receipt["inner_manifest_sha256"],
        "media": media,
        "provider_calls": receipt["provider_requests_total"] + 1,
        "release_tag": receipt["release_tag"],
        "synthetic_repository": True,
        "terminal_frame_sha256": digest(SOURCE),
        "transcript_sha256": digest(TRANSCRIPT),
        "tree": receipt["tree"],
        "voiceover": {
            "model": "gpt-4o-mini-tts-2025-12-15",
            "provider_calls": 1,
            "sha256": digest(VOICEOVER_AUDIO),
            "size": VOICEOVER_AUDIO.stat().st_size,
            "text_sha256": digest(VOICEOVER_TEXT),
            "voice": "marin",
        },
        "wheel_sha256": receipt["wheel_sha256"],
    }
    (ROOT / "media-manifest.json").write_text(json.dumps(manifest, sort_keys=True, separators=(",", ":")) + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
