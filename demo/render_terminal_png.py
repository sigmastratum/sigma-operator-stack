#!/usr/bin/env python3
"""Render the canonical synthetic terminal frame without host-local data."""

from pathlib import Path

from PIL import Image, ImageDraw, ImageFont


ROOT = Path(__file__).resolve().parent
SOURCE = ROOT / "terminal-frame.txt"
OUTPUT = ROOT / "recovery-terminal.png"


def main() -> int:
    lines = SOURCE.read_text(encoding="utf-8").splitlines()
    image = Image.new("RGB", (1200, 650), "#090d18")
    draw = ImageDraw.Draw(image)
    font = ImageFont.load_default(size=18)
    draw.rounded_rectangle((24, 24, 1176, 626), radius=14, fill="#111827", outline="#334155", width=2)
    for index, line in enumerate(lines):
        color = "#a7f3d0" if line.startswith(("success", "passed_local")) else "#e5e7eb"
        if line.startswith(("owner_required", "not_verified", "stale")):
            color = "#fbbf24"
        if line.startswith("$"):
            color = "#93c5fd"
        draw.text((52, 48 + index * 34), line, font=font, fill=color)
    image.save(OUTPUT, format="PNG", optimize=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
