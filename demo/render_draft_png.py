#!/usr/bin/env python3
"""Render the deterministic public-preparation diagram PNG."""

from pathlib import Path

from PIL import Image, ImageDraw, ImageFont


OUTPUT = Path(__file__).resolve().with_name("recovery-loop.png")
LABELS = ("discover", "preview", "install", "qualify", "recover", "stale", "safe next")


def main() -> int:
    image = Image.new("RGB", (1120, 180), "#0b1020")
    draw = ImageDraw.Draw(image)
    font = ImageFont.load_default(size=16)
    for index, label in enumerate(LABELS):
        left = 20 + index * 160
        right = left + (120 if index == 6 else 130)
        draw.rounded_rectangle((left, 60, right, 118), radius=10, fill="#18243f", outline="#6ea8fe", width=2)
        box = draw.textbbox((0, 0), label, font=font)
        width = box[2] - box[0]
        draw.text(((left + right - width) / 2, 80), label, font=font, fill="#e8eefc")
        if index < len(LABELS) - 1:
            draw.line((right, 89, left + 155, 89), fill="#9cbcff", width=2)
            draw.polygon(((left + 155, 89), (left + 147, 84), (left + 147, 94)), fill="#9cbcff")
    image.save(OUTPUT, format="PNG", optimize=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
