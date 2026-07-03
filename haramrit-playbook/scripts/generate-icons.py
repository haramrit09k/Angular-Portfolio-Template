#!/usr/bin/env python3
"""Generate PWA icons for Compass using only the Python standard library.

No PIL/ImageMagick dependency: this hand-writes raw PNG bytes (zlib + struct +
binascii) and draws a simple geometric compass mark (ring + two-tone needle)
in the app's accent color. One-off script — re-run only if the mark or the
--bg/--accent colors change.

Usage: python3 scripts/generate-icons.py
"""

import struct
import zlib
import binascii
import os

BG = (0x0F, 0x17, 0x2A)       # --bg
ACCENT = (0x38, 0xBD, 0xF8)   # --accent
ACCENT_DIM = (0x9C, 0xA3, 0xAF)  # --muted, used for the needle's south half

OUT_DIR = os.path.join(os.path.dirname(__file__), "..", "icons")


def smoothstep(edge0, edge1, x):
    if edge1 == edge0:
        return 1.0 if x >= edge1 else 0.0
    t = max(0.0, min(1.0, (x - edge0) / (edge1 - edge0)))
    return t * t * (3.0 - 2.0 * t)


def circle_coverage(dist, radius, feather):
    # 1.0 fully inside, 0.0 fully outside, soft edge across `feather` px
    return smoothstep(radius + feather / 2, radius - feather / 2, dist)


def point_in_triangle(px, py, ax, ay, bx, by, cx, cy):
    def sign(x1, y1, x2, y2, x3, y3):
        return (x1 - x3) * (y2 - y3) - (x2 - x3) * (y1 - y3)

    d1 = sign(px, py, ax, ay, bx, by)
    d2 = sign(px, py, bx, by, cx, cy)
    d3 = sign(px, py, cx, cy, ax, ay)
    has_neg = (d1 < 0) or (d2 < 0) or (d3 < 0)
    has_pos = (d1 > 0) or (d2 > 0) or (d3 > 0)
    return not (has_neg and has_pos)


def blend(base, color, alpha):
    return tuple(round(base[i] * (1 - alpha) + color[i] * alpha) for i in range(3))


def render(size):
    cx = cy = size / 2.0
    ring_outer = size * 0.40
    ring_inner = size * 0.34
    feather = max(1.0, size * 0.01)

    needle_top = (cx, cy - size * 0.28)
    needle_bottom = (cx, cy + size * 0.28)
    needle_left = (cx - size * 0.085, cy)
    needle_right = (cx + size * 0.085, cy)

    hub_radius = size * 0.035

    pixels = bytearray()
    for y in range(size):
        for x in range(size):
            px, py = x + 0.5, y + 0.5
            color = BG

            dist = ((px - cx) ** 2 + (py - cy) ** 2) ** 0.5
            ring_alpha = circle_coverage(dist, ring_outer, feather) - circle_coverage(dist, ring_inner, feather)
            if ring_alpha > 0:
                color = blend(color, ACCENT, min(1.0, ring_alpha))

            if point_in_triangle(px, py, *needle_top, *needle_right, *needle_left):
                color = ACCENT
            elif point_in_triangle(px, py, *needle_bottom, *needle_right, *needle_left):
                color = ACCENT_DIM

            hub_alpha = circle_coverage(dist, hub_radius, feather)
            if hub_alpha > 0:
                color = blend(color, BG, min(1.0, hub_alpha))

            pixels += bytes(color)
    return pixels


def write_png(path, size, pixel_bytes):
    def chunk(tag, data):
        return (
            struct.pack(">I", len(data))
            + tag
            + data
            + struct.pack(">I", binascii.crc32(tag + data) & 0xFFFFFFFF)
        )

    raw = bytearray()
    stride = size * 3
    for y in range(size):
        raw += b"\x00"  # filter type 0 (none) per scanline
        raw += pixel_bytes[y * stride:(y + 1) * stride]

    sig = b"\x89PNG\r\n\x1a\n"
    ihdr = struct.pack(">IIBBBBB", size, size, 8, 2, 0, 0, 0)  # 8-bit RGB
    idat = zlib.compress(bytes(raw), 9)

    with open(path, "wb") as f:
        f.write(sig)
        f.write(chunk(b"IHDR", ihdr))
        f.write(chunk(b"IDAT", idat))
        f.write(chunk(b"IEND", b""))


def write_svg(path):
    accent = "#%02x%02x%02x" % ACCENT
    accent_dim = "#%02x%02x%02x" % ACCENT_DIM
    bg = "#%02x%02x%02x" % BG
    svg = f'''<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 100 100">
  <rect width="100" height="100" fill="{bg}"/>
  <circle cx="50" cy="50" r="40" fill="none" stroke="{accent}" stroke-width="6"/>
  <polygon points="50,22 58.5,50 41.5,50" fill="{accent}"/>
  <polygon points="50,78 58.5,50 41.5,50" fill="{accent_dim}"/>
  <circle cx="50" cy="50" r="3.5" fill="{bg}"/>
</svg>
'''
    with open(path, "w") as f:
        f.write(svg)


def main():
    os.makedirs(OUT_DIR, exist_ok=True)
    targets = [("icon-192.png", 192), ("icon-512.png", 512), ("apple-touch-icon.png", 180)]
    for filename, size in targets:
        pixels = render(size)
        path = os.path.join(OUT_DIR, filename)
        write_png(path, size, pixels)
        print(f"Wrote {path} ({size}x{size})")

    svg_path = os.path.join(OUT_DIR, "icon.svg")
    write_svg(svg_path)
    print(f"Wrote {svg_path}")


if __name__ == "__main__":
    main()
