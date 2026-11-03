#!/usr/bin/env python3
"""Lab-only independent radial image fixture generator; Pillow is not a product dependency.

Each source camera independently observes the same continuous textured plane at Z=10.
The renderer inverts the documented two-term normalized radial equation using a scalar
Newton solve. It does not call the Rust rectifier, its backward map, or a pose solver.
No measured calibration or retained source authority is asserted by these authored images.
"""

from hashlib import sha256
from io import BytesIO
import json
import math
from pathlib import Path

from PIL import Image, __version__ as pillow_version


WIDTH, HEIGHT = 192, 128
FX, FY, CX, CY = 160.0, 160.0, 96.0, 64.0
K1, K2 = -0.08, 0.01
QUALITY = 96


def texel(x: int, y: int) -> float:
    value = ((x & 0xFFFFFFFF) * 0x9E3779B9) & 0xFFFFFFFF
    value ^= ((y & 0xFFFFFFFF) * 0x85EBCA6B) & 0xFFFFFFFF
    value ^= 0x12345678
    value ^= value >> 16
    value = (value * 0x7FEB352D) & 0xFFFFFFFF
    value ^= value >> 15
    return float(20 + value % 216)


def texture(x: float, y: float) -> int:
    x, y = x / 2.0, y / 2.0
    ix, iy = math.floor(x), math.floor(y)
    dx, dy = x - ix, y - iy
    top = texel(ix, iy) * (1.0 - dx) + texel(ix + 1, iy) * dx
    bottom = texel(ix, iy + 1) * (1.0 - dx) + texel(ix + 1, iy + 1) * dx
    return min(255, max(0, math.floor(top * (1.0 - dy) + bottom * dy + 0.5)))


def undistorted_ray(xd: float, yd: float) -> tuple[float, float]:
    distorted_radius = math.hypot(xd, yd)
    if distorted_radius == 0.0:
        return 0.0, 0.0
    radius = distorted_radius
    for _ in range(32):
        q = radius * radius
        projected = radius * (1.0 + K1 * q + K2 * q * q)
        slope = 1.0 + 3.0 * K1 * q + 5.0 * K2 * q * q
        correction = (projected - distorted_radius) / slope
        radius -= correction
        if abs(correction) < 1e-15:
            break
    q = radius * radius
    assert abs(radius * (1.0 + K1 * q + K2 * q * q) - distorted_radius) < 1e-12
    return xd * radius / distorted_radius, yd * radius / distorted_radius


def render(center_x: float) -> bytes:
    pixels = bytearray()
    for y in range(HEIGHT):
        for x in range(WIDTH):
            rx, ry = undistorted_ray((x + 0.5 - CX) / FX, (y + 0.5 - CY) / FY)
            # Independent world-plane intersection is [center_x+10*rx, 10*ry, 10].
            pixels.append(texture(160.0 * rx + 96.0 + 16.0 * center_x, 160.0 * ry + 64.0))
    return bytes(pixels)


def main() -> None:
    folder = Path(__file__).resolve().parent
    frames = []
    for camera in range(3):
        raw = render(float(camera))
        encoded = BytesIO()
        Image.frombytes("L", (WIDTH, HEIGHT), raw).save(
            encoded,
            format="JPEG",
            quality=QUALITY,
            subsampling=0,
            optimize=False,
            progressive=False,
        )
        data = encoded.getvalue()
        name = f"camera_{camera}.jpeg.hex"
        hexadecimal = data.hex()
        (folder / name).write_text(
            "\n".join(hexadecimal[i : i + 128] for i in range(0, len(hexadecimal), 128)) + "\n",
            encoding="ascii",
        )
        frames.append(
            {
                "file": name,
                "center": [camera, 0, 0],
                "source_plane_sha256": sha256(raw).hexdigest(),
                "jpeg_sha256": sha256(data).hexdigest(),
                "jpeg_bytes": len(data),
            }
        )
    manifest = {
        "purpose": "original synthetic native adopted-radial image/geometry oracle",
        "authority": "authored lab fixture; no measured calibration or retained custody",
        "generator": "generate.py",
        "pillow_version": pillow_version,
        "image": {"width": WIDTH, "height": HEIGHT, "fx": FX, "fy": FY, "cx": CX, "cy": CY},
        "distortion": {"model": "normalized Brown radial", "k1": K1, "k2": K2, "k3": 0, "p1": 0, "p2": 0},
        "source_and_target_grid": "same intrinsics, dimensions and optical axes",
        "plane_z": 10,
        "sampling": "pixel-edge centers; independent scalar radial inverse; bilinear two-pixel texture",
        "jpeg": {"components": "grayscale", "quality": QUALITY, "progressive": False, "optimize": False},
        "frames": frames,
    }
    (folder / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
