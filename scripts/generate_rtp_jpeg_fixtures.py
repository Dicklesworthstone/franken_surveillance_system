#!/usr/bin/env python3
"""OFFLINE LAB ONLY: RFC 2435-compatible JPEG encodes and independent pixel oracles.

An explicit --lab-authority label is required. Pillow/libjpeg and FFmpeg do not
participate in production or ordinary Rust tests. The JPEGs deliberately use standard
Huffman tables, whole-frame 4:2:2/4:2:0, and dimensions representable in RTP/JPEG.
"""
import argparse
import hashlib
import io
import json
from pathlib import Path
import subprocess

from PIL import Image, features


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--lab-authority", required=True)
    parser.add_argument("--output", type=Path, default=Path(__file__).resolve().parents[1]
                        / "crates/fss-codec-mjpeg/tests/fixtures/rtp_jpeg")
    args = parser.parse_args()
    if not args.lab_authority.strip():
        parser.error("a nonempty laboratory authority label is required")
    if Image.__version__ != "12.3.0":
        raise RuntimeError("reproduction requires Pillow 12.3.0")
    args.output.mkdir(parents=True, exist_ok=True)
    cases = []
    for sampling, width, height, quality, restart in [
        (1, 32, 24, 50, 0), (2, 32, 24, 75, 0), (2, 40, 32, 31, 2),
        (1, 40, 24, 80, 1), (2, 24, 16, 99, 0), (1, 16, 16, 1, 0),
    ]:
        pixels = bytearray()
        for y in range(height):
            for x in range(width):
                pixels.extend(((x * 17 + y * 11 + x * y % 41) % 256,
                               (x * 3 + y * 29 + (x ^ y) * 7) % 256,
                               (x * 31 + y * 5 + x * y % 67) % 256))
        image = Image.frombytes("RGB", (width, height), bytes(pixels))
        buffer = io.BytesIO()
        image.save(buffer, format="JPEG", quality=quality, optimize=False,
                   progressive=False, subsampling=sampling, restart_marker_blocks=restart)
        data = buffer.getvalue()
        name = f'{"422" if sampling == 1 else "420"}_{width}x{height}_q{quality}_rst{restart}'
        source = args.output / (name + ".jpg")
        source.write_bytes(data)
        decoded = subprocess.run(
            ["ffmpeg", "-v", "error", "-threads", "1", "-i", str(source),
             "-f", "rawvideo", "-pix_fmt", "yuvj444p", "-threads", "1", "pipe:1"],
            check=True, capture_output=True).stdout
        assert len(decoded) == width * height * 3
        luma = decoded[:width * height]
        luma_path = args.output / (name + ".ffmpeg.luma")
        luma_path.write_bytes(luma)
        restarts = sum(data.count(bytes([255, n])) for n in range(208, 216))
        assert bool(restarts) == bool(restart)
        cases.append({"name": name, "width": width, "height": height, "quality": quality,
                      "rtp_type": (0 if sampling == 1 else 1) + (64 if restart else 0),
                      "restart_interval": restart, "restart_markers": restarts,
                      "jpeg": {"file": source.name, "bytes": len(data),
                               "sha256": hashlib.sha256(data).hexdigest()},
                      "luma": {"file": luma_path.name, "bytes": len(luma),
                               "sha256": hashlib.sha256(luma).hexdigest()}})
    ffmpeg = subprocess.run(["ffmpeg", "-version"], check=True, capture_output=True,
                            text=True).stdout.splitlines()[0]
    manifest = {"schema": "fss.rtp_jpeg_lab_fixture.v1", "pillow": Image.__version__,
                "libjpeg": features.version_codec("jpg"), "ffmpeg": ffmpeg,
                "source_pattern": "deterministic synthetic RGB; no private camera footage",
                "cases": cases}
    (args.output / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
    print(json.dumps({"cases": len(cases), "output": str(args.output), "ffmpeg": ffmpeg}))


if __name__ == "__main__":
    main()
