#!/usr/bin/env python3
"""Compare bounded Rust decode with a local FFmpeg oracle; no camera I/O.

Both decoders read one operator-authorized, pre-existing MP4. Media stays on
this host; raw oracle frames pass through a bounded pipe and are never saved.
This laboratory helper is not a production recorder or capture-time proof.
"""
import argparse
import hashlib
import os
from pathlib import Path
import re
import select
import stat
import subprocess
import time

MAX_SOURCE = 64 * 1024 * 1024
MAX_DIMENSION = 4096
MAX_FRAMES = 30
TIMEOUT = 120


def digest(path):
    with open(path, "rb") as source:
        return hashlib.file_digest(source, "sha256").hexdigest()


def bounded_regular(path, limit):
    if not path.is_absolute():
        raise ValueError("absolute input paths required")
    info = path.stat(follow_symlinks=False)
    if not stat.S_ISREG(info.st_mode) or not 0 < info.st_size <= limit:
        raise ValueError("input is not a bounded regular file")


def compare(binary, source):
    bounded_regular(binary, 256 * 1024 * 1024)
    bounded_regular(source, MAX_SOURCE)
    binary_before, source_before = digest(binary), digest(source)
    env = os.environ.copy()
    env["FSS_UNIFI_RECORDING"] = str(source)
    rust = subprocess.run(
        [str(binary), "--ignored", "--exact", "supplied_recording_decodes_with_native_pipeline", "--nocapture"],
        env=env, capture_output=True, text=True, timeout=TIMEOUT, check=False,
    )
    if rust.returncode:
        raise ValueError("native decoder refused the input")
    pattern = (r"width=(\d+) height=(\d+) frames=(\d+) samples=(\d+) first_sample=(\d+) "
               r"first_i420_sha256=([0-9a-f]{64}) frame_digest_list_sha256=sha256:([0-9a-f]{64}) "
               r"source_bytes=(\d+) source_sha256=sha256:([0-9a-f]{64})")
    found = re.search(pattern, rust.stdout)
    if not found:
        raise ValueError("native result is missing its bounded decode report")
    width, height, frames, samples, start = map(int, found.group(1, 2, 3, 4, 5))
    if (not 0 < width <= MAX_DIMENSION or not 0 < height <= MAX_DIMENSION
            or width % 2 or height % 2 or not 0 < frames <= MAX_FRAMES
            or not 0 < samples <= MAX_FRAMES or start != 0 or found.group(9) != source_before):
        raise ValueError("native result cannot be aligned or exceeds the comparison bounds")
    frame_bytes = width * height * 3 // 2
    command = ["ffmpeg", "-v", "error", "-threads", "1", "-i", str(source), "-map", "0:v:0",
               "-frames:v", str(frames), "-vsync", "0", "-pix_fmt", "yuv420p", "-f", "rawvideo", "pipe:1"]
    oracle = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
    deadline = time.monotonic() + TIMEOUT
    individual = hashlib.sha256()
    try:
        for _ in range(frames):
            frame = hashlib.sha256()
            remaining = frame_bytes
            while remaining:
                wait = deadline - time.monotonic()
                if wait <= 0 or not select.select([oracle.stdout], [], [], wait)[0]:
                    raise TimeoutError("oracle frame deadline exceeded")
                chunk = os.read(oracle.stdout.fileno(), min(remaining, 1024 * 1024))
                if not chunk:
                    raise ValueError("oracle returned a partial frame")
                frame.update(chunk)
                remaining -= len(chunk)
            individual.update(frame.digest())
        wait = deadline - time.monotonic()
        if wait <= 0 or not select.select([oracle.stdout], [], [], wait)[0]:
            raise TimeoutError("oracle completion deadline exceeded")
        if os.read(oracle.stdout.fileno(), 1):
            raise ValueError("oracle returned additional output")
        if oracle.wait(timeout=max(0.001, deadline - time.monotonic())):
            raise ValueError("oracle decode failed")
    finally:
        if oracle.poll() is None:
            oracle.kill()
            oracle.wait()
        oracle.stdout.close()
    if digest(binary) != binary_before or digest(source) != source_before:
        raise ValueError("input changed during comparison")
    if individual.hexdigest() != found.group(7):
        raise ValueError("native and independent frame digests differ")
    print(f"recorded_decode_match width={width} height={height} frames={frames} samples={samples} "
          f"source_sha256={source_before} binary_sha256={binary_before} "
          f"frame_digest_list_sha256={individual.hexdigest()} media_written=false")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", type=Path, help="built unifi_recorded_mp4_contract test executable")
    parser.add_argument("source", type=Path, help="authorized existing MP4")
    parser.add_argument("--owner-authorized", action="store_true", required=True)
    args = parser.parse_args()
    compare(args.binary, args.source)


if __name__ == "__main__":
    main()
