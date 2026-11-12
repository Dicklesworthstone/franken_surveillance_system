#!/usr/bin/env python3
"""Benchmark and check a private FSS MP4 decode locally; never print media.

FFmpeg is a comparison oracle for this laboratory command, not a dependency of
the Rust decoder. Run only on the machine authorized to read the supplied
clip. Measurements include process startup, input, demux, and full decoding.
"""

import argparse
import hashlib
import json
import re
import statistics
import subprocess
import time
from fractions import Fraction
from pathlib import Path


def run(command, *, source=None):
    result = subprocess.run(
        command, stdin=source, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        timeout=300, check=False,
    )
    if result.returncode:
        raise RuntimeError(f"{Path(command[0]).name} failed (exit {result.returncode})")
    return result.stdout.decode("ascii")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("binary", type=Path)
    parser.add_argument("clip", type=Path)
    parser.add_argument("--repetitions", type=int, default=2, choices=range(1, 6))
    args = parser.parse_args()

    probe = json.loads(run([
        "ffprobe", "-v", "error", "-select_streams", "v:0", "-show_entries",
        "stream=width,height,avg_frame_rate:format=duration", "-of", "json", str(args.clip),
    ]))
    stream = probe["streams"][0]
    duration = float(probe["format"]["duration"])
    fps = float(Fraction(stream["avg_frame_rate"]))
    if duration <= 0 or fps <= 0:
        raise RuntimeError("invalid input duration or frame rate")

    timings = []
    summary = None
    for _ in range(args.repetitions):
        with args.clip.open("rb") as source:
            start = time.monotonic()
            report = run([str(args.binary), "--owner-authorized"], source=source)
            timings.append(time.monotonic() - start)
        lines = report.splitlines()
        if len(lines) != 1 or not lines[0].startswith("private_mp4_decode=ok "):
            raise RuntimeError("invalid Rust decode report")
        if summary is not None and summary != lines[0]:
            raise RuntimeError("Rust decode reports differed across repetitions")
        summary = lines[0]
    fields = dict(field.split("=", 1) for field in summary.split())
    frames = int(fields["frames"])
    if frames <= 0 or int(fields["width"]) != stream["width"] or int(fields["height"]) != stream["height"]:
        raise RuntimeError("Rust decode count or dimensions disagree with input")

    with args.clip.open("rb") as source:
        report = run([str(args.binary), "--owner-authorized", "--frame-hashes"], source=source)
    rust_hashes = [line.removeprefix("frame_sha256=") for line in report.splitlines()
                   if line.startswith("frame_sha256=")]
    oracle = run([
        "ffmpeg", "-v", "error", "-i", str(args.clip), "-map", "0:v:0", "-fps_mode",
        "passthrough", "-c:v", "rawvideo", "-threads", "1", "-pix_fmt", "yuvj420p",
        "-f", "framehash", "-hash", "sha256", "-",
    ])
    oracle_hashes = [line.rsplit(",", 1)[-1].strip() for line in oracle.splitlines()
                     if line and not line.startswith("#")]
    if len(rust_hashes) != frames or not all(re.fullmatch(r"[0-9a-f]{64}", h) for h in rust_hashes):
        raise RuntimeError("invalid Rust frame hashes")
    matches = sum(a == b for a, b in zip(rust_hashes, oracle_hashes))
    equal = rust_hashes == oracle_hashes
    with args.binary.open("rb") as executable:
        binary_hash = hashlib.file_digest(executable, "sha256").hexdigest()
    median = statistics.median(timings)
    print(f"binary_sha256={binary_hash} dimensions={stream['width']}x{stream['height']} "
          f"frames={frames} clip_seconds={duration:.3f} source_fps={fps:.3f}")
    print(f"decode_repetitions={len(timings)} wall_seconds=" + ",".join(f"{t:.3f}" for t in timings)
          + f" median_fps={frames / median:.3f} median_realtime_ratio={duration / median:.3f}")
    print(f"frame_comparison={'passed' if equal else 'diverged'} "
          f"rust_frames={len(rust_hashes)} oracle_frames={len(oracle_hashes)} matching_positions={matches}")
    if not equal:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
