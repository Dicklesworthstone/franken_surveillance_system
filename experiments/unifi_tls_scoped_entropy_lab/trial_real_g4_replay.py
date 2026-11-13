#!/usr/bin/env python3
"""Replay an owner-selected saved G4 clip through an isolated fake camera.

Run only in an isolated network namespace configured with 10.198.0.1/24.
Usage: trial_real_g4_replay.py BINARY SAVED_MP4 EXPECTED_SHA256 NEW_PRIVATE_DIR
The saved clip is never modified. The output directory retains private media.
"""
import hashlib
import os
from pathlib import Path
import subprocess
import sys

from trial_pin_discovery_fixture import certificate
from trial_profile_fixture import run


def digest(path):
    value = hashlib.sha256()
    with path.open("rb") as source:
        for block in iter(lambda: source.read(1024 * 1024), b""):
            value.update(block)
    return value.hexdigest()


def real_media(path):
    result = subprocess.run(["ffmpeg", "-nostdin", "-hide_banner", "-loglevel", "error",
                             "-stream_loop", "1", "-i", str(path), "-map", "0:v:0", "-c", "copy",
                             "-fs", "8388608", "-f", "flv", "pipe:1"],
                            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=30, check=True)
    data = bytearray(result.stdout)
    if not data.startswith(b"FLV\x01") or len(data) > 8 * 1024 * 1024:
        raise ValueError("unexpected bounded FLV input")
    offset, previous, changes, videos, keyframes = 13, None, 0, 0, 0
    while offset < len(data):
        if offset + 15 > len(data):
            raise ValueError("truncated FLV header")
        size = int.from_bytes(data[offset + 1:offset + 4], "big")
        end = offset + 11 + size
        if end + 4 > len(data) or int.from_bytes(data[end:end + 4], "big") != 11 + size:
            raise ValueError("invalid FLV tag length")
        body = data[offset + 11:end]
        if data[offset] == 9 and len(body) >= 5 and body[1] == 1:
            timestamp = int.from_bytes(data[offset + 4:offset + 7], "big") | data[offset + 7] << 24
            if previous is not None and timestamp == previous:
                timestamp += 1
                data[offset + 4:offset + 7] = (timestamp & 0xffffff).to_bytes(3, "big")
                data[offset + 7] = timestamp >> 24
                changes += 1
            if previous is not None and timestamp <= previous:
                raise ValueError("nonmonotone FLV timestamp")
            previous = timestamp
            videos += 1
            cursor, idr = 5, False
            while cursor < len(body):
                if cursor + 4 > len(body):
                    raise ValueError("invalid NAL header")
                length = int.from_bytes(body[cursor:cursor + 4], "big")
                cursor += 4
                if not length or cursor + length > len(body):
                    raise ValueError("invalid NAL length")
                idr |= body[cursor] & 31 == 5
                cursor += length
            keyframes += int(idr)
        offset = end + 4
    if (changes, videos, keyframes) != (2, 302, 4):
        raise ValueError("unexpected source frame structure")
    return bytes(data)


def main():
    if len(sys.argv) != 5:
        raise SystemExit(__doc__)
    binary = Path(sys.argv[1]).resolve(strict=True)
    source = Path(sys.argv[2]).resolve(strict=True)
    expected = sys.argv[3]
    root = Path(sys.argv[4])
    if len(expected) != 64 or any(c not in "0123456789abcdef" for c in expected):
        raise SystemExit("expected lowercase SHA-256")
    if not root.is_absolute() or root.exists():
        raise SystemExit("output directory must be absent and absolute")
    if digest(source) != expected:
        raise SystemExit("saved clip hash mismatch")
    binary_hash = digest(binary)
    data = real_media(source)
    root.mkdir(mode=0o700)
    (root / "camera-fence").mkdir(mode=0o700)
    cert = certificate(root, "synthetic-peer")
    key = root / "synthetic-key.der"
    subprocess.run(["openssl", "pkcs8", "-topk8", "-nocrypt", "-in", str(cert[1]),
                    "-outform", "der", "-out", str(key)], check=True)
    os.chmod(key, 0o600)
    profiles = {"video1": {"width": 2688, "height": 1512, "fps": 30},
                "video2": {"width": 1280, "height": 720, "fps": 30}}
    run(str(binary), "10.198.0.1", root, (cert[0], cert[1], cert[2], key),
        "auto-handoff-real-media", profiles, "video1", media=data,
        archive="video", auto_pin=True, wait_seconds=90, expect_auto_inband=True)
    if digest(source) != expected or digest(binary) != binary_hash:
        raise ValueError("source or executable changed")
    print("real_g4_replay=pass source=prior_scrypted_capture controller=simulated "
          "copies=2 timestamp_corrections=2 media_input=in_memory source_and_binary_unchanged=true", flush=True)


if __name__ == "__main__":
    main()
