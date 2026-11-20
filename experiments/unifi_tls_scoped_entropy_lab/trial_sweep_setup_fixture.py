#!/usr/bin/env python3
"""Run actual synthetic setup after discovery on the final page of a /24."""
import os
from pathlib import Path
import subprocess
import sys

from trial_pin_discovery_fixture import certificate
from trial_profile_fixture import archive_media, run


def flv_tag(timestamp, payload, kind=9):
    size = len(payload)
    header = bytes([kind]) + size.to_bytes(3, "big") + (timestamp & 0xffffff).to_bytes(3, "big") + bytes([timestamp >> 24]) + b"\0\0\0"
    return header + payload + (11 + size).to_bytes(4, "big")


def main():
    if len(sys.argv) != 4:
        raise SystemExit("expected trial binary, fresh private root, and synthetic AVC")
    binary = str(Path(sys.argv[1]).resolve(strict=True))
    root = Path(sys.argv[2])
    if not root.is_absolute() or not root.is_dir() or root.stat().st_mode & 0o077:
        raise SystemExit("expected private root")
    (root / "camera-fence").mkdir(mode=0o700)
    cert = certificate(root, "camera")
    key = root / "controller-key.der"
    subprocess.run(["openssl", "pkcs8", "-topk8", "-nocrypt", "-in", str(cert[1]),
                    "-outform", "der", "-out", str(key)], check=True)
    os.chmod(key, 0o600)
    profiles = {"video1": {"width": 2688, "height": 1512, "fps": 30}}
    media = archive_media(sys.argv[3], flv_tag)
    run(binary, "10.252.15.1", root, (*cert, key), "auto-handoff-sweep",
        profiles, "video1", media=media, archive="video", auto_pin=True,
        expect_auto_inband=True, min_archive_frames=2, sweep_peer="10.252.15.254")
    print("sweep_setup_fixture setup_controller_archive=pass camera=synthetic")


if __name__ == "__main__":
    main()
