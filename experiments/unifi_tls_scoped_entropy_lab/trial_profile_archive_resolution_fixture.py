#!/usr/bin/env python3
"""Check selected-profile admission through the synthetic managed archive.

Run only in an isolated network namespace with an existing private directory,
disposable certificates and synthetic media. No fixture files are removed.
"""

import ipaddress
import os
from pathlib import Path
import sys

from trial_live_media_probe import flv_tag
from trial_profile_fixture import archive_media, run


def main():
    if len(sys.argv) != 6:
        raise SystemExit("usage: BINARY PRIVATE_IP PRIVATE_DIR CERT_DIR SUPPORT_DIR")
    binary, address, root, cert_dir, support = sys.argv[1:]
    ip = ipaddress.IPv4Address(address)
    root, cert_dir, support = map(Path, (root, cert_dir, support))
    if ip.is_loopback or not ip.is_private or not root.is_absolute() or not root.is_dir() or root.stat().st_mode & 0o077:
        raise ValueError("expected isolated private address and private directory")
    certs = tuple(cert_dir / name for name in ("cert.pem", "key.pem", "cert.der", "key.der"))
    profiles = {
        "video1": {"width": 2688, "height": 1512, "fps": 30},
        "video2": {"width": 1280, "height": 720, "fps": 30},
        "video3": {"width": 640, "height": 360, "fps": 15},
    }
    high = archive_media(support / "synthetic_g4_resolution.264", flv_tag)
    low = archive_media(support / "baseline.264", flv_tag)
    run(binary, address, root, certs, "resolution-archive-matching", profiles,
        "video1", media=high, archive="video", wait_seconds=90, min_archive_frames=2)
    for name in ("resolution-archive-first-mismatch", "resolution-archive-reconnect-mismatch"):
        run(binary, address, root, certs, name, profiles, "video1", media=low,
            archive="video", wait_seconds=90,
            expect_media_refusal=b"trial_owned_media_error stage=recording reason=DimensionsMismatch")
    print("profile_archive_resolution_fixture passed=3 source=synthetic live_camera=not_contacted")


if __name__ == "__main__":
    os.umask(0o077)
    main()
