#!/usr/bin/env python3
"""Exercise optional stream-name selection with synthetic cameras and media.

Run in an isolated network namespace with an existing private directory and
disposable test certificates. No fixture file is removed.
"""

import ipaddress
import os
from pathlib import Path
import sys

from trial_live_media_probe import flv_tag
from trial_profile_fixture import archive_media, run


def metadata(name):
    encoded = name.encode("ascii")
    if len(encoded) != 16:
        raise ValueError("synthetic stream name must be 16 bytes")
    payload = b"\x02\x00\x06event1\x03\x00\x0astreamName\x02\x00\x10" + encoded + b"\x00\x00\x09"
    tag = bytearray(flv_tag(0, payload))
    tag[0] = 18
    return bytes(tag)


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
    def matching_media(source):
        return lambda claim: source[:13] + metadata(claim) + source[13:]

    def wrong_name(claim):
        other = ("0" if claim[0] != "0" else "1") + claim[1:]
        return high[:13] + metadata(other)

    names = []
    for name, first in (("name-matching", None),
                        ("name-wrong-first", wrong_name),
                        ("name-missing-first", high[:13])):
        names.append(run(binary, address, root, certs, name, profiles, "video1", media=matching_media(high),
                         wait_seconds=90, min_frames=2, stream_name_event="event1", first_candidate=first))
    run(binary, address, root, certs, "resolution-name-mismatch", profiles, "video1",
        media=matching_media(low), wait_seconds=90, stream_name_event="event1",
        expect_media_refusal=b"trial_stage=media_dimension_mismatch")
    if len(set(names)) != len(names):
        raise ValueError("independent trials reused their requested name")
    print("stream_name_fixture passed=4 source=synthetic identity=unverified live_camera=not_contacted")


if __name__ == "__main__":
    os.umask(0o077)
    main()
