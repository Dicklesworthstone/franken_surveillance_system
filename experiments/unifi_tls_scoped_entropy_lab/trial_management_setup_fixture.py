#!/usr/bin/env python3
"""Test opt-in management through TLS, WebSocket and synthetic full-res media.

Run only in an isolated network namespace with 10.198.0.1 assigned to loopback.
All credentials, certificates, and media in this fixture are synthetic.
"""
import os
from pathlib import Path
import subprocess
import sys

from trial_pin_discovery_fixture import certificate
from trial_profile_fixture import archive_media, run


def main():
    if len(sys.argv) != 5:
        raise SystemExit("usage: trial_management_setup_fixture.py BINARY NEW_ABSOLUTE_DIR MEDIA_HELPERS SYNTHETIC_AVC")
    binary = str(Path(sys.argv[1]).resolve(strict=True))
    root = Path(sys.argv[2])
    if not root.is_absolute() or root.exists():
        raise ValueError("fixture directory must be absent and absolute")
    root.mkdir(mode=0o700)
    cert = certificate(root, "synthetic-camera")
    key = root / "controller-key.der"
    subprocess.run(["openssl", "pkcs8", "-topk8", "-nocrypt", "-in", str(cert[1]), "-outform", "der", "-out", str(key)], check=True)
    os.chmod(key, 0o600)
    sys.path.insert(0, str(Path(sys.argv[3]).resolve(strict=True)))
    from media_before_reply_fixture import flv_tag
    media = archive_media(sys.argv[4], flv_tag)
    profiles = {"video1": {"width": 2688, "height": 1512, "fps": 30},
                "video2": {"width": 1280, "height": 720, "fps": 30}}
    for name, mode in (("matching", "matching"), ("mismatched", "mismatched")):
        case_root = root / name
        case_root.mkdir(mode=0o700)
        (case_root / "camera-fence").mkdir(mode=0o700)
        run(binary, "10.198.0.1", case_root, (cert[0], cert[1], cert[2], key),
            f"auto-handoff-management-{name}", profiles, "video1", auto_pin=True,
            media=media if mode == "matching" else None,
            archive="video" if mode == "matching" else False,
            expect_auto_inband=mode == "matching", management=mode)
    print("management_setup_fixture passed=2 media=synthetic identity=unverified", flush=True)


if __name__ == "__main__":
    main()
