#!/usr/bin/env python3
"""Test the automatic setup clock policy using only an isolated synthetic peer.

Usage: trial_auto_clock_fixture.py old|new BINARY NEW_ABSOLUTE_DIR MEDIA_HELPER_DIR AVC_FILE
The caller supplies an isolated network with 10.198.0.1 assigned to loopback.
The fixture retains all generated keys, journals, and media in the new directory.
"""
import os
from pathlib import Path
import re
import subprocess
import sys

from trial_pin_discovery_fixture import certificate
from trial_profile_fixture import MAC, archive_media, run


def main():
    if len(sys.argv) != 6 or sys.argv[1] not in ("old", "new"):
        raise SystemExit(__doc__)
    mode, binary, root_name, helper, avc = sys.argv[1:]
    binary = Path(binary).resolve(strict=True)
    root = Path(root_name)
    if not root.is_absolute() or root.exists():
        raise SystemExit("fixture directory must be absent and absolute")
    root.mkdir(mode=0o700)
    pem, pem_key, cert = certificate(root, "camera")
    key = root / "camera-key.der"
    subprocess.run(["openssl", "pkcs8", "-topk8", "-nocrypt", "-in", str(pem_key),
                    "-outform", "der", "-out", str(key)], check=True,
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    os.chmod(key, 0o600)
    profiles = {"video1": {"width": 2688, "height": 1512, "fps": 30},
                "video2": {"width": 1280, "height": 720, "fps": 30}}
    certs = (pem, pem_key, cert, key)
    if mode == "old":
        (root / "camera-fence").mkdir(mode=0o700)
        run(str(binary), "10.198.0.1", root, certs, "old-default", profiles,
            "video1", auto_pin=True, clock_burst="conservative")
        print("auto_clock_fixture old_default=correlated_request_ignored", flush=True)
        return
    sys.path.insert(0, str(Path(helper).resolve(strict=True)))
    from media_before_reply_fixture import flv_tag
    media = archive_media(avc, flv_tag)
    for name, clock in (("automatic", "auto-default"), ("conservative", "auto-conservative")):
        case_root = root / name
        case_root.mkdir(mode=0o700)
        (case_root / "camera-fence").mkdir(mode=0o700)
        kwargs = {"media": media, "archive": "video", "expect_auto_inband": True} if clock == "auto-default" else {}
        run(str(binary), "10.198.0.1", case_root, certs, name, profiles, "video1",
            auto_pin=True, clock_burst=clock, **kwargs)
        if clock == "auto-default":
            journal = case_root / name
            recovered = subprocess.run(
                [str(binary), "--inspect-anchored", str(journal / "journal"),
                 str(journal / "keeper"), str(journal / "root"),
                 "12345678-1234-4abc-9abc-123456789abc", MAC.hex(), "--owner-authorized"],
                capture_output=True, timeout=20, check=True)
            match = re.search(rb"trial_recovery=reconciliation_only operations=(\d+) unresolved=(\d+)", recovered.stdout)
            if not match or int(match.group(1)) < 14 or match.group(1) != match.group(2):
                raise ValueError("automatic clock effects not retained as unresolved journal operations")
    print("auto_clock_fixture new_default=10_replies_and_archive conservative=ignored", flush=True)


if __name__ == "__main__":
    main()
