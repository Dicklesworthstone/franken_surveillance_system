#!/usr/bin/env python3
"""Exercise optional restore against an isolated synthetic camera."""
from pathlib import Path
import subprocess
import sys

from trial_http_record_fixture import certificate, run


def main():
    if len(sys.argv) != 3:
        raise SystemExit("expected trial binary and private root")
    binary = str(Path(sys.argv[1]).resolve(strict=True))
    root = Path(sys.argv[2])
    if not root.is_absolute() or not root.is_dir() or root.stat().st_mode & 0o077:
        raise SystemExit("expected private root")
    cert = certificate(root, "camera")
    support = Path(__file__).resolve().parent / "tests/support"
    for mode in ("restore_success", "restore_object", "restore_ignored", "restore_drift", "restore_interrupted", "restore_missing", "restore_checkpoint_blocked", "av_restore", "restore_short", "restore_short_drift", "restore_short_ignored", "restore_bad_trailer", "av_restore_short", "av_restore_bad_avc", "restore_accept_timeout", "restore_accept_drift", "restore_accept_ignored", "av_restore_accept_timeout", "accept_timeout_no_opt", "restore_start_unconfirmed"):
        fixture = "synthetic_g4_av_gop3.264" if mode.startswith("av_restore") else "synthetic_g4_resolution.264"
        run(binary, root, cert, support / fixture, mode)
    args = [binary, "10.252.15.1:7442", "10.252.15.2", "020000000002", str(root / "unused-cert"),
            str(root / "unused-key"), str(root / "unused-effect"), str(root / "unused-archive"),
            "12345678-1234-4abc-9abc-123456789abc", "20", "--lab-http-restore-after", "--owner-authorized"]
    refused = subprocess.run(args, capture_output=True, timeout=15)
    if refused.returncode == 0 or b"HTTP restore requires a bounded HTTP recording" not in refused.stderr:
        raise ValueError("restore option without recording was not refused")
    if (root / "unused-effect").exists() or (root / "unused-archive").exists():
        raise ValueError("restore option refusal created effect or archive")
    print("http_restore_argument_refusal passed=1")
    print("http_restore_fixture passed=20 camera=synthetic effects=unsettled")


if __name__ == "__main__":
    main()
