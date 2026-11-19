#!/usr/bin/env python3
"""Compare journal custody for synthetic restore responses and lost replies."""
from pathlib import Path
import sys

from trial_http_record_fixture import certificate, run


def main():
    if len(sys.argv) != 3:
        raise SystemExit("expected trial binary and fresh private root")
    binary = str(Path(sys.argv[1]).resolve(strict=True))
    root = Path(sys.argv[2])
    if not root.is_absolute() or not root.is_dir() or root.stat().st_mode & 0o077:
        raise SystemExit("expected private root")
    cert = certificate(root, "camera")
    support = Path(__file__).resolve().parent / "tests/support"
    for mode in ("restore_success", "restore_ignored", "restore_interrupted", "restore_bad_trailer", "av_restore"):
        fixture = "synthetic_g4_av_gop3.264" if mode.startswith("av_") else "synthetic_g4_resolution.264"
        run(binary, root, cert, support / fixture, mode)
    print("restore_receipt_fixture passed=5 camera=synthetic effects=unsettled")


if __name__ == "__main__":
    main()
