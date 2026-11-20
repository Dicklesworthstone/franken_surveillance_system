#!/usr/bin/env python3
"""Replay bounded private video through an isolated simulated HTTP camera."""
from pathlib import Path
import sys

from trial_http_record_fixture import certificate, run


def main():
    if len(sys.argv) != 3:
        raise SystemExit("expected trial binary and private root")
    binary = str(Path(sys.argv[1]).resolve(strict=True))
    root = Path(sys.argv[2])
    if not root.is_absolute() or not root.is_dir() or root.stat().st_mode & 0o077:
        raise SystemExit("expected private root")
    media = sys.stdin.buffer.read(16 * 1024 * 1024 + 1)
    if not media.startswith(b"FLV\x01") or len(media) > 16 * 1024 * 1024:
        raise SystemExit("bounded FLV input required")
    cert = certificate(root, "camera")
    run(binary, root, cert, None, "video_real", media)


if __name__ == "__main__":
    main()
