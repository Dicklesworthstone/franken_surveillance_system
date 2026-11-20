#!/usr/bin/env python3
"""Replay a bounded owner-supplied camera sample through a synthetic HTTP peer."""
from pathlib import Path
import sys

from trial_http_record_fixture import certificate, run


def main():
    if len(sys.argv) not in (3, 4) or (len(sys.argv) == 4 and sys.argv[3] != "--supervised-replay"):
        raise SystemExit("expected trial binary, private root and optional --supervised-replay")
    binary = str(Path(sys.argv[1]).resolve(strict=True))
    root = Path(sys.argv[2])
    if not root.is_absolute() or not root.is_dir() or root.stat().st_mode & 0o077:
        raise SystemExit("expected private root")
    media = sys.stdin.buffer.read(1024 * 1024 + 1)
    if len(media) > 1024 * 1024 or not media.startswith(b"FLV\x01"):
        raise SystemExit("invalid bounded camera input")
    cert = certificate(root, "camera")
    # This deliberately replays one captured sample on both simulated
    # connections. It does not claim real-camera reconnection or continuity.
    mode = "av_real_supervised" if len(sys.argv) == 4 else "av_real"
    run(binary, root, cert, None, mode, media)


if __name__ == "__main__":
    main()
