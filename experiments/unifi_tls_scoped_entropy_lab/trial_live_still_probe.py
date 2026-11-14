#!/usr/bin/env python3
"""Exercise the live-still diagnostic using synthetic video and loopback.

The supplied directory must already be private and empty of the fixture names.
No file created by this fixture is removed or overwritten.
"""

import os
from pathlib import Path
import select
import socket
import subprocess
import sys

from trial_profile_fixture import archive_media
from trial_live_media_probe import flv_tag


def case(binary, source, output, media, allowed, expected=None, refusal=None):
    if output.exists():
        raise ValueError("fixture destination already exists")
    command = [binary, "127.0.0.1:0", "127.0.0.2", str(output), "--owner-authorized"]
    if expected is not None:
        command.extend(["--expect-dimensions", expected])
    process = subprocess.Popen(
        command,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    try:
        if not select.select([process.stdout], [], [], 30)[0]:
            raise RuntimeError("listener did not become ready")
        ready = process.stdout.readline().strip()
        if not ready.startswith("push_probe_ready port="):
            raise RuntimeError("unexpected listener startup")
        with socket.socket() as sender:
            sender.settimeout(30)
            sender.bind((source, 0))
            sender.connect(("127.0.0.1", int(ready.split("=")[1])))
            if media:
                sender.sendall(media)
        result, error = process.communicate(timeout=300)
        if allowed:
            if process.returncode or "push_probe_decoded width=2688 height=1512" not in result:
                raise RuntimeError("synthetic still did not complete: " + error.strip())
            if "jpeg_color=bt601-full" not in result or "source_retained=no" not in result:
                raise RuntimeError("missing still interpretation or custody result")
            data = output.read_bytes()
            if len(data) < 100 or not data.startswith(b"\xff\xd8") or not data.endswith(b"\xff\xd9"):
                raise RuntimeError("incomplete synthetic JPEG")
            if output.stat().st_mode & 0o077:
                raise RuntimeError("synthetic JPEG is not private")
        elif process.returncode == 0 or output.exists():
            raise RuntimeError("unapproved peer unexpectedly produced a file")
        elif refusal is not None and refusal not in error:
            raise RuntimeError("expected resolution refusal was not reported")
    finally:
        if process.poll() is None:
            process.terminate()
            try:
                process.communicate(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.communicate(timeout=5)


def main():
    if len(sys.argv) != 4:
        raise SystemExit("usage: trial_live_still_probe.py BINARY SYNTHETIC_ANNEX_B PRIVATE_DIR")
    binary, fixture, directory = sys.argv[1:]
    root = Path(directory)
    if not root.is_absolute() or not root.is_dir() or root.stat().st_mode & 0o077:
        raise ValueError("fixture directory must be private and absolute")
    missing = subprocess.run([binary, "127.0.0.1:0", "127.0.0.2", str(root / "no-auth.jpeg")],
                             capture_output=True, timeout=10)
    if missing.returncode == 0 or (root / "no-auth.jpeg").exists():
        raise RuntimeError("missing authorization accepted")
    for index, invalid in enumerate(("0x1512", "2688x0", "2688", "2688x1512x1")):
        destination = root / f"invalid-dimensions-{index}.jpeg"
        result = subprocess.run(
            [binary, "127.0.0.1:0", "127.0.0.2", str(destination),
             "--owner-authorized", "--expect-dimensions", invalid],
            capture_output=True, timeout=10,
        )
        if result.returncode == 0 or destination.exists() or b"invalid expected dimensions" not in result.stderr:
            raise RuntimeError("invalid dimensions accepted")
    synthetic = archive_media(fixture, flv_tag)
    case(binary, "127.0.0.3", root / "denied.jpeg", None, False)
    case(binary, "127.0.0.2", root / "wrong-resolution.jpeg", synthetic, False,
         "1280x720", "DimensionsMismatch")
    case(binary, "127.0.0.2", root / "synthetic-still.jpeg", synthetic, True, "2688x1512")
    print("live_still_fixture passed=8 synthetic_resolution=2688x1512")


if __name__ == "__main__":
    os.umask(0o077)
    main()
