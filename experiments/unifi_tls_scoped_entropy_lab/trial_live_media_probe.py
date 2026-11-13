#!/usr/bin/env python3
"""Exercise the bounded push diagnostic on an isolated loopback network.

Run only inside an isolated network namespace with 127.0.0.1 and 127.0.0.2
available. The input is the synthetic Annex-B fixture, never camera footage.
"""

import select
import socket
import subprocess
import sys

from trial_profile_fixture import archive_media


def flv_tag(timestamp, payload):
    size = len(payload)
    return (
        b"\x09"
        + size.to_bytes(3, "big")
        + (timestamp & 0xFFFFFF).to_bytes(3, "big")
        + bytes([timestamp >> 24])
        + b"\x00\x00\x00"
        + payload
        + (11 + size).to_bytes(4, "big")
    )


def case(binary, source, media, expect_success):
    process = subprocess.Popen(
        [binary, "127.0.0.1:0", "127.0.0.2", "--owner-authorized"],
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
        port = int(ready.removeprefix("push_probe_ready port="))
        with socket.socket() as sender:
            sender.settimeout(30)
            sender.bind((source, 0))
            sender.connect(("127.0.0.1", port))
            if media:
                sender.sendall(media)
        output, error = process.communicate(timeout=90)
        if expect_success:
            expected = "push_probe_decoded width=2688 height=1512 "
            if process.returncode != 0 or expected not in output or "source_retained=no" not in output:
                raise RuntimeError(f"expected decode did not complete: {error.strip()}")
        elif (process.returncode == 0 or "push_probe_decoded" in output
              or "UniFi stream listener refused: Denied" not in error):
            raise RuntimeError("unapproved peer was not rejected")
    finally:
        if process.poll() is None:
            process.kill()
            process.communicate(timeout=5)


def main():
    if len(sys.argv) != 3:
        raise SystemExit("usage: trial_live_media_probe.py BINARY SYNTHETIC_ANNEX_B")
    binary, fixture = sys.argv[1:]
    denied = subprocess.run([binary, "127.0.0.1:0", "127.0.0.2"], capture_output=True, timeout=10)
    if denied.returncode == 0 or b"usage: live_media_probe" not in denied.stderr:
        raise RuntimeError("missing authorization flag was accepted")
    media = archive_media(fixture, flv_tag)
    case(binary, "127.0.0.3", None, False)
    case(binary, "127.0.0.2", media, True)
    print("push_probe_fixture passed=3 synthetic_resolution=2688x1512")


if __name__ == "__main__":
    main()
