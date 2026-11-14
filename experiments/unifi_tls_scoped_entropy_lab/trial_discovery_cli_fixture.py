#!/usr/bin/env python3
"""Exercise the Rust discovery CLI against synthetic UDP cameras only.

Run inside an isolated network namespace with 10.252.12.1, .2 and .3 bound
to loopback. This fixture creates no files and contacts no physical camera.
"""

import socket
import subprocess
import sys

APPROVAL = "sha256:" + "01" * 32


def advertisement(address, mac):
    fields = ((1, mac), (2, mac + socket.inet_aton(address)),
              (3, b"UVC.fixture"), (12, b"UVC G4 Instant"))
    body = b"".join(bytes([kind]) + len(value).to_bytes(2, "big") + value for kind, value in fields)
    return b"\x01\x00" + len(body).to_bytes(2, "big") + body


def exercise(binary, conflicting):
    sockets = []
    try:
        for address in ("0.0.0.0", "10.252.12.2", "10.252.12.3"):
            peer = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            peer.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            peer.bind((address, 10001))
            peer.settimeout(8)
            sockets.append(peer)
        child = subprocess.Popen([binary, "10.252.12.1", "24", "principal:fixture", APPROVAL, "--owner-authorized"],
                                 stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        try:
            query, target = sockets[0].recvfrom(1024)
            if not query or target[0] != "10.252.12.1":
                raise ValueError("unexpected discovery query")
            first = bytes.fromhex("001122aabb01")
            second = first if conflicting else bytes.fromhex("001122aabb02")
            for peer, address, mac in zip(sockets[1:], ("10.252.12.2", "10.252.12.3"), (first, second)):
                peer.sendto(advertisement(address, mac), target)
            out, err = child.communicate(timeout=12)
        finally:
            if child.poll() is None:
                child.terminate()
                child.communicate(timeout=5)
        if child.returncode != 0:
            raise RuntimeError("discovery failed: " + err.decode(errors="replace"))
        if b"stop=WindowElapsed candidates=2" not in out or out.count(b"authenticated=false") != 2:
            raise ValueError("discovery count or identity qualification missing")
        expected = b"unconflicted=false" if conflicting else b"unconflicted=true"
        if out.count(expected) != 2:
            raise ValueError("discovery conflict assessment incorrect")
        print(f"discovery_cli_fixture conflicting={conflicting} candidates=2 result=pass", flush=True)
    finally:
        for peer in sockets:
            peer.close()


def main():
    if len(sys.argv) != 2:
        raise SystemExit("usage: trial_discovery_cli_fixture.py BINARY")
    binary = sys.argv[1]
    denied = subprocess.run([binary, "10.252.12.1", "24", "principal:fixture", APPROVAL], capture_output=True, timeout=5)
    invalid = subprocess.run([binary, "10.252.12.1", "0", "principal:fixture", APPROVAL, "--owner-authorized"], capture_output=True, timeout=5)
    unapproved = subprocess.run([binary, "10.252.12.1", "24", "principal:fixture", "sha256:" + "00" * 32, "--owner-authorized"], capture_output=True, timeout=5)
    if any(case.returncode == 0 for case in (denied, invalid, unapproved)):
        raise ValueError("missing authority, invalid scope or empty approval accepted")
    exercise(binary, False)
    exercise(binary, True)
    print("discovery_cli_fixture passed=5 source=synthetic live_camera=not_contacted")


if __name__ == "__main__":
    main()
