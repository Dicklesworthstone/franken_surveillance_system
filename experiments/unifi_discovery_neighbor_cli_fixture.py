#!/usr/bin/env python3
"""Synthetic neighbor-cache discovery; run only in a private network namespace.

The namespace must contain fssdummy with 10.252.14.1/24 and complete neighbor
entries for 10.252.14.2 and .3; those addresses must also be local on loopback.
No physical camera or real LAN address is contacted.
"""
import ipaddress
import json
import socket
import subprocess
import sys
import threading


def main():
    if len(sys.argv) != 2:
        raise SystemExit("expected discovery binary")
    binary = sys.argv[1]
    base = [binary, "--auto-scope", "10.252.14.0/24", "--only-interface", "fssdummy",
            "--neighbor-cache", "--include-mac-claims", "--principal", "principal:fixture",
            "--approval", "sha256:" + "11" * 32, "--owner-authorized"]
    addresses = ["10.252.14.2", "10.252.14.3"]
    peers = []
    threads = []
    errors = []
    for index, address in enumerate(addresses):
        peer = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        peer.bind((address, 10001))
        peer.settimeout(10)
        peers.append(peer)

        def respond(sock=peer, ip=address, suffix=index):
            try:
                query, sender = sock.recvfrom(128)
                if query != bytes([1, 0, 0, 0]):
                    raise RuntimeError("unexpected query")
                mac = bytes([0x10, 2, 3, 4, 5, 6 + suffix])
                values = [(1, mac), (2, mac + ipaddress.IPv4Address(ip).packed),
                          (3, b"UVC.fixture"), (12, b"UVC G4 Instant")]
                body = b"".join(bytes([kind]) + len(value).to_bytes(2, "big") + value for kind, value in values)
                sock.sendto(bytes([1, 0]) + len(body).to_bytes(2, "big") + body, sender)
            except (OSError, RuntimeError) as error:
                errors.append(type(error).__name__)

        thread = threading.Thread(target=respond)
        threads.append(thread)
        thread.start()
    try:
        result = subprocess.run(base, capture_output=True, text=True, timeout=15)
    finally:
        for thread in threads:
            thread.join(timeout=11)
        for peer in peers:
            peer.close()
    if result.returncode or errors or any(t.is_alive() for t in threads):
        raise RuntimeError("neighbor discovery failed: " + result.stderr[-300:])
    report = json.loads(result.stdout)
    combined = report.get("combined") or {}
    cameras = combined.get("cameras", [])
    if (report.get("windows_ok") is not True or report.get("absence_proven") is not False
            or report.get("neighbor_cache") is not True or report.get("neighbor_cache_completeness") != "unknown"
            or {c.get("address") for c in cameras} != set(addresses)
            or any(c.get("identity") != "unverified" for c in cameras)):
        raise RuntimeError("neighbor results did not match both synthetic peers")
    print("neighbor_cli_fixture peers=2 explicit_targets=0 camera=synthetic result=pass")


if __name__ == "__main__":
    main()
