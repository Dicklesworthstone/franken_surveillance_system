#!/usr/bin/env python3
"""Exercise two scoped sweep pages against synthetic, uncached camera peers.

Run only in a private network namespace with fssdummy at 10.252.14.1/24 and
10.252.14.2 and 10.252.14.254 local on loopback. No real network is contacted.
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
    addresses = ["10.252.14.2", "10.252.14.254"]
    for page, address in enumerate(addresses):
        peer = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        peer.bind((address, 10001))
        peer.settimeout(20)
        errors = []

        def respond():
            try:
                query, sender = peer.recvfrom(128)
                if query != bytes([1, 0, 0, 0]):
                    raise RuntimeError("unexpected query")
                mac = bytes([0x10, 2, 3, 4, 5, 6 + page])
                values = [(1, mac), (2, mac + ipaddress.IPv4Address(address).packed),
                          (3, b"UVC.fixture"), (12, b"UVC G4 Instant")]
                body = b"".join(bytes([kind]) + len(value).to_bytes(2, "big") + value
                                for kind, value in values)
                peer.sendto(bytes([1, 0]) + len(body).to_bytes(2, "big") + body, sender)
            except (OSError, RuntimeError) as error:
                errors.append(type(error).__name__)

        thread = threading.Thread(target=respond)
        thread.start()
        command = [binary, "--auto-scope", "10.252.14.0/24", "--only-interface", "fssdummy",
                   "--limited-broadcast", "--sweep-page", str(page), "--principal", "principal:fixture",
                   "--approval", "sha256:" + "11" * 32, "--owner-authorized"]
        try:
            result = subprocess.run(command, capture_output=True, text=True, timeout=25)
        finally:
            thread.join(timeout=21)
            peer.close()
        if result.returncode or errors or thread.is_alive():
            raise RuntimeError("sweep failed: " + result.stderr[-300:])
        report = json.loads(result.stdout)
        cameras = (report.get("combined") or {}).get("cameras", [])
        if (report.get("windows_ok") is not True or report.get("absence_proven") is not False
                or report.get("sweep_page") != page or report.get("sweep_pages") != 2
                or report.get("planned_hosts") != (248 if page == 0 else 5)
                or report.get("sweep_completeness") != "page_only"
                or {camera.get("address") for camera in cameras} != {address}
                or any(camera.get("identity") != "unverified" for camera in cameras)):
            raise RuntimeError("sweep page report mismatch")
    print("sweep_cli_fixture pages=2 uncached_peers=2 explicit_targets=0 result=pass")


if __name__ == "__main__":
    main()
