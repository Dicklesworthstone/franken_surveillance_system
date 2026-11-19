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

    for conflicting in (False, True):
        peers = []
        threads = []
        errors = []
        for index, address in enumerate(addresses):
            peer = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            peer.bind((address, 10001)); peer.settimeout(30)
            peers.append(peer)

            def respond_all(peer=peer, address=address, index=index):
                try:
                    query, sender = peer.recvfrom(128)
                    if query != bytes([1, 0, 0, 0]): raise RuntimeError("unexpected query")
                    mac = bytes([0x10, 2, 3, 4, 5, 6 + (0 if conflicting else index)])
                    values = [(1, mac), (2, mac + ipaddress.IPv4Address(address).packed),
                              (3, b"UVC.fixture"), (12, b"UVC G4 Instant")]
                    body = b"".join(bytes([kind]) + len(value).to_bytes(2, "big") + value for kind, value in values)
                    peer.sendto(bytes([1, 0]) + len(body).to_bytes(2, "big") + body, sender)
                except (OSError, RuntimeError) as error:
                    errors.append(type(error).__name__)

            thread = threading.Thread(target=respond_all)
            threads.append(thread); thread.start()
        command = [binary, "--auto-scope", "10.252.14.0/24", "--only-interface", "fssdummy",
                   "--limited-broadcast", "--sweep-all", "--include-mac-claims",
                   "--principal", "principal:fixture", "--approval", "sha256:" + "11" * 32,
                   "--owner-authorized"]
        try:
            result = subprocess.run(command, capture_output=True, text=True, timeout=40)
        finally:
            for thread in threads: thread.join(timeout=31)
            for peer in peers: peer.close()
        if result.returncode or errors or any(thread.is_alive() for thread in threads):
            raise RuntimeError("all-page sweep failed: " + result.stderr[-300:])
        report = json.loads(result.stdout)
        cameras = (report.get("combined") or {}).get("cameras", [])
        if (report.get("status") != "complete" or report.get("absence_proven") is not False
                or len(report.get("pages", [])) != 2 or len(report.get("windows", [])) != 5
                or {camera.get("address") for camera in cameras} != set(addresses)
                or any(camera.get("identity") != "unverified" for camera in cameras)
                or any(camera.get("claim_issues", {}).get("same_mac_at_multiple_addresses") != conflicting for camera in cameras)):
            raise RuntimeError("all-page sweep report mismatch")
    print("sweep_all_fixture cases=2 cross_page_conflict=detected result=pass")

    peer = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    peer.bind((addresses[0], 10001)); peer.settimeout(15)
    errors = []
    def flood_one_window():
        try:
            query, sender = peer.recvfrom(128)
            if query != bytes([1, 0, 0, 0]): raise RuntimeError("unexpected query")
            mac = bytes([0x10, 2, 3, 4, 5, 6])
            values = [(1, mac), (2, mac + ipaddress.IPv4Address(addresses[0]).packed),
                      (3, b"UVC.fixture"), (12, b"UVC G4 Instant")]
            body = b"".join(bytes([kind]) + len(value).to_bytes(2, "big") + value for kind, value in values)
            reply = bytes([1, 0]) + len(body).to_bytes(2, "big") + body
            for _ in range(64): peer.sendto(reply, sender)
        except (OSError, RuntimeError) as error:
            errors.append(type(error).__name__)
    thread = threading.Thread(target=flood_one_window); thread.start()
    try:
        result = subprocess.run(command, capture_output=True, text=True, timeout=15)
    finally:
        thread.join(timeout=16); peer.close()
    if result.returncode == 0 or errors or thread.is_alive():
        raise RuntimeError("incomplete all-page sweep was accepted")
    report = json.loads(result.stdout)
    if (report.get("status") != "incomplete" or report.get("combined") is not None
            or report.get("absence_proven") is not False or report.get("reason") != "incomplete_window"
            or (report.get("incomplete_window") or {}).get("stop") != "PacketLimit"):
        raise RuntimeError("partial all-page sweep report mismatch")
    print("sweep_all_incomplete_fixture cases=1 retained_partial=true result=pass")


if __name__ == "__main__":
    main()
