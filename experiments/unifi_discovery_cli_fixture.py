#!/usr/bin/env python3
"""Independent scoped UDP fixture for the native UniFi discovery CLI."""
import ipaddress
import json
import socket
import subprocess
import sys
import threading


def run_case(base, addresses, incomplete=False):
    peers = []
    errors = []
    threads = []
    for index, address in enumerate(addresses):
        peer = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        peer.bind((address, 10001))
        peer.settimeout(8)
        peers.append(peer)
        def respond(sock=peer, ip=address, suffix=index):
            try:
                query, sender = sock.recvfrom(128)
                if query != bytes([1, 0, 0, 0]):
                    raise RuntimeError('unexpected query')
                mac = bytes([0x10, 2, 3, 4, 5, 6 + suffix])
                values = [(1, mac), (2, mac + ipaddress.IPv4Address(ip).packed),
                          (3, b'UVC.fixture'), (12, b'UVC G4 Instant')]
                body = b''.join(bytes([kind]) + len(value).to_bytes(2, 'big') + value for kind, value in values)
                sock.sendto(bytes([1, 0]) + len(body).to_bytes(2, 'big') + body, sender)
                if incomplete:
                    values = [(2, mac + ipaddress.IPv4Address(ip).packed),
                              (3, b'UVC.fixture'), (12, b'UVC G4 Instant')]
                    body = b''.join(bytes([kind]) + len(value).to_bytes(2, 'big') + value for kind, value in values)
                    sock.sendto(bytes([1, 0]) + len(body).to_bytes(2, 'big') + body, sender)
            except (OSError, RuntimeError) as error:
                errors.append(type(error).__name__)
        thread = threading.Thread(target=respond)
        threads.append(thread)
        thread.start()
    args = base + [value for address in addresses for value in ('--target', address)]
    try:
        result = subprocess.run(args, capture_output=True, text=True, timeout=12)
    finally:
        for thread in threads:
            thread.join(timeout=9)
        for peer in peers:
            peer.close()
    if any(thread.is_alive() for thread in threads) or errors or result.returncode:
        raise RuntimeError('unicast fixture failed: ' + result.stderr[-300:])
    report = json.loads(result.stdout)
    cameras = report.get('cameras', [])
    if incomplete:
        if (report.get('stop') != 'WindowElapsed' or report.get('absence_proven') is not False
                or report.get('datagrams') != 2 or len(cameras) != 2
                or any(camera.get('identity') != 'unverified' for camera in cameras)):
            raise RuntimeError('unexpected incomplete-claim discovery report')
        issues = [camera.get('claim_issues', {}) for camera in cameras]
        if (sum(issue.get('missing_or_invalid_mac') is True for issue in issues) != 1
                or sum(issue.get('incomplete_claim_at_address') is True for issue in issues) != 1):
            raise RuntimeError('incomplete same-address claim was not exposed')
        good = next(issue for issue in issues if issue.get('missing_or_invalid_mac') is False)
        if good.get('incomplete_claim_at_address') is not True:
            raise RuntimeError('the otherwise clean claim was not marked ambiguous')
        return
    if (report.get('stop') != 'WindowElapsed' or report.get('absence_proven') is not False
            or report.get('datagrams') != len(addresses) or len(cameras) != len(addresses)
            or {camera.get('address') for camera in cameras} != set(addresses)
            or any(camera.get('identity') != 'unverified' or camera.get('source_advertised') is not True
                   or any(camera.get('claim_issues', {}).values()) for camera in cameras)):
        raise RuntimeError('unexpected discovery report')


def main():
    if len(sys.argv) != 2:
        raise SystemExit('unifi_discovery_cli_fixture.py BINARY')
    base = [sys.argv[1], '--iface', '127.0.0.3', '--prefix', '8', '--principal', 'principal:fixture',
            '--approval', 'sha256:' + '1' * 64, '--owner-authorized']
    for extra in (['--target', '192.0.2.4'], ['--target', '127.0.0.1', '--target', '127.0.0.1']):
        result = subprocess.run(base + extra, capture_output=True, text=True, timeout=5)
        if result.returncode == 0:
            raise RuntimeError('out-of-scope or duplicate target was accepted')
    run_case(base, ['127.0.0.1'])
    run_case(base, ['127.0.0.1', '127.0.0.2'])
    run_case(base, ['127.0.0.1'], incomplete=True)
    print('unicast CLI fixture: 5/5 passed')

if __name__ == '__main__':
    main()
