#!/usr/bin/env python3
"""Independent scoped UDP fixture for the native UniFi discovery CLI."""
import json
import socket
import subprocess
import sys
import threading


def main():
    if len(sys.argv) != 2:
        raise SystemExit('unifi_discovery_cli_fixture.py BINARY')
    binary = sys.argv[1]
    base = [binary, '--iface', '127.0.0.2', '--prefix', '8', '--principal', 'principal:fixture',
            '--approval', 'sha256:' + '1' * 64, '--owner-authorized']
    for extra in (['--target', '192.0.2.4'], ['--target', '127.0.0.1', '--target', '127.0.0.3']):
        result = subprocess.run(base + extra, capture_output=True, text=True, timeout=5)
        if result.returncode == 0:
            raise RuntimeError('out-of-scope or duplicate target was accepted')
    peer = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    peer.bind(('127.0.0.1', 10001))
    peer.settimeout(8)
    errors = []
    def respond():
        try:
            query, sender = peer.recvfrom(128)
            if not query:
                raise RuntimeError('empty query')
            mac = bytes([0x10, 2, 3, 4, 5, 6])
            values = [(1, mac), (2, mac + bytes([127, 0, 0, 1])),
                      (3, b'UVC.fixture'), (12, b'UVC G4 Instant')]
            body = b''.join(bytes([kind]) + len(value).to_bytes(2, 'big') + value for kind, value in values)
            peer.sendto(bytes([1, 0]) + len(body).to_bytes(2, 'big') + body, sender)
        except (OSError, RuntimeError) as error:
            errors.append(type(error).__name__)
    thread = threading.Thread(target=respond)
    thread.start()
    try:
        result = subprocess.run(base + ['--target', '127.0.0.1'], capture_output=True, text=True, timeout=12)
    finally:
        thread.join(timeout=9)
        peer.close()
    if thread.is_alive() or errors or result.returncode:
        raise RuntimeError('unicast fixture failed: ' + result.stderr[-300:])
    report = json.loads(result.stdout)
    cameras = report.get('cameras', [])
    if (report.get('stop') != 'WindowElapsed' or report.get('absence_proven') is not False
            or report.get('datagrams') != 1 or len(cameras) != 1
            or cameras[0].get('address') != '127.0.0.1'
            or cameras[0].get('identity') != 'unverified'
            or cameras[0].get('source_advertised') is not True
            or any(cameras[0].get('claim_issues', {}).values())):
        raise RuntimeError('unexpected discovery report')
    print('unicast CLI fixture: 3/3 passed')

if __name__ == '__main__':
    main()
