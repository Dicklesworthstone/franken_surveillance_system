#!/usr/bin/env python3
"""Independent disposable UDP and TLS peers for the read-only setup experiment."""
import http.server
import json
import os
import pathlib
import secrets
import socket
import ssl
import subprocess
import sys
import tempfile
import threading


def run_case(binary, cert_der, cert_pem, key_pem, jpeg, directory, mode):
    username, password, token = (secrets.token_hex(12) for _ in range(3))
    secret = pathlib.Path(directory) / (mode + '-credential.json')
    fd = os.open(secret, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, 'w') as output:
        json.dump({'username': username, 'password': password}, output)
    journal = pathlib.Path(directory) / (mode + '-journal')
    requests = []
    errors = []

    class Handler(http.server.BaseHTTPRequestHandler):
        protocol_version = 'HTTP/1.1'

        def log_message(self, *_):
            pass

        def body(self, body, cookie=False):
            self.send_response(200)
            self.send_header('Content-Length', str(len(body)))
            if cookie:
                self.send_header('Set-Cookie', 'authId=' + token + '; Path=/; HttpOnly')
            self.end_headers()
            self.wfile.write(body)

        def do_POST(self):
            n = int(self.headers.get('Content-Length', '0'))
            if self.path != '/api/1.1/login' or n > 4096 or json.loads(self.rfile.read(n)) != {'username': username, 'password': password}:
                self.send_error(403)
                return
            requests.append('login')
            self.body(b'{}', True)

        def do_GET(self):
            if self.headers.get('Cookie') != 'authId=' + token:
                self.send_error(403)
                return
            if self.path == '/api/1.1/status':
                requests.append('status')
                self.body(b'{"board":{},"fw":{},"controller":{}}')
            elif self.path == '/api/1.1/settings':
                requests.append('settings')
                current = '192.168.1.99' if mode == 'changed' and requests.count('settings') == 2 else '192.168.1.10'
                self.body(json.dumps({'controller': {'addr': current}}).encode())
            elif self.path == '/snap.jpeg':
                requests.append('snapshot')
                self.body(b'\xff\xd8invalid\xff\xd9' if mode == 'bad-image' else pathlib.Path(jpeg).read_bytes())
            else:
                self.send_error(404)

        def do_PUT(self):
            requests.append('PUT')
            self.send_error(403)

    server = http.server.HTTPServer(('127.0.0.1', 0), Handler)
    server.socket.settimeout(6)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(cert_pem, key_pem)
    server.socket = context.wrap_socket(server.socket, server_side=True)
    def serve():
        try:
            server.handle_request()
        except (OSError, ssl.SSLError) as error:
            if mode != 'bad-pin':
                errors.append(type(error).__name__)
    http_thread = threading.Thread(target=serve)
    http_thread.start()
    udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp.bind(('127.0.0.1', 0))
    udp.settimeout(5)
    mac = bytes([0x10, 2, 3, 4, 5, 6])
    def respond():
        try:
            _, peer = udp.recvfrom(128)
            fields = [(1, mac), (2, mac + bytes([127, 0, 0, 1])), (3, b'UVC.fixture'), (12, b'UVC G4 Instant')]
            body = b''.join(bytes([kind]) + len(value).to_bytes(2, 'big') + value for kind, value in fields)
            udp.sendto(bytes([1, 0]) + len(body).to_bytes(2, 'big') + body, peer)
        except OSError as error:
            errors.append(type(error).__name__)
    udp_thread = threading.Thread(target=respond)
    udp_thread.start()
    selected_mac = '10:02:03:04:05:07' if mode == 'wrong-mac' else '10:02:03:04:05:06'
    args = [binary, cert_der, '127.0.0.1', 'tls13', 'mismatch' if mode == 'bad-pin' else 'match',
            'sha256:' + '1' * 64, str(secret), str(server.server_port), '192.168.1.10',
            '192.168.1.40', str(journal), '--owner-authorized', '127.0.0.1', '8',
            '127.0.0.1:' + str(udp.getsockname()[1]), selected_mac]
    try:
        result = subprocess.run(args, capture_output=True, text=True, timeout=25)
    finally:
        udp_thread.join(timeout=6)
        udp.close()
        http_thread.join(timeout=7)
        server.server_close()
    if udp_thread.is_alive() or http_thread.is_alive() or errors:
        raise RuntimeError(mode + ': fixture peer failed')
    if any(value in result.stdout or value in result.stderr for value in (username, password, token)):
        raise RuntimeError(mode + ': secret reached process output')
    if journal.exists() or 'PUT' in requests:
        raise RuntimeError(mode + ': unexpected management effect')
    if mode == 'ok':
        if result.returncode or requests != ['login', 'status', 'settings', 'settings', 'snapshot'] or 'snapshot_decoded=' not in result.stdout or 'media_persisted=false' not in result.stdout:
            raise RuntimeError(mode + ': setup failed: ' + result.stderr[-500:])
    elif mode == 'bad-image':
        if not result.returncode or requests != ['login', 'status', 'settings', 'settings', 'snapshot'] or 'snapshot_decoded=' in result.stdout:
            raise RuntimeError(mode + ': invalid image was accepted')
    elif mode == 'changed':
        if not result.returncode or requests != ['login', 'status', 'settings', 'settings'] or 'Changed' not in result.stderr:
            raise RuntimeError(mode + ': changed settings not refused')
    elif mode == 'bad-pin':
        if result.returncode or requests or 'mismatch=rejected' not in result.stdout:
            raise RuntimeError(mode + ': pin mismatch not refused before login')
    elif mode == 'wrong-mac':
        if not result.returncode or requests or 'exactly one selected' not in result.stderr:
            raise RuntimeError(mode + ': unrelated discovery claim was selected')


def main():
    if len(sys.argv) != 6:
        raise SystemExit('discovery_observe_fixture.py BINARY CERT_DER CERT_PEM KEY_PEM JPEG')
    with tempfile.TemporaryDirectory(prefix='fss-unifi-discovery-observe-') as directory:
        for mode in ('ok', 'bad-image', 'changed', 'bad-pin', 'wrong-mac'):
            run_case(*sys.argv[1:], directory, mode)
    print('discovery observation fixture: 5/5 passed')

if __name__ == '__main__':
    main()
