#!/usr/bin/env python3
"""Real HTTP tests against the built native binary. No alternate server implementation."""
import argparse
import contextlib
import http.client
import json
import os
from pathlib import Path
import re
import socket
import subprocess
import tempfile
import time


@contextlib.contextmanager
def running(binary, seconds=30):
    with tempfile.TemporaryFile() as log:
        child = subprocess.Popen([binary, '--demo', '--port', '0', '--serve-seconds', str(seconds)],
                                 stdout=subprocess.DEVNULL, stderr=log)
        try:
            deadline = time.monotonic() + 15
            while time.monotonic() < deadline:
                log.seek(0)
                text = log.read(16384).decode('utf-8', errors='replace')
                match = re.search(r'http://127\.0\.0\.1:(\d+)', text)
                if match:
                    yield child, int(match.group(1))
                    return
                if child.poll() is not None:
                    raise AssertionError('Native dashboard exited before binding: ' + text)
                time.sleep(.02)
            raise AssertionError('Native dashboard did not bind before the test deadline')
        finally:
            if child.poll() is None:
                child.terminate()
                try:
                    child.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    child.kill()
                    child.wait(timeout=3)


def request(port, path='/', method='GET', headers=None):
    connection = http.client.HTTPConnection('127.0.0.1', port, timeout=4)
    try:
        connection.request(method, path, headers=headers or {})
        response = connection.getresponse()
        body = response.read(4 * 1024 * 1024 + 1)
        assert len(body) <= 4 * 1024 * 1024
        assert int(response.getheader('Content-Length')) == len(body)
        assert response.getheader('Cache-Control') == 'no-store'
        assert response.getheader('X-Content-Type-Options') == 'nosniff'
        assert response.getheader('Cross-Origin-Resource-Policy') == 'same-origin'
        assert response.getheader('Access-Control-Allow-Origin') is None
        assert "frame-ancestors 'none'" in response.getheader('Content-Security-Policy')
        return response.status, response.getheader('Content-Type'), body
    finally:
        connection.close()


def run(binary):
    snapshot = subprocess.run([binary, '--demo', '--snapshot'], capture_output=True, timeout=12, check=True)
    expected = json.loads(snapshot.stdout)
    assert expected['demo'] is True and len(expected['events']) == 9
    assert '1789398468000000123' in expected['events'][0]['recordJson']
    with running(binary) as (child, port):
        for path, mime in [('/', 'text/html'), ('/app.js', 'text/javascript'), ('/model.js', 'text/javascript'), ('/style.css', 'text/css'), ('/favicon.svg', 'image/svg+xml')]:
            code, content_type, body = request(port, path)
            assert code == 200 and mime in content_type and body, (path, code)
        code, _, body = request(port, '/api/snapshot', headers={'X-FSS-Read': '1', 'Sec-Fetch-Site': 'same-origin'})
        assert code == 200 and json.loads(body) == expected
        for headers in [{}, {'X-FSS-Read': '1', 'Host': 'attacker.invalid'}, {'X-FSS-Read': '1', 'Origin': 'null'}, {'X-FSS-Read': '1', 'Origin': 'https://attacker.invalid'}, {'X-FSS-Read': '1', 'Sec-Fetch-Site': 'cross-site'}]:
            assert request(port, '/api/snapshot', headers=headers)[0] == 403, headers
        assert request(port, '/api/snapshot', method='POST')[0] == 405
        for path in ['/../LAYOUT', '/%2e%2e/LAYOUT', '/demo.json', '/credentials', '/api/snapshot?root=/other']:
            assert request(port, path)[0] == 404, path
        for header in [f'Host: 127.0.0.1:{port}\r\n', 'Transfer-Encoding: chunked\r\n', 'Content-Length: 12\r\n']:
            with socket.create_connection(('127.0.0.1', port), timeout=4) as sock:
                sock.sendall(f'GET / HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\n{header}\r\n'.encode())
                assert sock.recv(1024).startswith(b'HTTP/1.1 400'), header
        # A slow partial request cannot monopolize the finite single-owner listener forever.
        with socket.create_connection(('127.0.0.1', port), timeout=4) as sock:
            sock.sendall(b'GET / HTTP/1.1\r\n')
            started = time.monotonic()
            assert sock.recv(1024) == b''
            assert time.monotonic() - started < 4
        assert request(port)[0] == 200 and child.poll() is None
    with running(binary, seconds=1) as (child, _):
        assert child.wait(timeout=5) == 0, 'Finite listener lease should end normally'
    print('PASS: native demo snapshot, embedded assets, exact HTTP lengths, origin/Host defenses, read header, path allowlist, write refusal, slow request timeout and finite lease.')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', default='target/debug/fss-dashboard')
    args = parser.parse_args()
    run(str(Path(args.binary).resolve()))
