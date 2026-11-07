#!/usr/bin/env python3
"""Independent, loopback-only TLS fixture; no physical camera or real credentials."""
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


def request(sock):
    data = bytearray()
    while b"\r\n\r\n" not in data:
        chunk = sock.recv(4096)
        if not chunk or len(data) + len(chunk) > 16384:
            raise RuntimeError("invalid fixture request")
        data.extend(chunk)
    head, body = data.split(b"\r\n\r\n", 1)
    head = bytes(head)
    lines = head.split(b"\r\n")
    headers = {}
    for line in lines[1:]:
        name, value = line.split(b":", 1)
        headers[name.lower()] = value.strip()
    size = int(headers.get(b"content-length", b"0"))
    if size > 4096:
        raise RuntimeError("fixture request too large")
    while len(body) < size:
        part = sock.recv(size - len(body))
        if not part:
            raise RuntimeError("truncated fixture request")
        body.extend(part)
    return lines[0], headers, bytes(body)


def main():
    if len(sys.argv) not in (6, 7) or (len(sys.argv) == 7 and sys.argv[6] not in ("--three-snapshots", "--disconnect-after-first", "--repeat-settings", "--changed-settings")):
        raise SystemExit("fixture.py BIN CERT_DER CERT_PEM KEY_PEM JPEG_FIXTURE [--three-snapshots|--disconnect-after-first|--repeat-settings|--changed-settings]")
    binary, cert_der, cert_pem, key_pem, jpeg_fixture = sys.argv[1:6]
    disconnect = len(sys.argv) == 7 and sys.argv[6] == "--disconnect-after-first"
    changed = len(sys.argv) == 7 and sys.argv[6] == "--changed-settings"
    repeat = len(sys.argv) == 7 and sys.argv[6] in ("--repeat-settings", "--changed-settings")
    count = 3 if len(sys.argv) == 7 and not repeat else 1
    username, password, token = (secrets.token_hex(16) for _ in range(3))
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    listener.settimeout(10)
    port = listener.getsockname()[1]
    errors = []
    requests = []

    def serve():
        try:
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.load_cert_chain(cert_pem, key_pem)
            raw, _ = listener.accept()
            with raw, context.wrap_socket(raw, server_side=True) as peer:
                peer.settimeout(10)
                line, _, body = request(peer)
                if line != b"POST /api/1.1/login HTTP/1.1" or json.loads(body) != {"username": username, "password": password}:
                    raise RuntimeError("incorrect login")
                requests.append("login")
                reply = b"{}"
                peer.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nSet-Cookie: authId=" + token.encode() + b"; Path=/; HttpOnly\r\nConnection: keep-alive\r\n\r\n" + reply)
                line, headers, body = request(peer)
                if line != b"GET /api/1.1/status HTTP/1.1" or headers.get(b"cookie") != b"authId=" + token.encode() or body:
                    raise RuntimeError("incorrect status request")
                requests.append("status")
                reply = b'{"board":{},"fw":{},"controller":{}}'
                peer.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: " + str(len(reply)).encode() + b"\r\nConnection: keep-alive\r\n\r\n" + reply)
                line, headers, body = request(peer)
                if line != b"GET /api/1.1/settings HTTP/1.1" or headers.get(b"cookie") != b"authId=" + token.encode() or body:
                    raise RuntimeError("incorrect settings request")
                requests.append("settings")
                reply = b'{"controller":{"addr":"127.0.0.1"},"av":{"video":{"video1":{"avSerializer":{"destinations":null}},"video2":{"avSerializer":{"destinations":["tcp://synthetic-private-destination:1234"],"parameters":{"withOpus":false}}},"video3":{"avSerializer":{"destinations":["file:///dev/null"]}}}},"password":"synthetic-settings-canary","padding":"' + b'x' * 60000 + b'"}'
                peer.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: " + str(len(reply)).encode() + b"\r\nConnection: keep-alive\r\n\r\n" + reply)
                if repeat:
                    line, headers, body = request(peer)
                    if line != b"GET /api/1.1/settings HTTP/1.1" or headers.get(b"cookie") != b"authId=" + token.encode() or body:
                        raise RuntimeError("incorrect repeated settings request")
                    requests.append("settings")
                    if changed:
                        reply = reply.replace(b"synthetic-private-destination", b"synthetic-alternate-destination")
                    peer.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: " + str(len(reply)).encode() + b"\r\nConnection: keep-alive\r\n\r\n" + reply)
                for index in range(1 if disconnect else count):
                    line, headers, body = request(peer)
                    if line != b"GET /snap.jpeg HTTP/1.1" or headers.get(b"cookie") != b"authId=" + token.encode() or body:
                        raise RuntimeError("incorrect snapshot request")
                    requests.append("snapshot")
                    reply = pathlib.Path(jpeg_fixture).read_bytes()
                    connection = b"close" if disconnect or index + 1 == count else b"keep-alive"
                    peer.sendall(b"HTTP/1.1 200 OK\r\nContent-Type: image/jpeg\r\nContent-Length: " + str(len(reply)).encode() + b"\r\nConnection: " + connection + b"\r\n\r\n" + reply)
        except Exception as exc:
            errors.append(type(exc).__name__)
        finally:
            listener.close()

    with tempfile.TemporaryDirectory(prefix="fss-unifi-auth-fixture-") as directory:
        credential = pathlib.Path(directory) / "credential.json"
        fd = os.open(credential, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w") as f:
            json.dump({"username": username, "password": password}, f)
        thread = threading.Thread(target=serve)
        thread.start()
        output = pathlib.Path("/tmp") / ("fss-unifi-snapshot-fixture-" + secrets.token_hex(12) + ".jpg")
        args = [binary, cert_der, "127.0.0.1", "tls13", "match", "sha256:" + "1" * 64, str(credential), str(port), str(output)]
        if count == 3:
            args.append("--three-snapshots")
        if repeat:
            args.append("--repeat-serializers")
        run = subprocess.run(args + ["--serializer-inspect", "--owner-authorized"], capture_output=True, text=True, timeout=20)
        thread.join(timeout=10)
        if thread.is_alive() or errors or requests != ["login", "status", "settings"] + (["settings"] if repeat else []) + ["snapshot"] * (1 if disconnect else count):
            if "message buffer full" in run.stderr:
                print("client failure: TLS message buffer full")
            raise SystemExit("loopback fixture failed: " + ", ".join(errors or ["client or sequence"]))
        if disconnect:
            if run.returncode == 0 or "snapshots_decoded=3" in run.stdout or output.exists():
                raise SystemExit("partial sequence was reported or persisted as complete")
            if any(secret in run.stdout or secret in run.stderr for secret in (username, password, token, "synthetic-settings-canary", "synthetic-private-destination", "synthetic-alternate-destination")):
                raise SystemExit("loopback fixture secret reached process output")
            print("loopback fixture: disconnected sequence failed without completed receipt or output")
            return
        if run.returncode:
            raise SystemExit("loopback fixture failed: client")
        if "login_http_status=200" not in run.stdout or "status_http_status=200" not in run.stdout or "settings_http_status=200" not in run.stdout or "controller_address=reported" not in run.stdout or "controller_matches_connection_source=true" not in run.stdout or "video_destinations=[NotReported, TcpOnly, DiscardOnly]" not in run.stdout or 'serializer_fields=Some([("null", "unknown"), ("array", "false"), ("array", "unknown")])' not in run.stdout or "snapshot_http_status=200" not in run.stdout or f"snapshots_decoded={count}" not in run.stdout or "adjacent_digest_changes=0" not in run.stdout or "decoded_luma=16x16" not in run.stdout or "media_persisted=true" not in run.stdout:
            raise SystemExit("loopback fixture did not decode the expected image")
        if repeat and ("serializer_binding_stable=Some(false)" if changed else "serializer_binding_stable=Some(true)") not in run.stdout:
            raise SystemExit("loopback fixture reported an incorrect serializer binding comparison")
        if any(secret in run.stdout or secret in run.stderr for secret in (username, password, token, "synthetic-settings-canary", "synthetic-private-destination", "synthetic-alternate-destination")):
            raise SystemExit("loopback fixture secret reached process output")
        if output.stat().st_mode & 0o777 != 0o600 or output.read_bytes() != pathlib.Path(jpeg_fixture).read_bytes():
            raise SystemExit("loopback fixture output mismatch")
        output.unlink()
    print(f"loopback fixture: login, status, settings, {count} JPEG decode(s), and private exact output passed; no synthetic secrets in output")


if __name__ == "__main__":
    main()
