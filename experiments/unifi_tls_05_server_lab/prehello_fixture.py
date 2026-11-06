#!/usr/bin/env python3
"""Synthetic TLS peer for the time-sync-before-hello controller ordering."""

import json
import os
import socket
import ssl
import subprocess
import sys
import tempfile
import time
from pathlib import Path

HEAD = (b"GET / HTTP/1.1\r\nHost: camera.local\r\nUpgrade: websocket\r\n"
        b"Connection: Upgrade\r\nSec-WebSocket-Version: 13\r\n"
        b"Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n"
        b"Camera-Mac: 001122aabbcc\r\nSec-WebSocket-Protocol: secure_transfer\r\n\r\n")


def frame(obj):
    data = json.dumps(obj, separators=(",", ":")).encode()
    if len(data) >= 126:
        raise ValueError("fixture message too long")
    mask = b"\x01\x02\x03\x04"
    return bytes((0x82, 0x80 | len(data))) + mask + bytes(b ^ mask[i % 4] for i, b in enumerate(data))


def message(name, message_id, response_to=None, payload=None):
    obj = {"from": "ubnt_avclient", "to": "UniFiVideo", "functionName": name, "messageId": message_id}
    if response_to is not None:
        obj["inResponseTo"] = response_to
    if payload is not None:
        obj["payload"] = payload
    return obj


def exact(sock, n):
    data = bytearray()
    while len(data) < n:
        part = sock.recv(n - len(data))
        if not part:
            raise EOFError("synthetic peer EOF")
        data.extend(part)
    return bytes(data)


def received(sock):
    head = exact(sock, 2)
    if head[0] != 0x82 or head[1] & 0x80:
        raise ValueError("invalid controller frame")
    length = head[1]
    if length == 126:
        length = int.from_bytes(exact(sock, 2), "big")
    if length > 4096:
        raise ValueError("controller frame too long")
    return json.loads(exact(sock, length))


def run_case(binary, cert_der, key_der, directory, coalesced):
    reserve = socket.socket()
    reserve.bind(("127.0.0.1", 0))
    port = reserve.getsockname()[1]
    reserve.close()
    root = Path(directory) / ("coalesced" if coalesced else "sequential")
    root.mkdir(mode=0o700)
    cmd = [binary, f"127.0.0.1:{port}", "127.0.0.1", "001122aabbcc", cert_der, key_der,
           str(root / "journal"), str(root / "clip.mp4"), "12345678-1234-4abc-9abc-123456789abc",
           "60", "--owner-authorized"]
    child = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    try:
        deadline = time.monotonic() + 15
        while True:
            try:
                raw = socket.create_connection(("127.0.0.1", port), timeout=1)
                break
            except OSError:
                if child.poll() is not None or time.monotonic() > deadline:
                    raise RuntimeError("controller did not start")
                time.sleep(0.05)
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE  # Disposable loopback certificate only.
        with ctx.wrap_socket(raw, server_hostname="localhost") as sock:
            sock.settimeout(40)
            sync = frame(message("ubnt_avclient_timeSync", 10))
            hello = frame(message("ubnt_avclient_hello", 7, payload={}))
            started = time.monotonic()
            sock.sendall(HEAD + (sync + hello if coalesced else b""))
            header = bytearray()
            while not header.endswith(b"\r\n\r\n"):
                header.extend(exact(sock, 1))
                if len(header) > 4096:
                    raise ValueError("upgrade limit")
            if not header.startswith(b"HTTP/1.1 101 "):
                raise ValueError("upgrade refused")
            if not coalesced:
                sock.sendall(sync)
            first = received(sock)
            sync_ms = round((time.monotonic() - started) * 1000)
            if first.get("functionName") != "ubnt_avclient_timeSync" or first.get("inResponseTo") != 10:
                raise ValueError("time-sync reply did not correlate")
            payload = first.get("payload")
            if (first.get("from") != "UniFiVideo" or first.get("to") != "ubnt_avclient"
                    or first.get("responseExpected") is not False or not isinstance(payload, dict)
                    or set(payload) != {"t1", "t2"}
                    or any(type(payload[k]) is not int for k in ("t1", "t2"))
                    or payload["t1"] != payload["t2"]
                    or abs(payload["t1"] - int(time.time() * 1000)) > 60_000):
                raise ValueError("time-sync reply envelope or wall time invalid")
            if not coalesced:
                sock.sendall(hello)
            second = received(sock)
            hello_ms = round((time.monotonic() - started) * 1000)
            if second.get("functionName") != "ubnt_avclient_hello" or second.get("inResponseTo") != 7:
                raise ValueError("hello reply did not correlate")
            agreement = received(sock)
            if agreement.get("functionName") != "ubnt_avclient_paramAgreement":
                raise ValueError("agreement missing")
            sock.sendall(frame(message("ubnt_avclient_paramAgreement", 8, agreement["messageId"])))
            stream = received(sock)
            if stream.get("functionName") != "ChangeVideoSettings":
                raise ValueError("stream request missing")
            print(f"case={'coalesced' if coalesced else 'sequential'} sync=correlated hello=correlated agreement=observed stream_request=observed sync_ms={sync_ms} hello_ms={hello_ms}", flush=True)
    finally:
        if child.poll() is None:
            child.terminate()
        try:
            child.communicate(timeout=5)
        except subprocess.TimeoutExpired:
            child.kill()
            child.communicate(timeout=5)


def main():
    if len(sys.argv) != 2:
        raise SystemExit("expected controller binary path")
    with tempfile.TemporaryDirectory(prefix="fss-unifi-prehello-") as directory:
        root = Path(directory)
        cert, key = root / "cert.pem", root / "key.pem"
        cert_der, key_der = root / "cert.der", root / "key.der"
        subprocess.run(["openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256",
                        "-nodes", "-keyout", str(key), "-out", str(cert), "-days", "1", "-subj", "/CN=localhost"],
                       check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        subprocess.run(["openssl", "x509", "-in", str(cert), "-outform", "der", "-out", str(cert_der)], check=True)
        subprocess.run(["openssl", "pkcs8", "-topk8", "-nocrypt", "-in", str(key), "-outform", "der", "-out", str(key_der)], check=True)
        os.chmod(key_der, 0o600)
        run_case(sys.argv[1], str(cert_der), str(key_der), directory, True)
        run_case(sys.argv[1], str(cert_der), str(key_der), directory, False)


if __name__ == "__main__":
    main()
