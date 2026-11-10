#!/usr/bin/env python3
"""Disposable TLS peer for the continuing clock-exchange trial policy.

This uses synthetic media and loopback only; it never contacts a camera.
"""
import os
from pathlib import Path
import socket
import ssl
import subprocess
import sys
import tempfile
import time
from urllib.parse import urlsplit

from prehello_fixture import HEAD, exact, frame, message, received


def clock_chain(sock, first_id, count):
    correlation = 0
    for index in range(count):
        request = message("ubnt_avclient_timeSync", first_id + index, correlation)
        request["responseExpected"] = True
        sock.sendall(frame(request))
        reply = received(sock)
        if (reply.get("functionName") != "ubnt_avclient_timeSync"
                or reply.get("inResponseTo") != first_id + index):
            raise ValueError("clock reply did not match the synthetic request")
        correlation = reply["messageId"]


def run(binary, root):
    pem, pem_key = root / "cert.pem", root / "key.pem"
    cert, key = root / "cert.der", root / "key.der"
    subprocess.run(["openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256",
                    "-nodes", "-keyout", str(pem_key), "-out", str(pem), "-days", "1", "-subj", "/CN=localhost"],
                   check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    subprocess.run(["openssl", "x509", "-in", str(pem), "-outform", "der", "-out", str(cert)], check=True)
    subprocess.run(["openssl", "pkcs8", "-topk8", "-nocrypt", "-in", str(pem_key), "-outform", "der", "-out", str(key)], check=True)
    os.chmod(key, 0o600)
    with socket.socket() as reserve:
        reserve.bind(("127.0.0.1", 0))
        port = reserve.getsockname()[1]
    command = [binary, f"127.0.0.1:{port}", "127.0.0.1", "001122aabbcc", str(cert), str(key),
               str(root / "journal"), str(root / "clip.mp4"), "12345678-1234-4abc-9abc-123456789abc",
               "60", "--bounded-continuing-clock", "--media-before-reply", "--owner-authorized"]
    child = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    try:
        deadline = time.monotonic() + 20
        while True:
            try:
                raw = socket.create_connection(("127.0.0.1", port), timeout=1)
                break
            except OSError:
                if child.poll() is not None or time.monotonic() >= deadline:
                    raise RuntimeError("synthetic controller did not start")
                time.sleep(0.05)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE  # Disposable loopback certificate only.
        with context.wrap_socket(raw, server_hostname="localhost") as sock:
            sock.settimeout(30)
            sock.sendall(HEAD)
            header = bytearray()
            while not header.endswith(b"\r\n\r\n"):
                header.extend(exact(sock, 1))
                if len(header) > 4096:
                    raise ValueError("upgrade limit")
            if not header.startswith(b"HTTP/1.1 101 "):
                raise ValueError("upgrade refused")
            clock_chain(sock, 100, 10)
            sock.sendall(frame(message("ubnt_avclient_hello", 200, payload={})))
            hello, agreement = received(sock), received(sock)
            if hello.get("inResponseTo") != 200 or agreement.get("functionName") != "ubnt_avclient_paramAgreement":
                raise ValueError("hello or agreement missing")
            sock.sendall(frame(message("ubnt_avclient_paramAgreement", 201, agreement["messageId"])))
            stream = received(sock)
            if stream.get("functionName") != "ChangeVideoSettings":
                raise ValueError("stream request missing")
            destination = urlsplit(stream["payload"]["video"]["video2"]["avSerializer"]["destinations"][0])
            if destination.scheme != "tcp" or destination.hostname != "127.0.0.1" or destination.port is None:
                raise ValueError("unexpected synthetic media destination")
            with socket.create_connection((destination.hostname, destination.port), timeout=5) as media:
                media.sendall(b"FLV\x01\x05\x00\x00\x00\x09\x00\x00\x00\x00")
                clock_chain(sock, 300, 10)
                clock_chain(sock, 400, 10)
                clock_chain(sock, 500, 10)
        out, err = child.communicate(timeout=15)
        if child.returncode == 0 or b"trial_complete " in out or (root / "clip.mp4").exists():
            raise ValueError("synthetic header must not produce a clip")
        print("continuing_clock_fixture startup_replies=10 established_chains=3 established_replies=30 clip=none")
    finally:
        if child.poll() is None:
            child.terminate()
        try:
            child.communicate(timeout=5)
        except subprocess.TimeoutExpired:
            child.kill()
            child.communicate(timeout=5)


if __name__ == "__main__":
    if len(sys.argv) != 2:
        raise SystemExit("expected Rust trial binary path")
    with tempfile.TemporaryDirectory(prefix="fss-continuing-clock-") as directory:
        run(sys.argv[1], Path(directory))
