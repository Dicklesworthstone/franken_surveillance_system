#!/usr/bin/env python3
"""Disposable TLS peer for the continuing clock-exchange trial policy.

This uses synthetic media and loopback only; it never contacts a camera.
"""
import os
from pathlib import Path
import socket
import ssl
import statistics
import subprocess
import sys
import tempfile
import time
from urllib.parse import urlsplit

from prehello_fixture import HEAD, exact, frame, message, received


def clock_chain(sock, first_id, count):
    correlation = 0
    elapsed = []
    for index in range(count):
        request = message("ubnt_avclient_timeSync", first_id + index, correlation)
        request["responseExpected"] = True
        started = time.monotonic()
        sock.sendall(frame(request))
        reply = received(sock)
        elapsed.append((time.monotonic() - started) * 1000)
        if (reply.get("functionName") != "ubnt_avclient_timeSync"
                or reply.get("inResponseTo") != first_id + index):
            raise ValueError("clock reply did not match the synthetic request")
        correlation = reply["messageId"]
    return elapsed


def run(binary, root, anchor_parent):
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
    remote_root = anchor_parent / ("anchor-" + root.name)
    command = [binary, f"127.0.0.1:{port}", "127.0.0.1", "001122aabbcc", str(cert), str(key),
               str(root / "journal"), str(root / "clip.mp4"), "12345678-1234-4abc-9abc-123456789abc",
               "60", "--bounded-continuing-clock", "--media-before-reply",
               f"--anchored-journal={root / 'keeper'},{remote_root}", "--owner-authorized"]
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
            startup_elapsed = clock_chain(sock, 100, 10)
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
                established_groups = [clock_chain(sock, 300, 10), clock_chain(sock, 400, 10), clock_chain(sock, 500, 10)]
                established_elapsed = sum(established_groups, [])
        out, err = child.communicate(timeout=15)
        if child.returncode == 0 or b"trial_complete " in out or (root / "clip.mp4").exists():
            raise ValueError("synthetic header must not produce a clip")
        if b"trial_journal=anchored" not in out:
            raise ValueError("anchored journal not reported")
        inspect = subprocess.run([binary,"--inspect-anchored",str(root / "journal"),str(root / "keeper"),
                                  str(remote_root),"12345678-1234-4abc-9abc-123456789abc",
                                  "001122aabbcc","--owner-authorized"],capture_output=True,timeout=30)
        if inspect.returncode != 0 or b"trial_recovery=reconciliation_only" not in inspect.stdout:
            raise ValueError("separate-process reconciliation inspection failed")
        print("continuing_clock_fixture startup_replies=10 established_chains=3 established_replies=30 clip=none")
        print(f"reply_latency_ms startup_p50={statistics.median(startup_elapsed):.1f} startup_max={max(startup_elapsed):.1f} "
              f"established_p50={statistics.median(established_elapsed):.1f} established_max={max(established_elapsed):.1f}")
        print("reply_latency_batch_p50_ms " + " ".join(f"batch{i}={statistics.median(group):.1f}" for i,group in enumerate([startup_elapsed]+established_groups)))
        print(inspect.stdout.decode().strip())
        print(f"fixture_local={root} fixture_anchor={remote_root} retention=explicit")
    finally:
        if child.poll() is None:
            child.terminate()
        try:
            child.communicate(timeout=5)
        except subprocess.TimeoutExpired:
            child.kill()
            child.communicate(timeout=5)


if __name__ == "__main__":
    if len(sys.argv) != 4:
        raise SystemExit("expected Rust binary, new local directory, and private anchor parent")
    binary, root, parent = Path(sys.argv[1]), Path(sys.argv[2]), Path(sys.argv[3])
    if not all(p.is_absolute() for p in (binary,root,parent)) or not parent.is_dir() or parent.stat().st_mode & 0o077:
        raise SystemExit("invalid fixture paths")
    root.mkdir(mode=0o700)
    run(str(binary), root, parent)
