#!/usr/bin/env python3
"""Compare a Rust lab controller with the reference handler on synthetic input.

The JavaScript handler runs with a fake socket and timer. The Rust controller
uses a disposable loopback TLS peer. Neither side contacts a real camera.
"""
import datetime
import json
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

UUID = "12345678-1234-4abc-9abc-123456789abc"


def oracle(script, reference, request):
    result = subprocess.run(
        ["node", str(script), str(reference)],
        input=json.dumps({"uuid": UUID, "message": request}),
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=True,
        timeout=10,
    )
    return json.loads(result.stdout)


def stream_oracle(script, reference, host, port):
    result = subprocess.run(
        ["node", str(script), str(reference)],
        input=json.dumps({"mode": "stream", "host": host, "port": port}),
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=True,
        timeout=10,
    )
    return json.loads(result.stdout)


def compare(actual, expected):
    assert actual["functionName"] == expected["name"]
    assert actual["inResponseTo"] == expected["responseTo"]
    assert actual["responseExpected"] is expected["expected"]
    assert actual["from"] == "UniFiVideo" and actual["to"] == "ubnt_avclient"
    assert type(actual["messageId"]) is int and actual["messageId"] > 0
    datetime.datetime.fromisoformat(actual["timeStamp"].replace("Z", "+00:00"))
    if expected["name"] == "ubnt_avclient_timeSync":
        now = int(time.time() * 1000)
        for key in ("t1", "t2"):
            assert type(actual["payload"][key]) is int
            assert abs(actual["payload"][key] - now) < 30_000
            assert type(expected["payload"][key]) is int
            assert abs(expected["payload"][key] - now) < 30_000
    elif expected["name"] == "ubnt_avclient_hello":
        expected_payload = dict(expected["payload"])
        # Controller names are owner configuration, not a protocol constant.
        assert actual["payload"]["controllerName"] == "FSS"
        assert expected_payload.pop("controllerName") == "Scrypted"
        actual_payload = dict(actual["payload"])
        actual_payload.pop("controllerName")
        assert actual_payload == expected_payload
    else:
        assert actual["payload"] == expected["payload"]


def run(binary, reference, script, root):
    pem, pem_key, cert, key = (root / name for name in ("cert.pem", "key.pem", "cert.der", "key.der"))
    subprocess.run(["openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256",
                    "-nodes", "-keyout", str(pem_key), "-out", str(pem), "-days", "1", "-subj", "/CN=localhost"],
                   check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    subprocess.run(["openssl", "x509", "-in", str(pem), "-outform", "der", "-out", str(cert)], check=True)
    subprocess.run(["openssl", "pkcs8", "-topk8", "-nocrypt", "-in", str(pem_key), "-outform", "der", "-out", str(key)], check=True)
    os.chmod(key, 0o600)
    reserve = socket.socket()
    reserve.bind(("127.0.0.1", 0))
    port = reserve.getsockname()[1]
    reserve.close()
    command = [binary, f"127.0.0.1:{port}", "127.0.0.1", "001122aabbcc", str(cert), str(key),
               str(root / "journal"), str(root / "clip.mp4"), UUID, "60", "--bounded-prehello-clock",
               "--media-before-reply", "--reply-events", "--reply-startup-requests", "--owner-authorized"]
    child = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    try:
        deadline = time.monotonic() + 15
        while True:
            try:
                raw = socket.create_connection(("127.0.0.1", port), timeout=1)
                break
            except OSError:
                if child.poll() is not None or time.monotonic() >= deadline:
                    raise RuntimeError("controller did not start")
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
            first = message("ubnt_avclient_timeSync", 100, 0)
            before = time.monotonic()
            sock.sendall(frame(first))
            first_reply = received(sock)
            first_reply_ms = (time.monotonic() - before) * 1000
            compare(first_reply, oracle(script, reference, first)[0])
            second = message("ubnt_avclient_timeSync", 101, first_reply["messageId"])
            sock.sendall(frame(second))
            compare(received(sock), oracle(script, reference, second)[0])
            for index, payload in enumerate((None, False, {"synthetic": [1, "two", True]})):
                request = message("FutureCameraRequest", 110 + index)
                request["payload"] = payload
                request["responseExpected"] = True
                sock.sendall(frame(request))
                compare(received(sock), oracle(script, reference, request)[0])
            event = message("EventSmartAudio", 120, payload={"synthetic": True})
            event["responseExpected"] = True
            sock.sendall(frame(event))
            compare(received(sock), oracle(script, reference, event)[0])
            hello = message("ubnt_avclient_hello", 200, payload={"protocolVersion": 72})
            expected = oracle(script, reference, hello)
            assert len(expected) == 2
            sock.sendall(frame(hello))
            compare(received(sock), expected[0])
            agreement = received(sock)
            compare(agreement, expected[1])
            sock.sendall(frame(message("ubnt_avclient_paramAgreement", 201, agreement["messageId"])))
            stream = received(sock)
            destination = urlsplit(stream["payload"]["video"]["video2"]["avSerializer"]["destinations"][0])
            assert destination.scheme == "tcp" and destination.hostname == "127.0.0.1"
            assert destination.port is not None
            expected_stream = stream_oracle(script, reference, destination.hostname, destination.port)
            assert len(expected_stream) == 1
            compare(stream, expected_stream[0])
        print("differential_startup clock=2 unknown_requests=3 event=1 hello=1 agreement=1 stream_request=1 "
              f"first_clock_reply_ms={first_reply_ms:.1f}")
    finally:
        if child.poll() is None:
            child.terminate()
        try:
            child.communicate(timeout=5)
        except subprocess.TimeoutExpired:
            child.kill()
            child.communicate(timeout=5)


if __name__ == "__main__":
    if len(sys.argv) != 3:
        raise SystemExit("expected Rust trial binary and reference controller source")
    with tempfile.TemporaryDirectory(prefix="fss-unifi-startup-differential-") as directory:
        run(sys.argv[1], Path(sys.argv[2]), Path(__file__).with_name("startup_reference_oracle.cjs"), Path(directory))
