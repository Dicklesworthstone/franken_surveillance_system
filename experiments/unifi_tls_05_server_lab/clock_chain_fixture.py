#!/usr/bin/env python3
"""Independent disposable TLS peer for the opt-in pre-hello clock chain.

Only loopback sockets and a freshly generated certificate are used. This
fixture does not contact a camera or establish device authentication.
"""

import os
from pathlib import Path
import socket
import ssl
import subprocess
import sys
import tempfile
import time

from prehello_fixture import HEAD, exact, frame, message, received


def run(binary, cert, key, root, quota, mixed=False, uncorrelated=False, coalesced=False, startup_request=False):
    reserve = socket.socket()
    reserve.bind(("127.0.0.1", 0))
    port = reserve.getsockname()[1]
    reserve.close()
    root.mkdir(mode=0o700)
    command = [binary, f"127.0.0.1:{port}", "127.0.0.1", "001122aabbcc",
               str(cert), str(key), str(root / "journal"), str(root / "clip.mp4"),
               "12345678-1234-4abc-9abc-123456789abc", "60",
               "--bounded-prehello-clock"]
    if startup_request:
        command.extend(["--media-before-reply", "--reply-startup-requests"])
    command.append("--owner-authorized")
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
            if startup_request:
                request = message("FutureCameraRequest", 80, payload={"synthetic": "fixture"})
                request["responseExpected"] = True
                sock.sendall(frame(request))
                reply = received(sock)
                if (reply.get("functionName") != "FutureCameraRequest"
                        or reply.get("inResponseTo") != 80
                        or reply.get("payload") != {"synthetic": "fixture"}):
                    raise ValueError("invalid startup request reply")
            correlation = 999
            count = 32 if quota else 12
            if coalesced:
                # Real transports can deliver several camera frames in one
                # read. Coalesce hello too, so buffered requests are drained
                # before the controller can advance its handshake.
                requests = []
                for index in range(count):
                    request = message("ubnt_avclient_timeSync", 100 + index, 0)
                    request["responseExpected"] = False
                    requests.append(frame(request))
                requests.append(frame(message("ubnt_avclient_hello", 200, payload={})))
                sock.sendall(b"".join(requests))
            for index in range(count):
                response_to = 0 if uncorrelated or (mixed and index % 2 == 0) else correlation
                request = message("ubnt_avclient_timeSync", 100 + index, response_to)
                request["responseExpected"] = False
                if not coalesced:
                    sock.sendall(frame(request))
                reply = received(sock)
                if (reply.get("functionName") != "ubnt_avclient_timeSync"
                        or reply.get("inResponseTo") != 100 + index):
                    raise ValueError("invalid clock reply")
                correlation = reply["messageId"]
            if quota:
                sock.sendall(frame(message("ubnt_avclient_timeSync", 132, 0 if uncorrelated else correlation)))
                try:
                    received(sock)
                except (EOFError, ConnectionResetError, ssl.SSLEOFError):
                    pass
                else:
                    raise ValueError("33rd reply escaped quota")
            else:
                if not coalesced:
                    sock.sendall(frame(message("ubnt_avclient_hello", 200, payload={})))
                hello = received(sock)
                agreement = received(sock)
                if hello.get("functionName") != "ubnt_avclient_hello" or hello.get("inResponseTo") != 200:
                    raise ValueError("invalid hello reply")
                if agreement.get("functionName") != "ubnt_avclient_paramAgreement":
                    raise ValueError("agreement missing")
                sock.sendall(frame(message("ubnt_avclient_paramAgreement", 201, agreement["messageId"])))
                if received(sock).get("functionName") != "ChangeVideoSettings":
                    raise ValueError("stream request missing")
        if quota:
            out, err = child.communicate(timeout=10)
            if child.returncode == 0 or b"TimeSyncLimit" not in out + err:
                raise ValueError("missing explicit time-sync quota stop")
        mode = 'startup_request' if startup_request else 'coalesced' if coalesced else 'uncorrelated' if uncorrelated else 'mixed' if mixed else 'correlated'
        print(f"clock_chain_fixture mode={mode} replies={count} result={'quota_stop' if quota else 'hello_agreement_stream'}")
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
    with tempfile.TemporaryDirectory(prefix="fss-unifi-clock-chain-") as directory:
        root = Path(directory)
        pem, pem_key = root / "cert.pem", root / "key.pem"
        cert, key = root / "cert.der", root / "key.der"
        subprocess.run(["openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256",
                        "-nodes", "-keyout", str(pem_key), "-out", str(pem), "-days", "1", "-subj", "/CN=localhost"],
                       check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        subprocess.run(["openssl", "x509", "-in", str(pem), "-outform", "der", "-out", str(cert)], check=True)
        subprocess.run(["openssl", "pkcs8", "-topk8", "-nocrypt", "-in", str(pem_key), "-outform", "der", "-out", str(key)], check=True)
        os.chmod(key, 0o600)
        run(sys.argv[1], cert, key, root / "handshake", False)
        run(sys.argv[1], cert, key, root / "quota", True)
        run(sys.argv[1], cert, key, root / "mixed", False, mixed=True)
        run(sys.argv[1], cert, key, root / "uncorrelated-quota", True, uncorrelated=True)
        run(sys.argv[1], cert, key, root / "coalesced", False, coalesced=True)
        run(sys.argv[1], cert, key, root / "startup-request", False, startup_request=True)


if __name__ == "__main__":
    main()
