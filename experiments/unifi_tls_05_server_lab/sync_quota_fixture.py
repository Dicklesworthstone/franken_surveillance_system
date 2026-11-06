#!/usr/bin/env python3
"""Independent loopback check of the opt-in controller time-sync ceiling."""

import os
from pathlib import Path
import socket
import ssl
import subprocess
import sys
import tempfile
import time

from prehello_fixture import HEAD, exact, frame, message, received


def run(binary, cert, key, root):
    reserve = socket.socket()
    reserve.bind(("127.0.0.1", 0))
    port = reserve.getsockname()[1]
    reserve.close()
    command = [binary, f"127.0.0.1:{port}", "127.0.0.1", "001122aabbcc", str(cert), str(key),
               str(root / "journal"), str(root / "clip.mp4"), "12345678-1234-4abc-9abc-123456789abc",
               "60", "--allow-correlated-timesync", "--owner-authorized"]
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
        context.verify_mode = ssl.CERT_NONE  # Disposable local certificate only.
        with context.wrap_socket(raw, server_hostname="localhost") as sock:
            sock.settimeout(20)
            sock.sendall(HEAD)
            header = bytearray()
            while not header.endswith(b"\r\n\r\n"):
                header.extend(exact(sock, 1))
                if len(header) > 4096:
                    raise ValueError("upgrade limit")
            if not header.startswith(b"HTTP/1.1 101 "):
                raise ValueError("upgrade refused")
            for number in range(8):
                request = message("ubnt_avclient_timeSync", 100 + number, 999)
                request["responseExpected"] = True
                sock.sendall(frame(request))
                response = received(sock)
                if response.get("functionName") != "ubnt_avclient_timeSync" or response.get("inResponseTo") != 100 + number:
                    raise ValueError("unexpected reply")
                echo = message("ubnt_avclient_timeSync", 200 + number, response["messageId"])
                echo["responseExpected"] = True
                sock.sendall(frame(echo))
            ninth = message("ubnt_avclient_timeSync", 108, 999)
            ninth["responseExpected"] = True
            sock.sendall(frame(ninth))
            try:
                received(sock)
            except (EOFError, ConnectionResetError, ssl.SSLEOFError):
                pass
            else:
                raise ValueError("ninth reply escaped the ceiling")
        out, err = child.communicate(timeout=10)
        if child.returncode == 0 or b"TimeSyncLimit" not in out + err:
            raise ValueError("missing explicit time-sync limit stop")
        print("quota_fixture replies=8 echoed_replies=ignored ninth=TimeSyncLimit")
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
    with tempfile.TemporaryDirectory(prefix="fss-unifi-sync-quota-") as directory:
        root = Path(directory)
        pem, pem_key = root / "cert.pem", root / "key.pem"
        cert, key = root / "cert.der", root / "key.der"
        subprocess.run(["openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256",
                        "-nodes", "-keyout", str(pem_key), "-out", str(pem), "-days", "1", "-subj", "/CN=localhost"],
                       check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        subprocess.run(["openssl", "x509", "-in", str(pem), "-outform", "der", "-out", str(cert)], check=True)
        subprocess.run(["openssl", "pkcs8", "-topk8", "-nocrypt", "-in", str(pem_key), "-outform", "der", "-out", str(key)], check=True)
        os.chmod(key, 0o600)
        run(sys.argv[1], cert, key, root)


if __name__ == "__main__":
    main()
