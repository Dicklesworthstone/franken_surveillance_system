#!/usr/bin/env python3
"""Disposable loopback test of discovery-to-pinned-HTTPS selection.

No real camera or credentials are used, and no camera settings are written.
"""
import os
from pathlib import Path
import socket
import ssl
import subprocess
import sys
import tempfile
import threading


MAC = bytes.fromhex("001122aabbcc")


def certificate(root, name):
    pem, key, der, key_der = (root / (name + suffix) for suffix in (".pem", ".key", ".der", ".key.der"))
    subprocess.run(["openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes", "-keyout", str(key), "-out", str(pem), "-days", "1", "-subj", "/CN=localhost"], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    subprocess.run(["openssl", "x509", "-in", str(pem), "-outform", "der", "-out", str(der)], check=True)
    subprocess.run(["openssl", "pkcs8", "-topk8", "-nocrypt", "-in", str(key), "-outform", "der", "-out", str(key_der)], check=True)
    os.chmod(key_der, 0o600)
    return pem, key, der, key_der


def advertisement(mac):
    address = mac + socket.inet_aton("127.0.0.1")
    body = b"".join(bytes([kind]) + len(value).to_bytes(2, "big") + value for kind, value in (
        (1, mac), (2, address), (3, b"UVC.fixture"), (12, b"UVC G4 Instant")))
    return b"\x01\x00" + len(body).to_bytes(2, "big") + body


def run(binary, root, cert, other, mode):
    root.mkdir(mode=0o700)
    udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp.bind(("0.0.0.0", 0))
    udp.settimeout(12)
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    listener.settimeout(12)
    reserve = socket.socket()
    reserve.bind(("127.0.0.1", 0))
    controller_port = reserve.getsockname()[1]
    reserve.close()
    server = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    server.minimum_version = ssl.TLSVersion.TLSv1_3
    server.load_cert_chain(cert[0], cert[1])
    outcome = {"queries": 0, "connections": 0, "handshakes": 0, "error": None}

    def peer():
        try:
            _, source = udp.recvfrom(1024)
            outcome["queries"] += 1
            udp.sendto(advertisement(bytes.fromhex("021122aabbcc") if mode == "unknown" else MAC), source)
            if mode == "conflict":
                udp.sendto(advertisement(bytes.fromhex("021122aabbcc")), source)
            if mode in ("unknown", "conflict"):
                return
            raw, _ = listener.accept()
            outcome["connections"] += 1
            try:
                with server.wrap_socket(raw, server_side=True):
                    outcome["handshakes"] += 1
            except ssl.SSLError:
                if mode != "wrong-pin":
                    raise
        except Exception as error:
            outcome["error"] = repr(error)

    worker = threading.Thread(target=peer)
    worker.start()
    pin = other[2] if mode == "wrong-pin" else cert[2]
    journal, output = root / "journal", root / "clip.mp4"
    command = [binary, f"127.0.0.1:{controller_port}", "auto", MAC.hex(), str(cert[2]), str(cert[3]), str(journal), str(output), "12345678-1234-4abc-9abc-123456789abc", "10", "--auto-discovery=24", f"--setup-camera={udp.getsockname()[1]},{listener.getsockname()[1]},{pin},{root / 'absent-credential'}", "--owner-authorized"]
    try:
        process = subprocess.run(command, capture_output=True, timeout=30)
        worker.join(timeout=15)
        if worker.is_alive() or outcome["error"] or outcome["queries"] != 1 or process.returncode == 0:
            raise RuntimeError(f"fixture did not finish correctly: {mode} {outcome}")
        expected = {"unknown": b"NotObserved", "conflict": b"Conflicted", "wrong-pin": b"Handshake", "matched-pin": b"private credential unavailable"}[mode]
        if expected not in process.stdout + process.stderr:
            raise RuntimeError(f"unexpected result for {mode}: {(process.stdout + process.stderr).decode(errors='replace')}")
        if mode in ("unknown", "conflict"):
            if journal.exists() or outcome["connections"]:
                raise RuntimeError("unselected claim reached setup")
        elif outcome["connections"] != 1 or not journal.is_dir() or outcome["handshakes"] != int(mode == "matched-pin"):
            raise RuntimeError(f"unexpected TLS path: {mode} {outcome}")
        if output.exists():
            raise RuntimeError("fixture unexpectedly produced media")
        print(f"auto_discovery_fixture mode={mode} result=expected")
    finally:
        udp.close()
        listener.close()
        worker.join(timeout=15)


def main():
    if len(sys.argv) != 2:
        raise SystemExit("expected trial binary path")
    with tempfile.TemporaryDirectory(prefix="fss-auto-discovery-") as directory:
        root = Path(directory)
        cert, other = certificate(root, "camera"), certificate(root, "other")
        for mode in ("unknown", "conflict", "wrong-pin", "matched-pin"):
            run(sys.argv[1], root / mode, cert, other, mode)


if __name__ == "__main__":
    main()
