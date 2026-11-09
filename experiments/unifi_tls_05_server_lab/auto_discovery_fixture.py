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


def run(binary, root, cert, other, mode, jpeg):
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
    # Observation has no reason to bind the controller port. Keep it occupied
    # so this fixture fails if the trial accidentally tries to listen there.
    if mode not in ("observe", "snapshot"):
        reserve.close()
    server = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    server.minimum_version = ssl.TLSVersion.TLSv1_3
    server.load_cert_chain(cert[0], cert[1])
    outcome = {"queries": 0, "connections": 0, "handshakes": 0, "error": None}

    def peer():
        try:
            _, source = udp.recvfrom(1024)
            outcome["queries"] += 1
            # Simulate a camera that does not answer the directed broadcast.
            _, second_source = udp.recvfrom(1024)
            outcome["queries"] += 1
            if second_source != source:
                raise ValueError("discovery sender changed between broadcasts")
            if mode in ("unicast-hint", "observe", "snapshot"):
                _, third_source = udp.recvfrom(1024)
                outcome["queries"] += 1
                if third_source != source:
                    raise ValueError("discovery sender changed for hint")
            udp.sendto(advertisement(bytes.fromhex("021122aabbcc") if mode == "unknown" else MAC), source)
            if mode == "conflict":
                udp.sendto(advertisement(bytes.fromhex("021122aabbcc")), source)
            if mode in ("unknown", "conflict"):
                return
            raw, _ = listener.accept()
            outcome["connections"] += 1
            try:
                with server.wrap_socket(raw, server_side=True) as tls:
                    outcome["handshakes"] += 1
                    if mode in ("observe", "snapshot"):
                        tls.settimeout(5)
                        routes = (b"POST /api/1.1/login ", b"GET /api/1.1/status ", b"GET /api/1.1/settings ", b"GET /api/1.1/settings ")
                        if mode == "snapshot":
                            routes += (b"GET /snap.jpeg ",)
                        for index, route in enumerate(routes):
                            header = bytearray()
                            while not header.endswith(b"\r\n\r\n"):
                                byte = tls.recv(1)
                                if not byte or len(header) >= 8192:
                                    raise ValueError("invalid HTTP header")
                                header.extend(byte)
                            if not header.startswith(route):
                                raise ValueError("unexpected camera request")
                            length = next((int(line.split(b":", 1)[1]) for line in bytes(header).split(b"\r\n") if line.lower().startswith(b"content-length:")), 0)
                            if length > 4096:
                                raise ValueError("HTTP body limit")
                            body = bytearray()
                            while len(body) < length:
                                part = tls.recv(length - len(body))
                                if not part:
                                    raise ValueError("incomplete HTTP body")
                                body.extend(part)
                            payload = (b'{}' if index == 0 else b'{"controller":{"port":7442}}' if index == 1 else jpeg if index == 4 else b'{"controller":{"addr":"192.168.1.10"}}')
                            cookie = b"Set-Cookie: authId=fixture-cookie\r\n" if index == 0 else b""
                            tls.sendall(b"HTTP/1.1 200 OK\r\n" + cookie + b"Content-Length: " + str(len(payload)).encode() + b"\r\nConnection: keep-alive\r\n\r\n" + payload)
                        if tls.recv(1):
                            raise ValueError("unexpected request after observation")
            except ssl.SSLError:
                if mode != "wrong-pin":
                    raise
        except Exception as error:
            outcome["error"] = repr(error)

    worker = threading.Thread(target=peer)
    worker.start()
    pin = other[2] if mode == "wrong-pin" else cert[2]
    journal, output = root / "journal", root / "clip.mp4"
    controller_cert = root / "absent-controller-cert" if mode in ("observe", "snapshot") else cert[2]
    controller_key = root / "absent-controller-key" if mode in ("observe", "snapshot") else cert[3]
    command = [binary, f"127.0.0.1:{controller_port}", "auto", MAC.hex(), str(controller_cert), str(controller_key), str(journal), str(output), "12345678-1234-4abc-9abc-123456789abc", "10", "--auto-discovery=24"]
    if mode in ("unicast-hint", "observe", "snapshot"):
        command.append("--discovery-hint=127.0.0.1")
    credential = root / "absent-credential"
    if mode in ("observe", "snapshot"):
        credential = root / "fixture-credential"
        credential.write_text('{"username":"fixture","password":"synthetic"}')
        os.chmod(credential, 0o600)
        command.append("--observe-only")
        if mode == "snapshot":
            command.append("--observe-snapshot")
    command.extend([f"--setup-camera={udp.getsockname()[1]},{listener.getsockname()[1]},{pin},{credential}", "--owner-authorized"])
    try:
        process = subprocess.run(command, capture_output=True, timeout=30)
        worker.join(timeout=15)
        if worker.is_alive() or outcome["error"] or outcome["queries"] != (3 if mode in ("unicast-hint", "observe", "snapshot") else 2) or (process.returncode == 0) != (mode in ("observe", "snapshot")):
            raise RuntimeError(f"fixture did not finish correctly: {mode} {outcome}")
        expected = {"unknown": b"NotObserved", "conflict": b"Conflicted", "wrong-pin": b"Handshake", "matched-pin": b"private credential unavailable", "unicast-hint": b"private credential unavailable", "observe": b"trial_observation=complete", "snapshot": b"trial_snapshot=decoded width=16 height=16"}[mode]
        if expected not in process.stdout + process.stderr:
            raise RuntimeError(f"unexpected result for {mode}: {(process.stdout + process.stderr).decode(errors='replace')}")
        if mode in ("unknown", "conflict"):
            if journal.exists() or outcome["connections"]:
                raise RuntimeError("unselected claim reached setup")
        elif outcome["connections"] != 1 or journal.is_dir() == (mode in ("observe", "snapshot")) or outcome["handshakes"] != int(mode in ("matched-pin", "unicast-hint", "observe", "snapshot")):
            raise RuntimeError(f"unexpected TLS path: {mode} {outcome}")
        if output.exists():
            raise RuntimeError("fixture unexpectedly produced media")
        print(f"auto_discovery_fixture mode={mode} result=expected")
    finally:
        reserve.close()
        udp.close()
        listener.close()
        worker.join(timeout=15)


def main():
    if len(sys.argv) != 3:
        raise SystemExit("expected trial binary path and synthetic JPEG fixture")
    jpeg = Path(sys.argv[2]).read_bytes()
    with tempfile.TemporaryDirectory(prefix="fss-auto-discovery-") as directory:
        root = Path(directory)
        cert, other = certificate(root, "camera"), certificate(root, "other")
        for mode in ("unknown", "conflict", "wrong-pin", "matched-pin", "unicast-hint", "observe", "snapshot"):
            run(sys.argv[1], root / mode, cert, other, mode, jpeg)


if __name__ == "__main__":
    main()
