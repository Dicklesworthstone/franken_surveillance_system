#!/usr/bin/env python3
"""Check stable versus same-shape changed serializer values with a fake camera."""
import json
import os
from pathlib import Path
import socket
import ssl
import subprocess
import sys

from trial_pin_discovery_fixture import certificate
from trial_profile_fixture import advertisement, exact


def serve(peer, changed):
    routes = (b"POST /api/1.1/login ", b"GET /api/1.1/status ",
              b"GET /api/1.1/settings ", b"GET /api/1.1/settings ",
              b"GET /api/1.1/settings ", b"GET /api/1.1/settings ")
    private_values = ("tcp://10.252.15.11:7000", "tcp://10.252.15.12:7000")
    for index, route in enumerate(routes):
        header = bytearray()
        while not header.endswith(b"\r\n\r\n"):
            header.extend(exact(peer, 1))
            if len(header) > 8192:
                raise ValueError("request header too large")
        if not header.startswith(route):
            raise ValueError("unexpected request")
        size = next((int(line.split(b":", 1)[1]) for line in bytes(header).split(b"\r\n")
                     if line.lower().startswith(b"content-length:")), 0)
        if size > 4096:
            raise ValueError("request body too large")
        exact(peer, size)
        if index == 0:
            body = b"{}"
        elif index == 1:
            body = b'{"controller":{"port":7442}}'
        else:
            destination = private_values[1 if changed and index == 5 else 0]
            body = json.dumps({"controller": {"addr": "10.252.15.1"}, "av": {"video": {
                "video1": {"width": 2688, "height": 1512, "fps": 30,
                           "avSerializer": {"type": "extendedFlv", "destinations": [destination]}}
            }}}, separators=(",", ":")).encode()
        cookie = b"Set-Cookie: authId=fixture-cookie\r\n" if index == 0 else b""
        peer.sendall(b"HTTP/1.1 200 OK\r\n" + cookie + b"Content-Length: " + str(len(body)).encode()
                     + b"\r\nConnection: keep-alive\r\n\r\n" + body)


def run(binary, root, cert, changed):
    case = root / ("changed" if changed else "stable")
    case.mkdir(mode=0o700)
    credential = case / "credential.json"
    with credential.open("x") as handle:
        handle.write('{"username":"fixture","password":"synthetic"}')
    os.chmod(credential, 0o600)
    udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp.bind(("10.252.15.2", 0))
    udp.settimeout(15)
    https = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    https.bind(("10.252.15.2", 0))
    https.listen(2)
    https.settimeout(15)
    server = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    server.minimum_version = ssl.TLSVersion.TLSv1_3
    server.num_tickets = 0
    server.load_cert_chain(*cert[:2])
    args = [binary, "10.252.15.1:7442", "auto", "auto", str(case / "unused-cert"),
            str(case / "unused-key"), str(case / "journal"), str(case / "clip"),
            "12345678-1234-4abc-9abc-123456789abc", "20", "--auto-discovery=24",
            "--discovery-neighbor-interface=fssdummy", "--observe-only", "--observe-serializers",
            f"--setup-camera={udp.getsockname()[1]},{https.getsockname()[1]},{cert[2]},{credential}",
            "--owner-authorized"]
    if not changed:
        refused = subprocess.run([arg for arg in args if arg != "--observe-only"],
                                 capture_output=True, timeout=10)
        assert refused.returncode != 0 and b"serializer observation requires --observe-only" in refused.stderr
        assert not (case / "journal").exists() and not (case / "clip").exists()
    child = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    try:
        query, source = udp.recvfrom(1024)
        assert query == bytes([1, 0, 0, 0])
        udp.sendto(advertisement("10.252.15.2"), source)
        raw, _ = https.accept()
        raw.settimeout(8)
        with server.wrap_socket(raw, server_side=True) as peer:
            try:
                assert not peer.recv(1), "pin probe sent application data"
            except (ssl.SSLEOFError, ssl.SSLZeroReturnError, ConnectionResetError, BrokenPipeError):
                pass
        raw, _ = https.accept()
        raw.settimeout(8)
        with server.wrap_socket(raw, server_side=True) as peer:
            serve(peer, changed)
        output, error = child.communicate(timeout=20)
        assert b"trial_video_destinations=[TcpOnly, NotReported, NotReported]" in output
        assert all(value not in output + error for value in (b"10.252.15.11", b"10.252.15.12"))
        if changed:
            assert child.returncode != 0 and b"serializer binding changed between reads" in error
            assert b"trial_serializer_observation=consistent" not in output
            assert b"trial_observation=complete" not in output
        else:
            assert child.returncode == 0, error.decode(errors="replace")
            assert b"trial_serializer_observation=consistent reads=2 values=redacted" in output
            assert b"trial_observation=complete" in output
        assert not (case / "journal").exists() and not (case / "clip").exists()
        print(f"serializer_fixture case={'changed' if changed else 'stable'} result=pass", flush=True)
    finally:
        udp.close()
        https.close()
        if child.poll() is None:
            child.terminate()
            child.communicate(timeout=10)


def main():
    if len(sys.argv) != 3:
        raise SystemExit("expected trial binary and private root")
    binary = str(Path(sys.argv[1]).resolve(strict=True))
    root = Path(sys.argv[2])
    if not root.is_absolute() or not root.is_dir() or root.stat().st_mode & 0o077:
        raise SystemExit("expected private root")
    cert = certificate(root, "camera")
    run(binary, root, cert, False)
    run(binary, root, cert, True)
    print("serializer_fixture passed=2 explicit_targets=0 camera=synthetic")


if __name__ == "__main__":
    main()
