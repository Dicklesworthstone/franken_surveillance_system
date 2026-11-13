#!/usr/bin/env python3
"""Loopback-only pinned-discovery checks; retain all synthetic fixture files.

Usage: trial_pin_discovery_fixture.py TRIAL_BINARY NEW_ABSOLUTE_DIRECTORY
No camera, real credential, or non-loopback test peer is used.
"""
import os
from pathlib import Path
import socket
import ssl
import subprocess
import sys

from trial_profile_fixture import MAC, advertisement, serve_http


def certificate(root, name):
    pem, key, der = (root / (name + suffix) for suffix in (".pem", ".key", ".der"))
    subprocess.run(["openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes", "-keyout", str(key), "-out", str(pem), "-days", "1", "-subj", "/CN=synthetic"], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    subprocess.run(["openssl", "x509", "-in", str(pem), "-outform", "der", "-out", str(der)], check=True)
    os.chmod(key, 0o600)
    return pem, key, der


def run_case(binary, root, server_cert, supplied_pin, name, expected):
    case = root / name
    case.mkdir(mode=0o700)
    credential = case / "credential.json"
    if expected:
        credential.write_text('{"username":"fixture","password":"synthetic"}')
        os.chmod(credential, 0o600)
    udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp.bind(("127.0.0.1", 0))
    udp.settimeout(15)
    https = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    https.bind(("127.0.0.1", 0))
    https.listen(2)
    https.settimeout(15)
    server = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    server.minimum_version = ssl.TLSVersion.TLSv1_3
    server.load_cert_chain(*server_cert[:2])
    args = [str(binary), "127.0.0.1:7442", "auto", "auto", str(case / "unused-cert"), str(case / "unused-key"), str(case / "journal"), str(case / "clip"), "12345678-1234-4abc-9abc-123456789abc", "20", "--auto-discovery=32", "--observe-only", f"--setup-camera={udp.getsockname()[1]},{https.getsockname()[1]},{supplied_pin},{credential}", "--owner-authorized"]
    child = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    try:
        _, source = udp.recvfrom(1024)
        udp.sendto(advertisement("127.0.0.1"), source)
        raw, _ = https.accept()
        raw.settimeout(8)
        try:
            with server.wrap_socket(raw, server_side=True) as peer:
                try:
                    if peer.recv(1):
                        raise AssertionError("TLS pin probe sent application data")
                except (ssl.SSLEOFError, ssl.SSLZeroReturnError):
                    pass
        except ssl.SSLError:
            if expected:
                raise
        if expected:
            raw, _ = https.accept()
            raw.settimeout(8)
            with server.wrap_socket(raw, server_side=True) as peer:
                serve_http(peer, 7442, "127.0.0.1", {"video1": {"width": 2688, "height": 1512, "fps": 30}})
        output, error = child.communicate(timeout=20)
        if expected:
            assert child.returncode == 0, error.decode(errors="replace")
            assert b"trial_pin_discovery=matched candidates=1 credentials_sent=false" in output
            assert b"trial_observation=complete" in output
            assert b"trial_reported_video=Some((Video1" in output
        else:
            assert child.returncode != 0
            assert b"no discovered candidate matched the camera pin" in error
            assert not credential.exists()
        assert not (case / "journal").exists() and not (case / "clip").exists()
        print(f"pin_discovery_fixture case={name} result=pass", flush=True)
    finally:
        udp.close()
        https.close()
        if child.poll() is None:
            child.terminate()
            child.communicate(timeout=10)


def run_ambiguous(binary, root, cert):
    case = root / "ambiguous"
    case.mkdir(mode=0o700)
    udp1 = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp1.bind(("127.0.0.1", 0))
    udp1.settimeout(15)
    udp2 = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp2.bind(("127.0.0.2", udp1.getsockname()[1]))
    https1 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    https1.bind(("127.0.0.1", 0))
    https1.listen(1)
    https1.settimeout(15)
    https2 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    https2.bind(("127.0.0.2", https1.getsockname()[1]))
    https2.listen(1)
    https2.settimeout(15)
    server = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    server.minimum_version = ssl.TLSVersion.TLSv1_3
    server.load_cert_chain(*cert[:2])
    credential = case / "absent-credential.json"
    args = [str(binary), "127.0.0.1:7442", "auto", "auto", str(case / "unused-cert"), str(case / "unused-key"), str(case / "journal"), str(case / "clip"), "12345678-1234-4abc-9abc-123456789abc", "20", "--auto-discovery=8", "--discovery-hint=127.0.0.1", "--observe-only", f"--setup-camera={udp1.getsockname()[1]},{https1.getsockname()[1]},{cert[2]},{credential}", "--owner-authorized"]
    child = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    try:
        _, source = udp1.recvfrom(1024)
        udp1.sendto(advertisement("127.0.0.1"), source)
        second_mac = bytes.fromhex("002233bbccdd")
        udp2.sendto(advertisement("127.0.0.2").replace(MAC, second_mac), source)
        for listener in (https1, https2):
            raw, _ = listener.accept()
            raw.settimeout(8)
            with server.wrap_socket(raw, server_side=True) as peer:
                try:
                    if peer.recv(1):
                        raise AssertionError("ambiguous pin probe sent application data")
                except (ssl.SSLEOFError, ssl.SSLZeroReturnError):
                    pass
        _, error = child.communicate(timeout=20)
        assert child.returncode != 0
        assert b"multiple candidates matched the camera pin" in error
        assert not credential.exists()
        assert not (case / "journal").exists() and not (case / "clip").exists()
        print("pin_discovery_fixture case=ambiguous result=pass", flush=True)
    finally:
        for sock in (udp1, udp2, https1, https2):
            sock.close()
        if child.poll() is None:
            child.terminate()
            child.communicate(timeout=10)


def main():
    if len(sys.argv) != 3:
        raise SystemExit(__doc__)
    binary = Path(sys.argv[1]).resolve(strict=True)
    root = Path(sys.argv[2])
    if not root.is_absolute() or root.exists():
        raise SystemExit("fixture directory must be absent and absolute")
    root.mkdir(mode=0o700)
    first = certificate(root, "first")
    second = certificate(root, "second")
    run_case(binary, root, first, first[2], "match", True)
    run_case(binary, root, first, second[2], "wrong-pin", False)
    run_ambiguous(binary, root, first)


if __name__ == "__main__":
    main()
