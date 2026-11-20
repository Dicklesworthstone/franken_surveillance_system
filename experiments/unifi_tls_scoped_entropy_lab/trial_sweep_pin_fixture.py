#!/usr/bin/env python3
"""Observe a pinned synthetic camera on the final page of a /24 sweep.

Run only in a private network namespace with fssdummy 10.252.15.1/24 and
10.252.15.254 assigned to loopback. All fixture files are private and retained.
"""
import hashlib
import os
from pathlib import Path
import socket
import ssl
import subprocess
import sys

from trial_pin_discovery_fixture import certificate
from trial_profile_fixture import advertisement, serve_http


def main():
    if len(sys.argv) != 3:
        raise SystemExit("expected trial binary and fresh private root")
    binary = str(Path(sys.argv[1]).resolve(strict=True))
    root = Path(sys.argv[2])
    if not root.is_absolute() or not root.is_dir() or root.stat().st_mode & 0o077:
        raise SystemExit("expected private root")
    cert = certificate(root, "camera")
    credential = root / "credential.json"
    with credential.open("x") as handle:
        handle.write('{"username":"fixture","password":"synthetic"}')
    os.chmod(credential, 0o600)
    udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp.bind(("10.252.15.254", 0))
    udp.settimeout(20)
    https = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    https.bind(("10.252.15.254", 0))
    https.listen(2)
    https.settimeout(20)
    server = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    server.minimum_version = ssl.TLSVersion.TLSv1_3
    server.num_tickets = 0
    server.load_cert_chain(*cert[:2])
    args = [binary, "10.252.15.1:7442", "auto", "auto", str(root / "unused-cert"),
            str(root / "unused-key"), str(root / "journal"), str(root / "clip"),
            "12345678-1234-4abc-9abc-123456789abc", "20", "--auto-discovery=24",
            "--discovery-neighbor-interface=fssdummy", "--lab-discovery-sweep-all", "--observe-only",
            f"--setup-camera={udp.getsockname()[1]},{https.getsockname()[1]},{cert[2]},{credential}",
            "--owner-authorized"]
    child = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    try:
        query, source = udp.recvfrom(1024)
        assert query == bytes([1, 0, 0, 0])
        udp.sendto(advertisement("10.252.15.254"), source)
        raw, _ = https.accept()
        raw.settimeout(8)
        with server.wrap_socket(raw, server_side=True) as peer:
            try:
                assert not peer.recv(1), "TLS pin probe sent application data"
            except (ssl.SSLEOFError, ssl.SSLZeroReturnError, ConnectionResetError, BrokenPipeError):
                pass
        raw, _ = https.accept()
        raw.settimeout(8)
        with server.wrap_socket(raw, server_side=True) as peer:
            serve_http(peer, 7442, "10.252.15.1",
                       {"video1": {"width": 2688, "height": 1512, "fps": 30}})
        output, error = child.communicate(timeout=20)
        assert child.returncode == 0, error.decode(errors="replace")
        assert b"trial_discovery_sweep=complete pages=2 windows=5 identity=unverified" in output
        assert b"trial_pin_discovery=matched candidates=1 credentials_sent=false" in output
        assert b"trial_observation=complete" in output
        assert not (root / "journal").exists() and not (root / "clip").exists()
        print("sweep_pin_fixture passed=1 pages=2 camera=synthetic writes=none")

        # The same all-page path must honor an already-existing persistent
        # fence before credentials, camera writes, or journal creation.
        fence = root / "fence"
        fence.mkdir(mode=0o700)
        claim = hashlib.sha256(b"fss.unifi-direct.pinned-camera-claim.v1\0" + cert[2].read_bytes()).hexdigest()
        marker = fence / ("sha256:" + claim + ".fence")
        with marker.open("xb") as handle:
            handle.write(b"prior unresolved synthetic operation")
        os.chmod(marker, 0o600)
        key = root / "controller-key.der"
        subprocess.run(["openssl", "pkcs8", "-topk8", "-nocrypt", "-in", str(cert[1]),
                        "-outform", "der", "-out", str(key)], check=True)
        os.chmod(key, 0o600)
        args = [binary, "10.252.15.1:7442", "auto", "auto", str(cert[2]), str(key),
                str(root / "journal"), str(root / "clip"), "12345678-1234-4abc-9abc-123456789abc",
                "20", "--auto-discovery=24", "--discovery-neighbor-interface=fssdummy",
                "--lab-discovery-sweep-all", "--lab-auto-pinned-setup", f"--lab-setup-fence={fence}",
                f"--anchored-journal={root / 'keeper'},{root / 'trusted'}",
                f"--setup-camera={udp.getsockname()[1]},{https.getsockname()[1]},{cert[2]},{credential}",
                "--owner-authorized"]
        child = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        query, source = udp.recvfrom(1024)
        assert query == bytes([1, 0, 0, 0])
        udp.sendto(advertisement("10.252.15.254"), source)
        raw, _ = https.accept()
        raw.settimeout(8)
        with server.wrap_socket(raw, server_side=True) as peer:
            try:
                assert not peer.recv(1), "fenced pin probe sent application data"
            except (ssl.SSLEOFError, ssl.SSLZeroReturnError, ConnectionResetError, BrokenPipeError):
                pass
        output, error = child.communicate(timeout=20)
        assert child.returncode != 0 and b"setup fence exists; reconcile the previous attempt" in error
        assert b"trial_discovery_sweep=complete pages=2 windows=5" in output
        assert marker.read_bytes() == b"prior unresolved synthetic operation"
        assert all(not (root / name).exists() for name in ("journal", "clip", "keeper", "trusted"))
        print("sweep_pin_fixture fenced_retry=pass credentials_sent=false")
    finally:
        udp.close()
        https.close()
        if child.poll() is None:
            child.terminate()
            child.communicate(timeout=10)


if __name__ == "__main__":
    main()
