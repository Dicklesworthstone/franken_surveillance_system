#!/usr/bin/env python3
"""Fake-camera pinned discovery via cached neighbors in a private network namespace.

Requires fssdummy at 10.252.15.1/24 and a complete neighbor entry for the
synthetic 10.252.15.2 address, which is also local on loopback. It retains all
fixture files and sends no packets to the physical network.
"""
import os
from pathlib import Path
import socket
import ssl
import subprocess
import sys

from trial_pin_discovery_fixture import certificate
from trial_profile_fixture import advertisement, serve_http


def scope_controls(binary, root, pin):
    udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp.bind(("10.252.15.2", 0))
    udp.settimeout(0.25)
    try:
        for name, prefix, interface in (("wrong-interface", 24, "lo"),
                                        ("too-wide", 23, "fssdummy")):
            case = root / name
            case.mkdir(mode=0o700)
            args = [binary, "10.252.15.1:7442", "auto", "auto", str(case / "unused-cert"),
                    str(case / "unused-key"), str(case / "journal"), str(case / "clip"),
                    "12345678-1234-4abc-9abc-123456789abc", "20", f"--auto-discovery={prefix}",
                    f"--discovery-neighbor-interface={interface}", "--observe-only",
                    f"--setup-camera={udp.getsockname()[1]},443,{pin},{case / 'missing-credential'}",
                    "--owner-authorized"]
            result = subprocess.run(args, capture_output=True, timeout=15)
            assert result.returncode != 0 and b"neighbor discovery refused: Configuration" in result.stderr
            assert b"trial_neighbor_discovery=hints" not in result.stdout
            assert not (case / "missing-credential").exists() and not (case / "journal").exists()
            try:
                udp.recvfrom(1024)
            except TimeoutError:
                pass
            else:
                raise AssertionError("scope refusal sent a discovery query")
            print(f"neighbor_pin_fixture case={name} result=pass", flush=True)
    finally:
        udp.close()


def run_case(binary, root, server_cert, supplied_pin, name, expected):
    case = root / name
    case.mkdir(mode=0o700)
    credential = case / "credential.json"
    if expected:
        credential.write_text('{"username":"fixture","password":"synthetic"}')
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
    server.load_cert_chain(*server_cert[:2])
    args = [binary, "10.252.15.1:7442", "auto", "auto", str(case / "unused-cert"), str(case / "unused-key"), str(case / "journal"), str(case / "clip"), "12345678-1234-4abc-9abc-123456789abc", "20", "--auto-discovery=24", "--discovery-neighbor-interface=fssdummy", "--observe-only", f"--setup-camera={udp.getsockname()[1]},{https.getsockname()[1]},{supplied_pin},{credential}", "--owner-authorized"]
    child = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    try:
        try:
            query, source = udp.recvfrom(1024)
        except TimeoutError as error:
            if child.poll() is not None:
                _, stderr = child.communicate()
                raise RuntimeError(f"trial stopped before discovery: exit={child.returncode} stderr={stderr.decode(errors='replace')[:500]}") from error
            raise
        if query != bytes([1, 0, 0, 0]):
            raise RuntimeError("unexpected discovery query")
        udp.sendto(advertisement("10.252.15.2"), source)
        raw, _ = https.accept()
        raw.settimeout(8)
        try:
            with server.wrap_socket(raw, server_side=True) as peer:
                try:
                    if peer.recv(1):
                        raise AssertionError("TLS pin probe sent application data")
                except (ssl.SSLEOFError, ssl.SSLZeroReturnError, ConnectionResetError, BrokenPipeError):
                    pass
        except ssl.SSLError:
            if expected:
                raise
        if expected:
            raw, _ = https.accept()
            raw.settimeout(8)
            with server.wrap_socket(raw, server_side=True) as peer:
                serve_http(peer, 7442, "10.252.15.1", {"video1": {"width": 2688, "height": 1512, "fps": 30}})
        output, error = child.communicate(timeout=20)
        if expected:
            assert child.returncode == 0, error.decode(errors="replace")
            assert b"trial_neighbor_discovery=hints count=1 completeness=unknown" in output
            assert b"trial_pin_discovery=matched candidates=1 credentials_sent=false" in output
            assert b"trial_observation=complete" in output
            assert b"trial_video_destinations=[NotReported, NotReported, NotReported] provenance=camera_claim values=redacted" in output
        else:
            assert child.returncode != 0
            assert b"no discovered candidate matched the camera pin" in error
            assert not credential.exists()
        assert not (case / "journal").exists() and not (case / "clip").exists()
        print(f"neighbor_pin_fixture case={name} result=pass", flush=True)
    finally:
        udp.close()
        https.close()
        if child.poll() is None:
            child.terminate()
            child.communicate(timeout=10)


def main():
    if len(sys.argv) != 3:
        raise SystemExit("expected trial binary and fresh private root")
    binary = str(Path(sys.argv[1]).resolve())
    root = Path(sys.argv[2])
    if not root.is_absolute() or not root.is_dir() or root.stat().st_mode & 0o077:
        raise SystemExit("expected private root")
    matching = certificate(root, "matching")
    other = certificate(root, "other")
    scope_controls(binary, root, matching[2])
    run_case(binary, root, matching, matching[2], "matching", True)
    run_case(binary, root, matching, other[2], "wrong-pin", False)
    print("neighbor_pin_fixture passed=4 explicit_targets=0 camera=synthetic")


if __name__ == "__main__":
    main()
