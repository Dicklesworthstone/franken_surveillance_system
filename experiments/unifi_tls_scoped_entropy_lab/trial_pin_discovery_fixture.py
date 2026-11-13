#!/usr/bin/env python3
"""Loopback-only pinned-discovery checks; retain all synthetic fixture files.

Usage: trial_pin_discovery_fixture.py TRIAL_BINARY NEW_ABSOLUTE_DIRECTORY
No camera, real credential, or non-loopback test peer is used.
"""
import os
from pathlib import Path
import select
import socket
import ssl
import subprocess
import sys
import time

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
    server.num_tickets = 0
    server.load_cert_chain(*server_cert[:2])
    args = [str(binary), "127.0.0.1:7442", "auto", "auto", str(case / "unused-cert"), str(case / "unused-key"), str(case / "journal"), str(case / "clip"), "12345678-1234-4abc-9abc-123456789abc", "20", "--auto-discovery=30", "--discovery-hint=127.0.0.1", "--observe-only", f"--setup-camera={udp.getsockname()[1]},{https.getsockname()[1]},{supplied_pin},{credential}", "--owner-authorized"]
    child = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    try:
        try:
            _, source = udp.recvfrom(1024)
        except TimeoutError as error:
            if child.poll() is not None:
                _, stderr = child.communicate()
                raise RuntimeError(f"trial stopped before discovery: exit={child.returncode} stderr={stderr.decode(errors='replace')[:500]}") from error
            raise
        udp.sendto(advertisement("127.0.0.1"), source)
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
    server.num_tickets = 0
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
                except (ssl.SSLEOFError, ssl.SSLZeroReturnError, ConnectionResetError, BrokenPipeError):
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


def run_many(binary, root, matching, other, count, duplicate=False, overflow=False):
    """Exercise bounded discovery, including late matches and saturation."""
    name = f"many-{count}-" + ("overflow" if overflow else "duplicate" if duplicate else "match")
    case = root / name
    case.mkdir(mode=0o700)
    credential = case / "credential.json"
    if not duplicate and not overflow:
        credential.write_text('{"username":"fixture","password":"synthetic"}')
        os.chmod(credential, 0o600)
    udp = []
    listeners = []
    child = None
    try:
        for index in range(count):
            address = f"127.0.0.{index + 1}"
            datagram = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            datagram.bind((address, udp[0].getsockname()[1] if udp else 0))
            datagram.settimeout(20)
            udp.append(datagram)
            listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            listener.bind((address, listeners[0].getsockname()[1] if listeners else 0))
            listener.listen(2)
            listeners.append(listener)
        contexts = []
        for cert in (matching, other):
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.minimum_version = ssl.TLSVersion.TLSv1_3
            context.num_tickets = 0
            context.load_cert_chain(*cert[:2])
            contexts.append(context)
        args = [str(binary), "127.0.0.1:7442", "auto", "auto", str(case / "unused-cert"), str(case / "unused-key"), str(case / "journal"), str(case / "clip"), "12345678-1234-4abc-9abc-123456789abc", "20", "--auto-discovery=8", "--discovery-hint=127.0.0.1", "--observe-only", f"--setup-camera={udp[0].getsockname()[1]},{listeners[0].getsockname()[1]},{matching[2]},{credential}", "--owner-authorized"]
        child = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        _, source = udp[0].recvfrom(1024)
        for index, datagram in enumerate(udp):
            mac = bytes((2, 17, 34, 51, 68, index + 1))
            datagram.sendto(advertisement(f"127.0.0.{index + 1}").replace(MAC, mac), source)
        if overflow:
            _, error = child.communicate(timeout=20)
            assert child.returncode != 0
            assert b"pin probe limit exceeded" in error
            assert not credential.exists()
            assert not (case / "journal").exists() and not (case / "clip").exists()
            for listener in listeners:
                assert not select.select([listener], [], [], 0)[0]
            print(f"pin_discovery_fixture case={name} result=pass", flush=True)
            return
        accepted = [0] * len(listeners)
        expected_connections = len(listeners) + (0 if duplicate else 1)
        deadline = time.monotonic() + 60
        while sum(accepted) < expected_connections:
            ready, _, _ = select.select(listeners, [], [], 0.5)
            if not ready:
                if child.poll() is not None:
                    _, error = child.communicate()
                    raise AssertionError("trial stopped before all candidates were probed: " + error.decode(errors="replace"))
                if time.monotonic() >= deadline:
                    raise AssertionError("not all synthetic candidates were probed before deadline")
                continue
            listener = ready[0]
            index = listeners.index(listener)
            accepted[index] += 1
            raw, _ = listener.accept()
            raw.settimeout(8)
            has_match = index == count - 1 or (duplicate and index == 0)
            try:
                with contexts[0 if has_match else 1].wrap_socket(raw, server_side=True) as peer:
                    if not duplicate and index == count - 1 and accepted[index] == 2:
                        serve_http(peer, 7442, "127.0.0.1", {"video1": {"width": 2688, "height": 1512, "fps": 30}})
                    else:
                        try:
                            if peer.recv(1):
                                raise AssertionError("pin probe sent application data")
                        except (ssl.SSLEOFError, ssl.SSLZeroReturnError, ConnectionResetError, BrokenPipeError):
                            pass
            except (ssl.SSLError, ConnectionResetError, BrokenPipeError):
                if has_match:
                    raise
        output, error = child.communicate(timeout=20)
        assert all(count >= 1 for count in accepted)
        if duplicate:
            assert child.returncode != 0
            assert b"multiple candidates matched the camera pin" in error
            assert not credential.exists()
        else:
            assert child.returncode == 0, error.decode(errors="replace")
            assert accepted[-1] == 2
            assert f"trial_pin_discovery=matched candidates={count} credentials_sent=false".encode() in output
            assert b"trial_observation=complete" in output
        assert not (case / "journal").exists() and not (case / "clip").exists()
        print(f"pin_discovery_fixture case={name} result=pass", flush=True)
    finally:
        for sock in udp + listeners:
            sock.close()
        if child is not None and child.poll() is None:
            child.terminate()
            child.communicate(timeout=10)


def run_packet_saturation(binary, root, cert):
    case = root / "packet-saturation"
    case.mkdir(mode=0o700)
    udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp.bind(("127.0.0.1", 0))
    udp.settimeout(20)
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    credential = case / "absent-credential.json"
    args = [str(binary), "127.0.0.1:7442", "auto", "auto", str(case / "unused-cert"), str(case / "unused-key"), str(case / "journal"), str(case / "clip"), "12345678-1234-4abc-9abc-123456789abc", "20", "--auto-discovery=8", "--discovery-hint=127.0.0.1", "--observe-only", f"--setup-camera={udp.getsockname()[1]},{listener.getsockname()[1]},{cert[2]},{credential}", "--owner-authorized"]
    child = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    try:
        _, source = udp.recvfrom(1024)
        packet = advertisement("127.0.0.1")
        for _ in range(128):
            udp.sendto(packet, source)
        _, error = child.communicate(timeout=20)
        assert child.returncode != 0
        assert b"incomplete discovery report" in error
        assert not credential.exists()
        assert not select.select([listener], [], [], 0)[0]
        assert not (case / "journal").exists() and not (case / "clip").exists()
        print("pin_discovery_fixture case=packet-saturation result=pass", flush=True)
    finally:
        udp.close()
        listener.close()
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
    run_many(binary, root, first, second, 17)
    run_many(binary, root, first, second, 17, duplicate=True)
    run_many(binary, root, first, second, 64)
    run_many(binary, root, first, second, 65, overflow=True)
    run_packet_saturation(binary, root, first)


if __name__ == "__main__":
    main()
