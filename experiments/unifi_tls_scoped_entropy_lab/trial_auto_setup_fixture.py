#!/usr/bin/env python3
"""Synthetic discovery, handoff and media trial in an isolated network namespace.

Usage: trial_auto_setup_fixture.py BINARY NEW_ABSOLUTE_DIR MEDIA_HELPER_DIR AVC_FILE
All generated fixture keys, journals and output remain in the new directory.
"""
import os
import hashlib
from pathlib import Path
import select
import socket
import ssl
import subprocess
import sys
import time

from trial_pin_discovery_fixture import certificate
from trial_profile_fixture import MAC, advertisement, run


def refusal_controls(binary, root, cert, key, wrong_pin):
    case = root / "refusals"
    case.mkdir(mode=0o700)
    common = [str(binary), "127.0.0.1:7442", "auto", "auto", str(cert), str(key),
              str(case / "journal"), str(case / "clip"),
              "12345678-1234-4abc-9abc-123456789abc", "20", "--auto-discovery=8"]
    setup = f"--setup-camera=10001,443,{wrong_pin},{case / 'missing-credential'}"
    anchored = f"--anchored-journal={case / 'keeper'},{case / 'root'}"
    fence = f"--lab-setup-fence={root / 'camera-fence'}"
    for name, extra, expected in (
        ("no-opt-in", [anchored, setup, "--owner-authorized"], b"explicit anchored laboratory setup"),
        ("no-anchor", ["--lab-auto-pinned-setup", fence, setup, "--owner-authorized"], b"requires auto discovery"),
        ("no-fence", ["--lab-auto-pinned-setup", anchored, setup, "--owner-authorized"], b"persistent fence"),
        ("observation-conflict", ["--lab-auto-pinned-setup", fence, "--observe-only", setup, "--owner-authorized"], b"requires auto discovery"),
        ("no-owner-authorization", ["--lab-auto-pinned-setup", fence, anchored, setup], b"usage:"),
    ):
        result = subprocess.run(common + extra, capture_output=True, timeout=10)
        assert result.returncode != 0 and expected in result.stderr, (name, result.stderr)
        assert all(not (case / path).exists() for path in ("journal", "clip", "keeper", "root", "missing-credential"))
        print(f"auto_setup_fixture case={name} result=pass", flush=True)


def wrong_pin_control(binary, root, server_cert, key, wrong_pin):
    case = root / "wrong-pin"
    case.mkdir(mode=0o700)
    udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp.bind(("127.0.0.1", 0))
    udp.settimeout(20)
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    listener.settimeout(20)
    server = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    server.minimum_version = ssl.TLSVersion.TLSv1_3
    server.num_tickets = 0
    server.load_cert_chain(*server_cert[:2])
    args = [str(binary), "127.0.0.1:7442", "auto", "auto", str(server_cert[2]), str(key),
            str(case / "journal"), str(case / "clip"), "12345678-1234-4abc-9abc-123456789abc", "20",
            "--auto-discovery=8", "--discovery-hint=127.0.0.1", "--lab-auto-pinned-setup",
            f"--lab-setup-fence={root / 'camera-fence'}",
            f"--anchored-journal={case / 'keeper'},{case / 'root'}",
            f"--setup-camera={udp.getsockname()[1]},{listener.getsockname()[1]},{wrong_pin},{case / 'missing-credential'}",
            "--owner-authorized"]
    child = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    try:
        _, source = udp.recvfrom(1024)
        udp.sendto(advertisement("127.0.0.1"), source)
        raw, _ = listener.accept()
        raw.settimeout(8)
        try:
            with server.wrap_socket(raw, server_side=True) as peer:
                try:
                    assert not peer.recv(1), "pin probe sent application data"
                except (ssl.SSLEOFError, ssl.SSLZeroReturnError, ConnectionResetError, BrokenPipeError):
                    pass
        except (ssl.SSLError, ConnectionResetError, BrokenPipeError):
            pass
        _, error = child.communicate(timeout=20)
        assert child.returncode != 0 and b"no discovered candidate matched the camera pin" in error
        assert all(not (case / path).exists() for path in ("journal", "clip", "keeper", "root", "missing-credential"))
        assert not list((root / "camera-fence").iterdir())
        print("auto_setup_fixture case=wrong-pin result=pass", flush=True)
    finally:
        udp.close()
        listener.close()
        if child.poll() is None:
            child.terminate()
            child.communicate(timeout=10)


def retry_after_restart(binary, root, server_cert, key):
    case = root / "retry-after-restart"
    case.mkdir(mode=0o700)
    fences = list((root / "camera-fence").iterdir())
    assert len(fences) == 1 and fences[0].stat().st_mode & 0o077 == 0
    original = fences[0].read_bytes()
    assert len(original) < 8192
    fields = []
    cursor = 0
    while cursor < len(original):
        assert cursor + 8 <= len(original)
        count = int.from_bytes(original[cursor:cursor + 8], "big")
        cursor += 8
        assert cursor + count <= len(original)
        fields.append(original[cursor:cursor + count])
        cursor += count
    assert len(fields) == 8 and fields[0] == b"fss.unifi-direct.lab-setup-fence.v1"
    assert len(fields[1]) == 32 and len(fields[2]) == 32
    assert fields[3] == b"12345678-1234-4abc-9abc-123456789abc" and fields[4] == MAC
    prior = root / "auto-handoff-media"
    assert fields[5:] == [str(prior / name).encode() for name in ("journal", "keeper", "root")]
    udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp.bind(("10.198.0.2", 0))
    udp.settimeout(20)
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.bind(("10.198.0.2", 0))
    listener.listen(1)
    listener.settimeout(20)
    server = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    server.minimum_version = ssl.TLSVersion.TLSv1_3
    server.num_tickets = 0
    server.load_cert_chain(*server_cert[:2])
    args = [str(binary), "10.198.0.1:7442", "auto", "auto", str(server_cert[2]), str(key),
            str(case / "journal"), str(case / "clip"), "12345678-1234-4abc-9abc-123456789abc", "20",
            "--auto-discovery=24", "--discovery-hint=10.198.0.2", "--lab-auto-pinned-setup",
            f"--lab-setup-fence={root / 'camera-fence'}", f"--anchored-journal={case / 'keeper'},{case / 'root'}",
            f"--setup-camera={udp.getsockname()[1]},{listener.getsockname()[1]},{server_cert[2]},{case / 'missing-credential'}",
            "--owner-authorized"]
    child = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    try:
        _, source = udp.recvfrom(1024)
        udp.sendto(advertisement("10.198.0.2").replace(MAC, bytes.fromhex("002233bbccdd")), source)
        raw, _ = listener.accept()
        raw.settimeout(8)
        with server.wrap_socket(raw, server_side=True) as peer:
            try:
                assert not peer.recv(1), "retry pin probe sent application data"
            except (ssl.SSLEOFError, ssl.SSLZeroReturnError, ConnectionResetError, BrokenPipeError):
                pass
        _, error = child.communicate(timeout=20)
        assert child.returncode != 0 and b"setup fence exists; reconcile the previous attempt" in error
        assert all(not (case / path).exists() for path in ("journal", "clip", "keeper", "root", "missing-credential"))
        assert hashlib.sha256(fences[0].read_bytes()).digest() == hashlib.sha256(original).digest()
        print("auto_setup_fixture case=restart-address-change-fenced result=pass", flush=True)
    finally:
        udp.close()
        listener.close()
        if child.poll() is None:
            child.terminate()
            child.communicate(timeout=10)


def concurrent_attempts(binary, root, server_cert, key):
    case = root / "concurrent"
    case.mkdir(mode=0o700)
    fence = case / "fence"
    fence.mkdir(mode=0o700)
    slots = [case / "first", case / "second"]
    for slot in slots:
        slot.mkdir(mode=0o700)
    udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp.bind(("10.198.0.2", 0))
    udp.settimeout(20)
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.bind(("10.198.0.2", 0))
    listener.listen(8)
    server = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    server.minimum_version = ssl.TLSVersion.TLSv1_3
    server.num_tickets = 0
    server.load_cert_chain(*server_cert[:2])
    children = []
    try:
        for slot in slots:
            args = [str(binary), "10.198.0.1:7442", "auto", "auto", str(server_cert[2]), str(key),
                    str(slot / "journal"), str(slot / "clip"), "12345678-1234-4abc-9abc-123456789abc", "20",
                    "--auto-discovery=24", "--discovery-hint=10.198.0.2", "--lab-auto-pinned-setup",
                    f"--lab-setup-fence={fence}", f"--anchored-journal={slot / 'keeper'},{slot / 'root'}",
                    f"--setup-camera={udp.getsockname()[1]},{listener.getsockname()[1]},{server_cert[2]},{slot / 'missing-credential'}",
                    "--owner-authorized"]
            children.append(subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE))
        sources = set()
        while len(sources) < 2:
            _, source = udp.recvfrom(1024)
            if source not in sources:
                sources.add(source)
                udp.sendto(advertisement("10.198.0.2"), source)
        connections = 0
        deadline = time.monotonic() + 30
        while any(child.poll() is None for child in children):
            if time.monotonic() >= deadline:
                raise TimeoutError("concurrent trials did not stop")
            ready, _, _ = select.select([listener], [], [], 0.5)
            if not ready:
                continue
            raw, _ = listener.accept()
            raw.settimeout(8)
            connections += 1
            with server.wrap_socket(raw, server_side=True) as peer:
                try:
                    assert not peer.recv(1), "concurrent attempt sent application data"
                except (ssl.SSLEOFError, ssl.SSLZeroReturnError, ConnectionResetError, BrokenPipeError):
                    pass
        outputs = [child.communicate(timeout=5) for child in children]
        assert all(child.returncode != 0 for child in children)
        assert sum(b"setup fence exists; reconcile the previous attempt" in err for _, err in outputs) == 1
        assert sum((slot / "journal").exists() for slot in slots) == 1
        assert len(list(fence.iterdir())) == 1 and connections == 3
        assert all(not (slot / "missing-credential").exists() and not (slot / "clip").exists() for slot in slots)
        print("auto_setup_fixture case=concurrent-attempts-fenced result=pass", flush=True)
    finally:
        udp.close()
        listener.close()
        for child in children:
            if child.poll() is None:
                child.terminate()
                child.communicate(timeout=10)


def inspect_fence_controls(binary, root, cert, wrong_cert):
    case = root / "fence-inspection"
    case.mkdir(mode=0o700)
    fences = list((root / "camera-fence").iterdir())
    assert len(fences) == 1
    marker = fences[0]
    original = marker.read_bytes()
    journal = root / "auto-handoff-media"
    def inventory():
        values = []
        for name in ("journal", "keeper", "root"):
            for path in sorted((journal / name).rglob("*")):
                if path.is_file():
                    values.append((str(path.relative_to(journal)), hashlib.sha256(path.read_bytes()).digest()))
        return values
    before = inventory()
    def inspect(fence, pin, scope):
        return subprocess.run([str(binary), "--inspect-setup-fence", str(fence), str(pin), str(scope), "--owner-authorized"],
                              capture_output=True, timeout=30)
    result = inspect(root / "camera-fence", cert, root)
    assert result.returncode == 0, result.stderr
    assert b"trial_fence_inspection=reconciliation_only operations=5 unresolved=5" in result.stdout
    assert inventory() == before and marker.read_bytes() == original
    print("auto_setup_fixture case=fence-inspection result=pass", flush=True)
    result = inspect(root / "camera-fence", wrong_cert, root)
    assert result.returncode != 0
    other_scope = case / "other-scope"
    other_scope.mkdir(mode=0o700)
    result = inspect(root / "camera-fence", cert, other_scope)
    assert result.returncode != 0 and b"outside the authorized scope" in result.stderr
    for name, content in (("truncated", original[:-1]), ("trailing", original + b"x"), ("empty", b"")):
        directory = case / name
        directory.mkdir(mode=0o700)
        target = directory / marker.name
        with target.open("xb") as handle:
            handle.write(content)
        os.chmod(target, 0o600)
        result = inspect(directory, cert, root)
        assert result.returncode != 0, name
    directory = case / "nonprivate"
    directory.mkdir(mode=0o700)
    with (directory / marker.name).open("xb") as handle:
        handle.write(original)
    os.chmod(directory / marker.name, 0o644)
    assert inspect(directory, cert, root).returncode != 0
    directory = case / "symlink"
    directory.mkdir(mode=0o700)
    os.symlink(marker, directory / marker.name)
    assert inspect(directory, cert, root).returncode != 0
    fields = []
    cursor = 0
    while cursor < len(original):
        count = int.from_bytes(original[cursor:cursor + 8], "big")
        cursor += 8
        fields.append(original[cursor:cursor + count])
        cursor += count
    assert len(fields) == 8
    missing = [case / name for name in ("missing-journal", "missing-keeper", "missing-root")]
    fields[5:] = [str(path).encode() for path in missing]
    encoded = b"".join(len(value).to_bytes(8, "big") + value for value in fields)
    directory = case / "missing-history"
    directory.mkdir(mode=0o700)
    with (directory / marker.name).open("xb") as handle:
        handle.write(encoded)
    os.chmod(directory / marker.name, 0o600)
    assert inspect(directory, cert, root).returncode != 0
    assert all(not path.exists() for path in missing)
    assert inventory() == before and marker.read_bytes() == original
    print("auto_setup_fixture case=invalid-fence-refusals result=pass", flush=True)


def main():
    if len(sys.argv) != 5:
        raise SystemExit(__doc__)
    binary = Path(sys.argv[1]).resolve(strict=True)
    root = Path(sys.argv[2])
    if not root.is_absolute() or root.exists():
        raise SystemExit("fixture directory must be absent and absolute")
    root.mkdir(mode=0o700)
    (root / "camera-fence").mkdir(mode=0o700)
    first = certificate(root, "first")
    second = certificate(root, "second")
    key = root / "first-key.der"
    subprocess.run(["openssl", "pkcs8", "-topk8", "-nocrypt", "-in", str(first[1]), "-outform", "der", "-out", str(key)], check=True)
    os.chmod(key, 0o600)
    refusal_controls(binary, root, first[2], key, second[2])
    wrong_pin_control(binary, root, first, key, second[2])
    sys.path.insert(0, str(Path(sys.argv[3]).resolve(strict=True)))
    from media_before_reply_fixture import media_fixture
    profiles = {"video1": {"width": 2688, "height": 1512, "fps": 30},
                "video2": {"width": 1280, "height": 720, "fps": 30}}
    run(str(binary), "10.198.0.1", root, (first[0], first[1], first[2], key),
        "auto-handoff-media", profiles, "video1", media=media_fixture(sys.argv[4]), auto_pin=True)
    case = root / "auto-handoff-media"
    recovered = subprocess.run([str(binary), "--inspect-anchored", str(case / "journal"),
                                str(case / "keeper"), str(case / "root"),
                                "12345678-1234-4abc-9abc-123456789abc", MAC.hex(), "--owner-authorized"],
                               capture_output=True, timeout=20, check=True)
    assert b"trial_recovery=reconciliation_only operations=5 unresolved=5" in recovered.stdout
    print("auto_setup_fixture case=unresolved-journal result=pass", flush=True)
    retry_after_restart(binary, root, first, key)
    concurrent_attempts(binary, root, first, key)
    inspect_fence_controls(binary, root, first[2], second[2])


if __name__ == "__main__":
    main()
