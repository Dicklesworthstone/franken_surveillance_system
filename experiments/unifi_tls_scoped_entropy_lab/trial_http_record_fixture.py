#!/usr/bin/env python3
"""Exercise the HTTP recording command against an isolated synthetic camera."""
import json
import os
from pathlib import Path
import re
import socket
import ssl
import subprocess
import sys

from trial_pin_discovery_fixture import certificate
from trial_profile_fixture import advertisement, exact


def tag(kind, timestamp, payload):
    size = len(payload)
    return (bytes([kind]) + size.to_bytes(3, "big") + (timestamp & 0xffffff).to_bytes(3, "big")
            + bytes([timestamp >> 24]) + b"\0\0\0" + payload + (11 + size).to_bytes(4, "big"))


def flv(path, trailer16=False, invalid_flag=False):
    nals = [n for n in re.split(b"\\x00\\x00\\x00?\\x01", path.read_bytes()) if n]
    sps = next(n for n in nals if n[0] & 31 == 7)
    pps = next(n for n in nals if n[0] & 31 == 8)
    pictures = [n for n in nals if n[0] & 31 == 5]
    if len(pictures) != 4:
        raise ValueError("unexpected synthetic picture count")
    avc = (b"\x17\0\0\0\0\x01" + sps[1:4] + b"\xff\xe1" + len(sps).to_bytes(2, "big")
           + sps + b"\x01" + len(pps).to_bytes(2, "big") + pps)
    trailer = b"\0" * 11 + (b"\0" if invalid_flag else b"\x01") + b"\0" * 4 if trailer16 else b""
    wire = b"FLV\x01\x01\0\0\0\x09\0\0\0\0" + tag(9, 0, avc) + trailer
    for i, picture in enumerate(pictures):
        wire += tag(9, 40 * i, b"\x17\x01\0\0\0" + len(picture).to_bytes(4, "big") + picture) + trailer
    return wire


def request(peer):
    head = bytearray()
    while not head.endswith(b"\r\n\r\n"):
        head.extend(exact(peer, 1))
        if len(head) > 8192:
            raise ValueError("request header too large")
    lines = bytes(head).split(b"\r\n")
    size = next((int(line.split(b":", 1)[1]) for line in lines if line.lower().startswith(b"content-length:")), 0)
    if size > 8192:
        raise ValueError("request body too large")
    return lines[0], exact(peer, size)


def reply(peer, body, cookie=False):
    body = json.dumps(body, separators=(",", ":")).encode()
    peer.sendall(b"HTTP/1.1 200 OK\r\n" + (b"Set-Cookie: authId=fixture-cookie\r\n" if cookie else b"")
                 + b"Content-Length: " + str(len(body)).encode() + b"\r\nConnection: keep-alive\r\n\r\n" + body)


def run(binary, root, cert, avc, mode):
    case = root / mode
    case.mkdir(mode=0o700)
    (case / "fence").mkdir(mode=0o700)
    credential = case / "credential.json"
    with credential.open("x") as handle:
        handle.write('{"username":"fixture","password":"synthetic"}')
    os.chmod(credential, 0o600)
    udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp.bind(("10.252.15.2", 0)); udp.settimeout(20)
    https = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    https.bind(("10.252.15.2", 0)); https.listen(2); https.settimeout(20)
    server = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    server.minimum_version = ssl.TLSVersion.TLSv1_3
    server.num_tickets = 0
    server.load_cert_chain(*cert[:2])
    args = [binary, "10.252.15.1:7442", "auto", "auto", str(case / "unused-cert"),
            str(case / "unused-key"), str(case / "effect"), str(case / "archive"),
            "12345678-1234-4abc-9abc-123456789abc", "20"]
    if mode in ("g4", "bad_trailer"): args.append("--lab-trailer16-av-flag")
    args += ["--auto-discovery=24",
            "--discovery-neighbor-interface=fssdummy", "--lab-auto-pinned-setup",
            f"--lab-setup-fence={case / 'fence'}", "--lab-http-record",
            f"--lab-http-checkpoint={case / 'checkpoint'}"]
    if mode in ("g4", "bad_trailer"): args.append("--lab-inband-avc")
    args += [
            f"--anchored-journal={case / 'keeper'},{case / 'root'}",
            f"--setup-camera={udp.getsockname()[1]},{https.getsockname()[1]},{cert[2]},{credential}",
            "--owner-authorized"]
    occupied = None
    if mode == "busy":
        occupied = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        occupied.bind(("10.252.15.1", 7442)); occupied.listen(1)
    child = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    try:
        query, source = udp.recvfrom(1024)
        assert query == bytes([1, 0, 0, 0])
        udp.sendto(advertisement("10.252.15.2"), source)
        raw, _ = https.accept(); raw.settimeout(8)
        with server.wrap_socket(raw, server_side=True) as peer:
            try:
                assert not peer.recv(1), "pin probe sent application data"
            except (ssl.SSLEOFError, ssl.SSLZeroReturnError, ConnectionResetError, BrokenPipeError):
                pass
        raw, _ = https.accept(); raw.settimeout(20)
        with server.wrap_socket(raw, server_side=True) as peer:
            settings = {"controller": {"addr": "10.252.15.9"}, "av": {"video": {
                "video1": {"width": 2688, "height": 1512, "fps": 30, "avSerializer": None},
                "video2": {"avSerializer": {"destinations": ["tcp://10.252.15.11:7000"]}}
            }}}
            if mode == "dimensions_mismatch":
                settings["av"]["video"]["video1"].update(width=1920, height=1080)
            routes = [b"POST /api/1.1/login", b"GET /api/1.1/status"] + [b"GET /api/1.1/settings"] * 4
            for i, route in enumerate(routes):
                line, _ = request(peer)
                if not line.startswith(route): raise ValueError("unexpected read route")
                view = json.loads(json.dumps(settings))
                if mode == "changed" and i == 5:
                    view["av"]["video"]["video2"]["avSerializer"]["destinations"] = ["tcp://10.252.15.12:7000"]
                reply(peer, {} if i == 0 else {"controller": {"port": 7442}} if i == 1 else view, i == 0)
            if mode in ("busy", "changed"):
                try:
                    assert not peer.recv(1), "unexpected write after preflight refusal"
                except (ssl.SSLEOFError, ssl.SSLZeroReturnError, ConnectionResetError, BrokenPipeError):
                    pass
            else:
                line, body = request(peer)
                if not line.startswith(b"PUT /api/1.1/settings"): raise ValueError("missing serializer update")
                change = json.loads(body)
                if set(change) != {"av"} or set(change["av"]["video"]) != {"video1"}:
                    raise ValueError("update widened its scope")
                if mode in ("success", "g4", "dimensions_mismatch", "bad_trailer"):
                    settings["av"]["video"]["video1"]["avSerializer"] = change["av"]["video"]["video1"]["avSerializer"]
                reply(peer, {})
                line, _ = request(peer)
                if not line.startswith(b"GET /api/1.1/settings"): raise ValueError("missing readback")
                reply(peer, settings)
                if mode in ("success", "g4", "dimensions_mismatch", "bad_trailer"):
                    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as media:
                        media.bind(("10.252.15.2", 0)); media.settimeout(10)
                        media.connect(("10.252.15.1", 7442))
                        media.sendall(flv(avc, mode in ("g4", "bad_trailer"), mode == "bad_trailer"))
        output, error = child.communicate(timeout=90)
        assert all(value not in output + error for value in (b"10.252.15.11", b"10.252.15.12", b"fixture-cookie"))
        if mode in ("success", "g4"):
            if child.returncode != 0: raise ValueError("recording trial failed: " + error.decode(errors="replace"))
            assert b"trial_http_checkpoint=anchored listener=bound" in output
            assert b"trial_http_record=published decoded_width=2688 decoded_height=1512" in output
            assert b"effect=reconciliation_required" in output and b"trial_task_outcome=effect_unsettled" in output
            assert (case / "checkpoint" / "key").is_file() and (case / "archive").is_dir()
        elif mode == "bad_readback":
            assert child.returncode != 0 and b"HTTP stream start refused; reconcile effect" in error
            assert b"trial_http_record=published" not in output and b"trial_task_outcome=effect_unsettled" in output
        elif mode in ("dimensions_mismatch", "bad_trailer"):
            assert child.returncode != 0 and b"camera media failed" in error
            assert b"trial_http_record=published" not in output and b"trial_task_outcome=effect_unsettled" in output
        else:
            assert child.returncode != 0 and b"trial_http_record=published" not in output
            assert (b"serializer binding changed between reads" if mode == "changed" else b"UniFi stream listener refused") in error
            assert not (case / "checkpoint").exists() and not (case / "archive").exists()
        inspection = subprocess.run([binary, "--inspect-setup-fence", str(case / "fence"), str(cert[2]),
                                     str(case), "--owner-authorized"], capture_output=True, timeout=30)
        if mode in ("success", "g4", "bad_readback", "dimensions_mismatch", "bad_trailer"):
            if inspection.returncode != 0: raise ValueError("fence inspection failed: " + inspection.stderr.decode(errors="replace"))
            assert b"operations=1 unresolved=1" in inspection.stdout
        else:
            assert inspection.returncode != 0 and b"missing effect checkpoint" in inspection.stderr
        print(f"http_record_fixture case={mode} result=pass")
    finally:
        udp.close(); https.close()
        if occupied is not None: occupied.close()
        if child.poll() is None:
            child.terminate(); child.communicate(timeout=10)


def main():
    if len(sys.argv) != 3: raise SystemExit("expected trial binary and private root")
    binary = str(Path(sys.argv[1]).resolve(strict=True)); root = Path(sys.argv[2])
    if not root.is_absolute() or not root.is_dir() or root.stat().st_mode & 0o077:
        raise SystemExit("expected private root")
    cert = certificate(root, "camera")
    avc = Path(__file__).resolve().parent / "tests/support/synthetic_g4_resolution.264"
    for mode in ("success", "g4", "changed", "busy", "bad_readback", "dimensions_mismatch", "bad_trailer"):
        run(binary, root, cert, avc, mode)
    print("http_record_fixture passed=7 camera=synthetic resolution=2688x1512")


if __name__ == "__main__": main()
