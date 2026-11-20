#!/usr/bin/env python3
"""Exercise the HTTP recording command against an isolated synthetic camera."""
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
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


def assert_spooled_wire(case, wire, offset):
    """Check a received synthetic prefix against an intact spool envelope."""
    needle = wire[offset:offset + 27]
    assert len(needle) == 27
    objects = (case / "archive" / "source" / "objects" / "spool" / "objects").iterdir()
    assert any(raw[:8] == b"FSSSPOOL" and int.from_bytes(raw[8:10], "little") == 1
               and int.from_bytes(raw[12:20], "little") == len(raw) - 52
               and raw[20:52].hex() == obj.name
               and hashlib.sha256(raw[52:]).hexdigest() == obj.name and needle in raw[52:]
               for obj in objects if len(raw := obj.read_bytes()) >= 52)


def flv(path, trailer16=False, invalid_flag=False, count=4):
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
    for i, picture in enumerate(pictures[:count]):
        wire += tag(9, 40 * i, b"\x17\x01\0\0\0" + len(picture).to_bytes(4, "big") + picture) + trailer
    return wire


def flv_av(path, supplied, short=False, inband_avc=False, changed_avc=False, third_segment=False, long_tail=False):
    """Two synthetic A/V segments; AAC bodies are structural test bytes only."""
    nals = [n for n in re.split(b"\\x00\\x00\\x00?\\x01", path.read_bytes()) if n]
    sps = next(n for n in nals if n[0] & 31 == 7)
    pps = next(n for n in nals if n[0] & 31 == 8)
    pictures = [n for n in nals if n[0] & 31 in (1, 5)]
    if len(pictures) != 7:
        raise ValueError("unexpected synthetic picture count")
    if third_segment:
        pictures += pictures[1:4]
    avc = (b"\x17\0\0\0\0\x01" + sps[1:4] + b"\xff\xe1" + len(sps).to_bytes(2, "big")
           + sps + b"\x01" + len(pps).to_bytes(2, "big") + pps)
    wire = b"FLV\x01\x05\0\0\0\x09\0\0\0\0" + tag(9, 0, avc)
    if not supplied:
        wire += tag(8, 0, b"\xaf\x00\x14\x08")
    frames = []
    for i, picture in enumerate(pictures[:4] if short else pictures):
        kind = b"\x17" if picture[0] & 31 == 5 else b"\x27"
        repeated_sps = sps[:-1] + bytes([sps[-1] ^ 1]) if changed_avc else sps
        units = ([repeated_sps, pps] if inband_avc and picture[0] & 31 == 5 else []) + [picture]
        payload = b"".join(len(unit).to_bytes(4, "big") + unit for unit in units)
        frames.append((40 * i, 0, tag(9, 40 * i, kind + b"\x01\0\0\0" + payload)))
    for i in range(2 if short else 6 if third_segment else 4):
        frames.append((64 * i, 1, tag(8, 64 * i, b"\xaf\x01\x11\x22")))
    if long_tail:
        for i in range(120 if long_tail is True else long_tail):
            timestamp = (128 if long_tail is True else 256) + 64 * i
            frames.append((timestamp, 1, tag(8, timestamp, b"\xaf\x01\x11\x22")))
    return wire + b"".join(frame for _, _, frame in sorted(frames))


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


def observe_again(binary, case, cert, credential, udp, https, server, settings, changed, wrong_certificate=False):
    args = [binary, "10.252.15.1:7442", "auto", "auto", str(case / "unused-cert"),
            str(case / "unused-key"), str(case / "live-unused-journal"), str(case / "live-unused-output"),
            "12345678-1234-4abc-9abc-123456789abc", "20", "--auto-discovery=24",
            "--discovery-neighbor-interface=fssdummy", "--observe-only", "--observe-serializers",
            f"--lab-compare-checkpoint={case / 'checkpoint'}",
            f"--setup-camera={udp.getsockname()[1]},{https.getsockname()[1]},{cert[2]},{credential}",
            "--owner-authorized"]
    child = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    try:
        try:
            query, source = udp.recvfrom(1024)
        except TimeoutError:
            if child.poll() is not None:
                output, error = child.communicate(timeout=10)
                raise ValueError("trial exited before discovery: " + error.decode(errors="replace") + output.decode(errors="replace"))
            raise
        assert query == bytes([1, 0, 0, 0]); udp.sendto(advertisement("10.252.15.2"), source)
        raw, _ = https.accept(); raw.settimeout(8)
        with server.wrap_socket(raw, server_side=True) as peer:
            try: assert not peer.recv(1), "pin probe sent application data"
            except (ssl.SSLEOFError, ssl.SSLZeroReturnError, ConnectionResetError, BrokenPipeError): pass
        raw, _ = https.accept(); raw.settimeout(20)
        with server.wrap_socket(raw, server_side=True) as peer:
            view = json.loads(json.dumps(settings))
            if changed:
                view["av"]["video"]["video2"]["avSerializer"]["destinations"] = ["tcp://10.252.15.12:7000"]
            routes = [b"POST /api/1.1/login", b"GET /api/1.1/status"] + [b"GET /api/1.1/settings"] * 4
            for i, route in enumerate(routes):
                line, _ = request(peer)
                if not line.startswith(route): raise ValueError("unexpected live comparison route")
                reply(peer, {} if i == 0 else {"controller": {"port": 7442}} if i == 1 else view, i == 0)
        output, error = child.communicate(timeout=30)
        if wrong_certificate:
            assert child.returncode != 0 and b"live checkpoint camera or certificate claim mismatch" in error
            assert b"trial_live_checkpoint_comparison=" not in output
        else:
            if child.returncode != 0: raise ValueError("live comparison failed: " + error.decode(errors="replace"))
            expected = b"OtherTracks { target_changed: true }" if changed else b"TargetTrackOnly"
            assert b"trial_live_checkpoint_comparison=" + expected in output
            assert b"requested_fields_match=true camera_write=false" in output and b"settlement=none" in output
        assert all(value not in output + error for value in (b"10.252.15.11", b"10.252.15.12", b"fixture-cookie"))
        assert not (case / "live-unused-journal").exists() and not (case / "live-unused-output").exists()
        print(f"http_checkpoint_live case={'wrong_certificate' if wrong_certificate else 'other_track_changed' if changed else 'matching'} result=pass")
    finally:
        if child.poll() is None:
            child.terminate(); child.communicate(timeout=10)


def run(binary, root, cert, avc, mode, private_media=None, long_tail=False, exhaust_network_after_bootstrap=False, exhaust_network_in_bootstrap=False, malformed_name_metadata=False):
    supervised = mode in ("av_supervised", "av_supervised_rollover", "av_supervised_rollover_exhaust", "av_supervised_no_successor", "av_supervised_denied_successor", "av_supervised_budget", "av_supervised_framing", "av_real_supervised", "av_supervised_many_tail")
    accept_timeout = mode in ("restore_accept_timeout", "restore_accept_drift", "restore_accept_ignored", "av_restore_accept_timeout", "accept_timeout_no_opt")
    failure_restore = mode in ("restore_short", "restore_short_drift", "restore_short_ignored", "restore_bad_trailer", "metadata_flag_strict", "name_mismatch", "name_mismatch_drift", "av_name_mismatch", "av_name_mismatch_drift", "av_restore_short", "av_restore_bad_avc", "av_auto_restore_short", "av_auto_restore_drift", "restore_accept_timeout", "restore_accept_drift", "restore_accept_ignored", "av_restore_accept_timeout", "restore_start_unconfirmed")
    restore_mode = mode in ("restore_success", "restore_precondition_drift", "restore_object", "restore_ignored", "restore_drift", "restore_interrupted", "restore_missing", "restore_checkpoint_blocked", "name_match", "metadata_flag_zero", "metadata_flag_opaque", "av_restore", "av_auto_restore", "av_name_match", "av_name_opaque", "av_auto_name_match") or failure_restore
    if long_tail and mode not in ("av_short", "av_auto_short", "av_supervised_budget"):
        raise ValueError("long tail requires an A/V short-stream scenario")
    if (exhaust_network_after_bootstrap or exhaust_network_in_bootstrap) and (not long_tail or mode not in ("av_short", "av_auto_short", "av_supervised_budget")):
        raise ValueError("network exhaustion requires a long-tail A/V short-stream scenario")
    if mode == "av_supervised_budget" and (not exhaust_network_after_bootstrap or exhaust_network_in_bootstrap):
        raise ValueError("supervised budget scenario requires post-bootstrap exhaustion")
    if exhaust_network_after_bootstrap and exhaust_network_in_bootstrap:
        raise ValueError("choose one exhaustion stage")
    if malformed_name_metadata and mode not in ("name_mismatch", "av_name_mismatch"):
        raise ValueError("malformed metadata requires a name-probe refusal case")
    case_name = mode + ("-malformed-metadata" if malformed_name_metadata else "") + ("-long-tail" if long_tail else "") + ("-network-exhaustion" if exhaust_network_after_bootstrap else "") + ("-bootstrap-exhaustion" if exhaust_network_in_bootstrap else "")
    case = root / case_name
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
    av_mode = supervised or mode in ("av_supplied", "av_inband", "av_inband_avc", "av_auto", "av_auto_short", "av_auto_restore", "av_auto_restore_short", "av_auto_restore_drift", "av_changed_avc", "av_real", "av_bad_readback", "av_short", "av_stale", "av_conflict", "av_restore", "av_restore_short", "av_restore_bad_avc", "av_restore_accept_timeout", "av_name_match", "av_name_opaque", "av_name_mismatch", "av_name_mismatch_drift", "av_auto_name_match", "av_bootstrap_framing")
    if av_mode: args.append("--lab-aac-source" if mode == "av_inband" else "--lab-aac-config=1408")
    if mode in ("av_real", "av_real_supervised"): args.append("--lab-zero-stream-id")
    if mode in ("zero_id_g4", "metadata_flag_zero"): args.append("--lab-zero-stream-id")
    if mode in ("metadata_flag_opaque", "av_name_opaque"): args.append("--lab-trailer16-opaque")
    if mode in ("g4", "bad_trailer", "restore_bad_trailer", "metadata_flag_strict", "av_supervised_framing", "av_bootstrap_framing"): args.append("--lab-trailer16-av-flag")
    if (mode in ("success", "g4", "zero_id_g4", "short_stream", "av_supplied", "av_inband", "av_inband_avc", "av_changed_avc", "av_bad_readback", "av_short", "av_stale", "av_conflict") or restore_mode) and mode not in ("av_auto_restore", "av_auto_name_match"): args.append("--lab-segments=2")
    if mode == "av_real_supervised": args.append("--lab-segments=2")
    elif mode in ("av_supervised_rollover", "av_supervised_rollover_exhaust"): args.append("--lab-segments=4")
    elif supervised or mode in ("av_auto", "av_auto_restore", "av_auto_name_match"): args.append("--lab-segments=3")
    if mode == "av_auto_short": args.append("--lab-segments=2")
    args += ["--auto-discovery=24",
            "--discovery-neighbor-interface=fssdummy", "--lab-auto-pinned-setup",
            f"--lab-setup-fence={case / 'fence'}", "--lab-http-av-record" if av_mode else "--lab-http-record"]
    if mode == "av_supervised_rollover": args.append("--lab-http-av-auto=2")
    elif supervised or mode in ("av_auto", "av_auto_short", "av_auto_restore", "av_auto_restore_short", "av_auto_restore_drift", "av_auto_name_match"): args.append("--lab-http-av-auto=1")
    if supervised: args.append("--lab-http-av-supervised")
    if mode in ("name_match", "name_mismatch", "name_mismatch_drift", "metadata_flag_strict", "metadata_flag_zero", "metadata_flag_opaque", "av_name_match", "av_name_opaque", "av_name_mismatch", "av_name_mismatch_drift", "av_auto_name_match"): args.append("--lab-http-name-probe")
    if restore_mode or exhaust_network_after_bootstrap or exhaust_network_in_bootstrap: args.append("--lab-http-restore-after")
    args.append(f"--lab-http-checkpoint={case / 'checkpoint'}")
    if mode in ("g4", "bad_trailer", "restore_bad_trailer"): args.append("--lab-inband-avc")
    if mode in ("av_auto", "av_auto_short", "av_auto_restore", "av_auto_restore_short", "av_auto_restore_drift", "av_auto_name_match", "av_supervised_rollover", "av_supervised_rollover_exhaust"): args.append("--lab-av-history-records=5")
    if exhaust_network_after_bootstrap: args.append("--lab-exhaust-network-after-bootstrap")
    if exhaust_network_in_bootstrap: args.append("--lab-exhaust-network-in-bootstrap")
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
        try:
            query, source = udp.recvfrom(1024)
        except TimeoutError:
            if child.poll() is not None:
                output, error = child.communicate(timeout=10)
                raise ValueError("trial exited before discovery: " + error.decode(errors="replace") + output.decode(errors="replace"))
            raise
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
            if mode in ("av_real", "av_real_supervised"):
                settings["av"]["video"]["video1"].update(width=1280, height=720)
            if mode == "restore_missing":
                settings["av"]["video"]["video1"].pop("avSerializer")
            if mode == "restore_object":
                settings["av"]["video"]["video1"]["avSerializer"] = {"type": "fixture", "destinations": ["tcp://10.252.15.11:7001"]}
            baseline = json.loads(json.dumps(settings))
            routes = [b"POST /api/1.1/login", b"GET /api/1.1/status"] + [b"GET /api/1.1/settings"] * 4
            for i, route in enumerate(routes):
                line, _ = request(peer)
                if not line.startswith(route): raise ValueError("unexpected read route")
                view = json.loads(json.dumps(settings))
                if mode == "changed" and i == 5:
                    view["av"]["video"]["video2"]["avSerializer"]["destinations"] = ["tcp://10.252.15.12:7000"]
                reply(peer, {} if i == 0 else {"controller": {"port": 7442}} if i == 1 else view, i == 0)
            if mode in ("busy", "changed", "restore_missing"):
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
                if (supervised or mode in ("success", "g4", "zero_id_g4", "video_real", "dimensions_mismatch", "bad_trailer", "stale_after_stream", "post_read_failure", "checkpoint_blocked", "short_stream", "av_supplied", "av_inband", "av_inband_avc", "av_auto", "av_auto_short", "av_changed_avc", "av_real", "av_short", "av_stale", "av_conflict", "av_bootstrap_framing", "accept_timeout_no_opt") or restore_mode) and mode != "restore_start_unconfirmed":
                    settings["av"]["video"]["video1"]["avSerializer"] = change["av"]["video"]["video1"]["avSerializer"]
                reply(peer, {})
                line, _ = request(peer)
                if not line.startswith(b"GET /api/1.1/settings"): raise ValueError("missing readback")
                reply(peer, settings)
                if not accept_timeout and mode != "restore_start_unconfirmed" and (supervised or mode in ("success", "g4", "zero_id_g4", "video_real", "dimensions_mismatch", "bad_trailer", "stale_after_stream", "post_read_failure", "checkpoint_blocked", "short_stream", "av_supplied", "av_inband", "av_inband_avc", "av_auto", "av_auto_short", "av_changed_avc", "av_real", "av_short", "av_stale", "av_conflict", "av_bootstrap_framing") or restore_mode):
                    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as media:
                        media.bind(("10.252.15.2", 0)); media.settimeout(10)
                        media.connect(("10.252.15.1", 7442))
                        wire = private_media if mode in ("av_real", "av_real_supervised", "video_real") else flv_av(avc, mode not in ("av_inband", "av_conflict"), mode in ("av_short", "av_auto_short", "av_restore_short", "av_auto_restore_short", "av_auto_restore_drift", "av_supervised_budget"), mode in ("av_inband_avc", "av_changed_avc", "av_restore_bad_avc"), mode in ("av_changed_avc", "av_restore_bad_avc"), mode in ("av_auto", "av_auto_restore", "av_auto_name_match", "av_supervised_rollover", "av_supervised_rollover_exhaust"), 200 if mode == "av_supervised_many_tail" else long_tail) if av_mode else flv(avc, mode in ("g4", "zero_id_g4", "bad_trailer", "restore_bad_trailer", "metadata_flag_opaque"), mode in ("zero_id_g4", "bad_trailer", "restore_bad_trailer", "metadata_flag_opaque"), 2 if mode in ("short_stream", "restore_short", "restore_short_drift", "restore_short_ignored") else 4)
                        if exhaust_network_after_bootstrap or exhaust_network_in_bootstrap:
                            # Ensure the already-reserved read cannot reach EOF before
                            # the next read observes the exhausted task ledger.
                            wire += tag(18, 9000, b"\x00" * 8192)
                        if exhaust_network_in_bootstrap:
                            # This separately published pre-roll creates a real gap
                            # between collector copies and the unfinished tail.
                            config_end = 13 + 15 + int.from_bytes(wire[14:17], "big")
                            wire = wire[:config_end] + tag(18, 0, b"\x02\x00\x01x") + wire[config_end:]
                        if mode == "av_name_opaque":
                            padded, pos = bytearray(wire[:13]), 13
                            while pos < len(wire):
                                size = int.from_bytes(wire[pos + 1:pos + 4], "big")
                                end = pos + 15 + size
                                if end > len(wire): raise ValueError("synthetic A/V tag is incomplete")
                                if pos != 13: padded.extend(b"\x00" * 11 + b"\x02" + b"\x00" * 4)
                                padded.extend(wire[pos:end]); pos = end
                            wire = bytes(padded)
                        if mode in ("av_supervised_framing", "av_bootstrap_framing"):
                            padded, pos, previous, index = bytearray(wire[:13]), 13, None, 0
                            while pos < len(wire):
                                size = int.from_bytes(wire[pos + 1:pos + 4], "big")
                                end = pos + 15 + size
                                if end > len(wire): raise ValueError("synthetic A/V tag is incomplete")
                                if previous is not None:
                                    flag = 0 if previous == 8 else 1
                                    if index == (8 if mode == "av_supervised_framing" else 2):
                                        flag ^= 1
                                        bad_tail_offset = len(padded)
                                    padded.extend(b"\x00" * 11 + bytes([flag]) + b"\x00" * 4)
                                previous = wire[pos]
                                padded.extend(wire[pos:end]); pos = end; index += 1
                            wire = bytes(padded)
                        if mode in ("name_match", "name_mismatch", "name_mismatch_drift", "metadata_flag_strict", "metadata_flag_zero", "metadata_flag_opaque", "av_name_match", "av_name_opaque", "av_name_mismatch", "av_name_mismatch_drift", "av_auto_name_match"):
                            name = change["av"]["video"]["video1"]["avSerializer"]["parameters"]["streamName"].encode()
                            if mode in ("name_mismatch", "name_mismatch_drift", "av_name_mismatch", "av_name_mismatch_drift"): name = (b"0" if name[:1] != b"0" else b"1") + name[1:]
                            metadata = b"\x02\x00\x0aonMetaData\x03\x00\x0astreamName\x02" + len(name).to_bytes(2, "big") + name + b"\x00\x00\x09"
                            if malformed_name_metadata:
                                metadata = b"\x02\x00\x01\xff\x03\x00\x00\x09"
                            trailer = b"\x00" * 11 + b"\x02" + b"\x00" * 4 if mode in ("metadata_flag_strict", "metadata_flag_zero", "metadata_flag_opaque", "av_name_opaque") else b""
                            wire = wire[:13] + tag(18, 0, metadata) + trailer + wire[13:]
                        media.sendall(wire)
                    if mode in ("av_supervised", "av_supervised_rollover", "av_supervised_rollover_exhaust", "av_supervised_denied_successor", "av_real_supervised", "av_supervised_many_tail"):
                        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as successor:
                            successor.bind(("10.252.15.3" if mode == "av_supervised_denied_successor" else "10.252.15.2", 0)); successor.settimeout(10)
                            successor.connect(("10.252.15.1", 7442))
                            if mode != "av_supervised_denied_successor": successor.sendall(private_media if mode == "av_real_supervised" else flv_av(avc, True))
                if exhaust_network_after_bootstrap or exhaust_network_in_bootstrap or mode in ("av_supervised_framing", "av_bootstrap_framing"):
                    try: assert not peer.recv(1), "network exhaustion triggered an unexpected camera request"
                    except (ssl.SSLEOFError, ssl.SSLZeroReturnError, ConnectionResetError, BrokenPipeError): pass
                if mode in ("accept_timeout_no_opt", "restore_start_unconfirmed"):
                    try: assert not peer.recv(1), "unexpected recovery without an eligible start"
                    except (ssl.SSLEOFError, ssl.SSLZeroReturnError, ConnectionResetError, BrokenPipeError): pass
                if mode not in ("accept_timeout_no_opt", "restore_start_unconfirmed") and (mode in ("av_supervised", "av_supervised_rollover", "av_real_supervised", "av_supervised_many_tail") or mode in ("success", "g4", "zero_id_g4", "video_real", "stale_after_stream", "checkpoint_blocked", "av_supplied", "av_inband", "av_inband_avc", "av_auto", "av_real", "av_stale") or restore_mode):
                    try:
                        line, _ = request(peer)
                    except EOFError:
                        output, error = child.communicate(timeout=10)
                        raise ValueError("trial stopped before post-recording readback: " + error.decode(errors="replace") + output.decode(errors="replace"))
                    if not line.startswith(b"GET /api/1.1/settings"): raise ValueError("missing post-recording readback")
                    if mode in ("stale_after_stream", "av_stale", "restore_short_drift", "restore_accept_drift", "av_auto_restore_drift", "name_mismatch_drift", "av_name_mismatch_drift"):
                        settings["av"]["video"]["video2"]["avSerializer"]["destinations"] = ["tcp://10.252.15.12:7000"]
                    if mode == "checkpoint_blocked":
                        (case / "checkpoint" / "observation").mkdir(mode=0o700)
                    reply(peer, settings)
                if mode in ("restore_short_drift", "restore_accept_drift", "av_auto_restore_drift", "name_mismatch_drift", "av_name_mismatch_drift"):
                    try: assert not peer.recv(1), "failure restore wrote despite changed other track"
                    except (ssl.SSLEOFError, ssl.SSLZeroReturnError, ConnectionResetError, BrokenPipeError): pass
                if restore_mode and mode not in ("restore_short_drift", "restore_accept_drift", "restore_start_unconfirmed", "av_auto_restore_drift", "name_mismatch_drift", "av_name_mismatch_drift"):
                    line, _ = request(peer)
                    if not line.startswith(b"GET /api/1.1/settings"): raise ValueError("missing restore preflight")
                    if mode == "restore_drift":
                        settings["av"]["video"]["video2"]["avSerializer"]["destinations"] = ["tcp://10.252.15.12:7000"]
                    if mode == "restore_precondition_drift":
                        settings["av"]["video"]["video1"]["avSerializer"]["parameters"]["fixtureExtra"] = True
                    reply(peer, settings)
                    if mode == "restore_drift":
                        try: assert not peer.recv(1), "restore wrote despite changed other track"
                        except (ssl.SSLEOFError, ssl.SSLZeroReturnError, ConnectionResetError, BrokenPipeError): pass
                    else:
                        line, body = request(peer)
                        if not line.startswith(b"PUT /api/1.1/settings"): raise ValueError("missing restore write")
                        expected = {"av": {"video": {"video1": {"avSerializer": baseline["av"]["video"]["video1"]["avSerializer"]}}}}
                        if json.loads(body) != expected: raise ValueError("restore body differed from baseline")
                        if mode != "restore_interrupted":
                            if mode not in ("restore_ignored", "restore_short_ignored", "restore_accept_ignored"): settings = baseline
                            reply(peer, {})
                            line, _ = request(peer)
                            if not line.startswith(b"GET /api/1.1/settings"): raise ValueError("missing restore readback")
                            if mode == "restore_checkpoint_blocked":
                                (case / "checkpoint" / "restored").mkdir(mode=0o700)
                            reply(peer, settings)
        output, error = child.communicate(timeout=90)
        assert all(value not in output + error for value in (b"10.252.15.11", b"10.252.15.12", b"fixture-cookie"))
        if mode in ("restore_short", "restore_bad_trailer", "metadata_flag_strict", "av_restore_short", "av_restore_bad_avc", "av_auto_restore_short", "restore_accept_timeout", "av_restore_accept_timeout"):
            assert child.returncode != 0 and b"trial_http_failure_restore=readback_matches restored_checkpoint=anchored recording=failed effects=reconciliation_required" in output
            assert b"trial_http_record=published" not in output and b"trial_http_av_record=published" not in output
            assert b"trial_task_outcome=effect_unsettled" in output
            if mode in ("av_restore_short", "av_auto_restore_short"):
                assert re.search(rb"trial_http_av_tail=published items=[1-9][0-9]* capture_time=unknown", output)
                assert output.index(b"trial_http_failure_restore=readback_matches") < output.index(b"trial_http_av_tail=published")
            if mode in ("restore_bad_trailer", "metadata_flag_strict"):
                assert b"trial_http_framing_diagnostic=" in output and b"boundary=unverified" in output
                assert re.search(rb"trial_http_video_failure_tail=verified records=[1-9][0-9]* capture_time=unknown coverage=unproven", output)
                assert_spooled_wire(case, wire, 13 + 15 + int.from_bytes(wire[14:17], "big"))
            if mode == "metadata_flag_strict": assert b"trial_http_name_probe=matched tag_index=0" in output
        elif mode in ("av_name_mismatch", "av_name_mismatch_drift"):
            assert child.returncode != 0 and b"HTTP A/V name probe did not match" in error
            expected_reason = b"metadata" if malformed_name_metadata else b"name_mismatch"
            assert b"trial_http_av_name_probe_reason=" + expected_reason + b" camera_identity=unverified effect=reconciliation_required" in error
            assert b"trial_http_av_record=published" not in output and b"trial_task_outcome=effect_unsettled" in output
            assert not list((case / "archive" / "av" / "objects" / "roots").glob("*.root"))
            expected = (b"trial_http_av_name_probe=refused restoration=readback_matches" if mode == "av_name_mismatch"
                        else b"trial_http_av_name_probe=refused restoration=requires_reconciliation")
            assert expected in output + error
        elif mode in ("name_mismatch", "name_mismatch_drift"):
            assert child.returncode != 0 and b"HTTP name probe did not match" in error
            expected_reason = b"metadata" if malformed_name_metadata else b"name_mismatch"
            assert b"trial_http_name_probe_reason=" + expected_reason + b" camera_identity=unverified effect=reconciliation_required" in error
            assert b"trial_http_record=published" not in output and b"trial_task_outcome=effect_unsettled" in output
            expected = (b"trial_http_name_probe=refused restoration=readback_matches" if mode == "name_mismatch"
                        else b"trial_http_name_probe=refused restoration=requires_reconciliation")
            assert expected in output + error
        elif mode in ("restore_short_drift", "restore_short_ignored", "restore_accept_drift", "restore_accept_ignored", "av_auto_restore_drift"):
            assert child.returncode != 0 and b"trial_http_failure_restore=requires_reconciliation recording=failed" in error
            assert b"trial_http_failure_restore=readback_matches" not in output and b"trial_task_outcome=effect_unsettled" in output
        elif mode in ("accept_timeout_no_opt", "restore_start_unconfirmed"):
            assert child.returncode != 0 and b"HTTP stream start refused" in error
            assert b"trial_http_failure_restore=" not in output + error and b"trial_task_outcome=effect_unsettled" in output
        elif mode in ("restore_success", "restore_precondition_drift", "restore_object", "name_match", "metadata_flag_zero", "metadata_flag_opaque"):
            if child.returncode != 0: raise ValueError("restore trial failed: " + error.decode(errors="replace"))
            assert b"trial_http_restore=readback_matches restored_checkpoint=anchored camera_identity=unverified effects=reconciliation_required" in output
            assert b"trial_http_record=published decoded_width=2688 decoded_height=1512" in output
            assert b"trial_task_outcome=effect_unsettled" in output
            if mode in ("name_match", "metadata_flag_zero", "metadata_flag_opaque"): assert b"trial_http_name_probe=matched tag_index=0" in output
        elif mode in ("restore_ignored", "restore_drift", "restore_interrupted", "restore_checkpoint_blocked"):
            assert child.returncode != 0 and (b"HTTP restoration checkpoint requires inspection" if mode == "restore_checkpoint_blocked" else b"HTTP restoration requires reconciliation") in error
            assert b"trial_http_restore=readback_matches" not in output and b"trial_task_outcome=effect_unsettled" in output
        elif mode == "restore_missing":
            assert child.returncode != 0 and b"HTTP restore requires a representable prior serializer" in error
            assert not (case / "checkpoint").exists() and not (case / "archive").exists()
        elif mode == "video_real":
            if child.returncode != 0: raise ValueError("real video trial failed: " + error.decode(errors="replace"))
            assert b"trial_avc_selection=automatic_inband format=avc3 configuration_changes=refused selection=conservative_policy" in output
            assert b"trial_http_checkpoint=anchored listener=bound" in output
            assert b"trial_http_record=published decoded_width=2688 decoded_height=1512" in output
            assert b"fragments=1" in output and b"observation_checkpoint=anchored" in output
            assert b"effect=reconciliation_required" in output and b"trial_task_outcome=effect_unsettled" in output
            print("camera_http_high_video_command=passed width=2688 height=1512 fragments=1")
        elif mode in ("success", "g4", "zero_id_g4"):
            if child.returncode != 0: raise ValueError("recording trial failed: " + error.decode(errors="replace"))
            if mode == "success":
                assert b"trial_avc_selection=automatic_inband format=avc3 configuration_changes=refused selection=conservative_policy" in output
            assert b"trial_http_checkpoint=anchored listener=bound" in output
            assert b"trial_http_record=published decoded_width=2688 decoded_height=1512" in output
            assert b"fragments=2" in output
            assert b"readbacks=consistent" in output and b"effect=reconciliation_required" in output and b"trial_task_outcome=effect_unsettled" in output
            assert (case / "checkpoint" / "key").is_file() and (case / "archive").is_dir()
            assert b"observation_checkpoint=anchored" in output
            for checkpoint in (case / "checkpoint", case / "checkpoint" / "observation"):
                inspected = subprocess.run([binary, "--inspect-http-checkpoint", str(checkpoint),
                                            "--owner-authorized"], capture_output=True, timeout=30)
                assert inspected.returncode == 0, inspected.stderr.decode(errors="replace")
                assert b"trial_http_checkpoint_inspection=authenticated camera_write=false" in inspected.stdout
                assert all(value not in inspected.stdout + inspected.stderr for value in (b"10.252.15.11", b"10.252.15.12"))
            compared = subprocess.run([binary, "--compare-http-checkpoints", str(case / "checkpoint"), str(case / "checkpoint" / "observation"),
                                       "--owner-authorized"], capture_output=True, timeout=30)
            assert compared.returncode == 0, compared.stderr.decode(errors="replace")
            assert b"trial_http_checkpoint_comparison=consistent camera_write=false" in compared.stdout
            assert b"effect=unsettled" in compared.stdout
            assert all(value not in compared.stdout + compared.stderr for value in (b"10.252.15.11", b"10.252.15.12"))
            joined = subprocess.run([binary, "--inspect-setup-fence-with-checkpoints", str(case / "fence"), str(cert[2]),
                                     str(case), str(case / "checkpoint"), str(case / "checkpoint" / "observation"),
                                     "--owner-authorized"], capture_output=True, timeout=30)
            assert joined.returncode == 0, joined.stderr.decode(errors="replace")
            assert b"trial_fence_checkpoint_match=consistent effect_state=adapter_accepted settlement=none" in joined.stdout
            assert b"trial_fence_start_acceptance_digest=present settlement=not_inferred" in joined.stdout
            assert b"operations=1 unresolved=1" in joined.stdout
            assert all(value not in joined.stdout + joined.stderr for value in (b"10.252.15.11", b"10.252.15.12"))
            observed_root = case / "checkpoint" / "observation"
            assert (observed_root / "key").stat().st_mode & 0o777 == 0o600
            for path in observed_root.rglob("*"):
                if path.is_file():
                    data = path.read_bytes()
                    assert all(value not in data for value in (b"10.252.15.11", b"10.252.15.12", b"fixture-cookie"))
            if mode == "success":
                observe_again(binary, case, cert, credential, udp, https, server, settings, False)
                observe_again(binary, case, cert, credential, udp, https, server, settings, True)
                other_cert = certificate(case, "other-camera")
                other_server = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
                other_server.minimum_version = ssl.TLSVersion.TLSv1_3
                other_server.num_tickets = 0
                other_server.load_cert_chain(*other_cert[:2])
                observe_again(binary, case, other_cert, credential, udp, https, other_server, settings, False, True)
        elif mode in ("av_bad_readback", "av_short", "av_auto_short", "av_stale", "av_conflict", "av_changed_avc"):
            expected = {"av_bad_readback": b"HTTP A/V stream start refused",
                        "av_short": b"HTTP A/V recording stopped",
                        "av_auto_short": b"HTTP A/V automatic trial requires reconciliation",
                        "av_stale": b"serializer observation changed after recording",
                        "av_conflict": b"HTTP A/V bootstrap stopped",
                        "av_changed_avc": b"HTTP A/V "}[mode]
            if exhaust_network_in_bootstrap: expected = b"HTTP A/V bootstrap stopped"
            assert child.returncode != 0 and expected in error
            assert b"trial_http_av_record=published" not in output and b"trial_task_outcome=effect_unsettled" in output
            if mode == "av_changed_avc":
                assert b"trial_http_av_media_refusal=recording:Mux(UnsupportedFormat)" in error
            if mode in ("av_short", "av_auto_short"):
                assert len(list((case / "archive" / "av" / "objects" / "roots").glob("*.root"))) == (0 if exhaust_network_in_bootstrap else 1)
                tail = re.search(rb"trial_http_av_tail=published items=([1-9][0-9]*) capture_time=unknown", output)
                assert tail and (not long_tail or exhaust_network_after_bootstrap or exhaust_network_in_bootstrap or int(tail.group(1)) > 85), (output, error)
                roots = re.search(rb"trial_http_av_tail_roots=([1-9][0-9]*)", output)
                assert roots and (not long_tail or int(roots.group(1)) == (2 if exhaust_network_in_bootstrap else 1))
                if exhaust_network_after_bootstrap:
                    assert b"trial_lab_network_exhaustion=injected stage=after_bootstrap" in output
                    assert b"trial_http_av_stop=network_budget_exhausted" in error
                    assert b"trial_http_failure_restore=" not in output + error
                if exhaust_network_in_bootstrap:
                    assert b"trial_lab_network_exhaustion=injected stage=bootstrap" in output
                    assert b"trial_http_av_bootstrap_stop=network_budget_exhausted" in error
                    assert re.search(rb"trial_http_av_bootstrap_collector=copies_published records=[1-9][0-9]* effect=reconciliation_required", output)
                    assert b"trial_http_failure_restore=" not in output + error
        elif mode in ("av_supervised_framing", "av_bootstrap_framing"):
            expected = b"supervised A/V trial requires reconciliation" if supervised else b"HTTP A/V bootstrap stopped"
            assert child.returncode != 0 and expected in error
            if supervised: assert b"trial_http_av_supervised_failure_tail=attempted effect=reconciliation_required" in error
            assert re.search(rb"trial_http_av_tail=published items=[1-9][0-9]* capture_time=unknown", output)
            assert b"trial_http_failure_restore=" not in output + error
            # The malformed trailer and following tag header must survive in
            # one content-addressed source object, not just in a status log.
            assert_spooled_wire(case, wire, bad_tail_offset)
        elif mode == "av_supervised_budget":
            assert child.returncode != 0 and b"supervised A/V trial requires reconciliation" in error
            assert b"trial_lab_network_exhaustion=injected stage=after_bootstrap" in output
            assert b"trial_http_av_supervised_failure_tail=attempted effect=reconciliation_required" in error
            assert re.search(rb"trial_http_av_tail=published items=[1-9][0-9]* capture_time=unknown", output)
            assert b"trial_http_failure_restore=" not in output + error
        elif mode == "av_supervised_rollover_exhaust":
            if child.returncode == 0 or b"supervised A/V trial requires reconciliation" not in error:
                raise ValueError("supervised generation exhaustion did not stop for reconciliation")
            assert b"reason=supervised generation intervention required" in error
            assert b"trial_http_av_supervised_stopped_rollovers=1 verified_reuse=1 published=3" in error
        elif mode == "av_supervised_no_successor":
            if child.returncode == 0 or b"supervised A/V trial requires reconciliation" not in error:
                raise ValueError("supervised missing successor did not stop for reconciliation")
            assert b"trial_http_av_supervised_stop=drained boundaries=0 effect=reconciliation_required" in error
            assert b"trial_http_av_supervised_listener_timeouts=2 denied_peers=0" in error
        elif mode == "av_supervised_denied_successor":
            if child.returncode == 0 or b"supervised A/V trial requires reconciliation" not in error:
                raise ValueError("denied successor did not stop for reconciliation")
            assert b"reason=supervised reconnect requires reconciliation" in error
            assert b"trial_http_av_supervised_listener_timeouts=0 denied_peers=1" in error
        elif av_mode:
            if child.returncode != 0: raise ValueError("A/V trial failed: " + error.decode(errors="replace"))
            if mode != "av_real" and not supervised:
                assert b"trial_http_av_allowance=renewed " in output
            if mode in ("av_restore", "av_auto_restore", "av_name_match", "av_name_opaque", "av_auto_name_match"):
                assert b"trial_http_restore=readback_matches restored_checkpoint=anchored camera_identity=unverified effects=reconciliation_required" in output
            if mode in ("av_name_match", "av_name_opaque", "av_auto_name_match"):
                assert b"trial_http_av_name_probe=matched tag_index=0" in output
            assert b"trial_avc_selection=automatic_inband format=avc3 configuration_changes=refused selection=conservative_policy" in output
            expected_origin = b"in_band" if mode == "av_inband" else b"supplied_unverified"
            expected_fragments = b"fragments=1" if mode == "av_real" else b"fragments=4" if mode == "av_supervised_rollover" else b"fragments=2" if mode == "av_real_supervised" else b"fragments=3" if supervised or mode in ("av_auto", "av_auto_restore", "av_auto_name_match") else b"fragments=2"
            assert b"trial_http_av_record=published" in output and expected_fragments in output
            if mode in ("av_auto", "av_auto_restore", "av_auto_name_match"):
                assert b"trial_http_av_auto=drained rollovers=1 retained_custody=1 restart_durable=false independent_storage=unverified" in output
            if mode in ("av_supervised", "av_supervised_rollover", "av_real_supervised", "av_supervised_many_tail"):
                assert b"trial_http_av_supervised=drained boundaries=1 effect=reconciliation_required" in output
                assert b"trial_http_av_final_tail=verified records=" in output
                assert b"capture_time=unknown coverage=unproven" in output
                tail = re.search(rb"trial_http_av_final_tail=verified records=(\d+)", output)
                print("http_av_final_tail case=" + mode + " records=" + tail.group(1).decode(), flush=True)
                if mode == "av_supervised_many_tail":
                    batched = re.search(rb"trial_http_av_supervised_tail_batches=(\d+) records=(\d+)", output)
                    assert batched and int(batched.group(1)) >= 1 and int(batched.group(2)) > 128
                expected = b"trial_http_av_supervised_rollovers=2 verified_reuse=1" if mode == "av_supervised_rollover" else b"trial_http_av_supervised_rollovers=0 verified_reuse=0"
                if expected not in output:
                    actual = re.search(rb"trial_http_av_supervised_rollovers=\d+ verified_reuse=\d+", output)
                    raise ValueError("supervised rollover accounting differs: " + (actual.group().decode() if actual else "missing"))
            assert b"audio_configuration=" + expected_origin in output
            assert b"readbacks=consistent observation_checkpoint=anchored effect=reconciliation_required" in output
            assert b"trial_task_outcome=effect_unsettled" in output
            if mode in ("av_real", "av_real_supervised"):
                fragments = b"2" if supervised else b"1"
                stats = re.search(rb"decoded_width=(\d+) decoded_height=(\d+) fragments=" + fragments + rb" video_samples=(\d+) audio_frames=(\d+)", output)
                if stats is None or int(stats.group(3)) == 0 or int(stats.group(4)) == 0:
                    raise ValueError("camera-derived A/V accounting missing")
                label = "camera_http_av_supervised_command=passed" if supervised else "camera_http_av_command=passed"
                print(label + " width=" + stats.group(1).decode() + " height=" + stats.group(2).decode()
                      + " video_samples=" + stats.group(3).decode() + " audio_frames=" + stats.group(4).decode())
        elif mode == "bad_readback":
            assert child.returncode != 0 and b"HTTP stream start refused; reconcile effect" in error
            assert b"trial_http_record=published" not in output and b"trial_task_outcome=effect_unsettled" in output
        elif mode in ("dimensions_mismatch", "bad_trailer"):
            assert child.returncode != 0 and b"camera media failed" in error
            if mode == "dimensions_mismatch":
                assert b"trial_http_record_media_refusal=recording:DimensionsMismatch" in error
            if mode == "bad_trailer":
                assert re.search(rb"trial_http_video_failure_tail=verified records=[1-9][0-9]* capture_time=unknown coverage=unproven", output)
                assert_spooled_wire(case, wire, 13 + 15 + int.from_bytes(wire[14:17], "big"))
            assert b"trial_http_record=published" not in output and b"trial_task_outcome=effect_unsettled" in output
        elif mode == "stale_after_stream":
            assert child.returncode != 0 and b"serializer observation changed after recording" in error
            assert b"readbacks=consistent" not in output and b"trial_task_outcome=effect_unsettled" in output
        elif mode == "post_read_failure":
            assert child.returncode != 0 and b"serializer observation unavailable" in error
            assert b"readbacks=consistent" not in output and b"trial_task_outcome=effect_unsettled" in output
        elif mode == "checkpoint_blocked":
            assert child.returncode != 0 and b"serializer observation checkpoint requires inspection" in error
            assert b"observation_checkpoint=anchored" not in output and b"trial_task_outcome=effect_unsettled" in output
        elif mode == "short_stream":
            assert child.returncode != 0 and b"camera stream ended" in error
            assert b"trial_http_record=published" not in output and b"trial_task_outcome=effect_unsettled" in output
            assert len(list((case / "archive" / "av" / "objects" / "roots").glob("*.root"))) == 1
        else:
            assert child.returncode != 0 and b"trial_http_record=published" not in output
            assert (b"serializer binding changed between reads" if mode == "changed" else b"UniFi stream listener refused") in error
            assert not (case / "checkpoint").exists() and not (case / "archive").exists()
        inspection = subprocess.run([binary, "--inspect-setup-fence", str(case / "fence"), str(cert[2]),
                                     str(case), "--owner-authorized"], capture_output=True, timeout=30)
        if supervised or mode in ("success", "g4", "zero_id_g4", "video_real", "bad_readback", "dimensions_mismatch", "bad_trailer", "stale_after_stream", "post_read_failure", "checkpoint_blocked", "short_stream", "av_supplied", "av_inband", "av_inband_avc", "av_auto", "av_auto_short", "av_changed_avc", "av_real", "av_bad_readback", "av_short", "av_stale", "av_conflict", "av_bootstrap_framing", "accept_timeout_no_opt") or (restore_mode and mode != "restore_missing"):
            if inspection.returncode != 0: raise ValueError("fence inspection failed: " + inspection.stderr.decode(errors="replace"))
            assert (b"operations=2 unresolved=2" if mode in ("restore_success", "restore_precondition_drift", "restore_object", "name_match", "name_mismatch", "metadata_flag_strict", "metadata_flag_zero", "metadata_flag_opaque", "restore_ignored", "restore_interrupted", "restore_checkpoint_blocked", "av_restore", "av_auto_restore", "av_name_match", "av_name_opaque", "av_name_mismatch", "av_auto_name_match", "av_auto_restore_short", "restore_short", "restore_short_ignored", "restore_bad_trailer", "av_restore_short", "av_restore_bad_avc", "restore_accept_timeout", "restore_accept_ignored", "av_restore_accept_timeout") else b"operations=1 unresolved=1") in inspection.stdout
            if mode in ("restore_success", "restore_ignored", "restore_object"):
                assert b"trial_http_restore_response=journaled response=peer_claim effect=unsettled" in output
                assert b"trial_http_start_response=journaled response=peer_claim effect=unsettled" in output
                assert b"committed=0 adapter_accepted=2 observed=0 verified=0" in inspection.stdout
            if mode == "restore_interrupted":
                assert b"trial_http_restore_response=journaled" not in output
                assert b"trial_http_start_response=journaled response=peer_claim effect=unsettled" in output
                assert b"committed=1 adapter_accepted=1 observed=0 verified=0" in inspection.stdout
            if mode in ("restore_start_unconfirmed", "bad_readback"):
                assert b"trial_http_start_response=journaled response=peer_claim effect=unsettled" in output
                assert b"committed=0 adapter_accepted=1 observed=0 verified=0" in inspection.stdout
        else:
            assert inspection.returncode != 0 and b"missing effect checkpoint" in inspection.stderr
        if mode in ("restore_success", "restore_precondition_drift", "restore_object", "name_match", "name_mismatch", "metadata_flag_strict", "metadata_flag_zero", "metadata_flag_opaque", "av_restore", "av_auto_restore", "av_name_match", "av_name_opaque", "av_name_mismatch", "av_auto_name_match", "av_auto_restore_short", "restore_short", "restore_bad_trailer", "av_restore_short", "av_restore_bad_avc", "restore_accept_timeout", "av_restore_accept_timeout"):
            before, after = case / "checkpoint", case / "checkpoint" / "restored"
            inspected = subprocess.run([binary, "--inspect-http-checkpoint", str(after), "--owner-authorized"], capture_output=True, timeout=30)
            assert inspected.returncode == 0 and b"trial_http_checkpoint_inspection=authenticated" in inspected.stdout
            compared = subprocess.run([binary, "--compare-http-restored-checkpoints", str(before), str(after), "--owner-authorized"], capture_output=True, timeout=30)
            assert compared.returncode == 0 and b"trial_http_restored_checkpoint_comparison=consistent" in compared.stdout
            assert b"effect=unsettled independence=unverified" in compared.stdout
            same = subprocess.run([binary, "--compare-http-restored-checkpoints", str(before), str(before), "--owner-authorized"], capture_output=True, timeout=30)
            assert same.returncode != 0 and b"restored checkpoint must be a separate observation" in same.stderr
            copied_root = case / "copied-checkpoint"
            shutil.copytree(before, copied_root)
            copied = subprocess.run([binary, "--compare-http-restored-checkpoints", str(before), str(copied_root), "--owner-authorized"], capture_output=True, timeout=30)
            assert copied.returncode != 0 and b"trial_http_restored_checkpoint_comparison=consistent" not in copied.stdout
            assert (b"checkpoint pin recovery refused" in copied.stderr or
                    b"restored checkpoint must be a distinct encrypted artifact" in copied.stderr)
            wrong = subprocess.run([binary, "--compare-http-restored-checkpoints", str(before), str(before / "observation"), "--owner-authorized"], capture_output=True, timeout=30)
            assert wrong.returncode != 0 and b"restored checkpoint differs from baseline" in wrong.stderr
            if mode in ("restore_success", "restore_object", "av_name_match", "av_name_mismatch"):
                fence_args = [binary, "--inspect-setup-fence-with-restored", str(case / "fence"), str(cert[2]), str(case), str(before), str(before / "observation")]
                combined = subprocess.run(fence_args + [str(after), "--owner-authorized"], capture_output=True, timeout=30)
                assert combined.returncode == 0 and b"trial_fence_restore_precondition=consistent effect_state=adapter_accepted request_binding=unverified settlement=none" in combined.stdout
                assert b"trial_fence_restore_acceptance_digest=present settlement=not_inferred" in combined.stdout
                assert b"operations=2 unresolved=2" in combined.stdout
                duplicate = subprocess.run(fence_args + [str(before / "observation"), "--owner-authorized"], capture_output=True, timeout=30)
                assert duplicate.returncode != 0 and b"restored checkpoint must be distinct" in duplicate.stderr
                request_args = [binary, "--inspect-setup-fence-with-restore-request", str(case / "fence"), str(cert[2]), str(case), str(before), str(before / "observation"), str(after)]
                request_match = subprocess.run(request_args + ["10.252.15.2", "--owner-authorized"], capture_output=True, timeout=30)
                assert request_match.returncode == 0 and b"trial_fence_restore_request=matches_baseline effect_state=adapter_accepted settlement=none" in request_match.stdout
                wrong_peer = subprocess.run(request_args + ["10.252.15.3", "--owner-authorized"], capture_output=True, timeout=30)
                assert wrong_peer.returncode != 0 and b"forward request or restore comparison invalid" in wrong_peer.stderr
            if mode == "restore_precondition_drift":
                fence_args = [binary, "--inspect-setup-fence-with-restored", str(case / "fence"), str(cert[2]), str(case), str(before), str(before / "observation"), str(after), "--owner-authorized"]
                changed = subprocess.run(fence_args, capture_output=True, timeout=30)
                assert changed.returncode != 0 and b"restore effect precondition does not match observation" in changed.stderr
                assert b"trial_fence_restore_precondition=consistent" not in changed.stdout
            assert all(value not in inspected.stdout + inspected.stderr + compared.stdout + compared.stderr + same.stdout + same.stderr + copied.stdout + copied.stderr + wrong.stdout + wrong.stderr for value in (b"10.252.15.11", b"10.252.15.12", b"fixture-cookie"))
        print(f"http_record_fixture case={case_name} result=pass")
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
    avc_av = Path(__file__).resolve().parent / "tests/support/synthetic_g4_av_gop3.264"
    for mode in ("success", "g4", "changed", "busy", "bad_readback", "dimensions_mismatch", "bad_trailer", "stale_after_stream", "post_read_failure", "checkpoint_blocked", "short_stream", "av_supplied", "av_inband"):
        run(binary, root, cert, avc_av if mode in ("av_supplied", "av_inband") else avc, mode)
    original = root / "success" / "checkpoint"
    for name, observation in (("same", original), ("wrong_request", root / "g4" / "checkpoint" / "observation")):
        compared = subprocess.run([binary, "--compare-http-checkpoints", str(original), str(observation), "--owner-authorized"],
                                  capture_output=True, timeout=30)
        assert compared.returncode != 0 and b"trial_http_checkpoint_comparison=consistent" not in compared.stdout
        assert (b"checkpoint observations do not match the requested change" if name == "same"
                else b"checkpoint camera or request claims differ") in compared.stderr
        print(f"http_checkpoint_pair case={name} result=pass")
    missing = subprocess.run([binary, "--compare-http-checkpoints", str(root / "bad_readback" / "checkpoint"), str(root / "bad_readback" / "checkpoint" / "observation"),
                              "--owner-authorized"], capture_output=True, timeout=30)
    assert missing.returncode != 0 and b"trial_http_checkpoint_comparison=consistent" not in missing.stdout
    print("http_checkpoint_pair case=missing result=pass")
    wrong_fence = subprocess.run([binary, "--inspect-setup-fence-with-checkpoints", str(root / "g4" / "fence"), str(cert[2]),
                                  str(root), str(original), str(original / "observation"), "--owner-authorized"],
                                 capture_output=True, timeout=30)
    assert wrong_fence.returncode != 0 and b"checkpoint does not match journaled effect" in wrong_fence.stderr
    assert b"trial_fence_checkpoint_match=consistent" not in wrong_fence.stdout
    print("http_checkpoint_journal case=wrong_fence result=pass")
    print("http_record_fixture passed=13 camera=synthetic resolution=2688x1512")
    print("http_checkpoint_pair passed=3 camera=synthetic")
    print("http_checkpoint_journal passed=3 camera=synthetic")
    print("http_checkpoint_live passed=3 camera=synthetic")


if __name__ == "__main__": main()
