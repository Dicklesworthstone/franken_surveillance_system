#!/usr/bin/env python3
"""Test the scoped trial's setup-to-stream profile choice with a fake camera.

The supplied IPv4 address must already belong to this host. Every socket is
bound to it and discovery is unicast to it; no physical camera is contacted.
The fixture creates throwaway credentials, keys, and journals in a temp dir.
"""
import ipaddress
import json
import os
from pathlib import Path
import re
import select
import socket
import ssl
import subprocess
import sys
import tempfile
import time
from urllib.parse import urlsplit

MAC = bytes.fromhex("001122aabbcc")
HEAD = (b"GET / HTTP/1.1\r\nHost: camera.local\r\nUpgrade: websocket\r\n"
        b"Connection: Upgrade\r\nSec-WebSocket-Version: 13\r\n"
        b"Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n"
        b"Camera-Mac: 001122aabbcc\r\nSec-WebSocket-Protocol: secure_transfer\r\n\r\n")


def frame(message):
    data = json.dumps(message, separators=(",", ":")).encode()
    if len(data) > 4096:
        raise ValueError("fixture frame too large")
    mask = b"\x01\x02\x03\x04"
    length = bytes((0x80 | len(data),)) if len(data) < 126 else b"\xfe" + len(data).to_bytes(2, "big")
    return b"\x82" + length + mask + bytes(b ^ mask[i % 4] for i, b in enumerate(data))


def message(name, mid, response_to=None, payload=None):
    value = {"from": "ubnt_avclient", "to": "UniFiVideo", "functionName": name, "messageId": mid}
    if response_to is not None:
        value["inResponseTo"] = response_to
    if payload is not None:
        value["payload"] = payload
    return value


def exact(sock, count):
    result = bytearray()
    while len(result) < count:
        part = sock.recv(count - len(result))
        if not part:
            raise EOFError("fixture peer closed")
        result.extend(part)
    return bytes(result)


def received(sock):
    head = exact(sock, 2)
    if head[0] != 0x82 or head[1] & 0x80:
        raise ValueError("unexpected controller frame")
    size = head[1]
    if size == 126:
        size = int.from_bytes(exact(sock, 2), "big")
    if size > 4096:
        raise ValueError("controller frame too large")
    return json.loads(exact(sock, size))


def advertisement(address):
    body = b"".join(bytes([kind]) + len(value).to_bytes(2, "big") + value for kind, value in (
        (1, MAC), (2, MAC + socket.inet_aton(address)), (3, b"UVC.fixture"), (12, b"UVC G4 Instant")))
    return b"\x01\x00" + len(body).to_bytes(2, "big") + body


def archive_media(path, flv_tag, audio=False):
    """Match the existing managed-rollover fixture's four-picture cycle."""
    source = Path(path).read_bytes()
    starts = list(re.finditer(b"\x00\x00\x00\x01|\x00\x00\x01", source))
    nals = [source[item.end():starts[i + 1].start() if i + 1 < len(starts) else len(source)]
            for i, item in enumerate(starts)]
    nals = [nal for nal in nals if nal]
    sps = next(nal for nal in nals if nal[0] & 31 == 7)
    pps = next(nal for nal in nals if nal[0] & 31 == 8)
    pictures = [nal for nal in nals if nal[0] & 31 in (1, 5)]
    if len(pictures) != 4 or pictures[0][0] & 31 != 5:
        raise ValueError("unexpected archive AVC input")
    config = bytes([0x17, 0, 0, 0, 0, 1, sps[1], sps[2], sps[3], 0xff, 0xe1])
    config += len(sps).to_bytes(2, "big") + sps + b"\x01" + len(pps).to_bytes(2, "big") + pps
    result = (b"FLV\x01\x05" if audio else b"FLV\x01\x01") + b"\x00\x00\x00\x09\x00\x00\x00\x00" + flv_tag(0, config)
    for index in range(13):
        nal = pictures[index % 4]
        if audio:
            tag = bytearray(flv_tag(index * 64, b"\xaf\x01\x02"))
            tag[0] = 8
            result += tag
        result += flv_tag(index * 40, b"\x17\x01\x00\x00\x00" + len(nal).to_bytes(4, "big") + nal)
    return result


def stop_child(child):
    if child.poll() is None:
        child.terminate()
    try:
        return child.communicate(timeout=15)
    except subprocess.TimeoutExpired:
        child.kill()
        return child.communicate(timeout=5)


def serve_http(tls, controller_port, address, profiles, needs_handoff=False, finish_handoff=False, changed=False):
    routes = (b"POST /api/1.1/login ", b"GET /api/1.1/status ",
              b"GET /api/1.1/settings ", b"GET /api/1.1/settings ")
    if finish_handoff:
        routes += (b"PUT /api/1.1/settings ", b"GET /api/1.1/settings ")
    prior = "192.168.1.10" if address != "192.168.1.10" else "192.168.1.11"
    settings = json.dumps({"controller": {"addr": prior if needs_handoff else address}, "av": {"video": profiles}}, separators=(",", ":")).encode()
    for index, route in enumerate(routes):
        header = bytearray()
        while not header.endswith(b"\r\n\r\n"):
            header.extend(exact(tls, 1))
            if len(header) > 8192:
                raise ValueError("HTTP header limit")
        if not header.startswith(route):
            raise ValueError("unexpected setup request")
        length = next((int(line.split(b":", 1)[1]) for line in bytes(header).split(b"\r\n")
                       if line.lower().startswith(b"content-length:")), 0)
        if length > 4096:
            raise ValueError("HTTP body limit")
        request_body = exact(tls, length)
        if index == 4 and json.loads(request_body) != {"controller": {"addr": address}}:
            raise ValueError("handoff targeted an unexpected destination")
        body = (b"{}" if index == 0 else
                json.dumps({"controller": {"port": controller_port}}).encode() if index == 1 else
                b'{"success":true}' if index == 4 else
                json.dumps({"controller": {"addr": address}, "av": {"video": {**profiles, "video1": {"width": 640, "height": 360, "fps": 15}} if changed else profiles}}, separators=(",", ":")).encode() if index == 5 else settings)
        cookie = b"Set-Cookie: authId=fixture-cookie\r\n" if index == 0 else b""
        tls.sendall(b"HTTP/1.1 200 OK\r\n" + cookie + b"Content-Length: " + str(len(body)).encode()
                    + b"\r\nConnection: keep-alive\r\n\r\n" + body)


def run(binary, address, root, certs, name, profiles, expected, override=None, media=None, archive=False, clock_burst=None, auto_pin=False):
    case = root / name
    case.mkdir(mode=0o700)
    credential = case / "credential.json"
    credential.write_text('{"username":"fixture","password":"synthetic"}')
    os.chmod(credential, 0o600)
    udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp.bind((address, 0))
    udp.settimeout(15)
    https = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    https.bind((address, 0))
    https.listen(1)
    https.settimeout(15)
    reserve = socket.socket()
    reserve.bind((address, 0))
    controller_port = reserve.getsockname()[1]
    reserve.close()
    pem, pem_key, cert, key = certs
    server = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    server.minimum_version = ssl.TLSVersion.TLSv1_3
    server.num_tickets = 0
    server.load_cert_chain(pem, pem_key)
    command = [binary, f"{address}:{controller_port}", "auto" if auto_pin else address, "auto" if auto_pin else MAC.hex(), str(cert), str(key),
               str(case / "journal"), str(case / "clip.mp4"), "12345678-1234-4abc-9abc-123456789abc", "20"]
    if override:
        command.append(f"--video-channel={override}")
    if clock_burst == "continuing":
        command.append("--bounded-continuing-clock")
    if media is not None:
        command.append("--media-before-reply")
        if name in ("full-empty-events", "full-empty-control", "full-idle-control", "full-prefix-control"):
            command.append("--reply-events")
        if archive == "av":
            command.append("--lab-aac-config=1408")
        command.append("--lab-segments=3" if archive else "--lab-segments=2")
    if auto_pin:
        command.extend(["--auto-discovery=24", f"--discovery-hint={address}", "--lab-auto-pinned-setup", f"--lab-setup-fence={root / 'camera-fence'}"])
    if archive:
        command.append("--lab-owned-archive")
        if archive != "av":
            command.append("--lab-video-only-archive")
        command.extend(["--lab-managed-archive", "--lab-av-history-records=5", "--lab-decode-owned"])
    if auto_pin:
        command.append(f"--anchored-journal={case / 'keeper'},{case / 'root'}")
    command += [f"--setup-camera={udp.getsockname()[1]},{https.getsockname()[1]},{cert},{credential}", "--owner-authorized"]
    child = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    output = b""
    try:
        _, source = udp.recvfrom(1024)
        udp.sendto(advertisement(address), source)
        if auto_pin:
            raw, _ = https.accept()
            raw.settimeout(8)
            with server.wrap_socket(raw, server_side=True) as probe:
                try:
                    if probe.recv(1):
                        raise ValueError("pin probe sent application data")
                except (ssl.SSLEOFError, ssl.SSLZeroReturnError, ConnectionResetError, BrokenPipeError):
                    pass
        raw, _ = https.accept()
        with server.wrap_socket(raw, server_side=True) as camera:
            camera.settimeout(15)
            handoff = name.startswith("handoff-") or name.startswith("auto-handoff-")
            serve_http(camera, controller_port, address, profiles, needs_handoff=expected is None or handoff, finish_handoff=handoff, changed=name == "handoff-changed")
            if expected is None:
                try:
                    sent = camera.recv(1)
                except ssl.SSLError:
                    sent = b""
                if sent:
                    raise ValueError("camera received a request after preflight refusal")
                out, err = child.communicate(timeout=15)
                output = out + err
                if child.returncode == 0 or b"VideoProfileUnavailable" not in output:
                    raise ValueError("missing profiles were not refused before handoff: " + output.decode(errors="replace")[-1000:])
                if b"dispatch_started=false accept_started=false" not in output:
                    raise ValueError("pre-effect refusal trace missing")
                print(f"trial_profile_fixture case={name} handoff=not_dispatched result=pass", flush=True)
                return
            client = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            client.check_hostname = False
            client.verify_mode = ssl.CERT_NONE  # Disposable local fixture cert.
            with client.wrap_socket(socket.create_connection((address, controller_port), timeout=15), server_hostname="localhost") as control:
                control.settimeout(15)
                control.sendall(HEAD + (b"" if clock_burst else frame(message("ubnt_avclient_hello", 7, payload={}))))
                header = bytearray()
                while not header.endswith(b"\r\n\r\n"):
                    header.extend(exact(control, 1))
                    if len(header) > 4096:
                        raise ValueError("upgrade header limit")
                if not header.startswith(b"HTTP/1.1 101 "):
                    raise ValueError("upgrade refused")
                if clock_burst:
                    first = message("ubnt_avclient_timeSync", 61)
                    first["responseExpected"] = True
                    control.sendall(frame(first))
                    first_reply = received(control)
                    if first_reply.get("functionName") != "ubnt_avclient_timeSync" or first_reply.get("inResponseTo") != 61:
                        raise ValueError("first pre-hello clock reply missing")
                    second = message("ubnt_avclient_timeSync", 62, first_reply["messageId"])
                    second["responseExpected"] = True
                    control.sendall(frame(second))
                    if clock_burst == "conservative":
                        control.settimeout(2)
                        try:
                            received(control)
                        except socket.timeout:
                            pass
                        else:
                            raise ValueError("conservative policy answered a correlated clock message")
                        control.close()
                        out, err = child.communicate(timeout=15)
                        output = out + err
                        if child.returncode == 0 or b"sync_correlated=1" not in output or b"sync_expected_to_last_written=1" not in output:
                            raise ValueError("conservative clock stop was not retained: " + output.decode(errors="replace")[-1600:])
                        print(f"trial_profile_fixture case={name} correlated_clock=ignored effects=reconciliation_required result=pass", flush=True)
                        return
                    second_reply = received(control)
                    if second_reply.get("functionName") != "ubnt_avclient_timeSync" or second_reply.get("inResponseTo") != 62:
                        raise ValueError("correlated pre-hello clock reply missing")
                    control.sendall(frame(message("ubnt_avclient_hello", 7, payload={})))
                if name == "handoff-changed":
                    out, err = child.communicate(timeout=15)
                    output = out + err
                    if auto_pin and (b"trial_pin_discovery=matched candidates=1 credentials_sent=false" not in output or b"trial_setup_fence=created" not in output or b"trial_journal=anchored" not in output):
                        raise ValueError("automatic pinned setup or anchored journal trace missing")
                    if auto_pin and b"trial_task_outcome=effect_unsettled" not in output:
                        raise ValueError("automatic setup lost its unsettled effect outcome")
                    if clock_burst == "continuing" and b"trial_stage=startup_protocol_trace clocks=2" not in output:
                        raise ValueError("pre-hello clock effect traces missing")
                    if child.returncode == 0 or b"video profile changed after setup" not in output or b"dispatch_started=true accept_started=true" not in output:
                        raise ValueError("changed readback did not stop stream: " + output.decode(errors="replace")[-1000:])
                    if control.recv(1):
                        raise ValueError("changed profile produced a stream request")
                    print(f"trial_profile_fixture case={name} stream=not_dispatched handoff=reconciliation_required result=pass", flush=True)
                    return
                if expected is not None:
                    hello = received(control)
                    if hello.get("functionName") != "ubnt_avclient_hello":
                        raise ValueError("hello missing")
                    agreement = received(control)
                    if agreement.get("functionName") != "ubnt_avclient_paramAgreement":
                        raise ValueError("agreement missing")
                    control.sendall(frame(message("ubnt_avclient_paramAgreement", 8, agreement["messageId"])))
                    stream = received(control)
                    if stream.get("functionName") != "ChangeVideoSettings" or set(stream.get("payload", {}).get("video", {})) != {expected}:
                        raise ValueError("wrong stream profile requested")
                    if media is None:
                        out, err = stop_child(child)
                    else:
                        control.sendall(frame(message("ChangeVideoSettings", 9, stream["messageId"])))
                        control.sendall(frame(message("ubnt_avclient_timeSync", 10)))
                        sync = received(control)
                        if sync.get("functionName") != "ubnt_avclient_timeSync" or sync.get("inResponseTo") != 10:
                            raise ValueError("time sync reply missing")
                        target = urlsplit(stream["payload"]["video"][expected]["avSerializer"]["destinations"][0])
                        if target.scheme != "tcp" or target.hostname != address or not target.port:
                            raise ValueError("media destination escaped fixture address")
                        prefix = b""
                        if name in ("full-empty-first", "full-empty-events", "full-empty-av", "full-empty-control"):
                            with socket.create_connection((address, target.port), timeout=5):
                                pass
                        held = []
                        if name == "full-idle-control":
                            held.append(socket.create_connection((address, target.port), timeout=5))
                        if name == "full-prefix-control":
                            for prefix_byte in (b"X", b"F"):
                                candidate = socket.create_connection((address, target.port), timeout=5)
                                candidate.sendall(prefix_byte)
                                held.append(candidate)
                        if name in ("full-empty-control", "full-idle-control", "full-prefix-control"):
                            deadline = time.monotonic() + 10
                            marker = b"trial_stage=media_candidate_selection_started"
                            while marker not in prefix:
                                remaining = deadline - time.monotonic()
                                if remaining <= 0 or not select.select([child.stdout], [], [], remaining)[0]:
                                    raise TimeoutError("candidate selection did not begin")
                                chunk = os.read(child.stdout.fileno(), 4096)
                                if not chunk:
                                    raise EOFError("trial stopped before candidate selection")
                                prefix += chunk
                                if len(prefix) > 65536:
                                    raise ValueError("fixture output limit")
                            request = message("ubnt_avclient_timeSync", 11)
                            request["responseExpected"] = True
                            control.sendall(frame(request))
                            reply = received(control)
                            if reply.get("functionName") != "ubnt_avclient_timeSync" or reply.get("inResponseTo") != 11:
                                raise ValueError("selection-time clock reply missing")
                            event = message("EventSmartMotion", 78, payload={"active": True})
                            event["responseExpected"] = True
                            control.sendall(frame(event))
                            reply = received(control)
                            if reply.get("functionName") != "EventSmartMotion" or reply.get("inResponseTo") != 78:
                                raise ValueError("selection-time event reply missing")
                        with socket.create_connection((address, target.port), timeout=5) as transport:
                            transport.sendall(media)
                        try:
                            out, err = child.communicate(timeout=90)
                        finally:
                            for candidate in held:
                                candidate.close()
                        out = prefix + out
                        if child.returncode != 0 or b"trial_complete" not in out:
                            report = out.decode(errors="replace")
                            raise RuntimeError("synthetic media trial failed: " + err.decode(errors="replace")[-1200:] + " stages=" + " | ".join(report.splitlines()[-20:]))
                        if name in ("full-empty-first", "full-empty-events", "full-empty-av", "full-empty-control", "full-idle-control") and b"trial_stage=media_candidate_selected attempts=2 header_retained=true" not in out:
                            raise ValueError("empty-first selection marker missing")
                        if name in ("full-empty-control", "full-idle-control", "full-prefix-control") and (b"trial_stage=media_selection_control clocks=2 event_replies=1" not in out or b"trial_owned_startup_event=already_answered" not in out):
                            raise ValueError("selection-time control trace missing or event not retained")
                        if name == "full-idle-control" and b"trial_stage=unselected_media_candidate source_bytes_omitted=0 unread_bytes_unknown=true" not in out:
                            raise ValueError("idle candidate omission not reported")
                        if name == "full-prefix-control" and (b"trial_stage=media_candidate_selected attempts=3 header_retained=true" not in out or out.count(b"trial_stage=unselected_media_candidate source_bytes_omitted=1 unread_bytes_unknown=true") != 2):
                            raise ValueError("invalid or partial prefix not retained and accounted")
                        clip = case / "clip.mp4"
                        if archive:
                            report = out.decode(errors="replace")
                            common = ("trial_complete archive=published segments=3", "trial_owned_readback segments=3", "trial_owned_sequence segments=3")
                            video = ("trial_owned_driver=video_only", "trial_owned_video_bootstrap=ready", "trial_owned_video_supply=installed custody=retained", "trial_owned_video_rollover=resumed outcome=AlreadyLedgered", "trial_owned_tail=archived ", "trial_owned_controller_retirement=observed reconciliation_required=false remote_effects=unverified")
                            av = ("trial_owned_driver=managed first_generation=1", "trial_owned_supply=installed custody=retained", "trial_owned_rollover=resumed outcome=AlreadyLedgered")
                            required = common + (av if archive == "av" else video)
                            if any(marker not in report for marker in required):
                                raise ValueError("archive marker missing: " + " | ".join(report.splitlines()[-30:]))
                            if not clip.is_dir() or any(not (clip / part).is_dir() for part in ("source", "av", "av-intent")) or clip.stat().st_mode & 0o077:
                                raise ValueError("private archive directories missing")
                            lineage = next((line for line in report.splitlines() if line.startswith("trial_owned_lineage_readback generations=")), "")
                            decoded = next((line for line in report.splitlines() if line.startswith("trial_owned_decoded ")), "")
                            fields = dict(part.split("=", 1) for part in decoded.split() if "=" in part)
                            lineage_fields = dict(part.split("=", 1) for part in lineage.split() if "=" in part)
                            if archive != "av" and (int(lineage_fields.get("generations", 0)) < 2 or int(lineage_fields.get("confirmed", 0)) != 3 or lineage_fields.get("boundary_duplicates") != "excluded"):
                                raise ValueError("archive lineage mismatch: " + lineage)
                            if archive == "av":
                                readback = next((line for line in report.splitlines() if line.startswith("trial_owned_readback ")), "")
                                readback_fields = dict(part.split("=", 1) for part in readback.split() if "=" in part)
                                if int(readback_fields.get("audio_frames", 0)) < 1 or int(readback_fields.get("video_samples", 0)) < 1:
                                    raise ValueError("A/V readback empty: " + readback)
                            if fields.get("width") != "2688" or fields.get("height") != "1512" or int(fields.get("frames", 0)) < (1 if archive == "av" else 5) or (archive != "av" and (fields.get("frames") != fields.get("samples") or fields.get("decode_mode") != "streamed_prefix")):
                                raise ValueError("archive decode mismatch: " + decoded)
                            streams = [{"nb_read_frames": fields["frames"]}]
                        else:
                            probe = subprocess.run(["ffprobe", "-v", "error", "-select_streams", "v:0", "-count_frames", "-show_entries", "stream=width,height,nb_read_frames", "-of", "json", str(clip)], capture_output=True, check=True, timeout=20)
                            streams = json.loads(probe.stdout)["streams"]
                            if len(streams) != 1 or streams[0]["width"] != 2688 or streams[0]["height"] != 1512 or int(streams[0]["nb_read_frames"]) < 6:
                                raise ValueError("synthetic high-resolution media output mismatch")
                            subprocess.run(["ffmpeg", "-v", "error", "-xerror", "-i", str(clip), "-map", "0:v:0", "-f", "null", "-"], capture_output=True, check=True, timeout=30)
                    output = out + err
                    if override is None and f"trial_video_channel_selected=Video{expected[-1]}".encode() not in output:
                        raise ValueError("selection marker missing")
        archive_detail = (f"segments=3 audio_packets={readback_fields['audio_frames']} video_rust_decode" if archive == "av" else
                          f"segments=3 generations={lineage_fields['generations']} archive_readback_and_rust_decode" if archive else "independent_decode")
        detail = (f" width=2688 height=1512 frames={streams[0]['nb_read_frames']} {archive_detail}=pass"
                  if media is not None else "")
        print(f"trial_profile_fixture case={name} selected={expected or 'none'}{detail} result=pass", flush=True)
    except Exception:
        if auto_pin:
            out, err = stop_child(child) if child.poll() is None else child.communicate()
            print("auto_setup_fixture diagnostic=" + (out + err).decode(errors="replace")[-3000:], flush=True)
        raise
    finally:
        if child.poll() is None:
            stop_child(child)
        udp.close()
        https.close()


def main():
    if len(sys.argv) not in (3, 5):
        raise SystemExit("expected trial binary and locally assigned private IPv4 [old fixture directory synthetic AVC]")
    binary, address = str(Path(sys.argv[1]).resolve()), sys.argv[2]
    if not ipaddress.IPv4Address(address).is_private or ipaddress.IPv4Address(address).is_loopback:
        raise SystemExit("expected a non-loopback private IPv4 address")
    with tempfile.TemporaryDirectory(prefix="fss-scoped-profile-") as temporary:
        root = Path(temporary)
        pem, pem_key, cert, key = (root / name for name in ("cert.pem", "key.pem", "cert.der", "key.der"))
        subprocess.run(["openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes", "-keyout", str(pem_key), "-out", str(pem), "-days", "1", "-subj", "/CN=localhost"], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        subprocess.run(["openssl", "x509", "-in", str(pem), "-outform", "der", "-out", str(cert)], check=True)
        subprocess.run(["openssl", "pkcs8", "-topk8", "-nocrypt", "-in", str(pem_key), "-outform", "der", "-out", str(key)], check=True)
        os.chmod(key, 0o600)
        profiles = {"video1": {"width": 2688, "height": 1512, "fps": 30},
                    "video2": {"width": 1280, "height": 720, "fps": 30},
                    "video3": {"width": 640, "height": 360, "fps": 15}}
        run(binary, address, root, (pem, pem_key, cert, key), "full", profiles, "video1")
        run(binary, address, root, (pem, pem_key, cert, key), "fallback", {**profiles, "video1": {"width": 8192, "height": 4320, "fps": 30}}, "video2")
        run(binary, address, root, (pem, pem_key, cert, key), "missing", {}, None)
        run(binary, address, root, (pem, pem_key, cert, key), "explicit", profiles, "video3", "3")
        run(binary, address, root, (pem, pem_key, cert, key), "handoff-valid", profiles, "video1")
        run(binary, address, root, (pem, pem_key, cert, key), "handoff-changed", profiles, "video1")
        if len(sys.argv) == 5:
            sys.path.insert(0, str(Path(sys.argv[3]).resolve()))
            from media_before_reply_fixture import flv_tag, media_fixture
            run(binary, address, root, (pem, pem_key, cert, key), "full-media", profiles, "video1", media=media_fixture(sys.argv[4]))
            run(binary, address, root, (pem, pem_key, cert, key), "full-empty-first", profiles, "video1", media=media_fixture(sys.argv[4]))
            run(binary, address, root, (pem, pem_key, cert, key), "full-empty-events", profiles, "video1", media=archive_media(sys.argv[4], flv_tag), archive="video")
            run(binary, address, root, (pem, pem_key, cert, key), "full-empty-av", profiles, "video1", media=archive_media(sys.argv[4], flv_tag, audio=True), archive="av")
            run(binary, address, root, (pem, pem_key, cert, key), "full-empty-control", profiles, "video1", media=archive_media(sys.argv[4], flv_tag), archive="video")
            run(binary, address, root, (pem, pem_key, cert, key), "full-idle-control", profiles, "video1", media=archive_media(sys.argv[4], flv_tag), archive="video")
            run(binary, address, root, (pem, pem_key, cert, key), "full-prefix-control", profiles, "video1", media=archive_media(sys.argv[4], flv_tag), archive="video")
            run(binary, address, root, (pem, pem_key, cert, key), "full-managed-archive", profiles, "video1", media=archive_media(sys.argv[4], flv_tag), archive="video")
            run(binary, address, root, (pem, pem_key, cert, key), "full-managed-av", profiles, "video1", media=archive_media(sys.argv[4], flv_tag, audio=True), archive="av")
            run(binary, address, root, (pem, pem_key, cert, key), "handoff-clock-conservative", profiles, "video1", clock_burst="conservative")
            run(binary, address, root, (pem, pem_key, cert, key), "handoff-clock-full-managed", profiles, "video1", media=archive_media(sys.argv[4], flv_tag), archive="video", clock_burst="continuing")


if __name__ == "__main__":
    main()
