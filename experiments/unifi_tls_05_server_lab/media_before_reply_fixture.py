#!/usr/bin/env python3
"""Disposable loopback TLS camera peer; no physical device or real media."""
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

from prehello_fixture import HEAD, exact, frame, message, received


def flv_tag(timestamp, payload):
    size = len(payload)
    header = bytes([9]) + size.to_bytes(3, "big") + (timestamp & 0xffffff).to_bytes(3, "big") + bytes([timestamp >> 24]) + b"\0\0\0"
    return header + payload + (11 + size).to_bytes(4, "big")


def media_fixture(path):
    source = Path(path).read_bytes()
    starts = list(re.finditer(b"\x00\x00\x00\x01|\x00\x00\x01", source))
    nals = [source[item.end():starts[i + 1].start() if i + 1 < len(starts) else len(source)] for i, item in enumerate(starts)]
    nals = [nal for nal in nals if nal]
    sps = next(nal for nal in nals if nal[0] & 31 == 7)
    pps = next(nal for nal in nals if nal[0] & 31 == 8)
    pictures = [nal for nal in nals if nal[0] & 31 in (1, 5)]
    if len(pictures) != 4 or pictures[0][0] & 31 != 5:
        raise ValueError("unexpected disposable AVC fixture")
    config = bytes([0x17, 0, 0, 0, 0, 1, sps[1], sps[2], sps[3], 0xff, 0xe1])
    config += len(sps).to_bytes(2, "big") + sps + b"\x01" + len(pps).to_bytes(2, "big") + pps
    result = b"FLV\x01\x01\x00\x00\x00\x09\x00\x00\x00\x00" + flv_tag(0, config)
    for index in range(7):
        nal = pictures[index % 3]
        result += flv_tag(index * 40, b"\x17\x01\x00\x00\x00" + len(nal).to_bytes(4, "big") + nal)
    return result


def run_case(binary, cert, key, root, media, early_reply, close_before_media=False, event_case=False, startup_event_case=False):
    root.mkdir(mode=0o700)
    reserve = socket.socket()
    reserve.bind(("127.0.0.1", 0))
    port = reserve.getsockname()[1]
    reserve.close()
    journal, clip = root / "journal", root / "clip.mp4"
    command = [binary, f"127.0.0.1:{port}", "127.0.0.1", "001122aabbcc", str(cert), str(key),
               str(journal), str(clip), "12345678-1234-4abc-9abc-123456789abc", "30",
               "--media-before-reply", "--owner-authorized"]
    child = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    prefix = b""
    try:
        end = time.monotonic() + 15
        while True:
            try:
                raw = socket.create_connection(("127.0.0.1", port), timeout=1)
                break
            except OSError:
                if child.poll() is not None or time.monotonic() >= end:
                    raise RuntimeError("controller did not start")
                time.sleep(0.05)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE  # Disposable loopback certificate only.
        with context.wrap_socket(raw, server_hostname="localhost") as control:
            control.settimeout(20)
            request = HEAD
            if startup_event_case:
                request += frame(message("EventSmartDetect", 19, payload={
                    "edgeType": "enter", "private": "TEST_PRIVATE_MARKER",
                    "descriptors": [{"objectType": "person", "confidenceLevel": 80}],
                }))
            control.sendall(request + frame(message("ubnt_avclient_hello", 7, payload={})))
            header = bytearray()
            while not header.endswith(b"\r\n\r\n"):
                header.extend(exact(control, 1))
                if len(header) > 4096:
                    raise ValueError("upgrade limit")
            if not header.startswith(b"HTTP/1.1 101 "):
                raise ValueError("upgrade refused")
            hello, agreement = received(control), received(control)
            if hello.get("functionName") != "ubnt_avclient_hello" or agreement.get("functionName") != "ubnt_avclient_paramAgreement":
                raise ValueError("hello or agreement missing")
            control.sendall(frame(message("ubnt_avclient_paramAgreement", 8, agreement["messageId"])))
            setting = received(control)
            if setting.get("functionName") != "ChangeVideoSettings":
                raise ValueError("stream request missing")
            if early_reply:
                control.sendall(frame(message("ChangeVideoSettings", 9, setting["messageId"])))
            control.sendall(frame(message("ubnt_avclient_timeSync", 10)))
            sync = received(control)
            if sync.get("functionName") != "ubnt_avclient_timeSync" or sync.get("inResponseTo") != 10:
                raise ValueError("pre-media clock request was not answered")
            if close_before_media:
                control.shutdown(socket.SHUT_RDWR)
            else:
                dest = setting["payload"]["video"]["video2"]["avSerializer"]["destinations"][0]
                parsed = urlsplit(dest)
                if parsed.scheme != "tcp" or parsed.hostname != "127.0.0.1" or not parsed.port:
                    raise ValueError("media destination escaped loopback")
                with socket.create_connection((parsed.hostname, parsed.port), timeout=5) as stream:
                    if event_case:
                        # The reply is logged only after the listener has accepted
                        # media; wait for it before emitting a supervised event.
                        stream.sendall(media[:1])
                        control.sendall(frame(message("ChangeVideoSettings", 9, setting["messageId"])))
                        end = time.monotonic() + 15
                        while b"trial_stage=stream_reply_observed" not in prefix:
                            remaining = end - time.monotonic()
                            if remaining <= 0 or not select.select([child.stdout], [], [], remaining)[0]:
                                raise RuntimeError("supervised reply marker timed out")
                            chunk = os.read(child.stdout.fileno(), 4096)
                            if not chunk:
                                raise RuntimeError("controller exited before reply marker")
                            prefix += chunk
                            if len(prefix) > 16384:
                                raise RuntimeError("controller diagnostic limit")
                        control.sendall(frame(message("EventSmartDetect", 20, payload={
                            "edgeType": "enter", "private": "TEST_PRIVATE_MARKER",
                            "descriptors": [{"objectType": "person", "confidenceLevel": 80}],
                        })))
                        control.sendall(frame(message("ubnt_avclient_timeSync", 11)))
                        sync = received(control)
                        if sync.get("functionName") != "ubnt_avclient_timeSync" or sync.get("inResponseTo") != 11:
                            raise ValueError("post-event clock request was not answered")
                        stream.sendall(media[1:])
                    else:
                        stream.sendall(media)
            out, err = child.communicate(timeout=30)
        report = (prefix + out).decode("utf-8", "replace")
        if close_before_media:
            expected = ("trial_stage=startup_trace dispatch_observed=true clock_requests=1 "
                        "clock_replies_written=1 settings_replies=1 effects_require_reconciliation=true")
            if child.returncode == 0 or expected not in report or clip.exists() or not journal.is_dir():
                raise RuntimeError("failure trace or reconciliation evidence missing: " + report[-1000:])
            if startup_event_case and ("trial_stage=startup_events_omitted frames=1" not in report
                                       or "TEST_PRIVATE_MARKER" in report):
                raise RuntimeError("startup event omission accounting missing or payload leaked")
            case = "peer_closed_after_startup_event" if startup_event_case else "peer_closed"
            print(f"loopback case={case} trace=retained effects=reconciliation_required clip=absent identity=synthetic")
            return
        if (child.returncode or "trial_complete" not in report or "trial_media_before_reply=true" not in report
                or "effects=reconciliation_required" not in report or "continuous_recording=false" not in report):
            raise RuntimeError("trial did not produce a completed clip: " + err.decode("utf-8", "replace")[-500:])
        observed = "trial_stage=stream_reply_observed" in report
        if observed != (early_reply or event_case) or not clip.is_file() or not journal.is_dir():
            raise ValueError("reply observation or artifact mismatch")
        if (event_case or startup_event_case) and ("trial_stage=camera_event kind=SmartDetect" not in report
                                                   or "TEST_PRIVATE_MARKER" in report):
            raise ValueError("supervised event missing or payload leaked")
        probe = subprocess.run(["ffprobe", "-v", "error", "-select_streams", "v:0", "-count_frames",
                                "-show_entries", "stream=codec_name,width,height,nb_read_frames", "-of", "json", str(clip)],
                               capture_output=True, check=True, timeout=20)
        streams = json.loads(probe.stdout)["streams"]
        if len(streams) != 1 or streams[0]["codec_name"] != "h264" or int(streams[0]["nb_read_frames"]) < 1:
            raise ValueError("independent clip probe failed")
        case = "startup_event" if startup_event_case else ("camera_event" if event_case else ("early_reply" if early_reply else "no_reply"))
        print(f"loopback case={case} pre_media_sync=answered clip=decoded frames={streams[0]['nb_read_frames']} identity=synthetic")
    finally:
        if child.poll() is None:
            child.terminate()
        try:
            child.communicate(timeout=5)
        except subprocess.TimeoutExpired:
            child.kill()
            child.communicate(timeout=5)


def main():
    if len(sys.argv) != 3:
        raise SystemExit("expected controller binary and disposable AVC fixture")
    binary = str(Path(sys.argv[1]).resolve())
    media = media_fixture(sys.argv[2])
    with tempfile.TemporaryDirectory(prefix="fss-unifi-media-first-") as directory:
        root = Path(directory)
        pem, pem_key = root / "cert.pem", root / "key.pem"
        cert, key = root / "cert.der", root / "key.der"
        subprocess.run(["openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256",
                        "-nodes", "-keyout", str(pem_key), "-out", str(pem), "-days", "1", "-subj", "/CN=localhost"],
                       check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        subprocess.run(["openssl", "x509", "-in", str(pem), "-outform", "der", "-out", str(cert)], check=True)
        subprocess.run(["openssl", "pkcs8", "-topk8", "-nocrypt", "-in", str(pem_key), "-outform", "der", "-out", str(key)], check=True)
        os.chmod(key, 0o600)
        run_case(binary, cert, key, root / "early", media, True)
        run_case(binary, cert, key, root / "none", media, False)
        run_case(binary, cert, key, root / "closed", media, True, close_before_media=True)
        run_case(binary, cert, key, root / "event", media, False, event_case=True)
        run_case(binary, cert, key, root / "startup", media, False, startup_event_case=True)
        run_case(binary, cert, key, root / "startup_closed", media, True, close_before_media=True, startup_event_case=True)


if __name__ == "__main__":
    main()
