#!/usr/bin/env python3
"""Disposable loopback TLS camera peer; no physical device or real media."""
import json
from decimal import Decimal
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


def flv_tag(timestamp, payload, kind=9):
    size = len(payload)
    header = bytes([kind]) + size.to_bytes(3, "big") + (timestamp & 0xffffff).to_bytes(3, "big") + bytes([timestamp >> 24]) + b"\0\0\0"
    return header + payload + (11 + size).to_bytes(4, "big")


def media_fixture(path, audio_frames=None, audio_step=64, inband=False, late_config=False, g4_trailers=False, corrupt_trailer=False, zero_decoy=False, clock_base=0, audio_offset=0, audio_timestamp_skew=0, video_count=7, second_audio_shift=0):
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
    result = b"FLV\x01" + (b"\x05" if audio_frames else b"\x01") + b"\x00\x00\x00\x09\x00\x00\x00\x00"
    prefix = [flv_tag(0, config)]
    if inband:
        prefix.append(flv_tag(0, b"\xaf\x00\x14\x08", 8))
    tags = []
    if late_config:
        tags.append((1, flv_tag(1, b"\xaf\x00\x14\x08", 8)))
    for index in range(video_count):
        nal = pictures[index % 3]
        tags.append((index * 40, flv_tag(clock_base + index * 40, b"\x17\x01\x00\x00\x00" + len(nal).to_bytes(4, "big") + nal)))
    for index, body in enumerate(audio_frames or []):
        offset = audio_offset + index * audio_step
        skew = audio_timestamp_skew + (second_audio_shift if index >= 2 else 0)
        tags.append((offset, flv_tag(clock_base + offset + skew, b"\xaf\x01" + body, 8)))
    records = prefix + [tag for _, tag in sorted(tags, key=lambda item: item[0])]
    result += records[0]
    for index, (previous, tag) in enumerate(zip(records, records[1:])):
        if g4_trailers:
            trailer = bytearray(b"\x09\x03\x08\x00" + b"\0" * 12)
            trailer[11] = 0 if previous[0] == 8 else 1
            if corrupt_trailer and index == 0:
                trailer[11] ^= 1
            result += trailer
        elif zero_decoy and index == 0:
            result += bytes(15) + b"\x08"
        result += tag
    return result


def second_idr_end(media):
    offset, video_samples = 13, 0
    while offset + 15 <= len(media):
        size = int.from_bytes(media[offset+1:offset+4], "big")
        end = offset + 11 + size + 4
        if end > len(media):
            break
        if media[offset] == 9 and size >= 2 and media[offset+12] == 1:
            video_samples += 1
            if video_samples == 4:
                return end
        offset = end
    raise ValueError("missing synthetic second IDR")


def disposable_aac(root):
    path = root / "silence.aac"
    subprocess.run(["ffmpeg", "-v", "error", "-f", "lavfi", "-i", "anullsrc=r=16000:cl=mono",
                    "-t", "0.5", "-c:a", "aac", "-b:a", "24k", "-f", "adts", str(path)],
                   check=True, timeout=20)
    data, frames, offset = path.read_bytes(), [], 0
    while offset < len(data):
        if len(data) - offset < 7 or data[offset] != 0xff or data[offset + 1] != 0xf1:
            raise ValueError("unexpected synthetic AAC ADTS header")
        size = ((data[offset + 3] & 3) << 11) | (data[offset + 4] << 3) | (data[offset + 5] >> 5)
        if size <= 7 or offset + size > len(data):
            raise ValueError("invalid synthetic AAC frame size")
        frames.append(data[offset + 7:offset + size])
        offset += size
    if len(frames) < 4:
        raise ValueError("insufficient synthetic AAC frames")
    return frames[:4]


def run_case(binary, cert, key, root, media, early_reply, close_before_media=False, event_case=False, startup_event_case=False, reply_events=False, accept_event_case=False, refuse_event_case=False, lab_audio=False, source_audio=False, reject_audio=None, g4_trailer=False, allow_early_close=False, zero_stream_id=False, expected_av_offset_ms=None, segments=1, event_between_segments=False, media_origin="synthetic"):
    root.mkdir(mode=0o700)
    reserve = socket.socket()
    reserve.bind(("127.0.0.1", 0))
    port = reserve.getsockname()[1]
    reserve.close()
    journal, clip = root / "journal", root / "clip.mp4"
    command = [binary, f"127.0.0.1:{port}", "127.0.0.1", "001122aabbcc", str(cert), str(key),
               str(journal), str(clip), "12345678-1234-4abc-9abc-123456789abc", "30",
               "--media-before-reply"]
    if reply_events:
        command.append("--reply-events")
    if lab_audio:
        command.append("--lab-aac-source" if source_audio else "--lab-aac-config=1408")
    if g4_trailer:
        command.append("--lab-trailer16-av-flag")
    if zero_stream_id:
        command.append("--lab-zero-stream-id")
    if segments != 1:
        command.append(f"--lab-segments={segments}")
    command.append("--owner-authorized")
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
                event = message("EventSmartDetect", 19, payload={
                    "edgeType": "enter", "private": "TEST_PRIVATE_MARKER",
                    "descriptors": [{"objectType": "person", "confidenceLevel": 80}],
                })
                if reply_events or refuse_event_case:
                    event["responseExpected"] = True
                request += frame(event)
            control.sendall(request + frame(message("ubnt_avclient_hello", 7, payload={})))
            header = bytearray()
            while not header.endswith(b"\r\n\r\n"):
                header.extend(exact(control, 1))
                if len(header) > 4096:
                    raise ValueError("upgrade limit")
            if not header.startswith(b"HTTP/1.1 101 "):
                raise ValueError("upgrade refused")
            if refuse_event_case:
                try:
                    unexpected = control.recv(1)
                except ssl.SSLError:
                    unexpected = b""
                out, err = child.communicate(timeout=30)
                report = out.decode("utf-8", "replace")
                if (unexpected or child.returncode == 0 or clip.exists()
                        or "trial_event_replies=false" not in report
                        or "trial_stage=startup_events_omitted frames=1" not in report
                        or "TEST_PRIVATE_MARKER" in report or b"TEST_PRIVATE_MARKER" in err):
                    raise RuntimeError("unapproved event reply did not stop safely")
                print("loopback case=event_reply_not_enabled response=omitted clip=absent identity=synthetic")
                return
            if startup_event_case and reply_events:
                echoed = received(control)
                if echoed.get("inResponseTo") != 19 or echoed.get("payload", {}).get("private") != "TEST_PRIVATE_MARKER":
                    raise ValueError("startup event reply mismatch")
            hello, agreement = received(control), received(control)
            if hello.get("functionName") != "ubnt_avclient_hello" or agreement.get("functionName") != "ubnt_avclient_paramAgreement":
                raise ValueError("hello or agreement missing")
            control.sendall(frame(message("ubnt_avclient_paramAgreement", 8, agreement["messageId"])))
            setting = received(control)
            if setting.get("functionName") != "ChangeVideoSettings":
                raise ValueError("stream request missing")
            if early_reply:
                control.sendall(frame(message("ChangeVideoSettings", 9, setting["messageId"])))
            if accept_event_case:
                event = message("EventSmartDetect", 21, payload={"private": "TEST_PRIVATE_MARKER"})
                event["responseExpected"] = True
                control.sendall(frame(event))
                echoed = received(control)
                if echoed.get("inResponseTo") != 21 or echoed.get("payload", {}).get("private") != "TEST_PRIVATE_MARKER":
                    raise ValueError("accept event reply mismatch")
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
                    if event_between_segments:
                        cut = second_idr_end(media)
                        stream.sendall(media[:cut])
                        end = time.monotonic() + 15
                        while b"trial_stage=segment_assembled count=1" not in prefix:
                            remaining = end - time.monotonic()
                            if remaining <= 0 or not select.select([child.stdout], [], [], remaining)[0]:
                                raise RuntimeError("first segment marker timed out")
                            chunk = os.read(child.stdout.fileno(), 4096)
                            if not chunk:
                                raise RuntimeError("trial exited before first segment")
                            prefix += chunk
                            if len(prefix) > 16384:
                                raise RuntimeError("controller diagnostic limit")
                        event = message("EventSmartDetect", 22, payload={"private": "TEST_PRIVATE_MARKER"})
                        event["responseExpected"] = True
                        control.sendall(frame(event))
                        echoed = received(control)
                        if echoed.get("inResponseTo") != 22 or echoed.get("payload", {}).get("private") != "TEST_PRIVATE_MARKER":
                            raise ValueError("between-segment event reply mismatch")
                        stream.sendall(media[cut:])
                    elif event_case:
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
                        event = message("EventSmartDetect", 20, payload={
                            "edgeType": "enter", "private": "TEST_PRIVATE_MARKER",
                            "descriptors": [{"objectType": "person", "confidenceLevel": 80}],
                        })
                        if reply_events:
                            event["responseExpected"] = True
                        control.sendall(frame(event))
                        if reply_events:
                            echoed = received(control)
                            if echoed.get("inResponseTo") != 20 or echoed.get("payload", {}).get("private") != "TEST_PRIVATE_MARKER":
                                raise ValueError("live event reply mismatch")
                        control.sendall(frame(message("ubnt_avclient_timeSync", 11)))
                        sync = received(control)
                        if sync.get("functionName") != "ubnt_avclient_timeSync" or sync.get("inResponseTo") != 11:
                            raise ValueError("post-event clock request was not answered")
                        stream.sendall(media[1:])
                    else:
                        try:
                            stream.sendall(media)
                        except (BrokenPipeError, ConnectionResetError):
                            if not allow_early_close:
                                raise
            out, err = child.communicate(timeout=30)
        report = (prefix + out).decode("utf-8", "replace")
        if reject_audio:
            case, reason = reject_audio
            if child.returncode == 0 or clip.exists() or reason not in err:
                raise RuntimeError("A/V mode did not refuse " + case + ": " + err.decode("utf-8", "replace")[-500:])
            if segments > 1 and "trial_stage=segment_assembled count=1" not in report:
                raise RuntimeError("failure occurred before the first segment")
            print(f"loopback case=av_{case} refused=true clip=absent identity=synthetic")
            return
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
        if f"trial_segment_limit={segments}" not in report or f"trial_stage=segment_assembled count={segments}" not in report:
            raise ValueError("requested segment count not assembled")
        if event_between_segments and ("trial_stage=event_reply_written" not in report or "TEST_PRIVATE_MARKER" in report):
            raise ValueError("between-segment event handling missing or payload leaked")
        if (event_case or startup_event_case or accept_event_case) and ("trial_stage=camera_event kind=SmartDetect" not in report
                                                   or "TEST_PRIVATE_MARKER" in report):
            raise ValueError("supervised event missing or payload leaked")
        if reply_events and (startup_event_case or accept_event_case) and "trial_stage=startup_event_already_answered" not in report:
            raise ValueError("startup reply accounting missing")
        if reply_events and event_case and "trial_stage=event_reply_written" not in report:
            raise ValueError("live reply accounting missing")
        probe = subprocess.run(["ffprobe", "-v", "error", "-select_streams", "v:0", "-count_frames",
                                "-show_entries", "stream=codec_name,width,height,nb_read_frames", "-of", "json", str(clip)],
                               capture_output=True, check=True, timeout=20)
        streams = json.loads(probe.stdout)["streams"]
        if len(streams) != 1 or streams[0]["codec_name"] != "h264" or int(streams[0]["nb_read_frames"]) < 1:
            raise ValueError("independent clip probe failed")
        if segments > 1 and not lab_audio:
            if int(streams[0]["nb_read_frames"]) < 6:
                raise ValueError("multi-segment video frames missing")
            print(f"loopback case=video_multiple_segments segments={segments} frames={streams[0]['nb_read_frames']} identity=synthetic")
            return
        if lab_audio:
            label = "in_band_connection_claim" if source_audio else "external_unverified"
            if "trial_stage=av_fragment" not in report or f"configuration_source={label} av_alignment=unverified" not in report:
                raise ValueError("A/V qualification markers missing")
            if g4_trailer and "trial_framing=trailer16_av_flag_heuristic" not in report:
                raise ValueError("G4 trailer policy marker missing")
            if zero_stream_id and "trial_framing=zero_stream_id_heuristic" not in report:
                raise ValueError("zero stream ID policy marker missing")
            audio_probe = subprocess.run(["ffprobe", "-v", "error", "-select_streams", "a:0", "-show_entries",
                                          "stream=codec_name,sample_rate,channels", "-of", "json", str(clip)],
                                         capture_output=True, check=True, timeout=20)
            audio_streams = json.loads(audio_probe.stdout)["streams"]
            if len(audio_streams) != 1 or audio_streams[0].get("codec_name") != "aac" or audio_streams[0].get("sample_rate") != "16000" or audio_streams[0].get("channels") != 1:
                raise ValueError("independent AAC probe failed")
            subprocess.run(["ffmpeg", "-v", "error", "-xerror", "-i", str(clip), "-map", "0:a:0", "-f", "null", "-"],
                           capture_output=True, check=True, timeout=20)
            if expected_av_offset_ms is not None:
                packets = subprocess.run(["ffprobe", "-v", "error", "-show_entries",
                                          "stream=index,codec_type:packet=stream_index,dts_time", "-of", "json", str(clip)],
                                         capture_output=True, check=True, timeout=20)
                data = json.loads(packets.stdout)
                indexes = {s["codec_type"]: s["index"] for s in data["streams"]}
                first = {}
                for packet in data["packets"]:
                    first.setdefault(packet["stream_index"], Decimal(packet["dts_time"]))
                actual = (first[indexes["audio"]] - first[indexes["video"]]) * 1000
                if actual != Decimal(expected_av_offset_ms):
                    raise ValueError("independent sender-clock offset mismatch")
                if f"audio_minus_video_ms={expected_av_offset_ms} " not in report:
                    raise ValueError("sender-clock diagnostic mismatch")
                if segments > 1:
                    audio_dts = [Decimal(p["dts_time"]) for p in data["packets"] if p["stream_index"] == indexes["audio"]]
                    if len(audio_dts) < 4 or any(b - a != Decimal("0.064") for a, b in zip(audio_dts, audio_dts[1:])):
                        raise ValueError("independent multi-segment audio timeline mismatch")
                    subprocess.run(["ffmpeg", "-v", "error", "-xerror", "-i", str(clip), "-map", "0:v:0", "-map", "0:a:0", "-f", "null", "-"],
                                   capture_output=True, check=True, timeout=20)
                    print(f"loopback case=av_multiple_segments segments={segments} audio_packets={len(audio_dts)} offset_ms={expected_av_offset_ms} event_between={event_between_segments} decoded=true controller=synthetic_loopback media={media_origin}")
                    return
                print(f"loopback case=av_sender_clock_offset offset_ms={expected_av_offset_ms} source={'inband' if source_audio else 'supplied'} identity=synthetic")
                return
            case = "zero_stream_id" if zero_stream_id else (("g4_inband" if g4_trailer else "inband") if source_audio else "supplied")
            print(f"loopback case=av_{case}_configuration video=h264 audio=aac decoded=true alignment=unverified identity=synthetic")
            return
        case = ("accept_event_reply" if accept_event_case else "startup_event_reply" if startup_event_case and reply_events
                else "live_event_reply" if event_case and reply_events else "startup_event" if startup_event_case
                else ("camera_event" if event_case else ("early_reply" if early_reply else "no_reply")))
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
    rejected = subprocess.run([binary, "--reply-events", "--owner-authorized"],
                              capture_output=True, timeout=10)
    if rejected.returncode == 0 or b"event replies require --media-before-reply" not in rejected.stderr:
        raise RuntimeError("event reply mode accepted without the required startup mode")
    print("loopback case=reply_mode_requires_media_first rejected=true identity=synthetic")
    invalid = subprocess.run([binary, "--lab-aac-config=zzzz", "--owner-authorized"],
                             capture_output=True, timeout=10)
    if invalid.returncode == 0 or b"four hexadecimal digits" not in invalid.stderr:
        raise RuntimeError("invalid AAC configuration was accepted")
    print("loopback case=invalid_aac_config rejected=true identity=synthetic")
    conflicting = subprocess.run([binary, "--lab-aac-config=1408", "--lab-aac-source", "--owner-authorized"],
                                 capture_output=True, timeout=10)
    if conflicting.returncode == 0 or b"choose one laboratory AAC configuration source" not in conflicting.stderr:
        raise RuntimeError("conflicting AAC source options were accepted")
    print("loopback case=conflicting_aac_sources rejected=true identity=synthetic")
    conflicting = subprocess.run([binary, "--lab-trailer16-av-flag", "--lab-zero-stream-id", "--owner-authorized"],
                                 capture_output=True, timeout=10)
    if conflicting.returncode == 0 or b"choose one laboratory framing policy" not in conflicting.stderr:
        raise RuntimeError("conflicting framing policies were accepted")
    print("loopback case=conflicting_framing_policies rejected=true identity=synthetic")
    for count in (0, 9):
        invalid = subprocess.run([binary, f"--lab-segments={count}", "--owner-authorized"], capture_output=True, timeout=10)
        if invalid.returncode == 0 or b"segment count must be 1 to 8" not in invalid.stderr:
            raise RuntimeError("invalid segment count was accepted")
    print("loopback case=invalid_segment_bounds rejected=true identity=synthetic")
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
        audio = disposable_aac(root)
        av_media = media_fixture(sys.argv[2], audio)
        av_inband_media = media_fixture(sys.argv[2], audio, inband=True)
        av_late_config_media = media_fixture(sys.argv[2], audio, late_config=True)
        av_changed_config_media = media_fixture(sys.argv[2], audio, inband=True, late_config=True)
        av_g4_media = media_fixture(sys.argv[2], audio, inband=True, g4_trailers=True)
        av_bad_trailer_media = media_fixture(sys.argv[2], audio, inband=True, g4_trailers=True, corrupt_trailer=True)
        zero_id_media = media_fixture(sys.argv[2], audio, zero_decoy=True, clock_base=0x01000000)
        zero_id_ambiguous = media_fixture(sys.argv[2], audio, zero_decoy=True)
        timed_media = media_fixture(sys.argv[2], audio, clock_base=10_000, audio_offset=10)
        timed_inband_media = media_fixture(sys.argv[2], audio, inband=True, clock_base=10_000, audio_offset=10)
        skewed_media = media_fixture(sys.argv[2], audio, clock_base=10_000, audio_offset=10, audio_timestamp_skew=5_000)
        multi_media = media_fixture(sys.argv[2], audio, clock_base=10_000, audio_offset=5)
        multi_inband_media = media_fixture(sys.argv[2], audio, inband=True, clock_base=10_000, audio_offset=5)
        multi_incomplete = media_fixture(sys.argv[2], audio, clock_base=10_000, audio_offset=5, video_count=4)
        multi_bad_audio = media_fixture(sys.argv[2], audio, clock_base=10_000, audio_offset=5, second_audio_shift=40)
        # Put the second sample before the first fragment's final video record,
        # while exceeding the 5 ms tolerance for a 64 ms AAC frame.
        bad_timing_media = media_fixture(sys.argv[2], audio, 70)
        run_case(binary, cert, key, root / "early", media, True)
        run_case(binary, cert, key, root / "none", media, False)
        run_case(binary, cert, key, root / "closed", media, True, close_before_media=True)
        run_case(binary, cert, key, root / "event", media, False, event_case=True)
        run_case(binary, cert, key, root / "startup", media, False, startup_event_case=True)
        run_case(binary, cert, key, root / "startup_closed", media, True, close_before_media=True, startup_event_case=True)
        run_case(binary, cert, key, root / "startup_reply", media, False, startup_event_case=True, reply_events=True)
        run_case(binary, cert, key, root / "accept_reply", media, False, reply_events=True, accept_event_case=True)
        run_case(binary, cert, key, root / "live_reply", media, False, event_case=True, reply_events=True)
        run_case(binary, cert, key, root / "reply_disabled", media, False, startup_event_case=True, refuse_event_case=True)
        run_case(binary, cert, key, root / "av", av_media, True, lab_audio=True)
        run_case(binary, cert, key, root / "av_missing", media, True, lab_audio=True, reject_audio=("missing_audio", b"NoAudio"))
        run_case(binary, cert, key, root / "av_bad_timing", bad_timing_media, True, lab_audio=True, reject_audio=("bad_timing", b"Timeline"))
        run_case(binary, cert, key, root / "av_inband", av_inband_media, True, lab_audio=True, source_audio=True)
        run_case(binary, cert, key, root / "av_no_inband", av_media, True, lab_audio=True, source_audio=True, reject_audio=("no_inband_config", b"no pre-video in-band AAC configuration"))
        run_case(binary, cert, key, root / "av_late_inband", av_late_config_media, True, lab_audio=True, source_audio=True, reject_audio=("late_inband_config", b"no pre-video in-band AAC configuration"))
        run_case(binary, cert, key, root / "av_changed_inband", av_changed_config_media, True, lab_audio=True, source_audio=True, reject_audio=("second_inband_config", b"ConfigurationObserved"))
        run_case(binary, cert, key, root / "av_g4_inband", av_g4_media, True, lab_audio=True, source_audio=True, g4_trailer=True)
        run_case(binary, cert, key, root / "av_bad_trailer", av_bad_trailer_media, True, lab_audio=True, source_audio=True, g4_trailer=True, reject_audio=("bad_g4_trailer", b"TrailerPolicyMismatch"))
        run_case(binary, cert, key, root / "av_zero_id", zero_id_media, True, lab_audio=True, zero_stream_id=True)
        run_case(binary, cert, key, root / "av_zero_id_ambiguous", zero_id_ambiguous, True, lab_audio=True, zero_stream_id=True, reject_audio=("zero_id_ambiguity", b"Media(Eof)"))
        run_case(binary, cert, key, root / "av_timed", timed_media, True, lab_audio=True, expected_av_offset_ms=10)
        run_case(binary, cert, key, root / "av_timed_inband", timed_inband_media, True, lab_audio=True, source_audio=True, expected_av_offset_ms=10)
        run_case(binary, cert, key, root / "av_skewed", skewed_media, True, lab_audio=True, reject_audio=("sender_clock_skew", b"Alignment"))
        run_case(binary, cert, key, root / "multi_video", media, True, segments=2)
        run_case(binary, cert, key, root / "multi_audio", multi_media, True, lab_audio=True, expected_av_offset_ms=5, segments=2)
        run_case(binary, cert, key, root / "multi_inband", multi_inband_media, True, lab_audio=True, source_audio=True, expected_av_offset_ms=5, segments=2)
        run_case(binary, cert, key, root / "multi_event", multi_media, True, lab_audio=True, reply_events=True, expected_av_offset_ms=5, segments=2, event_between_segments=True)
        run_case(binary, cert, key, root / "multi_incomplete", multi_incomplete, True, lab_audio=True, segments=2, reject_audio=("missing_second_segment", b"Media(Eof)"))
        run_case(binary, cert, key, root / "multi_bad_clock", multi_bad_audio, True, lab_audio=True, segments=2, reject_audio=("second_segment_clock", b"Timeline"))


if __name__ == "__main__":
    main()
