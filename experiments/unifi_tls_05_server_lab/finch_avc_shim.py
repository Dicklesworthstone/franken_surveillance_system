#!/usr/bin/env python3
"""Adapt a disposable Finch camera to synthetic H.264 for interop testing.

Finch and pyunifiwire remain external test oracles, never runtime dependencies.
This adapter changes their HEVC pusher to emit AVC; it does not modify their
control protocol or extended-FLV framing. Input must be a synthetic Annex B
AVC stream with one slice per frame. Do not point it at a real controller.
"""
import os
from pathlib import Path
import sys

sys.path.insert(0, str(Path(os.environ["FSS_FINCH_DIR"]).resolve()))
sys.path.insert(0, str(Path(os.environ["FSS_WIRE_DIR"]).resolve() / "src"))
import identity  # type: ignore[import-not-found]  # noqa: E402
import main  # type: ignore[import-not-found]  # noqa: E402
import push  # type: ignore[import-not-found]  # noqa: E402
from unifiwire import annexb, avc  # type: ignore[import-not-found]  # noqa: E402
from unifiwire import flv  # type: ignore[import-not-found]  # noqa: E402

identity.VIDEO_CODEC = "h264"


def config(source):
    units = list(annexb.annex_b_units(source.path.read_bytes()))
    sps = next(unit for unit in units if avc.nal_type(unit) == 7)
    pps = next(unit for unit in units if avc.nal_type(unit) == 8)
    return annexb.build_avcc(sps, pps)


def pictures(source):
    units = [unit for unit in annexb.annex_b_units(source.path.read_bytes())
             if avc.nal_type(unit) in (1, 5)]
    if not units:
        raise ValueError("synthetic input has no AVC pictures")
    return annexb.avc_frames(units)


def video_body(units, keyframe):
    prefix = bytes([0x17 if keyframe else 0x27, 1, 0, 0, 0])
    return prefix + b"".join(len(unit).to_bytes(4, "big") + unit for unit in units)


push.Source.hvcc = config
push.Source.pictures = pictures
push.config_body = lambda record: b"\x17\x00\x00\x00\x00" + record
push.video_body = video_body


def enable_synthetic_audio(path):
    """Interleave generated 16 kHz mono AAC with the synthetic AVC frames."""
    data = Path(path).read_bytes()
    if not data or len(data) > 4 * 1024 * 1024:
        raise ValueError("synthetic AAC input must be nonempty and at most 4 MiB")
    frames = []
    offset = 0
    while offset < len(data):
        header = data[offset:offset + 7]
        if (len(header) != 7 or header[0:2] != b"\xff\xf1" or
                (header[2] >> 6) + 1 != 2 or (header[2] >> 2) & 15 != 8 or
                ((header[2] & 1) << 2 | header[3] >> 6) != 1 or header[6] & 3):
            raise ValueError("expected single-block 16 kHz mono AAC-LC ADTS without CRC")
        size = ((header[3] & 3) << 11) | (header[4] << 3) | (header[5] >> 5)
        if size <= 7 or offset + size > len(data):
            raise ValueError("invalid ADTS frame length")
        frames.append(data[offset + 7:offset + size])
        offset += size
    if not frames:
        raise ValueError("synthetic AAC has no frames")

    metadata = push.metadata
    send = push.Pusher._send
    state = {"configured": False, "index": 0}

    def metadata_with_audio(stream_name, channel, audio=False):
        return metadata(stream_name, channel, audio=True)

    def send_with_audio(pusher, sock, kind, timestamp, body):
        if kind == flv.TagType.VIDEO and body[1:2] == b"\x00":
            send(pusher, sock, kind, timestamp, body)
            if state["configured"]:
                raise ValueError("unexpected second synthetic AVC configuration")
            send(pusher, sock, flv.TagType.AUDIO, timestamp, b"\xaf\x00\x14\x08")
            state["configured"] = True
            return
        if kind == flv.TagType.VIDEO and body[1:2] == b"\x01":
            while state["index"] * 64 < timestamp:
                index = state["index"]
                send(pusher, sock, flv.TagType.AUDIO, index * 64, b"\xaf\x01" + frames[index % len(frames)])
                state["index"] += 1
            send(pusher, sock, kind, timestamp, body)
            if state["index"] * 64 == timestamp:
                index = state["index"]
                send(pusher, sock, flv.TagType.AUDIO, timestamp, b"\xaf\x01" + frames[index % len(frames)])
                state["index"] += 1
            return
        send(pusher, sock, kind, timestamp, body)

    push.metadata = metadata_with_audio
    push.Pusher._send = send_with_audio


if os.environ.get("FSS_SYNTHETIC_AAC"):
    enable_synthetic_audio(os.environ["FSS_SYNTHETIC_AAC"])

if __name__ == "__main__":
    if main.parse_args().host != "127.0.0.1":
        raise SystemExit("synthetic Finch adapter only permits 127.0.0.1")
    raise SystemExit(main.main())
