#!/usr/bin/env python3
"""Packetize retained, decodable codec fixtures; never contact or record a camera.

This fixture-only generator uses the Python standard library. It preserves complete
NAL/entropy bytes from the checked-in codec corpus and adds deterministic RTP/rtpdump framing.
It is not a production media parser, encoder, decoder, or probe implementation.
"""

import base64
import hashlib
from pathlib import Path
import re
import struct


HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
FIRST_TIMESTAMP = 0xFFFFF000
FRAME_DURATION = 3600
MAX_PAYLOAD = 512
SOURCES = {
    "avc": (
        "crates/fss-packet/tests/fixtures/avc/baseline.264",
        "2a3e84de3a938a60ad254a69fa2fa7f38ada910cad72447b807f3d6266796d32",
        96,
        0x11223344,
    ),
    "hevc": (
        "crates/fss-codec-h265/tests/fixtures/decode/i_64x64_ctu32_qp30.h265",
        "8de0e8bdc831b0aedd649157e536b4b0aea4d54c93a280c8ed6ddef0e6faca46",
        98,
        0x55667788,
    ),
    "jpeg": (
        "crates/fss-codec-mjpeg/tests/fixtures/rtp_jpeg/422_32x24_q50_rst0.jpg",
        "a36a08e88d315693f58a8bb9f1faf92f5cd8cd4d12c7b1e39cbd4555c1b82afc",
        26,
        0x99AABBCC,
    ),
}


def annex_b_nals(data):
    """Remove Annex-B delimiters/trailing_zero_8bits from these known fixture files."""
    return [nal.rstrip(b"\0") for nal in re.split(b"\0\0\0?\1", data) if nal]


def kind(codec, nal):
    return nal[0] & 31 if codec == "avc" else (nal[0] >> 1) & 63


def payloads(codec, nal):
    if len(nal) <= MAX_PAYLOAD:
        return [nal]
    if codec == "avc":
        body, overhead = nal[1:], 2
        prefix = bytes([(nal[0] & 0xE0) | 28])
    else:
        body, overhead = nal[2:], 3
        prefix = bytes([(nal[0] & 0x81) | (49 << 1), nal[1]])
    chunks = [body[i:i + MAX_PAYLOAD - overhead]
              for i in range(0, len(body), MAX_PAYLOAD - overhead)]
    return [prefix + bytes([kind(codec, nal)
                            | (0x80 if index == 0 else 0)
                            | (0x40 if index + 1 == len(chunks) else 0)]) + chunk
            for index, chunk in enumerate(chunks)]


def packetize(codec, nals, payload_type, ssrc):
    dump = bytearray(b"#!rtpplay1.0 0.0.0.0/0\n" + bytes(16))
    sequence, picture, packets = 65534, 0, 0

    def emit(nal, picture_index, vcl):
        nonlocal sequence, packets
        pieces = payloads(codec, nal)
        timestamp = (FIRST_TIMESTAMP + picture_index * FRAME_DURATION) & 0xFFFFFFFF
        for index, piece in enumerate(pieces):
            marker = vcl and index + 1 == len(pieces)
            wire = struct.pack("!BBHII", 0x80, payload_type | (0x80 if marker else 0),
                               sequence, timestamp, ssrc) + piece
            dump.extend(struct.pack("!HHI", len(wire) + 8, len(wire), picture_index * 40))
            dump.extend(wire)
            sequence = (sequence + 1) & 0xFFFF
            packets += 1

    # The existing RTP receiver's first packet establishes sequence probation.
    emit(bytes([0x09, 0xF0]) if codec == "avc" else bytes([0x46, 0x01, 0x50]), 0, False)
    for nal in nals:
        vcl = kind(codec, nal) in (1, 5) if codec == "avc" else kind(codec, nal) <= 31
        emit(nal, picture, vcl)
        if vcl:
            # Both pinned corpus files contain one complete slice per picture.
            picture += 1
    if codec == "hevc":
        # EOS_NUT + rbsp_trailing_bits closes the last real picture. An RTP marker
        # alone is deliberately insufficient for the native HEVC assembly owner.
        emit(bytes([0x48, 0x01, 0x80]), picture - 1, False)
    return bytes(dump), picture, packets


def describe(codec, nals, payload_type):
    types = (7, 8) if codec == "avc" else (32, 33, 34)
    parameters = [next(nal for nal in nals if kind(codec, nal) == ty) for ty in types]
    encoded = [base64.b64encode(nal).decode("ascii") for nal in parameters]
    if codec == "avc":
        fmtp = f"packetization-mode=1;sprop-parameter-sets={encoded[0]},{encoded[1]}"
    else:
        fmtp = f"sprop-vps={encoded[0]};sprop-sps={encoded[1]};sprop-pps={encoded[2]}"
    name = "H264" if codec == "avc" else "H265"
    body = ("v=0\r\no=- 1 1 IN IP4 192.0.2.10\r\ns=offline codec fixture\r\nt=0 0\r\n"
            "a=control:*\r\n"
            f"m=video 0 RTP/AVP {payload_type}\r\na=rtpmap:{payload_type} {name}/90000\r\n"
            f"a=fmtp:{payload_type} {fmtp}\r\na=control:trackID=0\r\n").encode("ascii")
    response = ("RTSP/1.0 200 OK\r\nCSeq: 2\r\n"
                "Server: fixture-private-server-canary\r\n"
                "Content-Type: application/sdp\r\n"
                f"Content-Length: {len(body)}\r\n\r\n").encode("ascii") + body
    return response, parameters


def jpeg_fixture(data, payload_type, ssrc):
    """Copy the pinned 4:2:2, Q=50, 32x24 baseline fixture's complete entropy scan."""
    if data[:2] != b"\xff\xd8" or data[-2:] != b"\xff\xd9":
        raise SystemExit("JPEG fixture lacks complete image framing")
    at = 2
    while at + 4 <= len(data):
        end = at + 2 + int.from_bytes(data[at + 2:at + 4], "big")
        if end > len(data) or end <= at + 3:
            raise SystemExit("JPEG fixture segment is malformed")
        if data[at + 1] == 0xDA:
            scan = data[end:]
            break
        at = end
    else:
        raise SystemExit("JPEG fixture has no entropy scan")
    # Two fragments per image exercise completion across payload boundaries.
    split = len(scan) // 2
    pieces = [(0, scan[:split]), (split, scan[split:])]
    dump = bytearray(b"#!rtpplay1.0 0.0.0.0/0\n" + bytes(16))
    sequence = 65534
    for picture in range(3):
        timestamp = (FIRST_TIMESTAMP + picture * FRAME_DURATION) & 0xFFFFFFFF
        for index, (offset, piece) in enumerate(pieces):
            # RFC 2435 type0 (4:2:2), standard quality50, dimensions in eight-pixel units.
            header = bytes([0]) + offset.to_bytes(3, "big") + bytes([0, 50, 4, 3])
            marker = 0x80 if index + 1 == len(pieces) else 0
            wire = struct.pack("!BBHII", 0x80, payload_type | marker,
                               sequence, timestamp, ssrc) + header + piece
            dump.extend(struct.pack("!HHI", len(wire) + 8, len(wire), picture * 40))
            dump.extend(wire)
            sequence = (sequence + 1) & 0xFFFF
    # Static payload26 deliberately has no rtpmap: the native exact selector owns that rule.
    body = ("v=0\r\no=- 1 1 IN IP4 192.0.2.10\r\ns=offline codec fixture\r\nt=0 0\r\n"
            "a=control:*\r\n"
            f"m=video 0 RTP/AVP {payload_type}\r\na=control:trackID=0\r\n").encode("ascii")
    response = ("RTSP/1.0 200 OK\r\nCSeq: 2\r\n"
                "Server: fixture-private-server-canary\r\n"
                "Content-Type: application/sdp\r\n"
                f"Content-Length: {len(body)}\r\n\r\n").encode("ascii") + body
    return response, bytes(dump), 3, 6


def main():
    # Check every source before creating outputs; source changes require deliberate review.
    inputs = {}
    for codec, (path, expected, _, _) in SOURCES.items():
        data = (ROOT / path).read_bytes()
        actual = hashlib.sha256(data).hexdigest()
        if actual != expected:
            raise SystemExit(f"{codec} source digest differs from the pinned corpus")
        inputs[codec] = data if codec == "jpeg" else annex_b_nals(data)
    for codec, (_, _, payload_type, ssrc) in SOURCES.items():
        if codec == "jpeg":
            response, dump, pictures, packets = jpeg_fixture(inputs[codec], payload_type, ssrc)
            parameters = []
        else:
            nals = inputs[codec]
            response, parameters = describe(codec, nals, payload_type)
            dump, pictures, packets = packetize(codec, nals, payload_type, ssrc)
        (HERE / f"{codec}.describe.rtsp").write_bytes(response)
        (HERE / f"{codec}.rtpdump").write_bytes(dump)
        print(f"{codec}: {pictures} real pictures, {packets} RTP packets, {len(dump)} dump bytes")
        for suffix, data in [("describe.rtsp", response), ("rtpdump", dump)]:
            print(f"  {codec}.{suffix} sha256:{hashlib.sha256(data).hexdigest()}")
        print("  parameter digests:", ["sha256:" + hashlib.sha256(nal).hexdigest()
                                       for nal in parameters])


if __name__ == "__main__":
    main()
