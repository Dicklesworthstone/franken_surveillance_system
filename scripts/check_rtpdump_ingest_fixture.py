#!/usr/bin/env python3
"""Independent fixture/wire oracle. Does NOT execute FSS Rust or publish data."""
from __future__ import annotations
import argparse
import hashlib
import json
import pathlib
import struct
import subprocess
import tempfile

ROOT = pathlib.Path(__file__).resolve().parents[1]
FIXTURE = ROOT / "crates/fss-packet/tests/fixtures/avc/baseline.264"
EXPECTED_BLOB = "5d584a10e60d6e0ecdb89bfa2be742088021a45e"
HEADER = b"#!rtpplay1.0 0.0.0.0/0\n" + bytes(16)


def require(ok: bool, why: str) -> None:
    if not ok:
        raise ValueError(why)


def sha(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def split(b: bytes) -> list[bytes]:
    starts, at = [], 0
    while at + 3 <= len(b):
        length = 4 if b[at:at+4] == b"\0\0\0\1" else 3 if b[at:at+3] == b"\0\0\1" else 0
        if length:
            starts.append((at, at+length)); at += length
        else:
            at += 1
    return [b[start:starts[i+1][0] if i+1 < len(starts) else len(b)].rstrip(b"\0") for i, (_, start) in enumerate(starts)]


def make(nals: list[bytes], fragmented: bool) -> bytes:
    records, seq = [], 65534
    payloads = [(b"\x09\xf0", False, 0)]
    for i, nal in enumerate(nals):
        vcl = nal[0] & 31 in (1, 5)
        if fragmented and vcl:
            mid = 1 + (len(nal)-1)//2
            for j, body in enumerate([nal[1:mid], nal[mid:]]):
                payloads.append((bytes([(nal[0] & 0x60) | 28, (nal[0] & 31) | (128 if j == 0 else 64)]) + body, j == 1, i))
        else:
            payloads.append((nal, vcl, i))
    for payload, marker, offset in payloads:
        wire = struct.pack("!BBHII", 0x80, 96 | (128 if marker else 0), seq, 90000, 7) + payload
        records.append(struct.pack("!HHI", len(wire)+8, len(wire), offset) + wire)
        seq = (seq+1) & 65535
    return HEADER + b"".join(records)


def parse(data: bytes) -> list[tuple[int, bytes]]:
    # This oracle pins the retained synthetic recorder header. It is not a second
    # production parser or an acceptance test for arbitrary network endpoints.
    require(data.startswith(HEADER), "fixture header truncated/changed")
    records, pos = [], len(HEADER)
    while pos < len(data):
        require(len(data)-pos >= 8, "partial record prefix")
        length, plen, _ = struct.unpack_from("!HHI", data, pos)
        require(length >= 8 and plen == length-8, "invalid fixture record length")
        require(length <= len(data)-pos, "partial captured record")
        records.append((pos, data[pos+8:pos+length])); pos += length
    return records


def reconstruct(records: list[tuple[int, bytes]]) -> tuple[list[bytes], list[tuple[int, int, bytes]]]:
    output, copies = [], []
    pending = None
    last = None
    for ordinal, (position, raw) in enumerate(records):
        require(len(raw) >= 13 and raw[0] == 0x80 and raw[1] & 127 == 96, "RTP fixture shape")
        seq = int.from_bytes(raw[2:4], "big")
        if ordinal == 0:  # Deliberate source probation, retained but not delivered.
            last = seq
            continue
        require(seq == (last+1) & 65535, "sequence discontinuity")
        last = seq
        payload, begin = raw[12:], position+8+12
        if payload[0] & 31 == 28:
            start, end = bool(payload[1] & 128), bool(payload[1] & 64)
            if start:
                require(pending is None, "interrupted FU")
                pending = bytes([(payload[0] & 0xe0) | (payload[1] & 31)])
            require(pending is not None, "FU without start")
            copies.append((begin+2, begin+len(payload), payload[2:]))
            pending += payload[2:]
            if end:
                output.append(pending); pending = None
        else:
            require(pending is None, "unfinished FU")
            copies.append((begin, begin+len(payload), payload))
            output.append(payload)
    require(pending is None, "unfinished terminal FU")
    return output, copies


def pixels(path: pathlib.Path) -> bytes:
    return subprocess.run(["ffmpeg", "-v", "error", "-threads", "1", "-i", str(path),
        "-pix_fmt", "yuv420p", "-f", "rawvideo", "-"], check=True, capture_output=True, timeout=30).stdout


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--fixture", type=pathlib.Path, default=FIXTURE)
    args = parser.parse_args()
    raw = args.fixture.read_bytes()
    require(hashlib.sha1(f"blob {len(raw)}\0".encode()+raw).hexdigest() == EXPECTED_BLOB, "fixture identity drift")
    nals = split(raw)
    reference = pixels(args.fixture)
    frame_info = json.loads(subprocess.run(["ffprobe", "-v", "error", "-show_entries", "frame=pict_type",
        "-of", "json", str(args.fixture)], check=True, capture_output=True, timeout=30).stdout)
    require(len(frame_info["frames"]) == 4, "fixture frame count drift")
    cases = []
    with tempfile.TemporaryDirectory(prefix="fss-rtpdump-oracle-") as directory:
        for fragmented in [False, True]:
            data = make(nals, fragmented)
            records = parse(data)
            reconstructed, copies = reconstruct(records)
            require(reconstructed == nals, "transport changed NAL bytes/order")
            require(all(data[a:b] == copied for a, b, copied in copies), "incorrect source offset")
            require(HEADER + b"".join(data[pos:pos+8+len(wire)] for pos, wire in records) == data, "source record custody mismatch")
            boundaries = {len(HEADER)} | {pos+8+len(wire) for pos, wire in records}
            refused = 0
            for cut in range(len(HEADER), len(data)):
                try:
                    parse(data[:cut])
                except ValueError:
                    require(cut not in boundaries, "refused a valid file prefix boundary")
                    refused += 1
                else:
                    require(cut in boundaries, "accepted incomplete captured record")
            rebuilt = pathlib.Path(directory) / "reconstructed.264"
            rebuilt.write_bytes(b"".join(b"\0\0\0\1"+n for n in reconstructed))
            require(pixels(rebuilt) == reference, "reconstruction changed decoded pixels")
            if fragmented:
                missing = next(i for i, (_, p) in enumerate(records) if p[12] & 31 == 28 and p[13] & 128)
                try:
                    reconstruct(records[:missing]+records[missing+1:])
                except ValueError:
                    pass
                else:
                    raise ValueError("lost fragment became a complete stream")
            cases.append({"packetization": "fu-a" if fragmented else "single-nal", "records": len(records),
                "nals": len(reconstructed), "source_bytes": len(data), "source_sha256": sha(data),
                "copy_spans": len(copies), "incomplete_record_cuts_refused": refused,
                "decoded_frames": 4, "decoded_pixel_sha256": sha(reference)})
    print(json.dumps({"status": "passed", "rust_executed": False,
        "qualification": "independent_fixture_and_source_mapping_oracle_only",
        "fixture_sha256": sha(raw), "cases": cases, "missing_fu_start_refused": True}, sort_keys=True))


if __name__ == "__main__":
    main()
