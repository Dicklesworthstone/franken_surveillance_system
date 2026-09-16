#!/usr/bin/env python3
"""Independent laboratory window/packet oracle; DOES NOT execute FSS Rust code."""
from __future__ import annotations

import hashlib
import json
import pathlib
import shutil
import struct
import subprocess
import tempfile

ROOT = pathlib.Path(__file__).resolve().parents[1]
FIXTURE = ROOT / "crates/fss-packet/tests/fixtures/avc/baseline.264"
EXPECTED_GIT_BLOB = "5d584a10e60d6e0ecdb89bfa2be742088021a45e"


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def require(condition: bool, reason: str) -> None:
    if not condition:
        raise ValueError(reason)


def split(data: bytes) -> list[bytes]:
    starts: list[tuple[int, int]] = []
    at = 0
    while at + 3 <= len(data):
        length = 4 if data[at:at+4] == b"\0\0\0\1" else 3 if data[at:at+3] == b"\0\0\1" else 0
        if length:
            starts.append((at, at + length))
            at += length
        else:
            at += 1
    return [data[start:starts[i+1][0] if i+1 < len(starts) else len(data)].rstrip(b"\0")
            for i, (_, start) in enumerate(starts)]


def independent_windows(nals: list[bytes]) -> list[list[int]]:
    windows: list[list[int]] = []
    begin = 0
    prefix = None
    has_picture = False
    for i, nal in enumerate(nals):
        kind = nal[0] & 31
        if has_picture and kind in (6, 7, 8, 9) and prefix is None:
            prefix = i
        if kind not in (1, 5):
            continue
        if kind == 5 and has_picture:
            cut = i if prefix is None else prefix
            windows.append(list(range(begin, cut)))
            begin = cut
        has_picture = True
        prefix = None
    windows.append(list(range(begin, len(nals))))
    return windows


def packets(nals: list[bytes], fragmented: bool) -> list[tuple[int, bytes]]:
    out: list[tuple[int, bytes]] = []
    seq = 1
    frame = 0
    for ordinal, nal in enumerate(nals):
        vcl = nal[0] & 31 in (1, 5)
        if fragmented and vcl:
            half = 1 + (len(nal) - 1) // 2
            payloads = [bytes([(nal[0] & 0x60) | 28, (nal[0] & 31) | 0x80]) + nal[1:half],
                        bytes([(nal[0] & 0x60) | 28, (nal[0] & 31) | 0x40]) + nal[half:]]
        else:
            payloads = [nal]
        for i, payload in enumerate(payloads):
            header = struct.pack("!BBHII", 0x80, 96 | (128 if vcl and i+1 == len(payloads) else 0),
                                 seq, 90_000 + frame*3600, 7)
            out.append((ordinal, header + payload))
            seq += 1
        frame += int(vcl)
    return out


def reconstruct(wire: list[bytes]) -> list[bytes]:
    """Positive-fixture inverse plus explicit incomplete/sequence-gap refusal."""
    nals: list[bytes] = []
    pending = None
    previous = None
    for raw in wire:
        require(len(raw) >= 13 and raw[:1] == b"\x80", "fixture RTP framing")
        seq = struct.unpack("!H", raw[2:4])[0]
        payload = raw[12:]
        kind = payload[0] & 31
        if kind == 28:
            require(len(payload) >= 2, "short fragment")
            start, end = bool(payload[1] & 128), bool(payload[1] & 64)
            require(not (start and end), "fragment start/end conflict")
            if start:
                require(pending is None, "fragment interrupted")
                pending = bytes([(payload[0] & 0x60) | (payload[1] & 31)])
            else:
                require(pending is not None and previous is not None and seq == previous + 1,
                        "fragment lacks contiguous start")
            pending += payload[2:]
            if end:
                nals.append(pending)
                pending = None
        else:
            require(pending is None and 1 <= kind <= 23, "unexpected fixture packetization")
            nals.append(payload)
        previous = seq
    require(pending is None, "incomplete final fragment")
    return nals


def run(args: list[str]) -> bytes:
    return subprocess.run(args, check=True, capture_output=True, timeout=30).stdout


def main() -> None:
    for program in ("ffmpeg", "ffprobe"):
        require(shutil.which(program) is not None, f"missing laboratory {program}")
    data = FIXTURE.read_bytes()
    require(hashlib.sha1(f"blob {len(data)}\0".encode() + data).hexdigest() == EXPECTED_GIT_BLOB,
            "fixture differs from pinned source blob")
    nals = split(data)
    windows = independent_windows(nals)
    require(windows == [list(range(6)), list(range(6, 9))], "unexpected real-fixture GOP boundary")
    require([n[0] & 31 for n in nals if n[0] & 31 in (1, 5)] == [5, 1, 1, 5], "picture sequence")
    original = run(["ffmpeg", "-v", "error", "-threads", "1", "-i", str(FIXTURE),
                    "-f", "rawvideo", "-pix_fmt", "yuv420p", "-"])
    reports = []
    with tempfile.TemporaryDirectory(prefix="fss-collector-oracle-") as tmp:
        for fragmented in (False, True):
            all_packets = packets(nals, fragmented)
            assigned: list[bytes] = []
            decoded: list[bytes] = []
            details = []
            for number, selected in enumerate(windows):
                sources = [raw for ordinal, raw in all_packets if ordinal in selected]
                recovered = reconstruct(sources)
                require(recovered == [nals[i] for i in selected], "source-to-NAL mismatch")
                require(recovered[0][0] & 31 == 7 and recovered[1][0] & 31 == 8, "missing exact config")
                require(next(n for n in recovered if n[0] & 31 in (1, 5))[0] & 31 == 5, "non-IDR start")
                annexb = b"".join(b"\0\0\0\1" + nal for nal in recovered)
                path = pathlib.Path(tmp) / f"window-{number}.264"
                path.write_bytes(annexb)
                pixels = run(["ffmpeg", "-v", "error", "-threads", "1", "-i", str(path),
                              "-f", "rawvideo", "-pix_fmt", "yuv420p", "-"])
                frames = json.loads(run(["ffprobe", "-v", "error", "-show_entries",
                                         "frame=width,height,key_frame", "-of", "json", str(path)]))["frames"]
                require(len(frames) == (3 if number == 0 else 1), "decoded picture count")
                require(frames[0]["key_frame"] == 1, "independent window random access")
                decoded.append(pixels)
                assigned.extend(sources)
                details.append({"packets": len(sources), "pictures": len(frames),
                                "annexb_sha256": sha(annexb), "decoded_pixels_sha256": sha(pixels),
                                "source_sha256": sha(b"".join(sources))})
            require(assigned == [raw for _, raw in all_packets], "lost/repeated/rewritten original")
            require(b"".join(decoded) == original, "independent windows changed decoded pixels")
            reports.append({"packetization": "fu-a" if fragmented else "single-nal",
                            "original_packets": len(all_packets), "windows": details})
        fragments = packets(nals, True)
        # Remove the first VCL FU start. The retained FU end must not become a NAL.
        del fragments[3]
        try:
            reconstruct([raw for _, raw in fragments])
        except ValueError:
            pass
        else:
            raise ValueError("independent fixture inverse accepted missing FU start")
    print(json.dumps({"status": "passed", "qualification": "independent_fixture_oracle_only",
                      "rust_executed": False, "fixture_sha256": sha(data), "cases": reports,
                      "missing_fu_start_refused": True,
                      "ffmpeg": run(["ffmpeg", "-version"]).decode().splitlines()[0]}, sort_keys=True))


if __name__ == "__main__":
    main()
