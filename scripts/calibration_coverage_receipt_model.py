#!/usr/bin/env python3
"""Independent standard-library model of coverage abstention and receipt framing.

This is not execution of the Rust implementation or production qualification.
Run: python3 scripts/calibration_coverage_receipt_model.py
"""
from __future__ import annotations
import hashlib
import itertools
import json
import math
import random
import struct

DOMAIN = b"fss.calibration_coverage_receipt.v1"
POLICY = (b"fss.calibration_coverage_guard.v1:full-camera-marginal:"
          b"exact-ground-grid:radius-3:linearized-pixel-depth:half-open-image:"
          b"closed-contour-vs-half-open-mask:all-samples-inside-unmasked:abstention-only")
MAX_U64 = (1 << 64) - 1

def digest(data: bytes) -> bytes:
    return b"\x01" + hashlib.sha256(data).digest()

def text(data: bytes) -> bytes:
    return struct.pack(">Q", len(data)) + data

def partition(ranges: list[tuple[int, int, str]], first: int, last: int) -> bool:
    previous = None
    for lo, hi, _ in sorted(ranges):
        if lo > hi or lo < first or hi > last:
            return False
        if previous is None:
            if lo != first:
                return False
        elif previous == MAX_U64 or lo != previous + 1:
            return False
        previous = hi
    return previous == last

def compress(labels: list[str], offset: int) -> list[tuple[int, int, str]]:
    out: list[tuple[int, int, str]] = []
    for index, label in enumerate(labels, offset):
        if out and out[-1][2] == label and label != "entry":
            out[-1] = (out[-1][0], index, label)
        else:
            out.append((index, index, label))
    return [(a, b, "too_short" if a == b and c == "witness" else c) for a, b, c in out]

def project(ranges: list[tuple[int, int, str]], reject: bool) -> list[tuple[int, int, str]]:
    witnesses = [r for r in ranges if r[2] == "witness"]
    gaps = [r for r in ranges if r[2] != "witness"]
    if reject:
        gaps.extend((a, b, "calibration_uncertainty") for a, b, _ in witnesses)
        witnesses = []
    return sorted(witnesses + gaps)

def check_projection(labels: list[str], offset: int) -> None:
    source = compress(labels, offset)
    assert partition(source, offset, offset + len(labels) - 1)
    for reject in [False, True]:
        result = project(source, reject)
        assert partition(result, offset, offset + len(labels) - 1)
        # A separate per-segment oracle, not a second interval transformation.
        original = {i: reason for lo, hi, reason in source for i in range(lo, hi + 1)}
        expected = {i: "calibration_uncertainty" if reject and r == "witness" else r
                    for i, r in original.items()}
        actual = {i: r for lo, hi, r in result for i in range(lo, hi + 1)}
        assert actual == expected
        assert all(r in result for r in source if r[2] != "witness")
        assert project(result, reject) == result
    for index in range(len(source)):
        a, b, reason = source[index]
        overlap = source[:index] + [(a, b, reason), (a, b, reason)] + source[index + 1:]
        assert not partition(overlap, offset, offset + len(labels) - 1)
        assert not partition(source[:index] + source[index + 1:], offset, offset + len(labels) - 1)

class Decoder:
    def __init__(self, data: bytes):
        self.data, self.position = data, 0
    def take(self, length: int) -> bytes:
        if length < 0 or self.position + length > len(self.data):
            raise ValueError("truncated")
        part = self.data[self.position:self.position + length]
        self.position += length
        return part
    def integer(self, width: int) -> int:
        return int.from_bytes(self.take(width), "big")
    def text(self) -> bytes:
        n = self.integer(8)
        if n > 65536:
            raise ValueError("text budget")
        return self.take(n)
    def digest(self) -> bytes:
        value = self.take(33)
        if value[0] != 1:
            raise ValueError("digest algorithm")
        return value

def encode(entries: list[tuple[bytes, bytes, tuple[int, ...]]], pose: list[float]) -> bytes:
    body = text(DOMAIN) + text(POLICY)
    body += b"".join(digest(str(i).encode()) for i in range(7))
    body += struct.pack(">QQQQ", 1, 2, 3, 0)  # camera, two generations, no mask
    body += struct.pack(">36d", *pose)
    body += bytes([len(entries)])
    for key, base, counts in entries:
        body += key + base + struct.pack(">7I", *counts)
    return body

def decode(data: bytes) -> list[tuple[bytes, bytes, tuple[int, ...]]]:
    if len(data) > 8192:
        raise ValueError("receipt budget")
    d = Decoder(data)
    if d.text() != DOMAIN or d.text() != POLICY:
        raise ValueError("unknown contract")
    for _ in range(7):
        d.digest()
    camera = [d.integer(8) for _ in range(3)]
    if 0 in camera:
        raise ValueError("zero camera identity")
    d.integer(8)
    if not all(math.isfinite(x) for x in struct.unpack(">36d", d.take(288))):
        raise ValueError("nonfinite covariance")
    count = d.integer(1)
    if not 1 <= count <= 16:
        raise ValueError("zone budget")
    out = []
    for _ in range(count):
        key, base = d.digest(), d.digest()
        counts = tuple(d.integer(4) for _ in range(7))
        if not 1 <= sum(counts) <= 1024 or (out and out[-1][0] >= key):
            raise ValueError("noncanonical zone or counts")
        out.append((key, base, counts))
    if d.position != len(data):
        raise ValueError("trailing bytes")
    return out

def refuses(data: bytes) -> None:
    try:
        decode(data)
    except ValueError:
        return
    raise AssertionError("malformed receipt accepted")

def main() -> None:
    exhaustive = 0
    for labels in itertools.product(["witness", "gap", "entry"], repeat=8):
        check_projection(list(labels), 0)
        exhaustive += 1
    rng = random.Random(0xF55CA16)
    for _ in range(4096):
        n = rng.randrange(1, 65)
        labels = rng.choices(["witness", "gap", "entry", "privacy", "decode_refused"], k=n)
        check_projection(labels, rng.choice([0, 1000, MAX_U64 - n + 1]))
    truncated = 0
    fingerprint = hashlib.sha256()
    for count in range(1, 17):
        entries = sorted((digest(f"zone-{i}".encode()), digest(b"base"), (4, 0, 0, 0, 0, 0, 0))
                         for i in range(count))
        encoded = encode(entries, [0.0] * 36)
        assert len(encoded) <= 8192 and decode(encoded) == entries
        fingerprint.update(encoded)
        for end in range(len(encoded)):
            refuses(encoded[:end]); truncated += 1
        refuses(encoded + b"\0")
        refuses(encode(entries, [float("nan")] + [0.0] * 35))
        invalid = entries.copy()
        invalid[0] = (*invalid[0][:2], (0,) * 7)
        refuses(encode(invalid, [0.0] * 36))
        invalid[0] = (*invalid[0][:2], (0xFFFFFFFF,) * 7)
        refuses(encode(invalid, [0.0] * 36))
        if count > 1:
            refuses(encode(list(reversed(entries)), [0.0] * 36))
    refuses(encode([], [0.0] * 36))
    refuses(encode(entries + [entries[-1]], [0.0] * 36))
    print(json.dumps({"model": "independent_python_not_rust_execution", "passed": True,
        "exhaustive_partitions": exhaustive, "seeded_partitions": 4096,
        "receipt_sizes_tested": 16, "rejected_truncations": truncated,
        "receipt_fixture_sha256": fingerprint.hexdigest()}, indent=2))

if __name__ == "__main__":
    main()
