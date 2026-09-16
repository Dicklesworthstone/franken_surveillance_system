#!/usr/bin/env python3
"""Independent catalog-format/interval oracle. Does NOT execute or qualify Rust."""
from __future__ import annotations
import hashlib
import json
import pathlib
import random
import struct
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "crates/fss-reference/tests/fixtures/recording_catalog"
DOMAIN = b"fss.recording_catalog.v1"
KIND = b"avc_recording_catalog_v1"
WINDOW_KIND = b"avc_recording_window_v1"
MAX = (1 << 64) - 1


def need(ok: bool, reason: str) -> None:
    if not ok:
        raise ValueError(reason)


def sha(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def text(data: bytes) -> bytes:
    return struct.pack("!Q", len(data)) + data


def dg(data: bytes) -> bytes:
    need(len(data) == 32, "digest length")
    return b"\x01" + data


def manifest(kind: bytes, children: list[bytes], metadata: bytes) -> bytes:
    refs = sorted(children + [metadata])
    need(len(set(refs)) == len(refs), "duplicate manifest child")
    return text(b"fss.object_manifest.v1") + text(kind) + struct.pack("!Q", len(refs)) + b"".join(map(dg, refs)) + b"\x01" + dg(metadata)


def golden() -> tuple[bytes, bytes]:
    body = text(DOMAIN) + struct.pack("!Q", 1) + text(b"catalog-wire-fixture") + text(b"main")
    body += struct.pack("!Q", 1) + b"".join(dg(sha(s)) for s in [b"owner", b"receive", b"decode"])
    body += struct.pack("!IQ", 90000, 2)
    closure = []
    for name, start, label in [(b"first", 3600, b"A"), (b"second", 10800, b"B")]:
        # Opaque metadata fixture objects, NOT decodable footage or a recording proof.
        children = [sha(b"source-" + label), sha(b"shared-init"), sha(b"media-" + label), sha(b"index-" + label)]
        root = sha(manifest(WINDOW_KIND, children[:3], children[3]))
        body += text(name) + dg(root) + struct.pack("!6Q", start, start + 3600, 1, 1, 1, 512)
        body += b"".join(map(dg, children))
        closure += [root] + children
    index = body + dg(sha(body))
    return index, manifest(KIND, sorted(set(closure)), sha(index))


class Reader:
    def __init__(self, data: bytes):
        self.data = data
        self.pos = 0

    def take(self, count: int) -> bytes:
        need(0 <= count <= len(self.data) - self.pos, "truncated field")
        out = self.data[self.pos:self.pos + count]
        self.pos += count
        return out

    def u64(self) -> int:
        return int.from_bytes(self.take(8), "big")

    def string(self) -> bytes:
        size = self.u64()
        need(size <= 65536, "text bound")
        return self.take(size)

    def digest(self) -> bytes:
        need(self.take(1) == b"\x01", "non-SHA256 fixture digest")
        return self.take(32)

    def done(self) -> None:
        need(self.pos == len(self.data), "trailing bytes")


def decode(index: bytes, root: bytes) -> list[tuple[int, int]]:
    need(len(index) + len(root) <= 65536 and len(index) >= 33, "page bound")
    need(index[-33:] == dg(sha(index[:-33])), "checksum")
    d = Reader(index[:-33])
    need(d.string() == DOMAIN and d.u64() == 1, "version/domain")
    need(d.string() == b"catalog-wire-fixture" and d.string() == b"main" and d.u64() == 1, "scope")
    for label in [b"owner", b"receive", b"decode"]:
        need(d.digest() == sha(label), "clock/anchor")
    need(d.take(4) == struct.pack("!I", 90000), "tick rate")
    count = d.u64()
    need(1 <= count <= 64, "entry count")
    ranges, slots, roots, closure = [], set(), set(), set()
    for _ in range(count):
        slot = d.string()
        need(1 <= len(slot) <= 128 and slot[:1] not in (b"_", b"-") and all(c in b"abcdefghijklmnopqrstuvwxyz0123456789_-" for c in slot), "slot")
        window_root = d.digest()
        start, end, packets, samples, nals, size = [d.u64() for _ in range(6)]
        need(start < end and (not ranges or ranges[-1][1] <= start), "range order")
        need(slot not in slots and window_root not in roots, "duplicate entry")
        need(1 <= packets <= 4096 and 1 <= samples <= 256 and 1 <= nals <= 16384 and 1 <= size <= 33554432, "descriptor bound")
        children = [d.digest() for _ in range(4)]
        need(sha(manifest(WINDOW_KIND, children[:3], children[3])) == window_root, "window closure")
        slots.add(slot); roots.add(window_root); closure.update([window_root] + children)
        ranges.append((start, end))
    d.done()
    need(root == manifest(KIND, sorted(closure), sha(index)), "flat closure")
    return ranges


def selection(ranges: list[tuple[int, int]], start: int, end: int) -> tuple[list[tuple[int, int]], list[tuple[int, int]]]:
    need(start < end, "query interval")
    selected, gaps, cursor = [], [], start
    for a, b in ranges:
        a, b = max(start, a), min(end, b)
        if a >= b:
            continue
        if cursor < a:
            gaps.append((cursor, a))
        selected.append((a, b)); cursor = b
    if cursor < end:
        gaps.append((cursor, end))
    return selected, gaps


def main() -> None:
    index, root = golden()
    if sys.argv[1:] == ["--write-fixtures"]:
        FIXTURES.mkdir(parents=True, exist_ok=True)
        (FIXTURES / "v1.index").write_bytes(index)
        (FIXTURES / "v1.root").write_bytes(root)
    elif sys.argv[1:]:
        raise ValueError("only --write-fixtures is supported")
    need((FIXTURES / "v1.index").read_bytes() == index, "golden index drift")
    need((FIXTURES / "v1.root").read_bytes() == root, "golden manifest drift")
    ranges = decode(index, root)
    refused = 0
    for cut in range(len(index)):
        try:
            decode(index[:cut], root)
        except ValueError:
            refused += 1
        else:
            raise AssertionError("accepted truncation")
    for at in range(len(index)):
        corrupt = bytearray(index); corrupt[at] ^= 1
        try:
            decode(bytes(corrupt), root)
        except ValueError:
            refused += 1
        else:
            raise AssertionError("accepted changed byte")
    rng = random.Random(0xF55CA7)
    for _ in range(10000):
        start = rng.randrange(0, 20000); end = start + rng.randrange(1, 20000)
        selected, gaps = selection(ranges, start, end)
        pieces = sorted(selected + gaps)
        need(pieces[0][0] == start and pieces[-1][1] == end, "partition endpoints")
        need(all(a[1] == b[0] for a, b in zip(pieces, pieces[1:])), "partition hole/overlap")
        for tick in [start, end - 1, (start + end) // 2]:
            expected = any(a <= tick < b for a, b in ranges)
            need(any(a <= tick < b for a, b in selected) == expected, "selection differs from point membership")
    need(selection(ranges, 14400, MAX) == ([], [(14400, MAX)]), "u64 edge")
    print(json.dumps({"status": "passed", "rust_executed": False, "qualification": "independent_catalog_wire_and_interval_oracle_only",
        "index_sha256": sha(index).hex(), "root_sha256": sha(root).hex(), "index_bytes": len(index),
        "manifest_bytes": len(root), "refused_corruptions": refused, "interval_cases": 10001}, sort_keys=True))

if __name__ == "__main__":
    main()
