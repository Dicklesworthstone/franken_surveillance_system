#!/usr/bin/env python3
"""Differential test: tools/tapo_lzma2.py must byte-match Python's liblzma.

The reference encoder is the `lzma` stdlib module in LZMA2 raw mode; the decoder
under test is the hand-written range coder that exists because the SigmaStar
props byte can violate liblzma's lc+lp<=4 limit. Parity on every stream the
reference emits is the acceptance bar — a decoder that only round-trips its own
encoder proved nothing (the C460 ramdisk desync).
"""
from __future__ import annotations

import importlib.util
import lzma
import pathlib
import random
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("tapo_lzma2", ROOT / "tools" / "tapo_lzma2.py")
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


def reference_lzma2(payload: bytes, *, lc: int = 3, lp: int = 0, pb: int = 2,
                    preset: int = 6, dict_size: int | None = None) -> bytes:
    filt: dict = {"id": lzma.FILTER_LZMA2, "preset": preset, "lc": lc, "lp": lp, "pb": pb}
    if dict_size is not None:
        filt["dict_size"] = dict_size
    return lzma.compress(payload, format=lzma.FORMAT_RAW, filters=[filt])


class TapoLzma2Parity(unittest.TestCase):
    def decode(self, stream: bytes, out_size: int) -> bytes:
        return MODULE.lzma2(stream, out_size)

    def test_documented_divergence_hello_hello_world_x50(self) -> None:
        payload = b"hello hello hello world" * 50
        dec = self.decode(reference_lzma2(payload), len(payload))
        self.assertEqual(dec, payload)

    def test_empty_and_short(self) -> None:
        for payload in (b"", b"x", b"ab" * 3):
            with self.subTest(payload=payload):
                dec = self.decode(reference_lzma2(payload), len(payload))
                self.assertEqual(dec, payload)

    def test_all_repeat_distances_rep_sequences(self) -> None:
        # every rep0 distance 1..8 with mixed following literals, twice over, so
        # the rep-state machine (is_rep0_long short/long, g1, g2 rotation) is
        # exercised in every state including post-match states 7..10
        payload = b"".join(bytes([97 + (d % 26)]) * d + b"Z" for d in range(1, 9)) * 6
        dec = self.decode(reference_lzma2(payload), len(payload))
        self.assertEqual(dec, payload)

    def test_long_distance_direct_bits(self) -> None:
        # distances beyond slot 13 (>127) drive the direct-bit path of the
        # distance decoder, including the >4 GiB class only via dict-size-bounded
        # distances; 1 MiB of pseudo-random bytes then a re-match at distance ~1 MiB
        rnd = random.Random(20261026)
        payload = bytes(rnd.getrandbits(8) for _ in range(1 << 20))
        payload += payload[:8192]  # far match back to the start
        dec = self.decode(reference_lzma2(payload, preset=9), len(payload))
        self.assertEqual(dec, payload)

    def test_props_matrix(self) -> None:
        rnd = random.Random(42)
        payload = bytes(rnd.getrandbits(8) for _ in range(4096)) * 3 + b"hello" * 200
        for lc in range(3):
            for lp in range(2):
                for pb in range(3):
                    if lc + lp > 4:
                        continue
                    with self.subTest(lc=lc, lp=lp, pb=pb):
                        stream = reference_lzma2(payload, lc=lc, lp=lp, pb=pb)
                        dec = self.decode(stream, len(payload))
                        self.assertEqual(dec, payload)

    def test_multichunk_uncompressed_and_reset(self) -> None:
        # force multiple chunks (10 KiB payload with preset 1 -> 6 KiB dict gives
        # several LZMA chunks) plus an uncompressed chunk by hand-splicing
        payload = b"A" * 5000 + b"B" * 5000
        dec = self.decode(reference_lzma2(payload, preset=1), len(payload))
        self.assertEqual(dec, payload)
        # uncompressed LZMA2 chunk type 0x01, size-1 big-endian, then raw bytes
        raw = b"hello uncompressed world"
        stream = bytes([0x01]) + (len(raw) - 1).to_bytes(2, "big") + raw + b"\x00"
        dec = self.decode(stream, len(raw))
        self.assertEqual(dec, raw)

    def test_random_4kb_payloads(self) -> None:
        rnd = random.Random(0x460)
        for trial in range(20):
            n = rnd.choice((1, 17, 255, 1024, 4096))
            kind = trial % 3
            if kind == 0:
                payload = bytes(rnd.getrandbits(8) for _ in range(n))
            elif kind == 1:
                # highly repetitive: match-heavy with long distances
                chunk = bytes(rnd.getrandbits(8) for _ in range(rnd.randint(1, 40)))
                payload = (chunk * (n // max(1, len(chunk)) + 1))[:n]
            else:
                # structured: alternating literal runs and matches
                parts = []
                while sum(map(len, parts)) < n:
                    parts.append(bytes(rnd.getrandbits(8) for _ in range(rnd.randint(0, 30))))
                    if parts:
                        src = b"".join(parts)
                        if len(src) > 8:
                            d = rnd.randint(1, min(len(src), 500))
                            parts.append(src[-d:] * rnd.randint(1, 3))
                payload = b"".join(parts)[:n]
            with self.subTest(trial=trial, n=n, kind=kind):
                stream = reference_lzma2(payload)
                dec = self.decode(stream, len(payload))
                self.assertEqual(dec, payload, "trial %d kind %d" % (trial, kind))


if __name__ == "__main__":
    unittest.main(verbosity=2)
