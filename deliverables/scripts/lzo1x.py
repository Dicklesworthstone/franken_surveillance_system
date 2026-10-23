#!/usr/bin/env python3
"""Standalone LZO1X-1 decompressor with optional 64 KiB preset dictionary.

Implements the semantics of liblzo's lzo1x_decompress_safe(): same token
grammar, same EOF token, same bounds checks.  A preset dictionary (default:
64 KiB of zero bytes) is pre-loaded at the front of the output window, so a
back-reference whose distance exceeds the number of bytes produced resolves
into the dictionary instead of underflowing.

On failure the partial output is returned and the reason is reported.

CLI:
    lzo1x.py IN OUT [--offset N] [--max-size N] [--dict FILE|--zero-dict]
    lzo1x.py --selftest [--iters N]

--zero-dict (the default) uses 64 KiB of zero bytes; --dict FILE reads up to
65536 bytes from FILE instead (left-padded with zeros).
"""

import argparse
import os
import random
import sys

M2_MAX_OFFSET = 0x0800
TRACE = None
DICT_SIZE = 0x10000


class LzoError(Exception):
    pass


def decompress(src, dict_bytes=None, max_size=64 << 20, stats=None):
    """Decode as much as possible; partial output is returned with stats['err' set] on failure."""
    box = []
    try:
        return _core(src, dict_bytes, max_size, stats, box)
    except LzoError as e:
        if stats is not None:
            stats["err"] = str(e)
        win = box[0]
        return bytes(win[DICT_SIZE:])


def _core(src, dict_bytes=None, max_size=64 << 20, stats=None, box=None):
    """Decode an LZO1X stream.

    `dict_bytes` (<= 65536 bytes) is used as a preset window; it is
    zero-padded on the left to 64 KiB so that distance arithmetic lines up
    with the fixed 64 KiB window an encoder used.
    """
    if dict_bytes is None:
        dict_bytes = b"\x00" * DICT_SIZE
    if len(dict_bytes) > DICT_SIZE:
        raise LzoError("dictionary larger than 64 KiB")
    # Window is [zero pad][dict] with exactly DICT_SIZE bytes, so distance
    # arithmetic matches a fixed 64 KiB encoder window.
    win = bytearray(DICT_SIZE)
    win[DICT_SIZE - len(dict_bytes):] = dict_bytes
    if box is not None:
        box.append(win)
    op = DICT_SIZE

    n = len(src)
    ip = 0
    limit = DICT_SIZE + max_size

    def need_in(k=1):
        if ip + k > n:
            raise LzoError("input exhausted at %d" % ip)

    def need_out(k=1):
        if op + k > limit:
            if stats is not None:
                stats["ip"] = ip
            raise LzoError("output exceeds max-size %d" % max_size)

    def lit(count):
        nonlocal ip, op
        need_in(count)
        need_out(count)
        win[op:op + count] = src[ip:ip + count]
        if TRACE and TRACE[0] < 30:
            TRACE[0] += 1
            print("LIT ip=%d n=%d op=%d %r" % (ip, count, op, bytes(src[ip:ip+min(count,16)])))
        ip += count
        op += count

    def match(m_pos, count):
        nonlocal op
        need_out(count)
        if m_pos < 0:
            raise LzoError("back-reference before window start")
        if m_pos >= op:
            raise LzoError("back-reference at/after op")
        if TRACE and TRACE[0] < 30:
            TRACE[0] += 1
            print("MATCH op=%d dist=%d n=%d" % (op, op - m_pos, count))
        if op - m_pos >= count:
            win[op:op + count] = win[m_pos:m_pos + count]
            op += count
        else:
            for _ in range(count):
                win.append(win[m_pos])
                m_pos += 1
            op += count

    need_in(1)
    t = src[ip]
    if t > 17:
        ip += 1
        t -= 17
        if t < 4:
            # straight into the trailing-literal path of a match
            lit(t)
            need_in(1)
            t = src[ip]
            ip += 1
            state = "match"
        else:
            lit(t)
            state = "first_literal_run"
    else:
        state = "outer"

    while True:
        if state == "outer":
            need_in(1)
            t = src[ip]
            ip += 1
            if t >= 16:
                state = "match"
                continue
            if t == 0:
                while True:
                    need_in(1)
                    if src[ip] != 0:
                        break
                    t += 255
                    ip += 1
                t += 15 + src[ip]
                ip += 1
            lit(t + 3)
            state = "first_literal_run"
            continue

        if state == "first_literal_run":
            need_in(1)
            t = src[ip]
            ip += 1
            if t >= 16:
                state = "match"
                continue
            need_in(1)
            m_pos = op - (1 + M2_MAX_OFFSET)
            m_pos -= t >> 2
            m_pos -= src[ip] << 2
            ip += 1
            match(m_pos, 3)
            state = "match_done"
            continue

        if state == "match":
            if t >= 64:
                need_in(1)
                m_pos = op - 1
                m_pos -= (t >> 2) & 7
                m_pos -= src[ip] << 3
                ip += 1
                count = (t >> 5) - 1
            elif t >= 32:
                t &= 31
                if t == 0:
                    while True:
                        need_in(1)
                        if src[ip] != 0:
                            break
                        t += 255
                        ip += 1
                    t += 31 + src[ip]
                    ip += 1
                need_in(2)
                m_pos = op - 1
                m_pos -= (src[ip] >> 2) + (src[ip + 1] << 6)
                ip += 2
                count = t
            elif t >= 16:
                m_pos = op - ((t & 8) << 11)
                t &= 7
                if t == 0:
                    while True:
                        need_in(1)
                        if src[ip] != 0:
                            break
                        t += 255
                        ip += 1
                    t += 7 + src[ip]
                    ip += 1
                need_in(2)
                m_pos -= (src[ip] >> 2) + (src[ip + 1] << 6)
                ip += 2
                if m_pos == op:
                    if stats is not None:
                        stats["ip"] = ip
                        stats["eof"] = True
                    return bytes(win[DICT_SIZE:op])
                m_pos -= 0x4000
                count = t
            else:
                need_in(1)
                m_pos = op - 1
                m_pos -= t >> 2
                m_pos -= src[ip] << 2
                ip += 1
                match(m_pos, 2)
                state = "match_done"
                continue
            match(m_pos, count + 2)
            state = "match_done"
            continue

        if state == "match_done":
            if ip < 2:
                raise LzoError("match_done without offset bytes")
            t = src[ip - 2] & 3
            if t == 0:
                state = "outer"
                continue
            lit(t)
            # match_next in the reference: the following token is always a
            # match token, so read it and go straight to match handling.
            need_in(1)
            t = src[ip]
            ip += 1
            state = "match"
            continue


# --------------------------------------------------------------------------
# selftest
# --------------------------------------------------------------------------

def _find_lib():
    for d in ("/opt/homebrew/lib", "/usr/local/lib", "/usr/lib", "/usr/lib/x86_64-linux-gnu"):
        for name in ("liblzo2.dylib", "liblzo2.so.2", "liblzo2.so"):
            p = os.path.join(d, name)
            if os.path.exists(p):
                return p
    return None


def _load_liblzo():
    import ctypes
    path = _find_lib()
    if path is None:
        return None
    lib = ctypes.CDLL(path)
    lib.lzo1x_1_compress.restype = ctypes.c_int
    lib.lzo1x_1_compress.argtypes = [
        ctypes.c_char_p, ctypes.c_size_t, ctypes.c_char_p,
        ctypes.POINTER(ctypes.c_size_t), ctypes.c_void_p]
    lib.lzo1x_decompress_safe.restype = ctypes.c_int
    lib.lzo1x_decompress_safe.argtypes = [
        ctypes.c_char_p, ctypes.c_size_t, ctypes.c_char_p,
        ctypes.POINTER(ctypes.c_size_t), ctypes.c_void_p]
    return lib


def _lzo_compress(lib, data):
    import ctypes
    n = len(data)
    bound = n + n // 16 + 64 + 3
    out = ctypes.create_string_buffer(bound)
    outlen = ctypes.c_size_t(bound)
    wrk = ctypes.create_string_buffer(1 << 20)  # > LZO1X_1_MEM_COMPRESS
    r = lib.lzo1x_1_compress(data, n, out, ctypes.byref(outlen), wrk)
    if r != 0:
        raise RuntimeError("lzo1x_1_compress rc=%d" % r)
    return out.raw[:outlen.value]


def _lzo_decompress(lib, blob, expected):
    import ctypes
    out = ctypes.create_string_buffer(expected + 64)
    outlen = ctypes.c_size_t(expected + 64)
    r = lib.lzo1x_decompress_safe(blob, len(blob), out, ctypes.byref(outlen), None)
    if r != 0:
        raise RuntimeError("lzo1x_decompress_safe rc=%d" % r)
    return out.raw[:outlen.value]


def handcrafted_vectors():
    """Hand-assembled token streams exercising every token class.

    Length rules used: extended literal run `00 n` emits n+18 literals;
    header run `b` (18..255) emits b-17 literals; M1/M2 emit 2/3 bytes and
    carry the trailing-literal count in bits 1:0 of their first offset byte;
    M3 emits (t&31)+2; M4 emits (t&7)+2 after an extended count.
    EOF is an M4 token with t&8 == 0 and both offset bytes zero, which makes
    m_pos == op.
    """
    EOF = bytes([0x11, 0x00, 0x00])
    V = {}
    # 1. Extended literal run: 00, 01 -> 15 + 1 = 16, i.e. 19 literals.
    V["literal_run"] = (bytes([0x00, 0x01]) + b"A" * 19 + EOF, b"A" * 19)
    # 2. Header literal run, M3 match, then an M1 back-reference (dist 1)
    #    with one trailing literal, then EOF.
    V["hdr_literal_m1"] = (bytes([17 + 4]) + b"B" * 4 + bytes([0x21, 0x01, 0x00])
                           + b"C" + bytes([0x01, 0x00]) + b"D" + EOF,
                           b"B" * 7 + b"CCC" + b"D")
    # 3. M2 match resolving into the zero dictionary (dist 0x801), trailing 1.
    V["m2_dict"] = (bytes([17 + 4]) + b"X" * 4 + bytes([0x01, 0x00])
                    + b"C" + EOF, b"X" * 4 + b"\x00\x00\x00" + b"C")
    # 4. M3 overlapping match, dist 1, length 4, no trailing literals.
    V["m3_overlap"] = (bytes([17 + 4]) + b"A" * 4 + bytes([0x22, 0x00, 0x00])
                       + EOF, b"A" * 8)
    # 5. M4 match into the zero dictionary (dist 0x8000), length 10.
    V["m4_dict"] = (bytes([17 + 4]) + b"ZYXQ" + bytes([0x18, 0x01, 0x00, 0x00])
                    + EOF, b"ZYXQ" + b"\x00" * 10)
    # 6. Trailing-literal encoding: two literals after an overlapping match.
    #    dist 1 is a run repeat, so the match emits 4 b's.
    V["trailing_lits"] = (bytes([17 + 2]) + b"ab" + bytes([0x22, 0x02, 0x00])
                          + b"cd" + EOF, b"ab" + b"bbbb" + b"cd")
    # 7. Long extended match: M3 token 0x20 (t&31 == 0) with zero padding
    #    bytes then 0x01 -> length 255 + 31 + 1 + 2 = 289.
    V["extended_match"] = (bytes([17 + 2]) + b"ab"
                           + bytes([0x20, 0x00, 0x00, 0x01, 0x00, 0x00])
                           + EOF, b"ab" + b"b" * 544)
    return V


def _dict_vectors():
    """Vectors whose results depend on dictionary contents (not just zeros)."""
    EOF = bytes([0x11, 0x00, 0x00])
    return {
        # M2 at distance 0x802 straight into a 0xAA-filled dictionary.
        "dict_nonzero": (bytes([17 + 4]) + b"X" * 4 + bytes([0x04, 0x00]) + EOF,
                         b"X" * 4 + b"\xaa" * 3, b"\xaa" * 0x10000),
    }


def selftest(iters=400, verbose=True):
    import ctypes
    # --- handcrafted vectors first (always available) -------------------
    fails = 0
    vectors = handcrafted_vectors()
    for name, (stream, expect) in vectors.items():
        try:
            got = decompress(stream)
        except Exception as e:
            print("  FAIL %-16s raised %s" % (name, e))
            fails += 1
            continue
        if got != expect:
            print("  FAIL %-16s got %r want %r" % (name, got, expect))
            fails += 1
        elif verbose:
            print("  ok   %-16s" % name)
    for name, (stream, expect, d) in _dict_vectors().items():
        try:
            got = decompress(stream, d)
        except Exception as e:
            print("  FAIL %-16s raised %s" % (name, e)); fails += 1; continue
        if got != expect:
            print("  FAIL %-16s got %r want %r" % (name, got, expect)); fails += 1
        elif verbose:
            print("  ok   %-16s (nonzero dict)" % name)
    if fails:
        print("handcrafted vectors: %d failure(s)" % fails)
        return 1
    print("handcrafted vectors: all %d ok (incl. dictionary)" % (len(vectors) + 1))

    lib = _load_liblzo()
    if lib is None and not os.path.exists("/opt/homebrew/lib/liblzo2.dylib"):
        print("liblzo not found -> handcrafted vectors only")
        return 0
    if lib is None:
        # fall back to the CLI helper if the shim refuses to load
        print("liblzo present but not loadable via ctypes -> handcrafted only")
        return 0

    print("liblzo loaded, running %d round-trips" % iters)
    rnd = random.Random(1234)
    def rand_bytes(n):
        blob = bytearray(rnd.getrandbits(8) for _ in range(n))
        for _ in range(n // 40):           # sprinkle structure
            p = rnd.randrange(n)
            blob[p:p + rnd.randrange(1, 12)] = bytes([rnd.getrandbits(8)]) * 1
        return bytes(blob)
    def repetitive(n):
        alpha = bytes(rnd.getrandbits(8) for _ in range(rnd.randrange(1, 8)))
        return bytes(alpha[rnd.randrange(len(alpha))] for _ in range(n))
    def runs(n):
        out = bytearray()
        while len(out) < n:
            out.extend(bytes([rnd.getrandbits(8)]) * rnd.randrange(1, 300))
        return bytes(out[:n])

    cases = []
    for _ in range(iters):
        kind = rnd.randrange(3)
        size = rnd.choice([0, 1, 2, 3, 4, 5, 17, 18, 33, 64, 200, 1000, 5000, 40000, 70000])
        if kind == 0:
            cases.append(("random", rand_bytes(size)))
        elif kind == 1:
            cases.append(("repetitive", repetitive(size)))
        else:
            cases.append(("runs", runs(size)))

    for name, data in cases:
        blob = _lzo_compress(lib, data)
        ref = _lzo_decompress(lib, blob, len(data))
        if ref != data:
            print("  FAIL lzo itself disagreed on %s/%d" % (name, len(data)))
            return 1
        try:
            got = decompress(blob, max_size=max(len(data) + 64, 1 << 20))
        except Exception as e:
            print("  FAIL %s %d bytes raised %s" % (name, len(data), e))
            fails += 1
            continue
        if got != data:
            print("  FAIL %s %d bytes mismatch (%d vs %d)" % (name, len(data), len(got), len(data)))
            fails += 1
    print("round-trips: %d cases, %d failure(s)" % (len(cases), fails))

    # error detection: truncation and corruption must not silently pass
    import zlib
    bad = 0
    for _ in range(100):
        data = rand_bytes(rnd.randrange(100, 4000))
        blob = _lzo_compress(lib, data)
        if len(blob) < 4:
            continue
        cut = blob[:rnd.randrange(1, len(blob))]
        if _lzo_decompress_ok(lib, cut):
            continue  # liblzo also accepts it
        st = {}
        decompress(cut, None, len(data) + 64, st)
        if "err" in st:
            bad += 1
        else:
            print("  FAIL truncated stream decoded without error")
            fails += 1
    print("truncation detection: %d/100 rejected" % bad)
    return 1 if fails else 0


def _lzo_decompress_ok(lib, blob):
    import ctypes
    out = ctypes.create_string_buffer(1 << 20)
    outlen = ctypes.c_size_t(1 << 20)
    return lib.lzo1x_decompress_safe(blob, len(blob), out, ctypes.byref(outlen), None) == 0


def main(argv):
    ap = argparse.ArgumentParser(description="LZO1X decompressor with preset dictionary")
    ap.add_argument("input", nargs="?")
    ap.add_argument("output", nargs="?")
    ap.add_argument("--offset", type=lambda s: int(s, 0), default=0)
    ap.add_argument("--max-size", type=lambda s: int(s, 0), default=64 << 20)
    ap.add_argument("--dict")
    ap.add_argument("--zero-dict", action="store_true")
    ap.add_argument("--selftest", action="store_true")
    ap.add_argument("--iters", type=int, default=400)
    a = ap.parse_args(argv)

    if a.selftest:
        return selftest(a.iters)

    if not a.input or not a.output:
        ap.error("input and output are required")

    with open(a.input, "rb") as f:
        src = f.read()
    if a.offset:
        if a.offset > len(src):
            print("offset beyond end of file", file=sys.stderr)
            return 1
        src = src[a.offset:]

    d = None
    if a.dict:
        with open(a.dict, "rb") as f:
            d = f.read()
    st = {}
    out = decompress(src, d, a.max_size, st)
    with open(a.output, "wb") as f:
        f.write(out)
    print("%d -> %d%s" % (len(src), len(out), (" (" + st["err"] + ")") if "err" in st else ""))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
