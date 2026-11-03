#!/usr/bin/env python3
"""BCL1 container reader — the C660 U-Boot/ramdisk wrapper that replaced sstarXZ (fss-zgalk).

The C660 image has no `sstarXZ` container at all. It wraps its two compressed members in
**BCL1** blocks instead, and the block carries its own escape byte:

    0x00  'BCL1'
    0x04  u32, low half always 0x0009 (unidentified; kept verbatim on repack)
    0x08  u32 BE  uncompressed size
    0x0c  u32 BE  compressed size
    0x10  u8      escape byte for the body  (0xa7 in the U-Boot block, 0xde in the ramdisk)
    0x11  body

The body is a byte-oriented LZ77: every byte is a literal except the block's escape byte,
which is followed by `len, dist`, both big-endian base-128 VLQ (bit 7 = continuation;
`len == 0` means one literal escape byte). The doubling codes in the stream (`e 81 00`,
`e 82 00`, …) are length 128/256 at the same distance, which a byte-per-field reader
desyncs on at the first one. Reproduced byte-exactly: both C660 members decode to their
declared size, the ramdisk to a 6,776,832-byte newc cpio whose `/bin/main` is the connectAp
target.

The escape byte is *per block*. Hardcoding it silently desyncs the other member, which is
why it is read from the header and never assumed.

  bcl1.py <image> --scan                     # list every container and its header fields
  bcl1.py <image> --extract N --out PATH     # write member N's decoded body
  bcl1.py <image> --json
  bcl1.py --selftest                         # round-trip the codec, no image needed
"""
import argparse
import json
import struct
import sys

MAGIC = b"BCL1"
HEADER = 17


def parse(data: bytes, p: int) -> dict:
    out = {"magic_offset": p, "valid": False}
    if data[p:p + 4] != MAGIC:
        out["error"] = "no BCL1 magic"
        return out
    if p + HEADER > len(data):
        out["error"] = "truncated header"
        return out
    unknown = struct.unpack(">I", data[p + 4:p + 8])[0]
    out["uncompressed_size"] = struct.unpack(">I", data[p + 8:p + 12])[0]
    out["compressed_size"] = struct.unpack(">I", data[p + 12:p + 16])[0]
    out["escape"] = data[p + 16]
    out["unknown"] = unknown
    out["payload_offset"] = p + HEADER
    out["valid"] = (out["uncompressed_size"] > 0
                    and out["compressed_size"] > 0
                    and out["escape"] not in (0x00,)
                    and p + HEADER + out["compressed_size"] <= len(data))
    if not out["valid"]:
        # the three `BCL1` string literals in the U-Boot text also land here
        out["error"] = "sizes out of range or zero escape"
    return out


def scan(data: bytes) -> list[dict]:
    found, i = [], 0
    while True:
        p = data.find(MAGIC, i)
        if p < 0:
            return found
        i = p + 1
        found.append(parse(data, p))


def read_vlq(buf: bytes, i: int) -> tuple[int, int]:
    """Big-endian base-128: bit 7 set means another byte follows.

    The fields are *not* single bytes — a byte read desyncs the archive at the first
    `e 81 00 81 00` (length 128, distance 128) doubling pair.
    """
    v = 0
    while True:
        b = buf[i]
        i += 1
        v = (v << 7) | (b & 0x7F)
        if not b & 0x80:
            return v, i


def decode(body: bytes, want: int, esc: int) -> tuple[bytes, int, str | None]:
    """Decode one body. Returns (bytes, input_used, error). Refuses to guess a desync."""
    out = bytearray()
    i = 0
    while i < len(body) and len(out) < want:
        b = body[i]
        if b != esc:
            out.append(b)
            i += 1
            continue
        i += 1
        length, i = read_vlq(body, i)
        if length == 0:            # the escape byte itself, as a literal
            out.append(esc)
            continue
        dist, i = read_vlq(body, i)
        if dist == 0:
            dist = 256
        if dist > len(out):
            return bytes(out), i, "distance %d past output (%d) at %d" % (dist, len(out), i)
        start = len(out) - dist
        for k in range(length):
            out.append(out[start + k])
    return bytes(out), i, None


def decode_container(data: bytes, c: dict) -> tuple[bytes, int, str | None]:
    body = data[c["payload_offset"]:c["payload_offset"] + c["compressed_size"]]
    return decode(body, c["uncompressed_size"], c["escape"])


def encode(data: bytes, esc: int = 0xde, min_match: int = 4, window: int = 256) -> bytes:
    """Reference encoder used by the tests: greedy, back-references only inside `window`."""
    out = bytearray()
    i = 0
    while i < len(data):
        if data[i] == esc:
            out += bytes([esc, 0])
            i += 1
            continue
        best_len = best_dist = 0
        for dist in range(1, min(window, i) + 1):
            if dist == 256:
                break
            n = 0
            while (i + n < len(data) and n < 255
                   and data[i + n] == data[i + n - dist]):
                n += 1
            if n > best_len:
                best_len, best_dist = n, dist
        if best_len >= min_match:
            out += bytes([esc]) + write_vlq(best_len) + write_vlq(best_dist)
            i += best_len
        else:
            out += data[i:i + 1]
            i += 1
    return bytes(out)


def write_vlq(v: int) -> bytes:
    out = [v & 0x7F]
    v >>= 7
    while v:
        out.append((v & 0x7F) | 0x80)
        v >>= 7
    return bytes(reversed(out))


def build(payload: bytes, esc: int = 0xde, unknown: int = 0xBB490009) -> bytes:
    """Wrap a body in a BCL1 header (used by the tests and by repack work)."""
    comp = encode(payload, esc)
    return (MAGIC + struct.pack(">III", unknown, len(payload), len(comp))
            + bytes([esc]) + comp)


def selftest() -> int:
    fails = 0
    for esc in (0xde, 0xa7, 0x00 + 0x7e):
        # 300-byte block repeated: matches longer than 127 and distances past 127,
        # so both fields cross into their two-byte VLQ form.
        block = bytes((k * 7 + 3) & 0xFF for k in range(300))
        payload = (b"0707010514BAA0000041ED" + b"\x00" * 40
                   + bytes([esc]) * 9 + block + block + block)
        body = build(payload, esc)
        c = parse(body, 0)
        out, used, err = decode_container(body, c)
        ok = out == payload and err is None and used == c["compressed_size"]
        print("  [%s] round-trip escape 0x%02x (%d bytes)" %
              ("ok " if ok else "FAIL", esc, len(payload)))
        fails += not ok
    # a 600-byte run must produce a two-byte VLQ length (0x81 0x7f = 255), not a byte
    run = b"A" * 600
    body = build(run)
    two_byte = any(body[k] == 0xDE and body[k + 1] & 0x80
                   for k in range(len(body) - 1))
    out, _used, err = decode_container(body, parse(body, 0))
    ok = two_byte and out == run and err is None
    print("  [%s] long-run length uses two-byte VLQ" % ("ok " if ok else "FAIL"))
    fails += not ok

    # a distance greater than the output must be reported, never silently accepted
    body = MAGIC + struct.pack(">III", 0xBB490009, 8, 3) + b"\xde\xde\x04\x50"
    c = parse(body, 0)
    _out, _used, err = decode_container(body, c)
    ok = err is not None and "past output" in err
    print("  [%s] short-distance refusal" % ("ok " if ok else "FAIL"))
    fails += not ok
    return 1 if fails else 0


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("image", nargs="?")
    ap.add_argument("--scan", action="store_true")
    ap.add_argument("--extract", type=int, metavar="N")
    ap.add_argument("--out")
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--selftest", action="store_true")
    a = ap.parse_args()

    if a.selftest:
        return selftest()
    if not a.image:
        ap.error("an image is required unless --selftest")

    data = open(a.image, "rb").read()
    containers = scan(data)
    if a.extract is not None:
        if not 0 <= a.extract < len(containers):
            sys.exit("container %d out of range (%d found)" % (a.extract, len(containers)))
        c = containers[a.extract]
        if not c["valid"]:
            sys.exit("container at 0x%x is not valid: %s"
                     % (c["magic_offset"], c.get("error")))
        out, used, err = decode_container(data, c)
        if err:
            sys.exit("desync after %d bytes: %s" % (len(out), err))
        if len(out) != c["uncompressed_size"]:
            sys.exit("short decode: %d of %d" % (len(out), c["uncompressed_size"]))
        dest = a.out or ("bcl1-%d.bin" % a.extract)
        open(dest, "wb").write(out)
        print("wrote %s (%d bytes, %d compressed, escape 0x%02x)"
              % (dest, len(out), used, c["escape"]))
        return 0

    for n, c in enumerate(containers):
        print("#%d @0x%x esc=0x%02x uncomp=0x%x comp=0x%x valid=%s%s"
              % (n, c["magic_offset"], c.get("escape", 0), c.get("uncompressed_size", 0),
                 c.get("compressed_size", 0), c.get("valid"),
                 "" if c["valid"] else "  (%s)" % c.get("error")))
    if a.json:
        print(json.dumps(containers, indent=2))
    return 0 if containers else 1


if __name__ == "__main__":
    sys.exit(main())
