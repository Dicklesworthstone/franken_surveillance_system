#!/usr/bin/env python3
"""sstarXZ container walker — the C460/C660 SigmaStar ramdisk reader (fss-zgalk, wave-2).

The vendor wraps ramdisk/RTOS/kernel images in an `sstarXZ` container that is a
**descriptor, not an inline stream** (docs/exploit/tapo-c660-gadgets.md §5). Measured layout
in the decoded C460 image (`~/fss-exploit/c460_fw.bin.dec`):

    <p-64>   uImage header (magic 0x27051956), 64 bytes, name = container id
    <p>      'sstarXZ' + block-count byte + skipped byte (0x20)
    <p+9>    VLQ stream: block_count × (compressed_size, uncompressed_size) pairs, 0x00 term
    <align16> block_count × 20-byte XZ block headers (CRC32 of the first 16 bytes must
             equal the trailing u32) + 12-byte inline LZMA2 chunk per header
    ...      bulk LZMA2 continuation data

Each container is a complete uImage: `MVX4##…` (kernel), `sigmastar-rtos-sz`, `ramdisk`.
The three containers in the C460 image all parse with 4/4 CRC-valid block headers.

The preamble pointer table (16-byte fixed header + u64 entries with a -1 sentinel) belongs
to the *kernel* container's directory and its entries reference data in a rearranged layout;
the walker reports it but does not resolve it — see `--pointers`.

  python3 sstar_xz.py <image.dec> --scan            # locate + parse every container
  python3 sstar_xz.py <image.dec> --pointers        # dump the kernel-container pointer table
  python3 sstar_xz.py <image.dec> --decode N        # decode block N of the first container
  python3 sstar_xz.py <image.dec> --bulk-scan N     # search for block N's real bulk offset
  python3 sstar_xz.py <image.dec> --json            # machine-readable

Decoding: each block header is followed by a 12-byte LZMA2 chunk preamble whose
first six bytes are a real chunk header and whose next six are the first data
bytes (they decode to the uImage magic `27 05 31 4b`). The rest of the block's
data is *not* at `bulk_offset` — the byte there is never a valid chunk control
(props `0x3e`/`0x81`/`0xac`, all `lc+lp > 4`). `--bulk-scan` reports the best
offset found so the gap stays visible instead of being papered over.
"""
import argparse
import json
import lzma
import struct
import subprocess
import sys
import zlib

MAGIC = b"sstarXZ"
UIMAGE_MAGIC = 0x27051956


def read_vlq(buf: bytes, i: int) -> tuple[int, int]:
    v = shift = 0
    while True:
        b = buf[i]
        i += 1
        v |= (b & 0x7F) << shift
        shift += 7
        if not b & 0x80:
            return v, i


def parse_container(data: bytes, p: int) -> dict:
    """Parse one sstarXZ container whose magic sits at offset p."""
    out = {"magic_offset": p, "valid": False}
    if data[p:p + 7] != MAGIC:
        out["error"] = "no sstarXZ magic"
        return out
    count = data[p + 7]
    skipped = data[p + 8]
    out["block_count"] = count
    out["skipped_byte"] = skipped
    # VLQ (compressed, uncompressed) pairs
    i = p + 9
    vlqs = []
    while True:
        v, i = read_vlq(data, i)
        if v == 0:
            break
        vlqs.append(v)
    out["vlq_end"] = i
    if len(vlqs) % 2 or len(vlqs) // 2 != count:
        out["error"] = "VLQ stream does not form %d pairs (got %d values)" % (
            count, len(vlqs))
        return out
    pairs = [(vlqs[2 * k], vlqs[2 * k + 1]) for k in range(count)]
    out["blocks"] = [{"compressed": c, "uncompressed": u} for c, u in pairs]
    out["total_compressed"] = sum(c for c, _ in pairs)
    out["total_uncompressed"] = sum(u for _, u in pairs)
    # 16-byte aligned block headers
    hdr_base = (i + 15) & ~15
    out["header_base"] = hdr_base
    headers, crc_ok, bulk = [], 0, hdr_base + count * 32
    for b in range(count):
        h = hdr_base + b * 32
        hdr = data[h:h + 20]
        want = struct.unpack("<I", data[h + 16:h + 20])[0]
        ok = len(hdr) == 20 and zlib.crc32(hdr[:16]) == want
        crc_ok += ok
        # XZ block header: first byte = header size /4 (0x04 -> 20 bytes incl. CRC)
        hsize = hdr[0] * 4 if hdr else 0
        headers.append({
            "offset": h,
            "header_size": hsize,
            "crc32_ok": ok,
            "filter_props": hdr[2] if hsize >= 3 else None,  # LZMA2 dict/props byte
        })
    out["headers"] = headers
    out["bulk_offset"] = bulk
    out["crc_valid"] = crc_ok == count
    out["valid"] = out["crc_valid"]
    return out


def uimage_at(data: bytes, payload_off: int) -> dict | None:
    """If a uImage header ends exactly at payload_off (i.e. starts at -64), parse it."""
    s = payload_off - 64
    if s < 0:
        return None
    t = data[s:s + 64]
    if len(t) < 64 or struct.unpack(">I", t[:4])[0] != UIMAGE_MAGIC:
        return None
    _, hcrc, _ts, size, load, ep, dcrc = struct.unpack(">IIIIIII", t[:28])
    return {
        "header_offset": s,
        "size": size,
        "load": load,
        "ep": ep,
        "os": t[28],
        "arch": t[29],
        "type": t[30],
        "compression": t[31],
        "name": t[32:64].rstrip(b"\x00").decode("ascii", "replace"),
    }


PREAMBLE_SIG = bytes.fromhex("1600000003001100c0020100")


def pointer_table(data: bytes) -> dict | None:
    """Locate + parse the kernel-container preamble pointer table.

    Signature: `16 00 00 00 03 00 11 00 c0 02 01 00 04 00 00 00` then u64 entries until a
    `19` byte followed by an ELF-magic blob (measured at 0x700210 in c460_fw.bin.dec).
    Entry 0 is a small count/offset (0x109c); the rest are absolute offsets backward into
    the image, with one -1 sentinel. Returns None if the signature is absent.
    """
    p = data.find(PREAMBLE_SIG)
    if p < 0:
        return None
    entries_off = p + 16
    entries, i = [], entries_off
    while i + 8 <= len(data):
        # terminator: 0x19 byte then ELF magic (the table's entry-count + blob marker)
        if data[i] == 0x19 and data[i + 1:i + 5] == b"\x7fELF":
            break
        v = struct.unpack("<Q", data[i:i + 8])[0]
        entries.append(v)
        i += 8
    out = {"table_offset": p, "entries_offset": entries_off, "raw": entries}
    out["sentinel_count"] = sum(1 for v in entries if v == 0xFFFFFFFFFFFFFFFF)
    out["pointers"] = [v for v in entries if v != 0xFFFFFFFFFFFFFFFF]
    out["all_in_bounds"] = all(0 < v < len(data) for v in out["pointers"])
    out["all_backward"] = all(v < p for v in out["pointers"])
    out["terminator_offset"] = i          # 0x19 byte
    out["terminator_byte"] = data[i]
    out["elf_blob_offset"] = i + 1
    return out


def block_stream(data: bytes, c: dict, block: int, bulk: int | None = None) -> bytes:
    """The LZMA2 stream for one block: the 12-byte chunk preamble + the bulk tail.

    The preamble is `header_offset + 20`; its first six bytes are the chunk header
    and the next six are the chunk's first data bytes. `bulk` overrides the
    container's `bulk_offset` so `--bulk-scan` can try candidates.
    """
    h = c["headers"][block]["offset"] + 20
    pre = data[h:h + 12]
    start = c["bulk_offset"] if bulk is None else bulk
    size = c["blocks"][block]["compressed"] - 6
    return pre + data[start:start + size]


def decode_block(data: bytes, c: dict, block: int, bulk: int | None = None,
                 dict_size: int = 6144) -> dict:
    """Decode one block with liblzma. Returns the bytes produced before any error."""
    stream = block_stream(data, c, block, bulk)
    # `xz` writes everything it produced before the corrupt byte; liblzma's
    # Python binding discards the whole call's output when it raises.
    r = subprocess.run(["xz", "--format=raw", "--lzma2=dict=%d" % dict_size, "-dc"],
                       input=stream, capture_output=True)
    out = r.stdout
    return {
        "block": block,
        "bulk_offset": c["bulk_offset"] if bulk is None else bulk,
        "declared_compressed": c["blocks"][block]["compressed"],
        "declared_uncompressed": c["blocks"][block]["uncompressed"],
        "decoded": len(out),
        "complete": len(out) == c["blocks"][block]["uncompressed"],
        "head": out[:16].hex(),
        "bytes": out,
    }


def bulk_scan(data: bytes, c: dict, block: int, span: int = 0x10000,
              step: int = 1) -> list[tuple[int, int]]:
    """Offsets near `bulk_offset` ranked by how much they decode, best first."""
    scored = []
    start = c["bulk_offset"]
    for off in range(start, min(start + span, len(data) - 16), step):
        scored.append((decode_block(data, c, block, bulk=off)["decoded"], off))
    scored.sort(key=lambda t: (-t[0], t[1]))
    return scored


def scan(data: bytes) -> list[dict]:
    found = []
    start = 0
    while True:
        p = data.find(MAGIC, start)
        if p < 0:
            break
        start = p + 1
        c = parse_container(data, p)
        c["uimage"] = uimage_at(data, p)
        found.append(c)
    return found


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("image")
    ap.add_argument("--scan", action="store_true")
    ap.add_argument("--pointers", action="store_true",
                    help="dump the backward-pointer table of the first container's "
                         "preamble region")
    ap.add_argument("--decode", type=int, metavar="BLOCK",
                    help="decode block N of the first container and report the result")
    ap.add_argument("--bulk-scan", type=int, metavar="BLOCK",
                    help="rank bulk offsets for block N by decoded length")
    ap.add_argument("--span", type=lambda v: int(v, 0), default=0x10000,
                    help="bytes to search in --bulk-scan (default 0x10000)")
    ap.add_argument("--json", action="store_true")
    a = ap.parse_args()
    data = open(a.image, "rb").read()
    containers = scan(data)
    if a.pointers:
        pt = pointer_table(data)
        if pt:
            containers[0]["pointer_table"] = pt
        else:
            containers[0]["pointer_table"] = None
    if a.decode is not None or a.bulk_scan is not None:
        if not containers:
            sys.exit("no sstarXZ container in %s" % a.image)
        c = containers[0]
        if not c.get("valid"):
            sys.exit("container at 0x%x is not valid: %s"
                     % (c["magic_offset"], c.get("error")))
        block = a.decode if a.decode is not None else a.bulk_scan
        if not 0 <= block < c["block_count"]:
            sys.exit("block %d out of range (container has %d)"
                     % (block, c["block_count"]))
        if a.bulk_scan is not None:
            ranked = bulk_scan(data, c, block, span=a.span)
            for n, off in ranked[:10]:
                print("0x%x -> %d bytes" % (off, n))
            return 0
        r = decode_block(data, c, block)
        if a.json:
            r = dict(r)
            r.pop("bytes")
            print(json.dumps(r, indent=2))
        else:
            print("block %d: decoded %d of %d declared bytes (compressed %d), "
                  "bulk@0x%x, head=%s%s"
                  % (block, r["decoded"], r["declared_uncompressed"],
                     r["declared_compressed"], r["bulk_offset"], r["head"],
                     "" if r["complete"] else "  INCOMPLETE"))
        return 0 if r["complete"] else 1
    if a.json:
        print(json.dumps({"image": a.image, "containers": containers}, indent=2,
                         default=str))
        return 0 if all(c.get("valid") for c in containers) else 1
    for c in containers:
        u = c.get("uimage") or {}
        print("sstarXZ @0x%x  name=%-20s blocks=%d  crc %d/%d valid  "
              "comp=0x%x uncomp=0x%x  bulk@0x%x"
              % (c["magic_offset"], u.get("name", "?"), c.get("block_count", 0),
                 sum(1 for h in c.get("headers", []) if h["crc32_ok"]),
                 len(c.get("headers", [])),
                 c.get("total_compressed", 0), c.get("total_uncompressed", 0),
                 c.get("bulk_offset", 0)))
        for b, h in enumerate(c.get("headers", [])):
            print("    block %d @0x%x hdr_size=%d crc32_ok=%s" %
                  (b, h["offset"], h["header_size"], h["crc32_ok"]))
    if a.pointers:
        pt = containers[0].get("pointer_table")
        if not pt:
            print("no pointer-table preamble found")
        else:
            print("pointer table @0x%x: %d entries (%d pointers, %d sentinel), "
                  "in_bounds=%s backward=%s"
                  % (pt["table_offset"], len(pt["raw"]), len(pt["pointers"]),
                     pt["sentinel_count"], pt["all_in_bounds"], pt["all_backward"]))
            for v in pt["pointers"]:
                print("    -> 0x%x" % v)
            print("    terminator: 0x%02x + ELF blob @0x%x"
                  % (pt["terminator_byte"], pt["terminator_offset"]))
    return 0


if __name__ == "__main__":
    sys.exit(main())
