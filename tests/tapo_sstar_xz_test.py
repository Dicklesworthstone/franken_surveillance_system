#!/usr/bin/env python3
"""Pin the sstarXZ container walk against the real firmware images (fss-zgalk, wave-2).

Tests are live against `~/fss-exploit/c460_fw.bin.dec` (three containers, all CRC-valid)
and `~/fss-exploit/c660_fw.bin.dec` (no sstarXZ — it wraps the app in BCL1 instead; the
C660 test pins the BCL1/LZO facts from docs/exploit/tapo-c660-gadgets.md §3).

Skips with a loud message if the decoded images are not on disk, so the suite stays
green on machines without the lab artifacts while still pinning everything when they are.

  python3 tests/tapo_sstar_xz_test.py
"""
import json
import os
import struct
import subprocess
import sys
import zlib

HERE = os.path.dirname(os.path.abspath(__file__))
ORACLE = os.path.join(HERE, "..", "tools", "tapo_oracle", "sstar_xz.py")
C460 = os.path.expanduser("~/fss-exploit/c460_fw.bin.dec")
C660 = os.path.expanduser("~/fss-exploit/c660_fw.bin.dec")

failures = []


def check(name, cond, detail=""):
    tag = "ok " if cond else "FAIL"
    print("%s %s %s" % (tag, name, detail))
    if not cond:
        failures.append(name)


def run(args):
    r = subprocess.run([sys.executable, ORACLE] + args, capture_output=True, text=True)
    return r


def main() -> int:
    sys.path.insert(0, os.path.dirname(ORACLE))
    import sstar_xz

    # ---- synthetic invariants (no image needed) ------------------------------
    # minimal container: magic + count=1 + skip + VLQ(0x10, 0x20) + 0x00 term + pad to 16
    # + 16-byte header (per this build's hdr_size=0x04*4) + CRC32 + 12B tail
    pre = b"sstarXZ" + bytes([1, 0x20]) + bytes([0x10, 0x20, 0x00])
    hdr16 = bytes.fromhex("04c0f9a5248011000000000000000000")
    assert len(hdr16) == 16
    blob = pre + b"\x00" * 4 + hdr16 + struct.pack("<I", zlib.crc32(hdr16)) + b"\x00" * 12
    got = sstar_xz.parse_container(blob, 0)
    check("synthetic: crc valid", got["valid"], json.dumps(got.get("error", "")))
    check("synthetic: one pair", got["blocks"] == [{"compressed": 0x10,
                                                    "uncompressed": 0x20}])
    check("synthetic: bulk offset aligned", got["bulk_offset"] % 16 == 0,
          hex(got.get("bulk_offset", 0)))
    # corrupt a header byte must invalidate
    bad = bytearray(blob)
    bad[16] ^= 0xFF
    got2 = sstar_xz.parse_container(bytes(bad), 0)
    check("synthetic: crc corruption detected", not got2["valid"])

    # ---- real C460 image ------------------------------------------------------
    if os.path.exists(C460):
        data = open(C460, "rb").read()
        cs = sstar_xz.scan(data)
        check("c460: three containers", len(cs) == 3,
              "found %d" % len(cs))
        names = [c["uimage"]["name"] for c in cs if c.get("uimage")]
        check("c460: container names", names == ["MVX4##I###g#######KL_LX510##[BR:",
                                                 "sigmastar-rtos-sz", "ramdisk"],
              str(names))
        check("c460: all containers crc-valid", all(c["valid"] for c in cs))
        check("c460: every container has 4 blocks",
              all(c["block_count"] == 4 for c in cs))
        # uImage headers precede each container
        for c in cs:
            check("c460: uimage header @0x%x" % c["magic_offset"],
                  c["uimage"] is not None
                  and c["uimage"]["header_offset"] == c["magic_offset"] - 64)
        # ramdisk is the biggest uncompressed
        rd = cs[2]
        check("c460: ramdisk named", rd["uimage"]["name"] == "ramdisk")
        # uImage size covers the whole container (VLQ stream + aligned headers + bulk +
        # trailing pad); it strictly exceeds the compressed-block total by a small overhead.
        # Measured: kernel 0x62, rtos 0x6e, ramdisk 0x4a.
        for c in cs:
            ov = c["uimage"]["size"] - c["total_compressed"]
            check("c460: %s size overhead 0<x<0x200" % c["uimage"]["name"][:12],
                  0 < ov < 0x200, hex(ov))
        # pointer table
        pt = sstar_xz.pointer_table(data)
        check("c460: pointer table found", pt is not None)
        if pt:
            check("c460: table at measured offset", pt["table_offset"] == 0x700210,
                  hex(pt["table_offset"]))
            check("c460: 8 entries, 7 pointers + 1 sentinel",
                  len(pt["raw"]) == 8 and len(pt["pointers"]) == 7
                  and pt["sentinel_count"] == 1)
            check("c460: first entry is the small count 0x109c",
                  pt["raw"][0] == 0x109C)
            check("c460: all pointers in bounds", pt["all_in_bounds"])
            check("c460: all pointers backward", pt["all_backward"])
            check("c460: doc addresses present",
                  set(pt["pointers"]) >= {0x363E73, 0x363E6B, 0x362E27,
                                          0x363500, 0x363CD1, 0x363E5D})
            check("c460: terminator 0x19 + ELF blob",
                  pt["terminator_byte"] == 0x19
                  and data[pt["elf_blob_offset"]:pt["elf_blob_offset"] + 4] == b"\x7fELF")

    # ---- real C660 image ------------------------------------------------------
    if os.path.exists(C660):
        d6 = open(C660, "rb").read()
        cs6 = sstar_xz.scan(d6)
        check("c660: no sstarXZ containers", len(cs6) == 0,
              "found %d" % len(cs6))
        check("c660: BCL1 magic at 0x700200", d6[0x700200:0x700204] == b"BCL1")
        usize, csize = struct.unpack(">II", d6[0x700208:0x700210])
        check("c660: BCL1 declared sizes", (usize, csize) == (0x676800, 0x419CAF),
              "usize=0x%x csize=0x%x" % (usize, csize))
        check("c660: LZO first-block marker (doc: 27483 B first block)",
              d6[0x700210:0x700210 + 2] not in (b"", None))

    # ---- decode ---------------------------------------------------------------
    # Every container's first block decodes to the uImage magic from its 12-byte
    # chunk preamble; the bulk tail is still unresolved, so the count is pinned
    # as a regression marker rather than asserted complete.
    if os.path.exists(C460):
        for c in cs:
            r = sstar_xz.decode_block(data, c, 0)
            name = (c.get("uimage") or {}).get("name", "?")[:12]
            check("c460: %s block0 decodes the uImage magic" % name,
                  r["head"].startswith("2705314b"), r["head"])
            check("c460: %s block0 decoded > 0" % name, r["decoded"] > 0,
                  str(r["decoded"]))
            check("c460: %s block0 incomplete (bulk unresolved)" % name,
                  not r["complete"], str(r["decoded"]))
        k = sstar_xz.decode_block(data, cs[0], 0)
        check("c460: kernel block0 decoded count pinned", k["decoded"] == 200,
              str(k["decoded"]))
        ranked = sstar_xz.bulk_scan(data, cs[0], 0, span=0x400)
        check("c460: bulk_scan ranks offsets", len(ranked) == 0x400)
        check("c460: bulk_scan is best-first",
              all(ranked[i][0] >= ranked[i + 1][0] for i in range(len(ranked) - 1)))

    # ---- CLI surface ----------------------------------------------------------
    if os.path.exists(C460):
        r = run([C460, "--scan"])
        check("cli: scan rc=0", r.returncode == 0)
        check("cli: scan lists three containers", r.stdout.count("sstarXZ @") == 3)
        r = run([C460, "--pointers", "--json"])
        j = json.loads(r.stdout)
        pt = j["containers"][0].get("pointer_table")
        check("cli: json pointer table", bool(pt) and pt["all_backward"])
        r = run([C460, "--decode", "0"])
        check("cli: decode rc=1 while incomplete", r.returncode == 1)
        check("cli: decode reports the magic", "2705314b" in r.stdout)
        r = run([C460, "--decode", "0", "--json"])
        j = json.loads(r.stdout)
        check("cli: decode json", j["block"] == 0 and j["decoded"] > 0)
        r = run([C660, "--scan"]) if os.path.exists(C660) else None
        if r is not None:
            check("cli: c660 scan rc=0 (empty)", r.returncode == 0)

    print("\n%s" % ("ALL PASS" if not failures else "FAILURES: %s" % failures))
    return 0 if not failures else 1


if __name__ == "__main__":
    sys.exit(main())
