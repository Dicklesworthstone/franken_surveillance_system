#!/usr/bin/env python3
"""Pin the BCL1 container reader against the real C660 image (fss-zgalk).

The C660 has no sstarXZ: the U-Boot and the initramfs are BCL1 blocks, each with its own
escape byte in the header (`docs/exploit/tapo-c660-gadgets.md`). These tests pin the
facts the gadget work depends on, so a decoder regression cannot silently change the
`/bin/main` a chain is derived from:

  * container positions, sizes and per-block escape bytes;
  * the ramdisk decoding to a cpio that ends in TRAILER!!!;
  * `/bin/main` being an ET_EXEC ARM binary loaded at 0x10000 (no ASLR base to find);
  * the hardcoded-escape trap: 0xde against the 0xa7 block desyncs at 48 bytes.

Skips with a loud message when `~/fss-exploit/c660_fw.bin.dec` is not on disk.

  python3 tests/tapo_bcl1_test.py
"""
import importlib.util
import os
import struct
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
TOOL = os.path.join(HERE, "..", "tools", "tapo_oracle", "bcl1.py")
IMAGE = os.path.expanduser("~/fss-exploit/c660_fw.bin.dec")

failures = []


def check(name, cond, detail=""):
    print("%s %s%s" % ("ok " if cond else "FAIL", name,
                       " — %s" % detail if detail and not cond else ""))
    if not cond:
        failures.append(name)


def load_tool():
    spec = importlib.util.spec_from_file_location("bcl1", TOOL)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def cpio_entries(data):
    """Walk a newc archive; returns the entry names, stopping at TRAILER!!!."""
    names, i = [], 0
    while i < len(data):
        if data[i:i + 6] != b"070701":
            return names, i
        f = [int(data[i + 6 + 8 * k:i + 14 + 8 * k], 16) for k in range(13)]
        size, nsz = f[6], f[11]
        name = data[i + 110:i + 110 + nsz - 1].decode("utf-8", "replace")
        names.append(name)
        if name == "TRAILER!!!":
            return names, i
        i = (i + 110 + nsz + 3) & ~3
        i = (i + size + 3) & ~3
    return names, i


def extract_member(data, mod, index):
    out, _used, err = mod.decode_container(data, mod.scan(data)[index])
    assert err is None, err
    return out


def main():
    if not os.path.exists(IMAGE):
        print("SKIP: %s not on disk" % IMAGE)
        return 0
    mod = load_tool()
    data = open(IMAGE, "rb").read()

    print("container map")
    found = mod.scan(data)
    valid = [c for c in found if c["valid"]]
    check("three valid containers", len(valid) == 3, str(len(valid)))
    check("string literals are rejected, not parsed",
          len(found) > len(valid), "%d hits" % len(found))
    expect = [(0x16E50, 0xA6, 0x8F60), (0x60200, 0xA7, 0x4F120),
              (0x700200, 0xDE, 0x676800)]
    for (off, esc, size), c in zip(expect, valid):
        check("container 0x%x escape 0x%02x size 0x%x" % (off, esc, size),
              c["magic_offset"] == off and c["escape"] == esc
              and c["uncompressed_size"] == size,
              "%s" % {k: c[k] for k in ("magic_offset", "escape",
                                        "uncompressed_size")})

    print("hardcoded-escape trap")
    body = data[0x60200 + 17:]
    _out, _used, err = mod.decode(body, 0x4F120, 0xDE)
    check("0xde against the 0xa7 block desyncs", err is not None)
    out, _used, err = mod.decode(body, 0x4F120, 0xA7)
    check("0xa7 decodes the U-Boot block to its full size",
          err is None and len(out) == 0x4F120, str(len(out)))

    print("ramdisk")
    cpio = extract_member(data, mod, 5)
    check("ramdisk decodes to the declared size", len(cpio) == 0x676800,
          str(len(cpio)))
    names, broke_at = cpio_entries(cpio)
    check("archive walks to TRAILER!!!", names and names[-1] == "TRAILER!!!",
          "broke at 0x%x after %d" % (broke_at, len(names)))
    check("root entry is a directory", names and names[0] == ".")
    check("/bin/main present", "bin/main" in names)

    print("/bin/main")
    # carve the member: the walk above already validated every header
    i = 0
    blob = None
    while i < len(cpio):
        f = [int(cpio[i + 6 + 8 * k:i + 14 + 8 * k], 16) for k in range(13)]
        size, nsz = f[6], f[11]
        name = cpio[i + 110:i + 110 + nsz - 1].decode("utf-8", "replace")
        body_off = (i + 110 + nsz + 3) & ~3
        if name == "bin/main":
            blob = cpio[body_off:body_off + size]
            break
        i = (body_off + size + 3) & ~3
    check("bin/main carved", blob is not None and blob[:4] == b"\x7fELF")
    if blob:
        e = struct.unpack("<16sHHIIIIIHHHHHH", blob[:52])
        check("ET_EXEC (fixed load, no ASLR base to find)", e[1] == 2, str(e[1]))
        check("ARM", e[2] == 40, str(e[2]))
        phoff, phentsize, phnum = e[5], e[9], e[10]
        loads = [struct.unpack("<IIIIIIII", blob[phoff + k * phentsize:
                                                phoff + (k + 1) * phentsize])
                 for k in range(phnum)]
        loads = [p for p in loads if p[0] == 1]
        check("first PT_LOAD vaddr is 0x10000", loads and loads[0][2] == 0x10000,
              str([hex(p[2]) for p in loads]))
        check("entry point inside the first load", loads and
              loads[0][2] <= e[4] < loads[0][2] + loads[0][4],
              hex(e[4]))
        check("connectAp and device_confirm strings present",
              b"connectAp" in blob and b"device_confirm" in blob)
        check("section table ends exactly at EOF",
              e[6] + e[12] * e[11] == len(blob))

    if failures:
        print("\n%d failure(s): %s" % (len(failures), ", ".join(failures)))
        return 1
    print("\nall checks passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
