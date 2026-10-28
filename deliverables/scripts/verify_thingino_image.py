#!/usr/bin/env python3
"""Structural checker for the pinned Wyze Cam v4 (T41NQ) Thingino chip images.

Verifies, from bytes alone, every claim docs/exploit/flash-plan.md §"Verified byte
layout" and docs/exploit/cve-watch-2026-10.md §Plan A §1 make about the image:
size, chip header, INGE init table (CVE-2026-50719 secure-boot-flag clear), the
shipped 2-word terminator shape, SPL/uImage/kernel/rootfs/env landmarks.

  verify_thingino_image.py <image.bin> [<image2.bin> ...]

Exit 0 = every assertion held for every image. Any failure exits 1 and names the
image, offset, and expected/actual bytes. No device I/O, no writes, read-only.
"""
from __future__ import annotations

import struct
import sys
import zlib
from pathlib import Path

SIZE = 16 * 1024 * 1024  # 16777216: full 16 MiB NOR chip image
CHIP_HEADER = bytes.fromhex("06050403025 5aa55aa".replace(" ", ""))  # 06 05 04 03 02 55 aa 55 aa
VARIANT_BYTE = 0x9  # per-variant board/sensor id in the chip header
VARIANTS = {0x40: "gc4653", 0x52: "os04d10"}
INGE_MAGIC = b"INGE"
INGE_TABLE = 0x100
INGE_TABLE_END = 0x120  # magic + zero pad to 0x120
ENTRY0 = 0x120
# entry 0 = write 0x00000000 -> SRAM 0x80000090, poll 0xFFFFFFFF, mask 0, clear 0
# (the CVE-2026-50719 T41/T41NQ secure-boot-flag clear; byte-identical both variants)
ENTRY0_WORDS = (0x80000090, 0xFFFFFFFF, 0x00000000, 0x00000000, 0x00000000)
# terminator at 0x134: addr 0xFFFFFFFF, poll 0xFFFFFFFF, zeros to 0x140 — the SHIPPED
# 2-word shape, NOT the advisory PoC's five 0xFFFFFFFF words. A hand-built image must
# copy this shape (cve-watch-2026-10.md §Plan A §1, "Correction to the advisory PoC").
TERMINATOR_ADDR = 0x134
TERMINATOR_WORDS = (0xFFFFFFFF, 0xFFFFFFFF, 0x00000000, 0x00000000)
TABLE_END = 0x140
SPL_BANNER_OFF = 0xC0B8  # "SPL: ..." string table landmark
UBOOT_OFF = 0x14000  # uImage header of U-Boot 2026.10-rc4 for isvp-t41
UBOOT_MAGIC = 0x27051956
KERNEL_OFF = 0x70000  # kernel uImage, Linux-4.4.94
ROOTFS_OFF = 0x200000  # squashfs (`hsqs`, -all-root packed)
SQUASHFS_MAGIC = b"hsqs"
ENV_OFF = 0x50000
ENV_SIZE = 0x10000
BACKUP_ENV_OFF = 0x60000  # 0xFF in the pinned base and in the assembled image
BASE_MTDPARTS = (
    "mtdparts=sfc0_nor:320k(boot),64k(env),64k(backup),1600k(kernel),"
    "5760k(rootfs),8576k(data),16384k@0(all)"
)


class Fail(Exception):
    pass


def check(cond: bool, what: str) -> None:
    if not cond:
        raise Fail(what)


def verify(path: Path) -> list[str]:
    d = path.read_bytes()
    notes: list[str] = []
    check(len(d) == SIZE, f"size {len(d)} != {SIZE}")

    # chip header + per-variant byte at 0x9
    check(d[: len(CHIP_HEADER)] == CHIP_HEADER,
          f"chip header {d[:len(CHIP_HEADER)].hex(' ')} != {CHIP_HEADER.hex(' ')}")
    vb = d[VARIANT_BYTE]
    check(vb in VARIANTS, f"chip-header byte @{VARIANT_BYTE:#x} = {vb:#04x}, not a known variant")
    variant = VARIANTS[vb]
    notes.append(f"variant={variant} (chip-header byte @{VARIANT_BYTE:#x}={vb:#04x})")

    # INGE init table
    check(d[INGE_TABLE:INGE_TABLE + 4] == INGE_MAGIC, f"no INGE magic @{INGE_TABLE:#x}")
    check(d[INGE_TABLE + 4:INGE_TABLE_END] == bytes(INGE_TABLE_END - INGE_TABLE - 4),
          f"INGE magic pad @{INGE_TABLE+4:#x}..{INGE_TABLE_END:#x} not zero")
    got0 = struct.unpack_from("<5I", d, ENTRY0)
    check(got0 == ENTRY0_WORDS,
          f"init entry 0 @{ENTRY0:#x} = {[hex(w) for w in got0]} != "
          f"{[hex(w) for w in ENTRY0_WORDS]} (secure-boot-flag clear: write 0 -> 0x80000090)")
    notes.append("entry0: write 0x00000000 -> SRAM 0x80000090 (CVE-2026-50719 clear) OK")

    # shipped 2-word terminator, zeros to table end
    gotT = struct.unpack_from("<4I", d, TERMINATOR_ADDR)
    check(gotT == TERMINATOR_WORDS,
          f"terminator @{TERMINATOR_ADDR:#x} = {[hex(w) for w in gotT]} != "
          f"{[hex(w) for w in TERMINATOR_WORDS]} (shipped 2-word shape, not PoC's 5-word)")
    check(d[TABLE_END:0x150] == bytes(0x150 - TABLE_END),
          f"bytes @{TABLE_END:#x}..0x150 after terminator not zero")
    notes.append("terminator: 2-word (0xFFFFFFFF, 0xFFFFFFFF) + zeros to 0x140 OK")

    # SPL / U-Boot / kernel / rootfs landmarks
    check(d[SPL_BANNER_OFF:SPL_BANNER_OFF + 5] == b"SPL: ",
          f"no SPL banner @{SPL_BANNER_OFF:#x}: {d[SPL_BANNER_OFF:SPL_BANNER_OFF+16]!r}")
    u_hdr = struct.unpack_from(">8I", d, UBOOT_OFF)
    check(u_hdr[0] == UBOOT_MAGIC, f"U-Boot uImage magic @{UBOOT_OFF:#x} = {u_hdr[0]:#010x}")
    k_hdr = struct.unpack_from(">8I", d, KERNEL_OFF)
    check(k_hdr[0] == UBOOT_MAGIC, f"kernel uImage magic @{KERNEL_OFF:#x} = {k_hdr[0]:#010x}")
    check(d[ROOTFS_OFF:ROOTFS_OFF + 4] == SQUASHFS_MAGIC,
          f"no squashfs `hsqs` @{ROOTFS_OFF:#x}: {d[ROOTFS_OFF:ROOTFS_OFF+8].hex(' ')}")

    # env: U-Boot framing crc32(data) LE over the 64 KiB field, then mtdparts
    env = d[ENV_OFF:ENV_OFF + ENV_SIZE]
    stored, calc = struct.unpack_from("<I", env, 0)[0], zlib.crc32(env[4:]) & 0xFFFFFFFF
    check(stored == calc, f"env crc stored={stored:#010x} calc={calc:#010x}")
    entries = [e.decode("utf-8", "replace") for e in env[4:].split(b"\x00") if e]
    mtdparts = next((e for e in entries if e.startswith("mtdparts=")), None)
    check(mtdparts == BASE_MTDPARTS,
          f"mtdparts {mtdparts!r} != base {BASE_MTDPARTS!r} (pre-§3-rewrite pinned state)")
    notes.append(f"env: crc OK, {len(entries)} entries, base mtdparts (5760k rootfs)")

    # backup env partition is erased
    check(d[BACKUP_ENV_OFF:BACKUP_ENV_OFF + ENV_SIZE] == b"\xff" * ENV_SIZE,
          f"backup env @{BACKUP_ENV_OFF:#x} not all-0xFF")

    notes.append(f"sha256 pinned separately; image structurally valid")
    return notes


def main() -> int:
    paths = [Path(p) for p in sys.argv[1:]]
    if not paths:
        print(__doc__)
        return 2
    failures = 0
    for p in paths:
        print(f"== {p}")
        try:
            for line in verify(p):
                print(f"   OK  {line}")
        except (Fail, OSError) as e:
            print(f"  FAIL {e}")
            failures += 1
    print(f"verdict: {'PASS' if failures == 0 else 'FAIL'} ({len(paths) - failures}/{len(paths)} images)")
    return 0 if failures == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
