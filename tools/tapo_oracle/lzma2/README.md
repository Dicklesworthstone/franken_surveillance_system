# sstarXZ LZMA2 lab

Scratch harness + the patched SDK sources used to decode the Tapo block containers. Kept in-tree
because every "how" was hard-won and lived only in `/tmp` for a night.

## What is proven

- Block layout: `sstarXZ` magic, byte count, VLQ (compressed, uncompressed) pairs, then 32-byte
  slots of *16-byte XZ block header + that chunk's preamble*; bodies follow contiguously at
  `hdr_base + count*32`. Header CRCs are valid.
- Chunk control: the low five bits are the **high bits of the output size** (SDK rule), the two
  16-bit fields are sizes, `props` follows when bit 6 is set, and the next byte is a `0x00` marker.
- Distances may point **into the unwritten dictionary**; standard decoders reject that, the vendor
  decoder does not.
- Literal contexts are irrelevant here: three different lc/pb values give identical output, because
  the stream is almost all matches.
- `lzma2_roundtrip.sh` keeps the patched decoder honest against standard streams.

## What is open

The content decodes to ~94 % zeros with no `cpio`/ELF/squashfs marker, i.e. matches resolve into
zeros. Standard round-trip passes, so the fault is specific to how these distances code — not
framing, props or dictionary continuity (all three ruled out).

## Build / use

    cc -O1 -I<lzma-sdk>/C -o l2d3 l2d3.c Lzma2Dec.c LzmaDecU.c
    ./l2d3 <image> <block-off> <dict-prop> [props] [max-out] [unpack-size]

`LzmaDecU.c` and `Lzma2Dec.c` are the 19.00 SDK files with the vendor rules applied; every patch is
commented in place.

## Current best (vendor) build

`LzmaDec_rev.c` (reversed distance-slot tree, 5-bit table) + `Lzma2Dec_rev2.c` (no straddle extension,
two-byte chunk trailer). Result: 1,564,644 bytes, zeros 6.9 %, 2,844 ASCII runs. `LzmaDec_5bit.c` is
the same table without the reversal (86 % zeros) and is the control.

`Lzma2Dec_best.c` = no straddle extension + two-byte trailer skip; with a large cap it reads 1,564,644
bytes at 4.1 % zeros and stops on an undrained straddling match (`remain=41`). Adding the extension
re-breaks the boundary, and extension plus a scan resync does not compose either — the drain needs
more output than the caller offers, which is the open problem.

## Rebuilding (the SDK headers are not in-tree)

`l2d3.c` includes `lz19/C/Lzma2Dec.h`, so the toolchain headers must sit where that path resolves. The
pristine headers were pruned from `/tmp/lz19`, but a copy lives in `/tmp/lz19dbg`; rebuild with:

```
mkdir -p /tmp/inc && ln -sfn /tmp/lz19dbg /tmp/inc/lz19
cc -O1 -I/tmp/inc -o /tmp/l2d l2d3.c Lzma2Dec_<variant>.c LzmaDec_<variant>.c
```

Stock build for the round-trip guard (no vendor patches; needs the `g_unpack` the harness references):

```
printf 'unsigned long g_unpack;\n' > /tmp/g.c
cc -O1 -I/tmp/inc -I/tmp/lz19dbg -include /tmp/lz19dbg/Precomp.h \
   -o /tmp/l2d_stock l2d3.c /tmp/g.c /tmp/lz19dbg/Lzma2Dec.c /tmp/lz19/C/LzmaDec.c
bash ../lzma2_roundtrip.sh /tmp/l2d_stock 50000
```

`Lzma2Dec_stock_fixed.c` is the build the guard runs against: standard field order (uncompressed first)
and the uncompressed copy capped by the declared chunk size. `bash ../lzma2_roundtrip.sh <stock build>`
must print ROUNDTRIP OK; it did not before those two fixes.
