# sstarXZ desync research harness (2026-11-04)

Working ground truth: kernel uImage @0x30200 payload is a STANDARD xz stream
(`lzma.LZMADecompressor().decompress(blob[0x30240:...])` = 488624-byte ARM zImage).
`tools/tapo_lzma2.py` decodes liblzma-produced LZMA2/LZMA1 bit-exactly (verified).

The sstarXZ block streams decode WITHOUT range-coder invariant violations but to wrong
content. Decision-sequence alignment against c460_113 kernel block0 (chunk1 @0x70284+6,
usize 86257, csize 61439, props 0x5d):

- `cmp5.py` proves the divergence is structural: decoding pos2 WITHOUT an is_match decision
  yields 0x19 (matches uImage-magic hypothesis) where the standard loop yields 0x31.
- `combo.py`/`combo2.py` enumerate per-position is_match masks; best scores ~50% byte match
  (27051958...) — a pure per-position mask does NOT explain the stream.
- `idx_test.py`: is_match index variants (std/prevpos/nopos) — all fail deeper.
- Conclusion: the SXZ hardware decoder's decision sequence differs from xz software LZMA2
  in a position-dependent way (likely tied to the vendor block header's filter spec or a
  custom literal/match state machine). Next: differential-trace the SXZ decode against a
  synthetic stream whose plaintext we control end-to-end (encode with the vendor's own
  tools if findable, else align bit-by-bit using the CRC-verified container boundaries).

## Additions (same session, later)

- The image at 0x30200 is U-Boot 2021.10 (not the Linux kernel) — corrected in tapo.md C4.
- lc=0 variants (`lc0_test.py` logic): all give `27 04 …` — the 0x04 echoes the vendor block
  header's first byte; coincidence of fresh-probability decoding, not the rule.
- The SXZ hardware decode likely needs register-level tracing (hal_xzdec.c documents the
  interface; CTRL0=0x0003 for SXZ vs 0x0007 for XZ — the SXZ engine may implement a
  simplified/custom LZMA2). A UART/JTAG trace of one live decode would settle it.

## C660 /bin/main RE note (2026-11-04)

`/tmp/c660_rootfs/bin/main` (ARM 32-bit, THUMB, stripped): the DS method strings
(scanApList/connectAp/getConnectStatus) sit in a packed string block at file 0x4069xx with
ZERO absolute references anywhere in the image (checked .text literal pools, .data.rel.ro,
.data, .got, .rel.dyn/.rel.plt addends, aligned+unaligned, file-offset and vaddr forms).
The DS dispatcher computes string pointers at runtime (master-table + offset pattern).
Finding connectAp's handler → the stack-buffer offset needs this dispatch RE first;
the borrowed offset 1060 remains unverified for C460 (different SoC, same framework).

## Three-container consistency check (2026-11-05, 01:45)

Decoded block0 chunk1 of THREE independent containers with the same decoder+params:
- ramdisk (c460_fw @0x420284): 27 05 31 4b 00 00 00 …
- kernel (c460_113 @0x70284):  27 05 31 4b 00 00 00 …
- rtos (c460_fw @0x2a0284):    27 05 31 4b ef 91 …

All three decode WITHOUT rc violations, all produce the same first 4 bytes, and all
produce ~95% zeros with periodic high-entropy bursts (entropy 0.64; no ASCII strings,
no cpio/squashfs/ext4 magics anywhere in 60KB each).

Two readings remain:
(a) the decode is CORRECT and 27 05 31 4b is a genuine SigmaStar inner-image header
    (the ramdisk would then be a vendor-format image, not cpio/squashfs);
(b) the decode is systematically misaligned in a way that is identical across containers
    (same encoder → same misalignment).

Discriminating test for next session: the rtos container's block0 usize=237392 and the
kernel's usize=742400 — if (a), the images' internal length fields should appear inside
the decoded output at fixed offsets; if (b), nothing will. Also worth trying: decode with
`is_match` probs indexed by (state<<2|pos_state) but the LITERAL prob group selected by
`prev >> (8-lc)` where prev is the PREVIOUS-DECODED SYMBOL rather than the previous byte
(identical for literals, different after matches — matches the "position-dependent" note
above only partially).

### Discriminating test RESULT (01:50)

No length-field oracle (block usizes, container totals, compressed sizes — LE or BE)
appears anywhere in the decoded 60KB outputs. This supports reading (b): the decode is
systematically misaligned identically across all three containers. The vendor encoder's
decision-sequence layout differs from xz software LZMA2 in a way that pure parameter
variation cannot express. Next session: hardware trace (UART on the C460 while it boots —
the camera decodes these containers every boot with the xzdec engine) or capture the
vendor's encoder (check the Tapo cloud firmware repository for their build tools).

## C660 DS dispatcher RE note #2 (2026-11-05, 02:10)

The DS method strings (scanApList/connectAp/getConnectStatus/setLanguage/…) sit in a
rodata blob interleaved with [DS]… error messages around file offset 0x4069xx. Exhaustive
searches found ZERO references to this region anywhere in the image:
- 4-byte words (aligned + 2-byte aligned, THUMB literal pools): none
- .got (0x474000, 0xca0): pointers into OTHER string areas (0x415xxx, 0x402xxx) but not this one
- .data.rel.ro (0x471660): same — other strings but not the DS names
- .rel.dyn/.rel.plt addends: none

Implication: the DS dispatcher computes string addresses at runtime (base pointer +
accumulated strlen, or a hash table keyed by a different string copy). The handler table
is NOT statically linked to these strings. To find connectAp's handler: locate the [DS]
log-format strings' xrefs (the dispatcher's error paths WILL reference "[DS]Unsupport
method"), then walk back to the dispatch loop. That code will contain the strcmp/hashing
against the name area and the handler call — from which the stack layout at connectAp can
be recovered and the C460 offset verified.

## Mask enumeration result (2026-11-05, 03:00)

Extended per-position is_match masks to 10 positions, scored against the full expected
uImage header (27 05 19 56 d0 fd 9d 78 67 6c d1 9e): all masks plateau at 3/12 bytes
(best: 27 05 19 58…). Pure-literal decoding with per-position is_match skips cannot
express the vendor stream — positions 4+ require MATCH symbols (the header's zero fields
are match-encoded), so the decision-sequence search space is not a simple mask.

The three-byte prefix 27 05 19 is ROBUST across masks 0bxx000011 (pos2/pos3 skip
is_match) — the strongest structural signal so far: the vendor encoder does NOT write
is_match decisions for consecutive literals at pos2/pos3. But the byte-3 divergence
(0x58 vs 0x56) shows a second, independent difference (prob adaptation or a skipped
decision at pos4+) that pure masks cannot capture.

VERDICT: the SXZ decode requires the vendor's encoder or a hardware decode trace.
Black-box reverse engineering has extracted all available signal.
