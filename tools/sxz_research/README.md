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
