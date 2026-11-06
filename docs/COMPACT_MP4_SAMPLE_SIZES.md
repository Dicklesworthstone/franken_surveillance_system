# Compact MP4 sample-size tables

The native AVC/HEVC MP4 reader accepts `stz2` compact sample-size tables as an alternative
to `stsz`. Indexed recordings, an indexed prefix followed by fragments, and empty sample
tables initializing fragmented recordings share the same bounded sample-index pipeline.
The existing `mp4avc` and `mp4hevc` import paths use this reader without another format,
dependency, decoder, or custody representation.

The admitted encoding follows ISO/IEC 14496-12:2012, clauses 8.7.3.1 and 8.7.3.3
([standard reference](https://www.iso.org/standard/61988.html)):

- Exactly one of `stsz` or `stz2` must describe the selected track. Duplicate or competing
  tables refuse the complete parse.
- `stz2` version, flags, and reserved bits must be zero. Its field width is 4, 8, or 16 bits.
  Four-bit entries put the first sample in the high nibble; an odd final low nibble is zero
  padding. Sixteen-bit entries use big-endian byte order.
- The declared count determines the exact packed payload length. Extra bytes, missing
  entries, unsupported widths, and nonzero padding refuse.

The selected AVC/HEVC profile continues to require nonempty sample payloads. Empty tables
are useful only when fragments supply selected video samples. Every decoded size is charged
to the same sample and table-entry allowances as `stsz`, with count and length checks before
allocation and cancellation checkpoints during bounded table expansion.

This changes container admission only. Source sample byte ranges, decoding and composition
ticks, sync assertions, and extracted NAL bytes retain their existing meaning. Encryption,
external references, decoder limits, and other unsupported media layouts keep their existing
refusals.

Focused tests in `crates/fss-container/src/demux/tests/compact.rs` cover all three widths;
odd/even counts; one-, two-, and four-byte NAL lengths; `stco` and `co64`; width ceilings;
identical source/timing/Annex-B results; ordinary AVC/HEVC and mixed-file fixtures; fragment
initialization; malformed headers, counts, zero sizes, padding, duplicates, and truncation;
combined quotas; and cancellation at every parser checkpoint. The fixture transformations
only rewrite sample-size metadata and container lengths, preserving the media bytes.

```sh
cargo test -p fss-container compact
cargo test -p fss-container
```
