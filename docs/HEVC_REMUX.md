# HEVC configuration metadata and remux boundary

`fss_packet::hevc::HevcConfiguration::parse` screens an immutable original
VPS/SPS/PPS tuple for the bounded metadata needed by a container writer. It
reads VPS profile/tier/level and temporal declarations, SPS referenced IDs,
chroma format, coded dimensions, conformance crop and bit depths, and PPS IDs.
The exact original NAL bytes remain available. General VPS/SPS profile metadata
and temporal declarations must match; no merged or guessed profile is invented.

This first subset supports single-layer Main/Main10, 4:2:0, equal 8/10-bit
component depths, and up to seven temporal sublayers. It rejects mismatched
references, unsupported profiles/layouts, invalid reserved fields, malformed
emulation prevention, invalid crops, and byte/dimension/pixel limits before
unbounded work. No I/O, external runtime, allocation without a ceiling, or
canonical durable format is introduced.

This is deliberately **configuration-prefix metadata**, not full parameter-set
validation. The API exposes the exact number of interpreted prefix bits.
Remaining RBSP syntax, VUI/HRD/extensions, trailing bits, entropy-coded slices,
profile conformance and decoding are unverified. Display dimensions mean the
SPS conformance window, not an inferred VUI display window. Header acceptance
does not claim that all referenced pictures or independently decodable media
exist. The existing picture grouping and source custody boundaries are unchanged.

## Verification

`hevc_configuration_contract.rs` covers real retained Main/Main10 parameter
fixtures plus synthetic temporal-layer/profile alignment, ID mismatch, crop,
escape, unsupported-format, dimension and work-limit contracts:

```sh
cargo test -p fss-packet --test hevc_configuration_contract
```

The real parameter fixtures were generated from `testsrc2` using the locally
available FFmpeg 7.1.5-0+deb13u1 / libx265 laboratory encoder. An independent
Python prefix reader agreed with FFprobe on Main 8-bit (64x48 coded, 62x46 after
conformance crop) and Main10 (64x48, 10-bit) fixtures. The Rust tests were added
but not executed: no Rust toolchain is available in the editing environment.
The Python/FFprobe check is not a Rust build, test or qualification receipt.

Protocol/layout reference: HEVC VPS/SPS/PPS prefix syntax and ISO/IEC 14496-15
HEVC configuration records, cross-checked against FFmpeg 7.1's `hevc.c` and
`hevc/ps.c` as laboratory references only. No FFmpeg code or runtime is linked
into production.
