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

## Native fragmented MP4

`fss_container::HevcMuxer` consumes the existing `HevcPictureGroup` values
produced by the picture-aware RTSP client, plus `TimedHevcPicture` records with
explicit decode time, positive duration and signed composition offset. The
constructor pins the owner ingress/generation/SSRC, exact prefix-screened
configuration, positive track timescale, and independent `Mp4Limits`.

The writer emits reusable `ftyp + moov` initialization (one `hev1` track with
`hvcC`) and deterministic `moof + mdat` fragments. Every in-band NAL is retained,
including parameter sets, SEI, AUD, filler and supplied end markers. Four-byte
lengths replace transport framing without transcoding. Per-NAL output ranges
retain all RTP copy spans and FU header-synthesis inputs. Initialization returns
exact ranges for the owner's original out-of-band VPS/SPS/PPS; it does not
fabricate their RTP provenance. The unchanged AVC writer shares only the existing
bounded box primitive, not HEVC parameter or picture semantics.

Each fragment starts with an observed IDR type 19/20. CRA/BLA and leading
RADL/RASL pictures are deliberately rejected in this closed-GOP subset. Known
discontinuities, unverified EOF tails, a changed in-band parameter tuple, wrong
PPS/epoch/temporal identity, source overlap or reversal, zero/noncontiguous
sample durations, negative/overflowing presentation time and resource excess
fail without advancing sequence, timeline or source cursors. Explicit gaps
between fragments are receipted; no missing samples are fabricated. Timing is
never inferred from an RTP timestamp, arrival clock, VUI, or assumed frame rate.

`hev1` permits the retained in-band parameters; hvcC array-completeness flags
stay zero. Uninterpreted spatial segmentation, parallelism and frame-rate fields
remain unspecified. A source progressive/frame-only declaration is required.
This still does not certify full parameter-set syntax, entropy bodies, reference
availability, independently decodable output, camera coverage, privacy approval
or durable source/archive publication. Valid source media can be remuxed;
invalid source bodies can still be undecodable. No decoder, worker, second
runtime, socket, filesystem or external process is invoked by this API.

## Verification

`hevc_configuration_contract.rs` covers real retained Main/Main10 parameter
fixtures plus synthetic temporal-layer/profile alignment, ID mismatch, crop,
escape, unsupported-format, dimension and work-limit contracts:

```sh
cargo test -p fss-packet --test hevc_configuration_contract
cargo test -p fss-container --test hevc_remux_contract
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

The remux contracts pass NALs through the real RTP depacketizer and HEVC
assembler (no picture-constructor bypass). They cover a retained four-picture
synthetic stream, golden initialization bytes, complete parameter/source ranges,
AP/FU provenance, 64-bit decode bases, signed offsets, explicit gaps, retry-safe
errors, IDR requirements, EOF/discontinuity clamps and independent output limits.
The original AVC tests and outputs are unchanged.

`tests/fixtures/media/hevc/remux_main8.nals.hex` retains one original NAL per
line from synthetic `testsrc2` footage. `remux_main8.init.hex` is an independent
box-layout golden, not a Rust-generated success receipt. The associated
`remux_oracle.json` records the laboratory check: an independent Python MP4
layout with those source NALs was accepted by FFprobe as `hev1`, with four exact
0/18000/36000/54000 DTS/PTS positions and 18000-tick durations. FFmpeg decoded its
four frames to exactly the same 17,112 bytes as the original elementary stream
(SHA-256 `496ce8250220aa97f58ed8bdd2ff8e39486271a750125d055e30d4eac1eba48f`).
This checks the container layout and fixtures, **not execution of the Rust
implementation**. Rust compilation, tests, formatting, and qualification remain
unrun in this environment. No camera/device support or release gate is promoted.
