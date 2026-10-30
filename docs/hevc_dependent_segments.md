# Native HEVC dependent slice segments

The pure-Rust HEVC decoder admits independent and dependent slice segments in its
existing Main/Main Still Picture, progressive 8-bit 4:2:0 profile. Retained-file and
native capture analysis use this decoder. A dependent segment continues its
preceding logical slice; treating it as a fresh independent slice would produce
incorrect entropy, prediction and filtering behavior.

## Decoding contract

The streaming `fss_codec_h265::Decoder` binds a dependent segment to the most
recent independent header in the same unfinished picture. It inherits only the
omitted coding fields and parses the segment's own address, header suffix and
alignment. Every non-first segment must retain the picture's NAL identity and
active decode-relevant PPS/SPS values. An identical parameter retransmission is
accepted; redefining a parameter set cannot change the grammar underneath an
unfinished picture, including by disabling the dependent-segment flag.
Independent headers must also preserve the picture's POC, output, reference-set
and temporal-MVP identity, while legitimate per-slice QP, weights and filters may vary.

The decoder carries the prior segment's CABAC probability contexts, previous
quantization parameter and wavefront synchronization snapshot. Each segment starts
a new arithmetic engine. At a wavefront row boundary, the above-right context
snapshot takes precedence over the preceding segment's final contexts; when that
neighbor is unavailable, including a single-column picture, contexts initialize
from the slice parameters. A new independent slice resets its corresponding state.

Dependent segments retain their logical slice tag. Neighbor prediction, reference
maps, SAO merging and deblocking therefore see the correct slice boundary. Every
segment still consumes the existing `max_slices_per_picture` allowance, including
headers of intentionally skipped RASL pictures. Continuation is held only for the
current picture and cannot cross an IRAP restart, end of sequence or failed picture.

Malformed/truncated input, absent predecessors, gaps, overlaps, parameter changes
and exhausted bounds discard unfinished picture state and require IRAP recovery.
No concealed or partially reconstructed picture is published as a successful
decode. Already completed output and previously stored valid parameter sets retain
their existing ownership.

The stateless public `parse_slice_header` entry point keeps its signature and
parses independent segments. A dependent segment without a preceding independent
header returns `IncompletePicture`; applications decoding complete streams should
use `Decoder` rather than constructing hidden cross-call parser state.

The rules follow [ITU-T H.265 V11 (01/2026)](https://www.itu.int/rec/T-REC-H.265-202601-I/en),
sections 7.3.6, 7.4.7.1, 8.6.1 and 9.3.1–9.3.2. Tiles, Main 10, other sample formats,
field-coded sequences and unsupported extensions retain their existing refusals.

## Native verification and fixture provenance

The dependent-segment corpus is authored with real CABAC continuation and separate
arithmetic streams. It is not a header rewrite of independent libx265 slices.
Offline FFmpeg decoding supplies frozen I420 hashes; Rust tests invoke only the
native decoder. Coalescing dependent segments preserves every oracle pixel, and
the filter fixture proves that the dependent boundary is actually deblocked.

All **128 native H.265 tests pass** on pinned `nightly-2026-08-31`: 42 units,
48 original pixel-conformance cases, 20 dependent-segment cases, six skipped-RASL
contracts, ten hostile-input cases and two malformed-media gauntlets. Ten new
encoded streams supply 11 independently frozen oracle frames, and fresh generation
reproduces all 20 stream/hash files byte-for-byte.

The cases exercise mid-row continuation, adapted contexts, QP carry, independent
slice reset, wavefront cuts before and after the saved context, row-start precedence
and single-column rows. A real IDR-to-P-skip stream verifies inherited references,
merge prediction and P CABAC contexts; weighted P/B header inheritance is checked
separately, without claiming a B dependent-segment pixel oracle. Refusal tests cover
truncated payloads and headers, missing
or reordered segments, parameter/NAL changes, exact segment budgets and recovery
without partial output. Skipped-RASL contracts cover header-only omission, stream-end
reset, budget exhaustion, parameter/picture changes and immediate IDR recovery. See the
[fixture README](../crates/fss-codec-h265/tests/fixtures/decode/README.md) for the
full matrix and independent oracle version.

```sh
cargo +nightly-2026-08-31 test --locked --offline -j1 -p fss-codec-h265 --lib --tests
```

Existing recorded-frame receipt encodings and decoder labels are unchanged. The
pre-existing native conformance corpus remains the compatibility oracle for already
supported coding paths. These tests establish the bounded codec capability; they
do not establish physical-camera interoperability or full release qualification.
