# MP4 in-band AVC and HEVC configuration

`fss-container` can index and extract recordings whose video sample entry is
`avc3` or `hev1`, including recordings that replace an SPS/PPS under the same
bitstream ID. This makes a later random-access range decode with the parameters
that its samples actually reference. The original container bytes, parameter
NALs, sample payloads, decode/composition ticks, and copy maps remain intact.

## Admission and compatibility

The existing `AvcMp4::parse`, `parse_with_checkpoint`, and
`parse_recovering_tail` entrypoints retain their previous admission profile.
They continue to refuse `avc3`, incomplete out-of-band configuration records,
and in-band parameters that differ from the configured originals.

The explicit `parse_inband`, `parse_inband_with_checkpoint`, and
`parse_inband_recovering_tail` entrypoints add in-band configuration. Indexed
and fragmented MP4 share the same checked sample join. Original `avc1`, `hvc1`,
and unchanged `hev1` inputs keep their previous sample data, extraction bytes,
copy maps, and parser work counters. `uses_inband_configuration()` identifies
when the added admission/reconstruction profile was actually needed.

The added profile uses existing first-party metadata parsers: AVC Baseline,
Main and High 8-bit 4:2:0, and HEVC single-layer Main/Main10 4:2:0 configuration
prefixes. Metadata admission does not promise pixel decoding for every profile;
the native HEVC pixel decoder still explicitly refuses Main10. Encryption,
external data references, multiple sample descriptions, parameter-set tracks,
extension layers and unsupported coding tools are not guessed or approximated.

## Parameter references and random access

An SPS/PPS/VPS ID is a mutable name within the bitstream. The index tracks its
exact source bytes and parent reference, and binds each sample to the parameter
closure its primary picture uses. New bytes under an existing ID advance the
configuration generation. Identical retransmissions retain the generation and
still retain their own source locations.

`sample_configuration(index)` returns the referenced SPS/PPS or VPS/SPS/PPS in
dependency order, the original byte spans and originating samples, bounded SPS
dimensions/bit depth, and the local configuration generation. It does not claim
that entropy data is decodable, that every macroblock/CTU is present, or that a
reference picture is available.

An IDR/IRAP must have its referenced parameters in the sample entry or in that
sample. Every following picture must obtain its referenced definitions from the
entry or samples at or after that random-access point. A parameter from an earlier
GOP cannot become a hidden dependency of a later P/B picture. A stale initial SPS
is not substituted for a changed definition. Extraction beginning at a declared sync sample uses its checked parameter
closure and produces a byte-exact map for every copied NAL, including bootstrap
parameters carried by the selected sample itself. When a later sample references
a different tuple, extraction supplies that tuple before its original NALs;
this also supports a later PPS ID defined only in the sample entry. A non-random-access first
sample is refused. HEVC arrays marked complete cannot be extended or redefined
in-band under the added profile.

The original sample entry is available as `sample_entry_range()`. A caller can
retain that exact metadata span, later parse it with `InbandSampleEntry`, and
call `bootstrap` or `bootstrap_with_checkpoint` using only the selected sample.
The result borrows the exact needed NALs from those two retained objects. Earlier
video samples and mutable original paths are unnecessary. In that standalone
bootstrap's source map, `sample=None` addresses the retained sample-entry bytes;
`sample=Some(0)` addresses the selected sample bytes.

For a whole retained range, `InbandSampleEntry::stream(first_sample)` creates an
owned, bounded `InbandConfiguration`. Each sequential `sample` call updates the
original parameter definitions and returns the exact referenced tuple plus any
decoder prefix needed for a changed tuple. Other IDs from the entry remain
available without loading stale or unreferenced definitions into the decoder.
Source spans identify the original sample index and a local offset within that
sample; entry spans remain local to the retained entry. Parser quotas accumulate
across the range. A failed or cancelled state is terminal and cannot reuse its
partial updates. Starting a fresh state at a later IDR/IRAP restores independent
random-access behavior.

The new profile also checks one primary-picture prefix group per source sample.
AVC compares the parameter-dependent picture identity and primary macroblock
addresses. HEVC compares the first-slice flag, PPS ID, NAL type, temporal layer
and IRAP output flag; its full POC and segment-address agreement remain the native
decoder's responsibility. A second first slice, conflicting checked prefix,
parameter replacement after VCL data, missing parameter reference, or split or
reordered primary AVC slice sequence refuses. Prefix agreement remains separate
from complete native decode and its sample-to-picture accounting.

## Bounds and cancellation

The existing input, metadata, box, sample, table-entry, NAL and output ceilings
remain owner-narrowable. The added validation pass charges its NAL visits and
parameter-closure entries to those same aggregate ceilings. It checks
cancellation at sample, NAL, parameter and output-copy boundaries.

Each parameter NAL is bounded to 65,535 bytes. Parameter IDs have their codec
bounds; at most one initial and one current definition per ID is retained,
with byte-identical retransmissions sharing their allocation. The AVC namespace
has at most 32 SPS and 256 PPS IDs; HEVC has 16 VPS, 16 SPS and 64 PPS IDs. Native syntax caches
are bounded by the PPS namespace and invalidate when referenced bytes change,
so repeating a small PPS does not repeatedly parse a large unchanged SPS. The
ID-only prefix reader consumes at most 1,024 bits and allocates no RBSP. Sample
configuration storage is at most three source references per admitted sample.
No pixel buffers, network calls, worker threads or external processes are part
of container parsing or extraction.

## Independent evidence

`scripts/generate_mp4_inband_fixtures.py` is an offline laboratory generator.
It encodes original synthetic pixels with FFmpeg/libx264/libx265, independently
packages their original NALs, and verifies the resulting recordings with
FFmpeg 6.1.1. No camera footage is used. The committed manifest records input
hashes, per-frame I420 hashes, dimensions, exact sample ticks, and independently
decodable random-access ranges.

The fixtures exercise empty, partial and full configuration records; SPS/PPS
replacement under the same ID with a 64×48 to 96×64 dimension change; indexed
and fragmented layouts; 1/2/4-byte NAL lengths; AVC multiple slices; and AVC/HEVC
B-frame output reordering. Hybrid cases require parameters from both the sample
entry and the sample. The generator separately decodes each selected GOP to
avoid allowing FFmpeg's output filter to silently resize a changed resolution.

`scripts/generate_mp4_inband_multi_id_fixtures.py` adds AVC and HEVC recordings
whose later P picture uses entry-only PPS1 after the first picture used PPS0.
The HEVC P picture also has dependent segments. Their independent FFmpeg
verification checks exact output hashes and proves that removing entry PPS1
causes decoding to fail. These two fixtures have a separate `multi_id_manifest.json`.

`crates/fss-container/tests/inband_mp4.rs` runs the actual first-party AVC and
HEVC decoders on complete native extractions and later-GOP cold bootstraps. It
checks every expected pixel hash, dimension, unique decode index, timestamp and
NAL copy map. Failure cases include two genuine complete pictures in one
sample, missing later-GOP configuration, HEVC completeness violations,
truncation, cancellation and resource ceilings. The Rust tests never invoke
FFmpeg or regenerate their expected values.

The native regression lane passes 413 tests: 88 container, 165 H.264 and 160
H.265 tests. This includes 27 in-band configuration tests, nine tests of the
exact production sample driver, and three incomplete-picture boundary tests
for each codec. Strict Clippy passes for the changed libraries and those new
test targets with `--no-deps`. These results cover native parsing, extraction
and decoding; retained-runtime and CLI integration require their separate
qualification lanes.

```sh
cargo test --locked -p fss-container -p fss-codec-h264 -p fss-codec-h265
cargo clippy --locked -p fss-container --lib --test inband_mp4 \
  --test native_sample_boundary --no-deps -- -D warnings
cargo clippy --locked -p fss-codec-h264 -p fss-codec-h265 --lib \
  --test access_unit_boundary --no-deps -- -D warnings
```

## Standards basis

The storage and parameter-carriage rules follow ISO/IEC 14496-15, particularly
the AVC canonical-sample/configuration provisions in §5.3 and HEVC configuration
records in §8.3. The W3C [ISO BMFF Byte Stream Format](https://www.w3.org/TR/mse-byte-stream-format-isobmff/)
describes in-band and out-of-band parameter carriage and rejects missing
initialization at a required sample. The [ISO/IEC 14496-15 publication](https://webstore.iec.ch/en/publication/102880)
identifies the normative container standard. The offline encoder's
[HEVC configuration writer](https://ffmpeg.org/doxygen/6.1/hevc_8c_source.html)
provides an independent cross-check of the `hvc1`/`hev1` completeness signaling;
no foreign implementation is linked or called by FSS.
