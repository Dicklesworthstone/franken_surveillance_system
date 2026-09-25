# Retained JPEG decode pipeline

This reference composition connects completed ADP-FILE imports to the canonical production
`fss-codec-mjpeg` decoder. It does not call the separate reference colour decoder, invoke a
foreign process. The output is complete, full-range Y (luma), with the original encoded bytes
and source capsule retained as provenance. Annex-B H.264 (`annexb`) and H.265 (`hevc`) imports
use the separate range paths described in "Retained H.264 range decode" and "Retained H.265
import and range decode" below.

## Library execution

Use `fss_reference::ingest::recorded_decode::{RecordedDecodeRequest, RecordedFrame}`.
Select the exact import identity and segment index, explicitly supply `Grayscale` or `YCbCr`
component interpretation, and set independent source-read and codec ceilings. Pass a
`DecodeBudget` to `RecordedFrame::decode_and_publish`. One shared budget accumulates actual
codec work across multiple frames. Work units are deterministic operations, not milliseconds,
energy, or a fabricated full-resource measurement. A cancellable codec budget accepts an
owner-controlled cancellation flag; the deployment `ReplayCx` is checked at composition
boundaries, including after decode and before staging.

On success the graph retains raw compressed segment bytes, raw tightly packed Y samples,
the exact original capsule, import manifest/root and canonical decode receipt. The root is
published last through the existing local publisher and ledger bridge. A final `decode_receipt`
delta in the cognition plane establishes completion. The original capsule is never rewritten
or upgraded merely because decoding succeeded.

`RecordedFrame::open` reopens a completed derivative without the original source path or
another decode. It revalidates retained source, the exact receipt, final delta, publication
identity and luma checksum. `verify_by_replay` also reruns the canonical codec and compares
pixels, dimensions, codec accounting and work units without changing authority.

Capture intervals and clock basis are copied from the exact authority-held source capsule.
No EXIF orientation, ICC transform, lens correction, timestamp reconstruction, live coverage,
absence claim, person detection or alert authority is implied. The source interpretation is
explicit: ambiguous RGB/CMYK and unsupported JPEG coding processes fail in the canonical codec.

## Recovery and refusals

Successful retries reuse the same root and final batch; they do not append duplicate decode
claims or substitute a later global anchor. Decoder failure, exhausted work, bad source,
wrong interpretation or a pre-publication cancellation cannot publish partial pixels.

A failure after root publication but before the final decode delta may leave a durable root
whose decode operation is incomplete. `open` refuses it. Repeating `decode_and_publish` with
the same recipe resumes the final transition. An error may leave staged immutable objects;
this is not a claim of atomic rollback. Existing tombstones and publication conflicts are not
bypassed. Ordinary readers never truncate or repair journals.

## Binary receipt v2 (format owner: fss-reference retained-media composition)

This is internal reference evidence, not a replacement for the universal agent response
protocol. Its domain is `fss.recorded_luma_receipt.v2` (v2 added the privacy-mask marker,
fss-bgqkd); its migration rule is exact-v2 or explicit refusal, never silent conversion: a v1
receipt is a different decode identity and is never reopened as v2. The receipt is capped at
4096 bytes. It uses the existing checked canonical encoder in this exact field order:

1. Length-prefixed magic `FSSYREC2`, big-endian u32 version 2, domain text.
2. SHA-256 import identity, import root, import-manifest digest, canonical import-completion anchor.
3. u64 source segment index and file offset; capsule digest; complete canonical `SensorCapsule`.
4. u32 coded width and height; SHA-256 encoded source, luma and decoder identities.
5. u8 interpretation (0 grayscale, 1 YCbCr); u64 MCU count, entropy-block count, restart count,
   metadata-segment count, metadata-byte count and charged codec work units.
6. Privacy-mask marker: u8 0 (explicit "no policy": the sensor had no retained mask) or u8 1
   followed by the SHA-256 of the retained mask policy that was applied. The luma digest of
   item 4 is always the digest of the published (masked) plane.

The content-addressed parent manifest authenticates the receipt's expected checksum within
local custody; a self-consistent checksum is not remote principal authentication. Dimensions
are bounded by the canonical codec: each axis <=4096, at most 4,194,304 pixels, encoded input
<=16 MiB. Unknown magic/version/interpretation, trailing bytes, truncated fields, altered
source binding and incompatible decoder identity are refused. Previous generation receipts
remain immutable; future readers must implement an explicit version/decoder migration policy.

The derived key (`fss.recorded_luma_key.v2`) binds the immutable import root, segment index,
exact codec identity, interpretation and the mask binding digest (`fss.privacy_mask_binding.v1`
over the marker). Admission ceilings do not alter that key: a larger work allowance cannot
change the pixels or silently replace an existing result. The canonical object graph includes
both raw-pixel and compressed-source identities. PGM rendering is a separate export, with a
separate byte digest, and does not change the underlying evidence.

This implementation and its adversarial/restart/cancellation tests do not establish production
qualification. Run the repository's pinned-nightly Rust and local qualification lanes before
promoting a release claim.

## Privacy masks at decode (fss-bgqkd)

An owner declares a per-sensor mask policy with `fss-event privacy-mask declare --sensor ID
--resolution WxH --rect X,Y,W,H [...]`: a preview prints the canonical policy digest
(`fss.privacy_mask_policy.v1`) and an exact approval over the sensor's current retained policy;
only `--approve <approval>` retains it, as the next generation of the sensor's
`privacy_mask_policy` ledger object (authority plane). A stale or wrong approval is refused before
any write (`ERR-PRIVACY-MASK-APPROVAL-STALE-001`); an exact rerun writes nothing. Rectangles are
fss-core `RedactedRegion`s with the existing `transform:bounding_box_redact` method, at most 32,
in decoded pixels of the declared stream resolution. Polygons are not supported.

Every retained decode resolves the capsule sensor's *current* policy and applies it to the
decoded planes before any other code sees them:

- JPEG/MJPEG luma (`RecordedFrame::decode_and_publish`, `open`, `verify_by_replay`, the watch
  reader): masked samples become luma 16 before staging, digesting, PGM export or analysis;
- H.264 and H.265 frames (`RecordedH264Range`, `RecordedH265Range`): luma 16 and every Cb/Cr
  sample whose 2x2 luma block touches a masked sample becomes 128, before the receipt's luma,
  chroma and I420 digests are taken; `to_rgb` additionally writes RGB 16,16,16 over masked pixels;
- JPEG RGB (package-detect and the detection cascade): the native RGB decode is masked to RGB
  16,16,16 and re-receipted (decoder identity folded with the binding through
  `fss.privacy_mask_lineage.v1`); the same mask is the per-pixel permission of the RGB privacy
  projection, so no detection may touch a masked pixel.

A frame whose dimensions differ from the policy's declared resolution is refused
(`ERR-PRIVACY-MASK-RESOLUTION-001`), never served unmasked. Without a policy the pixels are
unchanged and every receipt carries the explicit no-policy marker. The H.264/H.265 frame receipt
domains moved to `fss.recorded_h264_frame_receipt.v2` / `fss.recorded_h265_frame_receipt.v2` for
the same marker.

A policy change is a new lineage: the JPEG decode key, the watch plan identity (and so every
candidate, analysis and coverage identity) and every coverage pipeline generation bind the mask
binding, so nothing retained under another generation is reused. `open`/`read-decoded` of a
decode retained under no or a superseded policy is refused as unmasked access
(`ERR-PRIVACY-UNMASKED-ACCESS-REFUSED-001`); decode again under the current policy. `fss-file
extract` of a masked sensor's raw retained source is refused the same way: compressed source
cannot be masked without re-encoding. There is no override capability. The retained source and
earlier decodes are not deleted (deletion closure is not implemented).

## Retained H.264 range decode

`fss_reference::ingest::recorded_decode::h264::{RecordedH264Request, RecordedH264Range,
decode_h264_range}` decode a retained Annex-B import with the pure-Rust `fss-codec-h264`
decoder (Constrained Baseline, Main and High; progressive, 8-bit, 4:2:0). Each retained segment is
one access unit. Pictures are returned in display order; with B frames this differs from decode
order, and each picture is bound to the segment that coded it through its decode index (the
range must yield exactly one picture per access unit). Because P and B pictures predict from
other pictures, a request names a contiguous range `first_segment ..
first_segment + segment_count` (1..=1024 segments) that must start at an IDR access unit and
must not contain a retained source gap. The interpretation must be `ycbcr`: every admitted
profile is decoded as 4:2:0 (monochrome and 4:2:2/4:4:4 streams are refused). `max_pictures` is narrowed to the range length; the other
`DecoderLimits` (dimensions, macroblocks, NAL bytes, slices, references) stay explicit.

Every picture carries a receipt binding import identity/root/manifest, range start, segment,
source offset, source capsule and its digest, visible dimensions, IDR flag, decode index, the
luma SHA-256 and the packed-I420 SHA-256 (the value FFmpeg's `yuv420p` framehash reports), and
the decoder label identity. H.264 frames are a rebuildable derivation: nothing is staged,
published or appended to the ledger, so `read-decoded`/`verify-decoded` refuse Annex-B imports.

Refusals are typed and carry registered identities: `ERR-DECODE-H264-RANGE-NOT-IDR-001`,
`ERR-DECODE-H264-RANGE-GAP-001`, `ERR-DECODE-INTERPRETATION-001`,
`ERR-DECODE-H264-UNSUPPORTED-001` (a profile or tool outside the admitted set; never
approximate pixels), `ERR-DECODE-BOUNDS-001`, `ERR-DECODE-SOURCE-UNAVAILABLE-001`, and
`ERR-DECODE-001` for corrupt pictures. A refused access unit ends the range; frames returned
before it remain valid. `fss-file decode --segment N [--segment-count M] --interpretation
ycbcr [--output FILE.pgm]` exposes the same path and writes one binary PGM luma image per frame.

## Retained H.265 import and range decode

**Import.** `FileIngestAdapter` retains an H.265/HEVC Annex-B elementary stream as media format
`hevc` (`--media-format hevc`, `FileFormatHint::Hevc`); `annexb` stays H.264. The two codecs
share Annex-B framing, so the choice is never guessed from framing alone. Auto-detection looks at
the first NAL unit header: it selects `hevc` only when that header is a plausible H.265 opener
(`forbidden_zero_bit` 0, `nuh_layer_id` 0, `nuh_temporal_id_plus1` non-zero, and a VPS, SPS,
PPS, access unit delimiter, prefix SEI or IRAP slice type) and not a plausible H.264 opener
(non-IDR slice; IDR slice, SPS or PPS with non-zero `nal_ref_idc`; SEI or delimiter with zero
`nal_ref_idc`). Every usual H.264 first byte fails the H.265 test, so H.264 detection is
unchanged. A header plausible as both (for example `28 01`, an H.265 IDR_N_LP slice and an H.264
PPS) is refused with `ERR-INGEST-FORMAT-AMBIGUOUS-001` until the format is declared; a declared
format that contradicts a header plausible only as the other codec is
`ERR-INGEST-FORMAT-CONFLICT-001`. The manifest records `format: hevc` and the detector evidence
(`hevc_nal_header`, or `annexb_start_code:operator_declared_hevc` when the operator decided).

Access units follow H.265 7.4.2.4.4 (`ingest::hevc_annexb::split_hevc_annexb`), with the same
start-code, padding, emulation-prevention and size bounds as the H.264 splitter. After a slice
segment, a new access unit starts at an access unit delimiter, a VPS, SPS, PPS, prefix SEI or
reserved type 41..44/48..55, or a slice segment whose `first_slice_segment_in_pic_flag` is 1;
end-of-sequence/bitstream closes the current one. Parameter sets and prefix SEI therefore travel
with the picture they precede, so one retained segment is one coded picture with exact source
spans. A NAL unit shorter than its two-byte header or with `nuh_temporal_id_plus1` 0, a slice
segment without payload, and a stream without any slice segment are typed refusals. A picture
before the stream's first VPS/SPS/PPS is marked as a gap, like the H.264 path.

**Decode.** `fss_reference::ingest::recorded_decode::h265::{RecordedH265Request,
RecordedH265Range, decode_h265_range}` decode a contiguous `hevc` range (1..=1024 segments)
with the pure-Rust `fss-codec-h265` decoder (Main and Main Still Picture, 8-bit 4:2:0). The
range must start at an IRAP access unit (IDR, CRA or BLA) and must not contain a retained source
gap; the interpretation must be `ycbcr`. Pictures come out in display order and are bound to
their coding segment through the codec's decode index.

The one-picture-per-access-unit rule has one exception, made explicit. When the range starts at a
CRA or BLA picture, that picture starts a new coded video sequence, and its RASL pictures
(types 8 and 9) reference pictures before the range. The codec skips them, as H.265 8.1.3 and
FFmpeg do. The range observes this through the codec's decoded-picture count, checks that every
slice segment of such an access unit is RASL, and lists the segment in
`RecordedH265Range::skipped_rasl_segments()`. It never fabricates a frame for it. Any other access
unit completing zero or several pictures, or a decoded picture that is never output, is
`RecordedDecodeError::H265AccessUnit` (`ERR-DECODE-001`). A range that starts at an IDR decodes
the RASL pictures of a later CRA normally. The CRA-led case is tested against a separate FFmpeg
oracle that decodes the same stream from the CRA access unit
(`crates/fss-reference/tests/fixtures/hevc_ingest/`).

Frame receipts bind the same custody as H.264, plus the picture's NAL unit type (IDR/IRAP),
picture order count and the `fss-codec-h265` decoder label identity. Frames are a rebuildable
derivation: nothing is published, so `read-decoded`/`verify-decoded` refuse `hevc` imports.
Refusals: `ERR-DECODE-H265-RANGE-NOT-IRAP-001`, `ERR-DECODE-H265-RANGE-GAP-001`,
`ERR-DECODE-H265-UNSUPPORTED-001` (Main 10, 4:2:2, range extensions, tiles, dependent slices,
long-term references, layers above the base layer; never approximate pixels),
`ERR-DECODE-INTERPRETATION-001`, `ERR-DECODE-BOUNDS-001`, `ERR-DECODE-SOURCE-UNAVAILABLE-001`,
and `ERR-DECODE-001` for corrupt pictures.

`fss-file decode --segment N [--segment-count M] --interpretation ycbcr [--output FILE.pgm]` on
an `hevc` import writes one binary PGM luma image per frame and prints `skipped_rasl_segment=`
lines for skipped pictures. `fss-event watch` and `fss-event corroborate` accept `hevc` imports
through the same range reader; a RASL picture skipped after a leading CRA contributes no frame.
