#![forbid(unsafe_code)]
//! H.265/HEVC decoding (Main and Main Still Picture, 8-bit 4:2:0) of retained `hevc` imports.
//!
//! The file adapter retains one access unit (one coded picture plus its prefix parameter sets and
//! SEI) per segment. Pictures predict from earlier pictures, so this module decodes a contiguous
//! segment range that must begin at an IRAP access unit (IDR, CRA or BLA) and must not cross a
//! retained source gap. Pictures are returned in display (output) order; each is mapped back to
//! the segment that coded it through the codec's decode index.
//!
//! One picture per access unit, with one honest exception. A CRA or BLA picture that starts the
//! range starts a new coded video sequence, so its RASL pictures (random access skipped leading
//! pictures, NAL types 8 and 9) reference pictures before the range and are not decodable. The
//! codec skips them exactly as H.265 8.1.3 and the FFmpeg oracle do: it decodes nothing for such
//! an access unit. This module observes that through the codec's decoded-picture count, verifies
//! that every slice segment of the skipped access unit is a RASL slice, and reports the segment in
//! [`RecordedH265Range::skipped_rasl_segments`]; it never fabricates a frame for it. Any other
//! access unit that completes zero pictures, or several, and any decoded picture that is never
//! output, is [`RecordedDecodeError::H265AccessUnit`]. A range that starts at an IDR (or contains
//! a CRA after its start) decodes every RASL picture normally.
//!
//! Every picture is bound to the same custody as the JPEG and H.264 paths (import identity, root,
//! manifest, source capsule) and to the exact codec output (luma and packed I420 digests). Frames
//! are a rebuildable derivation: nothing is staged, published or appended to the ledger. The
//! pure-Rust codec is deterministic and bit-exact against the FFmpeg oracle fixtures, and it owns
//! all H.265 semantics and refusals (Main 10, 4:2:2, range extensions, tiles, ...). Frames also
//! carry both chroma planes (`cb`, `cr`, per-plane digests on the receipt) and convert to RGB
//! through the declared transform in [`super::video_rgb`].

use std::collections::VecDeque;

pub use fss_codec_h265::{DecodeError as H265DecodeError, DecoderLimits, UnsupportedFeature};
use fss_codec_h265::{Decoder, Picture, annex_b_nal_units};
use fss_core::{CanonicalEncode, CanonicalEncoder, ContentDigest, SensorCapsule, SensorId};

use super::video_budget::RecordedVideoDecodeBudget;
use super::{ComponentInterpretation, RecordedDecodeError, checkpoint, source_capsule};
use crate::ingest::privacy_mask::{MaskBinding, binding_digest, current_mask, encode_marker};
use crate::ingest::{
    MKV_HEVC_PARAMETER_SET_REASON_PREFIX, MP4_HEVC_PARAMETER_SET_REASON_PREFIX, RetainedFileImport,
    RetainedReadLimits, VerifiedChunkCache,
};
use crate::{ReferenceDeployment, ReplayCx};

/// Maximum access units decoded by one range request.
pub const MAX_H265_RANGE_SEGMENTS: usize = 1024;
/// Maximum access units of one streaming range ([`RecordedH265Range::open_stream`]), the
/// long-dwell whole-recording bound.
pub const MAX_H265_STREAM_SEGMENTS: usize = 65_536;
/// Versioned label of the canonical decoder semantics bound into every frame receipt.
pub const H265_DECODER_LABEL: &str =
    "fss-codec-h265:main-420-8bit:scalar-reference:output-order:rasl-skip-at-range-start:v1";
/// Canonical frame-receipt domain.
pub const H265_FRAME_RECEIPT_DOMAIN: &str = "fss.recorded_h265_frame_receipt.v2";
/// Boundary before each retained access unit is read and decoded.
pub const STAGE_RECORDED_H265_SEGMENT: &str = "recorded_h265:segment";

/// Identity of [`H265_DECODER_LABEL`]; a semantics label, not a hash of compiled code.
#[must_use]
pub fn h265_decoder_identity() -> ContentDigest {
    ContentDigest::sha256(H265_DECODER_LABEL.as_bytes())
}

/// Explicit retained source range, interpretation, and independent read/decode bounds.
#[derive(Clone, Debug)]
pub struct RecordedH265Request {
    /// Exact completed `hevc` import.
    pub import_identity: ContentDigest,
    /// First zero-based segment; it must hold an IRAP (IDR, CRA or BLA) access unit.
    pub first_segment: usize,
    /// Number of contiguous segments, from one through [`MAX_H265_RANGE_SEGMENTS`].
    pub segment_count: usize,
    /// Must be [`ComponentInterpretation::YCbCr`]; every admitted H.265 profile is 4:2:0.
    pub interpretation: ComponentInterpretation,
    /// Custody-read ceilings for each retained access unit.
    pub read_limits: RetainedReadLimits,
    /// Codec ceilings. `max_pictures` is narrowed to `segment_count` before decoding.
    pub decoder_limits: DecoderLimits,
}

/// Source-to-pixels provenance of one decoded H.265 picture.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecordedH265FrameReceipt {
    import_identity: ContentDigest,
    import_root: ContentDigest,
    manifest_digest: ContentDigest,
    range_start: u64,
    segment_index: u64,
    source_offset: u64,
    capsule_digest: ContentDigest,
    capsule: SensorCapsule,
    width: u32,
    height: u32,
    nal_unit_type: u8,
    picture_order_count: i32,
    decode_index: u64,
    luma_sha256: ContentDigest,
    i420_sha256: ContentDigest,
    // Plane digests are exposed for audit but not encoded: the encoded I420 digest already
    // binds both chroma planes, so receipt bytes stay identical to the luma-era receipts.
    cb_sha256: ContentDigest,
    cr_sha256: ContentDigest,
    mask_policy: Option<ContentDigest>,
}

impl RecordedH265FrameReceipt {
    /// Exact import identity.
    #[must_use]
    pub fn import_identity(&self) -> ContentDigest {
        self.import_identity
    }
    /// Published import root witnessed by the import completion authority.
    #[must_use]
    pub fn import_root(&self) -> ContentDigest {
        self.import_root
    }
    /// IRAP segment the decoder state was started from.
    #[must_use]
    pub fn range_start(&self) -> u64 {
        self.range_start
    }
    /// Zero-based retained segment (access unit) of this picture.
    #[must_use]
    pub fn segment_index(&self) -> u64 {
        self.segment_index
    }
    /// Digest of the retained capsule payload bound to this segment.
    #[must_use]
    pub fn capsule_digest(&self) -> ContentDigest {
        self.capsule_digest
    }
    /// Original source capsule, including its conservative capture interval.
    #[must_use]
    pub fn capsule(&self) -> &SensorCapsule {
        &self.capsule
    }
    /// Visible (conformance-window cropped) luma width and height.
    #[must_use]
    pub fn dimensions(&self) -> [u32; 2] {
        [self.width, self.height]
    }
    /// `nal_unit_type` of the picture's slice segments.
    #[must_use]
    pub fn nal_unit_type(&self) -> u8 {
        self.nal_unit_type
    }
    /// Whether this picture is an IDR picture.
    #[must_use]
    pub fn is_idr(&self) -> bool {
        matches!(self.nal_unit_type, 19 | 20)
    }
    /// Whether this picture is an intra random access point (BLA, IDR or CRA).
    #[must_use]
    pub fn is_irap(&self) -> bool {
        (16..=23).contains(&self.nal_unit_type)
    }
    /// `PicOrderCntVal` within the range's coded video sequence.
    #[must_use]
    pub fn picture_order_count(&self) -> i32 {
        self.picture_order_count
    }
    /// Zero-based decode order among the pictures decoded in this range. Skipped RASL access
    /// units have no decode index.
    #[must_use]
    pub fn decode_index(&self) -> u64 {
        self.decode_index
    }
    /// SHA-256 of the tight row-major luma plane.
    #[must_use]
    pub fn luma_sha256(&self) -> ContentDigest {
        self.luma_sha256
    }
    /// SHA-256 of packed planar I420 (Y, Cb, Cr), comparable with FFmpeg `yuv420p` framehash.
    #[must_use]
    pub fn i420_sha256(&self) -> ContentDigest {
        self.i420_sha256
    }
    /// SHA-256 of the tight Cb plane (`ceil(w/2) x ceil(h/2)`); bound through the I420 digest.
    #[must_use]
    pub fn cb_sha256(&self) -> ContentDigest {
        self.cb_sha256
    }
    /// SHA-256 of the tight Cr plane (`ceil(w/2) x ceil(h/2)`); bound through the I420 digest.
    #[must_use]
    pub fn cr_sha256(&self) -> ContentDigest {
        self.cr_sha256
    }
    /// Retained privacy mask policy applied to every plane, or `None`: the explicit no-policy
    /// marker. Luma, chroma and I420 digests always name the planes as served (masked).
    #[must_use]
    pub fn mask_policy(&self) -> Option<ContentDigest> {
        self.mask_policy
    }
    /// Mask binding digest encoded into this receipt.
    #[must_use]
    pub fn mask_binding(&self) -> ContentDigest {
        binding_digest(self.mask_policy)
    }
    /// Canonical receipt bytes.
    #[must_use]
    pub fn encoded(&self) -> Vec<u8> {
        let mut encoder = CanonicalEncoder::new();
        encoder.text(H265_FRAME_RECEIPT_DOMAIN);
        encoder.digest(self.import_identity);
        encoder.digest(self.import_root);
        encoder.digest(self.manifest_digest);
        encoder.u64(self.range_start);
        encoder.u64(self.segment_index);
        encoder.u64(self.source_offset);
        encoder.digest(self.capsule_digest);
        self.capsule.encode_canonical(&mut encoder);
        encoder.u32(self.width);
        encoder.u32(self.height);
        encoder.u8(self.nal_unit_type);
        // Two's-complement bit pattern: the canonical encoder has no signed integers.
        encoder.u32(self.picture_order_count as u32);
        encoder.u64(self.decode_index);
        encoder.digest(self.luma_sha256);
        encoder.digest(self.i420_sha256);
        encoder.digest(h265_decoder_identity());
        encode_marker(&mut encoder, self.mask_policy);
        encoder.finish()
    }
    /// Content address of [`Self::encoded`].
    #[must_use]
    pub fn digest(&self) -> ContentDigest {
        ContentDigest::sha256(&self.encoded())
    }
}

/// One complete decoded picture; unsuccessful decoding never yields partial pixels.
///
/// The receipt's plane digests are computed from the served (masked) planes on the first
/// [`Self::receipt`] call, not for every decoded picture; the sealed receipt is a pure function
/// of the frame, so it is identical whenever it is computed.
#[derive(Clone, Debug)]
pub struct RecordedH265Frame {
    /// Sealed range-output position; source segment indices themselves are decode order.
    output_index: u64,
    range_segment_count: usize,
    /// Receipt fields fixed when the picture is bound; its four plane-digest slots hold
    /// placeholders that are never exposed (sealing replaces every one).
    unsealed: RecordedH265FrameReceipt,
    receipt: std::sync::OnceLock<RecordedH265FrameReceipt>,
    luma: Vec<u8>,
    cb: Vec<u8>,
    cr: Vec<u8>,
    mask: MaskBinding,
}

impl PartialEq for RecordedH265Frame {
    fn eq(&self, other: &Self) -> bool {
        self.output_index == other.output_index
            && self.range_segment_count == other.range_segment_count
            && self.unsealed == other.unsealed
            && self.luma == other.luma
            && self.cb == other.cb
            && self.cr == other.cr
            && self.mask == other.mask
    }
}
impl Eq for RecordedH265Frame {}

impl RecordedH265Frame {
    /// Zero-based position returned by this range in codec display order.
    #[must_use]
    pub const fn output_index(&self) -> u64 {
        self.output_index
    }
    /// Exact requested range length, including any RASL access units the codec skipped.
    #[must_use]
    pub const fn range_segment_count(&self) -> usize {
        self.range_segment_count
    }
    /// Source and codec provenance (plane digests computed on first use).
    #[must_use]
    pub fn receipt(&self) -> &RecordedH265FrameReceipt {
        self.receipt.get_or_init(|| {
            let mut receipt = self.unsealed.clone();
            let mut i420 = fss_core::Sha256Hasher::new();
            for plane in [&self.luma, &self.cb, &self.cr] {
                i420.update(plane);
            }
            receipt.luma_sha256 = ContentDigest::sha256(&self.luma);
            receipt.i420_sha256 = match i420.finalize() {
                Ok(bytes) => ContentDigest::new(fss_core::DigestAlgorithm::Sha256, bytes),
                // Unreachable for in-memory planes; the concatenated digest is still exact.
                Err(_) => ContentDigest::sha256(&[&self.luma[..], &self.cb, &self.cr].concat()),
            };
            receipt.cb_sha256 = ContentDigest::sha256(&self.cb);
            receipt.cr_sha256 = ContentDigest::sha256(&self.cr);
            receipt
        })
    }
    /// Zero-based retained segment (access unit) of this picture, without sealing the receipt.
    #[must_use]
    pub fn segment_index(&self) -> u64 {
        self.unsealed.segment_index
    }
    /// Original source capsule of this picture's segment.
    #[must_use]
    pub fn capsule(&self) -> &SensorCapsule {
        &self.unsealed.capsule
    }
    /// Digest of the retained capsule payload bound to this picture's segment.
    #[must_use]
    pub fn capsule_digest(&self) -> ContentDigest {
        self.unsealed.capsule_digest
    }
    /// Visible (cropped) luma width and height.
    #[must_use]
    pub fn dimensions(&self) -> [u32; 2] {
        [self.unsealed.width, self.unsealed.height]
    }
    /// Tight row-major Y plane of the visible picture (video range as coded, not RGB).
    #[must_use]
    pub fn pixels(&self) -> &[u8] {
        &self.luma
    }
    /// Portable binary PGM rendering of the luma plane.
    #[must_use]
    pub fn pgm_bytes(&self) -> Vec<u8> {
        let mut bytes = format!(
            "P5\n{} {}\n255\n",
            self.unsealed.width, self.unsealed.height
        )
        .into_bytes();
        bytes.extend_from_slice(&self.luma);
        bytes
    }
    /// Tight Cb plane, row stride `ceil(width / 2)` (video range as coded).
    #[must_use]
    pub fn cb(&self) -> &[u8] {
        &self.cb
    }
    /// Tight Cr plane, row stride `ceil(width / 2)` (video range as coded).
    #[must_use]
    pub fn cr(&self) -> &[u8] {
        &self.cr
    }
    /// Chroma plane width and height (`ceil(w/2)`, `ceil(h/2)`).
    #[must_use]
    pub fn chroma_dimensions(&self) -> [u32; 2] {
        [
            self.unsealed.width.div_ceil(2),
            self.unsealed.height.div_ceil(2),
        ]
    }
    /// Privacy mask binding applied to every plane of this frame.
    #[must_use]
    pub fn mask(&self) -> &MaskBinding {
        &self.mask
    }
    /// Packed RGB through the declared BT.601 limited-range transform
    /// ([`super::video_rgb::VIDEO_RGB_TRANSFORM`]), over the masked planes; masked pixels are
    /// then set to the fixed RGB fill.
    pub fn to_rgb(&self) -> Result<Vec<u8>, RecordedDecodeError> {
        let dimensions = [self.unsealed.width, self.unsealed.height];
        let mut rgb = super::video_rgb::i420_to_rgb(&self.luma, &self.cb, &self.cr, dimensions)?;
        self.mask.apply_rgb(&mut rgb, dimensions)?;
        Ok(rgb)
    }
}

/// NAL unit framing of a retained H.265 import's segments.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Framing {
    /// Annex-B start codes (`hevc`).
    AnnexB,
    /// MP4 sample (`mp4hevc`): NAL units behind big-endian length fields of this many bytes.
    LengthPrefixed(usize),
}

/// The NAL units of one retained segment. Length-prefixed framing was validated at import and
/// the segment bytes are digest-verified, so a framing failure is a custody inconsistency.
fn segment_nals(
    framing: Framing,
    bytes: &[u8],
    segment: usize,
) -> Result<Vec<&[u8]>, RecordedDecodeError> {
    match framing {
        Framing::AnnexB => Ok(annex_b_nal_units(bytes).collect()),
        Framing::LengthPrefixed(length) => {
            fss_container::demux::length_prefixed_nals(bytes, length)
                .map_err(|_| RecordedDecodeError::H265AccessUnit { segment })?
                .into_iter()
                .map(|range| {
                    bytes
                        .get(range)
                        .ok_or(RecordedDecodeError::H265AccessUnit { segment })
                })
                .collect()
        }
    }
}

/// `nal_unit_type` of every slice segment NAL unit in one retained access unit.
fn slice_segment_types(nals: &[&[u8]]) -> Vec<u8> {
    nals.iter()
        .filter_map(|nal| nal.first().map(|header| (header >> 1) & 0x3f))
        .filter(|nal_unit_type| *nal_unit_type <= 9 || (16..=21).contains(nal_unit_type))
        .collect()
}

/// Streaming decoder over one validated, IRAP-led, gap-free retained segment range.
#[derive(Debug)]
pub struct RecordedH265Range {
    request: RecordedH265Request,
    retained: RetainedFileImport,
    decoder: Decoder,
    framing: Framing,
    /// Verified custody chunks reused across the range's sequential segment reads.
    chunks: VerifiedChunkCache,
    next: usize,
    end: usize,
    decoded: u64,
    /// Sensor of the range's source capsules and its privacy mask, resolved once at open.
    sensor: SensorId,
    mask: MaskBinding,
    ready: VecDeque<Picture>,
    /// Segment of each decoded picture, indexed by the codec's decode index.
    coded_segments: Vec<usize>,
    /// Whether each decoded picture has been returned.
    seen: Vec<bool>,
    skipped: Vec<usize>,
    flushed: bool,
}

impl RecordedH265Range {
    /// Validates the request, the import, the range bounds and gaps, and that the first segment
    /// carries an IRAP picture. Reads only the first segment; decodes nothing yet.
    pub fn open(
        deployment: &ReferenceDeployment,
        request: RecordedH265Request,
        cx: &ReplayCx,
    ) -> Result<Self, RecordedDecodeError> {
        Self::open_bounded(deployment, request, cx, MAX_H265_RANGE_SEGMENTS, None)
    }

    /// [`Self::open`] with cumulative encoded-byte and coded-luma-capacity admission accounting.
    /// The same budget must accompany every [`Self::next_frame_with_budget`] call.
    pub fn open_with_budget(
        deployment: &ReferenceDeployment,
        request: RecordedH265Request,
        budget: &mut RecordedVideoDecodeBudget,
        cx: &ReplayCx,
    ) -> Result<Self, RecordedDecodeError> {
        Self::open_bounded(
            deployment,
            request,
            cx,
            MAX_H265_RANGE_SEGMENTS,
            Some(budget),
        )
    }

    /// [`Self::open`] for whole-recording streaming analysis: up to
    /// [`MAX_H265_STREAM_SEGMENTS`] segments, decoded one access unit at a time with the same
    /// custody, mask and refusal semantics. Memory grows only with per-segment bookkeeping.
    pub fn open_stream(
        deployment: &ReferenceDeployment,
        request: RecordedH265Request,
        cx: &ReplayCx,
    ) -> Result<Self, RecordedDecodeError> {
        Self::open_bounded(deployment, request, cx, MAX_H265_STREAM_SEGMENTS, None)
    }

    fn open_bounded(
        deployment: &ReferenceDeployment,
        request: RecordedH265Request,
        cx: &ReplayCx,
        maximum_segments: usize,
        mut budget: Option<&mut RecordedVideoDecodeBudget>,
    ) -> Result<Self, RecordedDecodeError> {
        checkpoint(cx, "recorded_h265:open")?;
        if request.interpretation != ComponentInterpretation::YCbCr {
            return Err(RecordedDecodeError::InterpretationMismatch);
        }
        if request.segment_count == 0 || request.segment_count > maximum_segments {
            return Err(RecordedDecodeError::Limit);
        }
        let retained =
            RetainedFileImport::open(deployment, request.import_identity, request.read_limits, cx)?;
        let (framing, parameter_sets) = match retained.manifest().format.as_str() {
            "hevc" => (Framing::AnnexB, Vec::new()),
            format @ ("mp4hevc" | "mkvhevc") => {
                let prefix = if format == "mp4hevc" {
                    MP4_HEVC_PARAMETER_SET_REASON_PREFIX
                } else {
                    MKV_HEVC_PARAMETER_SET_REASON_PREFIX
                };
                let (spans, length) = super::mp4_parameter_sets(&retained, prefix)?;
                (Framing::LengthPrefixed(length), spans)
            }
            _ => return Err(RecordedDecodeError::UnsupportedMedia),
        };
        let first = request.first_segment;
        let end = first
            .checked_add(request.segment_count)
            .ok_or(RecordedDecodeError::Limit)?;
        let spans = &retained.manifest().segment_spans;
        if end > spans.len() {
            return Err(RecordedDecodeError::Unavailable);
        }
        if let Some(span) = spans[first + 1..end].iter().find(|span| span.gap_before) {
            return Err(RecordedDecodeError::H265SourceGap {
                segment: span.segment_index,
            });
        }
        let mut chunks = VerifiedChunkCache::default();
        let first_bytes = retained.read_segment_cached(
            deployment,
            first,
            request.read_limits,
            cx,
            &mut chunks,
        )?;
        let first_types = slice_segment_types(&segment_nals(framing, &first_bytes, first)?);
        if first_types.is_empty() || !first_types.iter().all(|t| (16..=21).contains(t)) {
            return Err(RecordedDecodeError::H265RangeNotIrap { segment: first });
        }
        let limits = DecoderLimits {
            max_pictures: request
                .decoder_limits
                .max_pictures
                .min(request.segment_count as u64),
            ..request.decoder_limits
        };
        let mut decoder = Decoder::new(limits)?;
        // Out-of-band configuration precedes the first access unit; it codes no picture.
        for index in parameter_sets {
            let nal = retained.read_omission_span(deployment, index, request.read_limits, cx)?;
            if let Some(budget) = budget.as_deref_mut() {
                budget.reserve(nal.len(), 0, cx)?;
            }
            checkpoint(cx, "recorded_h265:parameter_set")?;
            if decoder.decode_nal(&nal)?.is_some() {
                return Err(RecordedDecodeError::CustodyMismatch);
            }
        }
        let (first_capsule, _) = source_capsule(deployment, &retained, first)?;
        let sensor = first_capsule.sensor_id;
        let mask = current_mask(deployment, &sensor)?;
        Ok(Self {
            request,
            retained,
            decoder,
            framing,
            chunks,
            next: first,
            end,
            decoded: 0,
            sensor,
            mask,
            ready: VecDeque::new(),
            coded_segments: Vec::new(),
            seen: Vec::new(),
            skipped: Vec::new(),
            flushed: false,
        })
    }

    /// Retained import this range reads.
    #[must_use]
    pub fn retained(&self) -> &RetainedFileImport {
        &self.retained
    }

    /// Custody chunk bytes this range has read and verified so far.
    #[must_use]
    pub const fn chunk_bytes_read(&self) -> u64 {
        self.chunks.chunk_bytes_read()
    }

    /// Privacy mask binding applied to every frame of this range.
    #[must_use]
    pub fn mask(&self) -> &MaskBinding {
        &self.mask
    }

    /// Pictures returned so far in this range.
    #[must_use]
    pub fn decoded(&self) -> u64 {
        self.decoded
    }

    /// Next access unit to feed the codec, which can be ahead of returned display pictures.
    #[must_use]
    pub const fn next_source_segment(&self) -> usize {
        self.next
    }

    /// Segments read so far whose RASL picture the codec skipped because the range starts a new
    /// coded video sequence at a CRA or BLA picture. They yield no frame.
    #[must_use]
    pub fn skipped_rasl_segments(&self) -> &[usize] {
        &self.skipped
    }

    /// Returns the next picture in display order, decoding further access units as needed.
    /// Returns `Ok(None)` once every picture of the range has been returned. Any refusal ends
    /// the range (the codec then waits for an IRAP picture); frames already returned stay valid.
    pub fn next_frame(
        &mut self,
        deployment: &ReferenceDeployment,
        cx: &ReplayCx,
    ) -> Result<Option<RecordedH265Frame>, RecordedDecodeError> {
        self.next_frame_bounded(deployment, None, cx)
    }

    /// [`Self::next_frame`] reserving each access unit before decoding, including decode-ahead
    /// and skipped RASL inputs. Returned frames and reservations survive a later refusal.
    pub fn next_frame_with_budget(
        &mut self,
        deployment: &ReferenceDeployment,
        budget: &mut RecordedVideoDecodeBudget,
        cx: &ReplayCx,
    ) -> Result<Option<RecordedH265Frame>, RecordedDecodeError> {
        self.next_frame_bounded(deployment, Some(budget), cx)
    }

    fn next_frame_bounded(
        &mut self,
        deployment: &ReferenceDeployment,
        mut budget: Option<&mut RecordedVideoDecodeBudget>,
        cx: &ReplayCx,
    ) -> Result<Option<RecordedH265Frame>, RecordedDecodeError> {
        loop {
            if let Some(picture) = self.ready.pop_front() {
                return self.frame(deployment, picture, cx).map(Some);
            }
            if self.flushed {
                if let Some(missing) = self.seen.iter().position(|seen| !seen) {
                    // A decoded picture that was never output (pic_output_flag 0).
                    return Err(RecordedDecodeError::H265AccessUnit {
                        segment: self.coded_segments[missing],
                    });
                }
                return Ok(None);
            }
            if self.next < self.end {
                self.decode_segment(deployment, budget.as_deref_mut(), cx)?;
            } else {
                self.ready.extend(self.decoder.finish()?);
                self.flushed = true;
            }
        }
    }

    /// Feeds one retained access unit and accounts for the picture it completed or skipped.
    fn decode_segment(
        &mut self,
        deployment: &ReferenceDeployment,
        budget: Option<&mut RecordedVideoDecodeBudget>,
        cx: &ReplayCx,
    ) -> Result<(), RecordedDecodeError> {
        let index = self.next;
        checkpoint(cx, STAGE_RECORDED_H265_SEGMENT)?;
        let bytes = self.retained.read_segment_cached(
            deployment,
            index,
            self.request.read_limits,
            cx,
            &mut self.chunks,
        )?;
        if let Some(budget) = budget {
            budget.reserve(
                bytes.len(),
                self.request.decoder_limits.max_luma_samples,
                cx,
            )?;
        }
        let before = self.decoder.pictures_decoded();
        let nals = segment_nals(self.framing, &bytes, index)?;
        for nal in &nals {
            checkpoint(cx, "recorded_h265:nal")?;
            if let Some(picture) = self.decoder.decode_nal(nal)? {
                self.ready.push_back(picture);
            }
            while let Some(picture) = self.decoder.next_output() {
                self.ready.push_back(picture);
            }
        }
        match self.decoder.pictures_decoded().checked_sub(before) {
            Some(1) => {
                self.coded_segments.push(index);
                self.seen.push(false);
            }
            Some(0) => {
                let types = slice_segment_types(&nals);
                // Only RASL pictures of the range's leading CRA/BLA are ever skipped; the codec
                // decides, this module only refuses to call anything else a skip.
                if index == self.request.first_segment
                    || types.is_empty()
                    || !types.iter().all(|t| matches!(t, 8 | 9))
                {
                    return Err(RecordedDecodeError::H265AccessUnit { segment: index });
                }
                self.skipped.push(index);
            }
            _ => return Err(RecordedDecodeError::H265AccessUnit { segment: index }),
        }
        self.next += 1;
        Ok(())
    }

    /// Binds one output picture to the retained segment that coded it.
    fn frame(
        &mut self,
        deployment: &ReferenceDeployment,
        picture: Picture,
        cx: &ReplayCx,
    ) -> Result<RecordedH265Frame, RecordedDecodeError> {
        let first = self.request.first_segment;
        let unbound = RecordedDecodeError::H265AccessUnit {
            segment: self.end - 1,
        };
        let Some(index) = usize::try_from(picture.decode_index())
            .ok()
            .and_then(|offset| {
                self.coded_segments
                    .get(offset)
                    .map(|index| (offset, *index))
            })
        else {
            return Err(unbound);
        };
        let (offset, index) = index;
        let seen = self
            .seen
            .get_mut(offset)
            .ok_or(RecordedDecodeError::H265AccessUnit { segment: index })?;
        if *seen {
            return Err(RecordedDecodeError::H265AccessUnit { segment: index });
        }
        *seen = true;
        if index == first && !picture.is_irap() {
            return Err(RecordedDecodeError::H265RangeNotIrap { segment: index });
        }
        let (capsule, capsule_digest) = source_capsule(deployment, &self.retained, index)?;
        if capsule.sensor_id != self.sensor {
            return Err(RecordedDecodeError::InvalidReceipt);
        }
        let span = &self.retained.manifest().segment_spans[index];
        // Mask every plane before any digest is taken or any consumer sees the pixels.
        let dimensions = [picture.width(), picture.height()];
        let mut luma = picture.luma().to_vec();
        let mut cb = picture.cb().to_vec();
        let mut cr = picture.cr().to_vec();
        self.mask.apply_luma(&mut luma, dimensions)?;
        self.mask.apply_chroma420(&mut cb, &mut cr, dimensions)?;
        // Plane digests are sealed lazily from these exact planes (see `RecordedH265Frame`).
        let placeholder = ContentDigest::sha256(&[]);
        let unsealed = RecordedH265FrameReceipt {
            import_identity: self.retained.import_identity(),
            import_root: self.retained.import_root(),
            manifest_digest: self.retained.manifest_digest(),
            range_start: first as u64,
            segment_index: index as u64,
            source_offset: span.offset,
            capsule_digest,
            capsule,
            width: picture.width(),
            height: picture.height(),
            nal_unit_type: picture.nal_unit_type(),
            picture_order_count: picture.poc(),
            decode_index: picture.decode_index(),
            luma_sha256: placeholder,
            i420_sha256: placeholder,
            cb_sha256: placeholder,
            cr_sha256: placeholder,
            mask_policy: self.mask.policy_digest(),
        };
        self.decoded += 1;
        checkpoint(cx, "recorded_h265:decoded")?;
        Ok(RecordedH265Frame {
            output_index: self.decoded - 1,
            range_segment_count: self.request.segment_count,
            unsealed,
            receipt: std::sync::OnceLock::new(),
            luma,
            cb,
            cr,
            mask: self.mask.clone(),
        })
    }
}

/// Decodes the whole range and returns every frame in display order, or the first refusal.
pub fn decode_h265_range(
    deployment: &ReferenceDeployment,
    request: RecordedH265Request,
    cx: &ReplayCx,
) -> Result<Vec<RecordedH265Frame>, RecordedDecodeError> {
    let mut range = RecordedH265Range::open(deployment, request, cx)?;
    let mut frames = Vec::new();
    while let Some(frame) = range.next_frame(deployment, cx)? {
        frames.push(frame);
    }
    Ok(frames)
}

#[cfg(test)]
mod tests;
