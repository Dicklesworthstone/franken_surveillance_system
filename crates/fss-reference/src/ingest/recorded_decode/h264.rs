#![forbid(unsafe_code)]
//! H.264 decoding (Constrained Baseline, Main and High, progressive 8-bit 4:2:0) of retained
//! Annex-B (`annexb`) and indexed MP4 (`mp4avc`) imports.
//!
//! The file adapter retains one access unit per segment: an Annex-B access unit, or one MP4
//! sample with its original length-prefixed NAL framing. An MP4 range first feeds the decoder
//! the import's retained `avcC` parameter-set spans, read back verbatim from custody. H.264 pictures predict from earlier
//! pictures, so a single P segment has no meaning on its own: this module decodes a contiguous
//! segment range that must begin at an IDR access unit and must not cross a retained source
//! gap. Pictures are returned in display (output) order, which differs from decode order when
//! the stream uses B-frames; each picture is mapped back to the segment that coded it through
//! the codec's decode index, and the range must yield exactly one picture per access unit.
//! Every picture is bound to the same custody the JPEG path uses (import identity, root,
//! manifest, source capsule) and to the exact codec output (luma and packed I420 digests).
//! Frames also carry both chroma planes (`cb`, `cr`, per-plane digests on the receipt) and convert
//! to RGB through the declared transform in [`super::video_rgb`].
//!
//! Unlike [`super::RecordedFrame`], these frames are a rebuildable derivation: nothing is staged,
//! published or appended to the ledger. Reproducing a frame means decoding the same retained
//! range again; the pure-Rust codec is deterministic and bit-exact against the FFmpeg oracle
//! fixtures. The codec, not this module, owns all H.264 semantics and refusals.

pub use fss_codec_h264::{DecodeError as H264DecodeError, DecoderLimits, UnsupportedFeature};
use fss_codec_h264::{Decoder, Picture, annex_b_nal_units};
use fss_core::{CanonicalEncode, CanonicalEncoder, ContentDigest, SensorCapsule, SensorId};

use super::video_budget::RecordedVideoDecodeBudget;
use super::{ComponentInterpretation, RecordedDecodeError, checkpoint, source_capsule};
use crate::ingest::privacy_mask::{MaskBinding, binding_digest, current_mask, encode_marker};
use crate::ingest::retained::SourceReadBudget;
use crate::ingest::{
    MKV_PARAMETER_SET_REASON_PREFIX, MP4_PARAMETER_SET_REASON_PREFIX, RetainedFileImport,
    RetainedReadLimits, VerifiedChunkCache,
};
use crate::{ReferenceDeployment, ReplayCx};

/// Maximum access units decoded by one range request.
pub const MAX_H264_RANGE_SEGMENTS: usize = 1024;
/// Maximum access units of one streaming range ([`RecordedH264Range::open_stream`]), the
/// long-dwell whole-recording bound.
pub const MAX_H264_STREAM_SEGMENTS: usize = 65_536;
/// Versioned label of the canonical decoder semantics bound into every frame receipt.
pub const H264_DECODER_LABEL: &str =
    "fss-codec-h264:baseline-main-high-progressive-420:scalar-reference:output-order:v2";
/// Canonical frame-receipt domain.
pub const H264_FRAME_RECEIPT_DOMAIN: &str = "fss.recorded_h264_frame_receipt.v2";
/// Boundary before each retained access unit is read and decoded.
pub const STAGE_RECORDED_H264_SEGMENT: &str = "recorded_h264:segment";

const NAL_IDR_SLICE: u8 = 5;

/// Identity of [`H264_DECODER_LABEL`]; a semantics label, not a hash of compiled code.
#[must_use]
pub fn h264_decoder_identity() -> ContentDigest {
    ContentDigest::sha256(H264_DECODER_LABEL.as_bytes())
}

/// Explicit retained source range, interpretation, and independent read/decode bounds.
#[derive(Clone, Debug)]
pub struct RecordedH264Request {
    /// Exact completed Annex-B import.
    pub import_identity: ContentDigest,
    /// First zero-based segment; it must hold an IDR access unit.
    pub first_segment: usize,
    /// Number of contiguous segments, from one through [`MAX_H264_RANGE_SEGMENTS`].
    pub segment_count: usize,
    /// Must be [`ComponentInterpretation::YCbCr`]; every admitted H.264 profile is 4:2:0.
    pub interpretation: ComponentInterpretation,
    /// Custody-read ceilings for each retained access unit.
    pub read_limits: RetainedReadLimits,
    /// Codec ceilings. `max_pictures` is narrowed to `segment_count` before decoding.
    pub decoder_limits: DecoderLimits,
}

/// Source-to-pixels provenance of one decoded H.264 picture.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecordedH264FrameReceipt {
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
    idr: bool,
    decode_index: u64,
    luma_sha256: ContentDigest,
    i420_sha256: ContentDigest,
    // Plane digests are exposed for audit but not encoded: the encoded I420 digest already
    // binds both chroma planes, so receipt bytes stay identical to the luma-era receipts.
    cb_sha256: ContentDigest,
    cr_sha256: ContentDigest,
    mask_policy: Option<ContentDigest>,
}

impl RecordedH264FrameReceipt {
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
    /// IDR segment the decoder state was started from.
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
    /// Visible (cropped) luma width and height.
    #[must_use]
    pub fn dimensions(&self) -> [u32; 2] {
        [self.width, self.height]
    }
    /// Whether this picture is an IDR picture.
    #[must_use]
    pub fn is_idr(&self) -> bool {
        self.idr
    }
    /// Zero-based decode order within the requested range.
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
        encoder.text(H264_FRAME_RECEIPT_DOMAIN);
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
        encoder.bool(self.idr);
        encoder.u64(self.decode_index);
        encoder.digest(self.luma_sha256);
        encoder.digest(self.i420_sha256);
        encoder.digest(h264_decoder_identity());
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
/// [`Self::receipt`] call, not for every decoded picture: frame consumers that never read a
/// receipt (streaming analysis, skipped frames) do not hash pictures. The sealed receipt is a
/// pure function of the frame, so it is identical whenever it is computed.
#[derive(Clone, Debug)]
pub struct RecordedH264Frame {
    /// Sealed range-output position; source segment indices themselves are decode order.
    output_index: u64,
    range_segment_count: usize,
    /// Receipt fields fixed when the picture is bound; its four plane-digest slots hold
    /// placeholders that are never exposed (sealing replaces every one).
    unsealed: RecordedH264FrameReceipt,
    receipt: std::sync::OnceLock<RecordedH264FrameReceipt>,
    luma: Vec<u8>,
    cb: Vec<u8>,
    cr: Vec<u8>,
    mask: MaskBinding,
}

impl PartialEq for RecordedH264Frame {
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
impl Eq for RecordedH264Frame {}

impl RecordedH264Frame {
    /// Zero-based position returned by this range in codec display order.
    #[must_use]
    pub const fn output_index(&self) -> u64 {
        self.output_index
    }
    /// Exact requested range length; continuation must reconstruct this range's decoder state.
    #[must_use]
    pub const fn range_segment_count(&self) -> usize {
        self.range_segment_count
    }
    /// Source and codec provenance (plane digests computed on first use).
    #[must_use]
    pub fn receipt(&self) -> &RecordedH264FrameReceipt {
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

/// NAL unit framing of a retained H.264 import's segments.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Framing {
    /// Annex-B start codes.
    AnnexB,
    /// MP4 sample: NAL units behind big-endian length fields of this many bytes.
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
                .map_err(|_| RecordedDecodeError::H264AccessUnit { segment })?
                .into_iter()
                .map(|range| {
                    bytes
                        .get(range)
                        .ok_or(RecordedDecodeError::H264AccessUnit { segment })
                })
                .collect()
        }
    }
}

fn segment_has_idr_slice(nals: &[&[u8]]) -> bool {
    nals.iter()
        .any(|nal| nal.first().is_some_and(|h| h & 0x1f == NAL_IDR_SLICE))
}

/// Streaming decoder over one validated, IDR-led, gap-free retained segment range.
#[derive(Debug)]
pub struct RecordedH264Range {
    request: RecordedH264Request,
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
    ready: std::collections::VecDeque<Picture>,
    seen: Vec<bool>,
    flushed: bool,
}

impl RecordedH264Range {
    /// Validates the request, the import, the range bounds and gaps, and that the first segment
    /// carries an IDR slice. Reads only the first segment; decodes nothing yet.
    pub fn open(
        deployment: &ReferenceDeployment,
        request: RecordedH264Request,
        cx: &ReplayCx,
    ) -> Result<Self, RecordedDecodeError> {
        Self::open_bounded(deployment, request, cx, MAX_H264_RANGE_SEGMENTS, None, None)
    }

    /// [`Self::open`] with cumulative encoded-byte and coded-luma-capacity admission accounting.
    /// The same budget must accompany every [`Self::next_frame_with_budget`] call.
    pub fn open_with_budget(
        deployment: &ReferenceDeployment,
        request: RecordedH264Request,
        budget: &mut RecordedVideoDecodeBudget,
        cx: &ReplayCx,
    ) -> Result<Self, RecordedDecodeError> {
        Self::open_bounded(
            deployment,
            request,
            cx,
            MAX_H264_RANGE_SEGMENTS,
            Some(budget),
            None,
        )
    }

    /// [`Self::open`] for whole-recording streaming analysis: up to
    /// [`MAX_H264_STREAM_SEGMENTS`] segments, decoded one access unit at a time with the same
    /// custody, mask and refusal semantics. Memory grows only with per-segment bookkeeping.
    pub fn open_stream(
        deployment: &ReferenceDeployment,
        request: RecordedH264Request,
        cx: &ReplayCx,
    ) -> Result<Self, RecordedDecodeError> {
        Self::open_bounded(
            deployment,
            request,
            cx,
            MAX_H264_STREAM_SEGMENTS,
            None,
            None,
        )
    }

    /// Whole-recording source-read admission shared across all recovery ranges.
    pub(crate) fn open_stream_with_source_budget(
        deployment: &ReferenceDeployment,
        request: RecordedH264Request,
        source_budget: &SourceReadBudget,
        cx: &ReplayCx,
    ) -> Result<Self, RecordedDecodeError> {
        Self::open_bounded(
            deployment,
            request,
            cx,
            MAX_H264_STREAM_SEGMENTS,
            None,
            Some(source_budget),
        )
    }

    fn open_bounded(
        deployment: &ReferenceDeployment,
        request: RecordedH264Request,
        cx: &ReplayCx,
        maximum_segments: usize,
        mut budget: Option<&mut RecordedVideoDecodeBudget>,
        source_budget: Option<&SourceReadBudget>,
    ) -> Result<Self, RecordedDecodeError> {
        checkpoint(cx, "recorded_h264:open")?;
        if request.interpretation != ComponentInterpretation::YCbCr {
            return Err(RecordedDecodeError::InterpretationMismatch);
        }
        if request.segment_count == 0 || request.segment_count > maximum_segments {
            return Err(RecordedDecodeError::Limit);
        }
        let retained =
            RetainedFileImport::open(deployment, request.import_identity, request.read_limits, cx)?;
        let (framing, parameter_sets) = match retained.manifest().format.as_str() {
            "annexb" => (Framing::AnnexB, Vec::new()),
            format @ ("mp4avc" | "mkvavc") => {
                let prefix = if format == "mp4avc" {
                    MP4_PARAMETER_SET_REASON_PREFIX
                } else {
                    MKV_PARAMETER_SET_REASON_PREFIX
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
            return Err(RecordedDecodeError::H264SourceGap {
                segment: span.segment_index,
            });
        }
        let mut chunks = VerifiedChunkCache::with_source_budget(source_budget);
        let first_bytes = retained.read_segment_cached(
            deployment,
            first,
            request.read_limits,
            cx,
            &mut chunks,
        )?;
        if !segment_has_idr_slice(&segment_nals(framing, &first_bytes, first)?) {
            return Err(RecordedDecodeError::H264RangeNotIdr { segment: first });
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
            let nal = retained.read_omission_span_budgeted(
                deployment,
                index,
                request.read_limits,
                cx,
                source_budget,
            )?;
            if let Some(budget) = budget.as_deref_mut() {
                budget.reserve(nal.len(), 0, cx)?;
            }
            checkpoint(cx, "recorded_h264:parameter_set")?;
            if decoder.decode_nal(&nal)?.is_some() {
                return Err(RecordedDecodeError::CustodyMismatch);
            }
        }
        let (first_capsule, _) = source_capsule(deployment, &retained, first)?;
        let sensor = first_capsule.sensor_id;
        let mask = current_mask(deployment, &sensor)?;
        let seen = vec![false; request.segment_count];
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
            ready: std::collections::VecDeque::new(),
            seen,
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

    /// Pictures decoded so far in this range.
    #[must_use]
    pub fn decoded(&self) -> u64 {
        self.decoded
    }

    /// Next access unit to feed the codec, which can be ahead of returned display pictures.
    #[must_use]
    pub const fn next_source_segment(&self) -> usize {
        self.next
    }

    /// Returns the next picture in display order, decoding further access units as needed.
    /// Returns `Ok(None)` once every picture of the range has been returned. Any refusal ends
    /// the range (the codec then waits for an IDR); frames already returned stay valid.
    pub fn next_frame(
        &mut self,
        deployment: &ReferenceDeployment,
        cx: &ReplayCx,
    ) -> Result<Option<RecordedH264Frame>, RecordedDecodeError> {
        self.next_frame_bounded(deployment, None, cx)
    }

    /// [`Self::next_frame`] reserving each access unit before decoding, including decode-ahead
    /// for B pictures. Returned frames and consumed reservations survive a later refusal.
    pub fn next_frame_with_budget(
        &mut self,
        deployment: &ReferenceDeployment,
        budget: &mut RecordedVideoDecodeBudget,
        cx: &ReplayCx,
    ) -> Result<Option<RecordedH264Frame>, RecordedDecodeError> {
        self.next_frame_bounded(deployment, Some(budget), cx)
    }

    fn next_frame_bounded(
        &mut self,
        deployment: &ReferenceDeployment,
        mut budget: Option<&mut RecordedVideoDecodeBudget>,
        cx: &ReplayCx,
    ) -> Result<Option<RecordedH264Frame>, RecordedDecodeError> {
        loop {
            if let Some(picture) = self.ready.pop_front() {
                return self.frame(deployment, picture, cx).map(Some);
            }
            if self.flushed {
                if let Some(missing) = self.seen.iter().position(|seen| !seen) {
                    return Err(RecordedDecodeError::H264AccessUnit {
                        segment: self.request.first_segment + missing,
                    });
                }
                return Ok(None);
            }
            if self.next < self.end {
                let index = self.next;
                checkpoint(cx, STAGE_RECORDED_H264_SEGMENT)?;
                let bytes = self.retained.read_segment_cached(
                    deployment,
                    index,
                    self.request.read_limits,
                    cx,
                    &mut self.chunks,
                )?;
                if let Some(budget) = budget.as_deref_mut() {
                    budget.reserve(
                        bytes.len(),
                        u64::from(self.request.decoder_limits.max_macroblocks) * 256,
                        cx,
                    )?;
                }
                for nal in segment_nals(self.framing, &bytes, index)? {
                    checkpoint(cx, "recorded_h264:nal")?;
                    if let Some(picture) = self.decoder.decode_nal(nal)? {
                        self.ready.push_back(picture);
                    }
                    while let Some(picture) = self.decoder.next_output() {
                        self.ready.push_back(picture);
                    }
                }
                self.next += 1;
            } else {
                self.ready.extend(self.decoder.finish()?);
                self.flushed = true;
            }
        }
    }

    /// Binds one output picture to the retained segment that coded it.
    fn frame(
        &mut self,
        deployment: &ReferenceDeployment,
        picture: Picture,
        cx: &ReplayCx,
    ) -> Result<RecordedH264Frame, RecordedDecodeError> {
        let first = self.request.first_segment;
        let offset = usize::try_from(picture.decode_index()).map_err(|_| {
            RecordedDecodeError::H264AccessUnit {
                segment: self.end - 1,
            }
        })?;
        let index = first
            .checked_add(offset)
            .filter(|index| *index < self.end)
            .ok_or(RecordedDecodeError::H264AccessUnit {
                segment: self.end - 1,
            })?;
        let seen = self
            .seen
            .get_mut(offset)
            .ok_or(RecordedDecodeError::H264AccessUnit { segment: index })?;
        if *seen {
            return Err(RecordedDecodeError::H264AccessUnit { segment: index });
        }
        *seen = true;
        if index == first && !picture.is_idr() {
            return Err(RecordedDecodeError::H264RangeNotIdr { segment: index });
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
        // Plane digests are sealed lazily from these exact planes (see `RecordedH264Frame`).
        let placeholder = ContentDigest::sha256(&[]);
        let unsealed = RecordedH264FrameReceipt {
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
            idr: picture.is_idr(),
            decode_index: picture.decode_index(),
            luma_sha256: placeholder,
            i420_sha256: placeholder,
            cb_sha256: placeholder,
            cr_sha256: placeholder,
            mask_policy: self.mask.policy_digest(),
        };
        self.decoded += 1;
        checkpoint(cx, "recorded_h264:decoded")?;
        Ok(RecordedH264Frame {
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
pub fn decode_h264_range(
    deployment: &ReferenceDeployment,
    request: RecordedH264Request,
    cx: &ReplayCx,
) -> Result<Vec<RecordedH264Frame>, RecordedDecodeError> {
    let mut range = RecordedH264Range::open(deployment, request, cx)?;
    let mut frames = Vec::new();
    while let Some(frame) = range.next_frame(deployment, cx)? {
        frames.push(frame);
    }
    Ok(frames)
}

#[cfg(test)]
mod tests;
