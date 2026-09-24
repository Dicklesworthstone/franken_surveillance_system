#![forbid(unsafe_code)]
//! H.264 decoding (Constrained Baseline, Main and High, progressive 8-bit 4:2:0) of retained
//! Annex-B imports.
//!
//! The file adapter retains one access unit per segment. H.264 pictures predict from earlier
//! pictures, so a single P segment has no meaning on its own: this module decodes a contiguous
//! segment range that must begin at an IDR access unit and must not cross a retained source
//! gap. Pictures are returned in display (output) order, which differs from decode order when
//! the stream uses B-frames; each picture is mapped back to the segment that coded it through
//! the codec's decode index, and the range must yield exactly one picture per access unit.
//! Every picture is bound to the same custody the JPEG path uses (import identity, root,
//! manifest, source capsule) and to the exact codec output (luma and packed I420 digests).
//!
//! Unlike [`super::RecordedFrame`], these frames are a rebuildable derivation: nothing is staged,
//! published or appended to the ledger. Reproducing a frame means decoding the same retained
//! range again; the pure-Rust codec is deterministic and bit-exact against the FFmpeg oracle
//! fixtures. The codec, not this module, owns all H.264 semantics and refusals.

pub use fss_codec_h264::{DecodeError as H264DecodeError, DecoderLimits, UnsupportedFeature};
use fss_codec_h264::{Decoder, Picture, annex_b_nal_units};
use fss_core::{CanonicalEncode, CanonicalEncoder, ContentDigest, SensorCapsule};

use super::{ComponentInterpretation, RecordedDecodeError, checkpoint, source_capsule};
use crate::ingest::{RetainedFileImport, RetainedReadLimits};
use crate::{ReferenceDeployment, ReplayCx};

/// Maximum access units decoded by one range request.
pub const MAX_H264_RANGE_SEGMENTS: usize = 1024;
/// Versioned label of the canonical decoder semantics bound into every frame receipt.
pub const H264_DECODER_LABEL: &str =
    "fss-codec-h264:baseline-main-high-progressive-420:scalar-reference:output-order:v2";
/// Canonical frame-receipt domain.
pub const H264_FRAME_RECEIPT_DOMAIN: &str = "fss.recorded_h264_frame_receipt.v1";
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
        encoder.finish()
    }
    /// Content address of [`Self::encoded`].
    #[must_use]
    pub fn digest(&self) -> ContentDigest {
        ContentDigest::sha256(&self.encoded())
    }
}

/// One complete decoded picture; unsuccessful decoding never yields partial pixels.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecordedH264Frame {
    receipt: RecordedH264FrameReceipt,
    luma: Vec<u8>,
}

impl RecordedH264Frame {
    /// Source and codec provenance.
    #[must_use]
    pub fn receipt(&self) -> &RecordedH264FrameReceipt {
        &self.receipt
    }
    /// Tight row-major Y plane of the visible picture (video range as coded, not RGB).
    #[must_use]
    pub fn pixels(&self) -> &[u8] {
        &self.luma
    }
    /// Portable binary PGM rendering of the luma plane.
    #[must_use]
    pub fn pgm_bytes(&self) -> Vec<u8> {
        let mut bytes =
            format!("P5\n{} {}\n255\n", self.receipt.width, self.receipt.height).into_bytes();
        bytes.extend_from_slice(&self.luma);
        bytes
    }
}

fn segment_has_idr_slice(bytes: &[u8]) -> bool {
    annex_b_nal_units(bytes).any(|nal| nal.first().is_some_and(|h| h & 0x1f == NAL_IDR_SLICE))
}

/// Streaming decoder over one validated, IDR-led, gap-free retained segment range.
#[derive(Debug)]
pub struct RecordedH264Range {
    request: RecordedH264Request,
    retained: RetainedFileImport,
    decoder: Decoder,
    next: usize,
    end: usize,
    decoded: u64,
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
        checkpoint(cx, "recorded_h264:open")?;
        if request.interpretation != ComponentInterpretation::YCbCr {
            return Err(RecordedDecodeError::InterpretationMismatch);
        }
        if request.segment_count == 0 || request.segment_count > MAX_H264_RANGE_SEGMENTS {
            return Err(RecordedDecodeError::Limit);
        }
        let retained =
            RetainedFileImport::open(deployment, request.import_identity, request.read_limits, cx)?;
        if retained.manifest().format != "annexb" {
            return Err(RecordedDecodeError::UnsupportedMedia);
        }
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
        let first_bytes = retained.read_segment(deployment, first, request.read_limits, cx)?;
        if !segment_has_idr_slice(&first_bytes) {
            return Err(RecordedDecodeError::H264RangeNotIdr { segment: first });
        }
        let limits = DecoderLimits {
            max_pictures: request
                .decoder_limits
                .max_pictures
                .min(request.segment_count as u64),
            ..request.decoder_limits
        };
        let decoder = Decoder::new(limits)?;
        Ok(Self {
            request,
            retained,
            decoder,
            next: first,
            end,
            decoded: 0,
            ready: std::collections::VecDeque::new(),
            seen: vec![false; request.segment_count],
            flushed: false,
        })
    }

    /// Retained import this range reads.
    #[must_use]
    pub fn retained(&self) -> &RetainedFileImport {
        &self.retained
    }

    /// Pictures decoded so far in this range.
    #[must_use]
    pub fn decoded(&self) -> u64 {
        self.decoded
    }

    /// Returns the next picture in display order, decoding further access units as needed.
    /// Returns `Ok(None)` once every picture of the range has been returned. Any refusal ends
    /// the range (the codec then waits for an IDR); frames already returned stay valid.
    pub fn next_frame(
        &mut self,
        deployment: &ReferenceDeployment,
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
                let bytes =
                    self.retained
                        .read_segment(deployment, index, self.request.read_limits, cx)?;
                for nal in annex_b_nal_units(&bytes) {
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
        let span = &self.retained.manifest().segment_spans[index];
        let receipt = RecordedH264FrameReceipt {
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
            luma_sha256: ContentDigest::sha256(picture.luma()),
            i420_sha256: ContentDigest::sha256(&picture.to_i420()),
        };
        self.decoded += 1;
        checkpoint(cx, "recorded_h264:decoded")?;
        Ok(RecordedH264Frame {
            receipt,
            luma: picture.luma().to_vec(),
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
