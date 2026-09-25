#![forbid(unsafe_code)]
//! Decode refusals as typed coverage gaps (fss-fnrgr follow-up), opt-in only.
//!
//! By default a typed decode refusal anywhere in a recorded range refuses the whole analysis.
//! When the operator opts in (`fss-event watch --tolerate-decode-refusals`), this source instead
//! turns a mid-recording refusal into an explicit gap and keeps decoding what is decodable:
//!
//! * JPEG/MJPEG frames are independent: a refused frame (malformed, truncated or unsupported
//!   coding) is one refused segment and the next frame decodes normally.
//! * H.264 and H.265 are inter-predicted: after a refusal (corrupt access unit, unsupported slice,
//!   missing reference, picture never completed) nothing may be concealed, so decoding restarts at
//!   the next segment that opens as an IDR (H.264) or IRAP (H.265) range. Every segment between
//!   the refusal and that restart that did not return a picture is refused.
//! * A retained source gap inside the range is treated the same way: MJPEG resumes at the next
//!   frame; H.264/H.265 resume at the next IDR/IRAP at or after the gap.
//!
//! Each discontinuity is reported as a [`TolerantItem::Break`] (with the refused segments and the
//! registered error id when segments were lost) so the caller can reset tracking: no track is
//! ever bridged across a gap. Resource limits, budget exhaustion, cancellation and custody
//! failures are never tolerated; they refuse the analysis exactly as before. A range in which no
//! frame decodes at all returns its first refusal.
//!
//! Every frame that does decode is served exactly as by the default sources: the sensor's
//! current retained privacy mask ([`super::privacy_mask`], resolved once at open from the first
//! segment's capsule) is applied to MJPEG luma here, and the H.264/H.265 ranges apply it
//! themselves. A mask error (for example a resolution mismatch) is never tolerated.

use std::collections::VecDeque;

use fss_codec_mjpeg::{DecodeBudget, DecodeError as JpegError, decode_luma};
use fss_core::{ContentDigest, SensorCapsule};

use super::privacy_mask::{MaskBinding, current_mask};
use super::recorded_decode::h264::{DecoderLimits, RecordedH264Range, RecordedH264Request};
use super::recorded_decode::h265::{
    DecoderLimits as H265DecoderLimits, RecordedH265Range, RecordedH265Request,
};
use super::recorded_decode::{
    ComponentInterpretation, DecodeLimits, RecordedDecodeError, source_capsule,
};
use super::{RetainedFileImport, RetainedReadLimits};
use crate::{ReferenceDeployment, ReplayCx};

/// One maximal run of retained segments whose decode was refused.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DecodeRefusal {
    /// First refused segment.
    pub first_segment: usize,
    /// Last refused segment.
    pub last_segment: usize,
    /// Registered stable identity of the refusal (registries/ERRORS.md).
    pub error_id: String,
}

/// One decoded frame.
#[derive(Debug)]
pub(crate) struct TolerantFrame {
    pub(crate) segment: usize,
    pub(crate) capsule: SensorCapsule,
    pub(crate) capsule_digest: ContentDigest,
    pub(crate) dimensions: [u32; 2],
    pub(crate) pixels: Vec<u8>,
}

/// A decoded frame, or a decode discontinuity before the next frame.
#[derive(Debug)]
pub(crate) enum TolerantItem {
    Frame(Box<TolerantFrame>),
    /// Decoding restarted; `Some` names the refused segments that yielded no frame.
    Break(Option<DecodeRefusal>),
}

/// Exact range, interpretation and ceilings of one tolerant decode.
#[derive(Clone, Copy, Debug)]
pub(crate) struct TolerantRequest {
    pub(crate) import_identity: ContentDigest,
    pub(crate) interpretation: ComponentInterpretation,
    pub(crate) first_segment: usize,
    pub(crate) end: usize,
    pub(crate) read_limits: RetainedReadLimits,
    pub(crate) jpeg_limits: DecodeLimits,
    pub(crate) h264_limits: DecoderLimits,
    pub(crate) h265_limits: H265DecoderLimits,
}

/// Whether `error` is a typed stream refusal (as opposed to a composition bound, budget,
/// cancellation or custody failure, which always refuses the analysis).
///
/// The H.264/H.265 codecs report bitstream exhaustion inside a NAL unit (a truncated or corrupt
/// access unit) as their `Limit`, so every codec-level refusal of an inter-coded access unit is a
/// stream refusal here and is recorded under its registered id (`ERR-DECODE-BOUNDS-001` for
/// `Limit`). A codec limit that every access unit hits (for example a frame larger than the
/// operator's ceiling) decodes nothing, so the analysis still refuses with that first error.
#[must_use]
pub fn tolerable(error: &RecordedDecodeError) -> bool {
    match error {
        RecordedDecodeError::Codec(error) => matches!(
            error,
            JpegError::Malformed | JpegError::Unsupported | JpegError::Truncated
        ),
        RecordedDecodeError::H264(_)
        | RecordedDecodeError::H265(_)
        | RecordedDecodeError::H264AccessUnit { .. }
        | RecordedDecodeError::H265AccessUnit { .. }
        | RecordedDecodeError::H264SourceGap { .. }
        | RecordedDecodeError::H265SourceGap { .. }
        | RecordedDecodeError::H264RangeNotIdr { .. }
        | RecordedDecodeError::H265RangeNotIrap { .. } => true,
        _ => false,
    }
}

#[derive(Debug)]
enum InterRange {
    H264(Box<RecordedH264Range>),
    H265(Box<RecordedH265Range>),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Codec {
    H264,
    H265,
}

#[derive(Debug)]
enum Inner {
    Jpeg {
        next: usize,
    },
    Inter {
        codec: Codec,
        range: Option<InterRange>,
        sub_start: usize,
        sub_end: usize,
    },
}

/// Decode source that turns typed refusals into gaps.
#[derive(Debug)]
pub(crate) struct TolerantSource {
    request: TolerantRequest,
    retained: RetainedFileImport,
    gaps: Vec<bool>,
    inner: Inner,
    returned: Vec<bool>,
    pending: VecDeque<TolerantItem>,
    first_error: Option<RecordedDecodeError>,
    returned_any: bool,
    /// The sensor's current privacy mask, applied to every decoded MJPEG frame.
    mask: MaskBinding,
}

impl TolerantSource {
    /// Opens the range. The first segment is the operator's choice and is never skipped: for
    /// H.264/H.265 it must open as an IDR/IRAP range exactly as without tolerance.
    pub(crate) fn open(
        deployment: &ReferenceDeployment,
        request: TolerantRequest,
        cx: &ReplayCx,
    ) -> Result<Self, RecordedDecodeError> {
        let retained =
            RetainedFileImport::open(deployment, request.import_identity, request.read_limits, cx)?;
        let spans = &retained.manifest().segment_spans;
        if request.end > spans.len() || request.first_segment >= request.end {
            return Err(RecordedDecodeError::Unavailable);
        }
        let gaps: Vec<bool> = spans.iter().map(|span| span.gap_before).collect();
        let (first_capsule, _) = source_capsule(deployment, &retained, request.first_segment)?;
        let mask = current_mask(deployment, &first_capsule.sensor_id)?;
        let codec = match retained.manifest().format.as_str() {
            "mjpeg" => None,
            "annexb" => Some(Codec::H264),
            "hevc" => Some(Codec::H265),
            _ => return Err(RecordedDecodeError::UnsupportedMedia),
        };
        let mut source = Self {
            request,
            retained,
            gaps,
            inner: Inner::Jpeg {
                next: request.first_segment,
            },
            returned: vec![false; request.end - request.first_segment],
            pending: VecDeque::new(),
            first_error: None,
            returned_any: false,
            mask,
        };
        if let Some(codec) = codec {
            let start = request.first_segment;
            let sub_end = source.sub_end(start);
            let range = source.open_range(deployment, codec, start, sub_end, cx)?;
            source.inner = Inner::Inter {
                codec,
                range: Some(range),
                sub_start: start,
                sub_end,
            };
        }
        Ok(source)
    }

    /// End (exclusive) of the gap-free sub-range starting at `start`.
    fn sub_end(&self, start: usize) -> usize {
        (start + 1..self.request.end)
            .find(|segment| self.gaps.get(*segment).copied().unwrap_or(false))
            .unwrap_or(self.request.end)
    }

    fn open_range(
        &self,
        deployment: &ReferenceDeployment,
        codec: Codec,
        start: usize,
        end: usize,
        cx: &ReplayCx,
    ) -> Result<InterRange, RecordedDecodeError> {
        Ok(match codec {
            Codec::H264 => InterRange::H264(Box::new(RecordedH264Range::open(
                deployment,
                RecordedH264Request {
                    import_identity: self.request.import_identity,
                    first_segment: start,
                    segment_count: end - start,
                    interpretation: self.request.interpretation,
                    read_limits: self.request.read_limits,
                    decoder_limits: self.request.h264_limits,
                },
                cx,
            )?)),
            Codec::H265 => InterRange::H265(Box::new(RecordedH265Range::open(
                deployment,
                RecordedH265Request {
                    import_identity: self.request.import_identity,
                    first_segment: start,
                    segment_count: end - start,
                    interpretation: self.request.interpretation,
                    read_limits: self.request.read_limits,
                    decoder_limits: self.request.h265_limits,
                },
                cx,
            )?)),
        })
    }

    fn remember(&mut self, error: RecordedDecodeError) {
        if self.first_error.is_none() {
            self.first_error = Some(error);
        }
    }

    fn mark_returned(&mut self, segment: usize) {
        if let Some(slot) = segment
            .checked_sub(self.request.first_segment)
            .and_then(|offset| self.returned.get_mut(offset))
        {
            *slot = true;
        }
        self.returned_any = true;
    }

    fn was_returned(&self, segment: usize) -> bool {
        segment
            .checked_sub(self.request.first_segment)
            .and_then(|offset| self.returned.get(offset))
            .copied()
            .unwrap_or(false)
    }

    /// Queues one break naming every maximal run of segments in `first..resume` that returned no
    /// picture (a break without refused segments when every one did).
    fn queue_break(&mut self, first: usize, resume: usize, error_id: &str) {
        let mut runs: Vec<DecodeRefusal> = Vec::new();
        for segment in first..resume {
            if self.was_returned(segment) {
                continue;
            }
            match runs.last_mut() {
                Some(run) if run.last_segment + 1 == segment => run.last_segment = segment,
                _ => runs.push(DecodeRefusal {
                    first_segment: segment,
                    last_segment: segment,
                    error_id: error_id.to_owned(),
                }),
            }
        }
        if runs.is_empty() {
            self.pending.push_back(TolerantItem::Break(None));
        }
        for run in runs {
            self.pending.push_back(TolerantItem::Break(Some(run)));
        }
    }

    /// Opens the first IDR/IRAP-led sub-range at or after `candidate`; returns the segment it
    /// starts at (or the range end when none opens) and installs it.
    fn resume(
        &mut self,
        deployment: &ReferenceDeployment,
        codec: Codec,
        candidate: usize,
        cx: &ReplayCx,
    ) -> Result<usize, RecordedDecodeError> {
        for start in candidate..self.request.end {
            let end = self.sub_end(start);
            match self.open_range(deployment, codec, start, end, cx) {
                Ok(range) => {
                    self.inner = Inner::Inter {
                        codec,
                        range: Some(range),
                        sub_start: start,
                        sub_end: end,
                    };
                    return Ok(start);
                }
                Err(
                    RecordedDecodeError::H264RangeNotIdr { .. }
                    | RecordedDecodeError::H265RangeNotIrap { .. },
                ) => {}
                Err(error) => return Err(error),
            }
        }
        self.inner = Inner::Inter {
            codec,
            range: None,
            sub_start: self.request.end,
            sub_end: self.request.end,
        };
        Ok(self.request.end)
    }

    /// Next frame or break; `None` once the range is exhausted.
    pub(crate) fn next(
        &mut self,
        deployment: &ReferenceDeployment,
        budget: &mut DecodeBudget<'_>,
        cx: &ReplayCx,
    ) -> Result<Option<TolerantItem>, RecordedDecodeError> {
        loop {
            if let Some(item) = self.pending.pop_front() {
                return Ok(Some(item));
            }
            let step = match &mut self.inner {
                Inner::Jpeg { next } => {
                    if *next >= self.request.end {
                        None
                    } else {
                        let segment = *next;
                        *next += 1;
                        Some(Step::Jpeg(segment))
                    }
                }
                Inner::Inter {
                    codec,
                    range,
                    sub_start,
                    sub_end,
                } => match range {
                    None => None,
                    Some(InterRange::H264(range)) => Some(Step::Inter(
                        *codec,
                        *sub_start,
                        *sub_end,
                        Box::new(range.next_frame(deployment, cx).map(|frame| {
                            frame.map(|frame| {
                                let receipt = frame.receipt();
                                (
                                    receipt.segment_index(),
                                    receipt.capsule().clone(),
                                    receipt.capsule_digest(),
                                    receipt.dimensions(),
                                    frame.pixels().to_vec(),
                                )
                            })
                        })),
                    )),
                    Some(InterRange::H265(range)) => Some(Step::Inter(
                        *codec,
                        *sub_start,
                        *sub_end,
                        Box::new(range.next_frame(deployment, cx).map(|frame| {
                            frame.map(|frame| {
                                let receipt = frame.receipt();
                                (
                                    receipt.segment_index(),
                                    receipt.capsule().clone(),
                                    receipt.capsule_digest(),
                                    receipt.dimensions(),
                                    frame.pixels().to_vec(),
                                )
                            })
                        })),
                    )),
                },
            };
            let Some(step) = step else {
                if !self.returned_any
                    && let Some(error) = self.first_error.take()
                {
                    return Err(error);
                }
                return Ok(None);
            };
            match step {
                Step::Jpeg(segment) => {
                    if let Some(item) = self.jpeg(deployment, segment, budget, cx)? {
                        return Ok(Some(item));
                    }
                }
                Step::Inter(codec, sub_start, sub_end, result) => match *result {
                    Ok(Some((segment, capsule, capsule_digest, dimensions, pixels))) => {
                        let segment =
                            usize::try_from(segment).map_err(|_| RecordedDecodeError::Limit)?;
                        self.mark_returned(segment);
                        return Ok(Some(TolerantItem::Frame(Box::new(TolerantFrame {
                            segment,
                            capsule,
                            capsule_digest,
                            dimensions,
                            pixels,
                        }))));
                    }
                    Ok(None) => {
                        // The sub-range ended at a source gap (or the range end).
                        if sub_end >= self.request.end {
                            self.inner = Inner::Inter {
                                codec,
                                range: None,
                                sub_start: self.request.end,
                                sub_end: self.request.end,
                            };
                            continue;
                        }
                        let error = match codec {
                            Codec::H264 => RecordedDecodeError::H264SourceGap { segment: sub_end },
                            Codec::H265 => RecordedDecodeError::H265SourceGap { segment: sub_end },
                        };
                        let id = error.stable_id();
                        self.remember(error);
                        let resume = self.resume(deployment, codec, sub_end, cx)?;
                        self.queue_break(sub_end, resume, id);
                    }
                    Err(error) if tolerable(&error) => {
                        let id = error.stable_id();
                        self.remember(error);
                        // Restart strictly after this sub-range's start and after every picture
                        // it returned, so the search always makes progress.
                        let last_returned = (sub_start..sub_end)
                            .rev()
                            .find(|segment| self.was_returned(*segment));
                        let candidate = last_returned
                            .map_or(sub_start + 1, |last| (last + 1).max(sub_start + 1));
                        let resume = self.resume(deployment, codec, candidate, cx)?;
                        self.queue_break(sub_start, resume, id);
                    }
                    Err(error) => return Err(error),
                },
            }
        }
    }

    /// Decodes one independent JPEG frame; a tolerable refusal becomes a one-segment break.
    fn jpeg(
        &mut self,
        deployment: &ReferenceDeployment,
        segment: usize,
        budget: &mut DecodeBudget<'_>,
        cx: &ReplayCx,
    ) -> Result<Option<TolerantItem>, RecordedDecodeError> {
        let span = &self.retained.manifest().segment_spans[segment];
        if span.len > self.request.jpeg_limits.maximum_bytes as u64 {
            return Err(RecordedDecodeError::Limit);
        }
        let gap_before = segment > self.request.first_segment && span.gap_before;
        let (capsule, capsule_digest) = source_capsule(deployment, &self.retained, segment)?;
        let bytes =
            self.retained
                .read_segment(deployment, segment, self.request.read_limits, cx)?;
        match decode_luma(
            &bytes,
            capsule.source_digest.bytes(),
            self.request.interpretation,
            self.request.jpeg_limits,
            budget,
        ) {
            Ok(image) => {
                // Masked before the caller (foreground model, tracker, zone gate) sees a pixel.
                let mut pixels = image.pixels().to_vec();
                self.mask.apply_luma(&mut pixels, image.dimensions())?;
                self.mark_returned(segment);
                let frame = TolerantItem::Frame(Box::new(TolerantFrame {
                    segment,
                    capsule,
                    capsule_digest,
                    dimensions: image.dimensions(),
                    pixels,
                }));
                if gap_before {
                    // Lost bytes precede this frame: reset tracking before it.
                    self.pending.push_back(frame);
                    return Ok(Some(TolerantItem::Break(None)));
                }
                Ok(Some(frame))
            }
            Err(error) => {
                let error = RecordedDecodeError::from(error);
                if !tolerable(&error) {
                    return Err(error);
                }
                let id = error.stable_id();
                self.remember(error);
                Ok(Some(TolerantItem::Break(Some(DecodeRefusal {
                    first_segment: segment,
                    last_segment: segment,
                    error_id: id.to_owned(),
                }))))
            }
        }
    }
}

type Decoded = (u64, SensorCapsule, ContentDigest, [u32; 2], Vec<u8>);

enum Step {
    Jpeg(usize),
    Inter(
        Codec,
        usize,
        usize,
        Box<Result<Option<Decoded>, RecordedDecodeError>>,
    ),
}
