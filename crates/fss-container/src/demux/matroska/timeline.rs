#![forbid(unsafe_code)]
//! Explicit Matroska presentation-time selection. The historical sample and manifest
//! representation remains unchanged. No timestamp here establishes physical capture time.

use super::{DemuxError, MatroskaSample, MatroskaVideo, VideoCodec};
use crate::demux::{MAX_MP4_INPUT_BYTES, MAX_MP4_SAMPLES};
use std::ops::Range;

const MAX_WORK: usize = 16_777_216;
const MAX_ROWS: usize = 262_144;
const DEFAULT_DURATION: u32 = 0x23_E383;
const TRACK_TIMESTAMP_SCALE: u32 = 0x23_314F;
const TRACK_OFFSET: u32 = 0x537F;
const CODEC_DELAY: u32 = 0x56AA;
const SEEK_PRE_ROLL: u32 = 0x56BB;
const BLOCK_DURATION: u32 = 0x9B;
const DISCARD_PADDING: u32 = 0x75A2;

/// Owner-narrowable aggregate bounds for a complete, atomic selection.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MatroskaSelectionLimits {
    /// Charged visits, ordering comparisons/swaps and output rows.
    pub max_work: usize,
    /// All sample, gap, uncertainty, decode-span and requested-index rows together.
    pub max_rows: usize,
    /// All frames in returned decode spans, including preroll and incidental frames.
    pub max_decode_samples: usize,
    /// Original length-prefixed frame bytes in returned decode spans.
    pub max_source_bytes: u64,
}
impl Default for MatroskaSelectionLimits {
    fn default() -> Self {
        Self {
            max_work: MAX_WORK,
            max_rows: MAX_ROWS,
            max_decode_samples: MAX_MP4_SAMPLES,
            max_source_bytes: 128 * 1024 * 1024,
        }
    }
}
impl MatroskaSelectionLimits {
    /// Invalid bounds refuse; callers cannot silently widen a hard ceiling.
    pub fn validate(self) -> Result<(), DemuxError> {
        if !(1..=MAX_WORK).contains(&self.max_work)
            || !(1..=MAX_ROWS).contains(&self.max_rows)
            || !(1..=MAX_MP4_SAMPLES).contains(&self.max_decode_samples)
            || !(1..=MAX_MP4_INPUT_BYTES as u64).contains(&self.max_source_bytes)
        {
            return Err(DemuxError::Limit);
        }
        Ok(())
    }
}

/// The source of a frame's duration; none implies a possible, unclosed presentation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MatroskaDurationSource {
    /// BlockDuration, in TimestampScale ticks for the admitted unit track scale.
    BlockDuration,
    /// Track DefaultDuration, already in nanoseconds.
    DefaultDuration,
    /// The next selected-track timestamp in presentation order.
    NextPresentation,
    /// No duration or following presentation is available.
    Unknown,
}

/// One requested frame, retaining its exact source and presentation evidence.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MatroskaPresentation {
    /// Selected-track frame index in decode/file order.
    pub sample_index: usize,
    /// Exact original length-prefixed frame byte range.
    pub source: Range<usize>,
    /// Segment presentation nanoseconds after CodecDelay, never capture time.
    pub presentation_start_ns: i128,
    /// Exact end when established by duration or the next presentation; otherwise unknown.
    pub presentation_end_ns: Option<i128>,
    /// Intersection with the request. With an unknown end this is possible overlap only.
    pub interval_ns: Range<u64>,
    /// Provenance of the duration.
    pub duration_source: MatroskaDurationSource,
}

/// One consecutive coding-order range beginning at a declared AVC or HEVC IDR frame.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MatroskaDecodeSpan {
    /// First selected-track frame, including preroll.
    pub first_sample: usize,
    /// Consecutive frames to decode; only requested_samples are selected for presentation.
    pub sample_count: usize,
    /// Requested frame indices in coding order, distinct from incidental/preroll frames.
    pub requested_samples: Vec<usize>,
    /// Exact original length-prefixed bytes across this span.
    pub source_bytes: u64,
}

/// Complete bounded metadata selection. It neither decodes nor extracts a new video.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MatroskaSelection {
    /// Nonempty half-open Segment presentation interval in nanoseconds.
    pub query_ns: Range<u64>,
    /// Original Info TimestampScale.
    pub timestamp_scale_ns: u64,
    /// Track CodecDelay subtracted from all presentation timestamps.
    pub codec_delay_ns: u64,
    /// Intersecting frames, sorted by original presentation timestamp and then index.
    pub samples: Vec<MatroskaPresentation>,
    /// No indexed presentation can cover these intervals. Never a physical-absence claim.
    pub gaps_ns: Vec<Range<u64>>,
    /// Possible overlap from an unclosed presentation; its end remains explicitly unknown.
    pub unresolved_ns: Vec<Range<u64>>,
    /// Decode-order spans with all random-access prerequisites included in the bounds.
    pub decode_spans: Vec<MatroskaDecodeSpan>,
    /// Exact charged selection work.
    pub work: usize,
    /// Original bytes of requested frames, counted once each.
    pub sample_bytes: u64,
    /// Original bytes of all decode spans, including prerequisite frames.
    pub decode_bytes: u64,
}

// These fields are intentionally separate from MatroskaSample and the historical canonical
// import metadata. Unsupported timing does not alter byte-preserving import acceptance.
#[derive(Clone, Debug, Default)]
pub(super) struct TrackTiming {
    default_duration: Option<u64>,
    codec_delay: Option<u64>,
    seen_scale: bool,
    seen_offset: bool,
    seen_preroll: bool,
    unsupported: bool,
}
impl TrackTiming {
    pub(super) const fn default_duration_ns(&self) -> Option<u64> {
        self.default_duration
    }

    /// The export-capable MovieSelection profile is intentionally narrower than metadata
    /// selection: it cannot silently apply CodecDelay or promote inferred/unknown durations.
    pub(super) fn supports_explicit_movie_profile(&self) -> bool {
        !self.unsupported && self.codec_delay.unwrap_or(0) == 0
    }

    pub(super) fn observe(&mut self, id: u32, bytes: &[u8]) {
        match id {
            DEFAULT_DURATION => {
                self.unsupported |= self.default_duration.is_some();
                match unsigned(bytes) {
                    Some(value) if value > 0 => self.default_duration = Some(value),
                    _ => self.unsupported = true,
                }
            }
            CODEC_DELAY => {
                self.unsupported |= self.codec_delay.is_some();
                match unsigned(bytes) {
                    Some(value) => self.codec_delay = Some(value),
                    None => self.unsupported = true,
                }
            }
            TRACK_TIMESTAMP_SCALE => {
                self.unsupported |= self.seen_scale
                    || !(bytes == 1_f32.to_be_bytes().as_slice()
                        || bytes == 1_f64.to_be_bytes().as_slice());
                self.seen_scale = true;
            }
            TRACK_OFFSET => {
                self.unsupported |= self.seen_offset || unsigned(bytes) != Some(0);
                self.seen_offset = true;
            }
            SEEK_PRE_ROLL => {
                self.unsupported |= self.seen_preroll || unsigned(bytes) != Some(0);
                self.seen_preroll = true;
            }
            _ => {}
        }
    }
}

#[derive(Clone, Debug, Default)]
pub(super) struct BlockTiming {
    pub(super) is_group: bool,
    duration: Option<u64>,
    seen_padding: bool,
    // Only the stricter movie export profile refuses this presence. The established
    // metadata selector's admission and its uncertainty semantics remain unchanged.
    seen_additions: bool,
    unsupported: bool,
}
impl BlockTiming {
    pub(super) const fn block_duration_ticks(&self) -> Option<u64> {
        self.duration
    }

    pub(super) fn explicit_duration_ns(
        &self,
        default_duration_ns: Option<u64>,
        timestamp_scale_ns: u64,
    ) -> Result<Option<u128>, DemuxError> {
        if self.unsupported || self.seen_padding || self.seen_additions {
            return Err(DemuxError::Unsupported);
        }
        Ok(if self.is_group {
            self.block_duration_ticks()
                .map(|ticks| u128::from(ticks) * u128::from(timestamp_scale_ns))
        } else {
            default_duration_ns.map(u128::from)
        })
    }

    pub(super) fn observe(&mut self, id: u32, bytes: &[u8]) {
        match id {
            BLOCK_DURATION => {
                self.unsupported |= self.duration.is_some();
                match unsigned(bytes) {
                    Some(value) => self.duration = Some(value),
                    None => self.unsupported = true,
                }
            }
            DISCARD_PADDING => {
                self.unsupported |= self.seen_padding || unsigned(bytes) != Some(0);
                self.seen_padding = true;
            }
            0x75A1 => self.seen_additions = true,
            _ => {}
        }
    }
}
fn unsigned(bytes: &[u8]) -> Option<u64> {
    if bytes.is_empty() || bytes.len() > 8 {
        return None;
    }
    Some(
        bytes
            .iter()
            .fold(0_u64, |value, byte| (value << 8) | u64::from(*byte)),
    )
}

struct Budget<'a> {
    limits: MatroskaSelectionLimits,
    work: usize,
    rows: usize,
    check: &'a mut dyn FnMut() -> Result<(), DemuxError>,
}
impl Budget<'_> {
    fn step(&mut self) -> Result<(), DemuxError> {
        (self.check)()?;
        self.work = self
            .work
            .checked_add(1)
            .filter(|n| *n <= self.limits.max_work)
            .ok_or(DemuxError::Limit)?;
        Ok(())
    }
    fn row(&mut self) -> Result<(), DemuxError> {
        self.step()?;
        self.rows = self
            .rows
            .checked_add(1)
            .filter(|n| *n <= self.limits.max_rows)
            .ok_or(DemuxError::Limit)?;
        Ok(())
    }
}
fn push<T>(out: &mut Vec<T>, value: T) -> Result<(), DemuxError> {
    out.try_reserve(1).map_err(|_| DemuxError::Limit)?;
    out.push(value);
    Ok(())
}
fn bytes_add(current: u64, bytes: usize, limit: u64) -> Result<u64, DemuxError> {
    current
        .checked_add(u64::try_from(bytes).map_err(|_| DemuxError::Limit)?)
        .filter(|n| *n <= limit)
        .ok_or(DemuxError::Limit)
}

impl MatroskaVideo<'_> {
    /// Select a Segment presentation interval without translating it into capture time.
    ///
    /// Supports unit TrackTimestampScale, zero TrackOffset/SeekPreRoll/DiscardPadding and
    /// unlaced frames. Explicit BlockDuration takes precedence, then DefaultDuration, then the
    /// next timestamp in display order. The final frame without either duration remains
    /// unclosed, is conservatively retained for later requests, and is marked unresolved.
    /// AVC and HEVC IDRs are admitted as decode starts. HEVC CRA pictures keep the earlier
    /// IDR prerequisite so leading RASL pictures remain reconstructible; a BLA resets that
    /// prerequisite and selection refuses until a later declared IDR. Negative presentations
    /// are decode prerequisites only. Duplicate presentation timestamps,
    /// unsupported timing and recovered/truncated sources refuse this explicit operation.
    pub fn select_presentation_interval(
        &self,
        query_ns: Range<u64>,
        limits: MatroskaSelectionLimits,
    ) -> Result<MatroskaSelection, DemuxError> {
        self.select_presentation_interval_with_checkpoint(query_ns, limits, &mut || Ok(()))
    }

    /// Selection with cancellation at bounded work boundaries. An error returns no partial rows.
    pub fn select_presentation_interval_with_checkpoint(
        &self,
        query_ns: Range<u64>,
        limits: MatroskaSelectionLimits,
        check: &mut dyn FnMut() -> Result<(), DemuxError>,
    ) -> Result<MatroskaSelection, DemuxError> {
        limits.validate()?;
        if query_ns.start >= query_ns.end {
            return Err(DemuxError::Timeline);
        }
        let mut budget = Budget {
            limits,
            work: 0,
            rows: 0,
            check,
        };
        budget.step()?;
        if self.tail.is_some()
            || self.track_timing.unsupported
            || self.block_timing.len() != self.samples.len()
        {
            return Err(DemuxError::Timeline);
        }
        let codec_delay = self.track_timing.codec_delay.unwrap_or(0);
        let mut order = Vec::new();
        order
            .try_reserve_exact(self.samples.len())
            .map_err(|_| DemuxError::Limit)?;
        for (sample, timing) in self.samples.iter().zip(&self.block_timing) {
            budget.step()?;
            if timing.unsupported
                || (timing.is_group
                    && self.track_timing.default_duration.is_some()
                    && timing.duration.is_none())
            {
                return Err(DemuxError::Timeline);
            }
            let pts = i128::from(sample.timestamp)
                .checked_mul(i128::from(self.timestamp_scale))
                .and_then(|n| n.checked_sub(i128::from(codec_delay)))
                .ok_or(DemuxError::Timeline)?;
            order.push((pts, sample.index));
        }
        sort_presentations(&mut order, &mut budget)?;
        let mut wanted = Vec::new();
        wanted
            .try_reserve_exact(self.samples.len())
            .map_err(|_| DemuxError::Limit)?;
        wanted.resize(self.samples.len(), false);
        let mut samples = Vec::new();
        let mut gaps = Vec::new();
        let mut unresolved = Vec::new();
        let mut covered_until = query_ns.start;
        let mut sample_bytes = 0_u64;
        for (at, &(start, index)) in order.iter().enumerate() {
            budget.step()?;
            let next = order.get(at + 1).map(|entry| entry.0);
            if next == Some(start) {
                return Err(DemuxError::Timeline);
            }
            let timing = &self.block_timing[index];
            let (end, duration_source) = if let Some(duration) = timing.duration {
                let duration = i128::from(duration)
                    .checked_mul(i128::from(self.timestamp_scale))
                    .ok_or(DemuxError::Timeline)?;
                (
                    Some(start.checked_add(duration).ok_or(DemuxError::Timeline)?),
                    MatroskaDurationSource::BlockDuration,
                )
            } else if let Some(duration) = self.track_timing.default_duration {
                (
                    Some(
                        start
                            .checked_add(i128::from(duration))
                            .ok_or(DemuxError::Timeline)?,
                    ),
                    MatroskaDurationSource::DefaultDuration,
                )
            } else if let Some(next) = next {
                (Some(next), MatroskaDurationSource::NextPresentation)
            } else {
                (None, MatroskaDurationSource::Unknown)
            };
            // Matroska negative presentations must be decoded when needed, but not displayed.
            if start < 0 || start >= i128::from(query_ns.end) {
                continue;
            }
            let left = start.max(i128::from(query_ns.start));
            let right = end
                .unwrap_or(i128::from(query_ns.end))
                .min(i128::from(query_ns.end));
            if left >= right {
                continue;
            }
            let interval = u64::try_from(left).map_err(|_| DemuxError::Timeline)?
                ..u64::try_from(right).map_err(|_| DemuxError::Timeline)?;
            if interval.start > covered_until {
                budget.row()?;
                push(&mut gaps, covered_until..interval.start)?;
            }
            covered_until = covered_until.max(interval.end);
            if end.is_none() {
                budget.row()?;
                push(&mut unresolved, interval.clone())?;
            }
            let sample = &self.samples[index];
            sample_bytes = bytes_add(sample_bytes, sample.source.len(), limits.max_source_bytes)?;
            wanted[index] = true;
            budget.row()?;
            push(
                &mut samples,
                MatroskaPresentation {
                    sample_index: index,
                    source: sample.source.clone(),
                    presentation_start_ns: start,
                    presentation_end_ns: end,
                    interval_ns: interval,
                    duration_source,
                },
            )?;
        }
        if covered_until < query_ns.end {
            budget.row()?;
            push(&mut gaps, covered_until..query_ns.end)?;
        }
        let mut spans: Vec<MatroskaDecodeSpan> = Vec::new();
        let mut bootstrap = None;
        for (index, sample) in self.samples.iter().enumerate() {
            budget.step()?;
            match random_access(self, sample, &mut || budget.step())? {
                Access::Idr => bootstrap = Some(index),
                Access::BrokenLink => bootstrap = None,
                Access::None => {}
            }
            if !wanted[index] {
                continue;
            }
            let first = bootstrap.ok_or(DemuxError::RandomAccessRequired)?;
            if spans.last().is_none_or(|span| span.first_sample != first) {
                budget.row()?;
                push(
                    &mut spans,
                    MatroskaDecodeSpan {
                        first_sample: first,
                        sample_count: 0,
                        requested_samples: Vec::new(),
                        source_bytes: 0,
                    },
                )?;
            }
            let span = spans.last_mut().ok_or(DemuxError::Layout)?;
            span.sample_count = index - first + 1;
            budget.row()?;
            push(&mut span.requested_samples, index)?;
        }
        let mut decode_samples = 0_usize;
        let mut decode_bytes = 0_u64;
        for span in &mut spans {
            budget.step()?;
            decode_samples = decode_samples
                .checked_add(span.sample_count)
                .filter(|n| *n <= limits.max_decode_samples)
                .ok_or(DemuxError::Limit)?;
            let end = span
                .first_sample
                .checked_add(span.sample_count)
                .ok_or(DemuxError::Limit)?;
            for sample in &self.samples[span.first_sample..end] {
                budget.step()?;
                span.source_bytes = bytes_add(
                    span.source_bytes,
                    sample.source.len(),
                    limits.max_source_bytes,
                )?;
                decode_bytes =
                    bytes_add(decode_bytes, sample.source.len(), limits.max_source_bytes)?;
            }
        }
        (budget.check)()?;
        Ok(MatroskaSelection {
            query_ns,
            timestamp_scale_ns: self.timestamp_scale,
            codec_delay_ns: codec_delay,
            samples,
            gaps_ns: gaps,
            unresolved_ns: unresolved,
            decode_spans: spans,
            work: budget.work,
            sample_bytes,
            decode_bytes,
        })
    }
}

pub(super) enum Access {
    None,
    Idr,
    BrokenLink,
}

/// A container IRAP assertion alone is insufficient for leading HEVC pictures. Starting at a
/// CRA suppresses RASL pictures and can omit their previous-GOP references. Keep the prior IDR
/// across CRA, and refuse across BLA because it breaks references even during continuous decode.
/// Header scans are over already validated source ranges, with explicit bounded work.
pub(super) fn random_access(
    video: &MatroskaVideo<'_>,
    sample: &MatroskaSample,
    checkpoint: &mut dyn FnMut() -> Result<(), DemuxError>,
) -> Result<Access, DemuxError> {
    if !sample.contains_idr {
        return Ok(Access::None);
    }
    if video.codec == VideoCodec::Avc {
        return Ok(if sample.keyframe {
            Access::Idr
        } else {
            Access::None
        });
    }
    let bytes = video
        .source
        .get(sample.source.clone())
        .ok_or(DemuxError::Layout)?;
    let mut at = 0_usize;
    let mut idr = false;
    let mut broken_link = false;
    while at < bytes.len() {
        checkpoint()?;
        let data = at
            .checked_add(video.length_bytes)
            .ok_or(DemuxError::Limit)?;
        let length = bytes
            .get(at..data)
            .ok_or(DemuxError::Nal)?
            .iter()
            .fold(0_usize, |n, byte| (n << 8) | usize::from(*byte));
        let end = data.checked_add(length).ok_or(DemuxError::Limit)?;
        let nal = bytes.get(data..end).ok_or(DemuxError::Nal)?;
        if nal.len() < 2 {
            return Err(DemuxError::Nal);
        }
        match (nal[0] >> 1) & 0x3f {
            16..=18 => broken_link = true,
            19 | 20 => idr = true,
            _ => {}
        }
        at = end;
    }
    Ok(if broken_link {
        Access::BrokenLink
    } else if sample.keyframe && idr {
        Access::Idr
    } else {
        Access::None
    })
}

// Heap sort makes comparison/swap work explicit and interruptible, including adversarial
// presentation order. No unmetered library sort or quadratic preceding-keyframe scan is used.
fn sort_presentations(
    rows: &mut [(i128, usize)],
    budget: &mut Budget<'_>,
) -> Result<(), DemuxError> {
    let len = rows.len();
    for root in (0..len / 2).rev() {
        sift(rows, root, len, budget)?;
    }
    for end in (1..len).rev() {
        budget.step()?;
        rows.swap(0, end);
        sift(rows, 0, end, budget)?;
    }
    Ok(())
}
fn sift(
    rows: &mut [(i128, usize)],
    mut root: usize,
    end: usize,
    budget: &mut Budget<'_>,
) -> Result<(), DemuxError> {
    while root < end / 2 {
        let mut child = root * 2 + 1;
        if child + 1 < end {
            budget.step()?;
            if rows[child] < rows[child + 1] {
                child += 1;
            }
        }
        budget.step()?;
        if rows[root] >= rows[child] {
            break;
        }
        budget.step()?;
        rows.swap(root, child);
        root = child;
    }
    Ok(())
}

#[cfg(test)]
mod tests;
