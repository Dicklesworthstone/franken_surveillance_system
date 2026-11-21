#![forbid(unsafe_code)]
//! Exact Matroska presentation selection from declared frame durations.
//!
//! RFC 9559 sections 5.1.3.5.3, 5.1.4.1.13 and 11 define BlockDuration,
//! DefaultDuration and signed timestamps. The admitted profile uses explicit durations:
//! no following timestamp is stretched backward into missing coverage. Negative-timestamp
//! frames can be decode prerequisites but must not be played. Nonunit track timestamp
//! scaling, codec delay, seek preroll and block-level timing transforms refuse selection.

use super::{
    MatroskaVideo,
    timeline::{Access, random_access},
};
use crate::demux::{
    DemuxError, MovieDecodeSpan, MovieEditSelection, MovieGap, MovieGapKind, MovieInterval,
    MovieSampleSelection, MovieSelection, MovieSelectionLimits,
};
use std::ops::Range;

const NANOS_PER_SECOND: u32 = 1_000_000_000;

struct Budget<'a> {
    limits: MovieSelectionLimits,
    work: usize,
    rows: usize,
    checkpoint: &'a mut dyn FnMut() -> Result<(), DemuxError>,
}

impl Budget<'_> {
    fn charge(&mut self, units: usize) -> Result<(), DemuxError> {
        (self.checkpoint)()?;
        self.work = self
            .work
            .checked_add(units)
            .filter(|n| *n <= self.limits.max_work)
            .ok_or(DemuxError::Limit)?;
        Ok(())
    }

    fn push<T>(&mut self, rows: &mut Vec<T>, row: T) -> Result<(), DemuxError> {
        self.charge(1)?;
        self.rows = self
            .rows
            .checked_add(1)
            .filter(|n| *n <= self.limits.max_rows)
            .ok_or(DemuxError::Limit)?;
        rows.try_reserve(1).map_err(|_| DemuxError::Limit)?;
        rows.push(row);
        Ok(())
    }
}

impl MatroskaVideo<'_> {
    /// Select source frames intersecting a half-open interval of Segment nanoseconds.
    ///
    /// Both returned timescales are one billion, preserving every integral TimestampScale
    /// exactly, even when it does not divide a second. Signed source timestamps remain in
    /// the parsed index. Negative-timestamp frames never become presentation rows, but may
    /// be required for decoding a selected later frame. These are file presentation times,
    /// with no physical capture-clock or absence claim.
    ///
    /// SimpleBlocks require track DefaultDuration; BlockGroups require BlockDuration.
    /// Unknown durations, unsupported timing transforms and overlapping presentations
    /// refuse the complete selection. Declared duration gaps remain explicit. Whole source
    /// samples and a preceding container-keyframe plus IDR bootstrap are selected. HEVC
    /// CRA retains the earlier IDR so leading RASL pictures remain reconstructible; BLA
    /// resets that prerequisite. The quoted Annex-B size includes parameter sets and all
    /// intervening samples.
    pub fn select_movie_interval(
        &self,
        query: Range<u64>,
        limits: MovieSelectionLimits,
    ) -> Result<MovieSelection, DemuxError> {
        self.select_movie_interval_with_checkpoint(query, limits, &mut || Ok(()))
    }

    /// Select with cancellation at every charged allocation, sort, frame and NAL boundary.
    ///
    /// `Timeline` denotes invalid intervals, duration overflow or overlapping presentations;
    /// `Unsupported` denotes timing this profile cannot apply; `RandomAccessRequired`
    /// denotes a missing bootstrap. Exhausted work, metadata or decode budgets return
    /// `Limit`. No refusal returns a partial result, copies media, or runs a decoder.
    pub fn select_movie_interval_with_checkpoint(
        &self,
        query: Range<u64>,
        limits: MovieSelectionLimits,
        check: &mut dyn FnMut() -> Result<(), DemuxError>,
    ) -> Result<MovieSelection, DemuxError> {
        limits.validate()?;
        if query.start >= query.end {
            return Err(DemuxError::Timeline);
        }
        let mut budget = Budget {
            limits,
            work: 0,
            rows: 0,
            checkpoint: check,
        };
        budget.charge(0)?;
        if !self.track_timing.supports_explicit_movie_profile() {
            return Err(DemuxError::Unsupported);
        }
        let order = self.presentation_order(&mut budget)?;
        let wanted = interval(query.start, query.end);
        let mut edits = Vec::new();
        budget.push(
            &mut edits,
            MovieEditSelection {
                edit_index: None,
                interval: wanted,
                media_time: Some(0),
            },
        )?;
        let mut samples = Vec::new();
        let mut gaps = Vec::new();
        let mut cursor = query.start;
        for (start, end, index) in order {
            budget.charge(1)?;
            let start = start.max(i128::from(query.start));
            let end = end.min(i128::from(query.end));
            if start >= end {
                continue;
            }
            let start = u64::try_from(start).map_err(|_| DemuxError::Timeline)?;
            let end = u64::try_from(end).map_err(|_| DemuxError::Timeline)?;
            push_gap(&mut gaps, cursor, start, &mut budget)?;
            budget.push(
                &mut samples,
                MovieSampleSelection {
                    sample_index: index,
                    edit_index: None,
                    source: self.samples[index].source.clone(),
                    interval: interval(start, end),
                },
            )?;
            cursor = end;
        }
        push_gap(&mut gaps, cursor, query.end, &mut budget)?;
        let (decode_spans, sample_bytes, decode_bytes, annex_b_bytes) =
            self.decode_selection(&samples, &mut budget)?;
        budget.charge(0)?;
        Ok(MovieSelection {
            query,
            movie_timescale: NANOS_PER_SECOND,
            media_timescale: NANOS_PER_SECOND,
            samples,
            edits,
            gaps,
            decode_spans,
            work: budget.work,
            sample_bytes,
            decode_bytes,
            annex_b_bytes,
        })
    }

    fn presentation_order(
        &self,
        budget: &mut Budget<'_>,
    ) -> Result<Vec<(i128, i128, usize)>, DemuxError> {
        if self.block_timing.len() != self.samples.len() {
            return Err(DemuxError::Layout);
        }
        budget.charge(self.samples.len())?;
        let mut order = Vec::new();
        order
            .try_reserve_exact(self.samples.len())
            .map_err(|_| DemuxError::Limit)?;
        for sample in &self.samples {
            budget.charge(1)?;
            let duration = self
                .movie_sample_duration_ns(sample.index)?
                .ok_or(DemuxError::Unsupported)?;
            let duration = i128::try_from(duration).map_err(|_| DemuxError::Timeline)?;
            if duration == 0 {
                return Err(DemuxError::Timeline);
            }
            let start = i128::from(sample.timestamp)
                .checked_mul(i128::from(self.timestamp_scale))
                .ok_or(DemuxError::Timeline)?;
            let end = start.checked_add(duration).ok_or(DemuxError::Timeline)?;
            // RFC 9559 section 11: frames with negative timestamps decode but do not play.
            if start >= 0 {
                order.push((start, end, sample.index));
            }
        }
        sort_items(&mut order, budget)?;
        let mut previous_end = None;
        for &(start, end, _) in &order {
            budget.charge(1)?;
            if previous_end.is_some_and(|prior| start < prior) {
                return Err(DemuxError::Timeline);
            }
            previous_end = Some(end);
        }
        Ok(order)
    }

    fn movie_sample_duration_ns(&self, index: usize) -> Result<Option<u128>, DemuxError> {
        self.block_timing
            .get(index)
            .ok_or(DemuxError::Layout)?
            .explicit_duration_ns(self.default_duration_ns(), self.timestamp_scale)
    }

    /// Raw Segment presentation bounds of one frame under the explicit-duration timing
    /// profile. An absent duration or unsupported transform cannot prove continuity. These
    /// bounds never establish a capture clock; the next timestamp is never used as an end.
    pub fn declared_sample_interval_ns(
        &self,
        index: usize,
    ) -> Result<Option<Range<i128>>, DemuxError> {
        let sample = self.samples.get(index).ok_or(DemuxError::Layout)?;
        if !self.track_timing.supports_explicit_movie_profile() {
            return Ok(None);
        }
        let duration = match self.movie_sample_duration_ns(index) {
            Ok(Some(duration)) if duration > 0 => duration,
            Ok(_) | Err(DemuxError::Unsupported) => return Ok(None),
            Err(error) => return Err(error),
        };
        let start = i128::from(sample.timestamp)
            .checked_mul(i128::from(self.timestamp_scale))
            .ok_or(DemuxError::Timeline)?;
        let end = start
            .checked_add(i128::try_from(duration).map_err(|_| DemuxError::Timeline)?)
            .ok_or(DemuxError::Timeline)?;
        Ok(Some(start..end))
    }

    fn decode_selection(
        &self,
        selected: &[MovieSampleSelection],
        budget: &mut Budget<'_>,
    ) -> Result<(Vec<MovieDecodeSpan>, u64, u64, u64), DemuxError> {
        if selected.is_empty() {
            return Ok((Vec::new(), 0, 0, 0));
        }
        budget.charge(self.samples.len())?;
        let mut desired = Vec::new();
        desired
            .try_reserve_exact(self.samples.len())
            .map_err(|_| DemuxError::Limit)?;
        desired.resize(self.samples.len(), false);
        let mut sample_bytes = 0_u64;
        for row in selected {
            budget.charge(1)?;
            if !desired[row.sample_index] {
                sample_bytes = add_bytes(
                    sample_bytes,
                    row.source.len(),
                    budget.limits.max_source_bytes,
                )?;
                desired[row.sample_index] = true;
            }
        }
        let mut spans: Vec<MovieDecodeSpan> = Vec::new();
        let mut bootstrap = None;
        for sample in &self.samples {
            budget.charge(1)?;
            match random_access(self, sample, &mut || budget.charge(1))? {
                Access::Idr => bootstrap = Some(sample.index),
                Access::BrokenLink => bootstrap = None,
                Access::None => {}
            }
            if !desired[sample.index] {
                continue;
            }
            let first = bootstrap.ok_or(DemuxError::RandomAccessRequired)?;
            let count = sample
                .index
                .checked_sub(first)
                .and_then(|n| n.checked_add(1))
                .ok_or(DemuxError::Layout)?;
            if let Some(last) = spans.last_mut()
                && last.first_sample == first
            {
                budget.push(&mut last.requested_samples, sample.index)?;
                last.sample_count = count;
            } else {
                let mut requested_samples = Vec::new();
                budget.push(&mut requested_samples, sample.index)?;
                budget.push(
                    &mut spans,
                    MovieDecodeSpan {
                        first_sample: first,
                        sample_count: count,
                        requested_samples,
                        source_bytes: 0,
                        annex_b_bytes: 0,
                    },
                )?;
            }
        }
        let mut decode_samples = 0_usize;
        let mut decode_bytes = 0_u64;
        let mut annex_b_bytes = 0_u64;
        for span in &mut spans {
            budget.charge(1)?;
            decode_samples = decode_samples
                .checked_add(span.sample_count)
                .filter(|n| *n <= budget.limits.max_decode_samples)
                .ok_or(DemuxError::Limit)?;
            let end = span
                .first_sample
                .checked_add(span.sample_count)
                .ok_or(DemuxError::Layout)?;
            for sample in &self.samples[span.first_sample..end] {
                budget.charge(1)?;
                span.source_bytes = add_bytes(
                    span.source_bytes,
                    sample.source.len(),
                    budget.limits.max_source_bytes,
                )?;
            }
            decode_bytes = decode_bytes
                .checked_add(span.source_bytes)
                .filter(|n| *n <= budget.limits.max_source_bytes)
                .ok_or(DemuxError::Limit)?;
            span.annex_b_bytes = self.quote_annex_b(
                span.first_sample..end,
                budget.limits.max_annex_b_bytes - annex_b_bytes,
                budget,
            )?;
            annex_b_bytes = annex_b_bytes
                .checked_add(span.annex_b_bytes)
                .ok_or(DemuxError::Limit)?;
        }
        Ok((spans, sample_bytes, decode_bytes, annex_b_bytes))
    }

    /// Quote the same CodecPrivate parameter sets and length-prefixed sample NALs used by
    /// the native recorded decoder. No media bytes are allocated, copied or rewritten.
    fn quote_annex_b(
        &self,
        samples: Range<usize>,
        ceiling: u64,
        budget: &mut Budget<'_>,
    ) -> Result<u64, DemuxError> {
        let ceiling = ceiling.min(self.limits.maximum_output_bytes as u64);
        let mut nals = 0_usize;
        let mut bytes = 0;
        for parameter_set in &self.parameter_sets {
            budget.charge(1)?;
            nals = nals
                .checked_add(1)
                .filter(|n| *n <= self.limits.maximum_nals)
                .ok_or(DemuxError::Limit)?;
            bytes = add_bytes(bytes, 4, ceiling)?;
            bytes = add_bytes(bytes, parameter_set.len(), ceiling)?;
        }
        for sample in &self.samples[samples] {
            budget.charge(1)?;
            let mut at = sample.source.start;
            while at < sample.source.end {
                budget.charge(1)?;
                nals = nals
                    .checked_add(1)
                    .filter(|n| *n <= self.limits.maximum_nals)
                    .ok_or(DemuxError::Limit)?;
                let header_end = at.checked_add(self.length_bytes).ok_or(DemuxError::Nal)?;
                let length_bytes = self
                    .source
                    .get(at..header_end)
                    .filter(|_| header_end <= sample.source.end)
                    .ok_or(DemuxError::Nal)?;
                let size = length_bytes
                    .iter()
                    .fold(0_usize, |n, byte| (n << 8) | usize::from(*byte));
                at = header_end
                    .checked_add(size)
                    .filter(|n| size != 0 && *n <= sample.source.end)
                    .ok_or(DemuxError::Nal)?;
                bytes = add_bytes(bytes, 4, ceiling)?;
                bytes = add_bytes(bytes, size, ceiling)?;
            }
        }
        Ok(bytes)
    }
}

fn add_bytes(total: u64, bytes: usize, ceiling: u64) -> Result<u64, DemuxError> {
    total
        .checked_add(u64::try_from(bytes).map_err(|_| DemuxError::Limit)?)
        .filter(|n| *n <= ceiling)
        .ok_or(DemuxError::Limit)
}

fn interval(start: u64, end: u64) -> MovieInterval {
    MovieInterval {
        start_numerator: u128::from(start) * u128::from(NANOS_PER_SECOND),
        end_numerator: u128::from(end) * u128::from(NANOS_PER_SECOND),
        denominator: NANOS_PER_SECOND,
    }
}

fn push_gap(
    gaps: &mut Vec<MovieGap>,
    start: u64,
    end: u64,
    budget: &mut Budget<'_>,
) -> Result<(), DemuxError> {
    budget.charge(1)?;
    if start < end {
        budget.push(
            gaps,
            MovieGap {
                interval: interval(start, end),
                kind: MovieGapKind::Unrepresented,
            },
        )?;
    }
    Ok(())
}

/// Fallible in-place heapsort keeps adversarial timestamp reordering bounded and cancellable.
fn sort_items<T: Ord>(rows: &mut [T], budget: &mut Budget<'_>) -> Result<(), DemuxError> {
    for root in (0..rows.len() / 2).rev() {
        sift_down(rows, root, rows.len(), budget)?;
    }
    for end in (1..rows.len()).rev() {
        budget.charge(1)?;
        rows.swap(0, end);
        sift_down(rows, 0, end, budget)?;
    }
    Ok(())
}

fn sift_down<T: Ord>(
    rows: &mut [T],
    mut root: usize,
    end: usize,
    budget: &mut Budget<'_>,
) -> Result<(), DemuxError> {
    loop {
        budget.charge(1)?;
        let mut child = root
            .checked_mul(2)
            .and_then(|n| n.checked_add(1))
            .ok_or(DemuxError::Limit)?;
        if child >= end {
            return Ok(());
        }
        if child + 1 < end {
            budget.charge(1)?;
            if rows[child] < rows[child + 1] {
                child += 1;
            }
        }
        budget.charge(1)?;
        if rows[root] >= rows[child] {
            return Ok(());
        }
        rows.swap(root, child);
        root = child;
    }
}

#[cfg(test)]
mod tests;
