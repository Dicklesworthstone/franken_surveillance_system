#![forbid(unsafe_code)]
//! Explicit movie-time selection over the source-preserving sample index.
//!
//! Mapping is unit-rate and exact: movie ticks are represented with the media timescale as
//! their denominator. Neither a file timestamp nor an edit establishes physical capture time.
//! This module selects complete original samples and quotes the existing Annex-B bootstrap;
//! it does not decode pictures, rewrite media, or upgrade gaps into evidence of absence.
//!
//! The admitted timing profile has unique composition timestamps. Within each continuous
//! decode run, each sample's declared duration must end at the next presentation timestamp;
//! the last presentation uses its declared duration. This agrees with the no-`cslg` terminal
//! duration convention in Apple's QuickTime File Format, "Composition offset atom ('ctts')".
//! ISO/IEC 14496-12:2012 sections 8.6.1.3-4 distinguish composition from decode durations and
//! describe terminal ambiguity. Inconsistent grids and any `cslg` box therefore refuse here,
//! rather than manufacturing presentation coverage. Existing parse/extract admission is intact.

use super::{AvcMp4, DemuxError, MAX_ANNEX_B_BYTES, MAX_MP4_INPUT_BYTES, MAX_MP4_SAMPLES};
use std::{cmp::Ordering, ops::Range};

const MAX_WORK: usize = 16_777_216;
const MAX_ROWS: usize = 262_144;

/// Owner-narrowable bounds on mapping, metadata, and the quoted decode selection.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MovieSelectionLimits {
    /// Charged index, edit, interval, sort, allocation-initialization and NAL visits.
    pub max_work: usize,
    /// Total returned sample, edit, gap, decode-span and requested-sample-reference rows.
    pub max_rows: usize,
    /// Whole source samples across all nonoverlapping decode spans, including preroll.
    pub max_decode_samples: usize,
    /// Length-prefixed source sample bytes across all decode spans, including preroll.
    pub max_source_bytes: u64,
    /// Quoted Annex-B bytes across all spans, including configuration and start codes.
    pub max_annex_b_bytes: u64,
}

impl Default for MovieSelectionLimits {
    fn default() -> Self {
        Self {
            max_work: MAX_WORK,
            max_rows: MAX_ROWS,
            max_decode_samples: MAX_MP4_SAMPLES,
            max_source_bytes: 128 * 1024 * 1024,
            max_annex_b_bytes: 128 * 1024 * 1024,
        }
    }
}

impl MovieSelectionLimits {
    /// Validate without reading a source. Invalid or widened ceilings refuse, never clamp.
    pub fn validate(self) -> Result<(), DemuxError> {
        if !(1..=MAX_WORK).contains(&self.max_work)
            || !(1..=MAX_ROWS).contains(&self.max_rows)
            || !(1..=MAX_MP4_SAMPLES).contains(&self.max_decode_samples)
            || !(1..=MAX_MP4_INPUT_BYTES as u64).contains(&self.max_source_bytes)
            || !(1..=MAX_ANNEX_B_BYTES as u64).contains(&self.max_annex_b_bytes)
        {
            return Err(DemuxError::Limit);
        }
        Ok(())
    }
}

/// Exact, nonempty half-open interval in movie ticks; never rounded or converted to UTC.
///
/// Each endpoint is its numerator divided by `denominator`. The common denominator is the
/// selected media timescale, even when a fraction could be reduced. All returned intervals
/// are clipped to the requested movie interval and, when present, the containing edit.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MovieInterval {
    /// Inclusive movie-tick numerator.
    pub start_numerator: u128,
    /// Exclusive movie-tick numerator.
    pub end_numerator: u128,
    /// Media ticks per second, used only as a rational denominator here.
    pub denominator: u32,
}

/// One presentation of a whole source sample; repeated edits may select it more than once.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MovieSampleSelection {
    /// Original zero-based selected-track index in decode order.
    pub sample_index: usize,
    /// Original edit-list row; `None` is the implicit movie-zero/media-zero mapping.
    pub edit_index: Option<usize>,
    /// Complete original length-prefixed sample, including bytes outside the visible interval.
    pub source: Range<usize>,
    /// Part of the sample's presentation interval visible in the query and this edit.
    pub interval: MovieInterval,
}

/// An explicit edit intersecting the query, or the implicit mapping when there is no list.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MovieEditSelection {
    /// Original edit-list row, or `None` for the implicit mapping.
    pub edit_index: Option<usize>,
    /// Query intersection, not a replacement for the original edit's complete duration.
    pub interval: MovieInterval,
    /// Original edit's media start in media ticks; `None` denotes a declared empty edit.
    /// This origin is not shifted when `interval` is clipped to the query.
    pub media_time: Option<u64>,
}

/// Why no selected source presentation occupies a movie interval.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MovieGapKind {
    /// The source explicitly declares an empty edit (`media_time == -1`).
    EmptyEdit,
    /// No indexed sample presentation represents this interval under the selected mapping.
    /// This includes requests outside the edit list or the retained sample index.
    Unrepresented,
}

/// An explicit gap in indexed presentation, with no scene-absence or capture-coverage claim.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MovieGap {
    /// Exact interval missing from the selected presentation.
    pub interval: MovieInterval,
    /// Source-declared empty edit versus an interval not represented by the sample index.
    pub kind: MovieGapKind,
}

/// A complete decode-order span accepted by the existing Annex-B extraction bootstrap.
///
/// A span begins at the closest preceding sample with both the container sync assertion and
/// an AVC IDR or HEVC IRAP NAL. That is the same admission rule as [`AvcMp4::annex_b`], not an
/// independent proof that every picture decodes. In particular, HEVC CRA leading-picture
/// behavior remains the decoder's responsibility. Samples outside `requested_samples` are
/// decode prerequisites/intervening samples, and their presentation times can precede or
/// follow the query because of reordering. No edit is silently applied to elementary bytes.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MovieDecodeSpan {
    /// Original index of the bootstrap sample, inclusive.
    pub first_sample: usize,
    /// Whole samples to extract, through the final requested sample in this random-access run.
    pub sample_count: usize,
    /// Unique desired source indices in ascending decode order, excluding incidental samples.
    pub requested_samples: Vec<usize>,
    /// Complete original length-prefixed bytes in this span.
    pub source_bytes: u64,
    /// Exact byte count from the shared Annex-B NAL/configuration planner.
    pub annex_b_bytes: u64,
}

/// Complete, bounded movie-time selection; a refusal never returns a partial report.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MovieSelection {
    /// Requested nonempty half-open movie ticks.
    pub query: Range<u64>,
    /// Movie ticks per second, not a sensor or wall clock.
    pub movie_timescale: u32,
    /// Original sample ticks per second, also the exact interval denominator.
    pub media_timescale: u32,
    /// Presentation order: interval start/end, edit index, then original sample index.
    pub samples: Vec<MovieSampleSelection>,
    /// Intersected edits in movie order; one implicit mapping row when there is no edit list.
    pub edits: Vec<MovieEditSelection>,
    /// Sorted, disjoint intervals outside the union of selected sample presentations.
    pub gaps: Vec<MovieGap>,
    /// Nonoverlapping source spans in decode order, independently quoted through `annex_b`.
    pub decode_spans: Vec<MovieDecodeSpan>,
    /// Charged work units, not CPU time or a physical source-I/O measurement.
    pub work: usize,
    /// Source sample bytes requested, counted once per source index despite repeated edits.
    pub sample_bytes: u64,
    /// Source sample bytes across decode spans, including incidental/preroll samples.
    pub decode_bytes: u64,
    /// Sum of the independently extracted spans, including repeated bootstrap configuration.
    pub annex_b_bytes: u64,
}

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

impl AvcMp4<'_> {
    /// Select complete source samples whose edited presentation intersects `query`.
    ///
    /// Unit-rate edits, empty edits, signed composition offsets and B-frame presentation
    /// reordering are applied only to the returned metadata. Mapping uses checked integers,
    /// so fractional movie ticks are preserved exactly. Desired samples are distinct from the
    /// preceding/random-access decode span; missing bootstrap refuses instead of guessing.
    /// The source remains borrowed and no media payload is copied or decoded.
    ///
    /// Within each continuous decode run, distinct presentation timestamps must meet exactly
    /// at the preceding sample's declared duration. The last presentation uses its declared
    /// duration. Other composition-duration conventions, including `cslg`, are unsupported.
    /// Decode discontinuities are never stretched into presentation or crossed for bootstrap.
    pub fn select_movie_interval(
        &self,
        query: Range<u64>,
        limits: MovieSelectionLimits,
    ) -> Result<MovieSelection, DemuxError> {
        self.select_movie_interval_with_checkpoint(query, limits, &mut || Ok(()))
    }

    /// Movie-time selection with cancellation at every charged work boundary.
    ///
    /// Existing parser/extractor ceilings remain authoritative in addition to these bounds.
    /// Invalid intervals return `Timeline`; missing random access returns
    /// `RandomAccessRequired`; exhausted work, rows or byte ceilings return `Limit`.
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
        self.validate_presentation(&mut budget)?;
        let wanted = interval(query.start, query.end, self.timescale)?;
        let mut samples = Vec::new();
        let mut edits = Vec::new();
        if self.edits.is_empty() {
            budget.push(
                &mut edits,
                MovieEditSelection {
                    edit_index: None,
                    interval: wanted,
                    media_time: Some(0),
                },
            )?;
            self.map_samples(None, 0, 0, wanted, &mut samples, &mut budget)?;
        } else {
            let mut movie_start = 0_u64;
            for (edit_index, edit) in self.edits.iter().enumerate() {
                budget.charge(1)?;
                let movie_end = movie_start
                    .checked_add(edit.movie_duration)
                    .ok_or(DemuxError::Timeline)?;
                let start = movie_start.max(query.start);
                let end = movie_end.min(query.end);
                if start < end {
                    let intersection = interval(start, end, self.timescale)?;
                    let media_time = match edit.media_time {
                        -1 => None,
                        n if n >= 0 => Some(n as u64),
                        _ => return Err(DemuxError::Timeline),
                    };
                    budget.push(
                        &mut edits,
                        MovieEditSelection {
                            edit_index: Some(edit_index),
                            interval: intersection,
                            media_time,
                        },
                    )?;
                    if let Some(media_time) = media_time {
                        self.map_samples(
                            Some(edit_index),
                            movie_start,
                            media_time,
                            intersection,
                            &mut samples,
                            &mut budget,
                        )?;
                    }
                }
                movie_start = movie_end;
            }
        }
        sort_presentations(&mut samples, &mut budget)?;
        let gaps = presentation_gaps(wanted, &edits, &samples, &mut budget)?;
        let (decode_spans, sample_bytes, decode_bytes, annex_b_bytes) =
            self.decode_selection(&samples, &mut budget)?;
        budget.charge(0)?;
        Ok(MovieSelection {
            query,
            movie_timescale: self.movie_timescale,
            media_timescale: self.timescale,
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

    fn validate_presentation(&self, budget: &mut Budget<'_>) -> Result<(), DemuxError> {
        if self.composition_shift {
            return Err(DemuxError::Unsupported);
        }
        let mut start = 0;
        let mut prior_presentation_end = None;
        for end in 1..=self.samples.len() {
            budget.charge(1)?;
            let previous = &self.samples[end - 1];
            let decode_end = previous
                .decode_time
                .checked_add(u64::from(previous.duration))
                .ok_or(DemuxError::Timeline)?;
            if let Some(next) = self.samples.get(end) {
                if next.decode_time < decode_end {
                    return Err(DemuxError::Timeline);
                }
                if next.decode_time == decode_end {
                    continue;
                }
            }
            // Source-index metadata only. Allocation and every sort comparison are bounded;
            // no copied sample bytes or uninterruptible standard-library sort is required.
            budget.charge(end - start)?;
            let mut order = Vec::new();
            order
                .try_reserve_exact(end - start)
                .map_err(|_| DemuxError::Limit)?;
            for sample in &self.samples[start..end] {
                budget.charge(1)?;
                order.push((sample.presentation_time(), sample.index));
            }
            sort_items(&mut order, |a, b| a.cmp(b), budget)?;
            let mut presentation_end = prior_presentation_end;
            for (at, (pts, index)) in order.into_iter().enumerate() {
                budget.charge(1)?;
                if let Some(previous_end) = presentation_end {
                    if at == 0 {
                        if pts < previous_end {
                            return Err(DemuxError::Timeline);
                        }
                    } else if pts != previous_end {
                        // This source may be valid under a different composition-duration
                        // convention, but selecting via its decode deltas would be dishonest.
                        return Err(if pts < previous_end {
                            DemuxError::Timeline
                        } else {
                            DemuxError::Unsupported
                        });
                    }
                }
                presentation_end = Some(
                    pts.checked_add(i128::from(self.samples[index].duration))
                        .ok_or(DemuxError::Timeline)?,
                );
            }
            prior_presentation_end = presentation_end;
            start = end;
        }
        Ok(())
    }

    fn map_samples(
        &self,
        edit_index: Option<usize>,
        movie_start: u64,
        media_start: u64,
        clip: MovieInterval,
        selected: &mut Vec<MovieSampleSelection>,
        budget: &mut Budget<'_>,
    ) -> Result<(), DemuxError> {
        let origin = i128::from(movie_start)
            .checked_mul(i128::from(self.timescale))
            .ok_or(DemuxError::Timeline)?;
        let clip_start = i128::try_from(clip.start_numerator).map_err(|_| DemuxError::Timeline)?;
        let clip_end = i128::try_from(clip.end_numerator).map_err(|_| DemuxError::Timeline)?;
        for sample in &self.samples {
            budget.charge(1)?;
            let start = sample
                .presentation_time()
                .checked_sub(i128::from(media_start))
                .and_then(|n| n.checked_mul(i128::from(self.movie_timescale)))
                .and_then(|n| n.checked_add(origin))
                .ok_or(DemuxError::Timeline)?;
            let end = i128::from(sample.duration)
                .checked_mul(i128::from(self.movie_timescale))
                .and_then(|n| start.checked_add(n))
                .ok_or(DemuxError::Timeline)?;
            let start = start.max(clip_start);
            let end = end.min(clip_end);
            if start < end {
                budget.push(
                    selected,
                    MovieSampleSelection {
                        sample_index: sample.index,
                        edit_index,
                        source: sample.source.clone(),
                        interval: MovieInterval {
                            start_numerator: u128::try_from(start)
                                .map_err(|_| DemuxError::Timeline)?,
                            end_numerator: u128::try_from(end).map_err(|_| DemuxError::Timeline)?,
                            denominator: self.timescale,
                        },
                    },
                )?;
            }
        }
        Ok(())
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
        let mut random_access = None;
        let mut decode_end = None;
        for sample in &self.samples {
            budget.charge(1)?;
            if decode_end.is_some_and(|end| sample.decode_time != end) {
                random_access = None;
            }
            decode_end = Some(
                sample
                    .decode_time
                    .checked_add(u64::from(sample.duration))
                    .ok_or(DemuxError::Timeline)?,
            );
            if sample.sync_sample && sample.contains_idr {
                random_access = Some(sample.index);
            }
            if !desired[sample.index] {
                continue;
            }
            let first = random_access.ok_or(DemuxError::RandomAccessRequired)?;
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
            let size = self.visit_annex_b_nals(
                span.first_sample,
                span.sample_count,
                &mut || budget.charge(1),
                &mut |_, _| Ok(()),
            )?;
            span.annex_b_bytes = u64::try_from(size).map_err(|_| DemuxError::Limit)?;
            annex_b_bytes = annex_b_bytes
                .checked_add(span.annex_b_bytes)
                .filter(|n| *n <= budget.limits.max_annex_b_bytes)
                .ok_or(DemuxError::Limit)?;
        }
        Ok((spans, sample_bytes, decode_bytes, annex_b_bytes))
    }
}

fn add_bytes(total: u64, bytes: usize, ceiling: u64) -> Result<u64, DemuxError> {
    total
        .checked_add(u64::try_from(bytes).map_err(|_| DemuxError::Limit)?)
        .filter(|n| *n <= ceiling)
        .ok_or(DemuxError::Limit)
}

fn interval(start: u64, end: u64, denominator: u32) -> Result<MovieInterval, DemuxError> {
    if start >= end || denominator == 0 {
        return Err(DemuxError::Timeline);
    }
    Ok(MovieInterval {
        start_numerator: u128::from(start)
            .checked_mul(u128::from(denominator))
            .ok_or(DemuxError::Timeline)?,
        end_numerator: u128::from(end)
            .checked_mul(u128::from(denominator))
            .ok_or(DemuxError::Timeline)?,
        denominator,
    })
}

fn presentation_gaps(
    wanted: MovieInterval,
    edits: &[MovieEditSelection],
    samples: &[MovieSampleSelection],
    budget: &mut Budget<'_>,
) -> Result<Vec<MovieGap>, DemuxError> {
    let mut gaps = Vec::new();
    let mut cursor = wanted.start_numerator;
    let mut sample_at = 0_usize;
    for edit in edits {
        budget.charge(1)?;
        push_gap(
            &mut gaps,
            cursor,
            edit.interval.start_numerator,
            wanted.denominator,
            MovieGapKind::Unrepresented,
            budget,
        )?;
        cursor = edit.interval.start_numerator;
        if edit.media_time.is_none() {
            push_gap(
                &mut gaps,
                cursor,
                edit.interval.end_numerator,
                wanted.denominator,
                MovieGapKind::EmptyEdit,
                budget,
            )?;
        } else {
            while let Some(sample) = samples.get(sample_at) {
                budget.charge(1)?;
                if sample.interval.start_numerator >= edit.interval.end_numerator {
                    break;
                }
                push_gap(
                    &mut gaps,
                    cursor,
                    sample.interval.start_numerator,
                    wanted.denominator,
                    MovieGapKind::Unrepresented,
                    budget,
                )?;
                cursor = cursor.max(sample.interval.end_numerator);
                sample_at += 1;
            }
            push_gap(
                &mut gaps,
                cursor,
                edit.interval.end_numerator,
                wanted.denominator,
                MovieGapKind::Unrepresented,
                budget,
            )?;
        }
        cursor = edit.interval.end_numerator;
    }
    push_gap(
        &mut gaps,
        cursor,
        wanted.end_numerator,
        wanted.denominator,
        MovieGapKind::Unrepresented,
        budget,
    )?;
    Ok(gaps)
}

fn push_gap(
    gaps: &mut Vec<MovieGap>,
    start: u128,
    end: u128,
    denominator: u32,
    kind: MovieGapKind,
    budget: &mut Budget<'_>,
) -> Result<(), DemuxError> {
    budget.charge(1)?;
    if start < end {
        budget.push(
            gaps,
            MovieGap {
                interval: MovieInterval {
                    start_numerator: start,
                    end_numerator: end,
                    denominator,
                },
                kind,
            },
        )?;
    }
    Ok(())
}

fn compare(a: &MovieSampleSelection, b: &MovieSampleSelection) -> Ordering {
    (
        a.interval.start_numerator,
        a.interval.end_numerator,
        a.edit_index,
        a.sample_index,
    )
        .cmp(&(
            b.interval.start_numerator,
            b.interval.end_numerator,
            b.edit_index,
            b.sample_index,
        ))
}

/// In-place heapsort keeps both work and cancellation fallible, including adversarial PTS
/// order. A standard infallible comparator would continue sorting after its budget expired.
fn sort_presentations(
    rows: &mut [MovieSampleSelection],
    budget: &mut Budget<'_>,
) -> Result<(), DemuxError> {
    sort_items(rows, compare, budget)
}

fn sort_items<T>(
    rows: &mut [T],
    compare: fn(&T, &T) -> Ordering,
    budget: &mut Budget<'_>,
) -> Result<(), DemuxError> {
    let length = rows.len();
    for root in (0..length / 2).rev() {
        sift_down(rows, root, length, compare, budget)?;
    }
    for end in (1..length).rev() {
        budget.charge(1)?;
        rows.swap(0, end);
        sift_down(rows, 0, end, compare, budget)?;
    }
    Ok(())
}

fn sift_down<T>(
    rows: &mut [T],
    mut root: usize,
    end: usize,
    compare: fn(&T, &T) -> Ordering,
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
            if compare(&rows[child], &rows[child + 1]).is_lt() {
                child += 1;
            }
        }
        budget.charge(1)?;
        if !compare(&rows[root], &rows[child]).is_lt() {
            return Ok(());
        }
        rows.swap(root, child);
        root = child;
    }
}
