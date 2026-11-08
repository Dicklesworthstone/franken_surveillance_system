#![forbid(unsafe_code)]
//! Byte-free movie-timeline selection over the retained source custody path.

use super::{ParseResult, RunResult, Values, malformed, number};
use fss_container::demux::{
    MovieGapKind, MovieInterval, MovieSelection, MovieSelectionLimits, VideoCodec,
};
use fss_core::ContentDigest;
use fss_reference::ingest::retained::{MAX_MOVIE_ORIGIN_READ_BYTES, RetainedMovieSelection};
use fss_reference::ingest::{RetainedFileImport, RetainedReadLimits};
use fss_reference::{ReferenceDeployment, ReplayCx};
use std::io::Write;
use std::ops::Range;

#[derive(Debug)]
pub(super) struct Action {
    identity: ContentDigest,
    query: Range<u64>,
    limits: MovieSelectionLimits,
    maximum_origin_read_bytes: u64,
}

impl Action {
    pub(super) fn identity(&self) -> ContentDigest {
        self.identity
    }

    pub(super) fn select(
        &self,
        retained: &RetainedFileImport,
        deployment: &ReferenceDeployment,
        read_limits: RetainedReadLimits,
        cx: &ReplayCx,
    ) -> RunResult<RetainedMovieSelection> {
        Ok(retained.select_movie_interval_with_origin_limit(
            deployment,
            self.query.clone(),
            read_limits,
            self.limits,
            self.maximum_origin_read_bytes,
            cx,
        )?)
    }
}

pub(super) fn accepts_option(command: &str, option: &str) -> bool {
    command == "select-movie"
        && matches!(
            option,
            "--start-movie-tick"
                | "--end-movie-tick"
                | "--selection-work-units"
                | "--max-selection-rows"
                | "--max-decode-samples"
                | "--max-decode-bytes"
                | "--max-annex-b-bytes"
                | "--max-origin-read-bytes"
        )
}

pub(super) fn parse(identity: ContentDigest, values: &Values) -> ParseResult<Action> {
    parse_with_decode_limit(
        identity,
        values,
        MovieSelectionLimits::default().max_decode_samples,
    )
}

/// Export has a tighter aggregate native-decoder ceiling than byte-free timeline inspection.
pub(super) fn parse_with_decode_limit(
    identity: ContentDigest,
    values: &Values,
    maximum_decode_samples: usize,
) -> ParseResult<Action> {
    let start = number(values, "--start-movie-tick", None)?;
    let end = number(values, "--end-movie-tick", None)?;
    if start >= end {
        return Err(malformed(
            "movie interval must be nonempty: start-movie-tick < end-movie-tick",
        ));
    }
    let maximum_origin_read_bytes = number(
        values,
        "--max-origin-read-bytes",
        Some(MAX_MOVIE_ORIGIN_READ_BYTES),
    )?;
    if maximum_origin_read_bytes == 0 || maximum_origin_read_bytes > MAX_MOVIE_ORIGIN_READ_BYTES {
        return Err(malformed(
            "movie origin read allowance must be positive and within the native origin bound",
        ));
    }
    let defaults = MovieSelectionLimits::default();
    let limits = MovieSelectionLimits {
        max_work: number(values, "--selection-work-units", Some(defaults.max_work))?,
        max_rows: number(values, "--max-selection-rows", Some(defaults.max_rows))?,
        max_decode_samples: number(
            values,
            "--max-decode-samples",
            Some(defaults.max_decode_samples.min(maximum_decode_samples)),
        )?,
        max_source_bytes: number(
            values,
            "--max-decode-bytes",
            Some(defaults.max_source_bytes),
        )?,
        max_annex_b_bytes: number(
            values,
            "--max-annex-b-bytes",
            Some(defaults.max_annex_b_bytes),
        )?,
    };
    limits
        .validate()
        .map_err(|_| malformed("movie selection limits must be positive and within hard bounds"))?;
    if limits.max_decode_samples > maximum_decode_samples {
        return Err(malformed(
            "movie export decodes at most 1024 aggregate source samples",
        ));
    }
    Ok(Action {
        identity,
        query: start..end,
        limits,
        maximum_origin_read_bytes,
    })
}

pub(super) fn run(
    action: &Action,
    retained: &RetainedFileImport,
    deployment: &ReferenceDeployment,
    read_limits: RetainedReadLimits,
    cx: &ReplayCx,
    out: &mut impl Write,
) -> RunResult<()> {
    let result = action.select(retained, deployment, read_limits, cx)?;
    cx.checkpoint("file_cli:movie_selection_release")?;
    report(&result, cx, out)?;
    writeln!(out, "selection_decoded_frames=0")?;
    writeln!(out, "selection_media_exported=false")?;
    writeln!(out, "selection_absence_certifiable=false")?;
    cx.checkpoint("file_cli:movie_report_complete")?;
    writeln!(out, "selection_complete=true")?;
    Ok(())
}

pub(super) fn report(
    result: &RetainedMovieSelection,
    cx: &ReplayCx,
    out: &mut impl Write,
) -> RunResult<()> {
    writeln!(out, "selection_time_basis=container_movie_timeline")?;
    writeln!(out, "selection_interval=half_open")?;
    writeln!(out, "selection_source_adapter={}", result.source_adapter_id)?;
    writeln!(
        out,
        "selection_source_adapter_generation={}",
        result.source_adapter_generation
    )?;
    writeln!(out, "selection_track_id={}", result.track_id)?;
    writeln!(
        out,
        "selection_codec={}",
        match result.codec {
            VideoCodec::Avc => "avc",
            VideoCodec::Hevc => "hevc",
        }
    )?;
    writeln!(
        out,
        "selection_verified_source_sha256={}",
        result.input_sha256
    )?;
    writeln!(out, "selection_source_bytes={}", result.input_bytes)?;
    writeln!(
        out,
        "selection_source_bytes_read={}",
        result.source_bytes_read
    )?;
    writeln!(
        out,
        "selection_origin_read_bytes_charged={}",
        result.origin_read_bytes_charged
    )?;
    writeln!(
        out,
        "selection_maximum_origin_read_bytes={}",
        result.maximum_origin_read_bytes
    )?;
    writeln!(out, "selection_origin_read_model=conservative_pre_io_bytes")?;
    write_selection(&result.selection, cx, out)?;
    Ok(())
}

fn interval_text(interval: &MovieInterval) -> String {
    format!(
        "{}/{},{}/{}",
        interval.start_numerator,
        interval.denominator,
        interval.end_numerator,
        interval.denominator,
    )
}

/// Rows describe presentation occurrences; repeated edits may select the same original segment
/// more than once. Decode spans name original coding segments, including all required intervening
/// samples, and are distinct from the requested presentation occurrences.
fn write_selection(
    selection: &MovieSelection,
    cx: &ReplayCx,
    out: &mut impl Write,
) -> RunResult<()> {
    writeln!(out, "movie_timescale={}", selection.movie_timescale)?;
    writeln!(out, "media_timescale={}", selection.media_timescale)?;
    writeln!(out, "query_start_movie_tick={}", selection.query.start)?;
    writeln!(out, "query_end_movie_tick={}", selection.query.end)?;
    writeln!(
        out,
        "selected_presentation_count={}",
        selection.samples.len()
    )?;
    writeln!(out, "movie_gap_count={}", selection.gaps.len())?;
    writeln!(out, "decode_span_count={}", selection.decode_spans.len())?;
    writeln!(out, "selection_work_units={}", selection.work)?;
    writeln!(out, "selected_sample_bytes={}", selection.sample_bytes)?;
    writeln!(out, "required_decode_bytes={}", selection.decode_bytes)?;
    writeln!(out, "quoted_annex_b_bytes={}", selection.annex_b_bytes)?;
    for (index, edit) in selection.edits.iter().enumerate() {
        cx.checkpoint("file_cli:movie_report_edit")?;
        let edit_index = edit
            .edit_index
            .map_or_else(|| "implicit".to_owned(), |n| n.to_string());
        let media_time = edit
            .media_time
            .map_or_else(|| "empty".to_owned(), |n| n.to_string());
        writeln!(
            out,
            "movie_edit={index} edit_index={edit_index} movie_interval={} media_time={media_time}",
            interval_text(&edit.interval),
        )?;
    }
    for (index, sample) in selection.samples.iter().enumerate() {
        cx.checkpoint("file_cli:movie_report_sample")?;
        let edit_index = sample
            .edit_index
            .map_or_else(|| "implicit".to_owned(), |n| n.to_string());
        writeln!(
            out,
            "movie_sample={index} segment={} edit_index={edit_index} movie_interval={} source_offset={} source_bytes={}",
            sample.sample_index,
            interval_text(&sample.interval),
            sample.source.start,
            sample.source.len(),
        )?;
    }
    for (index, gap) in selection.gaps.iter().enumerate() {
        cx.checkpoint("file_cli:movie_report_gap")?;
        let kind = match gap.kind {
            MovieGapKind::EmptyEdit => "empty_edit",
            MovieGapKind::Unrepresented => "unrepresented",
        };
        writeln!(
            out,
            "movie_gap={index} kind={kind} movie_interval={}",
            interval_text(&gap.interval),
        )?;
    }
    for (index, span) in selection.decode_spans.iter().enumerate() {
        cx.checkpoint("file_cli:movie_report_span")?;
        write!(
            out,
            "decode_span={index} start_segment={} segment_count={} source_bytes={} annex_b_bytes={} requested_segments=",
            span.first_sample, span.sample_count, span.source_bytes, span.annex_b_bytes,
        )?;
        for (offset, sample) in span.requested_samples.iter().enumerate() {
            cx.checkpoint("file_cli:movie_report_requested_sample")?;
            if offset != 0 {
                write!(out, ",")?;
            }
            write!(out, "{sample}")?;
        }
        writeln!(out)?;
    }
    Ok(())
}

#[cfg(test)]
#[path = "movie/tests.rs"]
mod tests;
