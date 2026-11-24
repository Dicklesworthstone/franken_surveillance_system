#![forbid(unsafe_code)]
//! Byte-free Matroska presentation selection through authenticated immutable custody.

use super::{ParseResult, RunResult, Values, malformed, number};
use fss_container::demux::{MatroskaDurationSource, MatroskaSelectionLimits, VideoCodec};
use fss_core::ContentDigest;
use fss_reference::ingest::{RetainedFileImport, RetainedReadLimits};
use fss_reference::{ReplayCx, RetainedSource};
use std::io::Write;
use std::ops::Range;

#[derive(Debug)]
pub(super) struct Action {
    identity: ContentDigest,
    query: Range<u64>,
    limits: MatroskaSelectionLimits,
}
impl Action {
    pub(super) fn identity(&self) -> ContentDigest {
        self.identity
    }
}
pub(super) fn accepts_option(command: &str, option: &str) -> bool {
    command == "select-matroska"
        && matches!(
            option,
            "--start-presentation-ns"
                | "--end-presentation-ns"
                | "--selection-work-units"
                | "--max-selection-rows"
                | "--max-decode-samples"
                | "--max-decode-bytes"
        )
}
pub(super) fn parse(identity: ContentDigest, values: &Values) -> ParseResult<Action> {
    let start = number(values, "--start-presentation-ns", None)?;
    let end = number(values, "--end-presentation-ns", None)?;
    if start >= end {
        return Err(malformed("presentation interval must be nonempty"));
    }
    let defaults = MatroskaSelectionLimits::default();
    let limits = MatroskaSelectionLimits {
        max_work: number(values, "--selection-work-units", Some(defaults.max_work))?,
        max_rows: number(values, "--max-selection-rows", Some(defaults.max_rows))?,
        max_decode_samples: number(
            values,
            "--max-decode-samples",
            Some(defaults.max_decode_samples),
        )?,
        max_source_bytes: number(
            values,
            "--max-decode-bytes",
            Some(defaults.max_source_bytes),
        )?,
    };
    limits
        .validate()
        .map_err(|_| malformed("Matroska selection limits exceed positive hard bounds"))?;
    Ok(Action {
        identity,
        query: start..end,
        limits,
    })
}

pub(super) fn run(
    action: &Action,
    retained: &RetainedFileImport,
    deployment: &dyn RetainedSource,
    read_limits: RetainedReadLimits,
    cx: &ReplayCx,
    out: &mut impl Write,
) -> RunResult<()> {
    let result = retained.select_matroska_interval(
        deployment,
        action.query.clone(),
        read_limits,
        action.limits,
        cx,
    )?;
    cx.checkpoint("file_cli:matroska_selection_release")?;
    writeln!(out, "selection_time_basis=matroska_segment_presentation")?;
    writeln!(out, "selection_time_unit=nanoseconds")?;
    writeln!(out, "selection_interval=half_open")?;
    writeln!(out, "selection_source_adapter={}", result.source_adapter_id)?;
    writeln!(
        out,
        "selection_source_adapter_generation={}",
        result.source_adapter_generation
    )?;
    writeln!(out, "selection_track_number={}", result.track_number)?;
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
    let selection = &result.selection;
    writeln!(
        out,
        "matroska_timestamp_scale_ns={}",
        selection.timestamp_scale_ns
    )?;
    writeln!(out, "matroska_codec_delay_ns={}", selection.codec_delay_ns)?;
    writeln!(
        out,
        "query_start_presentation_ns={}",
        selection.query_ns.start
    )?;
    writeln!(out, "query_end_presentation_ns={}", selection.query_ns.end)?;
    writeln!(
        out,
        "selected_presentation_count={}",
        selection.samples.len()
    )?;
    writeln!(out, "presentation_gap_count={}", selection.gaps_ns.len())?;
    writeln!(
        out,
        "presentation_unresolved_count={}",
        selection.unresolved_ns.len()
    )?;
    writeln!(out, "decode_span_count={}", selection.decode_spans.len())?;
    writeln!(out, "selection_work_units={}", selection.work)?;
    writeln!(out, "selected_sample_bytes={}", selection.sample_bytes)?;
    writeln!(out, "required_decode_bytes={}", selection.decode_bytes)?;
    for (index, sample) in selection.samples.iter().enumerate() {
        cx.checkpoint("file_cli:matroska_report_sample")?;
        let end = sample
            .presentation_end_ns
            .map_or_else(|| "unknown".to_owned(), |value| value.to_string());
        let duration = match sample.duration_source {
            MatroskaDurationSource::BlockDuration => "block_duration",
            MatroskaDurationSource::DefaultDuration => "default_duration",
            MatroskaDurationSource::NextPresentation => "next_presentation",
            MatroskaDurationSource::Unknown => "unknown",
        };
        writeln!(
            out,
            "matroska_sample={index} segment={} presentation_start_ns={} presentation_end_ns={end} duration_source={duration} query_interval_ns={},{} overlap_certainty={} source_offset={} source_bytes={}",
            sample.sample_index,
            sample.presentation_start_ns,
            sample.interval_ns.start,
            sample.interval_ns.end,
            if sample.presentation_end_ns.is_some() {
                "established"
            } else {
                "possible"
            },
            sample.source.start,
            sample.source.len(),
        )?;
    }
    for (index, gap) in selection.gaps_ns.iter().enumerate() {
        cx.checkpoint("file_cli:matroska_report_gap")?;
        writeln!(
            out,
            "presentation_gap={index} interval_ns={},{} kind=unrepresented",
            gap.start, gap.end
        )?;
    }
    for (index, interval) in selection.unresolved_ns.iter().enumerate() {
        cx.checkpoint("file_cli:matroska_report_unresolved")?;
        writeln!(
            out,
            "presentation_unresolved={index} interval_ns={},{} reason=unknown_frame_end",
            interval.start, interval.end
        )?;
    }
    for (index, span) in selection.decode_spans.iter().enumerate() {
        cx.checkpoint("file_cli:matroska_report_span")?;
        write!(
            out,
            "decode_span={index} start_segment={} segment_count={} source_bytes={} requested_segments=",
            span.first_sample, span.sample_count, span.source_bytes,
        )?;
        for (offset, sample) in span.requested_samples.iter().enumerate() {
            cx.checkpoint("file_cli:matroska_report_requested_sample")?;
            if offset != 0 {
                write!(out, ",")?;
            }
            write!(out, "{sample}")?;
        }
        writeln!(out)?;
    }
    writeln!(out, "selection_decoded_frames=0")?;
    writeln!(out, "selection_media_exported=false")?;
    writeln!(out, "selection_absence_certifiable=false")?;
    cx.checkpoint("file_cli:matroska_report_complete")?;
    writeln!(out, "selection_complete=true")?;
    Ok(())
}

#[cfg(test)]
#[path = "matroska/tests.rs"]
mod tests;
