#![forbid(unsafe_code)]
//! Source-time selection for local decoded output, under the retained timing classification.

use std::io::Write;

use fss_core::{ClockBasis, TimestampNs};
use fss_reference::ingest::RetainedFileImport;
use fss_reference::ingest::recorded_decode::window::{
    DecodedOutputWindow, FrameWindowReceipt, FrameWindowSelector, FrameWindowSource,
    FrameWindowTimeProvenance,
};
use fss_reference::ReplayCx;

use super::{FrameAction, ParseResult, RunResult, Values, malformed, text};

pub(super) fn parse(values: &Values) -> ParseResult<Option<DecodedOutputWindow>> {
    let interval = values.contains_key("--output-window-ns");
    let clock = values.contains_key("--output-clock-basis");
    if !interval && !clock {
        return Ok(None);
    }
    if !interval || !clock || !values.contains_key("--output") {
        return Err(malformed(
            "--output-window-ns and --output-clock-basis require each other and --output",
        ));
    }
    let value = text(values, "--output-window-ns")?;
    if value.len() > 81 {
        return Err(malformed("output window exceeds signed nanosecond bounds"));
    }
    let (start, end) = value
        .split_once(':')
        .ok_or_else(|| malformed("output window requires START:EXCLUSIVE_END"))?;
    let integer = |part: &str| {
        let digits = part.strip_prefix('-').unwrap_or(part);
        if digits.is_empty() || !digits.bytes().all(|byte| byte.is_ascii_digit()) {
            return Err(malformed("output window requires signed decimal nanoseconds"));
        }
        part.parse::<i128>()
            .map(TimestampNs)
            .map_err(|_| malformed("output window exceeds signed nanosecond bounds"))
    };
    let basis = ClockBasis::parse(text(values, "--output-clock-basis")?)
        .map_err(|_| malformed("output clock basis requires a canonical retained clock name"))?;
    DecodedOutputWindow::new(integer(start)?, integer(end)?, basis)
        .map(Some)
        .map_err(|_| malformed("output window must be a nonempty half-open interval"))
}

pub(super) fn prepare(
    action: &FrameAction,
    retained: &RetainedFileImport,
) -> RunResult<Option<FrameWindowSelector>> {
    let Some(window) = action.output_window else {
        return Ok(None);
    };
    let time_provenance = match retained.manifest().capture_time_label.as_str() {
        "operator_assumption" => FrameWindowTimeProvenance::OperatorAssumption,
        _ => FrameWindowTimeProvenance::Unknown,
    };
    Ok(Some(FrameWindowSelector::new(
        window,
        FrameWindowSource {
            import_identity: action.request.import_identity,
            import_root: retained.import_root(),
            first_segment: u64::try_from(action.request.segment_index)?,
            segment_count: action.segment_count,
            time_provenance,
        },
    )?))
}

pub(super) fn finish(
    selection: Option<FrameWindowSelector>,
    completed_output_frames: u64,
    cx: &ReplayCx,
) -> RunResult<Option<FrameWindowReceipt>> {
    selection
        .map(|selection| selection.finish(completed_output_frames, cx.is_cancelled()))
        .transpose()
        .map_err(Into::into)
}

/// Emit only after the output owner has successfully synced its complete image stream.
pub(super) fn report(
    window: Option<&DecodedOutputWindow>,
    receipt: Option<&FrameWindowReceipt>,
    out: &mut impl Write,
) -> RunResult<()> {
    let (Some(window), Some(receipt)) = (window, receipt) else {
        return Ok(());
    };
    writeln!(out, "output_window_start_ns={}", window.start().0)?;
    writeln!(out, "output_window_end_exclusive_ns={}", window.end().0)?;
    writeln!(out, "output_window_clock_basis={}", window.clock_basis())?;
    writeln!(out, "output_window_time_provenance=operator_assumption")?;
    writeln!(out, "output_window_request_digest={}", receipt.request_digest)?;
    writeln!(out, "output_window_selection_digest={}", receipt.selection_digest)?;
    writeln!(out, "output_window_observed_frames={}", receipt.observed_frames)?;
    writeln!(out, "output_window_selected_frames={}", receipt.selected_frames)?;
    writeln!(out, "output_window_skipped_frames={}", receipt.skipped_frames)?;
    writeln!(out, "output_window_selected_earliest_ns={}", receipt.selected_capture.earliest.0)?;
    writeln!(out, "output_window_selected_latest_ns={}", receipt.selected_capture.latest.0)?;
    writeln!(out, "output_window_timing_embedded=false")?;
    writeln!(out, "output_window_coverage_asserted=false")?;
    writeln!(out, "output_window_complete=true")?;
    Ok(())
}
