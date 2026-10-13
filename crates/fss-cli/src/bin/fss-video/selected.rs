#![forbid(unsafe_code)]
//! Retain one selected display output only after the unchanged native range has completed.
//! No alternative receipt, codec, export authority or publication protocol is introduced.

use super::{
    Frame, Gate, Plan, Range, RecordedVideoDecodeBudget, ReferenceDeployment, Reports,
    frame_json, publication_limits, scope,
};
use crate::{Result, fail};
use fss_reference::ingest::recorded_decode::RecordedDecodeError;
use fss_reference::ingest::recorded_decode::h264::MAX_H264_RANGE_SEGMENTS;
use fss_reference::ingest::video_publication::PublishedVideoFrame;
use std::io::Write;

struct Selected<T> {
    frame: T,
    outputs: usize,
}

// Keep one selected frame, never a range-sized pixel vector. Reaching the chosen output is not
// successful completion: a subsequent refusal or absent native end must prevent publication.
fn drain<T>(
    count: usize,
    wanted: u64,
    pixels: usize,
    dimension: u32,
    mut next: impl FnMut() -> Result<Option<T>>,
    metadata: impl Fn(&T) -> (u64, [u32; 2]),
) -> Result<Selected<T>> {
    if count == 0 || count > MAX_H264_RANGE_SEGMENTS || wanted >= count as u64 {
        return Err(RecordedDecodeError::Limit.into());
    }
    let mut selected = None;
    for position in 0..=count {
        let Some(frame) = next()? else {
            return selected
                .map(|frame| Selected { frame, outputs: position })
                .ok_or_else(|| RecordedDecodeError::Unavailable.into());
        };
        if position == count {
            return Err(RecordedDecodeError::Limit.into());
        }
        let (index, [width, height]) = metadata(&frame);
        if index != position as u64 {
            return Err(RecordedDecodeError::InvalidReceipt.into());
        }
        let luma = (width as usize)
            .checked_mul(height as usize)
            .ok_or(RecordedDecodeError::Limit)?;
        if width == 0 || height == 0 || width > dimension || height > dimension || luma > pixels {
            return Err(RecordedDecodeError::Limit.into());
        }
        if index == wanted {
            selected = Some(frame);
        }
    }
    Err(RecordedDecodeError::Limit.into())
}

pub(super) fn publish<W: Write>(
    plan: &Plan,
    range: &mut Range,
    deployment: &mut ReferenceDeployment,
    budget: &mut RecordedVideoDecodeBudget,
    gate: &Gate<'_>,
    reports: &mut Reports<'_, W>,
) -> Result<(usize, usize)> {
    let wanted = plan.output_index.ok_or_else(|| fail("display selection required"))?;
    let selected = drain(
        plan.count,
        wanted,
        plan.pixels,
        plan.dimension,
        || {
            gate.check()?;
            let next = range.next(deployment, budget, gate.cx)?;
            gate.check()?;
            Ok(next)
        },
        |frame| {
            let dimensions = match frame {
                Frame::Avc(frame) => frame.dimensions(),
                Frame::Hevc(frame) => frame.dimensions(),
            };
            (frame.output(), dimensions)
        },
    )?;
    gate.check()?;
    // Only the retained frame consumes derived admission. All source units, including skipped
    // or reordered pictures, have already consumed the SAME native decode allowance above.
    let quote = selected.frame.quote()?;
    if quote > plan.derived {
        return Err(fail("selected frame exceeds derived byte allowance"));
    }
    if crate::plan::REPORT_LIMIT.saturating_sub(reports.bytes) < crate::plan::SELECTED_REPORT_RESERVE {
        return Err(fail("selected frame report reserve exhausted"));
    }
    let frame = PublishedVideoFrame::publish(
        deployment,
        selected.frame.native(),
        publication_limits(plan),
        gate.cx,
    )?;
    // The original owner preserves its root-to-completion recovery and refuses stale privacy.
    // Output failure can still follow a committed frame; an exact retry never repairs damage.
    scope(plan, &frame)?;
    reports.row("frame", frame_json(&frame))?;
    Ok((selected.outputs, quote))
}

#[cfg(test)]
#[path = "selected_tests.rs"]
mod tests;
