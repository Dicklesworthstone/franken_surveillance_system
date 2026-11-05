#![forbid(unsafe_code)]
//! UTC candidate metadata over an exact recovered archive and retained clock index.
//! No decode-tick conversion, camera capture-time estimate, or source payload export.

use super::*;
use fss_reference::rtsp::recording_catalog::CatalogQueryLimits;
use fss_reference::rtsp::recording_clock::{
    MAX_CLOCK_WINDOWS, RecordingClockCodec, RecordingClockIndex, load_clock_index,
};

pub(super) struct UtcQuery {
    pub(super) expected_index: ContentDigest,
    pub(super) interval: Range<u64>,
}

/// Every clock row must name an original in this exact snapshot, even when the
/// row would not overlap the requested UTC interval. Extra originals remain
/// unknown; a missing clock row is never an exclusion witness.
fn bind_snapshot<C: ArchiveCodec>(
    index: &RecordingClockIndex,
    snapshot: &CodecArchiveSnapshot<C>,
    clock: &impl OperationClock,
) -> Result<Vec<Option<usize>>> {
    if index.scope() != snapshot.namespace().scope() {
        return Err(ArchiveCommandError::ClockIndexSnapshotMismatch);
    }
    let mut bindings = Vec::new();
    bindings
        .try_reserve_exact(snapshot.windows().len())
        .map_err(|_| ArchiveCommandError::ReportLimit)?;
    bindings.resize(snapshot.windows().len(), None);
    for (clock_ordinal, window) in index.windows().iter().enumerate() {
        clock.check()?;
        let (ordinal, original) = snapshot
            .windows()
            .iter()
            .enumerate()
            .find(|(_, original)| original.slot() == window.slot())
            .ok_or(ArchiveCommandError::ClockIndexSnapshotMismatch)?;
        if original.root() != window.root()
            || original.decode_interval() != window.decode_interval()
            || original.byte_len() != window.byte_len()
            || bindings[ordinal].is_some()
        {
            return Err(ArchiveCommandError::ClockIndexSnapshotMismatch);
        }
        bindings[ordinal] = Some(clock_ordinal);
    }
    Ok(bindings)
}

pub(super) fn execute<C: ArchiveCodec>(
    options: &ArchiveOptions,
    publisher: &LocalRootPublisher,
    snapshot: &CodecArchiveSnapshot<C>,
    identity: ContentDigest,
    clock: &impl OperationClock,
) -> Result<String> {
    let query = options
        .utc_query
        .as_ref()
        .ok_or_else(|| malformed("UTC query and clock-index pin required"))?;
    let codec = match options.codec {
        Codec::Avc => RecordingClockCodec::Avc,
        Codec::Hevc => RecordingClockCodec::Hevc,
    };
    clock.check()?;
    let index = load_clock_index(
        publisher,
        query.expected_index,
        &options.scope,
        codec,
        clock,
    )?;
    clock.check()?;
    let bindings = bind_snapshot(&index, snapshot, clock)?;
    // The shared clock index is one bounded page. Clamping its local selection
    // ceilings does not discard rows: overflow refuses, and aggregate output is
    // checked against the caller's full archive limits below.
    let selection = index.select(
        query.interval.clone(),
        CatalogQueryLimits {
            max_windows: options.query_limits.max_windows.min(MAX_CLOCK_WINDOWS),
            max_output_bytes: options
                .query_limits
                .max_output_bytes
                .min((MAX_CLOCK_WINDOWS * MAX_RECORDING_BYTES) as u64),
        },
    )?;
    let mut unavailable_windows = 0_usize;
    let mut unavailable_bytes = 0_u64;
    for (original, binding) in snapshot.windows().iter().zip(&bindings) {
        clock.check()?;
        if binding.is_none() {
            unavailable_windows = unavailable_windows
                .checked_add(1)
                .ok_or(ArchiveError::Limit)?;
            unavailable_bytes = unavailable_bytes
                .checked_add(u64::try_from(original.byte_len()).map_err(|_| ArchiveError::Limit)?)
                .ok_or(ArchiveError::Limit)?;
        }
    }
    let output_windows = selection
        .ordinals()
        .len()
        .checked_add(unavailable_windows)
        .ok_or(ArchiveError::Limit)?;
    let output_bytes = selection
        .output_bytes()
        .checked_add(unavailable_bytes)
        .ok_or(ArchiveError::Limit)?;
    if output_windows > options.query_limits.max_windows
        || output_bytes > options.query_limits.max_output_bytes
    {
        return Err(ArchiveError::Limit.into());
    }
    // Nothing is emitted until membership, all costs and the complete report
    // have passed. The ordinary archive command owns recovery and stdout.
    let mut out = String::new();
    append(
        &mut out,
        &format!(
            "{{\"schema\":\"{ARCHIVE_REPORT_SCHEMA}\",\"command\":\"query-utc\",\"codec\":\"{}\",\"snapshot\":{},\"clock_index\":{},\"namespace\":{},\"sensor\":{},\"stream\":{},\"generation\":{},\"anchor\":{},\"receive_clock\":{},\"decode_clock\":{},\"time_scale\":{},\"durable_windows\":{},\"indexed_windows\":{},\"pages\":{},\"source_replay_on_recovery\":true,\"clock_index_source_replay\":true,\"query_utc_ns\":{},\"query_bounds\":\"half_open\",\"time_basis\":\"node_read_admission_bracket\",\"utc_interval_bounds\":\"closed\",\"camera_capture_time\":\"unknown\",\"server_authenticated\":false,\"coverage_claim\":false,\"absence_claim\":false,\"candidate_windows\":{},\"clock_unavailable_windows\":{},\"whole_window_candidate_bytes\":{},\"whole_window_clock_unavailable_bytes\":{},\"whole_window_output_bytes\":{},\"all_snapshot_windows_have_clock_evidence\":{},\"candidates\":[",
            options.codec.name(),
            quoted(&identity.to_text()),
            quoted(&index.root().to_text()),
            quoted(&snapshot.namespace().digest().to_text()),
            quoted(options.scope.recording.sensor.as_str()),
            quoted(options.scope.recording.stream.as_str()),
            options.scope.recording.generation,
            quoted(&options.scope.recording.anchor.to_text()),
            quoted(&options.scope.recording.receive_clock.to_text()),
            quoted(&options.scope.decode_clock.to_text()),
            options.scope.time_scale,
            snapshot.windows().len(),
            snapshot.indexed_windows(),
            snapshot.pages().len(),
            interval(&query.interval),
            selection.ordinals().len(),
            unavailable_windows,
            selection.output_bytes(),
            unavailable_bytes,
            output_bytes,
            unavailable_windows == 0,
        ),
    )?;
    let mut first = true;
    for (ordinal, (original, binding)) in snapshot.windows().iter().zip(&bindings).enumerate() {
        clock.check()?;
        let Some(clock_ordinal) = *binding else {
            continue;
        };
        if !selection.ordinals().contains(&clock_ordinal) {
            continue;
        }
        if !first {
            append(&mut out, ",")?;
        }
        first = false;
        let window = &index.windows()[clock_ordinal];
        let bounds = window.utc_interval();
        let mut row = entry_json(ordinal, original, ordinal < snapshot.indexed_windows());
        let _ = row.pop();
        append(
            &mut row,
            &format!(
                ",\"clock_status\":\"candidate\",\"node_admission_utc_interval_ns\":[{},{}],\"source_receive_clock\":{},\"source_generation\":{}}}",
                bounds.earliest_ns,
                bounds.latest_ns,
                quoted(&options.scope.recording.receive_clock.to_text()),
                options.scope.recording.generation,
            ),
        )?;
        append(&mut out, &row)?;
    }
    append(&mut out, "],\"clock_unavailable\":[")?;
    first = true;
    for (ordinal, (original, binding)) in snapshot.windows().iter().zip(&bindings).enumerate() {
        clock.check()?;
        if binding.is_some() {
            continue;
        }
        if !first {
            append(&mut out, ",")?;
        }
        first = false;
        let mut row = entry_json(ordinal, original, ordinal < snapshot.indexed_windows());
        let _ = row.pop();
        append(
            &mut row,
            &format!(
                ",\"clock_status\":\"clock_unavailable\",\"node_admission_utc_interval_ns\":\"unknown\",\"source_receive_clock\":{},\"source_generation\":{}}}",
                quoted(&options.scope.recording.receive_clock.to_text()),
                options.scope.recording.generation,
            ),
        )?;
        append(&mut out, &row)?;
    }
    append(
        &mut out,
        "],\"range_read_completed\":false,\"payload_bytes_emitted\":0,\"complete\":true}\n",
    )?;
    clock.check()?;
    Ok(out)
}
