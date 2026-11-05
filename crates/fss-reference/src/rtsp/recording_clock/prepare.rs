#![forbid(unsafe_code)]
//! Checked source-coordinate and clock admission before canonical preparation.

use std::collections::BTreeSet;

use super::*;
use crate::rtsp::recording::{MAX_RECORDING_MAPPINGS, MAX_RECORDING_SAMPLES};

#[allow(clippy::too_many_arguments)]
pub(super) fn prepare(
    scope: CatalogScope,
    codec: RecordingClockCodec,
    approval_digest: ContentDigest,
    exchange: LocalNtpExchange,
    terminal: HostClockSample,
    brackets: &[ReceiveClockBracket],
    windows: &[ClockWindow],
) -> Result<RecordingClockIndex> {
    validate_scope(&scope)?;
    if !valid_digest(approval_digest) {
        return Err(RecordingClockError::Scope);
    }
    if windows.is_empty()
        || windows.len() > MAX_CLOCK_WINDOWS
        || brackets.is_empty()
        || brackets.len() > MAX_CLOCK_BRACKETS
    {
        return Err(RecordingClockError::Limit);
    }
    let mut roots = BTreeSet::new();
    let mut slots = BTreeSet::new();
    let mut required = bounded_vec(windows.len() * MAX_RECORDING_PACKETS)?;
    let mut previous_end = None;
    for window in windows {
        validate_window(window, &scope, codec)?;
        if previous_end.is_some_and(|end| end > window.summary.decode_interval.start)
            || !roots.insert(window.root())
            || !slots.insert(window.slot.as_str())
        {
            return Err(RecordingClockError::Order);
        }
        previous_end = Some(window.summary.decode_interval.end);
        required.extend_from_slice(&window.admissions);
    }
    required.sort_unstable();
    required.dedup();
    if required.len() > MAX_CLOCK_BRACKETS {
        return Err(RecordingClockError::Limit);
    }

    let mut correlation = exchange.correlation()?;
    let origin_end = correlation.origin().monotonic_after_ns;
    let mut previous_admission = None;
    let mut previous_completion = origin_end;
    let mut retained = bounded_vec(required.len())?;
    for bracket in brackets {
        if previous_admission.is_some_and(|prior| prior >= bracket.admission_ns)
            || bracket.admission_ns < previous_completion
            || bracket.admission_ns > bracket.completed.monotonic_before_ns
            || bracket.completed.monotonic_after_ns < bracket.completed.monotonic_before_ns
        {
            return Err(RecordingClockError::Order);
        }
        // Even a compatible bracket omitted from the compact table may reveal
        // a discontinuity. Refuse it before retaining any successful index.
        correlation.observe_later_sample(bracket.completed)?;
        previous_admission = Some(bracket.admission_ns);
        previous_completion = bracket.completed.monotonic_after_ns;
        if required.binary_search(&bracket.admission_ns).is_ok() {
            retained.push(*bracket);
        }
    }
    if retained.len() != required.len() {
        return Err(RecordingClockError::MissingBracket);
    }
    if terminal.monotonic_before_ns < previous_completion {
        return Err(RecordingClockError::Order);
    }
    correlation.observe_later_sample(terminal)?;

    // Bracket compatibility is not transitive: removing an intermediate wide
    // sample may expose a contradiction between the remaining neighbours. The
    // exact retained table must independently replay before it can be published.
    // Use that same monitor for projection so cold decoding is canonical.
    correlation = exchange.correlation()?;
    for bracket in &retained {
        correlation.observe_later_sample(bracket.completed)?;
    }
    correlation.observe_later_sample(terminal)?;

    let mut entries = bounded_vec(windows.len())?;
    for window in windows {
        let earliest = *window
            .admissions
            .first()
            .ok_or(RecordingClockError::MissingBracket)?;
        let mut latest = earliest;
        for admission in &window.admissions {
            let position = retained
                .binary_search_by_key(admission, |bracket| bracket.admission_ns)
                .map_err(|_| RecordingClockError::MissingBracket)?;
            latest = latest.max(retained[position].completed.monotonic_after_ns);
        }
        // Retain the asymmetric projected endpoints; separately enforce the
        // existing per-instant v1 uncertainty ceiling at both ends.
        correlation.witness_at(earliest)?;
        correlation.witness_at(latest)?;
        let utc = UtcInterval {
            earliest_ns: correlation.project(earliest)?.earliest_ns,
            latest_ns: correlation.project(latest)?.latest_ns,
        };
        if utc.earliest_ns > utc.latest_ns {
            return Err(RecordingClockError::Interval);
        }
        entries.push(ClockIndexEntry {
            window: window.clone(),
            utc,
        });
    }
    let index = wire::encode(
        &scope,
        codec,
        approval_digest,
        &exchange,
        terminal,
        &retained,
        &entries,
    )?;
    let manifest = manifest(&entries, digest(&index)?)?;
    if index
        .len()
        .checked_add(manifest.canonical_bytes().len())
        .is_none_or(|bytes| bytes > MAX_CLOCK_INDEX_BYTES)
    {
        return Err(RecordingClockError::Limit);
    }
    Ok(RecordingClockIndex {
        scope,
        codec,
        approval_digest,
        exchange,
        terminal,
        brackets: retained,
        windows: entries,
        index,
        manifest,
    })
}

pub(super) fn validate_scope(scope: &CatalogScope) -> Result<()> {
    if scope.recording.generation == 0
        || scope.time_scale == 0
        || !valid_digest(scope.recording.anchor)
        || !valid_digest(scope.recording.receive_clock)
        || !valid_digest(scope.decode_clock)
    {
        return Err(RecordingClockError::Scope);
    }
    Ok(())
}

fn validate_window(
    window: &ClockWindow,
    scope: &CatalogScope,
    codec: RecordingClockCodec,
) -> Result<()> {
    if window.codec != codec
        || window.summary.scope != scope.recording
        || window.summary.time_scale != scope.time_scale
    {
        return Err(RecordingClockError::Scope);
    }
    if !(1..=MAX_RECORDING_PACKETS).contains(&window.summary.packets)
        || !(1..=MAX_RECORDING_SAMPLES).contains(&window.summary.samples)
        || !(1..=MAX_RECORDING_MAPPINGS).contains(&window.summary.nals)
        || !(1..=MAX_RECORDING_BYTES).contains(&window.bytes)
        || window.admissions.is_empty()
        || window.admissions.len() > window.summary.packets
    {
        return Err(RecordingClockError::Limit);
    }
    if window.summary.decode_interval.start >= window.summary.decode_interval.end {
        return Err(RecordingClockError::Interval);
    }
    if window.admissions.windows(2).any(|pair| pair[0] >= pair[1]) {
        return Err(RecordingClockError::Order);
    }
    if !valid_digest(window.root()) || window.leaves.iter().any(|value| !valid_digest(*value)) {
        return Err(RecordingClockError::Digest);
    }
    let original = ObjectManifest::new(
        codec.recording_kind(),
        window.leaves[..3].iter().copied(),
        Some(window.leaves[3]),
    )
    .map_err(|_| RecordingClockError::Digest)?;
    if original.root() != window.root() {
        return Err(RecordingClockError::Digest);
    }
    Ok(())
}

pub(super) fn manifest(
    entries: &[ClockIndexEntry],
    metadata: ContentDigest,
) -> Result<ObjectManifest> {
    let mut children = BTreeSet::new();
    for entry in entries {
        children.insert(entry.root());
        children.extend(entry.original_leaf_digests());
    }
    ObjectManifest::new(CLOCK_INDEX_KIND, children, Some(metadata))
        .map_err(|_| RecordingClockError::Digest)
}
