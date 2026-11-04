#![forbid(unsafe_code)]
//! Complete finite reduction over actual sealed-owner cells. No inference or I/O in this module.

use std::collections::{BTreeMap, BTreeSet};

use fss_core::ContentDigest;

use super::*;
use crate::ingest::package_zones::{
    MAX_PACKAGE_ZONE_CELLS, MAX_PACKAGE_ZONE_EVENTS, PackageZoneCell, PackageZoneEvent,
    PackageZoneEventKind, PackageZoneFrame, PackageZoneRelation,
};

type CellIndex<'a> = BTreeMap<(ContentDigest, usize, usize), &'a PackageZoneCell>;

#[allow(clippy::too_many_arguments)]
pub(super) fn derive(
    config: &QsrConfig,
    maximum_gap_ns: u64,
    frames: &[PackageZoneFrame],
    cells: &[PackageZoneCell],
    events: &[PackageZoneEvent],
    tracks: &[ContentDigest],
    health: &[bool],
    masked: &[bool],
    mut checkpoint: impl FnMut() -> Result<()>,
) -> Result<QsrObservations> {
    let zones = config.zone_roles.len();
    if frames.is_empty()
        || frames.len() > 64
        || zones == 0
        || zones > MAX_QSR_ZONES
        || maximum_gap_ns == 0
        || events.len() > MAX_PACKAGE_ZONE_EVENTS
    {
        return Err(QsrError::Limit);
    }
    let expected = tracks
        .len()
        .checked_mul(zones)
        .and_then(|n| n.checked_mul(frames.len()))
        .ok_or(QsrError::Limit)?;
    if expected > MAX_PACKAGE_ZONE_CELLS {
        return Err(QsrError::Limit);
    }
    if cells.len() != expected
        || health.len() != frames.len()
        || masked.len() != zones
        || frames
            .iter()
            .any(|frame| frame.capture.earliest > frame.capture.latest)
    {
        return Err(QsrError::Mismatch);
    }
    let tracks: BTreeSet<_> = tracks.iter().copied().collect();
    if tracks
        .len()
        .checked_mul(zones)
        .and_then(|n| n.checked_mul(frames.len()))
        != Some(expected)
    {
        return Err(QsrError::Mismatch);
    }
    let mut index = BTreeMap::new();
    for cell in cells {
        if !tracks.contains(&cell.track)
            || cell.zone >= zones
            || cell.frame >= frames.len()
            || index
                .insert((cell.track, cell.zone, cell.frame), cell)
                .is_some()
        {
            return Err(QsrError::Mismatch);
        }
    }
    let mut samples = Vec::with_capacity(zones * frames.len());
    let mut summaries = Vec::with_capacity(zones);
    for (zone, is_masked) in masked.iter().copied().enumerate() {
        checkpoint()?;
        let mut observed = BTreeSet::new();
        let mut summary = QsrZoneSummary {
            zone,
            sampled_frames: frames.len(),
            supported_frames: 0,
            unknown_frames: 0,
            frames_with_observed_tracks: 0,
            maximum_observed_count: None,
            observed_tracks: Vec::new(),
        };
        for (frame, support) in health.iter().copied().enumerate() {
            let mut sample = QsrZoneSample {
                zone,
                frame,
                presence: QsrPresence::Unknown,
                confirmed_tracks: Vec::new(),
                masked: is_masked,
                historical_screen_support: support,
                tentative_tracks: 0,
                boundary_tracks: 0,
                partial_tracks: 0,
                unobserved_tracks: 0,
            };
            for track in &tracks {
                let cell = index
                    .get(&(*track, zone, frame))
                    .ok_or(QsrError::Mismatch)?;
                if cell.detection_row.is_none() || cell.bounds.is_none() {
                    sample.unobserved_tracks += 1;
                } else if !cell.sample_confirmed {
                    sample.tentative_tracks += 1;
                } else {
                    match cell.relation {
                        PackageZoneRelation::Inside if support && !is_masked && !cell.clipped => {
                            sample.confirmed_tracks.push(*track);
                            observed.insert(*track);
                        }
                        PackageZoneRelation::Boundary => sample.boundary_tracks += 1,
                        PackageZoneRelation::Partial => sample.partial_tracks += 1,
                        _ => {}
                    }
                }
            }
            if support && !is_masked {
                summary.supported_frames += 1;
                let count = sample.confirmed_tracks.len();
                sample.presence = if count == 0 {
                    QsrPresence::NotObserved
                } else {
                    QsrPresence::Observed
                };
                summary.frames_with_observed_tracks += usize::from(count > 0);
                summary.maximum_observed_count =
                    Some(summary.maximum_observed_count.unwrap_or(0).max(count));
            } else {
                summary.unknown_frames += 1;
            }
            samples.push(sample);
        }
        summary.observed_tracks = observed.into_iter().collect();
        summaries.push(summary);
    }
    let mut dwell = Vec::new();
    for event in events
        .iter()
        .filter(|event| event.kind == PackageZoneEventKind::SampledDwell)
    {
        checkpoint()?;
        let from = event.from_frame.ok_or(QsrError::Mismatch)?;
        if !tracks.contains(&event.track)
            || event.zone >= zones
            || from > event.at_frame
            || event.at_frame > event.through_frame
            || event.through_frame >= frames.len()
            || event.minimum_duration_ns.is_none()
            || event.maximum_duration_ns.is_none()
            || masked[event.zone]
        {
            return Err(QsrError::Mismatch);
        }
        // This is a source-owner event, not a second dwell implementation. Independently assert
        // that every supporting row remains admitted before projecting its exact endpoints.
        for frame in from..=event.through_frame {
            let cell = index
                .get(&(event.track, event.zone, frame))
                .ok_or(QsrError::Mismatch)?;
            if !health[frame]
                || !frames[frame].time_reliable
                || !cell.sample_confirmed
                || cell.relation != PackageZoneRelation::Inside
                || cell.clipped
                || cell.detection_row.is_none()
                || cell.bounds.is_none()
            {
                return Err(QsrError::Mismatch);
            }
        }
        dwell.push(event.clone());
    }
    let mut result = QsrObservations {
        zones: summaries,
        samples,
        dwell,
        lane_transitions: Vec::new(),
        lane_interruptions: Vec::new(),
    };
    if !config.lane_stages.is_empty() {
        let lane: Vec<_> = config
            .lane_stages
            .iter()
            .map(|stage| {
                config
                    .zone_roles
                    .iter()
                    .position(|binding| binding.zone == *stage)
                    .ok_or(QsrError::Mismatch)
            })
            .collect::<Result<_>>()?;
        for track in tracks {
            checkpoint()?;
            lane_track(
                track,
                &lane,
                maximum_gap_ns,
                frames,
                &index,
                health,
                masked,
                &mut result,
            )?;
        }
    }
    Ok(result)
}

fn interrupt(
    result: &mut QsrObservations,
    track: ContentDigest,
    active: &mut Option<(usize, usize)>,
    at_frame: usize,
    reason: QsrLaneInterruptionReason,
) {
    if let Some((from_stage, from_frame)) = active.take() {
        result.lane_interruptions.push(QsrLaneInterruption {
            track,
            from_stage,
            from_frame,
            at_frame,
            reason,
        });
    }
}

#[allow(clippy::too_many_arguments)]
fn lane_track(
    track: ContentDigest,
    lane: &[usize],
    maximum_gap_ns: u64,
    frames: &[PackageZoneFrame],
    index: &CellIndex<'_>,
    health: &[bool],
    masked: &[bool],
    result: &mut QsrObservations,
) -> Result<()> {
    use QsrLaneInterruptionReason as Why;
    let mut active = None;
    let mut previous: Option<usize> = None;
    for (position, frame) in frames.iter().enumerate() {
        if frame.source_boundary {
            interrupt(result, track, &mut active, position, Why::SourceBoundary);
            previous = None;
        }
        let cell = index
            .get(&(track, lane[0], position))
            .ok_or(QsrError::Mismatch)?;
        let unavailable = if !health[position] {
            Some(Why::HistoricalScreening)
        } else if lane.iter().any(|zone| masked[*zone]) {
            Some(Why::MaskedStage)
        } else if !frame.time_reliable {
            Some(Why::UnreliableTime)
        } else if !cell.sample_confirmed
            || cell.detection_row.is_none()
            || cell.bounds.is_none()
            || cell.clipped
            || matches!(
                cell.relation,
                PackageZoneRelation::Partial | PackageZoneRelation::Unobserved
            )
        {
            Some(Why::MissingObservation)
        } else {
            None
        };
        if let Some(reason) = unavailable {
            interrupt(result, track, &mut active, position, reason);
            previous = None;
            continue;
        }
        if let Some(last) = previous {
            let earlier = frames[last].capture;
            if frame.capture.earliest < earlier.earliest || frame.capture.latest < earlier.latest {
                return Err(QsrError::Invalid(
                    "capture bounds regressed without a source boundary",
                ));
            }
            if frame.capture.latest.0.abs_diff(earlier.earliest.0) > u128::from(maximum_gap_ns) {
                interrupt(result, track, &mut active, position, Why::SampleGap);
            }
        }
        previous = Some(position);
        let mut inside = None;
        let mut ambiguous = false;
        for (stage, zone) in lane.iter().enumerate() {
            let candidate = index
                .get(&(track, *zone, position))
                .ok_or(QsrError::Mismatch)?;
            if candidate.relation == PackageZoneRelation::Inside {
                if inside.is_some() {
                    ambiguous = true;
                }
                inside = Some(stage);
            }
        }
        if ambiguous {
            interrupt(result, track, &mut active, position, Why::AmbiguousStage);
            previous = None;
            continue;
        }
        let Some(stage) = inside else {
            continue;
        };
        if let Some((prior_stage, first)) = active {
            if stage == prior_stage {
                continue;
            }
            if stage == prior_stage + 1 {
                let earlier = frames[first].capture;
                result.lane_transitions.push(QsrLaneTransition {
                    track,
                    from_stage: prior_stage,
                    to_stage: stage,
                    from_frame: first,
                    at_frame: position,
                    minimum_elapsed_ns: if frame.capture.earliest > earlier.latest {
                        frame.capture.earliest.0.abs_diff(earlier.latest.0)
                    } else {
                        0
                    },
                    maximum_elapsed_ns: frame.capture.latest.0.abs_diff(earlier.earliest.0),
                });
            } else {
                interrupt(
                    result,
                    track,
                    &mut active,
                    position,
                    if stage < prior_stage {
                        Why::ReversedStage
                    } else {
                        Why::SkippedStage
                    },
                );
            }
        }
        active = Some((stage, position));
    }
    Ok(())
}
