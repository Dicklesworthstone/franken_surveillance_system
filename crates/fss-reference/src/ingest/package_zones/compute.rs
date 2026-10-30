#![forbid(unsafe_code)]
//! Complete, bounded geometry and temporal derivation. No source I/O inside track/zone loops.

use std::collections::BTreeMap;

use super::*;
use crate::ingest::zone_dwell::{DwellSample, dwell_spans};

const MAX_DERIVATION_WORK: usize = 8 * 1024 * 1024;
struct Work(usize);
impl Work {
    fn charge(&mut self, amount: usize) -> Result<()> {
        self.0 = self.0.checked_sub(amount).ok_or(PackageZoneError::Limit)?;
        Ok(())
    }
}
pub(super) fn admit(tracks: usize, frames: usize, zones: usize) -> Result<usize> {
    if frames == 0
        || frames > crate::ingest::package_detect::MAX_PACKAGE_DETECT_FRAMES
        || zones == 0
        || zones > MAX_PACKAGE_ZONES
    {
        return Err(PackageZoneError::Limit);
    }
    let cells = tracks
        .checked_mul(frames)
        .and_then(|n| n.checked_mul(zones))
        .ok_or(PackageZoneError::Limit)?;
    if cells > MAX_PACKAGE_ZONE_CELLS {
        return Err(PackageZoneError::Limit);
    }
    Ok(cells)
}

pub(super) fn relation(zone: &PackageZone, bounds: [u32; 4], clipped: bool) -> PackageZoneRelation {
    if clipped {
        return PackageZoneRelation::Partial;
    }
    let m = i128::from(zone.margin) * 256;
    let [left, top, right, bottom] = bounds.map(i128::from);
    let x = i128::from(zone.x) * 256;
    let y = i128::from(zone.y) * 256;
    let end_x = (i128::from(zone.x) + i128::from(zone.width)) * 256;
    let end_y = (i128::from(zone.y) + i128::from(zone.height)) * 256;
    if right + m < x || bottom + m < y || left - m > end_x || top - m > end_y {
        PackageZoneRelation::Outside
    } else if left - m > x && top - m > y && right + m < end_x && bottom + m < end_y {
        PackageZoneRelation::Inside
    } else {
        PackageZoneRelation::Boundary
    }
}

#[derive(Clone, Copy)]
struct Assignment {
    row: u64,
    bounds: [u32; 4],
    clipped: bool,
    confirmed: bool,
}

pub(super) fn derive(
    analysis: &PackageAnalysisReport,
    config: &PackageZoneConfig,
    frames: &[PackageZoneFrame],
    privacy: &MaskBinding,
    cx: &ReplayCx,
) -> Result<(Vec<PackageZoneCell>, Vec<PackageZoneEvent>)> {
    let count = admit(analysis.tracks().len(), frames.len(), config.zones.len())?;
    let mut work = Work(MAX_DERIVATION_WORK);
    let frame_index: BTreeMap<_, _> = frames
        .iter()
        .enumerate()
        .map(|(i, f)| (f.segment, i))
        .collect();
    let record = analysis.retained().record();
    let mut cells = Vec::new();
    cells
        .try_reserve_exact(count)
        .map_err(|_| PackageZoneError::Limit)?;
    let mut events = Vec::new();
    for track in analysis.tracks() {
        checkpoint(cx, "package_zones:track")?;
        let mut assignments = vec![None; frames.len()];
        for (ordinal, observation) in track.observations.iter().enumerate() {
            let frame = *frame_index
                .get(&observation.segment)
                .ok_or(PackageZoneError::Mismatch)?;
            let source_frame = &record.frames[frame];
            work.charge(source_frame.detections.len() + analysis.tracks().len() + 1)?;
            let (row, score, bounds, _) =
                observation.detection.ok_or(PackageZoneError::Mismatch)?;
            let mut matches = source_frame.detections.iter().filter(|d| {
                d.row == row
                    && d.class_index == analysis.class_index()
                    && d.score_bits == score
                    && d.bounds == bounds
            });
            let actual = matches.next().ok_or(PackageZoneError::Mismatch)?;
            if matches.next().is_some()
                || observation.capsule_digest != source_frame.capsule_digest
                || assignments[frame].is_some()
            {
                return Err(PackageZoneError::Mismatch);
            }
            assignments[frame] = Some(Assignment {
                row,
                bounds,
                clipped: actual.clipped,
                confirmed: analysis
                    .sample_is_confirmed(track.identity, ordinal)
                    .ok_or(PackageZoneError::Mismatch)?,
            });
        }
        for (zone_index, zone) in config.zones.iter().enumerate() {
            let masked = privacy.policy().is_some_and(|p| {
                p.zone_masking([zone.x, zone.y, zone.width, zone.height])
                    .any()
            });
            let start = cells.len();
            for (frame, assignment) in assignments.iter().enumerate() {
                checkpoint(cx, "package_zones:cell")?;
                work.charge(1)?;
                cells.push(PackageZoneCell {
                    track: track.identity,
                    zone: zone_index,
                    frame,
                    relation: if masked {
                        PackageZoneRelation::Masked
                    } else {
                        assignment.map_or(PackageZoneRelation::Unobserved, |a| {
                            relation(zone, a.bounds, a.clipped)
                        })
                    },
                    sample_confirmed: assignment.is_some_and(|a| a.confirmed),
                    detection_row: assignment.map(|a| a.row),
                    bounds: assignment.map(|a| a.bounds),
                    clipped: assignment.is_some_and(|a| a.clipped),
                });
            }
            work.charge(frames.len().checked_mul(3).ok_or(PackageZoneError::Limit)?)?;
            timeline(&cells[start..], frames, config, &mut events)?;
        }
    }
    events.sort_by_key(|e| (e.track, e.zone, e.at_frame, e.kind));
    Ok((cells, events))
}

fn push(events: &mut Vec<PackageZoneEvent>, event: PackageZoneEvent) -> Result<()> {
    if events.len() == MAX_PACKAGE_ZONE_EVENTS {
        return Err(PackageZoneError::Limit);
    }
    events.try_reserve(1).map_err(|_| PackageZoneError::Limit)?;
    events.push(event);
    Ok(())
}

pub(super) fn timeline(
    cells: &[PackageZoneCell],
    frames: &[PackageZoneFrame],
    config: &PackageZoneConfig,
    events: &mut Vec<PackageZoneEvent>,
) -> Result<()> {
    let Some(first) = cells.first() else {
        return Err(PackageZoneError::Mismatch);
    };
    if cells.len() != frames.len() {
        return Err(PackageZoneError::Mismatch);
    }
    let mut prior: Option<(PackageZoneRelation, usize)> = None;
    let mut last_sample: Option<usize> = None;
    for (index, cell) in cells.iter().enumerate() {
        let frame = &frames[index];
        let definite = cell.sample_confirmed
            && matches!(
                cell.relation,
                PackageZoneRelation::Inside | PackageZoneRelation::Outside
            );
        // A real complete boundary observation preserves trajectory continuity between two
        // definite sides, as in the native image-zone monitor. It never establishes a side
        // itself and never contributes to inside dwell. Partial/missing evidence clears both.
        let observable = cell.sample_confirmed
            && matches!(
                cell.relation,
                PackageZoneRelation::Inside
                    | PackageZoneRelation::Outside
                    | PackageZoneRelation::Boundary
            );
        let usable = observable && frame.time_reliable;
        let mut continuous = usable && !frame.source_boundary;
        if let Some(previous) = last_sample {
            let previous_time = frames[previous].capture;
            if usable
                && !frame.source_boundary
                && (frame.capture.earliest < previous_time.earliest
                    || frame.capture.latest < previous_time.latest)
            {
                return Err(PackageZoneError::Invalid(
                    "capture bounds regressed without a source boundary",
                ));
            }
            continuous &= previous.checked_add(1) == Some(index)
                && frame.capture.latest.0.abs_diff(previous_time.earliest.0)
                    <= u128::from(config.maximum_sample_gap_ns);
            if !continuous {
                push(
                    events,
                    event(
                        first,
                        PackageZoneEventKind::ObservationInterrupted,
                        Some(previous),
                        index,
                        0,
                    ),
                )?;
                prior = None;
                last_sample = None;
            }
        }
        if definite && cell.relation == PackageZoneRelation::Inside && prior.is_none() {
            push(
                events,
                event(first, PackageZoneEventKind::ObservedInside, None, index, 1),
            )?;
        }
        if usable && definite {
            if let Some((previous, previous_index)) = prior {
                let kind = match (previous, cell.relation) {
                    (PackageZoneRelation::Outside, PackageZoneRelation::Inside) => {
                        Some(PackageZoneEventKind::EnteredBetweenObservations)
                    }
                    (PackageZoneRelation::Inside, PackageZoneRelation::Outside) => {
                        Some(PackageZoneEventKind::LeftBetweenObservations)
                    }
                    _ => None,
                };
                if let Some(kind) = kind {
                    push(events, event(first, kind, Some(previous_index), index, 2))?;
                }
            }
            prior = Some((cell.relation, index));
        }
        if usable {
            last_sample = Some(index);
        }
    }
    if let Some(policy) = config.dwell_policy() {
        let samples: Vec<_> = cells
            .iter()
            .enumerate()
            .map(|(position, cell)| DwellSample {
                position,
                capture: frames[position]
                    .time_reliable
                    .then_some(frames[position].capture),
                matched_inside: cell.sample_confirmed
                    && cell.relation == PackageZoneRelation::Inside,
                discontinuity: frames[position].source_boundary,
            })
            .collect();
        for span in dwell_spans(&samples, policy).map_err(source)? {
            let first_time = frames[span.first].capture;
            let last_time = frames[span.last].capture;
            push(
                events,
                PackageZoneEvent {
                    kind: PackageZoneEventKind::SampledDwell,
                    track: first.track,
                    zone: first.zone,
                    from_frame: Some(span.first),
                    at_frame: span.triggered,
                    through_frame: span.last,
                    observations: span.observations,
                    minimum_duration_ns: Some(span.minimum_duration_ns),
                    maximum_duration_ns: Some(last_time.latest.0.abs_diff(first_time.earliest.0)),
                },
            )?;
        }
    }
    Ok(())
}
fn event(
    cell: &PackageZoneCell,
    kind: PackageZoneEventKind,
    from: Option<usize>,
    at: usize,
    count: usize,
) -> PackageZoneEvent {
    PackageZoneEvent {
        kind,
        track: cell.track,
        zone: cell.zone,
        from_frame: from,
        at_frame: at,
        through_frame: at,
        observations: count,
        minimum_duration_ns: None,
        maximum_duration_ns: None,
    }
}
