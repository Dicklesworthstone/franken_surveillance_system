#![forbid(unsafe_code)]
//! Independent expected outcomes for count exclusions and conservative lane-stage observations.

use super::*;
use crate::ingest::package_zones::{
    PackageZoneCell, PackageZoneEvent, PackageZoneEventKind, PackageZoneFrame, PackageZoneRelation,
};
use fss_core::{CaptureInterval, TimestampNs};

struct Fixture {
    config: QsrConfig,
    frames: Vec<PackageZoneFrame>,
    cells: Vec<PackageZoneCell>,
    events: Vec<PackageZoneEvent>,
    tracks: Vec<ContentDigest>,
    health: Vec<bool>,
    masked: Vec<bool>,
    gap: u64,
}
impl Fixture {
    fn lane(stages: &[Option<usize>]) -> Self {
        let zones = vec!["order".into(), "pay".into(), "present".into()];
        let config = QsrConfig {
            zone_roles: Vec::new(),
            lane_stages: zones.clone(),
        }
        .normalized(&zones)
        .expect("fixed config");
        let track = ContentDigest::sha256(b"sealed actual trajectory");
        let frames = stages
            .iter()
            .enumerate()
            .map(|(index, _)| PackageZoneFrame {
                segment: index as u64,
                capsule_digest: ContentDigest::sha256(&(index as u64).to_be_bytes()),
                capture: CaptureInterval {
                    earliest: TimestampNs(index as i128 * 10),
                    latest: TimestampNs(index as i128 * 10 + 2),
                },
                dimensions: [64, 48],
                time_reliable: true,
                source_boundary: false,
            })
            .collect();
        let mut cells = Vec::new();
        for zone in 0..3 {
            for (frame, stage) in stages.iter().enumerate() {
                cells.push(PackageZoneCell {
                    track,
                    zone,
                    frame,
                    relation: if *stage == Some(zone) {
                        PackageZoneRelation::Inside
                    } else {
                        PackageZoneRelation::Outside
                    },
                    sample_confirmed: true,
                    detection_row: Some(7),
                    bounds: Some([256, 512, 768, 1024]),
                    clipped: false,
                });
            }
        }
        Self {
            config,
            frames,
            cells,
            events: Vec::new(),
            tracks: vec![track],
            health: vec![true; stages.len()],
            masked: vec![false; 3],
            gap: 12,
        }
    }
    fn run(&self) -> Result<QsrObservations> {
        derive::derive(
            &self.config,
            self.gap,
            &self.frames,
            &self.cells,
            &self.events,
            &self.tracks,
            &self.health,
            &self.masked,
            || Ok(()),
        )
    }
    fn frame_cells(&mut self, frame: usize, mut change: impl FnMut(&mut PackageZoneCell)) {
        for cell in &mut self.cells {
            if cell.frame == frame {
                change(cell);
            }
        }
    }
}

#[test]
fn actual_confirmed_inside_boxes_are_counted_without_promoting_tentative_or_predicted_tracks()
-> Result<()> {
    let mut f = Fixture::lane(&[Some(0), Some(0), Some(0), Some(0), Some(0)]);
    f.config.lane_stages.clear();
    f.frame_cells(0, |cell| cell.sample_confirmed = false);
    f.frame_cells(2, |cell| {
        cell.detection_row = None;
        cell.bounds = None;
        cell.relation = PackageZoneRelation::Unobserved;
    });
    f.frame_cells(3, |cell| {
        cell.relation = PackageZoneRelation::Partial;
        cell.clipped = true;
    });
    f.cells
        .iter_mut()
        .find(|cell| cell.zone == 0 && cell.frame == 4)
        .expect("cell")
        .relation = PackageZoneRelation::Boundary;
    let report = f.run()?;
    let samples = &report.samples[..5];
    assert_eq!(
        samples
            .iter()
            .map(|sample| sample.confirmed_tracks.len())
            .collect::<Vec<_>>(),
        [0, 1, 0, 0, 0]
    );
    assert_eq!(samples[0].tentative_tracks, 1);
    assert_eq!(samples[2].unobserved_tracks, 1);
    assert_eq!(samples[3].partial_tracks, 1);
    assert_eq!(samples[4].boundary_tracks, 1);
    assert_eq!(samples[2].presence, QsrPresence::NotObserved);
    assert_eq!(report.zones[0].frames_with_observed_tracks, 1);
    assert_eq!(report.zones[0].observed_tracks, f.tracks);
    Ok(())
}

#[test]
fn unknown_screening_and_zero_track_masked_zones_never_become_zero_observed_counts() -> Result<()> {
    let mut f = Fixture::lane(&[None, None]);
    f.tracks.clear();
    f.cells.clear();
    f.masked[0] = true;
    f.health[1] = false;
    let report = f.run()?;
    assert_eq!(report.zones[0].maximum_observed_count, None);
    assert_eq!(
        (
            report.zones[0].supported_frames,
            report.zones[0].unknown_frames
        ),
        (0, 2)
    );
    assert_eq!(report.samples[0].presence, QsrPresence::Unknown);
    assert_eq!(report.samples[2].presence, QsrPresence::NotObserved);
    assert_eq!(report.samples[3].presence, QsrPresence::Unknown);
    assert_eq!(report.zones[1].maximum_observed_count, Some(0));
    Ok(())
}

#[test]
fn adjacent_stage_durations_bound_first_inside_endpoints_and_preserve_observed_corridor_samples()
-> Result<()> {
    let f = Fixture::lane(&[Some(0), Some(0), None, Some(1), None, Some(2)]);
    let report = f.run()?;
    assert_eq!(report.lane_transitions.len(), 2);
    let first = &report.lane_transitions[0];
    assert_eq!(
        (
            first.from_stage,
            first.to_stage,
            first.from_frame,
            first.at_frame
        ),
        (0, 1, 0, 3)
    );
    assert_eq!(
        (first.minimum_elapsed_ns, first.maximum_elapsed_ns),
        (28, 32)
    );
    let second = &report.lane_transitions[1];
    assert_eq!(
        (second.minimum_elapsed_ns, second.maximum_elapsed_ns),
        (18, 22)
    );
    assert!(report.lane_interruptions.is_empty());
    Ok(())
}

#[test]
fn missing_tentative_clipped_unreliable_and_unhealthy_samples_interrupt_instead_of_bridging()
-> Result<()> {
    use QsrLaneInterruptionReason as Why;
    for case in 0..6 {
        let mut f = Fixture::lane(&[Some(0), None, Some(1)]);
        let expected = match case {
            0 => {
                f.frame_cells(1, |cell| {
                    cell.detection_row = None;
                    cell.bounds = None;
                    cell.relation = PackageZoneRelation::Unobserved;
                });
                Why::MissingObservation
            }
            1 => {
                f.frame_cells(1, |cell| cell.sample_confirmed = false);
                Why::MissingObservation
            }
            2 => {
                f.frame_cells(1, |cell| {
                    cell.clipped = true;
                    cell.relation = PackageZoneRelation::Partial;
                });
                Why::MissingObservation
            }
            3 => {
                f.frames[1].time_reliable = false;
                Why::UnreliableTime
            }
            4 => {
                f.health[1] = false;
                Why::HistoricalScreening
            }
            _ => {
                f.frames[1].source_boundary = true;
                Why::SourceBoundary
            }
        };
        let report = f.run()?;
        assert!(report.lane_transitions.is_empty(), "case {case}");
        assert_eq!(report.lane_interruptions.len(), 1, "case {case}");
        assert_eq!(report.lane_interruptions[0].reason, expected, "case {case}");
    }
    Ok(())
}

#[test]
fn skipped_and_reversed_stages_are_explicit_and_never_fabricate_intermediate_stops() -> Result<()> {
    let report = Fixture::lane(&[Some(0), Some(2), Some(1), Some(2)]).run()?;
    assert_eq!(report.lane_transitions.len(), 1);
    assert_eq!(
        (
            report.lane_transitions[0].from_stage,
            report.lane_transitions[0].to_stage
        ),
        (1, 2)
    );
    assert_eq!(
        report
            .lane_interruptions
            .iter()
            .map(|event| event.reason)
            .collect::<Vec<_>>(),
        [
            QsrLaneInterruptionReason::SkippedStage,
            QsrLaneInterruptionReason::ReversedStage
        ]
    );
    Ok(())
}

#[test]
fn overlapping_stage_membership_interrupts_instead_of_choosing_a_preferred_stage() -> Result<()> {
    let mut f = Fixture::lane(&[Some(0), Some(0), Some(1)]);
    f.cells
        .iter_mut()
        .find(|cell| cell.zone == 1 && cell.frame == 1)
        .expect("cell")
        .relation = PackageZoneRelation::Inside;
    let report = f.run()?;
    assert!(report.lane_transitions.is_empty());
    assert_eq!(
        report.lane_interruptions[0].reason,
        QsrLaneInterruptionReason::AmbiguousStage
    );
    // Geometry is independently visible in both zone counts, without inventing stage order.
    assert_eq!(report.samples[1].confirmed_tracks.len(), 1);
    assert_eq!(report.samples[4].confirmed_tracks.len(), 1);
    Ok(())
}

#[test]
fn privacy_masked_stage_withholds_lane_sequences_even_if_another_zone_has_observations()
-> Result<()> {
    let mut f = Fixture::lane(&[Some(0), Some(1), Some(2)]);
    f.masked[1] = true;
    let report = f.run()?;
    assert!(report.lane_transitions.is_empty());
    assert_eq!(report.zones[0].maximum_observed_count, Some(1));
    assert_eq!(report.zones[1].maximum_observed_count, None);
    Ok(())
}

#[test]
fn widening_time_uncertainty_widens_endpoints_or_withholds_continuity() -> Result<()> {
    let mut f = Fixture::lane(&[Some(0), Some(1)]);
    let original = f.run()?.lane_transitions.remove(0);
    f.gap = 100;
    f.frames[0].capture.earliest.0 -= 3;
    f.frames[0].capture.latest.0 += 3;
    f.frames[1].capture.earliest.0 -= 3;
    f.frames[1].capture.latest.0 += 3;
    let widened = f.run()?.lane_transitions.remove(0);
    assert_eq!(
        (original.minimum_elapsed_ns, original.maximum_elapsed_ns),
        (8, 12)
    );
    assert_eq!(
        (widened.minimum_elapsed_ns, widened.maximum_elapsed_ns),
        (2, 18)
    );
    f.gap = 12;
    let withheld = f.run()?;
    assert!(withheld.lane_transitions.is_empty());
    assert_eq!(
        withheld.lane_interruptions[0].reason,
        QsrLaneInterruptionReason::SampleGap
    );
    Ok(())
}

#[test]
fn regressing_clock_refuses_and_explicit_discontinuity_resets_without_negative_durations()
-> Result<()> {
    let mut f = Fixture::lane(&[Some(0), Some(1)]);
    f.frames[1].capture = CaptureInterval {
        earliest: TimestampNs(-20),
        latest: TimestampNs(-18),
    };
    assert!(matches!(f.run(), Err(QsrError::Invalid(_))));
    f.frames[1].source_boundary = true;
    let report = f.run()?;
    assert!(report.lane_transitions.is_empty());
    assert_eq!(
        report.lane_interruptions[0].reason,
        QsrLaneInterruptionReason::SourceBoundary
    );
    Ok(())
}

#[test]
fn extreme_timestamp_separation_is_a_gap_without_signed_overflow() -> Result<()> {
    let mut f = Fixture::lane(&[Some(0), Some(1)]);
    f.frames[0].capture = CaptureInterval {
        earliest: TimestampNs(i128::MIN),
        latest: TimestampNs(i128::MIN + 1),
    };
    f.frames[1].capture = CaptureInterval {
        earliest: TimestampNs(i128::MAX - 1),
        latest: TimestampNs(i128::MAX),
    };
    f.gap = u64::MAX;
    let report = f.run()?;
    assert!(report.lane_transitions.is_empty());
    assert_eq!(
        report.lane_interruptions[0].reason,
        QsrLaneInterruptionReason::SampleGap
    );
    Ok(())
}

#[test]
fn sampled_dwell_keeps_the_original_owner_endpoints_and_never_bridges_withheld_support()
-> Result<()> {
    let mut f = Fixture::lane(&[Some(0), Some(0), Some(0)]);
    let dwell = PackageZoneEvent {
        kind: PackageZoneEventKind::SampledDwell,
        track: f.tracks[0],
        zone: 0,
        from_frame: Some(0),
        at_frame: 2,
        through_frame: 2,
        observations: 3,
        minimum_duration_ns: Some(18),
        maximum_duration_ns: Some(22),
    };
    f.events.push(dwell.clone());
    assert_eq!(f.run()?.dwell, [dwell]);
    f.health[1] = false;
    assert!(matches!(f.run(), Err(QsrError::Mismatch)));
    Ok(())
}

#[test]
fn complete_cell_permutations_do_not_change_results_but_duplicate_or_missing_rows_refuse()
-> Result<()> {
    let mut f = Fixture::lane(&[Some(0), Some(1), Some(2)]);
    let expected = f.run()?;
    f.cells.reverse();
    assert_eq!(f.run()?, expected);
    f.cells[0] = f.cells[1].clone();
    assert!(matches!(f.run(), Err(QsrError::Mismatch)));
    f.cells.pop();
    assert!(matches!(f.run(), Err(QsrError::Mismatch)));
    Ok(())
}

#[test]
fn configuration_keeps_lane_order_and_refuses_unknown_duplicate_or_conflicting_roles() -> Result<()>
{
    let zones = vec!["order".into(), "pay".into(), "present".into()];
    let config = QsrConfig {
        lane_stages: vec!["present".into(), "order".into()],
        ..QsrConfig::default()
    }
    .normalized(&zones)?;
    assert_eq!(config.lane_stages, ["present", "order"]);
    assert_eq!(config.zone_roles[1].role, QsrZoneRole::Area);
    for config in [
        QsrConfig {
            lane_stages: vec!["missing".into(), "pay".into()],
            ..QsrConfig::default()
        },
        QsrConfig {
            lane_stages: vec!["pay".into(), "pay".into()],
            ..QsrConfig::default()
        },
        QsrConfig {
            lane_stages: vec!["pay".into()],
            ..QsrConfig::default()
        },
        QsrConfig {
            zone_roles: vec![QsrZoneBinding {
                zone: "pay".into(),
                role: QsrZoneRole::Register,
            }],
            lane_stages: vec!["pay".into(), "present".into()],
        },
    ] {
        assert!(config.normalized(&zones).is_err());
    }
    Ok(())
}

#[test]
fn work_bounds_and_cancellation_refuse_complete_derivation() {
    let mut f = Fixture::lane(&[Some(0), Some(1)]);
    let cancelled = derive::derive(
        &f.config,
        f.gap,
        &f.frames,
        &f.cells,
        &f.events,
        &f.tracks,
        &f.health,
        &f.masked,
        || Err(QsrError::Cancelled),
    );
    assert!(matches!(cancelled, Err(QsrError::Cancelled)));
    f.frames = vec![f.frames[0].clone(); 65];
    f.health = vec![true; 65];
    assert!(matches!(f.run(), Err(QsrError::Limit)));
    assert!(
        QsrConfig {
            lane_stages: vec!["a".into(); 17],
            ..QsrConfig::default()
        }
        .validate_shape()
        .is_err()
    );
}
