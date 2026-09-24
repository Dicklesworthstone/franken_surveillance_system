#![forbid(unsafe_code)]
//! Track set contract contract tests.
mod common;
use fss_geometry::{PinholeIntrinsics, RigidPose, WorkBudget};
use fss_twin::association::*;
use fss_twin::association_hypotheses::*;
use fss_twin::stream::batch::*;
use fss_twin::stream::{ContactTrack, TrackError, TrackOptions, TrackScope};
use fss_twin::{
    ContactObservation, ProjectionError, ProjectionOptions, PropertyTwin, TrackingCamera, TwinError,
};
use std::error::Error;
use std::sync::atomic::AtomicBool;

type Test = Result<(), Box<dyn Error>>;
const NS: u64 = 1_000_000_000;
fn budget() -> WorkBudget<'static> {
    WorkBudget::new(100_000_000)
}
fn operation(sequence: u64) -> BatchOperation {
    BatchOperation {
        sequence,
        adjudication: [88; 32],
    }
}
fn policy() -> AssignmentPolicy {
    AssignmentPolicy {
        one_to_one_basis: [77; 32],
        maximum_per_factor: 1024,
        maximum_materialized: 4096,
    }
}
fn links() -> [AssignmentLink; 2] {
    [
        AssignmentLink {
            track: 1,
            detection: 1,
        },
        AssignmentLink {
            track: 2,
            detection: 2,
        },
    ]
}
fn camera(twin: &PropertyTwin) -> Result<TrackingCamera, Box<dyn Error>> {
    Ok(TrackingCamera {
        geometry: twin.basis(),
        camera: 1,
        calibration: 1,
        image_domain: 1,
        clock: 1,
        validity: [0, 100 * NS],
        error: Some(ProjectionError::EXACT),
        intrinsics: PinholeIntrinsics::new(128, 128, 100.0, 100.0, 64.0, 64.0)?,
        pose: RigidPose::from_center(
            [[1.0, 0.0, 0.0], [0.0, -1.0, 0.0], [0.0, 0.0, -1.0]],
            [2.0, 2.0, 5.0],
        )?,
    })
}
fn tracks(
    twin: &PropertyTwin,
    c: TrackingCamera,
    second_limit: bool,
) -> Result<Vec<ContactTrack>, Box<dyn Error>> {
    let mut result = Vec::new();
    for id in 1..=2_u64 {
        let options = if second_limit && id == 2 {
            TrackOptions {
                max_modes: 1,
                ..TrackOptions::default()
            }
        } else {
            TrackOptions::default()
        };
        let mut track = ContactTrack::new(
            twin,
            TrackScope {
                track: id,
                clock: 1,
                epoch: 1,
            },
            &[c],
            options,
            &mut budget(),
        )?;
        let count = if second_limit && id == 2 { 1 } else { 2 };
        for exposure in 1..=count {
            let x = if id == 1 {
                exposure as f64 * 0.5
            } else {
                4.0 - exposure as f64 * 0.5
            };
            let y = if id == 1 { 0.8 } else { 3.1 };
            let pixel = c.pose.project(c.intrinsics, [x, y, 0.0])?;
            track.ingest(
                twin,
                ContactObservation {
                    evidence: [(id * 10 + exposure) as u8; 32],
                    track: id,
                    camera: 1,
                    exposure,
                    image_domain: 1,
                    clock: 1,
                    capture: [exposure * NS; 2],
                    pixel_min: pixel,
                    pixel_max: pixel,
                    visible_contact: true,
                },
                None,
                &mut budget(),
            )?;
        }
        result.push(track);
    }
    Ok(result)
}
fn setup(
    capacity: usize,
) -> Result<(PropertyTwin, TrackingCamera, ContactTrackSet), Box<dyn Error>> {
    let twin = common::twin(&[0.0], Some(0.0))?;
    let c = camera(&twin)?;
    let owner = ContactTrackSet::new(
        &twin,
        [50; 32],
        tracks(&twin, c, false)?,
        capacity,
        &mut budget(),
    )?;
    Ok((twin, c, owner))
}
fn detections(c: TrackingCamera, exposure: u64) -> Result<Vec<UnassignedContact>, Box<dyn Error>> {
    (1..=2_u64)
        .map(|id| {
            let x = if id == 1 {
                exposure as f64 * 0.5
            } else {
                4.0 - exposure as f64 * 0.5
            };
            let y = if id == 1 { 0.8 } else { 3.1 };
            let pixel = c.pose.project(c.intrinsics, [x, y, 0.0])?;
            Ok(UnassignedContact {
                id,
                evidence: [(100 + id * 10 + exposure) as u8; 32],
                pixel_min: pixel,
                pixel_max: pixel,
                visible_contact: true,
            })
        })
        .collect()
}
fn graph(
    twin: &PropertyTwin,
    c: TrackingCamera,
    owner: &ContactTrackSet,
    exposure: u64,
    ds: &[UnassignedContact],
) -> Result<AssociationGraph, Box<dyn Error>> {
    let snapshots = owner.snapshots(&mut budget())?;
    Ok(gate_contact_batch(
        twin,
        AssociationFrame {
            camera: c,
            exposure,
            evidence: [(200 + exposure) as u8; 32],
            capture: [exposure * NS; 2],
        },
        &snapshots,
        ds,
        AssociationOptions {
            projection: ProjectionOptions::default(),
            acceleration: [0.0; 3],
            maximum_gap_ns: 30 * NS,
            maximum_witnesses: 4096,
        },
        &mut budget(),
    )?)
}
fn revisions(owner: &ContactTrackSet) -> Result<Vec<u64>, Box<dyn Error>> {
    [1, 2]
        .iter()
        .map(|id| {
            Ok(owner
                .track(*id)
                .ok_or("fixed fixture track missing")?
                .revision())
        })
        .collect()
}
#[test]
fn explicit_selection_updates_both_tracks_and_retains_original_sources() -> Test {
    let (twin, c, mut owner) = setup(4)?;
    let ds = detections(c, 3)?;
    let g = graph(&twin, c, &owner, 3, &ds)?;
    let h = factorize_associations(&g, policy(), &mut budget())?;
    let chosen = h.check_assignment(&links(), &mut budget())?;
    let result = owner.apply_selection(&twin, &chosen, operation(1), &mut budget())?;
    assert!(!result.replayed);
    assert_eq!(owner.sequence(), 1);
    assert_eq!(revisions(&owner)?, [3, 3]);
    assert_eq!(
        result
            .receipt
            .before()
            .iter()
            .map(|r| r.revision)
            .collect::<Vec<_>>(),
        [2, 2]
    );
    assert_eq!(
        result
            .receipt
            .after()
            .iter()
            .map(|r| r.revision)
            .collect::<Vec<_>>(),
        [3, 3]
    );
    assert_eq!(result.receipt.updates()[0].receipt.evidence, ds[0].evidence);
    assert_eq!(
        owner
            .track(2)
            .ok_or("track 2 missing")?
            .snapshot(3)?
            .motion()
            .ok_or("motion missing")?
            .association(),
        Some([88; 32])
    );
    assert_eq!(result.receipt.one_to_one_basis(), [77; 32]);
    assert_eq!(result.receipt.links(), links());
    Ok(())
}
#[test]
fn a_second_track_mode_limit_rolls_back_the_successfully_prepared_first() -> Test {
    let twin = common::twin(&[0.0, 1.0], Some(0.0))?;
    let c = camera(&twin)?;
    let mut owner =
        ContactTrackSet::new(&twin, [50; 32], tracks(&twin, c, true)?, 4, &mut budget())?;
    let g = graph(&twin, c, &owner, 3, &detections(c, 3)?)?;
    let h = factorize_associations(&g, policy(), &mut budget())?;
    let chosen = h.check_assignment(&links(), &mut budget())?;
    assert!(matches!(
        owner.apply_selection(&twin, &chosen, operation(1), &mut budget()),
        Err(BatchError::Track(TrackError::Twin(TwinError::Limit)))
    ));
    assert_eq!(revisions(&owner)?, [2, 1]);
    assert_eq!(owner.sequence(), 0);
    assert!(owner.last_receipt().is_none());
    Ok(())
}
#[test]
fn replaying_an_old_batch_after_newer_work_does_not_roll_back_tracks() -> Test {
    let (twin, c, mut owner) = setup(4)?;
    let g1 = graph(&twin, c, &owner, 3, &detections(c, 3)?)?;
    let h1 = factorize_associations(&g1, policy(), &mut budget())?;
    let s1 = h1.check_assignment(&links(), &mut budget())?;
    let first = owner.apply_selection(&twin, &s1, operation(1), &mut budget())?;
    let g2 = graph(&twin, c, &owner, 4, &detections(c, 4)?)?;
    let h2 = factorize_associations(&g2, policy(), &mut budget())?;
    let s2 = h2.check_assignment(&links(), &mut budget())?;
    owner.apply_selection(&twin, &s2, operation(2), &mut budget())?;
    let retry = owner.apply_selection(&twin, &s1, operation(1), &mut budget())?;
    assert!(retry.replayed);
    assert_eq!(retry.receipt, first.receipt);
    assert_eq!(owner.sequence(), 2);
    assert_eq!(revisions(&owner)?, [4, 4]);
    Ok(())
}
#[test]
fn changed_decision_or_unselected_input_cannot_reuse_a_sequence() -> Test {
    let (twin, c, mut owner) = setup(4)?;
    let ds = detections(c, 3)?;
    let mut changed = ds.clone();
    changed[1].evidence = [199; 32];
    let g1 = graph(&twin, c, &owner, 3, &ds)?;
    let g2 = graph(&twin, c, &owner, 3, &changed)?;
    let h1 = factorize_associations(&g1, policy(), &mut budget())?;
    let h2 = factorize_associations(&g2, policy(), &mut budget())?;
    let s1 = h1.check_assignment(&links()[..1], &mut budget())?;
    let s2 = h2.check_assignment(&links()[..1], &mut budget())?;
    owner.apply_selection(&twin, &s1, operation(1), &mut budget())?;
    assert!(matches!(
        owner.apply_selection(&twin, &s2, operation(1), &mut budget()),
        Err(BatchError::ConflictingReplay)
    ));
    assert!(matches!(
        owner.apply_selection(
            &twin,
            &s1,
            BatchOperation {
                adjudication: [89; 32],
                ..operation(1)
            },
            &mut budget()
        ),
        Err(BatchError::ConflictingReplay)
    ));
    assert_eq!(revisions(&owner)?, [3, 2]);
    Ok(())
}
#[test]
fn all_unmatched_advances_only_batch_history_and_cannot_be_reassigned_silently() -> Test {
    let (twin, c, mut owner) = setup(4)?;
    let g = graph(&twin, c, &owner, 3, &detections(c, 3)?)?;
    let h = factorize_associations(&g, policy(), &mut budget())?;
    let none = h.check_assignment(&[], &mut budget())?;
    let result = owner.apply_selection(&twin, &none, operation(1), &mut budget())?;
    assert_eq!(result.receipt.unmatched_tracks(), [1, 2]);
    assert_eq!(result.receipt.unmatched_detections(), [1, 2]);
    assert!(result.receipt.updates().is_empty());
    assert_eq!(revisions(&owner)?, [2, 2]);
    let selected = h.check_assignment(&links(), &mut budget())?;
    assert!(matches!(
        owner.apply_selection(&twin, &selected, operation(2), &mut budget()),
        Err(BatchError::ReusedExposure)
    ));
    assert_eq!(owner.sequence(), 1);
    Ok(())
}
#[test]
fn evicted_retries_and_sequence_gaps_cannot_create_duplicate_updates() -> Test {
    let (twin, c, mut owner) = setup(1)?;
    let g1 = graph(&twin, c, &owner, 3, &detections(c, 3)?)?;
    let h1 = factorize_associations(&g1, policy(), &mut budget())?;
    let s1 = h1.check_assignment(&links(), &mut budget())?;
    assert!(matches!(
        owner.apply_selection(&twin, &s1, operation(2), &mut budget()),
        Err(BatchError::Sequence)
    ));
    owner.apply_selection(&twin, &s1, operation(1), &mut budget())?;
    let g2 = graph(&twin, c, &owner, 4, &detections(c, 4)?)?;
    let h2 = factorize_associations(&g2, policy(), &mut budget())?;
    let s2 = h2.check_assignment(&links(), &mut budget())?;
    owner.apply_selection(&twin, &s2, operation(2), &mut budget())?;
    assert!(matches!(
        owner.apply_selection(&twin, &s1, operation(1), &mut budget()),
        Err(BatchError::ExpiredReplay)
    ));
    assert_eq!(revisions(&owner)?, [4, 4]);
    Ok(())
}
#[test]
fn work_exhaustion_at_each_sampled_boundary_leaves_the_entire_set_unchanged() -> Test {
    let (twin, c, mut owner) = setup(4)?;
    let g = graph(&twin, c, &owner, 3, &detections(c, 3)?)?;
    let h = factorize_associations(&g, policy(), &mut budget())?;
    let selection = h.check_assignment(&links(), &mut budget())?;
    let mut full = budget();
    owner.apply_selection(&twin, &selection, operation(1), &mut full)?;
    let required = full.used();
    for limit in [
        0,
        1,
        required / 4,
        required / 2,
        required * 3 / 4,
        required - 1,
    ] {
        let (_, _, mut candidate) = setup(4)?;
        assert!(
            candidate
                .apply_selection(&twin, &selection, operation(1), &mut WorkBudget::new(limit))
                .is_err()
        );
        assert_eq!(revisions(&candidate)?, [2, 2]);
        assert_eq!(candidate.sequence(), 0);
        assert!(candidate.last_receipt().is_none());
        candidate.apply_selection(&twin, &selection, operation(1), &mut budget())?;
        assert_eq!(revisions(&candidate)?, [3, 3]);
    }
    Ok(())
}
#[test]
fn cancellation_and_invalidation_publish_neither_partial_state_nor_empty_success() -> Test {
    let (twin, c, mut owner) = setup(4)?;
    let g = graph(&twin, c, &owner, 3, &detections(c, 3)?)?;
    let h = factorize_associations(&g, policy(), &mut budget())?;
    let selected = h.check_assignment(&links(), &mut budget())?;
    let flag = AtomicBool::new(true);
    assert!(
        owner
            .apply_selection(
                &twin,
                &selected,
                operation(1),
                &mut WorkBudget::cancellable(100_000_000, &flag)
            )
            .is_err()
    );
    assert_eq!(revisions(&owner)?, [2, 2]);
    owner.apply_selection(&twin, &selected, operation(1), &mut budget())?;
    owner.invalidate();
    assert!(matches!(
        owner.apply_selection(&twin, &selected, operation(1), &mut budget()),
        Err(BatchError::Invalidated)
    ));
    assert!(owner.snapshots(&mut budget()).is_err());
    assert_eq!(
        owner
            .last_receipt()
            .ok_or("receipt missing")?
            .operation()
            .sequence,
        1
    );
    Ok(())
}
#[test]
fn a_graph_over_only_selected_tracks_cannot_ignore_other_set_members() -> Test {
    let (twin, c, mut owner) = setup(4)?;
    let g = gate_contact_batch(
        &twin,
        AssociationFrame {
            camera: c,
            exposure: 3,
            evidence: [203; 32],
            capture: [3 * NS; 2],
        },
        &[owner.track(1).ok_or("track 1 missing")?.snapshot(2)?],
        &detections(c, 3)?[..1],
        AssociationOptions {
            projection: ProjectionOptions::default(),
            acceleration: [0.0; 3],
            maximum_gap_ns: 30 * NS,
            maximum_witnesses: 4096,
        },
        &mut budget(),
    )?;
    let h = factorize_associations(&g, policy(), &mut budget())?;
    let s = h.check_assignment(&links()[..1], &mut budget())?;
    assert!(
        owner
            .apply_selection(&twin, &s, operation(1), &mut budget())
            .is_err()
    );
    assert_eq!(revisions(&owner)?, [2, 2]);
    Ok(())
}
#[test]
fn empty_detections_record_the_source_frame_without_deleting_tracks() -> Test {
    let (twin, c, mut owner) = setup(4)?;
    let g = graph(&twin, c, &owner, 3, &[])?;
    let h = factorize_associations(&g, policy(), &mut budget())?;
    let s = h.check_assignment(&[], &mut budget())?;
    let result = owner.apply_selection(&twin, &s, operation(1), &mut budget())?;
    assert!(result.receipt.unmatched_detections().is_empty());
    assert_eq!(result.receipt.unmatched_tracks(), [1, 2]);
    assert_eq!(revisions(&owner)?, [2, 2]);
    Ok(())
}
