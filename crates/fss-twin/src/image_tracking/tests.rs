#![forbid(unsafe_code)]
use super::*;
use crate::localization::ImageIdentity;
use std::sync::atomic::AtomicBool;

fn key(n: u64) -> [u8; 32] { ContentDigest::sha256(&n.to_le_bytes()).bytes() }
fn policy() -> ImageTrackingPolicy {
    ImageTrackingPolicy { maximum_tracks: 16, maximum_detections: 16, maximum_exposures: 32,
        minimum_observations: 2, maximum_misses: 2, maximum_gap_ns: 10 * SECOND,
        maximum_speed: 100, gate_padding: 2, miss_cost: 1000, ambiguity_margin: 0 }
}
fn frame(sequence: u64) -> ImageTrackingFrame {
    ImageTrackingFrame {
        source: ForegroundSource { image: ImageIdentity { exposure: key(sequence), pixels: key(10_000 + sequence),
            image_domain: key(60_000), dimensions: [1000, 100] }, camera: 1, clock: 1,
            calibration: key(50_000), capture: [sequence * SECOND, sequence * SECOND] },
        detector: key(30_000), permission_mask: key(40_000), evidence: key(20_000 + sequence),
        availability: TrackingAvailability::Available,
    }
}
fn detection(sequence: u64, id: u64, x: u32) -> ImageDetection {
    ImageDetection { id, evidence: key(100_000 + sequence * 1000 + id),
        min: [x, 10], max: [x + 4, 14], partial: false }
}
fn tracker(p: ImageTrackingPolicy) -> Result<ImageTracker, ImageTrackingError> {
    ImageTracker::new(key(999_999), p, &mut WorkBudget::new(100_000))
}
fn budget() -> WorkBudget<'static> { WorkBudget::new(100_000_000) }

#[test]
fn assignment_is_global_not_greedy() -> Result<(), ImageTrackingError> {
    let result = assign(&[1, 2, 1000, 1000, 2, 100, 1000, 1000], 2, 4, None, &mut budget())?;
    assert_eq!(result.cost, 4);
    assert_eq!(&result.columns[..2], &[1, 0]);
    Ok(())
}

fn brute(costs: &[i64], rows: usize, columns: usize, row: usize,
    used: &mut [bool; MAX_COLUMNS], excluded: Option<(usize, usize)>) -> u64 {
    if row == rows { return 0; }
    let mut best = u64::MAX / 2;
    for column in 0..columns {
        let cost = costs[row * columns + column];
        if used[column] || cost >= FORBIDDEN || excluded == Some((row, column)) { continue; }
        used[column] = true;
        best = best.min(cost as u64 + brute(costs, rows, columns, row + 1, used, excluded));
        used[column] = false;
    }
    best
}
#[test]
fn assignment_and_edge_exclusion_match_exhaustive_oracle() -> Result<(), ImageTrackingError> {
    for encoding in 0..256 {
        let mut bits = encoding; let mut costs = [9_i64; 8];
        for slot in [0, 1, 4, 5] {
            costs[slot] = match bits % 4 { 0 => FORBIDDEN, n => n - 1 };
            bits /= 4;
        }
        for excluded in [None, Some((0, 0)), Some((0, 1)), Some((1, 0)), Some((1, 1))] {
            let exact = brute(&costs, 2, 4, 0, &mut [false; MAX_COLUMNS], excluded);
            let actual = assign(&costs, 2, 4, excluded, &mut budget())?;
            assert_eq!(actual.cost, exact);
            assert_ne!(actual.columns[0], actual.columns[1]);
        }
    }
    Ok(())
}
#[test]
fn rectangular_assignment_matches_larger_generated_oracles() -> Result<(), ImageTrackingError> {
    let mut random = 17_u64;
    for rows in 1..=4 {
        for _ in 0..40 {
            let columns = rows * 2; let mut costs = vec![100; rows * columns];
            for row in 0..rows { for column in 0..rows {
                random = random.wrapping_mul(6364136223846793005).wrapping_add(1);
                costs[row * columns + column] = if random.is_multiple_of(7) { FORBIDDEN } else { (random % 99) as i64 };
            }}
            let exact = brute(&costs, rows, columns, 0, &mut [false; MAX_COLUMNS], None);
            assert_eq!(assign(&costs, rows, columns, None, &mut budget())?.cost, exact);
        }
    }
    Ok(())
}
#[test]
fn constant_velocity_preserves_two_paths_through_a_crossing() -> Result<(), ImageTrackingError> {
    let mut tracker = tracker(policy())?;
    tracker.update(frame(1), &[detection(1, 1, 10), detection(1, 2, 50)], &mut budget())?;
    tracker.update(frame(2), &[detection(2, 1, 25), detection(2, 2, 35)], &mut budget())?;
    let report = tracker.update(frame(3), &[detection(3, 1, 20), detection(3, 2, 40)], &mut budget())?;
    assert_eq!(tracker.tracks()[0].latest().detection.min[0], 40);
    assert_eq!(tracker.tracks()[1].latest().detection.min[0], 20);
    assert_eq!(tracker.tracks()[0].observations(), 3);
    assert_eq!(tracker.tracks()[0].state(), ImageTrackState::Established);
    assert_eq!(report.candidates().len(), 4);
    assert_eq!(report.assignment_cost(), 0);
    Ok(())
}
#[test]
fn ambiguous_global_assignments_are_retained_without_merging() -> Result<(), ImageTrackingError> {
    let mut tracker = tracker(policy())?;
    tracker.update(frame(1), &[detection(1, 1, 10), detection(1, 2, 30)], &mut budget())?;
    let report = tracker.update(frame(2), &[detection(2, 1, 20), detection(2, 2, 20)], &mut budget())?;
    assert_eq!(report.candidates().iter().filter(|c| c.selected && c.ambiguous).count(), 2);
    assert!(report.decisions().iter().all(|d| d.disposition == ImageDetectionDisposition::Unresolved));
    assert!(tracker.tracks().iter().all(|t| t.observations() == 1 && t.state() == ImageTrackState::Coasting));
    assert_eq!(tracker.tracks().len(), 2);
    Ok(())
}
#[test]
fn a_global_margin_and_miss_alternative_can_block_a_local_best() -> Result<(), ImageTrackingError> {
    let mut p = policy(); p.miss_cost = 25; p.ambiguity_margin = 5;
    let mut tracker = tracker(p)?;
    tracker.update(frame(1), &[detection(1, 1, 10)], &mut budget())?;
    let report = tracker.update(frame(2), &[detection(2, 1, 20)], &mut budget())?;
    assert_eq!(report.assignment_cost(), 20);
    assert!(report.candidates()[0].ambiguous);
    assert_eq!(tracker.tracks()[0].observations(), 1);
    Ok(())
}
#[test]
fn empty_and_unobservable_frames_coast_without_inventing_observations() -> Result<(), ImageTrackingError> {
    let mut tracker = tracker(policy())?;
    tracker.update(frame(1), &[detection(1, 1, 10)], &mut budget())?;
    let observed = tracker.tracks()[0].latest();
    tracker.update(frame(2), &[], &mut budget())?;
    let mut unavailable = frame(3); unavailable.availability = TrackingAvailability::Unobservable;
    let report = tracker.update(unavailable, &[detection(3, 1, 12)], &mut budget())?;
    assert_eq!(report.decisions()[0].disposition, ImageDetectionDisposition::Unavailable);
    assert_eq!(tracker.tracks()[0].latest(), observed);
    assert_eq!(tracker.tracks()[0].misses(), 2);
    tracker.update(frame(4), &[detection(4, 1, 14)], &mut budget())?;
    assert_eq!(tracker.tracks()[0].id(), 1);
    assert_eq!(tracker.tracks()[0].observations(), 2);
    assert_eq!(tracker.tracks()[0].misses(), 0);
    Ok(())
}
#[test]
fn disturbed_frame_retains_proposals_without_births() -> Result<(), ImageTrackingError> {
    let mut tracker = tracker(policy())?; let mut disturbed = frame(1);
    disturbed.availability = TrackingAvailability::Disturbed;
    let report = tracker.update(disturbed, &[detection(1, 1, 10)], &mut budget())?;
    assert!(tracker.tracks().is_empty());
    assert_eq!(report.decisions().len(), 1);
    assert_eq!(report.decisions()[0].disposition, ImageDetectionDisposition::Unavailable);
    Ok(())
}
#[test]
fn expiry_is_explicit_and_ids_are_not_reused() -> Result<(), ImageTrackingError> {
    let mut p = policy(); p.maximum_misses = 0;
    let mut tracker = tracker(p)?;
    tracker.update(frame(1), &[detection(1, 1, 10)], &mut budget())?;
    let report = tracker.update(frame(2), &[], &mut budget())?;
    assert_eq!(report.expired()[0].reason, ImageTrackExpiry::MissLimit);
    tracker.update(frame(3), &[detection(3, 1, 10)], &mut budget())?;
    assert_eq!(tracker.tracks()[0].id(), 2);
    let report = tracker.update(frame(14), &[], &mut budget())?;
    assert_eq!(report.expired()[0].reason, ImageTrackExpiry::CaptureHorizon);
    assert!(tracker.tracks().is_empty());
    Ok(())
}
#[test]
fn input_order_does_not_change_tracks_or_receipt() -> Result<(), ImageTrackingError> {
    let mut a = tracker(policy())?; let mut b = tracker(policy())?;
    for n in 1..=3 {
        let detections = [detection(n, 9, 100 + n as u32), detection(n, 2, 10 + n as u32)];
        let ra = a.update(frame(n), &detections, &mut budget())?;
        let rb = b.update(frame(n), &[detections[1], detections[0]], &mut budget())?;
        assert_eq!(ra.digest(), rb.digest()); assert_eq!(a.tracks(), b.tracks());
    }
    Ok(())
}
#[test]
fn privacy_and_generation_drift_fail_atomically() -> Result<(), ImageTrackingError> {
    let mut tracker = tracker(policy())?;
    tracker.update(frame(1), &[detection(1, 1, 10)], &mut budget())?;
    let prior = tracker.digest(); let tracks = tracker.tracks().to_vec();
    let mut changed = [frame(2); 7];
    changed[0].source.camera += 1; changed[1].source.clock += 1;
    changed[2].source.calibration = key(987); changed[3].source.image.image_domain = key(988);
    changed[4].source.image.dimensions[0] += 1; changed[5].detector = key(989);
    changed[6].permission_mask = key(990);
    for input in changed {
        assert!(matches!(tracker.update(input, &[], &mut budget()), Err(ImageTrackingError::BasisMismatch)));
        assert_eq!(tracker.digest(), prior); assert_eq!(tracker.tracks(), tracks.as_slice());
        assert_eq!(tracker.exposure_count(), 1);
    }
    Ok(())
}
#[test]
fn replays_and_overlapping_capture_intervals_are_rejected() -> Result<(), ImageTrackingError> {
    let mut tracker = tracker(policy())?;
    tracker.update(frame(1), &[], &mut budget())?;
    let mut replay = frame(2); replay.source.image.exposure = frame(1).source.image.exposure;
    assert!(matches!(tracker.update(replay, &[], &mut budget()), Err(ImageTrackingError::ReusedExposure)));
    let mut overlap = frame(2); overlap.source.capture = [SECOND, 2 * SECOND];
    assert!(matches!(tracker.update(overlap, &[], &mut budget()), Err(ImageTrackingError::CaptureOrder)));
    Ok(())
}
#[test]
fn limits_and_duplicate_records_do_not_drop_or_partially_update_tracks() -> Result<(), ImageTrackingError> {
    let mut p = policy(); p.maximum_tracks = 1; p.maximum_exposures = 2;
    let mut tracker = tracker(p)?; let prior = tracker.digest();
    assert!(matches!(tracker.update(frame(1), &[detection(1, 1, 10), detection(1, 2, 900)], &mut budget()),
        Err(ImageTrackingError::Limit)));
    assert_eq!(tracker.digest(), prior); assert_eq!(tracker.exposure_count(), 0);
    let duplicate = detection(1, 1, 10);
    assert!(matches!(tracker.update(frame(1), &[duplicate, duplicate], &mut budget()), Err(ImageTrackingError::InvalidInput)));
    tracker.update(frame(1), &[duplicate], &mut budget())?;
    tracker.update(frame(2), &[], &mut budget())?;
    assert!(matches!(tracker.update(frame(3), &[], &mut budget()), Err(ImageTrackingError::Limit)));
    Ok(())
}
#[test]
fn cancelled_and_every_insufficient_budget_leave_state_unchanged() -> Result<(), ImageTrackingError> {
    let mut measured = tracker(policy())?; let mut work = budget();
    measured.update(frame(1), &[detection(1, 1, 10)], &mut work)?;
    let required = work.used();
    for limit in 0..required {
        let mut tracker = tracker(policy())?; let before = tracker.digest();
        assert!(matches!(tracker.update(frame(1), &[detection(1, 1, 10)], &mut WorkBudget::new(limit)),
            Err(ImageTrackingError::Geometry(GeometryError::BudgetExhausted))));
        assert_eq!(tracker.digest(), before); assert!(tracker.tracks().is_empty()); assert_eq!(tracker.exposure_count(), 0);
    }
    let flag = AtomicBool::new(true); let mut tracker = tracker(policy())?;
    assert!(matches!(tracker.update(frame(1), &[], &mut WorkBudget::cancellable(100_000, &flag)),
        Err(ImageTrackingError::Geometry(GeometryError::Cancelled))));
    Ok(())
}
#[test]
fn partial_boxes_do_not_supply_speed_exclusions() -> Result<(), ImageTrackingError> {
    let mut p = policy(); p.maximum_speed = 1; p.miss_cost = 10_000;
    let mut tracker = tracker(p)?;
    tracker.update(frame(1), &[detection(1, 1, 10)], &mut budget())?;
    let mut partial = detection(2, 1, 900); partial.partial = true;
    let report = tracker.update(frame(2), &[partial], &mut budget())?;
    assert!(report.candidates()[0].cost.is_some());
    assert_eq!(tracker.tracks()[0].latest().detection, partial);
    Ok(())
}

#[test]
fn uncertain_capture_times_do_not_invent_velocity() -> Result<(), ImageTrackingError> {
    let mut tracker = tracker(policy())?;
    tracker.update(frame(1), &[detection(1, 1, 10), detection(1, 2, 50)], &mut budget())?;
    tracker.update(frame(2), &[detection(2, 1, 25), detection(2, 2, 35)], &mut budget())?;
    let mut uncertain = frame(3); uncertain.source.capture[1] += SECOND / 2;
    let report = tracker.update(uncertain, &[detection(3, 1, 20), detection(3, 2, 40)], &mut budget())?;
    // Last-observation ranking is explicit, not a midpoint-derived velocity claim.
    assert_eq!(report.assignment_cost(), 20);
    assert_eq!(report.frame().source.capture, [3 * SECOND, 3 * SECOND + SECOND / 2]);
    assert_eq!(tracker.tracks()[0].latest().detection.min[0], 20);
    Ok(())
}
