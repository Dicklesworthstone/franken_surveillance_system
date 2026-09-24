#![forbid(unsafe_code)]
//! Global-optimum, identity, bounded admission and atomic-refusal regressions.
use super::*;

fn config() -> TrackerConfig {
    TrackerConfig {
        min_hits: 2,
        max_misses: 3,
        iou_threshold: 0.1,
        process_noise: 1.0,
        measurement_noise: 1.0,
    }
}
fn detection(x: f64) -> Detection {
    Detection {
        box_x: x,
        box_y: 0.0,
        box_w: 20.0,
        box_h: 20.0,
    }
}
fn snapshot(t: &MultiObjectTracker) -> String {
    format!(
        "{:?}|{:?}|{:?}|{}|{}",
        t.config, t.tracks, t.kalman, t.next_id, t.frame
    )
}

#[test]
fn complete_matching_prevents_greedy_track_loss() -> Result<(), TrackerError> {
    let mut t = MultiObjectTracker::new(config())?;
    t.step(&[detection(0.0), detection(12.0)]);
    let output = t.step(&[detection(4.0), detection(-8.0)]);
    assert_eq!(output.tracks.len(), 2);
    assert_eq!(output.new_tracks, 0);
    assert_eq!(output.deleted_tracks, 0);
    assert_eq!(output.tracks[0].id, 1);
    assert_eq!(output.tracks[1].id, 2);
    assert!(output.tracks[0].cx < 3.0);
    assert!(output.tracks[1].cx > 13.0 && output.tracks[1].cx < 15.0);
    assert!(
        output
            .tracks
            .iter()
            .all(|track| track.status == TrackStatus::Confirmed)
    );
    Ok(())
}

#[test]
fn exhaustive_rectangular_assignments_match_a_brute_force_oracle() {
    // Every 2x3 matrix over forbidden, 1/4, 1/2 and full IoU: 4096 cases.
    // Enumerate every injective choice independently, including unmatched dummies.
    use super::assignment::{IOU_SCALE, minimum_cost};
    let unmatched = 3 * IOU_SCALE;
    for encoded in 0_u32..4096 {
        let mut code = encoded;
        let mut costs = [[unmatched; 5]; 2];
        for row in &mut costs {
            for cell in row.iter_mut().take(3) {
                let digit = code % 4;
                code /= 4;
                *cell = match digit {
                    0 => unmatched + IOU_SCALE,
                    1 => 3 * IOU_SCALE / 4,
                    2 => IOU_SCALE / 2,
                    _ => 0,
                };
            }
        }
        let actual = minimum_cost(2, 5, |row, column| costs[row][column]);
        assert_eq!(actual.len(), 2);
        assert_ne!(actual[0], actual[1]);
        let observed = costs[0][actual[0]] + costs[1][actual[1]];
        let mut best = i128::MAX;
        for a in 0..5 {
            for b in 0..5 {
                if a != b {
                    best = best.min(costs[0][a] + costs[1][b]);
                }
            }
        }
        assert_eq!(observed, best, "matrix {encoded}");
    }
}

#[test]
fn equal_cardinality_prefers_total_overlap_not_the_largest_single_edge() {
    let costs = [[100, 200, 3000, 3000], [300, 900, 3000, 3000]];
    let result = assignment::minimum_cost(2, 4, |row, column| costs[row][column]);
    assert_eq!(result, vec![1, 0]);
}

#[test]
fn detection_permutations_do_not_reassign_birth_ids_or_matches() -> Result<(), TrackerError> {
    let mut a = MultiObjectTracker::new(config())?;
    let mut b = MultiObjectTracker::new(config())?;
    for positions in [[0.0, 80.0], [4.0, 76.0], [8.0, 72.0], [12.0, 68.0]] {
        a.step(&[detection(positions[0]), detection(positions[1])]);
        b.step(&[detection(positions[1]), detection(positions[0])]);
        assert_eq!(snapshot(&a), snapshot(&b));
    }
    Ok(())
}

#[test]
fn crossing_trajectories_preserve_directional_ids() -> Result<(), TrackerError> {
    let mut t = MultiObjectTracker::new(config())?;
    for frame in 0..30 {
        let out = t.step(&[
            detection(f64::from(frame) * 4.0),
            detection(100.0 - f64::from(frame) * 4.0),
        ]);
        assert_eq!(out.tracks.len(), 2);
        assert_eq!(out.new_tracks, if frame == 0 { 2 } else { 0 });
    }
    assert_eq!(t.tracks[0].id, 1);
    assert_eq!(t.tracks[1].id, 2);
    assert!(t.tracks[0].cx > t.tracks[1].cx);
    assert!(t.tracks[0].vx > 3.9);
    assert!(t.tracks[1].vx < -3.9);
    Ok(())
}

#[test]
fn zero_threshold_does_not_invent_overlap_support() -> Result<(), TrackerError> {
    let mut cfg = config();
    cfg.iou_threshold = 0.0;
    cfg.min_hits = 1;
    let mut t = MultiObjectTracker::new(cfg)?;
    t.step(&[detection(0.0)]);
    let out = t.step(&[detection(100.0)]);
    assert_eq!(out.new_tracks, 1);
    assert_eq!(out.tracks[0].status, TrackStatus::Lost);
    assert_eq!(out.tracks[0].misses, 1);
    assert_eq!(out.tracks[1].id, 2);
    Ok(())
}

#[test]
fn invalid_frame_is_rejected_atomically_then_valid_retry_matches_control()
-> Result<(), Box<dyn std::error::Error>> {
    let mut t = MultiObjectTracker::new(config())?;
    t.try_step(&[detection(0.0)], TrackerLimits::default())?;
    let mut control = t.clone();
    for value in [f64::NAN, f64::INFINITY, f64::NEG_INFINITY, 0.0, -1.0] {
        let before = snapshot(&t);
        let mut bad = detection(3.0);
        bad.box_w = value;
        assert_eq!(
            t.try_step(&[detection(2.0), bad], TrackerLimits::default())
                .err(),
            Some(TrackerStepError::Detection)
        );
        assert_eq!(snapshot(&t), before);
    }
    t.try_step(&[detection(2.0)], TrackerLimits::default())?;
    control.try_step(&[detection(2.0)], TrackerLimits::default())?;
    assert_eq!(snapshot(&t), snapshot(&control));
    Ok(())
}

#[test]
fn assignment_budget_has_an_exact_admission_boundary() -> Result<(), Box<dyn std::error::Error>> {
    let mut t = MultiObjectTracker::new(config())?;
    t.try_step(&[detection(0.0), detection(80.0)], TrackerLimits::default())?;
    let before = snapshot(&t);
    let mut limits = TrackerLimits {
        max_assignment_work: 15,
        ..TrackerLimits::default()
    };
    assert_eq!(
        t.try_step(&[detection(2.0), detection(78.0)], limits).err(),
        Some(TrackerStepError::Limit)
    );
    assert_eq!(snapshot(&t), before);
    limits.max_assignment_work = 16;
    let out = t.try_step(&[detection(2.0), detection(78.0)], limits)?;
    assert_eq!(out.new_tracks, 0);
    Ok(())
}

#[test]
fn active_track_limit_refuses_the_whole_frame_without_consuming_ids()
-> Result<(), Box<dyn std::error::Error>> {
    let mut t = MultiObjectTracker::new(config())?;
    let limits = TrackerLimits {
        max_tracks: 1,
        ..TrackerLimits::default()
    };
    let before = snapshot(&t);
    assert_eq!(
        t.try_step(&[detection(0.0), detection(100.0)], limits)
            .err(),
        Some(TrackerStepError::Limit)
    );
    assert_eq!(snapshot(&t), before);
    let output = t.try_step(&[detection(0.0)], limits)?;
    assert_eq!(output.tracks[0].id, 1);
    Ok(())
}

#[test]
fn retirement_can_release_capacity_in_the_same_transaction()
-> Result<(), Box<dyn std::error::Error>> {
    let mut cfg = config();
    cfg.min_hits = 1;
    cfg.max_misses = 1;
    let mut t = MultiObjectTracker::new(cfg)?;
    let limits = TrackerLimits {
        max_tracks: 1,
        ..TrackerLimits::default()
    };
    t.try_step(&[detection(0.0)], limits)?;
    t.try_step(&[], limits)?;
    let out = t.try_step(&[detection(100.0)], limits)?;
    assert_eq!(out.deleted_tracks, 1);
    assert_eq!(out.new_tracks, 1);
    assert_eq!(out.tracks.len(), 1);
    assert_eq!(out.tracks[0].id, 2);
    Ok(())
}

#[test]
fn numerical_overflow_rolls_back_filter_and_lifecycle_state()
-> Result<(), Box<dyn std::error::Error>> {
    let mut cfg = config();
    cfg.process_noise = f64::MAX;
    cfg.measurement_noise = f64::MAX;
    let mut t = MultiObjectTracker::new(cfg)?;
    t.try_step(&[detection(0.0)], TrackerLimits::default())?;
    t.try_step(&[detection(0.0)], TrackerLimits::default())?;
    let before = snapshot(&t);
    assert_eq!(
        t.try_step(&[detection(0.0)], TrackerLimits::default())
            .err(),
        Some(TrackerStepError::Numeric)
    );
    assert_eq!(snapshot(&t), before);
    Ok(())
}

#[test]
fn exhausted_ids_and_invalid_limits_do_not_advance_state() -> Result<(), TrackerError> {
    let mut t = MultiObjectTracker::new(config())?;
    t.next_id = u64::MAX;
    let before = snapshot(&t);
    assert_eq!(
        t.try_step(&[detection(0.0)], TrackerLimits::default())
            .err(),
        Some(TrackerStepError::CounterExhausted)
    );
    assert_eq!(snapshot(&t), before);
    let limits = TrackerLimits {
        max_tracks: MAX_CHECKED_TRACKS + 1,
        ..TrackerLimits::default()
    };
    assert_eq!(t.try_step(&[], limits).err(), Some(TrackerStepError::Limit));
    assert_eq!(snapshot(&t), before);
    Ok(())
}
