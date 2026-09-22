#![forbid(unsafe_code)]
//! Global association through the public perception API, not solver-only fixtures.

use fss_geometry::{GeometryError, WorkBudget};
use fss_reference::ingest::cross_camera::{
    ASSOCIATION_SCORE_SCALE, AssociationDisposition, AssociationExclusion, AssociationScore,
    CameraObservation, CrossCameraConfig, CrossCameraError, CrossCameraReport,
    MAX_CAMERA_ID_BYTES, MAX_CROSS_CAMERA_OBSERVATIONS, associate, associate_detailed,
};
use fss_twin::image_tracking::ImageTrackingError;
use std::sync::atomic::AtomicBool;

type Test = Result<(), CrossCameraError>;

fn config() -> CrossCameraConfig {
    CrossCameraConfig { max_time_delta_ns: 100, max_position_distance: 1.5, min_confidence: 0.1 }
}
fn obs(camera: &str, id: u64, x: f64) -> CameraObservation {
    CameraObservation { camera_id: camera.to_owned(), track_id: id, timestamp_ns: 0, ground_x: x, ground_y: 0.0 }
}
fn report(left: &[CameraObservation], right: &[CameraObservation]) -> Result<CrossCameraReport, CrossCameraError> {
    associate_detailed(&config(), 0, left, right, &mut WorkBudget::new(10_000_000))
}

#[test]
fn crossing_targets_use_the_better_global_pairing_not_the_best_first_edge() -> Test {
    let left = [obs("left", 1, 0.0), obs("left", 2, 1.0)];
    let right = [obs("right", 10, 0.2), obs("right", 20, -0.6)];
    // Greedy chooses 1->10, stranding 2. The full solution is 1->20, 2->10.
    let result = report(&left, &right)?;
    assert_eq!(result.assignment_cost(), 933_333);
    assert_eq!(result.left_dispositions(), &[AssociationDisposition::Matched(1), AssociationDisposition::Matched(0)]);
    let pairs = associate(&config(), &left, &right)?;
    assert_eq!(pairs.len(), 2);
    assert_eq!((pairs[0].first.track_id, pairs[0].second.track_id), (1, 20));
    assert_eq!((pairs[1].first.track_id, pairs[1].second.track_id), (2, 10));
    assert!(pairs.iter().map(|pair| pair.confidence).sum::<f64>() > 1.0);
    Ok(())
}

#[test]
fn tied_assignments_are_retained_and_the_pair_only_api_refuses_to_flatten_them() -> Test {
    let left = [obs("left", 1, -0.5), obs("left", 2, 0.5)];
    let right = [obs("right", 10, 0.0), obs("right", 20, 0.0)];
    let result = report(&left, &right)?;
    assert!(result.is_ambiguous());
    assert_eq!(result.candidates().len(), 4);
    assert_eq!(result.alternatives().len(), 2);
    assert_eq!(result.left_dispositions(), &[AssociationDisposition::Unresolved; 2]);
    assert_eq!(result.right_dispositions(), &[AssociationDisposition::Unresolved; 2]);
    for alternative in result.alternatives() {
        assert_eq!(alternative.cost, result.assignment_cost());
        assert_ne!(alternative.columns[alternative.excluded.0], Some(alternative.excluded.1));
        assert_ne!(alternative.columns[0], alternative.columns[1]);
    }
    assert!(matches!(associate(&config(), &left, &right), Err(CrossCameraError::AmbiguousAssignment)));
    Ok(())
}

#[test]
fn stable_pair_survives_alongside_a_different_ambiguous_component() -> Test {
    let left = [obs("left", 1, -0.5), obs("left", 2, 0.5), obs("left", 3, 10.0)];
    let right = [obs("right", 10, 0.0), obs("right", 20, 0.0), obs("right", 30, 10.0)];
    let result = report(&left, &right)?;
    assert!(result.is_ambiguous());
    assert_eq!(result.left_dispositions(), &[
        AssociationDisposition::Unresolved, AssociationDisposition::Unresolved, AssociationDisposition::Matched(2),
    ]);
    assert_eq!(result.right_dispositions()[2], AssociationDisposition::Matched(2));
    let stable = result.stable_pairs(&mut WorkBudget::new(100_000))?;
    assert_eq!(stable.len(), 1);
    assert_eq!((stable[0].first.track_id, stable[0].second.track_id), (3, 30));
    for alternative in result.alternatives() {
        assert_eq!(alternative.columns[2], Some(2));
    }
    Ok(())
}

#[test]
fn input_permutations_produce_the_same_complete_report() -> Test {
    let mut left = [obs("left", 1, -0.5), obs("left", 2, 0.5), obs("left", 3, 10.0)];
    let mut right = [obs("right", 10, 0.0), obs("right", 20, 0.0), obs("right", 30, 10.0)];
    let expected = report(&left, &right)?;
    for _ in 0..3 {
        left.rotate_left(1);
        for _ in 0..3 {
            right.rotate_left(1);
            assert_eq!(report(&left, &right)?, expected);
        }
    }
    Ok(())
}

#[test]
fn zero_gain_edge_is_ambiguous_with_leaving_the_observation_unmatched() -> Test {
    let config = CrossCameraConfig { min_confidence: 0.0, ..config() };
    let result = associate_detailed(&config, 0, &[obs("left", 1, 0.0)],
        &[obs("right", 2, config.max_position_distance)], &mut WorkBudget::new(1_000_000))?;
    assert_eq!(result.assignment_cost(), u64::from(ASSOCIATION_SCORE_SCALE));
    assert_eq!(result.left_dispositions(), &[AssociationDisposition::Unresolved]);
    assert!(result.is_ambiguous());
    assert_eq!(result.alternatives()[0].columns, vec![None]);
    Ok(())
}

#[test]
fn requested_margin_includes_its_boundary_and_declares_rounding_guard() -> Test {
    let config = CrossCameraConfig { max_position_distance: 2.0, ..config() };
    let left = [obs("left", 1, 0.0)];
    let right = [obs("right", 2, 0.0), obs("right", 3, 0.01)];
    let low = associate_detailed(&config, 4_998, &left, &right, &mut WorkBudget::new(1_000_000))?;
    let high = associate_detailed(&config, 4_999, &left, &right, &mut WorkBudget::new(1_000_000))?;
    assert!(!low.is_ambiguous());
    assert!(high.is_ambiguous());
    assert_eq!(high.requested_margin(), 4_999);
    assert_eq!(high.effective_margin(), 5_000);
    assert_eq!(high.config(), &config);
    Ok(())
}

#[test]
fn signed_timestamp_extremes_are_time_exclusions_not_overflow_or_matches() -> Test {
    let mut left = obs("left", 1, 0.0);
    let mut right = obs("right", 2, 0.0);
    left.timestamp_ns = i64::MIN;
    right.timestamp_ns = i64::MAX;
    for (a, b) in [(&left, &right), (&right, &left)] {
        let result = report(std::slice::from_ref(a), std::slice::from_ref(b))?;
        assert_eq!(result.candidates()[0].score, AssociationScore::Excluded(AssociationExclusion::Time));
        assert_eq!(result.left_dispositions(), &[AssociationDisposition::NoCandidate]);
    }
    Ok(())
}

#[test]
fn geometric_norm_preserves_large_and_tiny_finite_coordinates() -> Test {
    for scale in [1.0e200, 1.0e-200] {
        let config = CrossCameraConfig { max_position_distance: 2.0 * scale, ..config() };
        let left = [obs("left", 1, 0.0)];
        let mut right = [obs("right", 2, scale)];
        right[0].ground_y = scale;
        let pairs = associate(&config, &left, &right)?;
        assert_eq!(pairs.len(), 1);
        assert!((pairs[0].confidence - (1.0 - 2.0_f64.sqrt() / 2.0)).abs() < 1.0e-12);
    }
    Ok(())
}

#[test]
fn malformed_observations_are_rejected_even_when_the_other_camera_is_empty() {
    for nonfinite in [f64::NAN, f64::INFINITY, f64::NEG_INFINITY] {
        assert!(matches!(report(&[obs("left", 1, nonfinite)], &[]), Err(CrossCameraError::InvalidObservation(_))));
    }
    for camera in ["", "hidden\nrecord"] {
        assert!(matches!(report(&[obs(camera, 1, 0.0)], &[]), Err(CrossCameraError::InvalidObservation(_))));
    }
    assert!(matches!(report(&[obs("left", 0, 0.0)], &[]), Err(CrossCameraError::InvalidObservation(_))));
    assert!(matches!(report(&[obs(&"x".repeat(MAX_CAMERA_ID_BYTES + 1), 1, 0.0)], &[]), Err(CrossCameraError::Limit)));
    assert!(matches!(report(&[obs("left", 1, 0.0), obs("left", 1, 1.0)], &[]), Err(CrossCameraError::DuplicateObservation)));
    assert!(matches!(report(&[obs("left", 1, 0.0), obs("other", 2, 0.0)], &[]), Err(CrossCameraError::InvalidObservation(_))));
}

#[test]
fn empty_batches_and_unmatched_tracks_are_retained_without_forced_pairs() -> Test {
    let empty = report(&[], &[])?;
    assert!(empty.candidates().is_empty());
    assert_eq!(empty.assignment_cost(), 0);
    let left = [obs("left", 1, 0.0), obs("left", 2, 10.0)];
    let no_right = report(&left, &[])?;
    assert_eq!(no_right.left().len(), 2);
    assert_eq!(no_right.left_dispositions(), &[AssociationDisposition::NoCandidate; 2]);
    let result = report(&left, &[obs("right", 3, 0.0)])?;
    assert_eq!(result.left_dispositions(), &[AssociationDisposition::Matched(0), AssociationDisposition::NoCandidate]);
    Ok(())
}

#[test]
fn full_cartesian_report_keeps_named_time_position_confidence_and_same_camera_exclusions() -> Test {
    let left = [obs("left", 1, 0.0)];
    let mut right = [obs("right", 10, 0.0), obs("right", 20, 10.0), obs("right", 30, 1.49)];
    right[0].timestamp_ns = 101;
    let result = report(&left, &right)?;
    let reasons: Vec<_> = result.candidates().iter().map(|c| c.score).collect();
    assert_eq!(reasons, vec![AssociationScore::Excluded(AssociationExclusion::Time),
        AssociationScore::Excluded(AssociationExclusion::Position), AssociationScore::Excluded(AssociationExclusion::Confidence)]);
    let same = report(&left, &left)?;
    assert_eq!(same.candidates()[0].score, AssociationScore::Excluded(AssociationExclusion::SameCamera));
    Ok(())
}

#[test]
fn complete_input_limits_cancel_and_late_budget_exhaustion_are_typed() -> Test {
    let oversized: Vec<_> = (0..=MAX_CROSS_CAMERA_OBSERVATIONS).map(|i| obs("left", i as u64 + 1, 0.0)).collect();
    assert!(matches!(report(&oversized, &[]), Err(CrossCameraError::Limit)));
    let left = [obs("left", 1, -0.5), obs("left", 2, 0.5)];
    let right = [obs("right", 10, 0.0), obs("right", 20, 0.0)];
    let cancelled = AtomicBool::new(true);
    assert!(matches!(associate_detailed(&config(), 0, &left, &right,
        &mut WorkBudget::cancellable(1_000_000, &cancelled)),
        Err(CrossCameraError::Assignment(ImageTrackingError::Geometry(GeometryError::Cancelled)))));
    let mut budget = WorkBudget::new(1_000_000);
    let expected = associate_detailed(&config(), 0, &left, &right, &mut budget)?;
    assert!(matches!(associate_detailed(&config(), 0, &left, &right, &mut WorkBudget::new(budget.used() - 1)),
        Err(CrossCameraError::Assignment(ImageTrackingError::Geometry(GeometryError::BudgetExhausted)))));
    assert_eq!(report(&left, &right)?, expected);
    Ok(())
}

fn enumerate(costs: &[Option<u64>], columns: usize, excluded: Option<(usize, usize)>) -> u64 {
    let mut minimum = u64::MAX;
    for a in 0..columns {
        for b in 0..columns {
            if a == b || excluded == Some((0, a)) || excluded == Some((1, b)) { continue; }
            if let (Some(first), Some(second)) = (costs[a], costs[columns + b]) {
                minimum = minimum.min(first + second);
            }
        }
    }
    minimum
}

#[test]
fn global_objective_and_every_ambiguity_decision_match_exhaustive_assignments() -> Test {
    let config = CrossCameraConfig { max_position_distance: 5.0, ..config() };
    for seed in 0..200_u32 {
        let left = [obs("left", 1, f64::from(seed % 7)), obs("left", 2, f64::from((seed / 7) % 7))];
        let right = [obs("right", 10, f64::from((seed * 3) % 11)),
            obs("right", 20, f64::from((seed * 5 + 1) % 11)), obs("right", 30, f64::from((seed * 7 + 2) % 11))];
        let margin = (seed % 5) * 10_000;
        let result = associate_detailed(&config, margin, &left, &right, &mut WorkBudget::new(1_000_000))?;
        let mut costs = vec![None; 10];
        for candidate in result.candidates() {
            if let AssociationScore::Admissible { units, .. } = candidate.score {
                costs[candidate.left * 5 + candidate.right] = Some(u64::from(ASSOCIATION_SCORE_SCALE - units));
            }
        }
        costs[3] = Some(u64::from(ASSOCIATION_SCORE_SCALE));
        costs[9] = Some(u64::from(ASSOCIATION_SCORE_SCALE));
        let best = enumerate(&costs, 5, None);
        assert_eq!(result.assignment_cost(), best);
        for candidate in result.candidates().iter().filter(|candidate| candidate.selected) {
            let alternate = enumerate(&costs, 5, Some((candidate.left, candidate.right)));
            assert_eq!(candidate.exclusion_cost, Some(alternate));
            assert_eq!(candidate.ambiguous, alternate <= best + result.effective_margin());
        }
    }
    Ok(())
}
