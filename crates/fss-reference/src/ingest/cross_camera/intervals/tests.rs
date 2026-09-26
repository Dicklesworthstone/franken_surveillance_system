#![forbid(unsafe_code)]
use super::*;
use fss_core::TimestampNs;
use crate::ingest::cross_camera::{CameraObservation, associate_detailed};

type Test = Result<(), CrossCameraError>;

fn config() -> CrossCameraConfig {
    CrossCameraConfig { max_time_delta_ns: 10, max_position_distance: 10.0, min_confidence: 0.0 }
}
fn capture(first: i128, last: i128) -> CaptureInterval {
    CaptureInterval { earliest: TimestampNs(first), latest: TimestampNs(last) }
}
fn obs(camera: &str, track_id: u64, first: i128, last: i128, x: f64) -> IntervalCameraObservation {
    IntervalCameraObservation {
        camera_id: camera.into(), track_id, capture: capture(first, last), ground_x: x, ground_y: 0.0,
    }
}
fn report(left: &[IntervalCameraObservation], right: &[IntervalCameraObservation])
    -> Result<IntervalAssociationReport, CrossCameraError>
{
    associate_intervals(&config(), 0, left, right, &mut WorkBudget::new(100_000_000))
}
fn point(o: &IntervalCameraObservation) -> CameraObservation {
    CameraObservation {
        camera_id: o.camera_id.clone(), track_id: o.track_id,
        timestamp_ns: midpoint(o.capture) as i64, ground_x: o.ground_x, ground_y: o.ground_y,
    }
}

#[test]
fn uncertain_best_midpoint_cannot_steal_a_valid_counterpart() -> Test {
    let left = [obs("east", 1, 0, 0, 0.0)];
    let right = [obs("west", 10, -20, 20, 0.0), obs("west", 20, 0, 0, 1.0)];
    let old = associate_detailed(&config(), 0, &[point(&left[0])],
        &right.iter().map(point).collect::<Vec<_>>(), &mut WorkBudget::new(100_000_000))?;
    assert_eq!(old.left_dispositions(), &[AssociationDisposition::Matched(0)]);
    assert!(worst_case_separation(left[0].capture, right[0].capture) > 10);
    let new = report(&left, &right)?;
    assert_eq!(new.left_dispositions(), &[AssociationDisposition::Matched(1)]);
    assert_eq!(new.right_dispositions(), &[AssociationDisposition::NoCandidate, AssociationDisposition::Matched(0)]);
    assert!(new.time_uncertain_right(0));
    assert!(new.time_uncertain_left(0));
    assert_eq!(new.candidates()[0].score, AssociationScore::Excluded(AssociationExclusion::Time));
    assert!(!new.candidates()[0].selected);
    assert_eq!(new.separations()[0].gate, IntervalTimeGate::Uncertain);
    Ok(())
}

#[test]
fn valid_assignment_ambiguity_is_not_resolved_by_discarding_uncertain_edges() -> Test {
    let left = [obs("east", 1, 0, 0, 0.0)];
    let right = [obs("west", 1, -20, 20, 0.0), obs("west", 2, 0, 0, 1.0), obs("west", 3, 0, 0, 1.0)];
    let new = report(&left, &right)?;
    assert!(new.is_ambiguous());
    assert_eq!(new.left_dispositions(), &[AssociationDisposition::Unresolved]);
    assert!(!new.alternatives().is_empty());
    assert!(new.alternatives().iter().all(|a| a.columns.iter().all(|c| *c != Some(0))));
    Ok(())
}

#[test]
fn complete_point_graph_matches_legacy_including_exclusion_costs() -> Test {
    for shift in -3..=3 {
        let left = [obs("east", 2, 4, 4, 3.0), obs("east", 1, 0, 0, 0.0)];
        let right = [obs("west", 20, shift, shift, 0.5), obs("west", 10, 4 + shift, 4 + shift, 3.5)];
        for margin in [0, 1, 500_000] {
            let new = associate_intervals(&config(), margin, &left, &right, &mut WorkBudget::new(100_000_000))?;
            let old = associate_detailed(&config(), margin,
                &left.iter().map(point).collect::<Vec<_>>(), &right.iter().map(point).collect::<Vec<_>>(),
                &mut WorkBudget::new(100_000_000))?;
            assert_eq!(new.candidates(), old.candidates());
            assert_eq!(new.left_dispositions(), old.left_dispositions());
            assert_eq!(new.right_dispositions(), old.right_dispositions());
            assert_eq!(new.alternatives(), old.alternatives());
            assert_eq!(new.assignment_cost(), old.assignment_cost());
            assert_eq!(new.effective_margin(), old.effective_margin());
            assert_eq!(new.config(), old.config());
            assert_eq!(new.requested_margin(), old.requested_margin());
        }
    }
    Ok(())
}

#[test]
fn every_selected_edge_meets_the_complete_interval_gate() -> Test {
    for width in 0..=12 {
        let left = [obs("east", 1, -width, width, 0.0), obs("east", 2, 3, 3, 5.0)];
        let right = [obs("west", 1, 0, 0, 0.0), obs("west", 2, 3, 3, 5.0)];
        let result = report(&left, &right)?;
        for (candidate, bounds) in result.candidates().iter().zip(result.separations()) {
            if candidate.selected {
                assert_eq!(bounds.gate, IntervalTimeGate::Within);
                assert!(bounds.maximum_ns <= config().max_time_delta_ns as u128);
            }
        }
    }
    Ok(())
}

#[test]
fn separation_matches_enumeration_over_all_small_intervals() {
    for a0 in -4..=4 {
        for a1 in a0..=4 {
            for b0 in -4..=4 {
                for b1 in b0..=4 {
                    let values: Vec<_> = (a0..=a1).flat_map(|a: i128| (b0..=b1).map(move |b| a.abs_diff(b))).collect();
                    for gate in 1..=5 {
                        let bounds = separation(capture(a0, a1), capture(b0, b1), gate);
                        assert_eq!(Some(bounds.minimum_ns), values.iter().copied().min());
                        assert_eq!(Some(bounds.maximum_ns), values.iter().copied().max());
                        assert_eq!(bounds.gate == IntervalTimeGate::Within, values.iter().all(|v| *v <= gate));
                        assert_eq!(bounds.gate == IntervalTimeGate::Outside, values.iter().all(|v| *v > gate));
                    }
                }
            }
        }
    }
}

#[test]
fn full_width_time_extremes_do_not_overflow_or_narrow() -> Test {
    let wide = capture(i128::MIN, i128::MAX);
    assert_eq!(midpoint(wide), -1);
    assert_eq!(midpoint(capture(i128::MIN, i128::MIN + 1)), i128::MIN);
    assert_eq!(midpoint(capture(i128::MAX - 1, i128::MAX)), i128::MAX - 1);
    assert_eq!(worst_case_separation(wide, wide), u128::MAX);
    let left = [obs("east", 1, i128::MIN, i128::MIN, 0.0)];
    let right = [obs("west", 1, i128::MAX, i128::MAX, 0.0)];
    let result = report(&left, &right)?;
    assert_eq!(result.separations()[0], IntervalSeparation {
        minimum_ns: u128::MAX, maximum_ns: u128::MAX, gate: IntervalTimeGate::Outside,
    });
    assert_eq!(result.left_dispositions(), &[AssociationDisposition::NoCandidate]);
    let result = report(&[obs("east", 1, i128::MIN, i128::MAX, 0.0)], &[obs("west", 1, i128::MIN, i128::MAX, 0.0)])?;
    assert!(result.time_uncertain_left(0));
    assert!(!result.candidates()[0].selected);
    Ok(())
}

#[test]
fn common_translation_preserves_assignment_even_outside_i64_time() -> Test {
    let base = report(&[obs("east", 1, -2, 2, 0.0)], &[obs("west", 1, 0, 4, 1.0)])?;
    for shift in [i128::MIN + 10, i128::from(i64::MAX) + 1000, i128::MAX - 10] {
        let shifted = report(&[obs("east", 1, shift - 2, shift + 2, 0.0)], &[obs("west", 1, shift, shift + 4, 1.0)])?;
        assert_eq!(shifted.candidates(), base.candidates());
        assert_eq!(shifted.separations(), base.separations());
        assert_eq!(shifted.assignment_cost(), base.assignment_cost());
        assert_eq!(shifted.left()[0].capture, capture(shift - 2, shift + 2));
    }
    Ok(())
}

#[test]
fn nonzero_width_clean_candidates_keep_the_midpoint_ranking() -> Test {
    let left = [obs("east", 1, -1, 1, 0.0)];
    let right = [obs("west", 1, 1, 3, 1.0)];
    let result = report(&left, &right)?;
    let old = associate_detailed(&config(), 0, &[point(&left[0])], &[point(&right[0])], &mut WorkBudget::new(100_000_000))?;
    assert_eq!(result.candidates(), old.candidates());
    assert_eq!(result.separations()[0].maximum_ns, 4);
    Ok(())
}

#[test]
fn time_gate_is_inclusive_but_zero_rank_does_not_force_a_match() -> Test {
    let result = report(&[obs("east", 1, 0, 0, 0.0)], &[obs("west", 1, 10, 10, 0.0)])?;
    assert_eq!(result.separations()[0].gate, IntervalTimeGate::Within);
    assert_ne!(result.left_dispositions(), &[AssociationDisposition::Matched(0)]);
    assert!(matches!(result.candidates()[0].score, AssociationScore::Admissible { units: 0, .. }));
    Ok(())
}

#[test]
fn uncertain_input_is_reported_not_silently_dropped() -> Test {
    let result = report(&[obs("east", 1, -6, 6, 0.0)], &[obs("west", 1, -6, 6, 0.0)])?;
    assert_eq!(result.left().len(), 1);
    assert_eq!(result.right().len(), 1);
    assert_eq!(result.candidates().len(), 1);
    assert_eq!(result.separations()[0].minimum_ns, 0);
    assert_eq!(result.separations()[0].maximum_ns, 12);
    assert!(result.time_uncertain_left(0));
    assert!(result.time_uncertain_right(0));
    assert!(!result.time_uncertain_left(1));
    Ok(())
}

#[test]
fn rejected_geometry_is_not_misreported_as_a_viable_time_uncertain_candidate() -> Test {
    let result = report(&[obs("east", 1, -6, 6, 0.0)], &[obs("west", 1, -6, 6, 100.0)])?;
    assert_eq!(result.candidates()[0].score, AssociationScore::Excluded(AssociationExclusion::Position));
    assert!(!result.time_uncertain_left(0));
    Ok(())
}

#[test]
fn permutation_keeps_canonical_inputs_and_global_alternatives() -> Test {
    let mut left = [obs("east", 2, -2, 2, 5.0), obs("east", 1, 0, 0, 0.0)];
    let mut right = [obs("west", 3, -20, 20, 0.0), obs("west", 2, 0, 0, 5.0), obs("west", 1, 0, 0, 1.0)];
    let expected = report(&left, &right)?;
    left.reverse(); right.reverse();
    assert_eq!(report(&left, &right)?, expected);
    Ok(())
}

#[test]
fn invalid_interval_and_camera_inputs_fail_closed() {
    let right = [obs("west", 1, 0, 0, 0.0)];
    for invalid in [obs("east", 1, 1, 0, 0.0), obs("", 1, 0, 0, 0.0),
        obs("east", 0, 0, 0, 0.0), obs("east", 1, 0, 0, f64::NAN)]
    {
        assert!(matches!(report(&[invalid], &right), Err(CrossCameraError::InvalidObservation(_))));
    }
    let duplicate = obs("east", 1, 0, 0, 0.0);
    assert!(matches!(report(&[duplicate.clone(), duplicate], &right), Err(CrossCameraError::DuplicateObservation)));
    assert!(matches!(report(&[obs("east", 1, 0, 0, 0.0), obs("other", 2, 0, 0, 0.0)], &right), Err(CrossCameraError::InvalidObservation(_))));
}

#[test]
fn hard_input_and_work_limits_never_return_partial_matches() {
    let left = [obs("east", 1, 0, 0, 0.0)];
    let right = [obs("west", 1, 0, 0, 0.0)];
    assert!(associate_intervals(&config(), 0, &left, &right, &mut WorkBudget::new(0)).is_err());
    assert!(matches!(report(&vec![left[0].clone(); 65], &right), Err(CrossCameraError::Limit)));
    assert!(associate_intervals(&config(), u32::MAX, &left, &right, &mut WorkBudget::new(100_000_000)).is_err());
}

#[test]
fn empty_and_same_camera_batches_remain_explicit() -> Test {
    let left = [obs("east", 1, 0, 0, 0.0)];
    let result = report(&left, &[])?;
    assert_eq!(result.left_dispositions(), &[AssociationDisposition::NoCandidate]);
    assert!(result.candidates().is_empty());
    let result = report(&[], &left)?;
    assert_eq!(result.right_dispositions(), &[AssociationDisposition::NoCandidate]);
    let result = report(&left, &left)?;
    assert_eq!(result.candidates()[0].score, AssociationScore::Excluded(AssociationExclusion::SameCamera));
    assert!(!result.time_uncertain_left(0));
    Ok(())
}
