#![forbid(unsafe_code)]
//! Executes the actual production evaluator without the unrelated async runtime.
//! Its existing hand-computed regression suite is included by the same source.

#[path = "../../fss-reference/src/evaluation.rs"]
mod evaluation;

use std::cell::Cell;

use evaluation::{
    CandidateSet, ClosedIntervalNs, EvaluationError, EvaluationIdentity, EvaluationLimit,
    EvaluationPolicy, EventCandidate, FalseAlertBudget, LabelSet, LabeledClip,
    NotObservableInterval, NotObservableReason, TruthEvent, evaluate, evaluate_cancellable,
};

fn identity() -> EvaluationIdentity {
    EvaluationIdentity {
        pipeline_generation: "native-pipeline-test".into(),
        model_generation: "native-model-test".into(),
        policy_generation: "declared-label-policy-test".into(),
    }
}

fn policy() -> EvaluationPolicy {
    EvaluationPolicy {
        early_tolerance_ns: 0,
        late_tolerance_ns: 0,
        false_alert_budget: FalseAlertBudget {
            max_false_alerts: 1,
            per_observed_ns: 1000,
        },
    }
}

fn candidate(id: &str, detect_ns: u64, score_ppm: u32) -> EventCandidate {
    EventCandidate {
        candidate_id: id.into(),
        clip_id: "clip".into(),
        class: "person".into(),
        zone: None,
        detect_ns,
        score_ppm,
    }
}

fn fixture() -> (LabelSet, CandidateSet) {
    let labels = LabelSet {
        clips: vec![LabeledClip {
            clip_id: "clip".into(),
            duration_ns: 1000,
            not_observable: vec![NotObservableInterval {
                interval: ClosedIntervalNs::new(200, 209),
                reason: NotObservableReason::SensorDown,
            }],
        }],
        events: [("seen", 20, 29), ("hidden", 200, 209), ("missed", 350, 359)]
            .into_iter()
            .map(|(id, start, end)| TruthEvent {
                event_id: id.into(),
                clip_id: "clip".into(),
                class: "person".into(),
                zone: None,
                interval: ClosedIntervalNs::new(start, end),
            })
            .collect(),
    };
    let candidates = CandidateSet {
        candidates: vec![
            candidate("first", 20, 900_000),
            candidate("hidden", 200, 800_000),
            candidate("late", 380, 700_000),
            candidate("false", 100, 700_000),
        ],
    };
    (labels, candidates)
}

#[test]
fn exact_matching_bound_preserves_legacy_report_bytes_and_metrics() -> Result<(), EvaluationError> {
    let (labels, candidates) = fixture();
    assert_eq!(
        evaluate_cancellable(&identity(), &policy(), &labels, &candidates, 11, &|| false),
        Err(EvaluationError::LimitExceeded {
            limit: EvaluationLimit::MatchingCells,
            max: 11,
            actual: 12,
        }),
    );
    let report = evaluate_cancellable(&identity(), &policy(), &labels, &candidates, 12, &|| false)?;
    assert_eq!(
        report,
        evaluate(&identity(), &policy(), &labels, &candidates)?
    );
    assert!(report.verify_digest());
    assert_eq!(report.counts.true_positives, 1);
    assert_eq!(report.counts.false_positives, 2);
    assert_eq!(report.counts.false_negatives, 1);
    assert_eq!(report.counts.not_observable_truth_events, 1);
    assert_eq!(report.counts.candidates_inside_not_observable, 1);
    assert_eq!(report.durations.observed_ns, 990);
    Ok(())
}

#[test]
fn every_cancellation_boundary_refuses_without_a_partial_report() -> Result<(), EvaluationError> {
    let (labels, candidates) = fixture();
    let checks = Cell::new(0);
    let count = || {
        checks.set(checks.get() + 1);
        false
    };
    evaluate_cancellable(&identity(), &policy(), &labels, &candidates, 12, &count)?;
    let total = checks.get();
    assert!(total > candidates.candidates.len() + labels.events.len());
    for stop in 1..=total {
        let checks = Cell::new(0);
        let cancelled = || {
            checks.set(checks.get() + 1);
            checks.get() >= stop
        };
        assert_eq!(
            evaluate_cancellable(&identity(), &policy(), &labels, &candidates, 12, &cancelled),
            Err(EvaluationError::Cancelled),
            "cancellation boundary {stop}/{total}",
        );
    }
    Ok(())
}

#[test]
fn matching_admission_cannot_be_bypassed_by_class_or_coverage_filtering() {
    let (labels, mut candidates) = fixture();
    for candidate in &mut candidates.candidates {
        candidate.class = "unmatched-class".into();
        candidate.detect_ns = 200;
    }
    assert_eq!(
        evaluate_cancellable(&identity(), &policy(), &labels, &candidates, 11, &|| false),
        Err(EvaluationError::LimitExceeded {
            limit: EvaluationLimit::MatchingCells,
            max: 11,
            actual: 12,
        }),
    );
}

#[test]
fn zero_matching_cells_admit_negative_clips_and_empty_candidate_sets() -> Result<(), EvaluationError>
{
    let (mut labels, candidates) = fixture();
    labels.events.clear();
    let report = evaluate_cancellable(&identity(), &policy(), &labels, &candidates, 0, &|| false)?;
    assert_eq!(report.counts.false_positives, 3);
    assert_eq!(report.counts.candidates_inside_not_observable, 1);
    assert_eq!(report.durations.observed_ns, 990);
    let (labels, _) = fixture();
    let report = evaluate_cancellable(
        &identity(),
        &policy(),
        &labels,
        &CandidateSet::default(),
        0,
        &|| false,
    )?;
    assert_eq!(report.counts.false_negatives, 2);
    assert_eq!(report.counts.not_observable_truth_events, 1);
    Ok(())
}

#[test]
fn many_merged_gaps_keep_closed_endpoint_and_observed_duration_semantics()
-> Result<(), EvaluationError> {
    let mut gaps = Vec::new();
    let mut candidates = CandidateSet::default();
    for i in 0..128 {
        gaps.push(NotObservableInterval {
            interval: ClosedIntervalNs::new(i * 10 + 2, i * 10 + 4),
            reason: NotObservableReason::Occluded,
        });
        gaps.push(NotObservableInterval {
            interval: ClosedIntervalNs::new(i * 10 + 5, i * 10 + 5),
            reason: NotObservableReason::Uncalibrated,
        });
        for offset in [2, 5, 6] {
            candidates.candidates.push(candidate(
                &format!("c{i}-{offset}"),
                i * 10 + offset,
                500_000,
            ));
        }
    }
    let labels = LabelSet {
        clips: vec![LabeledClip {
            clip_id: "clip".into(),
            duration_ns: 1280,
            not_observable: gaps,
        }],
        events: Vec::new(),
    };
    let report = evaluate_cancellable(&identity(), &policy(), &labels, &candidates, 0, &|| false)?;
    assert_eq!(report.counts.candidates_inside_not_observable, 256);
    assert_eq!(report.counts.false_positives, 128);
    assert_eq!(report.durations.not_observable_ns, 512);
    assert_eq!(report.durations.observed_ns, 768);
    Ok(())
}

#[test]
fn disjoint_truth_windows_skip_irrelevant_matching_cells() -> Result<(), EvaluationError> {
    let (mut labels, mut candidates) = fixture();
    let n = 1024_u32;
    labels.clips[0].duration_ns = u64::from(n) * 10;
    labels.clips[0].not_observable.clear();
    labels.events.clear();
    candidates.candidates.clear();
    for i in 0..n {
        let at = u64::from(i) * 10;
        labels.events.push(TruthEvent {
            event_id: format!("truth-{i}"),
            clip_id: "clip".into(),
            class: "person".into(),
            zone: None,
            interval: ClosedIntervalNs::new(at, at + 1),
        });
        candidates
            .candidates
            .push(candidate(&format!("hit-{i}"), at + 1, i));
        candidates
            .candidates
            .push(candidate(&format!("miss-{i}"), at + 2, i));
    }
    // Every visited matching cell is a cancellation checkpoint. The former
    // scan visited over a million cells for this same bounded input.
    let visits = Cell::new(0);
    let report = evaluate_cancellable(
        &identity(),
        &policy(),
        &labels,
        &candidates,
        usize::MAX,
        &|| {
            visits.set(visits.get() + 1);
            false
        },
    )?;
    assert_eq!(report.counts.true_positives, u64::from(n));
    assert_eq!(report.counts.false_positives, u64::from(n));
    assert!(visits.get() < 40 * n);
    Ok(())
}

#[test]
fn nested_truth_intervals_preserve_long_event_and_closed_tolerance_endpoints()
-> Result<(), EvaluationError> {
    let (mut labels, _) = fixture();
    labels.clips[0].not_observable.clear();
    labels.events[0].interval = ClosedIntervalNs::new(10, 900);
    labels.events[1].interval = ClosedIntervalNs::new(20, 29);
    labels.events[2].interval = ClosedIntervalNs::new(30, 39);
    let candidates = CandidateSet {
        candidates: vec![
            candidate("long", 902, 3),
            candidate("short", 19, 2),
            candidate("outside", 42, 1),
        ],
    };
    let mut policy = policy();
    policy.early_tolerance_ns = 1;
    policy.late_tolerance_ns = 2;
    let result = evaluate(&identity(), &policy, &labels, &candidates)?;
    assert_eq!(result.counts.true_positives, 2);
    assert_eq!(result.counts.false_positives, 1);
    assert_eq!(result.counts.false_negatives, 1);
    Ok(())
}
