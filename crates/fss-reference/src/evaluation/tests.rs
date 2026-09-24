//! Hand-computed tests for the event-level evaluation harness (fss-zta8j).
//!
//! Every expected value below was computed by hand from the documented rules; none is read back
//! from the implementation. These synthetic cases prove the scoring arithmetic only, not the
//! detection quality of any pipeline.

use super::*;

const DAY: u64 = NANOS_PER_DAY;

fn identity() -> EvaluationIdentity {
    EvaluationIdentity {
        pipeline_generation: "pipeline-g1".to_owned(),
        model_generation: "model-g7".to_owned(),
        policy_generation: "policy-g2".to_owned(),
    }
}

fn policy(early: u64, late: u64, budget: FalseAlertBudget) -> EvaluationPolicy {
    EvaluationPolicy {
        early_tolerance_ns: early,
        late_tolerance_ns: late,
        false_alert_budget: budget,
    }
}

fn clip(id: &str, duration_ns: u64, gaps: &[(u64, u64)]) -> LabeledClip {
    LabeledClip {
        clip_id: id.to_owned(),
        duration_ns,
        not_observable: gaps
            .iter()
            .map(|&(start, end)| NotObservableInterval {
                interval: ClosedIntervalNs::new(start, end),
                reason: NotObservableReason::Occluded,
            })
            .collect(),
    }
}

fn truth(
    id: &str,
    clip_id: &str,
    class: &str,
    zone: Option<&str>,
    start: u64,
    end: u64,
) -> TruthEvent {
    TruthEvent {
        event_id: id.to_owned(),
        clip_id: clip_id.to_owned(),
        class: class.to_owned(),
        zone: zone.map(str::to_owned),
        interval: ClosedIntervalNs::new(start, end),
    }
}

fn cand(
    id: &str,
    clip_id: &str,
    class: &str,
    zone: Option<&str>,
    detect: u64,
    score: u32,
) -> EventCandidate {
    EventCandidate {
        candidate_id: id.to_owned(),
        clip_id: clip_id.to_owned(),
        class: class.to_owned(),
        zone: zone.map(str::to_owned),
        detect_ns: detect,
        score_ppm: score,
    }
}

fn ratio(numerator: u64, denominator: u64) -> Ratio {
    Ratio::Defined {
        numerator,
        denominator,
    }
}

fn point(threshold: u32, tp: u64, fp: u64, positives: u64, within: bool) -> PrPoint {
    PrPoint {
        threshold_ppm: threshold,
        true_positives: tp,
        false_positives: fp,
        precision: ratio(tp, tp + fp),
        recall: ratio(tp, positives),
        within_false_alert_budget: within,
    }
}

fn run(
    policy: &EvaluationPolicy,
    labels: &LabelSet,
    candidates: &[EventCandidate],
) -> Result<EvaluationReport, EvaluationError> {
    evaluate(
        &identity(),
        policy,
        labels,
        &CandidateSet {
            candidates: candidates.to_vec(),
        },
    )
}

fn disposition_of<'a>(
    report: &'a EvaluationReport,
    candidate_id: &str,
) -> Option<&'a CandidateDisposition> {
    report
        .candidate_outcomes
        .iter()
        .find(|outcome| outcome.candidate_id == candidate_id)
        .map(|outcome| &outcome.disposition)
}

fn truth_of<'a>(report: &'a EvaluationReport, event_id: &str) -> Option<&'a TruthDisposition> {
    report
        .truth_outcomes
        .iter()
        .find(|outcome| outcome.event_id == event_id)
        .map(|outcome| &outcome.disposition)
}

/// Three events, five candidates, one clip lasting exactly one day.
fn three_by_five() -> (LabelSet, Vec<EventCandidate>) {
    let labels = LabelSet {
        clips: vec![clip("cam1", DAY, &[])],
        events: vec![
            truth("e1", "cam1", "person", None, 1_000, 2_000),
            truth("e2", "cam1", "person", None, 10_000, 11_000),
            truth("e3", "cam1", "person", None, 20_000, 21_000),
        ],
    };
    let candidates = vec![
        cand("k1", "cam1", "person", None, 1_500, 900_000), // e1, TTD 500
        cand("k2", "cam1", "person", None, 50_000, 800_000), // FP
        cand("k3", "cam1", "person", None, 10_000, 700_000), // e2, TTD 0
        cand("k4", "cam1", "person", None, 60_000, 600_000), // FP
        cand("k5", "cam1", "person", None, 21_050, 500_000), // e3 via late tolerance, TTD 1050
    ];
    (labels, candidates)
}

#[test]
fn evaluation_three_events_five_candidates_hand_computed() -> Result<(), EvaluationError> {
    let (labels, candidates) = three_by_five();
    let report = run(
        &policy(100, 100, FalseAlertBudget::per_day(1)),
        &labels,
        &candidates,
    )?;
    // P = 3. Curve (threshold, TP, FP):
    //   900k: 1,0  precision 1/1  recall 1/3
    //   800k: 1,1  precision 1/2  recall 1/3
    //   700k: 2,1  precision 2/3  recall 2/3
    //   600k: 2,2  precision 2/4  recall 2/3
    //   500k: 3,2  precision 3/5  recall 3/3
    // Budget 1 FA per day, observed exactly one day: FP <= 1 holds down to 700k.
    assert_eq!(
        report.pr_curve,
        vec![
            point(900_000, 1, 0, 3, true),
            point(800_000, 1, 1, 3, true),
            point(700_000, 2, 1, 3, true),
            point(600_000, 2, 2, 3, false),
            point(500_000, 3, 2, 3, false),
        ]
    );
    // AUPRC = 1/3 * (1 * 1/1 + 1 * 2/3 + 1 * 3/5) = 1/3 * 34/15 = 34/45 = 0.7555...
    // -> 755_555.6 ppm, rounded half-up to 755_556.
    assert_eq!(report.auprc, PpmMetric::Defined(755_556));
    assert_eq!(report.precision, ratio(3, 5));
    assert_eq!(report.recall, ratio(3, 3));
    assert_eq!(report.counts.true_positives, 3);
    assert_eq!(report.counts.false_positives, 2);
    assert_eq!(report.counts.false_negatives, 0);
    // TTDs {500, 0, 1050}: min 0, lower median 500, max 1050.
    assert_eq!(
        report.time_to_detect,
        Some(TimeToDetectSummary {
            count: 3,
            min_ns: 0,
            median_ns: 500,
            max_ns: 1_050
        })
    );
    // Operating point 700k: recall 2/3; TTDs {500 (e1), 0 (e2)} -> min 0, lower median 0, max 500.
    assert_eq!(
        report.operating_point,
        OperatingPoint::WithinBudget {
            point: point(700_000, 2, 1, 3, true),
            time_to_detect: Some(TimeToDetectSummary {
                count: 2,
                min_ns: 0,
                median_ns: 0,
                max_ns: 500
            }),
        }
    );
    assert_eq!(report.operating_point.recall(), ratio(2, 3));
    assert_eq!(
        truth_of(&report, "e3"),
        Some(&TruthDisposition::Detected {
            candidate_id: "k5".to_owned(),
            score_ppm: 500_000,
            time_to_detect_ns: 1_050
        })
    );
    assert_eq!(report.durations.observed_ns, u128::from(DAY));
    assert!(report.verify_digest());
    Ok(())
}

#[test]
fn evaluation_false_alert_budget_boundary_is_inclusive() -> Result<(), EvaluationError> {
    let (mut labels, candidates) = three_by_five();
    // Exactly at budget: 1 FP in exactly one observed day is admitted (shown above); now remove
    // one observed nanosecond with a gap far from every event/candidate: 1 FP in (DAY - 1) ns
    // exceeds 1 per DAY, so only the 900k point (0 FP) remains within budget.
    labels.clips[0].not_observable.push(NotObservableInterval {
        interval: ClosedIntervalNs::new(80_000, 80_000),
        reason: NotObservableReason::SensorDown,
    });
    let report = run(
        &policy(100, 100, FalseAlertBudget::per_day(1)),
        &labels,
        &candidates,
    )?;
    assert_eq!(report.durations.observed_ns, u128::from(DAY) - 1);
    assert_eq!(report.durations.not_observable_ns, 1);
    assert_eq!(
        report.operating_point,
        OperatingPoint::WithinBudget {
            point: point(900_000, 1, 0, 3, true),
            time_to_detect: Some(TimeToDetectSummary {
                count: 1,
                min_ns: 500,
                median_ns: 500,
                max_ns: 500
            }),
        }
    );
    // Budget of 2 per day over (DAY - 1): 2 FP => 2*DAY <= 2*(DAY-1) is false; 1 FP => DAY <=
    // 2*DAY - 2 is true, so the operating point is 700k again.
    let report = run(
        &policy(100, 100, FalseAlertBudget::per_day(2)),
        &labels,
        &candidates,
    )?;
    assert_eq!(report.operating_point.recall(), ratio(2, 3));
    // Zero budget with a false positive at the top threshold: nothing is within budget.
    let mut top_fp = candidates.clone();
    top_fp.push(cand("k0", "cam1", "person", None, 70_000, 950_000));
    let report = run(
        &policy(100, 100, FalseAlertBudget::per_day(0)),
        &labels,
        &top_fp,
    )?;
    assert_eq!(
        report.operating_point,
        OperatingPoint::NoThresholdWithinBudget {
            false_positives_at_highest_threshold: 1
        }
    );
    Ok(())
}

#[test]
fn evaluation_score_ties_break_by_candidate_id() -> Result<(), EvaluationError> {
    let labels = LabelSet {
        clips: vec![clip("cam1", 100_000, &[])],
        events: vec![truth("e1", "cam1", "car", None, 1_000, 2_000)],
    };
    // Both eligible for e1 at the same score; "a" sorts first and wins, "b" is an FP.
    let candidates = vec![
        cand("b", "cam1", "car", None, 1_100, 500_000),
        cand("a", "cam1", "car", None, 1_900, 500_000),
    ];
    let report = run(
        &policy(0, 0, FalseAlertBudget::per_day(10)),
        &labels,
        &candidates,
    )?;
    // 1 FP in 100 us of observation is far over 10 per day.
    assert_eq!(report.pr_curve, vec![point(500_000, 1, 1, 1, false)]);
    // AUPRC = 1/1 * (1 * 1/2) = 0.5.
    assert_eq!(report.auprc, PpmMetric::Defined(500_000));
    assert_eq!(
        disposition_of(&report, "a"),
        Some(&CandidateDisposition::TruePositive {
            event_id: "e1".to_owned()
        })
    );
    assert_eq!(
        disposition_of(&report, "b"),
        Some(&CandidateDisposition::FalsePositive)
    );
    // e1 detected at 1_900 by "a": TTD 900.
    assert_eq!(
        truth_of(&report, "e1"),
        Some(&TruthDisposition::Detected {
            candidate_id: "a".to_owned(),
            score_ppm: 500_000,
            time_to_detect_ns: 900
        })
    );
    Ok(())
}

#[test]
fn evaluation_duplicate_candidate_for_same_truth_is_false_positive() -> Result<(), EvaluationError>
{
    let labels = LabelSet {
        clips: vec![clip("cam1", 100_000, &[])],
        events: vec![truth("e1", "cam1", "car", None, 1_000, 2_000)],
    };
    let candidates = vec![
        cand("first", "cam1", "car", None, 1_200, 900_000),
        cand("second", "cam1", "car", None, 1_300, 800_000),
    ];
    let report = run(
        &policy(0, 0, FalseAlertBudget::per_day(10)),
        &labels,
        &candidates,
    )?;
    // Curve: 900k (1,0), 800k (1,1). AUPRC = 1 * 1/1 + 0 * 1/2 = 1.0.
    assert_eq!(
        report.pr_curve,
        vec![
            point(900_000, 1, 0, 1, true),
            point(800_000, 1, 1, 1, false)
        ]
    );
    assert_eq!(report.auprc, PpmMetric::Defined(1_000_000));
    assert_eq!(
        disposition_of(&report, "second"),
        Some(&CandidateDisposition::FalsePositive)
    );
    assert_eq!(report.counts.false_positives, 1);
    assert_eq!(report.counts.true_positives, 1);
    Ok(())
}

#[test]
fn evaluation_tolerance_boundaries() -> Result<(), EvaluationError> {
    // Event span [1000, 2000], early tolerance 100, late tolerance 200:
    // matching window is [900, 2200] inclusive.
    let labels = LabelSet {
        clips: vec![clip("cam1", 100_000, &[])],
        events: vec![
            truth("e_early_in", "cam1", "early_in", None, 1_000, 2_000),
            truth("e_early_out", "cam1", "early_out", None, 1_000, 2_000),
            truth("e_late_in", "cam1", "late_in", None, 1_000, 2_000),
            truth("e_late_out", "cam1", "late_out", None, 1_000, 2_000),
        ],
    };
    let candidates = vec![
        cand("c_early_in", "cam1", "early_in", None, 900, 500_000),
        cand("c_early_out", "cam1", "early_out", None, 899, 500_000),
        cand("c_late_in", "cam1", "late_in", None, 2_200, 500_000),
        cand("c_late_out", "cam1", "late_out", None, 2_201, 500_000),
    ];
    let report = run(
        &policy(100, 200, FalseAlertBudget::per_day(10)),
        &labels,
        &candidates,
    )?;
    assert_eq!(report.counts.true_positives, 2);
    assert_eq!(report.counts.false_positives, 2);
    assert_eq!(report.counts.false_negatives, 2);
    // Early detection clamps TTD to 0; late one is 2200 - 1000 = 1200.
    assert_eq!(
        truth_of(&report, "e_early_in"),
        Some(&TruthDisposition::Detected {
            candidate_id: "c_early_in".to_owned(),
            score_ppm: 500_000,
            time_to_detect_ns: 0
        })
    );
    assert_eq!(
        truth_of(&report, "e_late_in"),
        Some(&TruthDisposition::Detected {
            candidate_id: "c_late_in".to_owned(),
            score_ppm: 500_000,
            time_to_detect_ns: 1_200
        })
    );
    assert_eq!(
        truth_of(&report, "e_early_out"),
        Some(&TruthDisposition::Missed)
    );
    assert_eq!(
        truth_of(&report, "e_late_out"),
        Some(&TruthDisposition::Missed)
    );
    assert_eq!(
        disposition_of(&report, "c_early_out"),
        Some(&CandidateDisposition::FalsePositive)
    );
    assert_eq!(
        disposition_of(&report, "c_late_out"),
        Some(&CandidateDisposition::FalsePositive)
    );
    // Single threshold (TP 2, FP 2, P 4): AUPRC = 2/4 * 2/4 = 0.25.
    assert_eq!(report.auprc, PpmMetric::Defined(250_000));
    Ok(())
}

#[test]
fn evaluation_zone_and_class_rules() -> Result<(), EvaluationError> {
    let labels = LabelSet {
        clips: vec![clip("cam1", 100_000, &[])],
        events: vec![
            truth("z_mismatch", "cam1", "person", Some("door"), 1_000, 2_000),
            truth(
                "z_cand_none",
                "cam1",
                "person",
                Some("door"),
                10_000,
                11_000,
            ),
            truth("z_truth_none", "cam1", "person", None, 20_000, 21_000),
            truth("class_mismatch", "cam1", "person", None, 30_000, 31_000),
        ],
    };
    let candidates = vec![
        cand("c1", "cam1", "person", Some("yard"), 1_500, 400_000), // zone mismatch -> FP
        cand("c2", "cam1", "person", None, 10_500, 400_000),        // zone unspecified -> TP
        cand("c3", "cam1", "person", Some("yard"), 20_500, 400_000), // truth zone None -> TP
        cand("c4", "cam1", "vehicle", None, 30_500, 400_000),       // class mismatch -> FP
    ];
    let report = run(
        &policy(0, 0, FalseAlertBudget::per_day(10)),
        &labels,
        &candidates,
    )?;
    assert_eq!(
        disposition_of(&report, "c1"),
        Some(&CandidateDisposition::FalsePositive)
    );
    assert_eq!(
        disposition_of(&report, "c2"),
        Some(&CandidateDisposition::TruePositive {
            event_id: "z_cand_none".to_owned()
        })
    );
    assert_eq!(
        disposition_of(&report, "c3"),
        Some(&CandidateDisposition::TruePositive {
            event_id: "z_truth_none".to_owned()
        })
    );
    assert_eq!(
        disposition_of(&report, "c4"),
        Some(&CandidateDisposition::FalsePositive)
    );
    assert_eq!(
        truth_of(&report, "z_mismatch"),
        Some(&TruthDisposition::Missed)
    );
    assert_eq!(
        truth_of(&report, "class_mismatch"),
        Some(&TruthDisposition::Missed)
    );
    assert_eq!(report.counts.false_negatives, 2);
    assert_eq!(report.precision, ratio(2, 4));
    assert_eq!(report.recall, ratio(2, 4));
    Ok(())
}

#[test]
fn evaluation_not_observable_accounting() -> Result<(), EvaluationError> {
    // Clip [0, 100000); gaps [5000, 9000] and [9001, 9100] merge into [5000, 9100] (4101 ns).
    let labels = LabelSet {
        clips: vec![clip("cam1", 100_000, &[(9_001, 9_100), (5_000, 9_000)])],
        events: vec![
            truth("e_obs", "cam1", "person", None, 1_000, 2_000),
            truth("e_hidden", "cam1", "person", None, 6_000, 7_000),
            // Wholly inside only the merged union.
            truth("e_hidden_merged", "cam1", "car", None, 8_990, 9_050),
            // Straddles the gap end: observable, and unmatched -> FN.
            truth("e_partial", "cam1", "bike", None, 9_050, 9_500),
        ],
    };
    let candidates = vec![
        cand("k_obs", "cam1", "person", None, 1_500, 900_000), // TP
        cand("k_in_gap", "cam1", "person", None, 6_500, 950_000), // inside gap: not scored
        // Observed time, but only eligible for e_hidden (7000 + late 3000 >= 9500): neutral.
        cand("k_neutral", "cam1", "person", None, 9_500, 800_000),
    ];
    let report = run(
        &policy(0, 3_000, FalseAlertBudget::per_day(10)),
        &labels,
        &candidates,
    )?;
    assert_eq!(
        report.counts,
        EvaluationCounts {
            truth_events: 4,
            observable_truth_events: 2,
            not_observable_truth_events: 2,
            candidates: 3,
            candidates_inside_not_observable: 1,
            candidates_matched_not_observable_truth: 1,
            true_positives: 1,
            false_positives: 0,
            false_negatives: 1,
        }
    );
    assert_eq!(
        report.durations,
        ObservedDurations {
            total_ns: 100_000,
            not_observable_ns: 4_101,
            observed_ns: 95_899,
        }
    );
    assert_eq!(
        disposition_of(&report, "k_in_gap"),
        Some(&CandidateDisposition::InsideNotObservable)
    );
    assert_eq!(
        disposition_of(&report, "k_neutral"),
        Some(&CandidateDisposition::MatchedNotObservableTruth {
            event_id: "e_hidden".to_owned()
        })
    );
    assert_eq!(
        truth_of(&report, "e_hidden"),
        Some(&TruthDisposition::NotObservable {
            matched_candidate_id: Some("k_neutral".to_owned())
        })
    );
    assert_eq!(
        truth_of(&report, "e_hidden_merged"),
        Some(&TruthDisposition::NotObservable {
            matched_candidate_id: None
        })
    );
    assert_eq!(
        truth_of(&report, "e_partial"),
        Some(&TruthDisposition::Missed)
    );
    // Only k_obs is scored: one curve point (TP 1, FP 0, P 2). AUPRC = 1/2 * 1 = 0.5.
    assert_eq!(report.pr_curve, vec![point(900_000, 1, 0, 2, true)]);
    assert_eq!(report.auprc, PpmMetric::Defined(500_000));
    Ok(())
}

#[test]
fn evaluation_empty_sets_are_undefined_not_nan() -> Result<(), EvaluationError> {
    let budget = policy(0, 0, FalseAlertBudget::per_day(1));
    // No events, no candidates.
    let labels = LabelSet {
        clips: vec![clip("cam1", 1_000, &[])],
        events: vec![],
    };
    let report = run(&budget, &labels, &[])?;
    assert_eq!(
        report.recall,
        Ratio::Undefined(UndefinedReason::NoObservableTruthEvents)
    );
    assert_eq!(
        report.precision,
        Ratio::Undefined(UndefinedReason::NoScoredCandidates)
    );
    assert_eq!(
        report.auprc,
        PpmMetric::Undefined(UndefinedReason::NoObservableTruthEvents)
    );
    assert_eq!(report.operating_point, OperatingPoint::NoScoredCandidates);
    assert!(report.pr_curve.is_empty());
    assert_eq!(report.time_to_detect, None);
    assert_eq!(report.recall.ppm_floor(), None);

    // Events but no candidates: recall 0/1 is defined, AUPRC is the empty sum 0.
    let labels = LabelSet {
        clips: vec![clip("cam1", 10_000, &[])],
        events: vec![truth("e1", "cam1", "car", None, 10, 20)],
    };
    let report = run(&budget, &labels, &[])?;
    assert_eq!(report.recall, ratio(0, 1));
    assert_eq!(report.auprc, PpmMetric::Defined(0));
    assert_eq!(report.counts.false_negatives, 1);
    assert_eq!(
        report.precision,
        Ratio::Undefined(UndefinedReason::NoScoredCandidates)
    );

    // Candidates but no events: every candidate is an FP; recall and AUPRC undefined.
    let labels = LabelSet {
        clips: vec![clip("cam1", 10_000, &[])],
        events: vec![],
    };
    let report = run(&budget, &labels, &[cand("k", "cam1", "car", None, 5, 10)])?;
    assert_eq!(report.precision, ratio(0, 1));
    assert_eq!(
        report.auprc,
        PpmMetric::Undefined(UndefinedReason::NoObservableTruthEvents)
    );
    assert_eq!(
        report.pr_curve,
        vec![PrPoint {
            threshold_ppm: 10,
            true_positives: 0,
            false_positives: 1,
            precision: ratio(0, 1),
            recall: Ratio::Undefined(UndefinedReason::NoObservableTruthEvents),
            // 1 FP in 10 us of observation vs 1 per day: over budget.
            within_false_alert_budget: false,
        }]
    );

    // No clips at all: zero observed time.
    let report = run(&budget, &LabelSet::default(), &[])?;
    assert_eq!(report.operating_point, OperatingPoint::NoObservedTime);
    assert_eq!(
        report.operating_point.recall(),
        Ratio::Undefined(UndefinedReason::NoObservedTime)
    );

    // Whole clip unobservable: observed time is zero.
    let labels = LabelSet {
        clips: vec![clip("cam1", 1_000, &[(0, 999)])],
        events: vec![],
    };
    let report = run(&budget, &labels, &[])?;
    assert_eq!(report.durations.observed_ns, 0);
    assert_eq!(report.operating_point, OperatingPoint::NoObservedTime);
    Ok(())
}

#[test]
fn evaluation_shuffled_input_yields_identical_digest() -> Result<(), EvaluationError> {
    let (mut labels, mut candidates) = three_by_five();
    labels.clips.push(clip("cam0", 5_000, &[(10, 20), (1, 2)]));
    let pol = policy(100, 100, FalseAlertBudget::per_day(1));
    let baseline = run(&pol, &labels, &candidates)?;

    labels.clips.reverse();
    labels.events.reverse();
    labels.events.swap(0, 1);
    for clip in &mut labels.clips {
        clip.not_observable.reverse();
    }
    candidates.reverse();
    candidates.swap(1, 3);
    let shuffled = run(&pol, &labels, &candidates)?;
    assert_eq!(shuffled.digest, baseline.digest);
    assert_eq!(shuffled, baseline);

    // Identity is bound into the digest.
    let mut other = identity();
    other.model_generation = "model-g8".to_owned();
    let rebound = evaluate(
        &other,
        &pol,
        &labels,
        &CandidateSet {
            candidates: candidates.clone(),
        },
    )?;
    assert_ne!(rebound.digest, baseline.digest);
    assert_eq!(rebound.label_set_digest, baseline.label_set_digest);

    // Tampering is detected.
    let mut tampered = baseline.clone();
    tampered.counts.false_positives = 0;
    assert!(!tampered.verify_digest());
    assert!(baseline.verify_digest());
    Ok(())
}

fn expect_err(labels: &LabelSet, candidates: &[EventCandidate]) -> Option<EvaluationError> {
    run(
        &policy(0, 0, FalseAlertBudget::per_day(1)),
        labels,
        candidates,
    )
    .err()
}

#[test]
fn evaluation_limit_refusals() {
    let clips: Vec<LabeledClip> = (0..=MAX_EVALUATION_CLIPS)
        .map(|index| clip(&format!("c{index}"), 10, &[]))
        .collect();
    let labels = LabelSet {
        clips,
        events: vec![],
    };
    assert_eq!(
        expect_err(&labels, &[]),
        Some(EvaluationError::LimitExceeded {
            limit: EvaluationLimit::Clips,
            max: MAX_EVALUATION_CLIPS,
            actual: MAX_EVALUATION_CLIPS + 1
        })
    );

    let labels = LabelSet {
        clips: vec![clip("cam1", 1_000, &[])],
        events: vec![],
    };
    let too_many: Vec<EventCandidate> = (0..=MAX_EVALUATION_CANDIDATES)
        .map(|index| cand(&format!("k{index}"), "cam1", "car", None, 1, 1))
        .collect();
    assert_eq!(
        expect_err(&labels, &too_many),
        Some(EvaluationError::LimitExceeded {
            limit: EvaluationLimit::Candidates,
            max: MAX_EVALUATION_CANDIDATES,
            actual: MAX_EVALUATION_CANDIDATES + 1
        })
    );

    let events: Vec<TruthEvent> = (0..=MAX_EVALUATION_TRUTH_EVENTS)
        .map(|index| truth(&format!("e{index}"), "cam1", "car", None, 1, 2))
        .collect();
    let labels = LabelSet {
        clips: vec![clip("cam1", 1_000, &[])],
        events,
    };
    assert_eq!(
        expect_err(&labels, &[]).map(|error| error.code()),
        Some("evaluation.limit_exceeded")
    );

    let gaps: Vec<(u64, u64)> = (0..=MAX_EVALUATION_NOT_OBSERVABLE_INTERVALS as u64)
        .map(|index| (index, index))
        .collect();
    let labels = LabelSet {
        clips: vec![clip("cam1", 1_000_000, &gaps)],
        events: vec![],
    };
    assert_eq!(
        expect_err(&labels, &[]),
        Some(EvaluationError::LimitExceeded {
            limit: EvaluationLimit::NotObservableIntervals,
            max: MAX_EVALUATION_NOT_OBSERVABLE_INTERVALS,
            actual: MAX_EVALUATION_NOT_OBSERVABLE_INTERVALS + 1
        })
    );
}

#[test]
fn evaluation_validation_refusals() {
    let base = || LabelSet {
        clips: vec![clip("cam1", 1_000, &[])],
        events: vec![truth("e1", "cam1", "car", None, 10, 20)],
    };

    let mut labels = base();
    labels.events[0].interval = ClosedIntervalNs::new(30, 20);
    assert_eq!(
        expect_err(&labels, &[]),
        Some(EvaluationError::InvalidInterval {
            owner_id: "e1".to_owned(),
            start_ns: 30,
            end_ns: 20
        })
    );

    let mut labels = base();
    labels.events.push(truth("e1", "cam1", "car", None, 40, 50));
    assert_eq!(
        expect_err(&labels, &[]),
        Some(EvaluationError::DuplicateId {
            field: "event_id",
            id: "e1".to_owned()
        })
    );

    let mut labels = base();
    labels.clips.push(clip("cam1", 5, &[]));
    assert_eq!(
        expect_err(&labels, &[]),
        Some(EvaluationError::DuplicateId {
            field: "clip_id",
            id: "cam1".to_owned()
        })
    );

    let dup = [
        cand("k", "cam1", "car", None, 1, 1),
        cand("k", "cam1", "car", None, 2, 2),
    ];
    assert_eq!(
        expect_err(&base(), &dup),
        Some(EvaluationError::DuplicateId {
            field: "candidate_id",
            id: "k".to_owned()
        })
    );

    assert_eq!(
        expect_err(&base(), &[cand("k", "cam9", "car", None, 1, 1)]),
        Some(EvaluationError::UnknownClip {
            owner_id: "k".to_owned(),
            clip_id: "cam9".to_owned()
        })
    );

    assert_eq!(
        expect_err(&base(), &[cand("k", "cam1", "car", None, 1, 1_000_001)]),
        Some(EvaluationError::ScoreOutOfRange {
            candidate_id: "k".to_owned(),
            score_ppm: 1_000_001
        })
    );
    // Exactly 1.0 is admitted.
    assert_eq!(
        expect_err(&base(), &[cand("k", "cam1", "car", None, 1, 1_000_000)]),
        None
    );

    assert_eq!(
        expect_err(&base(), &[cand("k", "cam1", "car", None, 1_000, 1)]),
        Some(EvaluationError::OutsideClip {
            owner_id: "k".to_owned(),
            at_ns: 1_000,
            duration_ns: 1_000
        })
    );

    let mut labels = base();
    labels.events[0].interval = ClosedIntervalNs::new(10, 1_000);
    assert_eq!(
        expect_err(&labels, &[]).map(|error| error.code()),
        Some("evaluation.outside_clip")
    );

    let mut labels = base();
    labels.clips[0].duration_ns = 0;
    assert_eq!(
        expect_err(&labels, &[]).map(|error| error.code()),
        Some("evaluation.zero_clip_duration")
    );

    let labels = LabelSet {
        clips: vec![clip("cam1", 1_000, &[(500, 400)])],
        events: vec![],
    };
    assert_eq!(
        expect_err(&labels, &[]).map(|error| error.code()),
        Some("evaluation.invalid_interval")
    );

    for (bad, violation) in [
        (String::new(), TextViolation::Empty),
        ("has space".to_owned(), TextViolation::InvalidCharacter),
        (
            "x".repeat(MAX_EVALUATION_ID_BYTES + 1),
            TextViolation::TooLong,
        ),
    ] {
        assert_eq!(
            expect_err(&base(), &[cand(&bad, "cam1", "car", None, 1, 1)]),
            Some(EvaluationError::InvalidText {
                field: "candidate_id",
                violation
            })
        );
    }

    let mut labels = base();
    labels.events[0].zone = Some("bad\tzone".to_owned());
    assert_eq!(
        expect_err(&labels, &[]),
        Some(EvaluationError::InvalidText {
            field: "event_zone",
            violation: TextViolation::InvalidCharacter
        })
    );

    let zero_budget = policy(
        0,
        0,
        FalseAlertBudget {
            max_false_alerts: 1,
            per_observed_ns: 0,
        },
    );
    assert_eq!(
        evaluate(&identity(), &zero_budget, &base(), &CandidateSet::default()).err(),
        Some(EvaluationError::InvalidBudget)
    );

    let mut blank = identity();
    blank.policy_generation = String::new();
    assert_eq!(
        evaluate(
            &blank,
            &policy(0, 0, FalseAlertBudget::per_hour(1)),
            &base(),
            &CandidateSet::default()
        )
        .err(),
        Some(EvaluationError::InvalidText {
            field: "policy_generation",
            violation: TextViolation::Empty
        })
    );
}
