#![forbid(unsafe_code)]
//! Contract of the reference fusion rule (`fss-x4a.16.9`): one textbook case per decision, and
//! seeded invariants over thousands of random queries:
//!
//! * the posterior interval contains every admissible point posterior (one member's likelihood
//!   per dependency cluster, any value in its interval) — the belief interval stays valid
//!   (`FORMAL-005`);
//! * a duplicate of an existing observation sharing any failure domain never raises the robust
//!   lower bound (no double counting);
//! * an independent supporting cluster never lowers it (monotonicity);
//! * no rejection without complete coverage and no missing observations; no plain alert below
//!   the required independent support; every wait has a deadline within `max_wait` and a
//!   positive value bound;
//! * the outcome is invariant under input order and its digest is deterministic.

use std::collections::BTreeSet;
use std::error::Error;

use fss_fusion::{
    Calibration, ClusterDirection, Coverage, Decision, EvidenceItem, FusionPolicy, FusionQuery,
    LlrInterval, Observability, Opportunity, Probe, Reason, Severity, fuse,
};

type TestResult<T = ()> = Result<T, Box<dyn Error>>;

fn domains(values: &[&str]) -> BTreeSet<String> {
    values.iter().map(|value| (*value).to_owned()).collect()
}

fn calibrated(
    id: &str,
    sensor: &str,
    extra: &[&str],
    lo: i64,
    hi: i64,
) -> TestResult<EvidenceItem> {
    let mut failure_domains = domains(extra);
    failure_domains.insert(format!("sensor:{sensor}"));
    Ok(EvidenceItem {
        id: id.to_owned(),
        sensor: sensor.to_owned(),
        failure_domains,
        calibration: Calibration::Calibrated {
            generation: "cal:person:v1".to_owned(),
            llr: LlrInterval::new(lo, hi)?,
        },
        observability: Observability::Observed,
    })
}

fn policy() -> FusionPolicy {
    FusionPolicy {
        generation: "policy:unknown-presence:v1".to_owned(),
        alert_threshold: 1_000,
        retain_threshold: -500,
        reject_threshold: -2_000,
        min_independent_support: 2,
        urgent_single_domain_threshold: None,
        max_wait_ns: 30_000_000_000,
        look_penalty_per_doubling: 301,
        operator_confirmation_available: false,
    }
}

fn query(evidence: Vec<EvidenceItem>) -> TestResult<FusionQuery> {
    Ok(FusionQuery {
        hypothesis: "event:1".to_owned(),
        kind: "unknown_presence".to_owned(),
        prior: LlrInterval::new(-2_000, -1_500)?,
        evidence,
        coverage: Coverage::Complete,
        opportunities: Vec::new(),
        probes: Vec::new(),
        severity: Severity {
            expected_harm: 10_000,
            false_alert_cost: 100,
            delay_cost_per_second: 10,
            reversible: false,
        },
        policy: policy(),
        looks: 1,
        now_ns: 1_000_000_000_000,
    })
}

#[test]
fn two_independent_cameras_alert_but_two_models_on_one_camera_do_not() -> TestResult {
    let both = query(vec![
        calibrated("cam-a/yolox", "cam-a", &["model:yolox"], 1_600, 2_000)?,
        calibrated("cam-b/hog", "cam-b", &["model:hog"], 1_500, 1_900)?,
    ])?;
    let outcome = fuse(&both)?;
    assert_eq!(outcome.decision, Decision::Alert);
    assert_eq!(outcome.supporting_clusters, 2);
    assert_eq!(outcome.posterior, LlrInterval::new(1_100, 2_400)?);
    assert_eq!(outcome.knowledge_state, "estimated");

    // The same two scores from one camera are one cluster: counted once, single domain.
    let same = query(vec![
        calibrated("cam-a/yolox", "cam-a", &["model:yolox"], 1_600, 2_000)?,
        calibrated("cam-a/hog", "cam-a", &["model:hog"], 1_500, 1_900)?,
    ])?;
    let outcome = fuse(&same)?;
    assert_eq!(outcome.clusters.len(), 1);
    assert_eq!(outcome.posterior, LlrInterval::new(-500, 500)?);
    assert_ne!(outcome.decision, Decision::Alert);
    assert!(
        outcome
            .reasons
            .contains(&Reason::InsufficientIndependentSupport)
    );

    // Two cameras behind one shared clock are not independent either.
    let shared_clock = query(vec![
        calibrated("cam-a/yolox", "cam-a", &["clock:ntp-1"], 1_600, 2_000)?,
        calibrated("cam-b/yolox", "cam-b", &["clock:ntp-1"], 1_500, 1_900)?,
    ])?;
    let outcome = fuse(&shared_clock)?;
    assert_eq!(outcome.clusters.len(), 1);
    assert_eq!(outcome.supporting_clusters, 1);
    Ok(())
}

#[test]
fn sensor_identity_is_a_common_cause_without_caller_domain_labels() -> TestResult {
    let mut first = calibrated("frame-a/yolox", "cam-a", &[], 1_600, 2_000)?;
    let mut second = calibrated("frame-b/hog", "cam-a", &[], 1_500, 1_900)?;
    // Different frames/models cannot become corroboration just by omitting the sensor label.
    first.failure_domains = domains(&["model:yolox"]);
    second.failure_domains = domains(&["model:hog"]);
    let mut same_sensor = query(vec![first, second])?;
    let outcome = fuse(&same_sensor)?;
    assert_eq!(outcome.supporting_clusters, 1);
    assert_eq!(outcome.posterior, LlrInterval::new(-500, 500)?);
    assert_eq!(
        outcome.clusters[0].failure_domains,
        domains(&["model:yolox", "model:hog", "sensor:cam-a"])
    );
    assert!(!matches!(
        outcome.decision,
        Decision::Alert | Decision::AlertDegradedCoverage
    ));
    same_sensor.evidence.reverse();
    assert_eq!(fuse(&same_sensor)?, outcome);

    // A genuinely distinct sensor with disjoint declarations retains the reference's
    // conditional-independence behavior.
    same_sensor.evidence[0].sensor = "cam-b".to_owned();
    assert_eq!(fuse(&same_sensor)?.decision, Decision::Alert);
    Ok(())
}

#[test]
fn intrinsic_sensor_domains_join_transitive_shared_failures() -> TestResult {
    let mut first = calibrated("a/first", "cam-a", &[], 1_600, 2_000)?;
    let mut second = calibrated("a/second", "cam-a", &[], 1_500, 1_900)?;
    let mut third = calibrated("c/first", "cam-c", &[], 1_700, 2_100)?;
    first.failure_domains = domains(&["model:first"]);
    second.failure_domains = domains(&["clock:shared"]);
    third.failure_domains = domains(&["clock:shared"]);
    let linked = query(vec![first, second, third])?;
    let outcome = fuse(&linked)?;
    assert_eq!(outcome.clusters.len(), 1);
    assert_eq!(outcome.supporting_clusters, 1);
    assert_eq!(
        outcome.clusters[0].members,
        ["a/first", "a/second", "c/first"]
    );
    assert_eq!(outcome.posterior, LlrInterval::new(-500, 600)?);
    assert_ne!(outcome.decision, Decision::Alert);
    Ok(())
}

#[test]
fn coverage_gaps_never_become_rejections() -> TestResult {
    let quiet = vec![
        calibrated("cam-a/none", "cam-a", &[], -900, -700)?,
        calibrated("cam-b/none", "cam-b", &[], -800, -600)?,
    ];
    let complete = fuse(&query(quiet.clone())?)?;
    assert_eq!(complete.decision, Decision::Reject);
    let mut gapped = query(quiet.clone())?;
    gapped.coverage = Coverage::Gap {
        reason: "cam-b dark 02:10-02:12".to_owned(),
    };
    let outcome = fuse(&gapped)?;
    assert_eq!(outcome.decision, Decision::RetainSilently);
    assert!(outcome.reasons.contains(&Reason::AbsenceNotCertified));
    assert!(outcome.reasons.contains(&Reason::CoverageNotComplete));
    // A not-observable observation is listed, never fused, and also blocks rejection.
    let mut missing = quiet;
    missing.push(EvidenceItem {
        id: "cam-c/none".to_owned(),
        sensor: "cam-c".to_owned(),
        failure_domains: domains(&["sensor:cam-c"]),
        calibration: Calibration::Calibrated {
            generation: "cal:person:v1".to_owned(),
            llr: LlrInterval::new(-900, -700)?,
        },
        observability: Observability::NotObservable {
            reason: "frozen frames".to_owned(),
        },
    });
    let outcome = fuse(&query(missing)?)?;
    assert_eq!(outcome.decision, Decision::RetainSilently);
    assert_eq!(
        outcome.excluded,
        vec![(
            "cam-c/none".to_owned(),
            "not_observable: frozen frames".to_owned()
        )]
    );
    Ok(())
}

#[test]
fn uncalibrated_scores_have_no_numeric_authority() -> TestResult {
    let mut evidence = vec![calibrated("cam-a/yolox", "cam-a", &[], 1_600, 2_000)?];
    evidence.push(EvidenceItem {
        id: "vlm/high-confidence".to_owned(),
        sensor: "cam-b".to_owned(),
        failure_domains: domains(&["sensor:cam-b", "model:vlm"]),
        calibration: Calibration::Uncalibrated {
            reason: "a VLM phrase has no numeric authority".to_owned(),
        },
        observability: Observability::Observed,
    });
    let outcome = fuse(&query(evidence)?)?;
    assert_eq!(outcome.uncalibrated, vec!["vlm/high-confidence".to_owned()]);
    assert_eq!(outcome.supporting_clusters, 1);
    assert!(
        outcome
            .reasons
            .contains(&Reason::UncalibratedEvidenceIgnored)
    );
    assert_ne!(outcome.decision, Decision::Alert);
    Ok(())
}

#[test]
fn absent_or_uncalibrated_observations_never_certify_rejection() -> TestResult {
    let mut empty = query(Vec::new())?;
    empty.prior = LlrInterval::new(-3_000, -2_500)?;
    let outcome = fuse(&empty)?;
    assert_eq!(outcome.knowledge_state, "unknown");
    assert_eq!(outcome.decision, Decision::RetainSilently);
    assert!(outcome.reasons.contains(&Reason::AbsenceNotCertified));

    let mut observed = empty;
    observed
        .evidence
        .push(calibrated("cam-a/none", "cam-a", &[], -900, -700)?);
    let outcome = fuse(&observed)?;
    assert_eq!(outcome.decision, Decision::Reject);
    // Removing its only observation leaves the low prior; no counterfactual absence claim.
    assert_eq!(
        outcome.counterfactuals[0].decision,
        Decision::RetainSilently
    );

    observed.evidence.push(EvidenceItem {
        id: "cam-b/possible-person".to_owned(),
        sensor: "cam-b".to_owned(),
        failure_domains: domains(&["sensor:cam-b"]),
        calibration: Calibration::Uncalibrated {
            reason: "detector has no calibration for current night mode".to_owned(),
        },
        observability: Observability::Observed,
    });
    let outcome = fuse(&observed)?;
    assert_eq!(outcome.decision, Decision::RetainSilently);
    assert!(outcome.reasons.contains(&Reason::AbsenceNotCertified));
    assert!(
        outcome
            .reasons
            .contains(&Reason::UncalibratedEvidenceIgnored)
    );
    assert_eq!(outcome.uncalibrated, ["cam-b/possible-person"]);
    Ok(())
}

#[test]
fn urgent_exception_still_requires_observed_calibrated_support() -> TestResult {
    let mut unsupported = query(Vec::new())?;
    unsupported.prior = LlrInterval::new(2_000, 2_500)?;
    unsupported.policy.urgent_single_domain_threshold = Some(500);
    assert_eq!(fuse(&unsupported)?.decision, Decision::HoldIndeterminate);

    unsupported.evidence.push(EvidenceItem {
        id: "cam-a/possible-person".to_owned(),
        sensor: "cam-a".to_owned(),
        failure_domains: domains(&["sensor:cam-a"]),
        calibration: Calibration::Uncalibrated {
            reason: "calibration unavailable".to_owned(),
        },
        observability: Observability::Observed,
    });
    assert_eq!(fuse(&unsupported)?.decision, Decision::HoldIndeterminate);

    unsupported.evidence[0] = calibrated("cam-a/person", "cam-a", &[], 100, 200)?;
    assert_eq!(
        fuse(&unsupported)?.decision,
        Decision::AlertSingleDomainUnconfirmed
    );
    Ok(())
}

#[test]
fn bounded_wait_for_an_independent_camera_and_its_refusals() -> TestResult {
    // Posterior [600, 1500]: below the alert threshold from one camera; a false alert costs
    // 1000, so the value of resolving it (200) exceeds the 9 s delay loss (90).
    let mut waiting = query(vec![calibrated("cam-a/yolox", "cam-a", &[], 2_600, 3_000)?])?;
    waiting.severity.false_alert_cost = 1_000;
    let now = waiting.now_ns;
    waiting.opportunities = vec![
        Opportunity {
            id: "cam-b/next".to_owned(),
            sensor: "cam-b".to_owned(),
            failure_domains: domains(&["sensor:cam-b"]),
            window_start: now + 4_000_000_000,
            window_end: now + 9_000_000_000,
            positive: LlrInterval::new(1_200, 1_500)?,
            negative: LlrInterval::new(-1_500, -1_000)?,
        },
        // Same camera as the evidence: never a corroboration.
        Opportunity {
            id: "cam-a/again".to_owned(),
            sensor: "cam-a".to_owned(),
            failure_domains: domains(&["sensor:cam-a"]),
            window_start: now,
            window_end: now + 1_000_000_000,
            positive: LlrInterval::new(1_200, 1_500)?,
            negative: LlrInterval::new(-1_500, -1_000)?,
        },
    ];
    let outcome = fuse(&waiting)?;
    let Decision::WaitForCorroboration {
        opportunity,
        deadline_ns,
        value_bound,
    } = &outcome.decision
    else {
        return Err(format!("expected a wait, got {:?}", outcome.decision).into());
    };
    assert_eq!(opportunity, "cam-b/next");
    assert_eq!(*deadline_ns, now + 9_000_000_000);
    assert!(*value_bound > 0);

    // A delay cost above the value of perfect information refuses the wait.
    let mut urgent = waiting.clone();
    urgent.severity.delay_cost_per_second = 1_000_000;
    let outcome = fuse(&urgent)?;
    assert!(!matches!(
        outcome.decision,
        Decision::WaitForCorroboration { .. }
    ));
    assert!(
        outcome
            .reasons
            .contains(&Reason::NoDecisionRelevantObservation)
    );

    // A window beyond max_wait is not admissible.
    let mut late = waiting.clone();
    late.opportunities[0].window_start = now + 60_000_000_000;
    late.opportunities[0].window_end = now + 70_000_000_000;
    assert!(!matches!(
        fuse(&late)?.decision,
        Decision::WaitForCorroboration { .. }
    ));

    // The urgent exception alerts from one domain, labeled unconfirmed.
    urgent.policy.urgent_single_domain_threshold = Some(500);
    assert_eq!(
        fuse(&urgent)?.decision,
        Decision::AlertSingleDomainUnconfirmed
    );
    // Without it, the operator is asked when available.
    let mut ask = urgent.clone();
    ask.policy.urgent_single_domain_threshold = None;
    ask.policy.operator_confirmation_available = true;
    assert_eq!(fuse(&ask)?.decision, Decision::RequestOperatorConfirmation);
    Ok(())
}

#[test]
fn opportunity_sensor_identity_prevents_false_corroboration_waits() -> TestResult {
    let mut observed = calibrated("cam-a/yolox", "cam-a", &[], 2_600, 3_000)?;
    observed.failure_domains = domains(&["model:yolox"]);
    let mut waiting = query(vec![observed])?;
    waiting.severity.false_alert_cost = 1_000;
    waiting.opportunities.push(Opportunity {
        id: "next-frame/hog".to_owned(),
        sensor: "cam-a".to_owned(),
        failure_domains: domains(&["model:hog"]),
        window_start: waiting.now_ns + 1_000_000_000,
        window_end: waiting.now_ns + 2_000_000_000,
        positive: LlrInterval::new(1_200, 1_500)?,
        negative: LlrInterval::new(-1_500, -1_000)?,
    });
    assert_eq!(fuse(&waiting)?.decision, Decision::HoldIndeterminate);
    waiting.opportunities[0].sensor = "cam-b".to_owned();
    assert!(matches!(
        fuse(&waiting)?.decision,
        Decision::WaitForCorroboration { .. }
    ));
    Ok(())
}

#[test]
fn probes_are_chosen_by_value_and_must_be_independent() -> TestResult {
    let mut probing = query(vec![calibrated(
        "cam-a/yolox",
        "cam-a",
        &["model:yolox"],
        900,
        1_400,
    )?])?;
    probing.prior = LlrInterval::new(-1_000, -800)?;
    probing.probes = vec![
        Probe {
            id: "verify/yolox-large".to_owned(),
            kind: "verifier".to_owned(),
            failure_domains: domains(&["model:yolox", "sensor:cam-a"]),
            cost: 1,
            latency_ns: 0,
            positive: LlrInterval::new(3_000, 3_000)?,
            negative: LlrInterval::new(-3_000, -3_000)?,
        },
        Probe {
            id: "verify/geometry-cam-c".to_owned(),
            kind: "geometry".to_owned(),
            failure_domains: domains(&["sensor:cam-c"]),
            cost: 20,
            latency_ns: 2_000_000_000,
            positive: LlrInterval::new(1_500, 2_000)?,
            negative: LlrInterval::new(-2_000, -1_500)?,
        },
        Probe {
            id: "verify/ptz-cam-d".to_owned(),
            kind: "ptz".to_owned(),
            failure_domains: domains(&["sensor:cam-d"]),
            cost: 5,
            latency_ns: 1_000_000_000,
            positive: LlrInterval::new(1_500, 2_000)?,
            negative: LlrInterval::new(-2_000, -1_500)?,
        },
    ];
    let outcome = fuse(&probing)?;
    let Decision::RequestObservation { probe, value_bound } = &outcome.decision else {
        return Err(format!("expected a probe, got {:?}", outcome.decision).into());
    };
    // The same-family verifier on the same frames is never chosen; the cheaper independent
    // probe wins.
    assert_eq!(probe, "verify/ptz-cam-d");
    assert!(*value_bound > 0);
    Ok(())
}

#[test]
fn repeated_looks_raise_the_alert_threshold() -> TestResult {
    let evidence = vec![
        calibrated("cam-a", "cam-a", &[], 1_600, 1_800)?,
        calibrated("cam-b", "cam-b", &[], 1_600, 1_800)?,
    ];
    let first = fuse(&query(evidence.clone())?)?;
    assert_eq!(first.decision, Decision::Alert);
    let mut eighth = query(evidence)?;
    eighth.looks = 8;
    let outcome = fuse(&eighth)?;
    assert_eq!(outcome.sequential_alert_threshold, 1_000 + 3 * 301);
    assert_ne!(outcome.decision, Decision::Alert);
    assert!(
        outcome
            .reasons
            .contains(&Reason::OptionalStoppingCorrection)
    );
    assert_eq!(outcome.support_to_alert, Some(1_903 - 1_200));
    Ok(())
}

#[test]
fn conflicts_and_counterfactuals_are_explicit() -> TestResult {
    let outcome = fuse(&query(vec![
        calibrated("cam-a/person", "cam-a", &[], 1_600, 2_000)?,
        calibrated("cam-b/person", "cam-b", &[], 1_500, 1_900)?,
        calibrated("cam-c/raccoon", "cam-c", &[], -1_200, -900)?,
    ])?)?;
    assert_eq!(outcome.knowledge_state, "conflicted");
    assert!(outcome.reasons.contains(&Reason::ConflictingEvidence));
    assert_eq!(outcome.contradicting_clusters, 1);
    assert_eq!(outcome.counterfactuals.len(), 3);
    // Removing the contradicting camera alerts.
    let raccoon = outcome
        .clusters
        .iter()
        .find(|cluster| cluster.direction == ClusterDirection::Contradicts)
        .ok_or("contradicting cluster")?;
    let without = outcome
        .counterfactuals
        .iter()
        .find(|c| c.removed_cluster == raccoon.label)
        .ok_or("counterfactual")?;
    assert_eq!(without.decision, Decision::Alert);
    Ok(())
}

#[test]
fn malformed_queries_are_refused_with_stable_identities() -> TestResult {
    let mut bad = query(vec![calibrated("x", "cam-a", &[], 0, 0)?])?;
    bad.policy.retain_threshold = bad.policy.alert_threshold + 1;
    assert_eq!(
        fuse(&bad).err().map(|e| e.stable_id()),
        Some("ERR-FUSION-POLICY-INVALID-001")
    );
    let mut duplicate = query(vec![
        calibrated("x", "cam-a", &[], 0, 0)?,
        calibrated("x", "cam-b", &[], 0, 0)?,
    ])?;
    assert_eq!(
        fuse(&duplicate).err().map(|e| e.stable_id()),
        Some("ERR-FUSION-INPUT-INVALID-001")
    );
    duplicate.evidence.truncate(1);
    duplicate.evidence[0].failure_domains.clear();
    assert_eq!(
        fuse(&duplicate).err().map(|e| e.stable_id()),
        Some("ERR-FUSION-INPUT-INVALID-001")
    );
    assert!(LlrInterval::new(5, 4).is_err());
    assert!(LlrInterval::new(0, 100_001).is_err());
    Ok(())
}

#[test]
fn all_i64_boundary_values_are_refused_without_panics_or_wrapping() -> TestResult {
    for value in [i64::MIN, -100_001, 100_001, i64::MAX] {
        assert_eq!(
            LlrInterval::point(value).err().map(|e| e.stable_id()),
            Some("ERR-FUSION-INPUT-INVALID-001")
        );
    }
    assert!(LlrInterval::new(-100_000, 100_000).is_ok());
    assert!(LlrInterval::new(i64::MIN, 0).is_err());
    assert!(LlrInterval::new(0, i64::MAX).is_err());
    for value in [i64::MIN, i64::MAX] {
        for field in 0..5 {
            let mut malformed = query(Vec::new())?;
            match field {
                0 => malformed.policy.reject_threshold = value,
                1 => malformed.policy.retain_threshold = value,
                2 => malformed.policy.alert_threshold = value,
                3 => malformed.policy.urgent_single_domain_threshold = Some(value),
                _ => malformed.policy.look_penalty_per_doubling = value,
            }
            assert_eq!(
                fuse(&malformed).err().map(|e| e.stable_id()),
                Some("ERR-FUSION-POLICY-INVALID-001"),
                "field {field}, value {value}"
            );
        }
    }
    Ok(())
}

/// SplitMix64.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^ (z >> 31)
    }

    fn range(&mut self, lo: i64, hi: i64) -> i64 {
        lo + (self.next() % (hi - lo + 1) as u64) as i64
    }

    fn below(&mut self, bound: usize) -> usize {
        (self.next() % bound.max(1) as u64) as usize
    }
}

fn random_query(seed: u64) -> TestResult<FusionQuery> {
    let mut rng = Rng(seed);
    let sensors = ["cam-a", "cam-b", "cam-c", "cam-d", "cam-e"];
    let shared = ["clock:ntp-1", "model:yolox", "net:switch-1", "power:c3"];
    let mut evidence = Vec::new();
    for index in 0..rng.below(7) {
        let sensor = sensors[rng.below(sensors.len())];
        let mut extra = Vec::new();
        if rng.below(3) == 0 {
            extra.push(shared[rng.below(shared.len())]);
        }
        let center = rng.range(-2_500, 2_500);
        let width = rng.range(0, 800);
        let mut item = calibrated(
            &format!("obs-{index}"),
            sensor,
            &extra,
            center - width,
            center + width,
        )?;
        match rng.below(10) {
            0 => item.observability = Observability::Stale,
            1 => {
                item.calibration = Calibration::Uncalibrated {
                    reason: "uncalibrated mode".to_owned(),
                }
            }
            _ => {}
        }
        evidence.push(item);
    }
    let mut query = query(evidence)?;
    let prior = rng.range(-3_000, 0);
    query.prior = LlrInterval::new(prior - rng.range(0, 500), prior)?;
    query.coverage = match rng.below(3) {
        0 => Coverage::Gap {
            reason: "gap".to_owned(),
        },
        1 => Coverage::Degraded {
            reason: "night".to_owned(),
        },
        _ => Coverage::Complete,
    };
    query.looks = 1 + rng.below(9) as u32;
    query.policy.min_independent_support = 1 + rng.below(3) as u32;
    query.policy.operator_confirmation_available = rng.below(2) == 0;
    if rng.below(2) == 0 {
        query.policy.urgent_single_domain_threshold = Some(rng.range(-400, 2_000));
    }
    let now = query.now_ns;
    for index in 0..rng.below(3) {
        let start = now + rng.next() % 40_000_000_000;
        query.opportunities.push(Opportunity {
            id: format!("opp-{index}"),
            sensor: sensors[rng.below(sensors.len())].to_owned(),
            failure_domains: domains(&[&format!("sensor:{}", sensors[rng.below(sensors.len())])]),
            window_start: start,
            window_end: start + rng.next() % 10_000_000_000,
            positive: LlrInterval::new(rng.range(0, 1_000), rng.range(1_000, 2_500))?,
            negative: LlrInterval::new(rng.range(-2_500, -1_000), rng.range(-1_000, 0))?,
        });
    }
    query.severity.delay_cost_per_second = rng.next() % 50;
    Ok(query)
}

#[test]
fn seeded_invariants_hold() -> TestResult {
    let mut decisions = BTreeSet::new();
    for seed in 0..4_000_u64 {
        let query = random_query(seed)?;
        let outcome = fuse(&query)?;
        decisions.insert(outcome.decision.as_str());
        // Validity: every admissible point posterior lies inside the interval.
        let mut rng = Rng(seed ^ 0xfeed);
        for _ in 0..8 {
            let mut point = rng.range(query.prior.lo(), query.prior.hi());
            for cluster in &outcome.clusters {
                // One member's likelihood per cluster, any value in its interval.
                let member = &cluster.members[rng.below(cluster.members.len())];
                let item = query
                    .evidence
                    .iter()
                    .find(|item| &item.id == member)
                    .ok_or("member")?;
                let Calibration::Calibrated { llr, .. } = item.calibration else {
                    return Err("an uncalibrated member was clustered".into());
                };
                point += rng.range(llr.lo(), llr.hi());
            }
            assert!(
                outcome.posterior.lo() <= point && point <= outcome.posterior.hi(),
                "seed {seed}"
            );
        }
        // Safety clamps.
        if outcome.decision == Decision::Reject {
            assert_eq!(query.coverage, Coverage::Complete, "seed {seed}");
            assert!(outcome.excluded.is_empty(), "seed {seed}");
            assert!(outcome.uncalibrated.is_empty(), "seed {seed}");
            assert!(!outcome.clusters.is_empty(), "seed {seed}");
        }
        if matches!(
            outcome.decision,
            Decision::Alert | Decision::AlertDegradedCoverage
        ) {
            assert!(
                outcome.supporting_clusters >= query.policy.min_independent_support,
                "seed {seed}"
            );
            assert!(
                outcome.posterior.lo() >= outcome.sequential_alert_threshold,
                "seed {seed}"
            );
        }
        if let Decision::WaitForCorroboration {
            deadline_ns,
            value_bound,
            ..
        } = outcome.decision
        {
            assert!(
                deadline_ns >= query.now_ns
                    && deadline_ns <= query.now_ns + query.policy.max_wait_ns
            );
            assert!(value_bound > 0);
        }
        // No double counting: a dependent duplicate never raises the lower bound.
        if let Some(first) = query
            .evidence
            .iter()
            .find(|item| item.observability == Observability::Observed)
        {
            let mut duplicated = query.clone();
            let mut copy = first.clone();
            copy.id = "zz-duplicate".to_owned();
            copy.calibration = Calibration::Calibrated {
                generation: "cal:other-model:v1".to_owned(),
                llr: LlrInterval::new(2_000, 2_500)?,
            };
            duplicated.evidence.push(copy);
            let again = fuse(&duplicated)?;
            if matches!(first.calibration, Calibration::Calibrated { .. }) {
                assert!(
                    again.posterior.lo() <= outcome.posterior.lo(),
                    "seed {seed}: a dependent duplicate raised the lower bound"
                );
            }
        }
        // Monotonicity: an independent supporting observation never lowers the lower bound.
        let mut more = query.clone();
        more.evidence
            .push(calibrated("zz-independent", "cam-z", &[], 100, 900)?);
        assert!(
            fuse(&more)?.posterior.lo() >= outcome.posterior.lo(),
            "seed {seed}"
        );
        // Order invariance and digest determinism.
        let mut reversed = query.clone();
        reversed.evidence.reverse();
        reversed.opportunities.reverse();
        assert_eq!(fuse(&reversed)?, outcome, "seed {seed}");
    }
    for expected in [
        "alert",
        "alert_degraded_coverage",
        "retain_silently",
        "reject",
        "wait_for_corroboration",
        "request_operator_confirmation",
        "hold_indeterminate",
        "alert_single_domain_unconfirmed",
    ] {
        assert!(
            decisions.contains(expected),
            "the corpus never reached {expected}: {decisions:?}"
        );
    }
    Ok(())
}

fn synthetic_outcomes(seed: u64, count: usize) -> Vec<(u32, bool)> {
    let mut rng = Rng(seed);
    (0..count)
        .map(|_| {
            let positive = rng.below(4) == 0;
            // True events score high more often than false alarms.
            let score = if positive {
                600_000 + rng.below(400_001) as u32
            } else {
                rng.below(800_001) as u32
            };
            (score, positive)
        })
        .collect()
}

#[test]
fn score_calibration_brackets_point_estimates_and_feeds_fusion() -> TestResult {
    use fss_fusion::ScoreCalibration;
    let edges = [0, 300_000, 600_000, 800_000, 950_000];
    let outcomes = synthetic_outcomes(7, 5_000);
    let calibration = ScoreCalibration::build("yolox-nano:cam-a:night:v1", &edges, &outcomes)?;
    let (positives, negatives) = (calibration.positives as f64, calibration.negatives as f64);
    for bin in &calibration.bins {
        if bin.positives > 0 && bin.negatives > 0 {
            let point = ((bin.positives as f64 / positives) / (bin.negatives as f64 / negatives))
                .log10()
                * 1000.0;
            assert!(
                bin.llr.lo() as f64 <= point && point <= bin.llr.hi() as f64,
                "bin {}..{}: {point} outside {:?}",
                bin.lo_ppm,
                bin.hi_ppm,
                bin.llr
            );
        }
    }
    // The lowest bin holds no true events: its upper bound is finite, its lower bound clamps.
    assert_eq!(calibration.bins[0].positives, 0);
    assert_eq!(calibration.bins[0].llr.lo(), -fss_fusion::MAX_ABS_LLR);
    // The top bins hold no false alarms: their upper bound clamps.
    assert_eq!(calibration.bins[4].negatives, 0);
    assert_eq!(calibration.bins[4].llr.hi(), fss_fusion::MAX_ABS_LLR);
    assert!(calibration.bins[4].llr.lo() > 0);
    let prior_point = (positives / negatives).log10() * 1000.0;
    assert!(
        calibration.prior.lo() as f64 <= prior_point
            && prior_point <= calibration.prior.hi() as f64
    );
    // Order of outcomes never changes the calibration.
    let mut reversed = outcomes.clone();
    reversed.reverse();
    assert_eq!(
        ScoreCalibration::build("yolox-nano:cam-a:night:v1", &edges, &reversed)?,
        calibration
    );
    // Refusals.
    assert!(ScoreCalibration::build("x", &[100], &outcomes).is_err());
    assert!(ScoreCalibration::build("x", &[0, 5, 5], &outcomes).is_err());
    assert!(ScoreCalibration::build("x", &edges, &[(900_000, true)]).is_err());
    assert!(ScoreCalibration::build("x", &edges, &[(1_000_001, true), (0, false)]).is_err());

    // End to end: two independent cameras with top-bin scores alert; mid-bin scores do not.
    let evidence = |score: u32| -> TestResult<Vec<EvidenceItem>> {
        Ok(["cam-a", "cam-b"]
            .iter()
            .map(|sensor| EvidenceItem {
                id: format!("{sensor}/candidate"),
                sensor: (*sensor).to_owned(),
                failure_domains: domains(&[&format!("sensor:{sensor}")]),
                calibration: calibration.calibrate(score),
                observability: Observability::Observed,
            })
            .collect())
    };
    let mut strong = query(evidence(970_000)?)?;
    strong.prior = calibration.prior;
    let outcome = fuse(&strong)?;
    assert_eq!(outcome.decision, Decision::Alert, "{outcome:?}");
    let mut weak = query(evidence(400_000)?)?;
    weak.prior = calibration.prior;
    let outcome = fuse(&weak)?;
    assert_ne!(outcome.decision, Decision::Alert);
    Ok(())
}
