#![forbid(unsafe_code)]

use std::collections::BTreeSet;

use fss_fusion::{
    AblationTarget, Calibration, Coverage, Decision, EvidenceItem, FusionPolicy, FusionQuery,
    LlrInterval, MAX_ABLATION_TARGETS, Observability, Opportunity, Probe, Reason, Severity, ablate,
    fuse,
};

type TestResult = Result<(), Box<dyn std::error::Error>>;

fn domains(names: &[&str]) -> BTreeSet<String> {
    names.iter().map(|name| (*name).to_owned()).collect()
}

fn item(id: &str, sensor: &str, causes: &[&str], lo: i64, hi: i64) -> EvidenceItem {
    EvidenceItem {
        id: id.to_owned(),
        sensor: sensor.to_owned(),
        failure_domains: domains(causes),
        calibration: Calibration::Calibrated {
            generation: "count-calibration:v1".to_owned(),
            llr: LlrInterval::new(lo, hi).unwrap(),
        },
        observability: Observability::Observed,
    }
}

fn query(evidence: Vec<EvidenceItem>) -> FusionQuery {
    FusionQuery {
        hypothesis: "event:intrusion".to_owned(),
        kind: "unknown_presence".to_owned(),
        prior: LlrInterval::point(0).unwrap(),
        evidence,
        coverage: Coverage::Complete,
        opportunities: Vec::new(),
        probes: Vec::new(),
        severity: Severity {
            expected_harm: 10_000,
            false_alert_cost: 200,
            delay_cost_per_second: 1,
            reversible: false,
        },
        policy: FusionPolicy {
            generation: "policy:v1".to_owned(),
            alert_threshold: 1_000,
            retain_threshold: 0,
            reject_threshold: -2_000,
            min_independent_support: 2,
            urgent_single_domain_threshold: None,
            max_wait_ns: 100,
            look_penalty_per_doubling: 301,
            operator_confirmation_available: false,
        },
        looks: 1,
        now_ns: 20,
    }
}

#[test]
fn removing_a_sensor_reclusters_the_remaining_transitive_component() -> TestResult {
    let original = query(vec![
        item("a", "camera-a", &["power:a"], 600, 900),
        item(
            "bridge",
            "camera-bridge",
            &["power:a", "power:b"],
            -100,
            400,
        ),
        item("b", "camera-b", &["power:b"], 700, 1_000),
    ]);
    let result = ablate(&original, &[AblationTarget::Sensor("camera-bridge".into())])?;
    assert_eq!(result.baseline().clusters.len(), 1);
    assert_eq!(result.baseline().posterior, LlrInterval::new(-100, 1_000)?);
    assert_eq!(result.outcome().clusters.len(), 2);
    assert_eq!(result.outcome().posterior, LlrInterval::new(1_300, 1_900)?);
    assert_eq!(result.outcome().decision, Decision::AlertDegradedCoverage);
    assert_eq!(result.unavailable_evidence(), ["bridge"]);
    assert!(matches!(
        result.counterfactual_query().coverage,
        Coverage::Gap { .. }
    ));
    assert_eq!(result.original_query().coverage, Coverage::Complete);
    assert_eq!(result.counterfactual_query().evidence.len(), 3);
    assert_eq!(result.work().selector_item_checks, 3);
    assert_eq!(result.work().fusion_evaluations, 2);
    // The source query and its numerical policy/time are not changed by the explanation.
    assert_eq!(original.coverage, Coverage::Complete);
    assert_eq!(original.looks, result.counterfactual_query().looks);
    assert_eq!(original.now_ns, result.counterfactual_query().now_ns);
    assert_eq!(original.policy, result.counterfactual_query().policy);
    assert_eq!(
        fuse(result.counterfactual_query())?.decision_digest,
        result.outcome().decision_digest,
    );
    Ok(())
}

#[test]
fn removing_one_correlated_sensor_keeps_the_other_member_and_recomputes_its_hull() -> TestResult {
    let original = query(vec![
        item("weak", "camera-a", &["network:shared"], -700, 600),
        item("strong", "camera-b", &["network:shared"], 800, 900),
    ]);
    let result = ablate(&original, &[AblationTarget::Sensor("camera-a".into())])?;
    assert_eq!(result.outcome().clusters.len(), 1);
    assert_eq!(result.outcome().clusters[0].members, ["strong"]);
    assert_eq!(result.outcome().posterior, LlrInterval::new(800, 900)?);
    assert_eq!(result.outcome().supporting_clusters, 1);
    assert_ne!(result.outcome().decision, Decision::Alert);
    Ok(())
}

#[test]
fn sensor_and_domain_selectors_honor_intrinsic_and_declared_dependencies() -> TestResult {
    let original = query(vec![
        item("a", "camera-a", &["model:detector"], 700, 800),
        item(
            "b",
            "camera-b",
            &["model:detector", "sensor:camera-a"],
            800,
            900,
        ),
        item("c", "camera-c", &["model:independent"], 600, 700),
    ]);
    for selector in [
        AblationTarget::Sensor("camera-a".into()),
        AblationTarget::FailureDomain("sensor:camera-a".into()),
        AblationTarget::FailureDomain("model:detector".into()),
    ] {
        let result = ablate(&original, &[selector])?;
        assert_eq!(result.unavailable_evidence(), ["a", "b"]);
        assert_eq!(result.outcome().clusters.len(), 1);
        assert_eq!(result.outcome().clusters[0].members, ["c"]);
    }
    Ok(())
}

#[test]
fn loss_never_converts_missing_or_negative_evidence_into_certified_absence() -> TestResult {
    let mut redacted = item("redacted", "camera-b", &["model:b"], 1_000, 1_000);
    redacted.observability = Observability::Redacted;
    let mut stale = item("stale", "camera-b", &["model:b"], 1_000, 1_000);
    stale.observability = Observability::Stale;
    let mut gap = item("gap", "camera-b", &["model:b"], 1_000, 1_000);
    gap.observability = Observability::NotObservable {
        reason: "original outage".into(),
    };
    let original = query(vec![
        item("negative", "camera-a", &["model:a"], -4_000, -3_000),
        item("positive", "camera-b", &["model:b"], 200, 300),
        redacted,
        stale,
        gap,
    ]);
    let result = ablate(&original, &[AblationTarget::Sensor("camera-b".into())])?;
    assert_eq!(result.outcome().decision, Decision::RetainSilently);
    assert!(
        result
            .outcome()
            .reasons
            .contains(&Reason::AbsenceNotCertified)
    );
    for id in ["redacted", "stale", "gap"] {
        let before = original.evidence.iter().find(|row| row.id == id).unwrap();
        let after = result
            .counterfactual_query()
            .evidence
            .iter()
            .find(|row| row.id == id)
            .unwrap();
        assert_eq!(before.observability, after.observability);
    }
    let mut gapped = original;
    gapped.coverage = Coverage::Gap {
        reason: "unsampled interval".into(),
    };
    let result = ablate(&gapped, &[AblationTarget::Sensor("camera-a".into())])?;
    assert_eq!(result.counterfactual_query().coverage, gapped.coverage);
    Ok(())
}

#[test]
fn unavailable_future_observations_are_not_offered_as_waits_or_probes() -> TestResult {
    let mut original = query(vec![item("a", "camera-a", &["model:a"], 500, 700)]);
    original.opportunities.push(Opportunity {
        id: "arrival-b".into(),
        sensor: "camera-b".into(),
        failure_domains: domains(&["model:b"]),
        window_start: 30,
        window_end: 50,
        positive: LlrInterval::point(900)?,
        negative: LlrInterval::point(-900)?,
    });
    original.probes.push(Probe {
        id: "resample-b".into(),
        kind: "camera_sample".into(),
        failure_domains: domains(&["sensor:camera-b"]),
        cost: 1,
        latency_ns: 1,
        positive: LlrInterval::point(900)?,
        negative: LlrInterval::point(-900)?,
    });
    assert!(matches!(
        fuse(&original)?.decision,
        Decision::WaitForCorroboration { .. }
    ));
    let result = ablate(&original, &[AblationTarget::Sensor("camera-b".into())])?;
    assert!(result.unavailable_evidence().is_empty());
    assert_eq!(result.removed_opportunities(), ["arrival-b"]);
    assert_eq!(result.removed_probes(), ["resample-b"]);
    assert_eq!(result.outcome().decision, Decision::HoldIndeterminate);
    assert!(result.counterfactual_query().opportunities.is_empty());
    assert!(result.counterfactual_query().probes.is_empty());
    assert_eq!(result.work().selector_item_checks, 3);
    Ok(())
}

#[test]
fn simultaneous_losses_are_order_independent_and_cannot_fabricate_new_looks() -> TestResult {
    let mut original = query(vec![
        item("a", "camera-a", &["model:a"], 700, 800),
        item("b", "camera-b", &["model:b"], 800, 900),
        item("c", "camera-c", &["model:c"], 600, 700),
    ]);
    original.looks = 7;
    let selectors = [
        AblationTarget::FailureDomain("model:b".into()),
        AblationTarget::Sensor("camera-a".into()),
    ];
    let result = ablate(&original, &selectors)?;
    original.evidence.reverse();
    let permuted = ablate(&original, &[selectors[1].clone(), selectors[0].clone()])?;
    assert_eq!(result.digest(), permuted.digest());
    assert_eq!(
        result.outcome().decision_digest,
        permuted.outcome().decision_digest
    );
    assert_eq!(result.counterfactual_query().looks, 7);
    assert_eq!(
        result.baseline().sequential_alert_threshold,
        result.outcome().sequential_alert_threshold
    );
    assert_eq!(result.unavailable_evidence(), ["a", "b"]);
    assert_ne!(
        result.digest(),
        ablate(&original, &[selectors[0].clone()])?.digest()
    );
    assert_eq!(result.work().selector_item_checks, 6);
    Ok(())
}

#[test]
fn malformed_duplicate_unmatched_and_excess_selectors_refuse_without_changing_input() -> TestResult
{
    let original = query(vec![item("a", "camera-a", &["model:a"], 700, 800)]);
    let original_digest = original.digest();
    for selectors in [
        vec![],
        vec![AblationTarget::Sensor("".into())],
        vec![AblationTarget::Sensor("camera\na".into())],
        vec![AblationTarget::Sensor("x".repeat(257))],
        vec![AblationTarget::Sensor("absent".into())],
        vec![
            AblationTarget::Sensor("camera-a".into()),
            AblationTarget::Sensor("absent".into()),
        ],
        vec![AblationTarget::Sensor("camera-a".into()); 2],
        vec![AblationTarget::Sensor("camera-a".into()); MAX_ABLATION_TARGETS + 1],
    ] {
        assert!(ablate(&original, &selectors).is_err());
        assert_eq!(original.digest(), original_digest);
    }
    let mut invalid = original.clone();
    invalid.evidence.push(invalid.evidence[0].clone());
    assert!(ablate(&invalid, &[AblationTarget::Sensor("camera-a".into())]).is_err());
    Ok(())
}

#[test]
fn maximum_selector_inventory_is_fully_accounted_and_all_loss_is_not_observable() -> TestResult {
    let mut evidence = Vec::new();
    let mut selectors = Vec::new();
    for index in 0..MAX_ABLATION_TARGETS {
        let sensor = format!("camera:{index}");
        evidence.push(item(
            &format!("row:{index}"),
            &sensor,
            &["network:shared"],
            500,
            800,
        ));
        selectors.push(AblationTarget::Sensor(sensor));
    }
    let original = query(evidence);
    let result = ablate(&original, &selectors)?;
    assert_eq!(result.unavailable_evidence().len(), MAX_ABLATION_TARGETS);
    assert_eq!(
        result.work().selector_item_checks,
        (MAX_ABLATION_TARGETS * MAX_ABLATION_TARGETS) as u64
    );
    assert!(result.outcome().clusters.is_empty());
    assert_eq!(result.outcome().knowledge_state, "not_observable");
    assert_ne!(result.outcome().decision, Decision::Reject);
    Ok(())
}
