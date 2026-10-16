#![forbid(unsafe_code)]
//! Scope, compatibility and shared-work contracts for whole-recording class advice.
use super::*;
use crate::json_input::{Value, parse};

fn pin(name: &str) -> ContentDigest { ContentDigest::sha256(name.as_bytes()) }

fn spec() -> ClassFusionSpec {
    ClassFusionSpec {
        plan_digest: pin("whole analysis"),
        cascade_digest: pin("whole detector recipe"),
        coverage_digests: BTreeSet::new(),
        class_index: 0,
        prior: LlrInterval::point(-500).expect("bounded fixture prior"),
        policy: FusionPolicy {
            generation: "policy:long-watch-fixture".into(),
            alert_threshold: 1000, retain_threshold: -500, reject_threshold: -1500,
            min_independent_support: 2, urgent_single_domain_threshold: None,
            max_wait_ns: 10, look_penalty_per_doubling: 301,
            operator_confirmation_available: true,
        },
        severity: Severity {
            expected_harm: 1000, false_alert_cost: 10, delay_cost_per_second: 0,
            reversible: false,
        },
        looks: 1, now_ns: 10,
        calibrations: vec![SensorCalibration {
            sensor: "sensor:long-watch-fixture".into(),
            calibration: ScoreCalibration::from_counts(
                "fixture-counts-v1", &[0, 500_000], &[(100, 9_900), (9_900, 100)],
            ).expect("valid labelled fixture counts"),
            failure_domains: BTreeSet::new(),
        }],
    }
}
fn read_profile(json: &str) -> Result<EventFusionProfile> {
    EventFusionProfile::from_json(json.as_bytes(), ContentDigest::sha256(json.as_bytes()))
}

#[test]
fn complete_analysis_profile_roundtrips_without_a_coverage_claim() {
    let p = EventFusionProfile::for_long_watch(spec(), pin("analysis graph")).unwrap();
    assert!(p.spec().coverage_digests.is_empty());
    let json = p.to_json().unwrap();
    let parsed = read_profile(&json).unwrap();
    assert_eq!(parsed.digest(), p.digest());
    assert_eq!(parsed.long_watch_analysis_root(), Some(pin("analysis graph")));
    assert_eq!(parsed.to_json().unwrap(), json);
    let Value::Object(fields) = parse(&json).unwrap() else { panic!("object required") };
    assert_eq!(fields["schema"].text(), Some("fss.event_class_fusion_profile.v2"));
    assert!(fields["coverage_digests"].array().unwrap().is_empty());
}

#[test]
fn an_analysis_root_cannot_be_substituted_for_coverage_or_vice_versa() {
    assert_eq!(EventFusionProfile::new(spec()).unwrap_err(), EventFusionError::Profile);
    let mut covered = spec();
    covered.coverage_digests.insert(pin("coverage"));
    assert_eq!(EventFusionProfile::for_long_watch(covered.clone(), pin("graph")).unwrap_err(),
        EventFusionError::Profile);
    let short = EventFusionProfile::new(covered).unwrap();
    assert!(short.long_watch_analysis_root().is_none());
    let json = short.to_json().unwrap();
    assert!(json.contains("fss.event_class_fusion_profile.v1"));
    assert!(!json.contains("long_watch_analysis_root"));
    assert_eq!(read_profile(&json).unwrap().digest(), short.digest());
    let long = EventFusionProfile::for_long_watch(spec(), pin("graph")).unwrap().to_json().unwrap();
    assert!(read_profile(&long.replace("profile.v2", "profile.v1")).is_err());
    assert!(read_profile(&json.replace("profile.v1", "profile.v2")).is_err());
}

#[test]
fn each_complete_source_binding_changes_the_semantic_identity() {
    let original = EventFusionProfile::for_long_watch(spec(), pin("graph")).unwrap();
    let different_root = EventFusionProfile::for_long_watch(spec(), pin("other graph")).unwrap();
    assert_ne!(original.digest(), different_root.digest());
    let mut other_analysis = spec();
    other_analysis.plan_digest = pin("other analysis");
    assert_ne!(original.digest(), EventFusionProfile::for_long_watch(other_analysis, pin("graph")).unwrap().digest());
    let mut other_recipe = spec();
    other_recipe.cascade_digest = pin("other recipe");
    assert_ne!(original.digest(), EventFusionProfile::for_long_watch(other_recipe, pin("graph")).unwrap().digest());
    let json = original.to_json().unwrap();
    assert_eq!(EventFusionProfile::from_json(json.as_bytes(), pin("not exact bytes")).unwrap_err(),
        EventFusionError::Profile);
}

#[test]
fn every_long_scope_identity_must_be_nonzero_sha256() {
    let zero = ContentDigest::parse(&format!("sha256:{}", "00".repeat(32))).unwrap();
    for position in 0..3 {
        let mut request = spec();
        let mut root = pin("graph");
        match position { 0 => request.plan_digest = zero, 1 => request.cascade_digest = zero, _ => root = zero }
        assert_eq!(EventFusionProfile::for_long_watch(request, root).unwrap_err(), EventFusionError::Profile);
    }
}

#[test]
fn legacy_profile_digest_uses_the_original_canonical_field_sequence() {
    let mut request = spec();
    request.coverage_digests.insert(pin("coverage"));
    let profile = EventFusionProfile::new(request).unwrap();
    let s = profile.spec();
    let mut e = CanonicalEncoder::new();
    e.text(RECIPE); e.digest(s.plan_digest); e.digest(s.cascade_digest);
    e.u64(s.coverage_digests.len() as u64);
    for root in &s.coverage_digests { e.digest(*root); }
    e.u64(s.class_index as u64);
    e.digest(query(s, "profile", Vec::new()).digest());
    e.u64(s.calibrations.len() as u64);
    for binding in &s.calibrations {
        e.text(&binding.sensor); e.digest(binding.calibration.digest);
        e.u64(binding.failure_domains.len() as u64);
        for domain in &binding.failure_domains { e.text(domain); }
    }
    assert_eq!(profile.digest(), digest(e).unwrap());
}

#[test]
fn one_shared_allowance_covers_every_candidate_and_every_missing_observation() {
    assert_eq!(MAX_LONG_CANDIDATES, 256);
    assert!(admit_inventory(0, std::iter::empty()).is_ok());
    assert!(admit_inventory(256, std::iter::repeat_n(0, 256)).is_ok());
    assert!(admit_inventory(256, std::iter::repeat_n(1, 256)).is_ok());
    assert!(admit_inventory(32, std::iter::repeat_n(8, 32)).is_ok());
    assert_eq!(admit_inventory(33, std::iter::repeat_n(8, 33)), Err(EventFusionError::Limit));
    assert_eq!(admit_inventory(257, std::iter::repeat_n(0, 257)), Err(EventFusionError::Limit));
    assert_eq!(admit_inventory(2, [256, 0].into_iter()), Err(EventFusionError::Limit));
    assert_eq!(admit_inventory(1, [usize::MAX].into_iter()), Err(EventFusionError::Limit));
    assert_eq!(admit_inventory(2, [1].into_iter()), Err(EventFusionError::Evidence));
    assert_eq!(admit_inventory(1, std::iter::repeat(1)), Err(EventFusionError::Limit));
}

const COUNTS: &str = r#"{
  "schema":"fss.event_class_fusion_counts.v1", "class_index":0,
  "prior":[-500,-500], "looks":1, "now_ns":10,
  "policy":{"generation":"policy:long-watch-fixture", "alert_threshold":1000,
    "retain_threshold":-500, "reject_threshold":-1500, "min_independent_support":2,
    "urgent_single_domain_threshold":null, "max_wait_ns":10,
    "look_penalty_per_doubling":301,"operator_confirmation_available":true},
  "severity":{"expected_harm":1000,"false_alert_cost":10,"delay_cost_per_second":0,"reversible":false},
  "calibrations":[{"sensor":"sensor:long-watch-fixture", "failure_domains":[],
    "calibration":{"schema":"fss.score_calibration_counts.v1", "generation":"fixture-counts-v1",
      "bins":[{"lo_ppm":0,"true_positives":100,"false_positives":9900},
              {"lo_ppm":500000,"true_positives":9900,"false_positives":100}]}}]
}"#;

#[test]
fn count_authoring_uses_the_native_calibration_owner_and_exact_external_scope() {
    let from_counts = EventFusionProfile::from_long_watch_counts_json(
        COUNTS.as_bytes(), pin(COUNTS), spec().plan_digest, spec().cascade_digest, pin("graph"),
    ).unwrap();
    let direct = EventFusionProfile::for_long_watch(spec(), pin("graph")).unwrap();
    assert_eq!(from_counts.digest(), direct.digest());
    assert_eq!(from_counts.to_json().unwrap(), direct.to_json().unwrap());
    let spoof = COUNTS.replacen(""class_index":0", ""class_index":0,"long_watch_analysis_root":"spoof"", 1);
    assert!(EventFusionProfile::from_long_watch_counts_json(
        spoof.as_bytes(), pin(&spoof), spec().plan_digest, spec().cascade_digest, pin("graph"),
    ).is_err());
}

#[test]
fn no_score_or_unobserved_class_can_become_negative_evidence() {
    let p = EventFusionProfile::for_long_watch(spec(), pin("graph")).unwrap();
    let shared = ["model:fixture".into(), "package:fixture".into(), "cascade:fixture".into()];
    let result = fuse_input(Input {
        candidate: pin("candidate"), proposal: pin("proposal"), provenance: pin("provenance"),
        sources: vec![Source { sensor: "sensor:long-watch-fixture", dependency: None, evidence: &[] }],
    }, "person", &p, pin("context"), &shared).unwrap();
    assert!(matches!(&result.query.coverage, Coverage::Gap { .. }));
    assert_eq!(result.scores.len(), 1);
    assert!(result.scores[0].score_bits.is_none());
    assert!(result.scores[0].score_ppm.is_none());
    assert!(result.scores[0].calibration.is_none());
    assert!(matches!(&result.query.evidence[0].calibration, Calibration::Uncalibrated { .. }));
    assert_ne!(result.outcome.decision, fss_fusion::Decision::Reject);
}

fn class_record(name: &str, score: f32) -> ClassEvidence {
    use fss_reference::ingest::detector_cascade::{CascadeDetection, SelectionReason};
    ClassEvidence {
        segment: 0, reason: SelectionReason::ZoneEntry,
        outcome: EvidenceOutcome::Associated {
            detection: CascadeDetection {
                row: 0, class_index: 0, label: "person".into(), score,
                bounds: [0, 0, 256, 256],
            }, iou_ppm: 1_000_000,
        },
        digest: pin(name), record: name.as_bytes().to_vec(),
    }
}

#[test]
fn repeated_native_class_support_keeps_one_common_cause_and_exact_counterfactual() {
    let p = EventFusionProfile::for_long_watch(spec(), pin("graph")).unwrap();
    let observations = [class_record("first", 0.9), class_record("second", 0.9)];
    let result = fuse_input(Input {
        candidate: pin("candidate"), proposal: pin("proposal"), provenance: pin("provenance"),
        sources: vec![Source {
            sensor: "sensor:long-watch-fixture", dependency: None, evidence: &observations,
        }],
    }, "person", &p, pin("context"), &["model:fixture".into(), "package:fixture".into(), "cascade:fixture".into()]).unwrap();
    assert_eq!(result.outcome.clusters.len(), 1);
    assert_eq!(result.outcome.supporting_clusters, 1);
    assert_eq!(result.outcome.counterfactuals.len(), 1);
    assert_eq!(result.outcome.counterfactuals[0].posterior, p.spec().prior);
    assert!(result.outcome.reasons.contains(&fss_fusion::Reason::InsufficientIndependentSupport));
    assert!(!matches!(result.outcome.decision,
        fss_fusion::Decision::Alert | fss_fusion::Decision::AlertDegradedCoverage));
}

#[test]
fn budget_refusals_are_retained_but_do_not_contribute_zero_scores() {
    let p = EventFusionProfile::for_long_watch(spec(), pin("graph")).unwrap();
    let mut skipped = class_record("skipped original record", 0.0);
    skipped.outcome = EvidenceOutcome::BudgetExhausted;
    let result = fuse_input(Input {
        candidate: pin("candidate"), proposal: pin("proposal"), provenance: pin("provenance"),
        sources: vec![Source {
            sensor: "sensor:long-watch-fixture", dependency: None,
            evidence: std::slice::from_ref(&skipped),
        }],
    }, "person", &p, pin("context"), &["model:fixture".into()]).unwrap();
    assert_eq!(result.outcome.posterior, p.spec().prior);
    assert_eq!(result.outcome.excluded.len(), 1);
    assert_eq!(result.scores[0].source_record, Some(skipped.digest));
    assert!(result.scores[0].score_bits.is_none());
    assert!(result.scores[0].score_ppm.is_none());
    assert!(result.scores[0].calibration.is_none());
}
