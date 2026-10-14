#![forbid(unsafe_code)]
use super::*;
use fss_fusion::{Decision, Reason};
use fss_reference::ingest::detector_cascade::{CascadeDetection, SelectionReason};
type Test<T = ()> = std::result::Result<T, Box<dyn std::error::Error>>;
fn d(s: &str) -> ContentDigest {
    ContentDigest::sha256(s.as_bytes())
}
fn calibration() -> Test<ScoreCalibration> {
    Ok(ScoreCalibration::from_counts(
        "camera-mode-v1",
        &[0, 500_000],
        &[(100, 9900), (9900, 100)],
    )?)
}
fn spec() -> Test<ClassFusionSpec> {
    Ok(ClassFusionSpec {
        plan_digest: d("plan"),
        cascade_digest: d("cascade"),
        class_index: 0,
        prior: LlrInterval::point(-500)?,
        policy: FusionPolicy {
            generation: "policy:test".to_owned(),
            alert_threshold: 1000,
            retain_threshold: -500,
            reject_threshold: -1500,
            min_independent_support: 2,
            urgent_single_domain_threshold: None,
            max_wait_ns: 10,
            look_penalty_per_doubling: 301,
            operator_confirmation_available: true,
        },
        severity: Severity {
            expected_harm: 1000,
            false_alert_cost: 10,
            delay_cost_per_second: 0,
            reversible: false,
        },
        looks: 1,
        now_ns: 10,
        calibrations: vec![
            SensorCalibration {
                sensor: "sensor:a".to_owned(),
                calibration: calibration()?,
                failure_domains: BTreeSet::new(),
            },
            SensorCalibration {
                sensor: "sensor:b".to_owned(),
                calibration: calibration()?,
                failure_domains: BTreeSet::new(),
            },
        ],
    })
}
fn record(name: &str, score: f32) -> ClassEvidence {
    ClassEvidence {
        segment: 0,
        reason: SelectionReason::ZoneEntry,
        outcome: EvidenceOutcome::Associated {
            detection: CascadeDetection {
                row: 0,
                class_index: 0,
                label: "person".to_owned(),
                score,
                bounds: [0, 0, 256, 256],
            },
            iou_ppm: 1_000_000,
        },
        digest: d(name),
        record: name.as_bytes().to_vec(),
    }
}
fn run(
    profile: ClassFusionSpec,
    a: &[ClassEvidence],
    b: &[ClassEvidence],
) -> std::result::Result<CandidateFusion, EventFusionError> {
    fuse_input(
        Input {
            candidate: d("candidate"),
            proposal: d("proposal"),
            provenance: d("source graph"),
            sources: vec![
                Source {
                    sensor: "sensor:a",
                    dependency: None,
                    evidence: a,
                },
                Source {
                    sensor: "sensor:b",
                    dependency: None,
                    evidence: b,
                },
            ],
        },
        "person",
        &EventFusionProfile::new(profile)?,
        d("source-context"),
        &["model:shared".to_owned()],
    )
}
#[test]
fn common_model_and_calibration_never_multiply_confidence() -> Test {
    let r = run(
        spec()?,
        &[record("a", 0.9), record("a2", 0.9)],
        &[record("b", 0.9)],
    )?;
    assert_eq!(r.outcome.clusters.len(), 1);
    assert_eq!(r.outcome.supporting_clusters, 1);
    assert!(
        r.outcome
            .reasons
            .contains(&Reason::InsufficientIndependentSupport)
    );
    assert_eq!(r.outcome.counterfactuals.len(), 1);
    assert_eq!(r.outcome.counterfactuals[0].posterior, spec()?.prior);
    assert!(!matches!(
        r.outcome.decision,
        Decision::Alert | Decision::AlertDegradedCoverage
    ));
    Ok(())
}
#[test]
fn missing_scores_and_unbound_sensors_remain_explicit_without_negative_evidence() -> Test {
    let mut p = spec()?;
    p.calibrations.pop();
    let mut skipped = record("skip", 0.0);
    skipped.outcome = EvidenceOutcome::BudgetExhausted;
    let r = run(p, &[skipped], &[record("b", 0.9)])?;
    assert_eq!(r.outcome.posterior, spec()?.prior);
    assert_eq!(r.outcome.excluded.len(), 1);
    assert_eq!(r.outcome.uncalibrated.len(), 1);
    assert!(!matches!(r.outcome.decision, Decision::Reject));
    let r = run(spec()?, &[], &[])?;
    assert_eq!(r.outcome.excluded.len(), 2);
    assert!(r.scores.iter().all(|s| s.source_record.is_none()));
    Ok(())
}
#[test]
fn calibrated_low_scores_never_certify_class_absence() -> Test {
    let mut p = spec()?;
    p.prior = LlrInterval::point(-3000)?;
    let r = run(p, &[record("a", 0.1)], &[record("b", 0.1)])?;
    assert!(r.outcome.posterior.hi() < -1500);
    assert_ne!(r.outcome.decision, Decision::Reject);
    assert!(r.outcome.reasons.contains(&Reason::AbsenceNotCertified));
    Ok(())
}
#[test]
fn score_rounding_retains_both_sides_of_a_calibration_boundary() -> Test {
    let below = f32::from_bits(0.5f32.to_bits() - 1);
    assert_eq!(score_interval(below)?, [499999, 500000]);
    let r = run(spec()?, &[record("a", below)], &[record("b", below)])?;
    let c = calibration()?;
    assert_eq!(r.outcome.clusters[0].llr, c.bins[0].llr.hull(c.bins[1].llr));
    assert_eq!(score_interval(0.0)?, [0, 0]);
    assert_eq!(score_interval(1.0)?, [1000000, 1000000]);
    Ok(())
}
#[test]
fn invalid_scores_are_not_clamped_into_calibrated_evidence() {
    for score in [f32::NAN, f32::INFINITY, -0.1, 1.1] {
        assert_eq!(score_interval(score), Err(EventFusionError::Evidence));
    }
}
#[test]
fn rebuilt_calibration_rejects_tampered_likelihoods_even_with_unchanged_digest() -> Test {
    let mut p = spec()?;
    p.calibrations[0].calibration.bins[0].llr = LlrInterval::point(99999)?;
    assert!(matches!(
        EventFusionProfile::new(p),
        Err(EventFusionError::Profile)
    ));
    let mut p = spec()?;
    p.calibrations[0].calibration.positives += 1;
    assert!(matches!(
        EventFusionProfile::new(p),
        Err(EventFusionError::Profile)
    ));
    Ok(())
}
#[test]
fn profile_binds_every_numeric_policy_and_the_exact_native_scope() -> Test {
    let base = EventFusionProfile::new(spec()?)?.digest();
    for which in 0..6 {
        let mut p = spec()?;
        match which {
            0 => p.plan_digest = d("other"),
            1 => p.cascade_digest = d("other"),
            2 => p.looks += 1,
            3 => p.now_ns += 1,
            4 => p.policy.alert_threshold += 1,
            _ => p.prior = LlrInterval::point(1)?,
        };
        assert_ne!(base, EventFusionProfile::new(p)?.digest());
    }
    let mut p = spec()?;
    p.calibrations.reverse();
    assert_eq!(base, EventFusionProfile::new(p)?.digest());
    Ok(())
}
#[test]
fn invalid_policy_empty_duplicate_and_conflicting_generation_profiles_refuse() -> Test {
    let mut p = spec()?;
    p.looks = 0;
    assert!(EventFusionProfile::new(p).is_err());
    let mut p = spec()?;
    p.calibrations.clear();
    assert!(EventFusionProfile::new(p).is_err());
    let mut p = spec()?;
    p.calibrations[1].sensor = p.calibrations[0].sensor.clone();
    assert!(EventFusionProfile::new(p).is_err());
    let mut p = spec()?;
    p.calibrations[1].calibration =
        ScoreCalibration::from_counts("camera-mode-v1", &[0], &[(2, 3)])?;
    assert!(EventFusionProfile::new(p).is_err());
    Ok(())
}
#[test]
fn exact_duplicate_source_records_count_once_and_cannot_change_sensor() -> Test {
    let r = record("same", 0.9);
    let a = run(spec()?, &[r.clone(), r.clone()], &[])?;
    let b = run(spec()?, &[r.clone()], &[])?;
    assert_eq!(a.binding_digest, b.binding_digest);
    assert!(matches!(
        run(spec()?, &[r.clone()], &[r]),
        Err(EventFusionError::Evidence)
    ));
    Ok(())
}
#[test]
fn source_digest_and_label_inconsistencies_are_typed_refusals() -> Test {
    let mut r = record("a", 0.9);
    r.record.push(1);
    assert!(matches!(
        run(spec()?, &[r], &[]),
        Err(EventFusionError::Evidence)
    ));
    let mut r = record("a", 0.9);
    if let EvidenceOutcome::Associated { detection, .. } = &mut r.outcome {
        detection.label = "other".to_owned();
    }
    assert!(matches!(
        run(spec()?, &[r], &[]),
        Err(EventFusionError::Evidence)
    ));
    Ok(())
}
#[test]
fn other_classes_and_unassociated_detections_do_not_become_a_zero_score() -> Test {
    let mut r = record("a", 0.99);
    r.outcome = EvidenceOutcome::NoAssociation { detections: 2 };
    let result = run(spec()?, &[r], &[])?;
    assert_eq!(result.outcome.posterior, spec()?.prior);
    assert!(result.scores.iter().all(|s| s.score_bits.is_none()));
    Ok(())
}
#[test]
fn optional_stopping_changes_the_engine_threshold_and_complete_binding() -> Test {
    let r = record("a", 0.9);
    let a = run(spec()?, &[r.clone()], &[])?;
    let mut p = spec()?;
    p.looks = 8;
    let b = run(p, &[r], &[])?;
    assert!(b.outcome.sequential_alert_threshold > a.outcome.sequential_alert_threshold);
    assert_ne!(a.binding_digest, b.binding_digest);
    Ok(())
}

fn profile_json() -> Test<String> {
    Ok(format!(
        r#"{{"schema":"fss.event_class_fusion_profile.v1",
        "plan_digest":"{}","cascade_digest":"{}","class_index":0,"prior":[-500,-500],
        "looks":1,"now_ns":"18446744073709551615",
        "policy":{{"generation":"policy:test","alert_threshold":1000,"retain_threshold":-500,
        "reject_threshold":-1500,"min_independent_support":2,"urgent_single_domain_threshold":null,
        "max_wait_ns":"10","look_penalty_per_doubling":301,"operator_confirmation_available":true}},
        "severity":{{"expected_harm":"1000","false_alert_cost":"10","delay_cost_per_second":"0","reversible":false}},
        "calibrations":[{{"sensor":"sensor:a","failure_domains":["network:shared"],"calibration":{}}}]}}"#,
        d("plan"),
        d("cascade"),
        render::count_calibration(&calibration()?)
    ))
}
fn parse_profile(text: &str) -> Result<EventFusionProfile> {
    EventFusionProfile::from_json(text.as_bytes(), d(text))
}
#[test]
fn count_profile_roundtrips_evaluation_calibration_and_full_width_time() -> Test {
    let text = profile_json()?;
    let parsed = parse_profile(&text)?;
    assert_eq!(parsed.spec().now_ns, u64::MAX);
    assert_eq!(parsed.spec().calibrations[0].calibration, calibration()?);
    let spaced = text.replace(',', ",\n  ");
    assert_eq!(parse_profile(&spaced)?.digest(), parsed.digest());
    assert_ne!(d(&spaced), d(&text));
    Ok(())
}
#[test]
fn profile_digest_is_checked_before_json_or_count_parsing() -> Test {
    let text = profile_json()?;
    for bytes in [text.as_bytes(), b"not-json", b"\xff"] {
        assert_eq!(
            EventFusionProfile::from_json(bytes, d("wrong")).err(),
            Some(EventFusionError::Profile)
        );
    }
    assert_eq!(
        EventFusionProfile::from_json(&[], d("")).err(),
        Some(EventFusionError::Limit)
    );
    let bytes = vec![b' '; MAX_PROFILE_BYTES + 1];
    assert_eq!(
        EventFusionProfile::from_json(&bytes, ContentDigest::sha256(&bytes)).err(),
        Some(EventFusionError::Limit)
    );
    Ok(())
}
#[test]
fn unknown_duplicate_malformed_and_unbounded_profile_fields_fail_closed() -> Test {
    let text = profile_json()?;
    for changed in [
        text.replacen("{", "{\"unsupported\":true,", 1),
        text.replacen("\"looks\":1", "\"looks\":1,\"looks\":1", 1),
        text.replace("\"looks\":1", "\"looks\":0"),
        text.replace("\"class_index\":0", "\"class_index\":65536"),
        text.replace("18446744073709551615", "18446744073709551616"),
        text.replace(
            "\"network:shared\"",
            "\"network:shared\",\"network:shared\"",
        ),
        text.replace("\"class_index\":0", "\"class_index\":0.0"),
        format!("{text} null"),
    ] {
        assert!(
            parse_profile(&changed).is_err(),
            "accepted malformed profile"
        );
    }
    Ok(())
}
#[test]
fn recomputed_file_digest_cannot_bless_changed_calibration_claims() -> Test {
    let text = profile_json()?;
    let c = calibration()?;
    for changed in [
        text.replace("\"true_positives\":10000", "\"true_positives\":9999"),
        text.replace("\"lo_ppm\":500000", "\"lo_ppm\":500001"),
        text.replace("\"hi_ppm\":499999", "\"hi_ppm\":500000"),
        text.replace("wilson_z2_per_bin_not_simultaneous", "guaranteed_certainty"),
        text.replace(
            &format!(
                "\"llr_millibans\":[{},{}]",
                c.bins[0].llr.lo(),
                c.bins[0].llr.hi()
            ),
            "\"llr_millibans\":[0,0]",
        ),
        text.replace(
            &format!(
                "\"prior_log_odds_millibans\":[{},{}]",
                c.prior.lo(),
                c.prior.hi()
            ),
            "\"prior_log_odds_millibans\":[100,100]",
        ),
    ] {
        assert_ne!(changed, text, "test failed to modify calibration");
        assert!(
            parse_profile(&changed).is_err(),
            "accepted changed calibration"
        );
    }
    Ok(())
}
