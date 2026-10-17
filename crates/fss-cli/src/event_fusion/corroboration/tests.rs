#![forbid(unsafe_code)]
//! Synthetic count and source-scope contracts, not field calibration claims.
use super::*;
use crate::json_input::parse;
use fss_reference::ingest::detector_cascade::{CascadeDetection, SelectionReason};
type Test<T = ()> = std::result::Result<T, Box<dyn std::error::Error>>;
fn pin(value: &str) -> ContentDigest {
    ContentDigest::sha256(value.as_bytes())
}
fn spec() -> Test<ClassFusionSpec> {
    Ok(ClassFusionSpec {
        plan_digest: pin("paired analysis"),
        cascade_digest: pin("complete detector recipe"),
        coverage_digests: BTreeSet::new(),
        class_index: 0,
        prior: LlrInterval::point(-500)?,
        policy: FusionPolicy {
            generation: "policy:paired-fixture".into(),
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
        calibrations: ["sensor:a", "sensor:b"]
            .into_iter()
            .map(|sensor| {
                Ok(SensorCalibration {
                    sensor: sensor.into(),
                    failure_domains: BTreeSet::new(),
                    calibration: ScoreCalibration::from_counts(
                        "counts-v1",
                        &[0, 500000],
                        &[(100, 9900), (9900, 100)],
                    )?,
                })
            })
            .collect::<Test<_>>()?,
    })
}
fn profile() -> Test<EventFusionProfile> {
    Ok(EventFusionProfile::for_long_corroboration(
        spec()?,
        [pin("east"), pin("west")],
    )?)
}
fn read(json: &str) -> Result<EventFusionProfile> {
    EventFusionProfile::from_json(json.as_bytes(), pin(json))
}

#[test]
fn paired_profile_roundtrips_and_preserves_ordered_distinct_roots() -> Test {
    let profile = profile()?;
    let json = profile.to_json()?;
    assert_eq!(read(&json)?.digest(), profile.digest());
    assert_eq!(read(&json)?.to_json()?, json);
    assert_eq!(
        profile.long_corroboration_analysis_roots(),
        Some([pin("east"), pin("west")])
    );
    assert_eq!(profile.long_watch_analysis_root(), None);
    let parsed = parse(&json)?;
    let fields = parsed.object().ok_or("profile object")?;
    assert_eq!(
        fields["schema"].text(),
        Some("fss.event_class_fusion_profile.v3")
    );
    assert!(
        fields["coverage_digests"]
            .array()
            .ok_or("coverage array")?
            .is_empty()
    );
    assert!(!fields.contains_key("long_watch_analysis_root"));
    Ok(())
}

#[test]
fn every_analysis_pin_and_camera_order_changes_the_identity() -> Test {
    let original = profile()?;
    for index in 0..5 {
        let mut spec = spec()?;
        let mut roots = [pin("east"), pin("west")];
        match index {
            0 => spec.plan_digest = pin("other analysis"),
            1 => spec.cascade_digest = pin("other detector"),
            2 => roots[0] = pin("other east"),
            3 => roots[1] = pin("other west"),
            _ => roots.swap(0, 1),
        }
        assert_ne!(
            original.digest(),
            EventFusionProfile::for_long_corroboration(spec, roots)?.digest()
        );
    }
    Ok(())
}

#[test]
fn schemas_cannot_substitute_coverage_single_camera_or_extra_scope_fields() -> Test {
    let paired = profile()?.to_json()?;
    for version in ["profile.v1", "profile.v2"] {
        assert!(read(&paired.replace("profile.v3", version)).is_err());
    }
    let watch = EventFusionProfile::for_long_watch(spec()?, pin("east"))?.to_json()?;
    assert!(read(&watch.replace("profile.v2", "profile.v3")).is_err());
    let extra = paired.replacen(
        "{",
        &format!("{{\"long_watch_analysis_root\":\"{}\",", pin("extra")),
        1,
    );
    assert!(read(&extra).is_err());
    let mut covered = spec()?;
    covered.coverage_digests.insert(pin("coverage"));
    assert!(
        EventFusionProfile::for_long_corroboration(covered, [pin("east"), pin("west")]).is_err()
    );
    Ok(())
}

#[test]
fn missing_duplicate_zero_roots_and_inexact_bytes_fail_closed() -> Test {
    let zero = ContentDigest::parse(format!("sha256:{}", "00".repeat(32)))?;
    for index in 0..4 {
        let mut spec = spec()?;
        let mut roots = [pin("east"), pin("west")];
        match index {
            0 => spec.plan_digest = zero,
            1 => spec.cascade_digest = zero,
            2 => roots[0] = zero,
            _ => roots[1] = zero,
        }
        assert!(EventFusionProfile::for_long_corroboration(spec, roots).is_err());
    }
    assert!(
        EventFusionProfile::for_long_corroboration(spec()?, [pin("east"), pin("east")]).is_err()
    );
    let json = profile()?.to_json()?;
    let roots = format!("[\"{}\",\"{}\"]", pin("east"), pin("west"));
    assert!(json.contains(&roots));
    for replacement in [
        "[]".to_owned(),
        format!("[\"{}\"]", pin("east")),
        format!(
            "[\"{}\",\"{}\",\"{}\"]",
            pin("east"),
            pin("west"),
            pin("extra")
        ),
    ] {
        assert!(read(&json.replace(&roots, &replacement)).is_err());
    }
    assert!(EventFusionProfile::from_json(json.as_bytes(), pin("not exact bytes")).is_err());
    Ok(())
}

#[test]
fn count_authoring_rebuilds_calibration_and_cannot_replace_native_scope() -> Test {
    let counts = r#"{"schema":"fss.event_class_fusion_counts.v1","class_index":0,"prior":[-500,-500],
      "policy":{"generation":"policy:paired-fixture","alert_threshold":1000,"retain_threshold":-500,
      "reject_threshold":-1500,"min_independent_support":2,"urgent_single_domain_threshold":null,
      "max_wait_ns":10,"look_penalty_per_doubling":301,"operator_confirmation_available":true},
      "severity":{"expected_harm":1000,"false_alert_cost":10,"delay_cost_per_second":0,"reversible":false},
      "looks":1,"now_ns":10,"calibrations":[
      {"sensor":"sensor:a","failure_domains":[],"calibration":{"schema":"fss.score_calibration_counts.v1",
       "generation":"counts-v1","bins":[{"lo_ppm":0,"true_positives":100,"false_positives":9900},
       {"lo_ppm":500000,"true_positives":9900,"false_positives":100}]}},
      {"sensor":"sensor:b","failure_domains":[],"calibration":{"schema":"fss.score_calibration_counts.v1",
       "generation":"counts-v1","bins":[{"lo_ppm":0,"true_positives":100,"false_positives":9900},
       {"lo_ppm":500000,"true_positives":9900,"false_positives":100}]}}]}"#;
    let expected = profile()?;
    let authored = EventFusionProfile::from_long_corroboration_counts_json(
        counts.as_bytes(),
        pin(counts),
        expected.spec.plan_digest,
        expected.spec.cascade_digest,
        [pin("east"), pin("west")],
    )?;
    assert_eq!(authored.digest(), expected.digest());
    assert_eq!(authored.to_json()?, expected.to_json()?);
    let spoof = counts.replacen("{", "{\"long_corroboration_analysis_roots\":[],", 1);
    assert!(
        EventFusionProfile::from_long_corroboration_counts_json(
            spoof.as_bytes(),
            pin(&spoof),
            expected.spec.plan_digest,
            expected.spec.cascade_digest,
            [pin("east"), pin("west")]
        )
        .is_err()
    );
    Ok(())
}

fn record(name: &str, score: f32) -> ClassEvidence {
    ClassEvidence {
        segment: 150,
        reason: SelectionReason::ZoneEntry,
        outcome: EvidenceOutcome::Associated {
            detection: CascadeDetection {
                row: 0,
                class_index: 0,
                label: "person".into(),
                score,
                bounds: [0, 0, 256, 256],
            },
            iou_ppm: 1000000,
        },
        digest: pin(name),
        record: name.as_bytes().to_vec(),
    }
}
#[test]
fn two_camera_scores_share_model_causes_and_retain_native_links_and_counterfactuals() -> Test {
    let p = profile()?;
    let a = [record("east class", 0.9)];
    let b = [record("west class", 0.9)];
    let result = fuse_input(
        Input {
            candidate: pin("candidate"),
            proposal: pin("proposal"),
            provenance: pin("native graph"),
            sources: vec![
                Source {
                    sensor: "sensor:a",
                    dependency: Some("east domain"),
                    evidence: &a,
                },
                Source {
                    sensor: "sensor:b",
                    dependency: Some("west domain"),
                    evidence: &b,
                },
            ],
        },
        "person",
        &p,
        pin("context"),
        &["model:shared".into(), "package:shared".into()],
    )?;
    assert_eq!(result.native_proposal, pin("proposal"));
    assert_eq!(result.native_provenance, pin("native graph"));
    assert_eq!(result.scores.len(), 2);
    assert_eq!(result.outcome.clusters.len(), 1);
    assert_eq!(result.outcome.supporting_clusters, 1);
    assert_eq!(result.outcome.counterfactuals.len(), 1);
    assert_eq!(result.outcome.counterfactuals[0].posterior, p.spec.prior);
    assert_eq!(
        fuse(&result.query)?.decision_digest,
        result.outcome.decision_digest
    );
    assert!(matches!(result.query.coverage, Coverage::Gap { .. }));
    assert!(!matches!(
        result.outcome.decision,
        fss_fusion::Decision::Alert | fss_fusion::Decision::Reject
    ));
    Ok(())
}

mod native;
