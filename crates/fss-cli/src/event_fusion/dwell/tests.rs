#![forbid(unsafe_code)]
//! Dwell-specific scope, count calibration and evidence-conservation contracts.

use super::*;
use fss_fusion::{Decision, Reason};
use fss_reference::ingest::detector_cascade::{CascadeDetection, SelectionReason};

mod native;

type Test<T = ()> = std::result::Result<T, Box<dyn std::error::Error>>;

fn pin(text: &str) -> ContentDigest {
    ContentDigest::sha256(text.as_bytes())
}

fn spec() -> Test<ClassFusionSpec> {
    Ok(ClassFusionSpec {
        plan_digest: pin("complete dwell analysis"),
        cascade_digest: pin("retained dwell detector recipe"),
        coverage_digests: BTreeSet::new(),
        class_index: 0,
        prior: LlrInterval::point(-500)?,
        policy: FusionPolicy {
            generation: "policy:dwell-fixture".into(),
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
        calibrations: vec![SensorCalibration {
            sensor: "sensor:dwell-fixture".into(),
            calibration: ScoreCalibration::from_counts(
                "fixture-only-not-deployment-calibration",
                &[0, 500_000],
                &[(100, 9900), (9900, 100)],
            )?,
            failure_domains: BTreeSet::new(),
        }],
    })
}

fn read(json: &str) -> Result<EventFusionProfile> {
    EventFusionProfile::from_json(json.as_bytes(), pin(json))
}

#[test]
fn dwell_scope_roundtrips_and_cannot_impersonate_existing_profile_scopes() -> Test {
    let dwell = EventFusionProfile::for_long_dwell(spec()?, pin("graph"))?;
    let watch = EventFusionProfile::for_long_watch(spec()?, pin("graph"))?;
    let paired =
        EventFusionProfile::for_long_corroboration(spec()?, [pin("graph"), pin("other graph")])?;
    let mut short_spec = spec()?;
    short_spec.coverage_digests.insert(pin("coverage"));
    let short = EventFusionProfile::new(short_spec)?;
    let json = dwell.to_json()?;
    assert!(json.contains("fss.event_class_fusion_profile.v4"));
    assert_eq!(read(&json)?.digest(), dwell.digest());
    assert_eq!(read(&json)?.to_json()?, json);
    assert_eq!(dwell.long_dwell_analysis_root(), Some(pin("graph")));
    assert!(dwell.long_watch_analysis_root().is_none());
    assert!(dwell.long_corroboration_analysis_roots().is_none());
    for old in [short, watch, paired] {
        assert_ne!(old.digest(), dwell.digest());
        assert!(old.long_dwell_analysis_root().is_none());
        assert!(
            read(
                &old.to_json()?
                    .replace("profile.v1", "profile.v4")
                    .replace("profile.v2", "profile.v4")
                    .replace("profile.v3", "profile.v4")
            )
            .is_err()
        );
    }
    for version in ["v1", "v2", "v3"] {
        assert!(read(&json.replace("profile.v4", &format!("profile.{version}"))).is_err());
    }
    for field in [
        "long_watch_analysis_root",
        "long_corroboration_analysis_roots",
    ] {
        let mixed = json.replacen('{', &format!("{{\"{field}\":null,"), 1);
        assert!(read(&mixed).is_err());
    }
    Ok(())
}

#[test]
fn dwell_pins_bind_rule_analysis_package_recipe_and_source_root_without_coverage() -> Test {
    let baseline = EventFusionProfile::for_long_dwell(spec()?, pin("graph"))?;
    for field in 0..3 {
        let mut changed = spec()?;
        let mut root = pin("graph");
        match field {
            0 => changed.plan_digest = pin("other dwell rule analysis"),
            1 => changed.cascade_digest = pin("other detector recipe"),
            _ => root = pin("other source graph"),
        }
        assert_ne!(
            baseline.digest(),
            EventFusionProfile::for_long_dwell(changed, root)?.digest()
        );
        let zero = ContentDigest::parse(&format!("sha256:{}", "00".repeat(32)))?;
        let mut invalid = spec()?;
        let mut root = pin("graph");
        match field {
            0 => invalid.plan_digest = zero,
            1 => invalid.cascade_digest = zero,
            _ => root = zero,
        }
        assert!(matches!(
            EventFusionProfile::for_long_dwell(invalid, root),
            Err(EventFusionError::Profile)
        ));
    }
    let mut coverage = spec()?;
    coverage.coverage_digests.insert(pin("graph"));
    assert!(matches!(
        EventFusionProfile::for_long_dwell(coverage, pin("graph")),
        Err(EventFusionError::Profile)
    ));
    Ok(())
}

#[test]
fn every_episode_and_omission_spends_one_shared_bounded_inventory() {
    assert_eq!(MAX_LONG_DWELL_CANDIDATES, 32);
    assert_eq!(admit_inventory(32, std::iter::repeat_n(8, 32)), Ok(()));
    assert_eq!(admit_inventory(32, std::iter::repeat_n(0, 32)), Ok(()));
    assert_eq!(
        admit_inventory(33, std::iter::repeat_n(0, 33)),
        Err(EventFusionError::Limit)
    );
    assert_eq!(
        admit_inventory(2, [256, 0].into_iter()),
        Err(EventFusionError::Limit)
    );
    assert_eq!(
        admit_inventory(1, [usize::MAX].into_iter()),
        Err(EventFusionError::Limit)
    );
    assert_eq!(
        admit_inventory(2, [1].into_iter()),
        Err(EventFusionError::Evidence)
    );
    assert_eq!(
        admit_inventory(1, std::iter::repeat(0)),
        Err(EventFusionError::Limit)
    );
}

fn observation(name: &str) -> ClassEvidence {
    ClassEvidence {
        segment: 5,
        reason: SelectionReason::DwellStart,
        outcome: EvidenceOutcome::Associated {
            detection: CascadeDetection {
                row: 0,
                class_index: 0,
                label: "person".into(),
                score: 0.9,
                bounds: [0, 0, 256, 256],
            },
            iou_ppm: 1_000_000,
        },
        digest: pin(name),
        record: name.as_bytes().to_vec(),
    }
}

fn result(profile: &EventFusionProfile, evidence: &[ClassEvidence]) -> Result<CandidateFusion> {
    fuse_input(
        Input {
            candidate: pin("native dwell episode"),
            proposal: pin("native approval"),
            provenance: pin("native episode root"),
            sources: vec![Source {
                sensor: "sensor:dwell-fixture",
                dependency: None,
                evidence,
            }],
        },
        "person",
        profile,
        pin("context"),
        &["model:fixture".into(), "package:fixture".into()],
    )
}

#[test]
fn repeated_dwell_samples_stay_one_domain_with_a_recomputed_counterfactual() -> Test {
    let profile = EventFusionProfile::for_long_dwell(spec()?, pin("graph"))?;
    let fused = result(&profile, &[observation("first"), observation("next")])?;
    assert_eq!(fused.outcome.clusters.len(), 1);
    assert_eq!(fused.outcome.supporting_clusters, 1);
    assert_eq!(fused.outcome.counterfactuals.len(), 1);
    assert_eq!(
        fused.outcome.counterfactuals[0].posterior,
        profile.spec().prior
    );
    assert!(
        fused
            .outcome
            .reasons
            .contains(&Reason::InsufficientIndependentSupport)
    );
    assert!(!matches!(
        fused.outcome.decision,
        Decision::Alert | Decision::AlertDegradedCoverage
    ));
    assert_eq!(fused.native_proposal, pin("native approval"));
    assert_eq!(fused.native_provenance, pin("native episode root"));
    Ok(())
}

#[test]
fn unobserved_dwell_class_and_budget_refusal_do_not_create_negative_evidence() -> Test {
    let profile = EventFusionProfile::for_long_dwell(spec()?, pin("graph"))?;
    let mut skipped = observation("original skipped record");
    skipped.outcome = EvidenceOutcome::BudgetExhausted;
    for evidence in [Vec::new(), vec![skipped]] {
        let fused = result(&profile, &evidence)?;
        assert_eq!(fused.outcome.posterior, profile.spec().prior);
        assert_ne!(fused.outcome.decision, Decision::Reject);
        assert!(matches!(fused.query.coverage, Coverage::Gap { .. }));
        assert_eq!(fused.scores.len(), 1);
        assert!(fused.scores[0].score_bits.is_none());
        assert!(fused.scores[0].score_ppm.is_none());
        assert!(fused.scores[0].calibration.is_none());
    }
    Ok(())
}
