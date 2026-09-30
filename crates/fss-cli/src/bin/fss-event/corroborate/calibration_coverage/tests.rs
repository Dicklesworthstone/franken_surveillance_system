#![forbid(unsafe_code)]

use super::*;
use fss_core::{CaptureInterval, ContractError, LedgerAnchor, TimestampNs};
use fss_geometry::{
    AdjustedCamera, BundleParameter, CameraCovariance, CameraGeneration, PinholeIntrinsics,
    RadialDistortion, RigidPose,
};
use fss_reference::ingest::calibration_coverage::{
    MAX_CALIBRATION_COVERAGE_WORK, apply_calibration_coverage,
};
use fss_reference::ingest::ground_visibility::{
    CameraModel, Occlusion, OcclusionUnknownReason, PoseCovariance, PoseRobustness,
    PoseRobustnessClass, VisibilityPolicy, ZoneVisibility,
};
use fss_reference::ingest::privacy_mask::MaskBinding;
use fss_reference::ingest::recorded_corroboration::GroundZone;
use fss_reference::ingest::recorded_coverage::{
    CoverageEntry, CoverageExtras, CoverageFrame, CoverageInput, CoverageRecord, CoverageSource,
    CoverageZoneInput, GenerationCurrency, PoseUncertainty, UncoveredReason, approval_digest,
    build_coverage_with,
};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

fn fixture(
    variance: f64,
    time: &str,
) -> TestResult<(CoverageRecord, CalibrationCoverageAssessment)> {
    use BundleParameter::{Cx, Cy, Fx, Fy, K1, K2, Rotation, Translation};
    let model = AdjustedCamera {
        identity: CameraGeneration {
            camera: 1,
            intrinsics: 2,
            extrinsics: 3,
        },
        intrinsics: PinholeIntrinsics::new(100, 100, 100.0, 100.0, 50.0, 50.0)?,
        distortion: RadialDistortion::NONE,
        pose: RigidPose::new(
            [[1.0, 0.0, 0.0], [0.0, -1.0, 0.0], [0.0, 0.0, -1.0]],
            [0.0, 0.0, 10.0],
        )?,
        covariance: CameraCovariance {
            parameters: vec![Cx],
            matrix: vec![variance],
            fixed: vec![
                Rotation(0),
                Rotation(1),
                Rotation(2),
                Translation(0),
                Translation(1),
                Translation(2),
                Fx,
                Fy,
                Cy,
                K1,
                K2,
            ],
        },
    };
    let ground = [
        GroundZone {
            zone_id: "center".to_owned(),
            x: -1.0,
            y: -1.0,
            width: 2.0,
            height: 2.0,
        },
        GroundZone {
            zone_id: "edge".to_owned(),
            x: 4.5,
            y: -1.0,
            width: 0.4,
            height: 2.0,
        },
    ];
    let calibration = ContentDigest::sha256(b"CLI guard calibration fixture");
    let assessment = assess_calibration_coverage(
        CalibrationCoverageInput {
            camera_name: "front",
            camera: &model,
            calibration_digest: calibration,
            sensor: &SensorId::parse("sensor:front")?,
            privacy: &MaskBinding::NoPolicy,
            zones: &ground,
            policy: VisibilityPolicy {
                grid: 2,
                threshold_ppm: 1_000_000,
            },
        },
        &mut WorkBudget::new(MAX_CALIBRATION_COVERAGE_WORK),
    )?;
    let frames = (0..20)
        .filter(|segment| *segment != 8)
        .map(|segment| {
            Ok(CoverageFrame {
                segment,
                capture: CaptureInterval::new(
                    TimestampNs(1_000 + segment as i128 * 100),
                    TimestampNs(1_002 + segment as i128 * 100),
                )?,
            })
        })
        .collect::<Result<Vec<_>, ContractError>>()?;
    let visibility = ZoneVisibility {
        camera_model: CameraModel::CalibratedPose,
        grid: 2,
        threshold_ppm: 1_000_000,
        samples: 4,
        visible: 4,
        outside_frustum: 0,
        occluded: 0,
        privacy_masked: 0,
        occlusion: Occlusion::Unknown(OcclusionUnknownReason::NoSceneMesh),
    };
    let robust = PoseRobustness {
        nominal: PoseRobustnessClass::Observable,
        perturbations: 12,
        observable: 12,
        occluded: 0,
        outside_frustum: 0,
        privacy_masked: 0,
    };
    let record = build_coverage_with(
        &CoverageInput {
            source: CoverageSource::Corroborate,
            import_identity: ContentDigest::sha256(b"CLI guard import"),
            import_root: ContentDigest::sha256(b"CLI guard root"),
            sensor_id: "sensor:front",
            analysis_digest: ContentDigest::sha256(b"CLI analysis"),
            basis: LedgerAnchor::genesis("site:guard-cli"),
            capture_time_label: time,
            segment_gaps: &[false; 20],
            first_segment: 0,
            last_segment: 19,
            frames: &frames,
            confirmation_hits: 3,
            zones: ground
                .iter()
                .map(|zone| CoverageZoneInput {
                    zone_id: zone.zone_id.clone(),
                    geometry: format!("{},{},{},{}", zone.x, zone.y, zone.width, zone.height),
                    inside_frame: true,
                    pipeline_generation: ContentDigest::sha256(zone.zone_id.as_bytes()),
                    entries: vec![CoverageEntry {
                        segment: 12,
                        candidate: ContentDigest::sha256(b"observed entry"),
                        event_id: Some("event:entry".to_owned()),
                    }],
                })
                .collect(),
        },
        &CoverageExtras {
            visibility: vec![Some(visibility.clone()), Some(visibility)],
            refusals: Vec::new(),
            restarts: vec![9],
            pose_provenance: Some(PoseProvenance::SiteCalibration {
                calibration_digest: calibration,
                camera_handle: 1,
                intrinsics_generation: 2,
                extrinsics_generation: 3,
                currency: GenerationCurrency::OwnerAsserted,
            }),
            pose_uncertainty: Some(PoseUncertainty::SigmaPoints {
                covariance: PoseCovariance::new([[0.0; 6]; 6])?,
            }),
            pose_robustness: vec![Some(robust), Some(robust)],
        },
    )?;
    Ok((record, assessment))
}

fn guard(variance: f64, time: &str) -> TestResult<(CoverageRecord, CoverageGuard)> {
    let (nominal, assessment) = fixture(variance, time)?;
    let mut budget = WorkBudget::new(MAX_CALIBRATION_COVERAGE_WORK);
    let guarded = GuardedCoverageSet::project(
        &[CoverageProjectionInput {
            record: &nominal,
            assessment: Some(&assessment),
            privacy: &MaskBinding::NoPolicy,
        }],
        &mut budget,
    )?;
    let guard = CoverageGuard {
        assessments: vec![assessment],
        guarded,
        read_limits: RetainedReadLimits::default(),
        status: CoverageStatus::Proposed,
        work_units: budget.used(),
        work_units_total: budget.used(),
        work_units_remaining: budget.remaining(),
    };
    Ok((nominal, guard))
}

#[test]
fn mixed_zones_publish_only_guard_bound_witnesses_and_approval() -> TestResult {
    let (nominal, guard) = guard(4.0, "operator_assumption")?;
    assert!(!guard.guarded.records()[0].zones[0].witnesses.is_empty());
    assert!(guard.guarded.records()[0].zones[1].witnesses.is_empty());
    let json = guard.coverage_json("fss-event corroborate --root test --site site:guard-cli");
    assert!(json.contains("calibration_uncertainty"));
    assert!(json.contains(&guard.guarded.records()[0].digest().to_text()));
    assert!(json.contains(&approval_digest(&[&guard.guarded.records()[0]]).to_text()));
    assert!(!json.contains(&approval_digest(&[&nominal]).to_text()));
    assert!(json.contains("--retain-coverage"));
    Ok(())
}

#[test]
fn fully_uncertain_zones_still_have_explicit_retainable_exclusions() -> TestResult {
    let (_, guard) = guard(400.0, "operator_assumption")?;
    assert_eq!(guard.guarded.records()[0].witnesses().count(), 0);
    assert_eq!(guard.guarded.records()[0].zones.len(), 2);
    let json = guard.coverage_json("fss-event corroborate");
    assert!(json.contains("calibration_uncertainty"));
    assert!(json.contains(&approval_digest(&[&guard.guarded.records()[0]]).to_text()));
    assert!(!json.contains("\"records\":[]"));
    assert!(
        guard
            .to_json()
            .contains("\"absence_claim_authorized\":false")
    );
    Ok(())
}

#[test]
fn a_clear_screen_cannot_create_missing_time_or_coverage() -> TestResult {
    let (nominal, guard) = guard(0.01, "unknown")?;
    assert_eq!(nominal.witnesses().count(), 0);
    assert_eq!(guard.guarded.records()[0].witnesses().count(), 0);
    for (old, new) in nominal.zones.iter().zip(&guard.guarded.records()[0].zones) {
        assert_eq!(old.uncovered, new.uncovered);
    }
    Ok(())
}

#[test]
fn positive_entries_gaps_warmup_and_latency_are_not_relabelled() -> TestResult {
    let (nominal, guard) = guard(4.0, "operator_assumption")?;
    for (old, new) in nominal.zones.iter().zip(&guard.guarded.records()[0].zones) {
        for interval in &old.uncovered {
            assert!(new.uncovered.contains(interval));
        }
    }
    let excluded = &guard.guarded.records()[0].zones[1].uncovered;
    assert!(
        excluded
            .iter()
            .any(|i| matches!(i.reason, UncoveredReason::ZoneEntry { .. }))
    );
    assert!(
        excluded
            .iter()
            .any(|i| i.reason == UncoveredReason::SegmentNotDecoded)
    );
    assert!(
        guard
            .to_json()
            .contains("\"positive_event_approvals_changed\":false")
    );
    assert!(
        guard
            .to_json()
            .contains("\"existing_coverage_retracted\":false")
    );
    Ok(())
}

#[test]
fn source_and_model_bindings_cannot_be_substituted() -> TestResult {
    let (mut nominal, assessment) = fixture(4.0, "operator_assumption")?;
    nominal.import_root = ContentDigest::sha256(b"changed import");
    // A fresh legitimate screen binds the actual input root in its new receipt.
    let guarded = apply_calibration_coverage(
        &nominal,
        &assessment,
        &mut WorkBudget::new(MAX_CALIBRATION_COVERAGE_WORK),
    )?;
    let mut forged = guarded;
    forged.import_root = ContentDigest::sha256(b"substituted after screening");
    assert!(forged.validate().is_err());
    Ok(())
}

#[test]
fn camera_projection_work_is_cumulative_and_refusal_leaves_input_unchanged() -> TestResult {
    let (nominal, assessment) = fixture(4.0, "operator_assumption")?;
    let before = nominal.to_bytes();
    let mut measured = WorkBudget::new(MAX_CALIBRATION_COVERAGE_WORK);
    apply_calibration_coverage(&nominal, &assessment, &mut measured)?;
    let one = measured.used();
    let mut shared = WorkBudget::new(one * 2 - 1);
    apply_calibration_coverage(&nominal, &assessment, &mut shared)?;
    assert!(apply_calibration_coverage(&nominal, &assessment, &mut shared).is_err());
    assert_eq!(nominal.to_bytes(), before);
    Ok(())
}

#[test]
fn repeated_projection_and_rendering_are_deterministic() -> TestResult {
    let (_, first) = guard(4.0, "operator_assumption")?;
    let (_, second) = guard(4.0, "operator_assumption")?;
    assert_eq!(first.to_json(), second.to_json());
    assert_eq!(
        first.coverage_json("command"),
        second.coverage_json("command")
    );
    assert_eq!(
        first.guarded.records()[0].to_bytes(),
        second.guarded.records()[0].to_bytes()
    );
    Ok(())
}
