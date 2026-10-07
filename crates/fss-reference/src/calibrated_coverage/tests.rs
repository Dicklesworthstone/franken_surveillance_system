#![forbid(unsafe_code)]
use super::*;
use crate::ingest::calibration_coverage::{
    CalibrationCoverageInput, MAX_CALIBRATION_COVERAGE_WORK, assess_calibration_coverage,
};
use crate::ingest::ground_visibility::{
    CameraModel, Occlusion, OcclusionUnknownReason, PoseCovariance, PoseRobustness,
    PoseRobustnessClass, VisibilityPolicy, ZoneVisibility,
};
use crate::ingest::recorded_corroboration::GroundZone;
use crate::ingest::recorded_coverage::{
    CoverageEntry, CoverageExtras, CoverageFrame, CoverageInput, CoverageZoneInput,
    GenerationCurrency, build_coverage_with,
};
use fss_core::{CaptureInterval, LedgerAnchor, SensorId, TimestampNs};
use fss_geometry::{
    AdjustedCamera, BundleParameter, CameraCovariance, CameraGeneration, PinholeIntrinsics,
    RadialDistortion, RigidPose,
};
use std::sync::atomic::AtomicBool;

type TestResult = Result<(), Box<dyn std::error::Error>>;
static NO_POLICY: MaskBinding = MaskBinding::NoPolicy;

pub(super) fn fixture(
    index: u64,
    calibrated: bool,
) -> Result<(CoverageRecord, CalibrationCoverageAssessment), Box<dyn std::error::Error>> {
    use BundleParameter::{Cx, Cy, Fx, Fy, K1, K2, Rotation, Translation};
    let sensor = SensorId::parse(format!("sensor:camera-{index}"))?;
    let identity = CameraGeneration {
        camera: index,
        intrinsics: 2,
        extrinsics: 3,
    };
    let model = AdjustedCamera {
        identity,
        intrinsics: PinholeIntrinsics::new(100, 100, 100.0, 100.0, 50.0, 50.0)?,
        distortion: RadialDistortion::NONE,
        pose: RigidPose::new(
            [[1.0, 0.0, 0.0], [0.0, -1.0, 0.0], [0.0, 0.0, -1.0]],
            [0.0, 0.0, 10.0],
        )?,
        covariance: CameraCovariance {
            parameters: vec![Cx],
            matrix: vec![4.0],
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
    let ground = vec![
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
    let calibration = ContentDigest::sha256(b"guarded coverage fixture calibration");
    let assessment = assess_calibration_coverage(
        CalibrationCoverageInput {
            camera_name: "front",
            camera: &model,
            calibration_digest: calibration,
            sensor: &sensor,
            privacy: &MaskBinding::NoPolicy,
            zones: &ground,
            policy: VisibilityPolicy {
                grid: 2,
                threshold_ppm: 1_000_000,
            },
        },
        &mut WorkBudget::new(MAX_CALIBRATION_COVERAGE_WORK),
    )?;
    let frames: Vec<_> = (0..20)
        .filter(|n| *n != 8)
        .map(|segment| {
            Ok(CoverageFrame {
                segment,
                capture: CaptureInterval::new(
                    TimestampNs(1_000 + segment as i128 * 100),
                    TimestampNs(1_002 + segment as i128 * 100),
                )?,
            })
        })
        .collect::<Result<_, ContractError>>()?;
    let zones = ground
        .iter()
        .map(|zone| CoverageZoneInput {
            zone_id: zone.zone_id.clone(),
            geometry: format!("{},{},{},{}", zone.x, zone.y, zone.width, zone.height),
            inside_frame: true,
            pipeline_generation: ContentDigest::sha256(zone.zone_id.as_bytes()),
            entries: vec![CoverageEntry {
                segment: 12,
                candidate: ContentDigest::sha256(b"observed entry"),
                event_id: Some("event:observed-entry".to_owned()),
            }],
        })
        .collect();
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
    let mut record = build_coverage_with(
        &CoverageInput {
            source: CoverageSource::Corroborate,
            import_identity: ContentDigest::sha256(format!("import-{index}").as_bytes()),
            import_root: ContentDigest::sha256(format!("root-{index}").as_bytes()),
            sensor_id: sensor.as_str(),
            analysis_digest: ContentDigest::sha256(b"nominal analysis"),
            basis: LedgerAnchor::genesis("site:guarded-coverage"),
            capture_time_label: "operator_assumption",
            segment_gaps: &[false; 20],
            first_segment: 0,
            last_segment: 19,
            frames: &frames,
            confirmation_hits: 3,
            zones,
        },
        &CoverageExtras {
            sensor_health: None,
            visibility: vec![Some(visibility.clone()), Some(visibility)],
            refusals: Vec::new(),
            restarts: vec![9],
            pose_provenance: Some(if calibrated {
                PoseProvenance::SiteCalibration {
                    calibration_digest: calibration,
                    camera_handle: identity.camera,
                    intrinsics_generation: identity.intrinsics,
                    extrinsics_generation: identity.extrinsics,
                    currency: GenerationCurrency::OwnerAsserted,
                }
            } else {
                PoseProvenance::OwnerPoseArgument
            }),
            pose_uncertainty: Some(if calibrated {
                PoseUncertainty::SigmaPoints {
                    covariance: PoseCovariance::new([[0.0; 6]; 6])?,
                }
            } else {
                PoseUncertainty::NotProvided
            }),
            pose_robustness: if calibrated {
                vec![Some(robust), Some(robust)]
            } else {
                vec![None, None]
            },
        },
    )?;
    for zone in &mut record.zones {
        for interval in &mut zone.uncovered {
            if interval.reason == UncoveredReason::SegmentNotDecoded {
                interval.reason = UncoveredReason::DecodeRefused {
                    error_id: "ERR-MEDIA-DECODE-001".to_owned(),
                };
            }
        }
    }
    record.validate()?;
    Ok((record, assessment))
}

fn input<'a>(
    record: &'a CoverageRecord,
    assessment: Option<&'a CalibrationCoverageAssessment>,
) -> CoverageProjectionInput<'a> {
    CoverageProjectionInput {
        record,
        assessment,
        privacy: &NO_POLICY,
    }
}

#[test]
fn two_camera_projection_keeps_safe_witnesses_and_every_original_exclusion() -> TestResult {
    let (a, screen_a) = fixture(1, true)?;
    let (b, screen_b) = fixture(2, true)?;
    let bytes = [a.to_bytes(), b.to_bytes()];
    let result = GuardedCoverageSet::project(
        &[input(&a, Some(&screen_a)), input(&b, Some(&screen_b))],
        &mut WorkBudget::new(MAX_CALIBRATION_COVERAGE_WORK),
    )?;
    assert_eq!([a.to_bytes(), b.to_bytes()], bytes);
    assert_ne!(result.approval(), approval_digest(&[&a, &b]));
    let mut abstained = 0;
    for (old, new) in [&a, &b].into_iter().zip(result.records()) {
        assert!(!new.zones[0].witnesses.is_empty());
        assert!(new.zones[1].witnesses.is_empty());
        abstained += old.zones[1].witnesses.len();
        for (old_zone, new_zone) in old.zones.iter().zip(&new.zones) {
            for exclusion in &old_zone.uncovered {
                assert!(new_zone.uncovered.contains(exclusion));
            }
        }
        assert_eq!(
            CoverageRecord::from_bytes(&new.to_bytes(), new.digest())?,
            *new
        );
    }
    assert_eq!(result.abstained_intervals(), abstained);
    assert!(abstained > 0);
    Ok(())
}

#[test]
fn uncalibrated_companion_is_byte_identical_and_not_silently_screened() -> TestResult {
    let (a, screen_a) = fixture(1, true)?;
    let (b, screen_b) = fixture(2, false)?;
    let result = GuardedCoverageSet::project(
        &[input(&a, Some(&screen_a)), input(&b, None)],
        &mut WorkBudget::new(MAX_CALIBRATION_COVERAGE_WORK),
    )?;
    assert_eq!(result.records()[1].to_bytes(), b.to_bytes());
    assert!(
        GuardedCoverageSet::project(
            &[input(&a, Some(&screen_a)), input(&b, Some(&screen_b))],
            &mut WorkBudget::new(MAX_CALIBRATION_COVERAGE_WORK),
        )
        .is_err()
    );
    Ok(())
}

#[test]
fn every_calibrated_camera_requires_its_exact_screen() -> TestResult {
    let (a, screen_a) = fixture(1, true)?;
    let (b, screen_b) = fixture(2, true)?;
    for inputs in [
        vec![input(&a, None), input(&b, Some(&screen_b))],
        vec![input(&a, Some(&screen_a)), input(&b, None)],
        vec![input(&a, Some(&screen_b)), input(&b, Some(&screen_a))],
        vec![input(&a, Some(&screen_a)), input(&a, Some(&screen_a))],
    ] {
        assert!(
            GuardedCoverageSet::project(
                &inputs,
                &mut WorkBudget::new(MAX_CALIBRATION_COVERAGE_WORK),
            )
            .is_err()
        );
    }
    Ok(())
}

#[test]
fn refusal_of_the_second_camera_never_mutates_the_first() -> TestResult {
    let (a, screen_a) = fixture(1, true)?;
    let (mut b, screen_b) = fixture(2, true)?;
    let before = a.to_bytes();
    b.zones[0].geometry = "-2,-1,2,2".to_owned();
    assert!(
        GuardedCoverageSet::project(
            &[input(&a, Some(&screen_a)), input(&b, Some(&screen_b))],
            &mut WorkBudget::new(MAX_CALIBRATION_COVERAGE_WORK),
        )
        .is_err()
    );
    assert_eq!(a.to_bytes(), before);
    Ok(())
}

#[test]
fn work_budget_is_shared_and_checked_at_the_exact_boundary() -> TestResult {
    let (a, screen_a) = fixture(1, true)?;
    let (b, screen_b) = fixture(2, true)?;
    let inputs = [input(&a, Some(&screen_a)), input(&b, Some(&screen_b))];
    let mut measured = WorkBudget::new(MAX_CALIBRATION_COVERAGE_WORK);
    let expected = GuardedCoverageSet::project(&inputs, &mut measured)?;
    let used = measured.used();
    assert!(GuardedCoverageSet::project(&inputs, &mut WorkBudget::new(used - 1)).is_err());
    let mut exact = WorkBudget::new(used);
    let actual = GuardedCoverageSet::project(&inputs, &mut exact)?;
    assert_eq!(actual.approval(), expected.approval());
    assert_eq!(exact.remaining(), 0);
    let cancelled = AtomicBool::new(true);
    assert!(
        GuardedCoverageSet::project(
            &inputs,
            &mut WorkBudget::cancellable(MAX_CALIBRATION_COVERAGE_WORK, &cancelled),
        )
        .is_err()
    );
    Ok(())
}

#[test]
fn mixed_anchors_empty_sets_and_unbounded_companions_are_refused() -> TestResult {
    let (a, screen_a) = fixture(1, true)?;
    let (mut b, screen_b) = fixture(2, true)?;
    b.basis = LedgerAnchor::genesis("site:other");
    assert!(
        GuardedCoverageSet::project(
            &[input(&a, Some(&screen_a)), input(&b, Some(&screen_b))],
            &mut WorkBudget::new(MAX_CALIBRATION_COVERAGE_WORK),
        )
        .is_err()
    );
    assert!(
        GuardedCoverageSet::project(&[], &mut WorkBudget::new(MAX_CALIBRATION_COVERAGE_WORK))
            .is_err()
    );
    let (mut companion, _) = fixture(3, false)?;
    companion.zones[0].geometry = "x".repeat(257);
    assert!(
        GuardedCoverageSet::project(
            &[input(&a, Some(&screen_a)), input(&companion, None)],
            &mut WorkBudget::new(MAX_CALIBRATION_COVERAGE_WORK),
        )
        .is_err()
    );
    Ok(())
}
