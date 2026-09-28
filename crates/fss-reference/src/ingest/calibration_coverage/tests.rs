#![forbid(unsafe_code)]
use super::super::privacy_mask::{PrivacyMaskPolicy, RetainedMaskPolicy};
use super::*;
use fss_geometry::{CameraGeneration, PinholeIntrinsics, RigidPose};
use std::sync::atomic::AtomicBool;

fn parameters() -> Vec<BundleParameter> {
    use BundleParameter::{Cx, Cy, Fx, Fy, K1, K2, Rotation, Translation};
    vec![
        Rotation(0),
        Rotation(1),
        Rotation(2),
        Translation(0),
        Translation(1),
        Translation(2),
        Fx,
        Fy,
        Cx,
        Cy,
        K1,
        K2,
    ]
}
fn camera(free: Vec<BundleParameter>, matrix: Vec<f64>) -> AdjustedCamera {
    let fixed = parameters()
        .into_iter()
        .filter(|p| !free.contains(p))
        .collect();
    AdjustedCamera {
        identity: CameraGeneration {
            camera: 1,
            intrinsics: 2,
            extrinsics: 3,
        },
        intrinsics: PinholeIntrinsics::new(100, 100, 100.0, 100.0, 50.0, 50.0).unwrap(),
        distortion: RadialDistortion::NONE,
        pose: RigidPose::new(
            [[1.0, 0.0, 0.0], [0.0, -1.0, 0.0], [0.0, 0.0, -1.0]],
            [0.0, 0.0, 10.0],
        )
        .unwrap(),
        covariance: CameraCovariance {
            parameters: free,
            matrix,
            fixed,
        },
    }
}
fn zones() -> Vec<GroundZone> {
    vec![GroundZone {
        zone_id: "door".to_owned(),
        x: -1.0,
        y: -1.0,
        width: 2.0,
        height: 2.0,
    }]
}
fn sensor() -> SensorId {
    SensorId::parse("sensor:front").unwrap()
}
fn mask(rectangles: &[[u32; 4]]) -> MaskBinding {
    let policy = PrivacyMaskPolicy::new(sensor(), [100, 100], rectangles).unwrap();
    MaskBinding::Policy(Box::new(RetainedMaskPolicy {
        digest: policy.digest(),
        policy,
        generation: 1,
    }))
}
fn assess(
    camera: &AdjustedCamera,
    privacy: &MaskBinding,
    zones: &[GroundZone],
) -> CalibrationCoverageAssessment {
    assess_with(
        camera,
        privacy,
        zones,
        &sensor(),
        &mut WorkBudget::new(MAX_CALIBRATION_COVERAGE_WORK),
    )
    .unwrap()
}
fn assess_with(
    camera: &AdjustedCamera,
    privacy: &MaskBinding,
    zones: &[GroundZone],
    sensor: &SensorId,
    budget: &mut WorkBudget<'_>,
) -> Result<CalibrationCoverageAssessment, CorroborationError> {
    assess_calibration_coverage(
        CalibrationCoverageInput {
            camera_name: "front",
            camera,
            calibration_digest: ContentDigest::sha256(b"synthetic calibration"),
            sensor,
            privacy,
            zones,
            policy: VisibilityPolicy {
                grid: 2,
                threshold_ppm: 1_000_000,
            },
        },
        budget,
    )
}

#[test]
fn interior_keeps_all_samples_but_does_not_claim_coverage() {
    let report = assess(&camera(vec![], vec![]), &MaskBinding::NoPolicy, &zones());
    let zone = &report.zones()[0];
    assert_eq!(zone.samples(), 4);
    assert_eq!(zone.count(CalibrationSampleRelation::InsideUnmasked), 4);
    assert!(!zone.requires_abstention());
    assert!(
        report
            .to_json()
            .contains("conditional_linearized_screen_not_coverage_or_physical_currency")
    );
    assert_eq!(report.work_units(), SETUP_WORK + 4 * (SAMPLE_WORK + 8));
}

#[test]
fn lens_variance_alone_blocks_a_nominally_visible_ground_zone() {
    let small = assess(
        &camera(vec![BundleParameter::Cx], vec![1.0]),
        &MaskBinding::NoPolicy,
        &zones(),
    );
    let large = assess(
        &camera(vec![BundleParameter::Cx], vec![400.0]),
        &MaskBinding::NoPolicy,
        &zones(),
    );
    assert!(!small.zones()[0].requires_abstention());
    assert_eq!(
        large.zones()[0].count(CalibrationSampleRelation::FrustumBoundary),
        4
    );
    assert!(large.zones()[0].requires_abstention());
    assert_ne!(small.input_digest(), large.input_digest());
}

#[test]
fn pose_lens_correlations_change_the_real_ground_zone_decision() {
    use BundleParameter::{Cx, Translation};
    let positive = camera(vec![Translation(0), Cx], vec![1.0, 9.99, 9.99, 100.0]);
    let negative = camera(vec![Translation(0), Cx], vec![1.0, -9.99, -9.99, 100.0]);
    let a = assess(&positive, &MaskBinding::NoPolicy, &zones());
    let b = assess(&negative, &MaskBinding::NoPolicy, &zones());
    assert!(a.zones()[0].requires_abstention());
    assert!(!b.zones()[0].requires_abstention());
}

#[test]
fn a_current_mask_can_be_reached_without_the_mean_being_masked() {
    let report = assess(
        &camera(vec![BundleParameter::Cx], vec![4.0]),
        &mask(&[[60, 40, 10, 20]]),
        &zones(),
    );
    assert_eq!(
        report.zones()[0].count(CalibrationSampleRelation::PrivacyBoundary),
        2
    );
    assert_eq!(
        report.zones()[0].count(CalibrationSampleRelation::InsideUnmasked),
        2
    );
    assert_eq!(
        report.zones()[0].count(CalibrationSampleRelation::PrivacyMasked),
        0
    );
    assert!(report.zones()[0].requires_abstention());
}

#[test]
fn masked_means_and_overlapping_rectangles_are_counted_once() {
    let report = assess(
        &camera(vec![], vec![]),
        &mask(&[[54, 40, 2, 20], [54, 39, 3, 22]]),
        &zones(),
    );
    assert_eq!(
        report.zones()[0].count(CalibrationSampleRelation::PrivacyMasked),
        2
    );
    assert_eq!(report.zones()[0].samples(), 4);
}

#[test]
fn mask_intersection_respects_included_and_excluded_edges() {
    let binding = mask(&[[60, 40, 10, 20]]);
    assert!(meets_mask([59.0, 45.0], [60.0, 45.0], &binding));
    assert!(meets_mask([65.0, 39.0], [65.0, 40.0], &binding));
    assert!(!meets_mask([70.0, 45.0], [71.0, 45.0], &binding));
    assert!(!meets_mask([65.0, 60.0], [65.0, 61.0], &binding));
}

#[test]
fn camera_plane_and_outside_means_remain_explicit() {
    let report = assess(
        &camera(vec![BundleParameter::Translation(2)], vec![100.0]),
        &MaskBinding::NoPolicy,
        &zones(),
    );
    assert_eq!(
        report.zones()[0].count(CalibrationSampleRelation::CameraPlaneCrossing),
        4
    );
    let mut outside = zones();
    outside[0].x = 10.0;
    let report = assess(&camera(vec![], vec![]), &MaskBinding::NoPolicy, &outside);
    assert_eq!(
        report.zones()[0].count(CalibrationSampleRelation::OutsideFrustum),
        4
    );
    let mut behind = camera(vec![], vec![]);
    behind.pose = RigidPose::IDENTITY
        .left_perturbed([0.0; 3], [0.0, 0.0, -10.0])
        .unwrap();
    let report = assess(&behind, &MaskBinding::NoPolicy, &zones());
    assert_eq!(
        report.zones()[0].count(CalibrationSampleRelation::MeanBehindCamera),
        4
    );
}

#[test]
fn invalid_covariance_is_not_hidden_by_behind_camera_samples() {
    let mut invalid = camera(
        vec![BundleParameter::Cx, BundleParameter::Cy],
        vec![1.0, 2.0, 2.0, 1.0],
    );
    invalid.pose = RigidPose::IDENTITY
        .left_perturbed([0.0; 3], [0.0, 0.0, -10.0])
        .unwrap();
    assert!(matches!(
        assess_with(
            &invalid,
            &MaskBinding::NoPolicy,
            &zones(),
            &sensor(),
            &mut WorkBudget::new(MAX_CALIBRATION_COVERAGE_WORK)
        ),
        Err(CorroborationError::InvalidPose { .. })
    ));
}

#[test]
fn sensor_resolution_digest_and_generation_mismatches_fail_closed() {
    let model = camera(vec![], vec![]);
    let valid = mask(&[[60, 40, 10, 20]]);
    let other = SensorId::parse("sensor:other").unwrap();
    assert!(
        assess_with(
            &model,
            &valid,
            &zones(),
            &other,
            &mut WorkBudget::new(MAX_CALIBRATION_COVERAGE_WORK)
        )
        .is_err()
    );
    let mut resized = model.clone();
    resized.intrinsics = PinholeIntrinsics::new(200, 100, 100.0, 100.0, 50.0, 50.0).unwrap();
    assert!(
        assess_with(
            &resized,
            &valid,
            &zones(),
            &sensor(),
            &mut WorkBudget::new(MAX_CALIBRATION_COVERAGE_WORK)
        )
        .is_err()
    );
    for change in 0..2 {
        let mut corrupt = valid.clone();
        if let MaskBinding::Policy(retained) = &mut corrupt {
            if change == 0 {
                retained.generation = 0;
            } else {
                retained.digest = ContentDigest::sha256(b"not the policy");
            }
        }
        assert!(
            assess_with(
                &model,
                &corrupt,
                &zones(),
                &sensor(),
                &mut WorkBudget::new(MAX_CALIBRATION_COVERAGE_WORK)
            )
            .is_err()
        );
    }
}

#[test]
fn zone_order_is_canonical_but_geometry_and_mask_changes_rebind_inputs() {
    let model = camera(vec![], vec![]);
    let mut two = zones();
    let mut second = two[0].clone();
    second.zone_id = "back".to_owned();
    second.x += 0.1;
    two.push(second);
    let a = assess(&model, &MaskBinding::NoPolicy, &two);
    two.reverse();
    let b = assess(&model, &MaskBinding::NoPolicy, &two);
    assert_eq!(a.input_digest(), b.input_digest());
    assert_eq!(a.to_json(), b.to_json());
    assert_eq!(a.zones()[0].zone_id(), "back");
    two[0].width += 0.1;
    assert_ne!(
        a.input_digest(),
        assess(&model, &MaskBinding::NoPolicy, &two).input_digest()
    );
    assert_ne!(
        a.input_digest(),
        assess(&model, &mask(&[[90, 90, 1, 1]]), &two).input_digest()
    );
}

#[test]
fn malformed_or_oversized_zones_refuse_before_spending_the_work_budget() {
    let model = camera(vec![], vec![]);
    let mut invalid = Vec::new();
    invalid.push(vec![]);
    invalid.push(vec![zones()[0].clone(); MAX_CORROBORATION_ZONES + 1]);
    invalid.push(vec![zones()[0].clone(); 2]);
    for axis in 0..3 {
        let mut z = zones();
        match axis {
            0 => z[0].width = -1.0,
            1 => z[0].x = f64::NAN,
            _ => z[0].zone_id = "bad/name".to_owned(),
        }
        invalid.push(z);
    }
    for z in invalid {
        let mut budget = WorkBudget::new(MAX_CALIBRATION_COVERAGE_WORK);
        assert!(assess_with(&model, &MaskBinding::NoPolicy, &z, &sensor(), &mut budget).is_err());
        assert_eq!(budget.used(), 0);
    }
}

#[test]
fn budget_is_shared_and_cancellation_never_returns_a_partial_report() {
    let model = camera(vec![], vec![]);
    let required = SETUP_WORK + 4 * (SAMPLE_WORK + 8);
    let mut short = WorkBudget::new(required - 1);
    assert!(matches!(
        assess_with(
            &model,
            &MaskBinding::NoPolicy,
            &zones(),
            &sensor(),
            &mut short
        ),
        Err(CorroborationError::Visibility(VisibilityError::Geometry(
            GeometryError::BudgetExhausted
        )))
    ));
    assert_eq!(short.used(), 0);
    let mut shared = WorkBudget::new(required * 2);
    assess_with(
        &model,
        &MaskBinding::NoPolicy,
        &zones(),
        &sensor(),
        &mut shared,
    )
    .unwrap();
    assess_with(
        &model,
        &MaskBinding::NoPolicy,
        &zones(),
        &sensor(),
        &mut shared,
    )
    .unwrap();
    assert_eq!(shared.remaining(), 0);
    let flag = AtomicBool::new(true);
    let mut cancelled = WorkBudget::cancellable(MAX_CALIBRATION_COVERAGE_WORK, &flag);
    assert!(matches!(
        assess_with(
            &model,
            &MaskBinding::NoPolicy,
            &zones(),
            &sensor(),
            &mut cancelled
        ),
        Err(CorroborationError::Visibility(VisibilityError::Geometry(
            GeometryError::Cancelled
        )))
    ));
    assert_eq!(cancelled.used(), 0);
}

#[test]
fn distorted_or_malformed_camera_blocks_are_not_pinhole_substitutes() {
    let mut model = camera(vec![], vec![]);
    model.distortion.k1 = 0.1;
    assert!(
        assess_with(
            &model,
            &MaskBinding::NoPolicy,
            &zones(),
            &sensor(),
            &mut WorkBudget::new(MAX_CALIBRATION_COVERAGE_WORK)
        )
        .is_err()
    );
    model.distortion = RadialDistortion::NONE;
    model.covariance.fixed.pop();
    assert!(
        assess_with(
            &model,
            &MaskBinding::NoPolicy,
            &zones(),
            &sensor(),
            &mut WorkBudget::new(MAX_CALIBRATION_COVERAGE_WORK)
        )
        .is_err()
    );
}
