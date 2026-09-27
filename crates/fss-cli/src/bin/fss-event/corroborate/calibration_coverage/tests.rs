#![forbid(unsafe_code)]
use super::*;
use fss_geometry::{AdjustedCamera, BundleParameter, CameraCovariance, CameraGeneration,
    PinholeIntrinsics, RadialDistortion, RigidPose};
use fss_reference::ingest::ground_visibility::VisibilityPolicy;
use fss_reference::ingest::privacy_mask::MaskBinding;
use fss_reference::ingest::recorded_corroboration::GroundZone;

fn assessment(variance: f64) -> CalibrationCoverageAssessment {
    use BundleParameter::{Cx, Cy, Fx, Fy, K1, K2, Rotation, Translation};
    let model = AdjustedCamera {
        identity: CameraGeneration { camera: 1, intrinsics: 1, extrinsics: 1 },
        intrinsics: PinholeIntrinsics::new(100, 100, 100.0, 100.0, 50.0, 50.0).unwrap(),
        distortion: RadialDistortion::NONE,
        pose: RigidPose::new([[1.0, 0.0, 0.0], [0.0, -1.0, 0.0], [0.0, 0.0, -1.0]], [0.0, 0.0, 10.0]).unwrap(),
        covariance: CameraCovariance {
            parameters: vec![Cx], matrix: vec![variance],
            fixed: vec![Rotation(0), Rotation(1), Rotation(2), Translation(0), Translation(1), Translation(2), Fx, Fy, Cy, K1, K2],
        },
    };
    let zones = [GroundZone { zone_id: "door".to_owned(), x: -1.0, y: -1.0, width: 2.0, height: 2.0 }];
    assess_calibration_coverage(CalibrationCoverageInput {
        camera_name: "front", camera: &model,
        calibration_digest: ContentDigest::sha256(b"synthetic"),
        sensor: &SensorId::parse("sensor:front").unwrap(), privacy: &MaskBinding::NoPolicy,
        zones: &zones, policy: VisibilityPolicy { grid: 2, threshold_ppm: 1_000_000 },
    }, &mut WorkBudget::new(MAX_CALIBRATION_COVERAGE_WORK)).unwrap()
}

#[test]
fn uncertainty_withholds_only_when_the_matching_zone_has_a_nominal_witness() {
    let uncertain = assessment(400.0);
    assert!(blocks_nominal_witness(&uncertain, |zone| zone == "door"));
    assert!(!blocks_nominal_witness(&uncertain, |_| false));
    assert!(!blocks_nominal_witness(&uncertain, |zone| zone == "unrelated"));
}

#[test]
fn a_clear_screen_does_not_invent_a_witness() {
    let clear = assessment(1.0);
    assert!(!blocks_nominal_witness(&clear, |_| true));
    assert!(!blocks_nominal_witness(&clear, |_| false));
    let guard = CoverageGuard { assessments: vec![clear], blocked: false };
    assert!(guard.check_retention(true).is_ok());
    assert!(guard.to_json().contains("\"absence_claim_authorized\":false"));
}

#[test]
fn uncertain_preview_allows_positive_work_but_a_mixed_retention_request_refuses() {
    let guard = CoverageGuard { assessments: vec![assessment(400.0)], blocked: true };
    assert!(guard.check_retention(false).is_ok());
    let error = guard.check_retention(true).unwrap_err();
    assert!(matches!(error.downcast_ref::<CorroborationError>(), Some(CorroborationError::InvalidPose { .. })));
    assert!(guard.to_json().contains("\"positive_event_approvals_changed\":false"));
}

#[test]
fn withheld_output_exposes_no_nominal_record_or_coverage_approval() {
    let guard = CoverageGuard { assessments: vec![assessment(400.0)], blocked: true };
    let output = guard.withheld_coverage_json();
    for required in [
        "\"format\":\"fss.calibration_coverage_refusal.v1\"",
        "\"status\":\"blocked\"", "\"knowledge_state\":\"not_observable\"",
        "\"approval_digest\":null", "\"approve_command\":null", "\"records\":[]",
        "\"existing_coverage_retracted\":false", "\"frustum_boundary\":4",
    ] { assert!(output.contains(required), "missing {required}"); }
    assert!(!output.contains("--retain-coverage"));
}

#[test]
fn repeated_screening_and_rendering_are_deterministic() {
    let first = CoverageGuard { assessments: vec![assessment(400.0)], blocked: true };
    let second = CoverageGuard { assessments: vec![assessment(400.0)], blocked: true };
    assert_eq!(first.to_json(), second.to_json());
    assert_eq!(first.withheld_coverage_json(), second.withheld_coverage_json());
}
