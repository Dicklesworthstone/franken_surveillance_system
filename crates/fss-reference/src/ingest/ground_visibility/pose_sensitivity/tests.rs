#![forbid(unsafe_code)]
//! Pose-uncertainty propagation (fss-x8j0v): sigma-point construction, robust versus
//! pose-sensitive classification of a zone near the frustum edge and of a centred zone,
//! determinism, typed budget and covariance refusals.

use fss_core::{CanonicalDecoder, CanonicalEncoder};
use fss_geometry::{PinholeIntrinsics, RigidPose, WorkBudget};

use super::super::{VisibilityPolicy, assess_ground_zone, rectangle};
use super::*;

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

const DIMENSIONS: [u32; 2] = [96, 48];

/// A camera 10 units above (48, 24) looking straight down, f = 10 px, principal point (48, 24):
/// image column `u = x` and row `v = 48 - y`, so it sees exactly the ground [0, 96) x (0, 48].
fn down_camera() -> TestResult<CameraPose> {
    Ok(CameraPose {
        intrinsics: PinholeIntrinsics::new(96, 48, 10.0, 10.0, 48.0, 24.0)?,
        pose: RigidPose::from_center(
            [[1.0, 0.0, 0.0], [0.0, -1.0, 0.0], [0.0, 0.0, -1.0]],
            [48.0, 24.0, 10.0],
        )?,
    })
}

/// Diagonal pose covariance: rotation variance (rad^2), translation variance (units^2).
fn diagonal(rotation: f64, translation: f64) -> TestResult<PoseCovariance> {
    let mut matrix = [[0.0_f64; 6]; 6];
    for (index, row) in matrix.iter_mut().enumerate() {
        row[index] = if index < 3 { rotation } else { translation };
    }
    Ok(PoseCovariance::new(matrix)?)
}

/// Tight: sigma 1e-4 rad and 0.01 units, so every sigma point moves a pixel by at most ~0.03.
fn tight() -> TestResult<PoseCovariance> {
    diagonal(1e-8, 1e-4)
}

/// Inflated translation: sigma 1 unit (the translation sigma points move pixels by about 3),
/// rotation as tight as [`tight`] (sigma 1e-4 rad).
fn inflated() -> TestResult<PoseCovariance> {
    diagonal(1e-8, 1.0)
}

/// Ground x 86..95: the outermost sample column (x = 94.44) projects 1.56 px inside the right
/// image edge, so a 3-unit translation sigma point pushes it out.
fn edge_zone() -> [(f64, f64); 4] {
    rectangle(86.0, 4.0, 9.0, 40.0)
}

/// Ground 40..56 x 16..32 around the principal point: every sample stays tens of pixels inside.
fn centred_zone() -> [(f64, f64); 4] {
    rectangle(40.0, 16.0, 16.0, 16.0)
}

fn robustness(zone: &[(f64, f64)], covariance: &PoseCovariance) -> TestResult<PoseRobustness> {
    let pose = down_camera()?;
    let policy = VisibilityPolicy::default();
    let nominal = assess_ground_zone(
        VisibilityCamera::Pose(&pose),
        DIMENSIONS,
        zone,
        None,
        policy,
    )?;
    let mut budget = WorkBudget::new(MAX_POSE_SENSITIVITY_WORK);
    Ok(assess_pose_robustness(
        &pose,
        covariance,
        DIMENSIONS,
        zone,
        None,
        policy,
        None,
        &nominal,
        &mut budget,
    )?)
}

#[test]
fn sigma_points_are_the_documented_twelve_poses_in_order() -> TestResult {
    let pose = down_camera()?;
    // Translation sigma 0.5 on X only: the points are t (+/-) 1.5 on the X column, the others
    // are exactly the nominal pose (zero columns of a semidefinite factor).
    let mut matrix = [[0.0_f64; 6]; 6];
    matrix[3][3] = 0.25;
    let points = pose_sigma_points(&pose, &PoseCovariance::new(matrix)?)?;
    assert_eq!(points.len(), POSE_SENSITIVITY_PERTURBATIONS as usize);
    let nominal = pose.pose.translation();
    for (index, point) in points.iter().enumerate() {
        assert_eq!(point.intrinsics, pose.intrinsics);
        assert_eq!(point.pose.rotation(), pose.pose.rotation());
        let expected = match index {
            6 => [nominal[0] + 1.5, nominal[1], nominal[2]],
            7 => [nominal[0] - 1.5, nominal[1], nominal[2]],
            _ => nominal,
        };
        assert_eq!(point.pose.translation(), expected, "sigma point {index}");
    }
    // A correlated block factors exactly: L = [[2, 0], [1, sqrt(2)]] scaled by the radius.
    let mut correlated = [[0.0_f64; 6]; 6];
    correlated[3][3] = 4.0;
    correlated[3][4] = 2.0;
    correlated[4][3] = 2.0;
    correlated[4][4] = 3.0;
    let points = pose_sigma_points(&pose, &PoseCovariance::new(correlated)?)?;
    assert_eq!(
        points[6].pose.translation(),
        [nominal[0] + 6.0, nominal[1] + 3.0, nominal[2]]
    );
    assert_eq!(
        points[9].pose.translation(),
        [nominal[0], nominal[1] - 3.0 * 2.0_f64.sqrt(), nominal[2]]
    );
    Ok(())
}

#[test]
fn a_zone_near_the_frustum_edge_is_robust_when_tight_and_pose_sensitive_when_inflated() -> TestResult
{
    let tight_edge = robustness(&edge_zone(), &tight()?)?;
    assert_eq!(tight_edge.nominal, PoseRobustnessClass::Observable);
    assert_eq!(tight_edge.perturbations, 12);
    assert_eq!(tight_edge.observable, 12);
    assert!(tight_edge.robust());
    assert_eq!(tight_edge.state(), "robust");
    assert!(!tight_edge.observable_but_sensitive());
    assert_eq!(tight_edge.disagreeing_ppm(), 0);

    let inflated_edge = robustness(&edge_zone(), &inflated()?)?;
    assert_eq!(inflated_edge.nominal, PoseRobustnessClass::Observable);
    assert!(!inflated_edge.robust());
    assert_eq!(inflated_edge.state(), "pose_sensitive");
    assert!(inflated_edge.observable_but_sensitive());
    // +3 on translation X shifts every image column right by 3 px (out of frame); -3 on
    // translation Z brings the camera closer and magnifies the zone out of frame; the rotation
    // points (3e-4 rad, well under a pixel here) and the other translations stay in.
    assert_eq!(
        (
            inflated_edge.observable,
            inflated_edge.outside_frustum,
            inflated_edge.occluded,
            inflated_edge.privacy_masked
        ),
        (10, 2, 0, 0)
    );
    assert_eq!(inflated_edge.agreeing(), 10);
    assert_eq!(inflated_edge.disagreeing_ppm(), 166_666);
    assert_eq!(
        inflated_edge.classes(),
        vec![
            PoseRobustnessClass::Observable,
            PoseRobustnessClass::OutsideFrustum
        ]
    );
    assert_eq!(
        inflated_edge.summary(),
        "pose_sensitive: 2 of 12 sigma-point poses disagree with the nominal observable \
         (166666 ppm; observable 10, outside_frustum 2)"
    );
    Ok(())
}

#[test]
fn a_centred_zone_stays_robust_under_both_covariances() -> TestResult {
    for covariance in [tight()?, inflated()?] {
        let centred = robustness(&centred_zone(), &covariance)?;
        assert_eq!(centred.nominal, PoseRobustnessClass::Observable);
        assert_eq!(centred.observable, 12);
        assert!(centred.robust());
    }
    // A zone outside the frustum that the inflated points bring into view is pose-sensitive but
    // not observable under the nominal pose: it stays uncovered either way.
    let beyond = robustness(&rectangle(96.5, 4.0, 1.0, 40.0), &inflated()?)?;
    assert_eq!(beyond.nominal, PoseRobustnessClass::OutsideFrustum);
    assert!(!beyond.robust());
    assert!(!beyond.observable_but_sensitive());
    Ok(())
}

#[test]
fn robustness_is_deterministic_and_round_trips_canonically() -> TestResult {
    let first = robustness(&edge_zone(), &inflated()?)?;
    let second = robustness(&edge_zone(), &inflated()?)?;
    assert_eq!(first, second);
    let pose = down_camera()?;
    let a = pose_sigma_points(&pose, &inflated()?)?;
    let b = pose_sigma_points(&pose, &inflated()?)?;
    for (left, right) in a.iter().zip(&b) {
        assert_eq!(left.parameter_bits(), right.parameter_bits());
    }
    let mut e = CanonicalEncoder::new();
    first.encode(&mut e);
    inflated()?.encode(&mut e);
    let bytes = e.finish();
    let nominal = assess_ground_zone(
        VisibilityCamera::Pose(&pose),
        DIMENSIONS,
        &edge_zone(),
        None,
        VisibilityPolicy::default(),
    )?;
    let mut d = CanonicalDecoder::new(&bytes);
    assert_eq!(PoseRobustness::decode(&mut d, &nominal)?, first);
    assert_eq!(PoseCovariance::decode(&mut d)?, inflated()?);
    d.ensure_finished()?;
    // Counts that do not add up to the registered perturbation count are refused.
    let mut e = CanonicalEncoder::new();
    PoseRobustness {
        observable: 11,
        ..first
    }
    .encode(&mut e);
    let bytes = e.finish();
    assert!(PoseRobustness::decode(&mut CanonicalDecoder::new(&bytes), &nominal).is_err());
    Ok(())
}

#[test]
fn an_exhausted_budget_and_an_invalid_covariance_are_typed_refusals() -> TestResult {
    let pose = down_camera()?;
    let policy = VisibilityPolicy::default();
    let zone = edge_zone();
    let nominal = assess_ground_zone(
        VisibilityCamera::Pose(&pose),
        DIMENSIONS,
        &zone,
        None,
        policy,
    )?;
    // 12 perturbations x 64 samples = 768 units: 767 is refused before any assessment.
    let mut budget = WorkBudget::new(767);
    assert_eq!(
        assess_pose_robustness(
            &pose,
            &tight()?,
            DIMENSIONS,
            &zone,
            None,
            policy,
            None,
            &nominal,
            &mut budget,
        ),
        Err(VisibilityError::PoseSensitivityBudget)
    );
    assert_eq!(budget.used(), 0);
    let mut budget = WorkBudget::new(768);
    assert!(
        assess_pose_robustness(
            &pose,
            &tight()?,
            DIMENSIONS,
            &zone,
            None,
            policy,
            None,
            &nominal,
            &mut budget,
        )?
        .robust()
    );
    assert_eq!(budget.remaining(), 0);
    // Not symmetric, not finite, clearly indefinite, and a negative scale are refused.
    let mut asymmetric = [[0.0_f64; 6]; 6];
    asymmetric[0][0] = 1.0;
    asymmetric[1][1] = 1.0;
    asymmetric[0][1] = 0.5;
    assert_eq!(
        PoseCovariance::new(asymmetric),
        Err(VisibilityError::InvalidCovariance)
    );
    let mut infinite = [[0.0_f64; 6]; 6];
    infinite[2][2] = f64::INFINITY;
    assert_eq!(
        PoseCovariance::new(infinite),
        Err(VisibilityError::InvalidCovariance)
    );
    let mut indefinite = [[0.0_f64; 6]; 6];
    indefinite[0][0] = 1.0;
    indefinite[1][1] = 1.0;
    indefinite[0][1] = 2.0;
    indefinite[1][0] = 2.0;
    assert_eq!(
        PoseCovariance::new(indefinite),
        Err(VisibilityError::InvalidCovariance)
    );
    let mut negative = [[0.0_f64; 6]; 6];
    negative[4][4] = -1.0;
    assert_eq!(
        PoseCovariance::new(negative),
        Err(VisibilityError::InvalidCovariance)
    );
    assert_eq!(
        tight()?.scaled(-1.0),
        Err(VisibilityError::InvalidCovariance)
    );
    assert_eq!(diagonal(0.25, 0.5)?.scaled(4.0)?, diagonal(1.0, 2.0)?);
    Ok(())
}
