#![forbid(unsafe_code)]

use super::*;
use crate::{CameraCovariance, PinholeIntrinsics, RadialDistortion, RigidPose};
use std::sync::atomic::AtomicBool;

fn parameters() -> [BundleParameter; N] {
    use BundleParameter::{Cx, Cy, Fx, Fy, K1, K2, Rotation, Translation};
    [
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
        .filter(|p| {
            !free
                .iter()
                .any(|q| parameter_slot(*p) == parameter_slot(*q))
        })
        .collect();
    AdjustedCamera {
        identity: CameraGeneration {
            camera: 1,
            intrinsics: 2,
            extrinsics: 3,
        },
        intrinsics: PinholeIntrinsics::new(640, 480, 800.0, 900.0, 320.0, 240.0).unwrap(),
        distortion: RadialDistortion::NONE,
        pose: RigidPose::IDENTITY,
        covariance: CameraCovariance {
            parameters: free,
            matrix,
            fixed,
        },
    }
}
fn estimate(
    camera: &AdjustedCamera,
) -> Result<CameraProjectionUncertainty, ProjectionUncertaintyError> {
    camera.project_uncertainty(
        camera.identity,
        [2.0, 1.0, 10.0],
        &mut WorkBudget::new(CAMERA_UNCERTAINTY_WORK_UNITS),
    )
}
fn close(a: f64, b: f64) {
    assert!(
        (a - b).abs() <= 1e-9 * a.abs().max(b.abs()).max(1.0),
        "{a} != {b}"
    );
}

#[test]
fn cross_terms_can_increase_or_decrease_projected_uncertainty() {
    use BundleParameter::{Fx, Translation};
    for (cross, expected) in [(0.25, 73.0), (0.0, 65.0), (-0.25, 57.0)] {
        let input = camera(vec![Translation(0), Fx], vec![0.01, cross, cross, 25.0]);
        let output = estimate(&input).unwrap();
        assert_eq!(output.identity(), input.identity);
        assert_eq!(output.pixel(), [480.0, 330.0]);
        assert_eq!(output.world_point(), [2.0, 1.0, 10.0]);
        close(output.covariance_px2()[0][0], expected);
        assert_eq!(output.covariance_px2()[1][1], 0.0);
        assert_eq!(output.fixed_parameters(), input.covariance.fixed);
    }
}

#[test]
fn aspect_held_focal_changes_both_image_axes() {
    let input = camera(vec![BundleParameter::Focal], vec![25.0]);
    let output = estimate(&input).unwrap();
    close(output.covariance_px2()[0][0], 1.0);
    close(output.covariance_px2()[0][1], 0.5625);
    close(output.covariance_px2()[1][1], 0.31640625);
    assert!(output.fixed_parameters().contains(&BundleParameter::Fy));
}

#[test]
fn all_fixed_is_conditional_zero_not_missing_metadata() {
    let input = camera(vec![], vec![]);
    let output = estimate(&input).unwrap();
    assert_eq!(output.covariance_px2(), [[0.0; 2]; 2]);
    assert_eq!(output.fixed_parameters().len(), N);
}

#[test]
fn reordering_free_parameters_and_covariance_preserves_result() {
    use BundleParameter::{Fx, Translation};
    let a = camera(vec![Translation(0), Fx], vec![0.01, 0.25, 0.25, 25.0]);
    let b = camera(vec![Fx, Translation(0)], vec![25.0, 0.25, 0.25, 0.01]);
    let (a, b) = (estimate(&a).unwrap(), estimate(&b).unwrap());
    assert_eq!(a.pixel(), b.pixel());
    for (a, b) in a
        .covariance_px2()
        .iter()
        .flatten()
        .zip(b.covariance_px2().iter().flatten())
    {
        close(*a, *b);
    }
}

fn perturbed(input: &AdjustedCamera, parameter: BundleParameter, delta: f64) -> AdjustedCamera {
    use BundleParameter::{Cx, Cy, Focal, Fx, Fy, K1, K2, Rotation, Translation};
    let mut input = input.clone();
    let [width, height] = input.intrinsics.dimensions();
    let [mut fx, mut fy] = input.intrinsics.focal_lengths();
    let [mut cx, mut cy] = input.intrinsics.principal_point();
    match parameter {
        Rotation(axis) => {
            let mut rotation = [0.0; 3];
            rotation[axis] = delta;
            input.pose = input.pose.left_perturbed(rotation, [0.0; 3]).unwrap();
        }
        Translation(axis) => {
            let mut translation = [0.0; 3];
            translation[axis] = delta;
            input.pose = input.pose.left_perturbed([0.0; 3], translation).unwrap();
        }
        Focal => {
            let aspect = fy / fx;
            fx += delta;
            fy = fx * aspect;
        }
        Fx => fx += delta,
        Fy => fy += delta,
        Cx => cx += delta,
        Cy => cy += delta,
        K1 => input.distortion.k1 += delta,
        K2 => input.distortion.k2 += delta,
    }
    input.intrinsics = PinholeIntrinsics::new(width, height, fx, fy, cx, cy).unwrap();
    input
}

#[test]
fn all_analytic_columns_match_finite_differences_with_nonzero_translation() {
    let mut input = camera(vec![], vec![]);
    input.pose = RigidPose::IDENTITY
        .left_perturbed([0.1, -0.2, 0.05], [1.0, -0.5, 0.3])
        .unwrap();
    input.distortion = RadialDistortion {
        k1: 0.015,
        k2: -0.003,
    };
    let point = [0.8, 0.4, 8.0];
    let (_, jacobian) = projection_jacobian(&input, point).unwrap();
    for (slot, parameter) in parameters().into_iter().enumerate() {
        let step = if (6..=9).contains(&slot) { 1e-3 } else { 1e-6 };
        let (plus, _) = projection_jacobian(&perturbed(&input, parameter, step), point).unwrap();
        let (minus, _) = projection_jacobian(&perturbed(&input, parameter, -step), point).unwrap();
        for row in 0..2 {
            let numerical = (plus[row] - minus[row]) / (2.0 * step);
            assert!(
                (numerical - jacobian[row][slot]).abs() <= 1e-5 * numerical.abs().max(1.0),
                "parameter {parameter:?}, row {row}: numerical {numerical}, analytic {}",
                jacobian[row][slot],
            );
        }
    }
    let step = 1e-3;
    let (plus, _) =
        projection_jacobian(&perturbed(&input, BundleParameter::Focal, step), point).unwrap();
    let (minus, _) =
        projection_jacobian(&perturbed(&input, BundleParameter::Focal, -step), point).unwrap();
    let [fx, fy] = input.intrinsics.focal_lengths();
    close((plus[0] - minus[0]) / (2.0 * step), jacobian[0][6]);
    close(
        (plus[1] - minus[1]) / (2.0 * step),
        jacobian[1][7] * fy / fx,
    );
}

#[test]
fn stale_or_zero_generation_refuses_without_an_estimate() {
    let input = camera(vec![], vec![]);
    for current in [
        CameraGeneration {
            camera: 9,
            ..input.identity
        },
        CameraGeneration {
            intrinsics: 9,
            ..input.identity
        },
        CameraGeneration {
            extrinsics: 9,
            ..input.identity
        },
    ] {
        assert!(matches!(
            input.project_uncertainty(current, [0.0, 0.0, 10.0], &mut WorkBudget::new(100_000)),
            Err(ProjectionUncertaintyError::GenerationMismatch { .. }),
        ));
    }
    let mut invalid = input;
    invalid.identity.camera = 0;
    assert_eq!(
        estimate(&invalid),
        Err(ProjectionUncertaintyError::InvalidGeneration)
    );
}

#[test]
fn malformed_matrix_and_parameter_contracts_are_refused() {
    use ProjectionUncertaintyError::{
        ConflictingFocalModel, InvalidMatrixShape, InvalidParameterPartition,
    };
    let mut input = camera(vec![BundleParameter::Fx], vec![]);
    assert_eq!(estimate(&input), Err(InvalidMatrixShape));
    input.covariance.matrix = vec![1.0, 2.0];
    assert_eq!(estimate(&input), Err(InvalidMatrixShape));
    input.covariance.matrix = vec![1.0];
    input.covariance.fixed[0] = BundleParameter::Fx;
    assert_eq!(estimate(&input), Err(InvalidParameterPartition));
    input.covariance.fixed[0] = BundleParameter::Rotation(3);
    assert_eq!(estimate(&input), Err(InvalidParameterPartition));
    input.covariance.fixed.clear();
    assert_eq!(estimate(&input), Err(InvalidParameterPartition));
    let input = camera(
        vec![BundleParameter::Focal, BundleParameter::Fy],
        vec![1.0, 0.0, 0.0, 1.0],
    );
    assert_eq!(estimate(&input), Err(ConflictingFocalModel));
    let mut input = camera(vec![], vec![]);
    input.covariance.parameters = vec![BundleParameter::Fx; N + 1];
    let mut budget = WorkBudget::new(0);
    assert_eq!(
        input.project_uncertainty(input.identity, [0.0, 0.0, 1.0], &mut budget),
        Err(InvalidParameterPartition),
    );
    assert_eq!(budget.used(), 0);
}

#[test]
fn indefinite_nonfinite_asymmetric_and_zero_variance_cross_terms_refuse() {
    use BundleParameter::{Cx, Cy, Fx};
    use ProjectionUncertaintyError::{
        AsymmetricCovariance, NonFiniteCovariance, NotPositiveSemidefinite,
    };
    for (matrix, expected) in [
        (vec![1.0, 2.0, 2.0, 1.0], NotPositiveSemidefinite),
        (vec![1.0, 0.1, 0.2, 1.0], AsymmetricCovariance),
        (vec![0.0, 0.01, 0.01, 1.0], NotPositiveSemidefinite),
        (vec![-1.0, 0.0, 0.0, 1.0], NotPositiveSemidefinite),
        (vec![1.0, f64::NAN, f64::NAN, 1.0], NonFiniteCovariance),
        (vec![f64::INFINITY, 0.0, 0.0, 1.0], NonFiniteCovariance),
    ] {
        assert_eq!(estimate(&camera(vec![Cx, Cy], matrix)), Err(expected));
    }
    // All pairwise correlations are <= 1, but the complete matrix is indefinite.
    let input = camera(
        vec![Cx, Cy, Fx],
        vec![1.0, -0.75, -0.75, -0.75, 1.0, -0.75, -0.75, -0.75, 1.0],
    );
    assert_eq!(estimate(&input), Err(NotPositiveSemidefinite));
}

#[test]
fn exact_semidefinite_zero_and_mixed_scale_covariances_are_supported() {
    use BundleParameter::{Cx, Cy};
    let rank_one = estimate(&camera(vec![Cx, Cy], vec![1.0; 4])).unwrap();
    assert_eq!(rank_one.covariance_px2(), [[1.0; 2]; 2]);
    let zero = estimate(&camera(vec![Cx, Cy], vec![0.0; 4])).unwrap();
    assert_eq!(zero.covariance_px2(), [[0.0; 2]; 2]);
    let mixed = estimate(&camera(vec![Cx, Cy], vec![1e-24, 0.0, 0.0, 1e24])).unwrap();
    assert!((mixed.covariance_px2()[0][0] / 1e-24 - 1.0).abs() < 1e-12);
    assert!((mixed.covariance_px2()[1][1] / 1e24 - 1.0).abs() < 1e-12);
}

#[test]
fn budget_and_cancellation_fail_without_partial_charges() {
    let input = camera(vec![], vec![]);
    let mut budget = WorkBudget::new(CAMERA_UNCERTAINTY_WORK_UNITS - 1);
    assert_eq!(
        input.project_uncertainty(input.identity, [0.0, 0.0, 1.0], &mut budget),
        Err(GeometryError::BudgetExhausted.into()),
    );
    assert_eq!(budget.used(), 0);
    let mut exact = WorkBudget::new(CAMERA_UNCERTAINTY_WORK_UNITS);
    input
        .project_uncertainty(input.identity, [0.0, 0.0, 1.0], &mut exact)
        .unwrap();
    assert_eq!(exact.remaining(), 0);
    let flag = AtomicBool::new(true);
    let mut cancelled = WorkBudget::cancellable(100_000, &flag);
    assert_eq!(
        input.project_uncertainty(input.identity, [0.0, 0.0, 1.0], &mut cancelled),
        Err(GeometryError::Cancelled.into()),
    );
    assert_eq!(cancelled.used(), 0);
}

#[test]
fn invalid_geometry_does_not_become_a_zero_variance_projection() {
    let input = camera(vec![], vec![]);
    for point in [[0.0, 0.0, 0.0], [0.0, 0.0, -1.0], [f64::NAN, 0.0, 1.0]] {
        assert!(
            input
                .project_uncertainty(input.identity, point, &mut WorkBudget::new(100_000))
                .is_err()
        );
    }
    let mut invalid = input;
    invalid.distortion.k1 = f64::INFINITY;
    assert!(estimate(&invalid).is_err());
}

fn frustum_at(pixel: [f64; 2], variance: f64, multiplier: f64) -> LinearizedFrustumAssessment {
    let mut input = camera(
        vec![BundleParameter::Cx, BundleParameter::Cy],
        vec![variance, 0.0, 0.0, variance],
    );
    input.intrinsics = PinholeIntrinsics::new(640, 480, 800.0, 900.0, pixel[0], pixel[1]).unwrap();
    let projection = input
        .project_uncertainty(
            input.identity,
            [0.0, 0.0, 10.0],
            &mut WorkBudget::new(100_000),
        )
        .unwrap();
    projection
        .linearized_frustum(
            multiplier,
            &mut WorkBudget::new(FRUSTUM_UNCERTAINTY_WORK_UNITS),
        )
        .unwrap()
}

#[test]
fn frustum_keeps_half_open_edges_and_uncertain_membership_distinct() {
    use LinearizedFrustumRelation::{Boundary, Inside, Outside};
    for (pixel, variance, expected) in [
        ([320.0, 240.0], 1.0, Inside),
        ([0.0, 0.0], 0.0, Inside),
        ([640.0, 240.0], 0.0, Outside),
        ([320.0, 480.0], 0.0, Outside),
        ([0.0, 240.0], 1.0, Boundary),
        ([639.0, 240.0], 1.0, Boundary),
        ([-1.0, 240.0], 1.0, Boundary),
        ([-2.0, 240.0], 1.0, Outside),
        ([641.0, 240.0], 1.0, Outside),
    ] {
        let result = frustum_at(pixel, variance, 1.0);
        assert_eq!(
            result.relation, expected,
            "pixel {pixel:?}, variance {variance}"
        );
    }
    let result = frustum_at([0.0, 240.0], 1.0, 3.0);
    assert_eq!(result.pixel_min, [-3.0, 237.0]);
    assert_eq!(result.pixel_max, [3.0, 243.0]);
    assert_eq!(result.sigma_multiplier, 3.0);
}

#[test]
fn depth_crossing_camera_plane_overrides_zero_pixel_variance() {
    let input = camera(vec![BundleParameter::Translation(2)], vec![100.0]);
    let output = input
        .project_uncertainty(
            input.identity,
            [0.0, 0.0, 10.0],
            &mut WorkBudget::new(100_000),
        )
        .unwrap();
    assert_eq!(output.covariance_px2(), [[0.0; 2]; 2]);
    assert_eq!(output.camera_depth(), 10.0);
    close(output.depth_variance(), 100.0);
    let crossing = output
        .linearized_frustum(1.0, &mut WorkBudget::new(100_000))
        .unwrap();
    assert_eq!(crossing.depth_interval, [0.0, 20.0]);
    assert_eq!(
        crossing.relation,
        LinearizedFrustumRelation::CrossesCameraPlane
    );
    let interior = output
        .linearized_frustum(0.5, &mut WorkBudget::new(100_000))
        .unwrap();
    assert_eq!(interior.relation, LinearizedFrustumRelation::Inside);
}

#[test]
fn depth_covariance_keeps_rotation_translation_correlation() {
    use BundleParameter::{Rotation, Translation};
    // At identity R, dz/dwx = world_y = 1 and dz/dtz = 1.
    let input = camera(
        vec![Rotation(0), Translation(2)],
        vec![1.0, -0.5, -0.5, 1.0],
    );
    let output = estimate(&input).unwrap();
    close(output.depth_variance(), 1.0); // 1 + 1 - 2 * 0.5, not diagonal-only 2.
}

#[test]
fn frustum_scale_and_budget_are_explicit() {
    let output = estimate(&camera(vec![], vec![])).unwrap();
    for scale in [0.0, -1.0, f64::NAN, f64::INFINITY, 1e6 + 1.0] {
        let mut budget = WorkBudget::new(0);
        assert_eq!(
            output.linearized_frustum(scale, &mut budget),
            Err(ProjectionUncertaintyError::InvalidSigmaMultiplier)
        );
        assert_eq!(budget.used(), 0);
    }
    let mut short = WorkBudget::new(FRUSTUM_UNCERTAINTY_WORK_UNITS - 1);
    assert_eq!(
        output.linearized_frustum(1.0, &mut short),
        Err(GeometryError::BudgetExhausted.into())
    );
    assert_eq!(short.used(), 0);
    let flag = AtomicBool::new(true);
    let mut cancelled = WorkBudget::cancellable(100_000, &flag);
    assert_eq!(
        output.linearized_frustum(1.0, &mut cancelled),
        Err(GeometryError::Cancelled.into())
    );
}

fn solved_bundle() -> BundleAdjustment {
    use crate::{
        AnchoredBundleProblem, BundleCamera, BundleControlPoint, BundleObservation, BundleOptions,
        IntrinsicsRefinement, bundle_adjust_anchored,
    };
    let base = camera(vec![], vec![]);
    let cameras: Vec<_> = (0..2)
        .map(|i| BundleCamera {
            identity: CameraGeneration {
                camera: i + 1,
                ..base.identity
            },
            intrinsics: base.intrinsics,
            distortion: RadialDistortion::NONE,
            pose: RigidPose::IDENTITY
                .left_perturbed([0.0; 3], [-(i as f64) * 0.5, 0.0, 0.0])
                .unwrap(),
            refinement: IntrinsicsRefinement::FIXED,
        })
        .collect();
    let mut control_points = Vec::new();
    for z in [5.0, 8.0] {
        for y in [-1.0, 1.0] {
            for x in [-1.0, 1.0] {
                control_points.push(BundleControlPoint {
                    landmark: control_points.len() as u64 + 1,
                    position: [x, y, z],
                });
            }
        }
    }
    let mut observations = Vec::new();
    for camera in &cameras {
        for point in &control_points {
            observations.push(BundleObservation {
                camera: camera.identity.camera,
                landmark: point.landmark,
                pixel: camera
                    .pose
                    .project(camera.intrinsics, point.position)
                    .unwrap(),
            });
        }
    }
    bundle_adjust_anchored(
        &AnchoredBundleProblem {
            basis: GeometryBasis::new(1, 1).unwrap(),
            cameras,
            landmarks: vec![],
            control_points,
            observations,
            gauge: BundleGaugeChoice::ControlPoints,
        },
        BundleOptions {
            observation_sigma_px: Some(1.0),
            ..BundleOptions::default()
        },
        &mut WorkBudget::new(1_000_000_000),
    )
    .unwrap()
}

#[test]
fn solved_bundle_flows_through_generation_checked_projection_and_frustum() {
    let bundle = solved_bundle();
    let current = bundle.dependencies();
    let mut budget = WorkBudget::new(
        BUNDLE_UNCERTAINTY_VALIDATION_WORK_UNITS
            + CAMERA_UNCERTAINTY_WORK_UNITS
            + FRUSTUM_UNCERTAINTY_WORK_UNITS,
    );
    let result = bundle
        .project_camera_uncertainty(1, bundle.basis(), &current, [0.0, 0.0, 6.0], &mut budget)
        .unwrap();
    assert_eq!(result.basis(), bundle.basis());
    assert_eq!(result.dependencies(), current);
    assert_eq!(result.gauge(), BundleGaugeChoice::ControlPoints);
    assert_eq!(result.observation_sigma_px(), (1.0, false));
    assert_eq!(result.projection().pixel(), [320.0, 240.0]);
    assert!(result.projection().covariance_px2()[0][0] > 0.0);
    let frustum = result
        .projection()
        .linearized_frustum(3.0, &mut budget)
        .unwrap();
    assert_eq!(frustum.relation, LinearizedFrustumRelation::Inside);
    assert_eq!(budget.remaining(), 0);
}

#[test]
fn changing_a_different_camera_invalidates_a_joint_projection() {
    let bundle = solved_bundle();
    let mut current = bundle.dependencies();
    current[1].intrinsics += 1;
    let result = bundle.project_camera_uncertainty(
        1,
        bundle.basis(),
        &current,
        [0.0, 0.0, 6.0],
        &mut WorkBudget::new(100_000),
    );
    assert!(
        matches!(result, Err(ProjectionUncertaintyError::InvalidatedBundle(ref changes)) if changes.len() == 1 && changes[0].camera == 2)
    );
    current[1].intrinsics -= 1;
    let missing = bundle.project_camera_uncertainty(
        1,
        bundle.basis(),
        &current[..1],
        [0.0, 0.0, 6.0],
        &mut WorkBudget::new(100_000),
    );
    assert!(matches!(
        missing,
        Err(ProjectionUncertaintyError::InvalidatedBundle(_))
    ));
}

#[test]
fn bundle_projection_refuses_ambiguous_generations_wrong_basis_and_unknown_camera() {
    let bundle = solved_bundle();
    let current = bundle.dependencies();
    let duplicate = [current[0], current[1], current[0]];
    assert_eq!(
        bundle.project_camera_uncertainty(
            1,
            bundle.basis(),
            &duplicate,
            [0.0, 0.0, 6.0],
            &mut WorkBudget::new(100_000)
        ),
        Err(ProjectionUncertaintyError::InvalidDependencySet),
    );
    assert_eq!(
        bundle.project_camera_uncertainty(
            1,
            GeometryBasis::new(1, 2).unwrap(),
            &current,
            [0.0, 0.0, 6.0],
            &mut WorkBudget::new(100_000)
        ),
        Err(GeometryError::BasisMismatch.into()),
    );
    assert_eq!(
        bundle.project_camera_uncertainty(
            99,
            bundle.basis(),
            &current,
            [0.0, 0.0, 6.0],
            &mut WorkBudget::new(100_000)
        ),
        Err(ProjectionUncertaintyError::UnknownCamera(99)),
    );
    let oversized = vec![current[0]; MAX_BUNDLE_CAMERAS + 1];
    assert_eq!(
        bundle.project_camera_uncertainty(
            1,
            bundle.basis(),
            &oversized,
            [0.0, 0.0, 6.0],
            &mut WorkBudget::new(0)
        ),
        Err(ProjectionUncertaintyError::InvalidDependencySet),
    );
}
