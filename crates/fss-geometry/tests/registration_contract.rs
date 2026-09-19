#![forbid(unsafe_code)]
//! Pose-registration contracts: correspondence solving, residuals, and validation sets.

use fss_geometry::{
    Correspondence, GeometryBasis, GeometryError, PinholeIntrinsics, PoseSolverOptions, RigidPose,
    WorkBudget, estimate_nonplanar_camera_pose as estimate_camera_pose,
};
use std::sync::atomic::AtomicBool;

type TestResult = Result<(), Box<dyn std::error::Error>>;
fn intrinsics() -> Result<PinholeIntrinsics, GeometryError> {
    PinholeIntrinsics::new(1920, 1080, 800.0, 820.0, 960.0, 540.0)
}
fn controls(start: u64, count: usize, x_shift: f64) -> Vec<Correspondence> {
    (0..count)
        .map(|i| {
            let id = start + i as u64;
            let n = id as f64;
            let world = [
                2.0 * (n * 0.7).sin(),
                1.5 * (n * 1.3).cos(),
                1.2 * (n * 0.31).sin(),
            ];
            let x = 0.8 * world[0] + 0.6 * world[2] + 0.3 + x_shift;
            let y = world[1] - 0.4;
            let z = -0.6 * world[0] + 0.8 * world[2] + 8.0;
            Correspondence {
                landmark: id,
                physical_group: id,
                world,
                pixel: [800.0 * x / z + 960.0, 820.0 * y / z + 540.0],
            }
        })
        .collect()
}
fn truth() -> Result<RigidPose, GeometryError> {
    RigidPose::new(
        [[0.8, 0.0, 0.6], [0.0, 1.0, 0.0], [-0.6, 0.0, 0.8]],
        [0.3, -0.4, 8.0],
    )
}
fn distance(a: [f64; 3], b: [f64; 3]) -> f64 {
    (a[0] - b[0]).hypot(a[1] - b[1]).hypot(a[2] - b[2])
}
fn fast() -> PoseSolverOptions {
    PoseSolverOptions {
        ransac_trials: 0,
        ..PoseSolverOptions::default()
    }
}

#[test]
fn recovers_camera_from_independent_image_controls() -> TestResult {
    let basis = GeometryBasis::new(1, 1)?;
    let search = estimate_camera_pose(
        basis,
        intrinsics()?,
        &controls(1, 24, 0.0),
        fast(),
        &mut WorkBudget::new(10_000_000),
    )?;
    assert_eq!(search.candidates().len(), 1);
    let candidate = &search.candidates()[0];
    assert!(distance(candidate.pose().center(), truth()?.center()) < 1e-5);
    assert!(candidate.rms_px() < 1e-5);
    assert_eq!(candidate.inlier_landmarks().len(), 24);
    assert!(
        search
            .validate_candidate(
                0,
                basis,
                &controls(101, 12, 0.0),
                0.01,
                &mut WorkBudget::new(100_000)
            )?
            .passed
    );
    Ok(())
}

#[test]
fn six_point_nonplanar_seed_is_supported_explicitly() -> TestResult {
    let options = PoseSolverOptions {
        minimum_inliers: 6,
        minimum_inlier_fraction: 1.0,
        ..fast()
    };
    let search = estimate_camera_pose(
        GeometryBasis::new(1, 1)?,
        intrinsics()?,
        &controls(1, 6, 0.0),
        options,
        &mut WorkBudget::new(10_000_000),
    )?;
    assert!(distance(search.candidates()[0].pose().center(), truth()?.center()) < 1e-4);
    Ok(())
}

#[test]
fn rejects_planar_maps_instead_of_claiming_a_general_solver() -> TestResult {
    let mut points = controls(1, 24, 0.0);
    for point in &mut points {
        point.world[2] = 0.0;
    }
    assert!(matches!(
        estimate_camera_pose(
            GeometryBasis::new(1, 1)?,
            intrinsics()?,
            &points,
            fast(),
            &mut WorkBudget::new(10_000_000)
        ),
        Err(GeometryError::UnsupportedGeometry)
    ));
    Ok(())
}

#[test]
fn input_order_cannot_change_the_seeded_result() -> TestResult {
    let basis = GeometryBasis::new(1, 1)?;
    let points = controls(1, 24, 0.0);
    let mut reversed = points.clone();
    reversed.reverse();
    let options = PoseSolverOptions {
        ransac_trials: 8,
        ..fast()
    };
    let a = estimate_camera_pose(
        basis,
        intrinsics()?,
        &points,
        options,
        &mut WorkBudget::new(10_000_000),
    )?;
    let b = estimate_camera_pose(
        basis,
        intrinsics()?,
        &reversed,
        options,
        &mut WorkBudget::new(10_000_000),
    )?;
    assert_eq!(a.candidates()[0].pose(), b.candidates()[0].pose());
    assert_eq!(
        a.candidates()[0].inlier_landmarks(),
        b.candidates()[0].inlier_landmarks()
    );
    assert_eq!(a.work_units(), b.work_units());
    Ok(())
}

#[test]
fn robust_sampling_rejects_a_quarter_of_incorrect_matches() -> TestResult {
    let mut points = controls(1, 40, 0.0);
    for (i, point) in points.iter_mut().enumerate() {
        if i % 4 == 0 {
            point.pixel = [110.0 + 23.0 * i as f64, 90.0 + 17.0 * i as f64];
        } else {
            point.pixel[0] += 0.15 * (i as f64 * 3.0).sin();
            point.pixel[1] += 0.15 * (i as f64 * 5.0).cos();
        }
    }
    let search = estimate_camera_pose(
        GeometryBasis::new(1, 1)?,
        intrinsics()?,
        &points,
        PoseSolverOptions::default(),
        &mut WorkBudget::new(100_000_000),
    )?;
    let candidate = &search.candidates()[0];
    assert_eq!(candidate.inlier_landmarks().len(), 30);
    assert!(distance(candidate.pose().center(), truth()?.center()) < 0.03);
    assert!(candidate.rms_px() < 0.3);
    Ok(())
}

#[test]
fn physical_aliases_and_repeated_world_points_are_not_extra_support() -> TestResult {
    let mut points = controls(1, 24, 0.0);
    points[1].physical_group = points[0].physical_group;
    assert!(matches!(
        estimate_camera_pose(
            GeometryBasis::new(1, 1)?,
            intrinsics()?,
            &points,
            fast(),
            &mut WorkBudget::new(100_000)
        ),
        Err(GeometryError::InvalidCorrespondence)
    ));
    points[1].physical_group = 2;
    points[1].world = points[0].world;
    assert!(matches!(
        estimate_camera_pose(
            GeometryBasis::new(1, 1)?,
            intrinsics()?,
            &points,
            fast(),
            &mut WorkBudget::new(100_000)
        ),
        Err(GeometryError::InvalidCorrespondence)
    ));
    Ok(())
}

#[test]
fn validation_is_held_out_and_retains_failed_residuals() -> TestResult {
    let basis = GeometryBasis::new(1, 1)?;
    let fit = controls(1, 24, 0.0);
    let search = estimate_camera_pose(
        basis,
        intrinsics()?,
        &fit,
        fast(),
        &mut WorkBudget::new(10_000_000),
    )?;
    assert_eq!(
        search.validate_candidate(0, basis, &fit[..4], 3.0, &mut WorkBudget::new(100_000)),
        Err(GeometryError::HoldoutLeak)
    );
    let mut held = controls(101, 8, 0.0);
    held[0].pixel[0] += 50.0;
    let report = search.validate_candidate(0, basis, &held, 3.0, &mut WorkBudget::new(100_000))?;
    assert!(!report.passed);
    assert_eq!(report.residuals.len(), 8);
    assert!(report.maximum_error_px.is_some_and(|error| error > 49.9));
    Ok(())
}

#[test]
fn holding_out_renamed_fitting_geometry_is_still_leakage() -> TestResult {
    let basis = GeometryBasis::new(1, 1)?;
    let fit = controls(1, 24, 0.0);
    let search = estimate_camera_pose(
        basis,
        intrinsics()?,
        &fit,
        fast(),
        &mut WorkBudget::new(10_000_000),
    )?;
    let mut held = controls(101, 8, 0.0);
    held[0].world = fit[0].world;
    assert_eq!(
        search.validate_candidate(0, basis, &held, 3.0, &mut WorkBudget::new(100_000)),
        Err(GeometryError::HoldoutLeak)
    );
    Ok(())
}

#[test]
fn validation_cannot_rebind_the_scene_revision() -> TestResult {
    let search = estimate_camera_pose(
        GeometryBasis::new(1, 1)?,
        intrinsics()?,
        &controls(1, 24, 0.0),
        fast(),
        &mut WorkBudget::new(10_000_000),
    )?;
    assert_eq!(
        search.validate_candidate(
            0,
            GeometryBasis::new(1, 2)?,
            &controls(101, 8, 0.0),
            3.0,
            &mut WorkBudget::new(100_000)
        ),
        Err(GeometryError::BasisMismatch)
    );
    Ok(())
}

#[test]
fn scaled_relative_worlds_preserve_projection_not_metric_certainty() -> TestResult {
    for factor in [0.01, 100.0] {
        let mut points = controls(1, 24, 0.0);
        for point in &mut points {
            for value in &mut point.world {
                *value *= factor;
            }
        }
        let search = estimate_camera_pose(
            GeometryBasis::new(1, 1)?,
            intrinsics()?,
            &points,
            fast(),
            &mut WorkBudget::new(10_000_000),
        )?;
        let center = search.candidates()[0].pose().center().map(|v| v / factor);
        assert!(distance(center, truth()?.center()) < 1e-5);
    }
    Ok(())
}

#[test]
fn ambiguous_match_sets_retain_both_camera_modes() -> TestResult {
    let mut points = controls(1, 20, 0.0);
    points.extend(controls(101, 20, 2.5));
    let options = PoseSolverOptions {
        ransac_trials: 512,
        minimum_inliers: 18,
        minimum_inlier_fraction: 0.45,
        ..PoseSolverOptions::default()
    };
    let search = estimate_camera_pose(
        GeometryBasis::new(1, 1)?,
        intrinsics()?,
        &points,
        options,
        &mut WorkBudget::new(1_000_000_000),
    )?;
    assert!(search.candidates().len() >= 2);
    Ok(())
}

#[test]
fn solver_budget_cancel_and_invalid_options_do_not_publish_a_pose() -> TestResult {
    let basis = GeometryBasis::new(1, 1)?;
    let points = controls(1, 24, 0.0);
    assert!(matches!(
        estimate_camera_pose(
            basis,
            intrinsics()?,
            &points,
            fast(),
            &mut WorkBudget::new(1)
        ),
        Err(GeometryError::BudgetExhausted)
    ));
    let flag = AtomicBool::new(true);
    assert!(matches!(
        estimate_camera_pose(
            basis,
            intrinsics()?,
            &points,
            fast(),
            &mut WorkBudget::cancellable(1_000_000, &flag)
        ),
        Err(GeometryError::Cancelled)
    ));
    let bad = PoseSolverOptions {
        inlier_threshold_px: f64::NAN,
        ..fast()
    };
    assert!(matches!(
        estimate_camera_pose(
            basis,
            intrinsics()?,
            &points,
            bad,
            &mut WorkBudget::new(100_000)
        ),
        Err(GeometryError::InvalidSolverOptions)
    ));
    Ok(())
}
