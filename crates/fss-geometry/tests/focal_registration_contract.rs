#![forbid(unsafe_code)]
//! Focal-length registration contracts: candidate selection, validation, and unique-passing behavior.

use fss_geometry::{
    Correspondence, FocalSampleOutcome, FocalScanOptions, GeometryBasis, GeometryError,
    PoseSolverOptions, WorkBudget, scan_camera_focal_length,
};
use std::error::Error;
use std::sync::atomic::AtomicBool;

type Test = Result<(), Box<dyn Error>>;
fn points(start: u64, count: usize) -> Vec<Correspondence> {
    (0..count)
        .map(|i| {
            let id = start + i as u64;
            let n = id as f64;
            let world = [
                2.0 * (n * 0.7).sin(),
                1.5 * (n * 1.3).cos(),
                1.2 * (n * 0.31).sin(),
            ];
            let x = 0.8 * world[0] + 0.6 * world[2] + 0.3;
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
fn options() -> FocalScanOptions {
    FocalScanOptions {
        minimum_fx_px: 400.0,
        maximum_fx_px: 1600.0,
        y_over_x: 820.0 / 800.0,
        principal_point: [960.0, 540.0],
        samples: 33,
        pose: PoseSolverOptions {
            ransac_trials: 0,
            ..PoseSolverOptions::default()
        },
    }
}

#[test]
fn scan_preserves_all_samples_and_contains_true_focal_solution() -> Test {
    let scan = scan_camera_focal_length(
        GeometryBasis::new(1, 1)?,
        [1920, 1080],
        &points(1, 32),
        options(),
        &mut WorkBudget::new(500_000_000),
    )?;
    assert_eq!(scan.samples().len(), 33);
    assert!(scan.successful_samples() > 0);
    let midpoint = &scan.samples()[16];
    assert!((midpoint.intrinsics().focal_lengths()[0] - 800.0).abs() < 1e-9);
    let FocalSampleOutcome::Candidates(search) = midpoint.outcome() else {
        return Err("true focal sample failed".into());
    };
    assert_eq!(search.candidates()[0].inlier_landmarks().len(), 32);
    assert!(search.candidates()[0].rms_px() < 1e-5);
    assert!(scan.admissible_candidates(30, 0.01)?.contains(&(16, 0)));
    Ok(())
}

#[test]
fn excluded_landmarks_can_leave_a_unique_focal_pose_without_refitting() -> Test {
    let basis = GeometryBasis::new(1, 1)?;
    let scan = scan_camera_focal_length(
        basis,
        [1920, 1080],
        &points(1, 32),
        options(),
        &mut WorkBudget::new(500_000_000),
    )?;
    let validation = scan.validate_all_candidates(
        basis,
        &points(101, 12),
        0.01,
        &mut WorkBudget::new(100_000_000),
    )?;
    assert_eq!(validation.unique_passing_candidate(), Some((16, 0)));
    assert!(validation.reports().iter().any(|r| !r.validation.passed));
    Ok(())
}

#[test]
fn rejected_holdout_has_no_unique_focal_candidate() -> Test {
    let basis = GeometryBasis::new(1, 1)?;
    let scan = scan_camera_focal_length(
        basis,
        [1920, 1080],
        &points(1, 32),
        options(),
        &mut WorkBudget::new(500_000_000),
    )?;
    let mut holdout = points(101, 12);
    for point in &mut holdout {
        point.pixel[0] += 300.0;
    }
    let validation =
        scan.validate_all_candidates(basis, &holdout, 0.01, &mut WorkBudget::new(100_000_000))?;
    assert!(!validation.reports().is_empty());
    assert!(validation.passing_candidates().is_empty());
    assert_eq!(validation.unique_passing_candidate(), None);
    Ok(())
}

#[test]
fn ambiguous_holdout_has_no_unique_focal_candidate() -> Test {
    let basis = GeometryBasis::new(1, 1)?;
    let scan = scan_camera_focal_length(
        basis,
        [1920, 1080],
        &points(1, 32),
        options(),
        &mut WorkBudget::new(500_000_000),
    )?;
    let validation = scan.validate_all_candidates(
        basis,
        &points(101, 12),
        128.0,
        &mut WorkBudget::new(100_000_000),
    )?;
    assert!(validation.passing_candidates().len() > 1);
    assert_eq!(validation.unique_passing_candidate(), None);
    Ok(())
}

#[test]
fn scan_does_not_silently_select_or_drop_geometric_failures() -> Test {
    let mut opt = options();
    opt.samples = 9;
    let scan = scan_camera_focal_length(
        GeometryBasis::new(1, 1)?,
        [1920, 1080],
        &points(1, 32),
        opt,
        &mut WorkBudget::new(200_000_000),
    )?;
    assert_eq!(scan.samples().len(), 9);
    for sample in scan.samples() {
        match sample.outcome() {
            FocalSampleOutcome::Candidates(search) => assert!(!search.candidates().is_empty()),
            FocalSampleOutcome::GeometricFailure(error) => assert!(!matches!(
                error,
                GeometryError::Cancelled
                    | GeometryError::BudgetExhausted
                    | GeometryError::LimitExceeded
            )),
        }
    }
    Ok(())
}

#[test]
fn invalid_family_and_control_failures_refuse_partial_scans() -> Test {
    let mut bad = options();
    bad.samples = 2;
    assert!(matches!(
        scan_camera_focal_length(
            GeometryBasis::new(1, 1)?,
            [1920, 1080],
            &points(1, 32),
            bad,
            &mut WorkBudget::new(100_000)
        ),
        Err(GeometryError::InvalidSolverOptions)
    ));
    let flag = AtomicBool::new(true);
    assert!(matches!(
        scan_camera_focal_length(
            GeometryBasis::new(1, 1)?,
            [1920, 1080],
            &points(1, 32),
            options(),
            &mut WorkBudget::cancellable(500_000_000, &flag)
        ),
        Err(GeometryError::Cancelled)
    ));
    assert!(matches!(
        scan_camera_focal_length(
            GeometryBasis::new(1, 1)?,
            [1920, 1080],
            &points(1, 32),
            options(),
            &mut WorkBudget::new(1)
        ),
        Err(GeometryError::BudgetExhausted)
    ));
    Ok(())
}
