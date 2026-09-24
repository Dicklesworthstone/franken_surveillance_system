#![forbid(unsafe_code)]
//! Calibration monitor contract contract tests.
mod common;

use fss_geometry::{GeometryError, PinholeIntrinsics, RigidPose, WorkBudget};
use fss_twin::calibration_monitor::*;
use fss_twin::localization::*;
use std::error::Error;
use std::sync::atomic::AtomicBool;

type Test = Result<(), Box<dyn Error>>;

fn descriptor(id: u64) -> BinaryDescriptor {
    BinaryDescriptor([
        id.wrapping_mul(0x9e3779b97f4a7c15),
        !id,
        id.rotate_left(17),
        id.wrapping_mul(0xd6e8feb86659fd93),
    ])
}
fn camera() -> Result<LocalizationCamera, GeometryError> {
    Ok(LocalizationCamera {
        intrinsics: PinholeIntrinsics::new(640, 480, 500.0, 500.0, 320.0, 240.0)?,
        image_domain: [3; 32],
    })
}
fn pose() -> Result<RigidPose, GeometryError> {
    RigidPose::new(
        [[1.0, 0.0, 0.0], [0.0, 1.0, 0.0], [0.0, 0.0, 1.0]],
        [0.0, 0.0, 8.0],
    )
}
fn pixel(world: [f64; 3]) -> [f64; 2] {
    [
        500.0 * world[0] / (world[2] + 8.0) + 320.0,
        500.0 * world[1] / (world[2] + 8.0) + 240.0,
    ]
}
fn worlds() -> Vec<[f64; 3]> {
    let xs = [-2.0, -0.7, 0.7, 2.0];
    let ys = [-1.2, 0.0, 1.2];
    ys.into_iter()
        .flat_map(|y| xs.into_iter().map(move |x| [x, y, 0.0]))
        .collect()
}
fn frame(
    exposure: u8,
    shift: [f64; 2],
    take: usize,
    domain: [u8; 32],
    budget: &mut WorkBudget<'_>,
) -> Result<FeatureFrame, LocalizationError> {
    let features = worlds()
        .into_iter()
        .take(take)
        .enumerate()
        .map(|(i, w)| {
            let p = pixel(w);
            ImageFeature {
                id: i as u64 + 1,
                pixel: [p[0] + shift[0], p[1] + shift[1]],
                descriptor: descriptor(i as u64 + 1),
            }
        })
        .collect();
    FeatureFrame::new(
        ImageIdentity {
            exposure: [exposure; 32],
            pixels: [exposure.wrapping_add(10); 32],
            image_domain: domain,
            dimensions: [640, 480],
        },
        [9; 32],
        features,
        budget,
    )
}
fn atlas(
    twin: &fss_twin::PropertyTwin,
    budget: &mut WorkBudget<'_>,
) -> Result<LocalizationAtlas, Box<dyn Error>> {
    let reference = frame(1, [0.0, 0.0], 12, [3; 32], budget)?;
    let mut landmarks = Vec::new();
    let mut bindings = Vec::new();
    for (i, w) in worlds().into_iter().enumerate() {
        let id = i as u64 + 1;
        landmarks.push(AtlasLandmark {
            id,
            physical_group: id,
            feature: 0,
            world: w,
            evidence: [7; 32],
            error: None,
        });
        bindings.push(AtlasBinding {
            landmark: id,
            reference: 1,
            image_feature: id,
        });
    }
    Ok(LocalizationAtlas::new(
        twin,
        landmarks,
        vec![AtlasReference {
            id: 1,
            frame: reference,
        }],
        bindings,
        budget,
    )?)
}
fn frozen() -> Result<FrozenCalibration, GeometryError> {
    Ok(FrozenCalibration {
        id: [8; 32],
        camera: camera()?,
        pose: pose()?,
    })
}
fn matching() -> MatchOptions {
    MatchOptions {
        maximum_distance: 0,
        ratio_percent: 80,
    }
}

#[test]
fn stable_distributed_landmarks_keep_calibration_valid() -> Test {
    let twin = common::twin(&[0.0], None)?;
    let mut budget = WorkBudget::new(10_000_000);
    let atlas = atlas(&twin, &mut budget)?;
    let query = frame(2, [0.0, 0.0], 12, [3; 32], &mut budget)?;
    let report = monitor_calibration(
        &twin,
        &atlas,
        &query,
        frozen()?,
        matching(),
        CalibrationMonitorPolicy::default(),
        &mut budget,
    )?;
    assert_eq!(report.disposition, CalibrationDisposition::ValidUnderPolicy);
    assert_eq!(report.inliers, 12);
    assert_eq!(report.projected, 12);
    assert_eq!(report.rms_inlier_px, Some(0.0));
    assert!(report.image_span_fraction[0] > 0.3 && report.image_span_fraction[1] > 0.2);
    Ok(())
}

#[test]
fn distributed_pixel_shift_invalidates_without_refitting() -> Test {
    let twin = common::twin(&[0.0], None)?;
    let mut budget = WorkBudget::new(10_000_000);
    let atlas = atlas(&twin, &mut budget)?;
    let query = frame(2, [20.0, 0.0], 12, [3; 32], &mut budget)?;
    let report = monitor_calibration(
        &twin,
        &atlas,
        &query,
        frozen()?,
        matching(),
        CalibrationMonitorPolicy::default(),
        &mut budget,
    )?;
    assert_eq!(report.disposition, CalibrationDisposition::Invalidate);
    assert_eq!(report.inliers, 0);
    assert_eq!(report.projected, 12);
    assert!(
        report
            .residuals
            .iter()
            .all(|r| r.error_px.is_some_and(|e| e > 19.9))
    );
    Ok(())
}

#[test]
fn sparse_current_support_is_indeterminate_not_valid_or_invalid() -> Test {
    let twin = common::twin(&[0.0], None)?;
    let mut budget = WorkBudget::new(10_000_000);
    let atlas = atlas(&twin, &mut budget)?;
    let query = frame(2, [40.0, 0.0], 5, [3; 32], &mut budget)?;
    let report = monitor_calibration(
        &twin,
        &atlas,
        &query,
        frozen()?,
        matching(),
        CalibrationMonitorPolicy::default(),
        &mut budget,
    )?;
    assert_eq!(report.disposition, CalibrationDisposition::Indeterminate);
    assert_eq!(report.matches.correspondences.len(), 5);
    Ok(())
}

#[test]
fn reference_reuse_and_image_domain_rebinding_are_refused() -> Test {
    let twin = common::twin(&[0.0], None)?;
    let mut budget = WorkBudget::new(10_000_000);
    let atlas = atlas(&twin, &mut budget)?;
    let reused = frame(1, [0.0, 0.0], 12, [3; 32], &mut budget)?;
    assert!(matches!(
        monitor_calibration(
            &twin,
            &atlas,
            &reused,
            frozen()?,
            matching(),
            CalibrationMonitorPolicy::default(),
            &mut budget
        ),
        Err(CalibrationMonitorError::ReferenceExposure)
    ));
    let wrong = frame(2, [0.0, 0.0], 12, [4; 32], &mut budget)?;
    assert!(matches!(
        monitor_calibration(
            &twin,
            &atlas,
            &wrong,
            frozen()?,
            matching(),
            CalibrationMonitorPolicy::default(),
            &mut budget
        ),
        Err(CalibrationMonitorError::BasisMismatch)
    ));
    Ok(())
}

#[test]
fn cancellation_never_publishes_a_monitor_result() -> Test {
    let twin = common::twin(&[0.0], None)?;
    let mut budget = WorkBudget::new(10_000_000);
    let atlas = atlas(&twin, &mut budget)?;
    let query = frame(2, [0.0, 0.0], 12, [3; 32], &mut budget)?;
    let flag = AtomicBool::new(true);
    assert!(matches!(
        monitor_calibration(
            &twin,
            &atlas,
            &query,
            frozen()?,
            matching(),
            CalibrationMonitorPolicy::default(),
            &mut WorkBudget::cancellable(10_000_000, &flag)
        ),
        Err(CalibrationMonitorError::Geometry(GeometryError::Cancelled))
            | Err(CalibrationMonitorError::Localization(
                LocalizationError::Geometry(GeometryError::Cancelled)
            ))
    ));
    Ok(())
}
