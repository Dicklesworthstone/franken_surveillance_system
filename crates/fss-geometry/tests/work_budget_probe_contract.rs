#![forbid(unsafe_code)]
//! Owner cancellation remains observable inside a native solve without a timer thread.

use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use fss_geometry::triangulation::{
    CalibratedView, TriangulationError, TriangulationOptions, triangulate,
};
use fss_geometry::{GeometryError, PinholeIntrinsics, RigidPose, WorkBudget};

type Test = Result<(), Box<dyn std::error::Error>>;

#[test]
fn caller_probe_cancels_before_charging_and_preserves_consumed_work() -> Test {
    let cancelled = AtomicBool::new(false);
    let probe = || cancelled.load(Ordering::Acquire);
    let mut budget = WorkBudget::with_cancellation_probe(100, &probe);
    budget.charge(25)?;
    cancelled.store(true, Ordering::Release);
    assert_eq!(budget.charge(0), Err(GeometryError::Cancelled));
    assert_eq!(budget.charge(75), Err(GeometryError::Cancelled));
    assert_eq!(budget.used(), 25);
    assert_eq!(budget.remaining(), 75);
    Ok(())
}

#[test]
fn an_owner_can_interrupt_a_native_triangulation_mid_solve() -> Test {
    let intrinsics = PinholeIntrinsics::new(640, 480, 400.0, 400.0, 320.0, 240.0)?;
    let rotation = [[1.0, 0.0, 0.0], [0.0, 1.0, 0.0], [0.0, 0.0, 1.0]];
    let mut views = Vec::new();
    for (index, center) in [[-2.0, 0.0, 0.0], [2.0, 0.0, 0.0], [0.0, 2.0, 0.0]]
        .into_iter()
        .enumerate()
    {
        let pose = RigidPose::from_center(rotation, center)?;
        views.push(CalibratedView {
            camera: index as u64 + 1,
            pose,
            intrinsics,
            pixel: pose.project(intrinsics, [0.0, 0.0, 6.0])?,
            sigma_pixels: 0.5,
        });
    }
    let complete = triangulate(
        &views,
        TriangulationOptions::default(),
        &mut WorkBudget::new(1_000_000),
    )?;
    assert!(complete.rms_reprojection_pixels < 1e-8);
    let checks = AtomicUsize::new(0);
    let probe = || checks.fetch_add(1, Ordering::Relaxed) >= 4;
    let mut budget = WorkBudget::with_cancellation_probe(1_000_000, &probe);
    assert!(matches!(
        triangulate(&views, TriangulationOptions::default(), &mut budget),
        Err(TriangulationError::Geometry(GeometryError::Cancelled))
    ));
    assert_eq!(checks.load(Ordering::Relaxed), 5);
    assert!(budget.used() > 0);
    assert!(budget.remaining() > 0);
    Ok(())
}

#[test]
fn observation_probe_preserves_send_and_sync_budget_contract() {
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<WorkBudget<'_>>();
}
