#![forbid(unsafe_code)]
//! Synthetic, supplied-correspondence camera registration followed by ground projection.

use fss_geometry::{
    Correspondence, GeometryBasis, IndexedTriangle, MeshLimits, PinholeIntrinsics,
    PoseSolverOptions, TriangleMesh, WorkBudget, estimate_camera_pose,
};

fn controls(start: u64, count: usize) -> Vec<Correspondence> {
    (0..count)
        .map(|i| {
            let id = start + i as u64;
            let n = id as f64;
            let world = [
                4.0 + 2.0 * (n * 0.7).sin(),
                2.0 + 2.0 * (n * 1.3).cos(),
                2.0 + 1.5 * (n * 0.31).sin(),
            ];
            // Independent truth: optical center [4,-8,5], forward [0,0.8,-0.6].
            let x = world[0] - 4.0;
            let y = -0.6 * world[1] - 0.8 * world[2] - 0.8;
            let z = 0.8 * world[1] - 0.6 * world[2] + 9.4;
            Correspondence {
                landmark: id,
                physical_group: id,
                world,
                pixel: [800.0 * x / z + 960.0, 820.0 * y / z + 540.0],
            }
        })
        .collect()
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let basis = GeometryBasis::new(1, 1)?;
    let intrinsics = PinholeIntrinsics::new(1920, 1080, 800.0, 820.0, 960.0, 540.0)?;
    let mut budget = WorkBudget::new(10_000_000);
    let search = estimate_camera_pose(
        basis,
        intrinsics,
        &controls(1, 24),
        PoseSolverOptions {
            ransac_trials: 0,
            ..PoseSolverOptions::default()
        },
        &mut budget,
    )?;
    let candidate = search.candidates().first().ok_or("no camera candidate")?;
    let validation = search.validate_candidate(0, basis, &controls(101, 12), 0.01, &mut budget)?;
    if !validation.passed {
        return Err("independent landmark check failed".into());
    }
    let mesh = TriangleMesh::from_indexed(
        basis,
        &[[-20.0, -20.0, 0.0], [20.0, -20.0, 0.0], [0.0, 20.0, 0.0]],
        &[IndexedTriangle {
            vertices: [0, 1, 2],
            feature: 1,
            support: true,
            opaque: true,
        }],
        MeshLimits::default(),
        &mut budget,
    )?;
    // Pixel independently projected from physical fixture point [4,2,0].
    let ray = candidate
        .pose()
        .ray(intrinsics, [960.0, 540.0 - 820.0 * 2.0 / 11.0])?;
    let hits = mesh.support_hits(basis, ray, 0.0, 100.0, 4, &mut budget)?;
    let hit = hits.first().ok_or("fixture ground not intersected")?;
    println!(
        "{{\"scenario\":\"synthetic_camera_registration\",\"camera_center\":{:?},\"rotation\":{:?},\"translation\":{:?},\"inliers\":{},\"fit_rms_px\":{},\"holdout_passed\":{},\"ground_hit\":{:?},\"work_units\":{},\"physical_accuracy_qualified\":false}}",
        candidate.pose().center(),
        candidate.pose().rotation(),
        candidate.pose().translation(),
        candidate.inlier_landmarks().len(),
        candidate.rms_px(),
        validation.passed,
        hit.point,
        budget.used()
    );
    Ok(())
}
