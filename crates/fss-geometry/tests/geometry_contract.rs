#![forbid(unsafe_code)]

use std::sync::atomic::AtomicBool;
use fss_geometry::{GeometryBasis, GeometryError, IndexedTriangle, MeshLimits,
    PinholeIntrinsics, Ray, RigidPose, TriangleMesh, WorkBudget};

type TestResult = Result<(), Box<dyn std::error::Error>>;

fn close(a: f64, b: f64) { assert!((a - b).abs() < 1e-8, "{a} != {b}"); }
fn triangle(feature: u64, z_offset: u32) -> IndexedTriangle {
    IndexedTriangle { vertices: [z_offset, z_offset + 1, z_offset + 2], feature, support: true, opaque: true }
}
fn layers() -> Result<TriangleMesh, GeometryError> {
    TriangleMesh::from_indexed(GeometryBasis::new(1, 1)?,
        &[[-10.0, -10.0, 0.0], [10.0, -10.0, 0.0], [0.0, 10.0, 0.0],
          [-10.0, -10.0, 1.0], [10.0, -10.0, 1.0], [0.0, 10.0, 1.0]],
        &[triangle(1, 0), triangle(2, 3)], MeshLimits::default(), &mut WorkBudget::new(100))
}

#[test]
fn independent_axis_and_center_controls() -> TestResult {
    let k = PinholeIntrinsics::new(640, 720, 500.0, 500.0, 320.0, 240.0)?;
    let pose = RigidPose::new([[1.0, 0.0, 0.0], [0.0, 0.0, -1.0], [0.0, 1.0, 0.0]], [0.0, 3.0, 5.0])?;
    assert_eq!(pose.center(), [0.0, -5.0, 3.0]);
    assert_eq!(pose.project(k, [0.0, 0.0, 3.0])?, [320.0, 240.0]);
    assert_eq!(pose.project(k, [1.0, 0.0, 3.0])?, [420.0, 240.0]);
    assert_eq!(pose.project(k, [0.0, 0.0, 4.0])?, [320.0, 140.0]);
    assert_eq!(pose.project(k, [0.0, 0.0, 0.0])?, [320.0, 540.0]);
    let hit = pose.ray(k, [320.0, 540.0])?.at(34.0_f64.sqrt())?;
    for value in hit { close(value, 0.0); }
    Ok(())
}

#[test]
fn identity_is_valid_but_reflections_are_not() -> TestResult {
    let identity = RigidPose::new([[1.0, 0.0, 0.0], [0.0, 1.0, 0.0], [0.0, 0.0, 1.0]], [0.0; 3])?;
    assert_eq!(identity, RigidPose::IDENTITY);
    assert!(matches!(RigidPose::new([[1.0, 0.0, 0.0], [0.0, 1.0, 0.0], [0.0, 0.0, -1.0]], [0.0; 3]),
        Err(GeometryError::InvalidRotation)));
    assert!(RigidPose::new([[1.0, 0.1, 0.0], [0.0, 1.0, 0.0], [0.0, 0.0, 1.0]], [0.0; 3]).is_err());
    Ok(())
}

#[test]
fn camera_domain_and_positive_depth_are_explicit() -> TestResult {
    let k = PinholeIntrinsics::new(640, 480, 500.0, 500.0, 320.0, 240.0)?;
    assert!(k.contains([0.5, 0.5]));
    assert!(!k.contains([640.0, 240.0]));
    assert!(!k.contains([f64::NAN, 0.0]));
    assert_eq!(k.project([0.0, 0.0, -1.0]), Err(GeometryError::BehindCamera));
    assert_eq!(k.project([0.0; 3]), Err(GeometryError::BehindCamera));
    assert_eq!(k.bearing([640.0, 10.0]), Err(GeometryError::OutOfImage));
    assert!(!k.contains(k.project([100.0, 0.0, 1.0])?));
    assert!(PinholeIntrinsics::new(640, 480, -1.0, 500.0, 320.0, 240.0).is_err());
    assert!(PinholeIntrinsics::new(640, 480, f64::NAN, 500.0, 320.0, 240.0).is_err());
    Ok(())
}

#[test]
fn ray_parameter_is_world_distance() -> TestResult {
    let ray = Ray::new([1.0, 2.0, 3.0], [0.0, 0.0, -20.0])?;
    assert_eq!(ray.at(2.0)?, [1.0, 2.0, 1.0]);
    assert!(ray.at(-1.0).is_err());
    assert!(Ray::new([0.0; 3], [0.0; 3]).is_err());
    assert!(Ray::new([0.0; 3], [f64::INFINITY, 0.0, 0.0]).is_err());
    Ok(())
}

#[test]
fn support_layers_are_not_collapsed_to_nearest_ground() -> TestResult {
    let mesh = layers()?;
    let ray = Ray::new([0.0, 0.0, 3.0], [0.0, 0.0, -1.0])?;
    let hits = mesh.support_hits(mesh.basis(), ray, 0.0, 5.0, 4, &mut WorkBudget::new(100))?;
    assert_eq!(hits.len(), 2);
    assert_eq!((hits[0].feature, hits[1].feature), (2, 1));
    assert_eq!((hits[0].distance, hits[1].distance), (2.0, 3.0));
    assert_eq!(hits[0].point, [0.0, 0.0, 1.0]);
    close(hits[0].barycentric.iter().sum(), 1.0);
    Ok(())
}

#[test]
fn support_output_overflow_does_not_publish_a_partial_set() -> TestResult {
    let mesh = layers()?;
    let ray = Ray::new([0.0, 0.0, 3.0], [0.0, 0.0, -1.0])?;
    assert!(matches!(mesh.support_hits(mesh.basis(), ray, 0.0, 5.0, 1, &mut WorkBudget::new(100)),
        Err(GeometryError::LimitExceeded)));
    Ok(())
}

#[test]
fn wrong_revision_and_other_property_are_rejected() -> TestResult {
    let mesh = layers()?;
    let ray = Ray::new([0.0, 0.0, 3.0], [0.0, 0.0, -1.0])?;
    for basis in [GeometryBasis::new(1, 2)?, GeometryBasis::new(2, 1)?] {
        assert!(matches!(mesh.support_hits(basis, ray, 0.0, 5.0, 4, &mut WorkBudget::new(100)),
            Err(GeometryError::BasisMismatch)));
    }
    Ok(())
}

#[test]
fn opaque_occlusion_excludes_endpoint_self_intersections() -> TestResult {
    let mesh = layers()?;
    assert!(mesh.segment_occluded(mesh.basis(), [0.0, 0.0, 3.0], [0.0, 0.0, 0.0],
        1e-6, &mut WorkBudget::new(100))?);
    assert!(!mesh.segment_occluded(mesh.basis(), [0.0, 0.0, 3.0], [0.0, 0.0, 1.0],
        1e-6, &mut WorkBudget::new(100))?);
    Ok(())
}

#[test]
fn support_and_opacity_are_independent_roles() -> TestResult {
    let mut tri = triangle(1, 0);
    tri.opaque = false;
    let mesh = TriangleMesh::from_indexed(GeometryBasis::new(1, 1)?,
        &[[-1.0, -1.0, 0.0], [1.0, -1.0, 0.0], [0.0, 1.0, 0.0]], &[tri],
        MeshLimits::default(), &mut WorkBudget::new(100))?;
    assert!(!mesh.segment_occluded(mesh.basis(), [0.0, 0.0, 1.0], [0.0, 0.0, -1.0],
        1e-6, &mut WorkBudget::new(100))?);
    let hits = mesh.support_hits(mesh.basis(), Ray::new([0.0, 0.0, 1.0], [0.0, 0.0, -1.0])?,
        0.0, 3.0, 4, &mut WorkBudget::new(100))?;
    assert_eq!(hits.len(), 1);
    Ok(())
}

#[test]
fn bad_indices_degenerate_geometry_and_nan_fail_import() -> TestResult {
    let basis = GeometryBasis::new(1, 1)?;
    let vertices = [[0.0, 0.0, 0.0], [1.0, 0.0, 0.0], [0.0, 1.0, 0.0]];
    let mut tri = triangle(1, 0);
    tri.vertices[2] = 9;
    assert!(matches!(TriangleMesh::from_indexed(basis, &vertices, &[tri], MeshLimits::default(),
        &mut WorkBudget::new(100)), Err(GeometryError::InvalidIndex)));
    tri.vertices[2] = 1;
    assert!(matches!(TriangleMesh::from_indexed(basis, &vertices, &[tri], MeshLimits::default(),
        &mut WorkBudget::new(100)), Err(GeometryError::Degenerate)));
    let mut bad = vertices;
    bad[0][0] = f64::NAN;
    assert!(matches!(TriangleMesh::from_indexed(basis, &bad, &[triangle(1, 0)], MeshLimits::default(),
        &mut WorkBudget::new(100)), Err(GeometryError::NonFinite)));
    Ok(())
}

#[test]
fn budgets_and_owner_cancellation_are_fail_closed() -> TestResult {
    let mesh = layers()?;
    let ray = Ray::new([0.0, 0.0, 3.0], [0.0, 0.0, -1.0])?;
    let mut budget = WorkBudget::new(1);
    assert!(matches!(mesh.support_hits(mesh.basis(), ray, 0.0, 5.0, 4, &mut budget),
        Err(GeometryError::BudgetExhausted)));
    assert_eq!(budget.used(), 1);
    let cancelled = AtomicBool::new(true);
    let mut budget = WorkBudget::cancellable(100, &cancelled);
    assert!(matches!(mesh.support_hits(mesh.basis(), ray, 0.0, 5.0, 4, &mut budget),
        Err(GeometryError::Cancelled)));
    assert_eq!(budget.used(), 0);
    Ok(())
}

#[test]
fn parallel_rays_miss_and_winding_is_double_sided() -> TestResult {
    let mesh = layers()?;
    for direction in [[1.0, 0.0, 0.0], [0.0, 1.0, 0.0]] {
        assert!(mesh.support_hits(mesh.basis(), Ray::new([0.0, 0.0, 3.0], direction)?,
            0.0, 5.0, 4, &mut WorkBudget::new(100))?.is_empty());
    }
    assert_eq!(mesh.support_hits(mesh.basis(), Ray::new([0.0, 0.0, -1.0], [0.0, 0.0, 1.0])?,
        0.0, 5.0, 4, &mut WorkBudget::new(100))?.len(), 2);
    Ok(())
}
