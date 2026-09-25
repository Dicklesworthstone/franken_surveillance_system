#![forbid(unsafe_code)]
//! Geometric visibility: sampling, homography and pinhole frustum, mesh occlusion, typed causes,
//! canonical round trip and determinism (fss-2h5zq.53).

use fss_core::{CanonicalDecoder, CanonicalEncoder, ContentDigest};
use fss_geometry::{GeometryBasis, IndexedTriangle, MeshLimits, TriangleMesh, WorkBudget};

use super::*;

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

const DIMENSIONS: [u32; 2] = [96, 48];
/// Image→ground map of the downward camera below: `x = u`, `y = 48 - v`.
const DOWN: [f64; 9] = [1.0, 0.0, 0.0, 0.0, -1.0, 48.0, 0.0, 0.0, 1.0];

/// A camera 10 units above (48, 24) looking straight down, f = 10 px, principal point (48, 24):
/// it sees exactly the ground rectangle [0, 96) x (0, 48].
fn down_camera() -> TestResult<CameraPose> {
    Ok(CameraPose {
        intrinsics: PinholeIntrinsics::new(96, 48, 10.0, 10.0, 48.0, 24.0)?,
        pose: RigidPose::from_center(
            [[1.0, 0.0, 0.0], [0.0, -1.0, 0.0], [0.0, 0.0, -1.0]],
            [48.0, 24.0, 10.0],
        )?,
    })
}

/// A large opaque ground plane at z = 0 and, optionally, an opaque wall in the plane x = 52
/// (z 0..20) between the camera and every ground point with x > 52.
fn mesh(wall: bool) -> TestResult<TriangleMesh> {
    let mut vertices = vec![
        [-100.0, -100.0, 0.0],
        [200.0, -100.0, 0.0],
        [200.0, 200.0, 0.0],
        [-100.0, 200.0, 0.0],
    ];
    let mut triangles = vec![
        IndexedTriangle {
            vertices: [0, 1, 2],
            feature: 1,
            support: true,
            opaque: true,
        },
        IndexedTriangle {
            vertices: [0, 2, 3],
            feature: 1,
            support: true,
            opaque: true,
        },
    ];
    if wall {
        vertices.extend([
            [52.0, -10.0, 0.0],
            [52.0, 60.0, 0.0],
            [52.0, 60.0, 20.0],
            [52.0, -10.0, 20.0],
        ]);
        for corners in [[4, 5, 6], [4, 6, 7]] {
            triangles.push(IndexedTriangle {
                vertices: corners,
                feature: 2,
                support: false,
                opaque: true,
            });
        }
    }
    Ok(TriangleMesh::from_indexed(
        GeometryBasis::new(1, 1)?,
        &vertices,
        &triangles,
        MeshLimits::default(),
        &mut WorkBudget::new(1_000),
    )?)
}

fn scene(mesh: &TriangleMesh) -> SceneMesh<'_> {
    SceneMesh {
        mesh,
        package_digest: ContentDigest::sha256(b"owner scene mesh package"),
    }
}

#[test]
fn a_zone_fully_in_view_is_observable_and_without_a_mesh_is_frustum_only() -> TestResult {
    let door = rectangle(56.0, 0.0, 40.0, 48.0);
    let visibility = assess_ground_zone(
        VisibilityCamera::Homography(&DOWN),
        DIMENSIONS,
        &door,
        None,
        VisibilityPolicy::default(),
    )?;
    assert_eq!(visibility.samples, 64);
    assert_eq!(visibility.visible, 64);
    assert_eq!(visibility.visible_fraction_ppm(), 1_000_000);
    assert!(visibility.observable());
    assert_eq!(visibility.cause(), None);
    assert_eq!(visibility.camera_model, CameraModel::OwnerHomography);
    assert_eq!(
        visibility.occlusion,
        Occlusion::Unknown(OcclusionUnknownReason::NoSceneMesh)
    );
    assert!(visibility.frustum_only());
    assert_eq!(visibility.claim(), "frustum_only");
    let clause = visibility.predicate_clause();
    assert!(clause.contains("occlusion_unknown"), "{clause}");
    assert!(clause.contains("frustum-only"), "{clause}");
    assert!(clause.contains("grid-cell-centers:8x8"), "{clause}");

    // A mesh without a pose cannot place the camera: occlusion stays unknown, never clear.
    let ground = mesh(false)?;
    let homography_with_mesh = assess_ground_zone(
        VisibilityCamera::Homography(&DOWN),
        DIMENSIONS,
        &door,
        Some(scene(&ground)),
        VisibilityPolicy::default(),
    )?;
    assert_eq!(
        homography_with_mesh.occlusion,
        Occlusion::Unknown(OcclusionUnknownReason::NoCameraPose)
    );
    assert!(homography_with_mesh.frustum_only());
    Ok(())
}

#[test]
fn a_zone_outside_the_image_or_behind_the_horizon_is_outside_the_frustum() -> TestResult {
    let far = rectangle(200.0, 0.0, 40.0, 48.0);
    let visibility = assess_ground_zone(
        VisibilityCamera::Homography(&DOWN),
        DIMENSIONS,
        &far,
        None,
        VisibilityPolicy::default(),
    )?;
    assert_eq!(visibility.visible, 0);
    assert_eq!(visibility.outside_frustum, 64);
    assert!(!visibility.observable());
    assert_eq!(visibility.cause(), Some(NotVisibleCause::OutsideFrustum));

    // A perspective homography whose horizon cuts the ground: w = 1 - u / 48 <= 0 for u >= 48,
    // so ground points beyond it have no image preimage in front of the camera.
    let perspective = [1.0, 0.0, 0.0, 0.0, 1.0, 0.0, -1.0 / 48.0, 0.0, 1.0];
    let straddling = assess_ground_zone(
        VisibilityCamera::Homography(&perspective),
        DIMENSIONS,
        &rectangle(-400.0, 0.0, 380.0, 40.0),
        None,
        VisibilityPolicy::default(),
    )?;
    assert!(straddling.outside_frustum > 0);
    assert!(!straddling.observable());

    // Behind the calibrated camera (it looks down; the ground behind it projects outside).
    let pose = down_camera()?;
    let behind = assess_ground_zone(
        VisibilityCamera::Pose(&pose),
        DIMENSIONS,
        &far,
        None,
        VisibilityPolicy::default(),
    )?;
    assert_eq!(behind.visible, 0);
    assert_eq!(behind.cause(), Some(NotVisibleCause::OutsideFrustum));
    Ok(())
}

#[test]
fn a_zone_behind_a_mesh_wall_is_occluded_and_a_clear_one_is_mesh_checked() -> TestResult {
    let pose = down_camera()?;
    let door = rectangle(56.0, 0.0, 40.0, 48.0);
    let ground = mesh(false)?;
    let clear = assess_ground_zone(
        VisibilityCamera::Pose(&pose),
        DIMENSIONS,
        &door,
        Some(scene(&ground)),
        VisibilityPolicy::default(),
    )?;
    assert_eq!(
        clear.visible, 64,
        "the ground itself never occludes its samples"
    );
    assert_eq!(clear.occluded, 0);
    assert!(clear.observable());
    assert!(!clear.frustum_only());
    assert_eq!(clear.claim(), "frustum_and_mesh_occlusion");
    assert_eq!(
        clear.occlusion,
        Occlusion::MeshChecked(ContentDigest::sha256(b"owner scene mesh package"))
    );

    let walled = mesh(true)?;
    let hidden = assess_ground_zone(
        VisibilityCamera::Pose(&pose),
        DIMENSIONS,
        &door,
        Some(scene(&walled)),
        VisibilityPolicy::default(),
    )?;
    assert_eq!(hidden.visible, 0);
    assert_eq!(hidden.occluded, 64);
    assert!(!hidden.observable());
    assert_eq!(hidden.cause(), Some(NotVisibleCause::Occluded));

    // The wall only hides what lies behind it.
    let porch = assess_ground_zone(
        VisibilityCamera::Pose(&pose),
        DIMENSIONS,
        &rectangle(8.0, 8.0, 32.0, 32.0),
        Some(scene(&walled)),
        VisibilityPolicy::default(),
    )?;
    assert_eq!(porch.visible, porch.samples);

    // A zone straddling the wall: half visible. Below the default threshold it is not observable;
    // under a registered 400000 ppm threshold it is, with the fraction recorded.
    let straddle = rectangle(32.0, 8.0, 40.0, 32.0);
    let strict = assess_ground_zone(
        VisibilityCamera::Pose(&pose),
        DIMENSIONS,
        &straddle,
        Some(scene(&walled)),
        VisibilityPolicy::default(),
    )?;
    assert_eq!(strict.visible_fraction_ppm(), 500_000);
    assert!(!strict.observable());
    assert_eq!(strict.cause(), Some(NotVisibleCause::Occluded));
    let lenient = assess_ground_zone(
        VisibilityCamera::Pose(&pose),
        DIMENSIONS,
        &straddle,
        Some(scene(&walled)),
        VisibilityPolicy {
            grid: 8,
            threshold_ppm: 400_000,
        },
    )?;
    assert!(lenient.observable());
    assert_eq!(lenient.visible_fraction_ppm(), 500_000);
    Ok(())
}

#[test]
fn pose_and_homography_agreement_and_dimension_checks_are_enforced() -> TestResult {
    let pose = down_camera()?;
    let door = rectangle(56.0, 0.0, 40.0, 48.0);
    assert!(pose_matches_homography(
        &pose,
        &DOWN,
        &door,
        VisibilityPolicy::default()
    ));
    let identity = [1.0, 0.0, 0.0, 0.0, 1.0, 0.0, 0.0, 0.0, 1.0];
    assert!(!pose_matches_homography(
        &pose,
        &identity,
        &door,
        VisibilityPolicy::default()
    ));
    assert_eq!(
        assess_ground_zone(
            VisibilityCamera::Pose(&pose),
            [128, 48],
            &door,
            None,
            VisibilityPolicy::default(),
        ),
        Err(VisibilityError::PoseDimensions)
    );
    assert_eq!(
        VisibilityPolicy {
            grid: 1,
            threshold_ppm: 1
        }
        .validate(),
        Err(VisibilityError::InvalidPolicy)
    );
    assert_eq!(
        VisibilityPolicy {
            grid: 8,
            threshold_ppm: 0
        }
        .validate(),
        Err(VisibilityError::InvalidPolicy)
    );
    assert_eq!(
        ground_samples(&[(0.0, 0.0), (1.0, 1.0)], VisibilityPolicy::default()),
        Err(VisibilityError::InvalidZone)
    );
    Ok(())
}

#[test]
fn visibility_round_trips_canonically_and_is_deterministic() -> TestResult {
    let pose = down_camera()?;
    let walled = mesh(true)?;
    let door = rectangle(32.0, 8.0, 40.0, 32.0);
    let assess = || {
        assess_ground_zone(
            VisibilityCamera::Pose(&pose),
            DIMENSIONS,
            &door,
            Some(scene(&walled)),
            VisibilityPolicy::default(),
        )
    };
    let first = assess()?;
    assert_eq!(assess()?, first);
    for value in [
        first.clone(),
        assess_ground_zone(
            VisibilityCamera::Homography(&DOWN),
            DIMENSIONS,
            &door,
            None,
            VisibilityPolicy::default(),
        )?,
    ] {
        let mut e = CanonicalEncoder::new();
        value.encode(&mut e);
        let bytes = e.finish();
        let mut d = CanonicalDecoder::new(&bytes);
        assert_eq!(ZoneVisibility::decode(&mut d)?, value);
        d.ensure_finished()?;
    }
    // Inconsistent counts are refused on decode.
    let mut broken = first;
    broken.visible += 1;
    let mut e = CanonicalEncoder::new();
    broken.encode(&mut e);
    let bytes = e.finish();
    assert!(ZoneVisibility::decode(&mut CanonicalDecoder::new(&bytes)).is_err());
    // An unknown occlusion never counts an occluded sample.
    let mut unknown = assess_ground_zone(
        VisibilityCamera::Homography(&DOWN),
        DIMENSIONS,
        &door,
        None,
        VisibilityPolicy::default(),
    )?;
    unknown.visible -= 1;
    unknown.occluded += 1;
    assert!(unknown.validate().is_err());
    Ok(())
}
