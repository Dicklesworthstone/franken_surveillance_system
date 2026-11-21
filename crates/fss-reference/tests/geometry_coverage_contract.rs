#![forbid(unsafe_code)]
//! Integration contract tests for geometric ground-zone visibility and coverage (fss-2h5zq.54).
//!
//! Verifies:
//! - Hand-derived occlusion scenes: open yard (all visible), opaque wall (half occluded,
//!   fully occluded, and clear zones across two cameras), and camera facing away
//!   (`outside_frustum`) plus frustum-only (`occlusion_unknown`) homography honesty.
//! - Metamorphic invariants: rigid world transform (mesh + cameras + zones/samples) preserves
//!   visibility classes and per-sample occlusion decisions; translating an occluder out of the
//!   line of sight reveals previously occluded samples and updates mesh/basis digests cleanly.
//! - Resource budget exhaustion and cooperative cancellation (pre-cancelled and mid-run probe)
//!   across both single-zone visibility and pose-sensitivity passes.
//! - Canonical encoding round-trip, `CoverageWitness` integration, and deterministic basis-digest
//!   stability & perturbation sensitivity.
//!
//! Emits one structured `CAPLOG` record per contract check (`caplog_support::Record`) logging
//! per-camera, per-zone visible fractions (ppm), states, and basis digests.

use std::collections::BTreeSet;
use std::error::Error;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::Instant;

use fss_core::{
    CanonicalDecode, CanonicalDecoder, CanonicalEncode, CanonicalEncoder, Completeness,
    ContentDigest, CoverageContinuity, CoverageStopReason, CoverageWitness, LedgerAnchor,
};
use fss_geometry::{
    BodySamples, CameraAvailability, CaptureSchedule, ForecastBasis, GeometryBasis, GeometryError,
    HandoffCamera, HandoffOptions, IndexedTriangle, MeshLimits, NanosecondInterval,
    NextCameraOutcome, PinholeIntrinsics, RigidPose, RouteBody, RouteCandidate, RouteEnd,
    RoutePriors, RouteSurface, TriangleMesh, WorkBudget, forecast_routes, predict_camera_handoffs,
};
use fss_reference::ingest::ground_visibility::{
    CameraModel, CameraPose, NotVisibleCause, OCCLUSION_MARGIN_RATIO, Occlusion,
    OcclusionUnknownReason, PoseCovariance, PoseRobustnessClass, SceneMesh, VISIBILITY_POLICY,
    VisibilityCamera, VisibilityError, VisibilityPolicy, ZoneVisibility, assess_ground_zone,
    assess_ground_zone_masked, assess_ground_zone_with_budget, assess_pose_robustness,
    bind_visibility_parameters, ground_samples, import_scene_mesh, rectangle,
};

mod caplog_support;
use caplog_support::{RawJson, Record, json_string};

type TestResult<T = ()> = Result<T, Box<dyn Error>>;

const DIMENSIONS: [u32; 2] = [96, 48];
/// Owner image->ground homography matching `down_camera`: `x = u`, `y = 48 - v`.
const DOWN_HOMOGRAPHY: [f64; 9] = [1.0, 0.0, 0.0, 0.0, -1.0, 48.0, 0.0, 0.0, 1.0];

/// Camera 10 units above `(48, 24)` looking straight down (`f = 10 px`, principal point `(48, 24)`).
/// Sees the ground rectangle `[0, 96) x (0, 48]` exactly.
fn down_camera() -> TestResult<CameraPose> {
    Ok(CameraPose {
        intrinsics: PinholeIntrinsics::new(96, 48, 10.0, 10.0, 48.0, 24.0)?,
        pose: RigidPose::from_center(
            [[1.0, 0.0, 0.0], [0.0, -1.0, 0.0], [0.0, 0.0, -1.0]],
            [48.0, 24.0, 10.0],
        )?,
    })
}

/// Companion camera on the east side `(76, 24, 10)` looking straight down across `[28, 124) x (0, 48]`.
fn east_camera() -> TestResult<CameraPose> {
    Ok(CameraPose {
        intrinsics: PinholeIntrinsics::new(96, 48, 10.0, 10.0, 48.0, 24.0)?,
        pose: RigidPose::from_center(
            [[1.0, 0.0, 0.0], [0.0, -1.0, 0.0], [0.0, 0.0, -1.0]],
            [76.0, 24.0, 10.0],
        )?,
    })
}

/// Camera at `(48, 24, 10)` rotated 180 degrees around X so its optical axis points straight UP
/// (`+z`), away from the ground plane `z = 0`.
fn away_camera() -> TestResult<CameraPose> {
    Ok(CameraPose {
        intrinsics: PinholeIntrinsics::new(96, 48, 10.0, 10.0, 48.0, 24.0)?,
        pose: RigidPose::from_center(
            [[1.0, 0.0, 0.0], [0.0, 1.0, 0.0], [0.0, 0.0, 1.0]],
            [48.0, 24.0, 10.0],
        )?,
    })
}

fn state_label(v: &ZoneVisibility) -> &'static str {
    match v.cause() {
        None => "visible",
        Some(NotVisibleCause::Occluded) => "occluded",
        Some(NotVisibleCause::OutsideFrustum) => "outside_frustum",
        Some(NotVisibleCause::PrivacyMasked) => "privacy_masked",
    }
}

/// Deterministic basis digest computed from `bind_visibility_parameters`.
fn visibility_basis_digest(
    policy: VisibilityPolicy,
    pose: Option<&CameraPose>,
    mesh: Option<ContentDigest>,
) -> ContentDigest {
    let mut params = Vec::new();
    bind_visibility_parameters(&mut params, policy, pose, mesh);
    let mut encoder = CanonicalEncoder::new();
    encoder.text(VISIBILITY_POLICY);
    encoder.u64(params.len() as u64);
    for word in params {
        encoder.u64(word);
    }
    ContentDigest::sha256(&encoder.finish())
}

fn wire_text(out: &mut Vec<u8>, value: &str) -> TestResult {
    let len = u16::try_from(value.len())?;
    out.extend_from_slice(&len.to_le_bytes());
    out.extend_from_slice(value.as_bytes());
    Ok(())
}

fn wire_count(out: &mut Vec<u8>, value: usize) -> TestResult {
    let count = u32::try_from(value)?;
    out.extend_from_slice(&count.to_le_bytes());
    Ok(())
}

/// Builds a first-party `FSSTWIN1` package with an opaque ground plane `[-100, 200]^2` at `z = 0`
/// and an optional vertical opaque wall along `x = wall_x`, `y in [-10, 60]`, `z in [0, 20]`.
fn build_twin_package(wall_x: Option<f64>) -> TestResult<(Vec<u8>, ContentDigest, ContentDigest)> {
    let mut vertices = vec![
        [-100.0_f64, -100.0, 0.0],
        [200.0, -100.0, 0.0],
        [200.0, 200.0, 0.0],
        [-100.0, 200.0, 0.0],
    ];
    let mut triangles: Vec<[u32; 4]> = vec![[0, 1, 2, 0], [0, 2, 3, 0]];
    let mut features: Vec<(&str, u8)> = vec![("ground", 2)];
    let mut objects: Vec<(&str, u32, u8, u8)> = vec![("ground", 0, 1, 1)];
    if let Some(wx) = wall_x {
        vertices.extend([
            [wx, -10.0, 0.0],
            [wx, 60.0, 0.0],
            [wx, 60.0, 20.0],
            [wx, -10.0, 20.0],
        ]);
        triangles.push([4, 5, 6, 1]);
        triangles.push([4, 6, 7, 1]);
        features.push(("wall", 5));
        objects.push(("wall", 1, 0, 1));
    }

    let mut source_enc = CanonicalEncoder::new();
    source_enc.text("geometry-coverage-contract-scene");
    source_enc.bool(wall_x.is_some());
    if let Some(wx) = wall_x {
        source_enc.u64(wx.to_bits());
    }
    let source_scene_digest = ContentDigest::sha256(&source_enc.finish());

    let mut body = source_scene_digest.bytes().to_vec();
    wire_text(&mut body, "fss-contract/yard/Z-up")?;
    wire_text(&mut body, "synthetic")?;
    body.push(0); // relative scale
    for value in [0.0_f64, -1.0, -1.0] {
        body.extend_from_slice(&value.to_le_bytes());
    }
    wire_count(&mut body, features.len())?;
    wire_count(&mut body, objects.len())?;
    wire_count(&mut body, vertices.len())?;
    wire_count(&mut body, triangles.len())?;
    for (id, surface) in features {
        wire_text(&mut body, id)?;
        body.push(surface);
    }
    for (id, feature, support, opaque) in objects {
        wire_text(&mut body, id)?;
        body.extend_from_slice(&feature.to_le_bytes());
        body.extend_from_slice(&[support, opaque]);
    }
    for v in &vertices {
        for coord in v {
            body.extend_from_slice(&coord.to_le_bytes());
        }
    }
    for tri in &triangles {
        for idx in tri {
            body.extend_from_slice(&idx.to_le_bytes());
        }
    }

    let mut package = b"FSSTWIN1".to_vec();
    package.extend_from_slice(&(body.len() as u64).to_le_bytes());
    package.extend_from_slice(&body);
    let trailer = ContentDigest::sha256(&package).bytes();
    package.extend_from_slice(&trailer);
    let package_digest = ContentDigest::sha256(&package);
    Ok((package, package_digest, source_scene_digest))
}

fn transform_point_z(p: [f64; 3], cos: f64, sin: f64, tx: f64, ty: f64) -> [f64; 3] {
    [
        cos * p[0] - sin * p[1] + tx,
        sin * p[0] + cos * p[1] + ty,
        p[2],
    ]
}

fn transform_pose_z(
    pose: &CameraPose,
    cos: f64,
    sin: f64,
    tx: f64,
    ty: f64,
) -> TestResult<CameraPose> {
    // R_w = [[cos, -sin, 0], [sin, cos, 0], [0, 0, 1]], so R_w^T = [[cos, sin, 0], [-sin, cos, 0], [0, 0, 1]].
    let rw_t = [[cos, sin, 0.0], [-sin, cos, 0.0], [0.0, 0.0, 1.0]];
    let r = pose.pose.rotation();
    let mut r_prime = [[0.0_f64; 3]; 3];
    for i in 0..3 {
        for j in 0..3 {
            r_prime[i][j] = r[i][0] * rw_t[0][j] + r[i][1] * rw_t[1][j] + r[i][2] * rw_t[2][j];
        }
    }
    let c_prime = transform_point_z(pose.pose.center(), cos, sin, tx, ty);
    Ok(CameraPose {
        intrinsics: pose.intrinsics,
        pose: RigidPose::from_center(r_prime, c_prime)?,
    })
}

fn build_transformed_mesh(
    wall_x: Option<f64>,
    cos: f64,
    sin: f64,
    tx: f64,
    ty: f64,
) -> TestResult<TriangleMesh> {
    let mut raw_vertices = vec![
        [-100.0_f64, -100.0, 0.0],
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
    if let Some(wx) = wall_x {
        raw_vertices.extend([
            [wx, -10.0, 0.0],
            [wx, 60.0, 0.0],
            [wx, 60.0, 20.0],
            [wx, -10.0, 20.0],
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
    let vertices: Vec<[f64; 3]> = raw_vertices
        .into_iter()
        .map(|v| transform_point_z(v, cos, sin, tx, ty))
        .collect();
    Ok(TriangleMesh::from_indexed(
        GeometryBasis::new(1, 1)?,
        &vertices,
        &triangles,
        MeshLimits::default(),
        &mut WorkBudget::new(10_000),
    )?)
}

fn zone_entry_json(camera: &str, zone: &str, v: &ZoneVisibility) -> String {
    format!(
        "{{\"camera\":{},\"zone\":{},\"state\":{},\"visible_fraction_ppm\":{},\"samples\":{},\"visible\":{},\"occluded\":{},\"outside_frustum\":{},\"claim\":{}}}",
        json_string(camera),
        json_string(zone),
        json_string(state_label(v)),
        v.visible_fraction_ppm(),
        v.samples,
        v.visible,
        v.occluded,
        v.outside_frustum,
        json_string(v.claim()),
    )
}

#[test]
fn scene_open_yard_all_visible() -> TestResult {
    let start = Instant::now();
    let policy = VisibilityPolicy::default();
    let cam = down_camera()?;
    let (pkg, mesh_digest, source_digest) = build_twin_package(None)?;
    let twin = import_scene_mesh(&pkg, mesh_digest, source_digest)?;
    let scene = SceneMesh {
        mesh: twin.mesh(),
        package_digest: mesh_digest,
    };

    let yard = rectangle(8.0, 8.0, 80.0, 32.0);
    let vis = assess_ground_zone(
        VisibilityCamera::Pose(&cam),
        DIMENSIONS,
        &yard,
        Some(scene),
        policy,
    )?;
    let basis = visibility_basis_digest(policy, Some(&cam), Some(mesh_digest));

    let authorized: BTreeSet<String> = ["ground-zone:open-yard".to_owned()].into_iter().collect();
    let observed: BTreeSet<String> = if vis.observable() {
        authorized.clone()
    } else {
        BTreeSet::new()
    };
    let witness = CoverageWitness {
        anchor: LedgerAnchor::genesis("site:geo-contract"),
        authorized_domain: authorized,
        observed_domain: observed,
        excluded_domain: BTreeSet::new(),
        continuity: CoverageContinuity::Continuous,
        completeness: Completeness::Complete,
        negative_predicate: format!("no_unknown_person{}", vis.predicate_clause()),
        stop_reason: CoverageStopReason::Complete,
        authorized_generation: 1,
        observed_generation: 1,
    };

    let ok = vis.samples == 64
        && vis.visible == 64
        && vis.occluded == 0
        && vis.outside_frustum == 0
        && vis.visible_fraction_ppm() == 1_000_000
        && vis.observable()
        && vis.cause().is_none()
        && vis.occlusion == Occlusion::MeshChecked(mesh_digest)
        && witness.certifies_absence();

    let view = zone_entry_json("cam-overhead", "ground-zone:open-yard", &vis);
    let rec = Record::new("scene_open_yard_all_visible")
        .check("scene", "open_yard", "open_yard")
        .check("basis_digest", basis.to_string(), basis.to_string())
        .check(
            "mesh_digest",
            mesh_digest.to_string(),
            mesh_digest.to_string(),
        )
        .check(
            "visible_fraction_ppm",
            1_000_000_u32,
            vis.visible_fraction_ppm(),
        )
        .check("state", "visible", state_label(&vis))
        .check("certifies_absence", true, witness.certifies_absence())
        .check(
            "views",
            RawJson(format!("[{view}]")),
            RawJson(format!("[{view}]")),
        );
    assert!(rec.emit_checked(start.elapsed().as_millis(), ok));
    Ok(())
}

#[test]
fn scene_wall_half_occluded_and_multi_camera_coverage() -> TestResult {
    let start = Instant::now();
    let strict = VisibilityPolicy::default();
    let lenient = VisibilityPolicy {
        grid: 8,
        threshold_ppm: 400_000,
    };
    let cam_west = down_camera()?;
    let cam_east = east_camera()?;
    let (pkg, mesh_digest, source_digest) = build_twin_package(Some(52.0))?;
    let twin = import_scene_mesh(&pkg, mesh_digest, source_digest)?;
    let scene = SceneMesh {
        mesh: twin.mesh(),
        package_digest: mesh_digest,
    };

    // Wall at x = 52 splits [32, 72] x [8, 40] symmetrically: 4 columns west (32 samples),
    // 4 columns east (32 samples).
    let straddle = rectangle(32.0, 8.0, 40.0, 32.0);
    let east_zone = rectangle(56.0, 8.0, 32.0, 32.0);
    let west_zone = rectangle(8.0, 8.0, 32.0, 32.0);

    let west_straddle = assess_ground_zone(
        VisibilityCamera::Pose(&cam_west),
        DIMENSIONS,
        &straddle,
        Some(scene),
        strict,
    )?;
    let west_straddle_lenient = assess_ground_zone(
        VisibilityCamera::Pose(&cam_west),
        DIMENSIONS,
        &straddle,
        Some(scene),
        lenient,
    )?;
    let west_east = assess_ground_zone(
        VisibilityCamera::Pose(&cam_west),
        DIMENSIONS,
        &east_zone,
        Some(scene),
        strict,
    )?;
    let west_west = assess_ground_zone(
        VisibilityCamera::Pose(&cam_west),
        DIMENSIONS,
        &west_zone,
        Some(scene),
        strict,
    )?;
    let east_east = assess_ground_zone(
        VisibilityCamera::Pose(&cam_east),
        DIMENSIONS,
        &east_zone,
        Some(scene),
        strict,
    )?;

    let basis_west = visibility_basis_digest(strict, Some(&cam_west), Some(mesh_digest));
    let basis_east = visibility_basis_digest(strict, Some(&cam_east), Some(mesh_digest));

    // Under cam_west alone, only west_zone is observable; straddle and east_zone are occluded,
    // so CoverageWitness over all 3 zones must NOT certify absence.
    let authorized: BTreeSet<String> = [
        "ground-zone:west-porch".to_owned(),
        "ground-zone:wall-straddle".to_owned(),
        "ground-zone:east-bay".to_owned(),
    ]
    .into_iter()
    .collect();
    let observed_west_only: BTreeSet<String> = if west_west.observable() {
        ["ground-zone:west-porch".to_owned()].into_iter().collect()
    } else {
        BTreeSet::new()
    };
    let uncertified = CoverageWitness {
        anchor: LedgerAnchor::genesis("site:geo-contract"),
        authorized_domain: authorized,
        observed_domain: observed_west_only,
        excluded_domain: BTreeSet::new(),
        continuity: CoverageContinuity::Continuous,
        completeness: Completeness::Partial,
        negative_predicate: format!("no_unknown_person{}", west_straddle.predicate_clause()),
        stop_reason: CoverageStopReason::Complete,
        authorized_generation: 1,
        observed_generation: 1,
    };

    let ok = west_straddle.samples == 64
        && west_straddle.visible == 32
        && west_straddle.occluded == 32
        && west_straddle.outside_frustum == 0
        && west_straddle.visible_fraction_ppm() == 500_000
        && !west_straddle.observable()
        && west_straddle.cause() == Some(NotVisibleCause::Occluded)
        && west_straddle_lenient.observable()
        && west_straddle_lenient.visible_fraction_ppm() == 500_000
        && west_east.visible == 0
        && west_east.occluded == 64
        && west_east.cause() == Some(NotVisibleCause::Occluded)
        && west_west.visible == 64
        && west_west.observable()
        && east_east.visible == 64
        && east_east.observable()
        && !uncertified.certifies_absence()
        && basis_west != basis_east;

    let views = format!(
        "[{},{},{},{}]",
        zone_entry_json("cam-west", "ground-zone:wall-straddle", &west_straddle),
        zone_entry_json("cam-west", "ground-zone:east-bay", &west_east),
        zone_entry_json("cam-west", "ground-zone:west-porch", &west_west),
        zone_entry_json("cam-east", "ground-zone:east-bay", &east_east),
    );
    let rec = Record::new("scene_wall_half_occluded_and_multi_camera_coverage")
        .check("basis_west", basis_west.to_string(), basis_west.to_string())
        .check("basis_east", basis_east.to_string(), basis_east.to_string())
        .check(
            "straddle_ppm",
            500_000_u32,
            west_straddle.visible_fraction_ppm(),
        )
        .check(
            "straddle_strict_state",
            "occluded",
            state_label(&west_straddle),
        )
        .check(
            "straddle_lenient_state",
            "visible",
            state_label(&west_straddle_lenient),
        )
        .check("west_east_ppm", 0_u32, west_east.visible_fraction_ppm())
        .check(
            "east_east_ppm",
            1_000_000_u32,
            east_east.visible_fraction_ppm(),
        )
        .check(
            "west_only_certifies_absence",
            false,
            uncertified.certifies_absence(),
        )
        .check("views", RawJson(views.clone()), RawJson(views));
    assert!(rec.emit_checked(start.elapsed().as_millis(), ok));
    Ok(())
}

#[test]
fn scene_camera_facing_away_outside_frustum_and_frustum_only_honesty() -> TestResult {
    let start = Instant::now();
    let policy = VisibilityPolicy::default();
    let cam_away = away_camera()?;
    let (pkg, mesh_digest, source_digest) = build_twin_package(None)?;
    let twin = import_scene_mesh(&pkg, mesh_digest, source_digest)?;
    let scene = SceneMesh {
        mesh: twin.mesh(),
        package_digest: mesh_digest,
    };

    let yard = rectangle(8.0, 8.0, 80.0, 32.0);
    let away_vis = assess_ground_zone(
        VisibilityCamera::Pose(&cam_away),
        DIMENSIONS,
        &yard,
        Some(scene),
        policy,
    )?;

    // Frustum-only homography camera without a pose must explicitly stay `occlusion_unknown`,
    // even when a scene mesh is supplied.
    let homography_vis = assess_ground_zone(
        VisibilityCamera::Homography(&DOWN_HOMOGRAPHY),
        DIMENSIONS,
        &yard,
        Some(scene),
        policy,
    )?;

    let basis_away = visibility_basis_digest(policy, Some(&cam_away), Some(mesh_digest));
    let basis_homography = visibility_basis_digest(policy, None, Some(mesh_digest));

    let ok = away_vis.samples == 64
        && away_vis.visible == 0
        && away_vis.occluded == 0
        && away_vis.outside_frustum == 64
        && away_vis.visible_fraction_ppm() == 0
        && !away_vis.observable()
        && away_vis.cause() == Some(NotVisibleCause::OutsideFrustum)
        && homography_vis.camera_model == CameraModel::OwnerHomography
        && homography_vis.occlusion == Occlusion::Unknown(OcclusionUnknownReason::NoCameraPose)
        && homography_vis.frustum_only()
        && homography_vis.claim() == "frustum_only"
        && homography_vis
            .predicate_clause()
            .contains("occlusion_unknown");

    let views = format!(
        "[{},{}]",
        zone_entry_json("cam-away", "ground-zone:open-yard", &away_vis),
        zone_entry_json("cam-homography", "ground-zone:open-yard", &homography_vis),
    );
    let rec = Record::new("scene_camera_facing_away_outside_frustum_and_frustum_only_honesty")
        .check("basis_away", basis_away.to_string(), basis_away.to_string())
        .check(
            "basis_homography",
            basis_homography.to_string(),
            basis_homography.to_string(),
        )
        .check("away_state", "outside_frustum", state_label(&away_vis))
        .check("away_ppm", 0_u32, away_vis.visible_fraction_ppm())
        .check("away_outside_frustum", 64_u32, away_vis.outside_frustum)
        .check("homography_claim", "frustum_only", homography_vis.claim())
        .check("views", RawJson(views.clone()), RawJson(views));
    assert!(rec.emit_checked(start.elapsed().as_millis(), ok));
    Ok(())
}

#[test]
fn metamorphic_rigid_world_transform_invariance() -> TestResult {
    let start = Instant::now();
    let policy = VisibilityPolicy::default();
    let cam = down_camera()?;
    let cam_away = away_camera()?;
    let orig_mesh = build_transformed_mesh(Some(52.0), 1.0, 0.0, 0.0, 0.0)?;
    let orig_digest = ContentDigest::sha256(b"metamorphic-orig-mesh");
    let orig_scene = SceneMesh {
        mesh: &orig_mesh,
        package_digest: orig_digest,
    };

    // Transform A: exact 90-degree Z-rotation + translation (preserves axis-aligned grid lattice).
    let (cos90, sin90, tx90, ty90) = (0.0_f64, 1.0_f64, 13.5_f64, -7.25_f64);
    let rot90_mesh = build_transformed_mesh(Some(52.0), cos90, sin90, tx90, ty90)?;
    let rot90_digest = ContentDigest::sha256(b"metamorphic-rot90-mesh");
    let rot90_scene = SceneMesh {
        mesh: &rot90_mesh,
        package_digest: rot90_digest,
    };
    let cam_rot90 = transform_pose_z(&cam, cos90, sin90, tx90, ty90)?;
    let cam_away_rot90 = transform_pose_z(&cam_away, cos90, sin90, tx90, ty90)?;

    let zones = [
        ("open", rectangle(8.0, 8.0, 32.0, 32.0)),
        ("half_wall", rectangle(32.0, 8.0, 40.0, 32.0)),
        ("occluded", rectangle(56.0, 8.0, 32.0, 32.0)),
    ];
    let mut exact_matches = 0_u32;
    for (_, poly) in &zones {
        let orig = assess_ground_zone(
            VisibilityCamera::Pose(&cam),
            DIMENSIONS,
            poly,
            Some(orig_scene),
            policy,
        )?;
        let xformed_poly: Vec<(f64, f64)> = poly
            .iter()
            .map(|&(x, y)| {
                let p = transform_point_z([x, y, 0.0], cos90, sin90, tx90, ty90);
                (p[0], p[1])
            })
            .collect();
        let rot = assess_ground_zone(
            VisibilityCamera::Pose(&cam_rot90),
            DIMENSIONS,
            &xformed_poly,
            Some(rot90_scene),
            policy,
        )?;
        if orig.samples == rot.samples
            && orig.visible == rot.visible
            && orig.occluded == rot.occluded
            && orig.outside_frustum == rot.outside_frustum
            && orig.cause() == rot.cause()
        {
            exact_matches += 1;
        }
    }
    let away_orig = assess_ground_zone(
        VisibilityCamera::Pose(&cam_away),
        DIMENSIONS,
        &zones[0].1,
        Some(orig_scene),
        policy,
    )?;
    let away_poly_rot90: Vec<(f64, f64)> = zones[0]
        .1
        .iter()
        .map(|&(x, y)| {
            let p = transform_point_z([x, y, 0.0], cos90, sin90, tx90, ty90);
            (p[0], p[1])
        })
        .collect();
    let away_rot = assess_ground_zone(
        VisibilityCamera::Pose(&cam_away_rot90),
        DIMENSIONS,
        &away_poly_rot90,
        Some(rot90_scene),
        policy,
    )?;
    if away_orig.outside_frustum == away_rot.outside_frustum
        && away_orig.cause() == away_rot.cause()
    {
        exact_matches += 1;
    }

    // Transform B: general Pythagorean 3-4-5 rotation (cos=0.6, sin=0.8) + translation applied
    // to mesh, camera pose, and every individual ground sample of the half-wall zone.
    let (cos345, sin345, tx345, ty345) = (0.6_f64, 0.8_f64, 17.25_f64, -9.5_f64);
    let rot345_mesh = build_transformed_mesh(Some(52.0), cos345, sin345, tx345, ty345)?;
    let cam_rot345 = transform_pose_z(&cam, cos345, sin345, tx345, ty345)?;
    let samples = ground_samples(&zones[1].1, policy)?;
    let mut ray_matches = 0_u32;
    let mut budget = WorkBudget::new(100_000);
    for &(x, y) in &samples {
        let p0 = [x, y, 0.0];
        let p1 = transform_point_z(p0, cos345, sin345, tx345, ty345);
        let uv0 = cam.pose.project(cam.intrinsics, p0)?;
        let uv1 = cam_rot345.pose.project(cam_rot345.intrinsics, p1)?;
        let pixel_close = (uv0[0] - uv1[0]).abs() <= 1e-9 && (uv0[1] - uv1[1]).abs() <= 1e-9;

        let from0 = cam.pose.center();
        let len0 =
            ((p0[0] - from0[0]).powi(2) + (p0[1] - from0[1]).powi(2) + (p0[2] - from0[2]).powi(2))
                .sqrt();
        let occ0 = orig_mesh.segment_occluded(
            orig_mesh.basis(),
            from0,
            p0,
            OCCLUSION_MARGIN_RATIO * len0,
            &mut budget,
        )?;

        let from1 = cam_rot345.pose.center();
        let len1 =
            ((p1[0] - from1[0]).powi(2) + (p1[1] - from1[1]).powi(2) + (p1[2] - from1[2]).powi(2))
                .sqrt();
        let occ1 = rot345_mesh.segment_occluded(
            rot345_mesh.basis(),
            from1,
            p1,
            OCCLUSION_MARGIN_RATIO * len1,
            &mut budget,
        )?;
        if pixel_close && occ0 == occ1 {
            ray_matches += 1;
        }
    }

    let basis_orig = visibility_basis_digest(policy, Some(&cam), Some(orig_digest));
    let basis_rot90 = visibility_basis_digest(policy, Some(&cam_rot90), Some(rot90_digest));
    let ok = exact_matches == 4 && ray_matches == 64 && basis_orig != basis_rot90;
    let rec = Record::new("metamorphic_rigid_world_transform_invariance")
        .check("basis_orig", basis_orig.to_string(), basis_orig.to_string())
        .check(
            "basis_rot90",
            basis_rot90.to_string(),
            basis_rot90.to_string(),
        )
        .check("rot90_exact_scene_matches", 4_u32, exact_matches)
        .check("rot345_ray_and_occlusion_matches", 64_u32, ray_matches);
    assert!(rec.emit_checked(start.elapsed().as_millis(), ok));
    Ok(())
}

#[test]
fn metamorphic_moving_occluder_and_privacy_mask_precedence() -> TestResult {
    let start = Instant::now();
    let policy = VisibilityPolicy::default();
    let cam = down_camera()?;
    let target = rectangle(56.0, 8.0, 32.0, 32.0);

    // Wall at x = 52 blocks all 64 samples of [56, 88].
    let (pkg_blocked, digest_blocked, src_blocked) = build_twin_package(Some(52.0))?;
    let twin_blocked = import_scene_mesh(&pkg_blocked, digest_blocked, src_blocked)?;
    let vis_blocked = assess_ground_zone(
        VisibilityCamera::Pose(&cam),
        DIMENSIONS,
        &target,
        Some(SceneMesh {
            mesh: twin_blocked.mesh(),
            package_digest: digest_blocked,
        }),
        policy,
    )?;

    // Move wall east to x = 92 (beyond target [56, 88]): all 64 samples become visible.
    let (pkg_clear, digest_clear, src_clear) = build_twin_package(Some(92.0))?;
    let twin_clear = import_scene_mesh(&pkg_clear, digest_clear, src_clear)?;
    let vis_clear = assess_ground_zone(
        VisibilityCamera::Pose(&cam),
        DIMENSIONS,
        &target,
        Some(SceneMesh {
            mesh: twin_clear.mesh(),
            package_digest: digest_clear,
        }),
        policy,
    )?;

    // Privacy mask over pixel u >= 72 on the blocked scene: masked pixels are classified as
    // `privacy_masked` BEFORE mesh occlusion, and cause becomes `privacy_masked`.
    let mask_fn = |u: u32, _v: u32| u >= 72;
    let vis_masked = assess_ground_zone_masked(
        VisibilityCamera::Pose(&cam),
        DIMENSIONS,
        &target,
        Some(SceneMesh {
            mesh: twin_blocked.mesh(),
            package_digest: digest_blocked,
        }),
        policy,
        Some(&mask_fn),
    )?;

    let basis_blocked = visibility_basis_digest(policy, Some(&cam), Some(digest_blocked));
    let basis_clear = visibility_basis_digest(policy, Some(&cam), Some(digest_clear));
    let ok = vis_blocked.visible == 0
        && vis_blocked.occluded == 64
        && vis_blocked.cause() == Some(NotVisibleCause::Occluded)
        && vis_clear.visible == 64
        && vis_clear.occluded == 0
        && vis_clear.observable()
        && vis_clear.cause().is_none()
        && digest_blocked != digest_clear
        && basis_blocked != basis_clear
        && vis_masked.privacy_masked == 32
        && vis_masked.occluded == 32
        && vis_masked.visible == 0
        && !vis_masked.observable()
        && vis_masked.cause() == Some(NotVisibleCause::PrivacyMasked);

    let rec = Record::new("metamorphic_moving_occluder_and_privacy_mask_precedence")
        .check(
            "basis_blocked",
            basis_blocked.to_string(),
            basis_blocked.to_string(),
        )
        .check(
            "basis_clear",
            basis_clear.to_string(),
            basis_clear.to_string(),
        )
        .check("blocked_ppm", 0_u32, vis_blocked.visible_fraction_ppm())
        .check("blocked_state", "occluded", state_label(&vis_blocked))
        .check("clear_ppm", 1_000_000_u32, vis_clear.visible_fraction_ppm())
        .check("clear_state", "visible", state_label(&vis_clear))
        .check("masked_count", 32_u32, vis_masked.privacy_masked)
        .check("masked_state", "privacy_masked", state_label(&vis_masked));
    assert!(rec.emit_checked(start.elapsed().as_millis(), ok));
    Ok(())
}

#[test]
fn budget_exhaustion_and_cooperative_cancellation() -> TestResult {
    let start = Instant::now();
    let policy = VisibilityPolicy::default();
    let cam = down_camera()?;
    let (pkg, mesh_digest, source_digest) = build_twin_package(Some(52.0))?;
    let twin = import_scene_mesh(&pkg, mesh_digest, source_digest)?;
    let scene = SceneMesh {
        mesh: twin.mesh(),
        package_digest: mesh_digest,
    };
    let straddle = rectangle(32.0, 8.0, 40.0, 32.0);

    // 1. Tight unit budget fails closed with GeometryError::BudgetExhausted.
    let mut small_budget = WorkBudget::new(10);
    let err_budget = assess_ground_zone_with_budget(
        VisibilityCamera::Pose(&cam),
        DIMENSIONS,
        &straddle,
        Some(scene),
        policy,
        None,
        &mut small_budget,
    );

    // 2. Pre-set cancellation flag fails closed with GeometryError::Cancelled and 0 charges.
    let cancel_now = AtomicBool::new(true);
    let mut cancelled_budget = WorkBudget::cancellable(100_000, &cancel_now);
    let err_pre_cancel = assess_ground_zone_with_budget(
        VisibilityCamera::Pose(&cam),
        DIMENSIONS,
        &straddle,
        Some(scene),
        policy,
        None,
        &mut cancelled_budget,
    );

    // 3. Cooperative probe cancels mid-run after 5 charges without completing all 64 samples.
    let probes = AtomicU64::new(0);
    let probe = || probes.fetch_add(1, Ordering::Relaxed) >= 5;
    let mut mid_budget = WorkBudget::with_cancellation_probe(100_000, &probe);
    let err_mid_cancel = assess_ground_zone_with_budget(
        VisibilityCamera::Pose(&cam),
        DIMENSIONS,
        &straddle,
        Some(scene),
        policy,
        None,
        &mut mid_budget,
    );

    // 4. Pose-sensitivity budget exhaustion and cancellation.
    let nominal = assess_ground_zone(
        VisibilityCamera::Pose(&cam),
        DIMENSIONS,
        &straddle,
        Some(scene),
        policy,
    )?;
    let cov = PoseCovariance::new([
        [1e-6, 0.0, 0.0, 0.0, 0.0, 0.0],
        [0.0, 1e-6, 0.0, 0.0, 0.0, 0.0],
        [0.0, 0.0, 1e-6, 0.0, 0.0, 0.0],
        [0.0, 0.0, 0.0, 1e-4, 0.0, 0.0],
        [0.0, 0.0, 0.0, 0.0, 1e-4, 0.0],
        [0.0, 0.0, 0.0, 0.0, 0.0, 1e-4],
    ])?;
    let mut pose_small = WorkBudget::new(100);
    let err_pose_budget = assess_pose_robustness(
        &cam,
        &cov,
        DIMENSIONS,
        &straddle,
        Some(scene),
        policy,
        None,
        &nominal,
        &mut pose_small,
    );
    let mut pose_cancel = WorkBudget::cancellable(100_000, &cancel_now);
    let err_pose_cancel = assess_pose_robustness(
        &cam,
        &cov,
        DIMENSIONS,
        &straddle,
        Some(scene),
        policy,
        None,
        &nominal,
        &mut pose_cancel,
    );
    let mut pose_ok_budget = WorkBudget::new(100_000);
    let robustness = assess_pose_robustness(
        &cam,
        &cov,
        DIMENSIONS,
        &straddle,
        Some(scene),
        policy,
        None,
        &nominal,
        &mut pose_ok_budget,
    )?;

    let ok = err_budget == Err(VisibilityError::Geometry(GeometryError::BudgetExhausted))
        && err_pre_cancel == Err(VisibilityError::Geometry(GeometryError::Cancelled))
        && cancelled_budget.used() == 0
        && err_mid_cancel == Err(VisibilityError::Geometry(GeometryError::Cancelled))
        && mid_budget.used() > 0
        && mid_budget.used() < 64
        && err_pose_budget == Err(VisibilityError::PoseSensitivityBudget)
        && err_pose_cancel == Err(VisibilityError::Geometry(GeometryError::Cancelled))
        && robustness.nominal == PoseRobustnessClass::Occluded
        && robustness.robust();

    let rec = Record::new("budget_exhaustion_and_cooperative_cancellation")
        .check(
            "zone_budget_exhausted",
            true,
            err_budget == Err(VisibilityError::Geometry(GeometryError::BudgetExhausted)),
        )
        .check(
            "zone_pre_cancelled",
            true,
            err_pre_cancel == Err(VisibilityError::Geometry(GeometryError::Cancelled))
                && cancelled_budget.used() == 0,
        )
        .check(
            "zone_mid_cancelled",
            true,
            err_mid_cancel == Err(VisibilityError::Geometry(GeometryError::Cancelled))
                && mid_budget.used() > 0
                && mid_budget.used() < 64,
        )
        .check(
            "pose_budget_refused",
            true,
            err_pose_budget == Err(VisibilityError::PoseSensitivityBudget),
        )
        .check(
            "pose_cancelled",
            true,
            err_pose_cancel == Err(VisibilityError::Geometry(GeometryError::Cancelled)),
        )
        .check("pose_robust_state", "robust", robustness.state());
    assert!(rec.emit_checked(start.elapsed().as_millis(), ok));
    Ok(())
}

#[test]
fn canonical_digest_and_basis_stability() -> TestResult {
    let start = Instant::now();
    let policy_a = VisibilityPolicy::default();
    let policy_b = VisibilityPolicy {
        grid: 16,
        threshold_ppm: 1_000_000,
    };
    let policy_c = VisibilityPolicy {
        grid: 8,
        threshold_ppm: 500_000,
    };
    let cam_a = down_camera()?;
    let cam_b = east_camera()?;
    let (pkg_a, mesh_a, src_a) = build_twin_package(Some(52.0))?;
    let (pkg_b, mesh_b, _) = build_twin_package(Some(92.0))?;
    let twin_a = import_scene_mesh(&pkg_a, mesh_a, src_a)?;
    let scene_a = SceneMesh {
        mesh: twin_a.mesh(),
        package_digest: mesh_a,
    };
    let straddle = rectangle(32.0, 8.0, 40.0, 32.0);

    let run1 = assess_ground_zone(
        VisibilityCamera::Pose(&cam_a),
        DIMENSIONS,
        &straddle,
        Some(scene_a),
        policy_a,
    )?;
    let run2 = assess_ground_zone(
        VisibilityCamera::Pose(&cam_a),
        DIMENSIONS,
        &straddle,
        Some(scene_a),
        policy_a,
    )?;

    let encode_vis = |v: &ZoneVisibility, with_masked: bool| -> Vec<u8> {
        let mut e = CanonicalEncoder::new();
        v.encode_versioned(&mut e, with_masked);
        e.finish()
    };
    let bytes1 = encode_vis(&run1, true);
    let bytes2 = encode_vis(&run2, true);
    let digest1 = ContentDigest::sha256(&bytes1);
    let digest2 = ContentDigest::sha256(&bytes2);
    let mut dec = CanonicalDecoder::new(&bytes1);
    let decoded = ZoneVisibility::decode_versioned(&mut dec, true)?;
    dec.ensure_finished()?;

    // Basis digest stability and single-parameter perturbation sensitivity.
    let basis_ref_1 = visibility_basis_digest(policy_a, Some(&cam_a), Some(mesh_a));
    let basis_ref_2 = visibility_basis_digest(policy_a, Some(&cam_a), Some(mesh_a));
    let basis_grid = visibility_basis_digest(policy_b, Some(&cam_a), Some(mesh_a));
    let basis_thresh = visibility_basis_digest(policy_c, Some(&cam_a), Some(mesh_a));
    let basis_pose = visibility_basis_digest(policy_a, Some(&cam_b), Some(mesh_a));
    let basis_mesh = visibility_basis_digest(policy_a, Some(&cam_a), Some(mesh_b));
    let basis_no_mesh = visibility_basis_digest(policy_a, Some(&cam_a), None);

    // Witness canonical round-trip stability.
    let witness = CoverageWitness {
        anchor: LedgerAnchor::genesis("site:geo-contract"),
        authorized_domain: ["ground-zone:west-porch".to_owned()].into_iter().collect(),
        observed_domain: ["ground-zone:west-porch".to_owned()].into_iter().collect(),
        excluded_domain: BTreeSet::new(),
        continuity: CoverageContinuity::Continuous,
        completeness: Completeness::Complete,
        negative_predicate: format!("no_unknown_person{}", run1.predicate_clause()),
        stop_reason: CoverageStopReason::Complete,
        authorized_generation: 1,
        observed_generation: 1,
    };
    let mut w_enc = CanonicalEncoder::new();
    witness.encode_canonical(&mut w_enc);
    let w_bytes = w_enc.finish();
    let mut w_dec = CanonicalDecoder::new(&w_bytes);
    let w_roundtrip = CoverageWitness::decode_canonical(&mut w_dec)?;
    w_dec.ensure_finished()?;

    let distinct_bases: BTreeSet<ContentDigest> = [
        basis_ref_1,
        basis_grid,
        basis_thresh,
        basis_pose,
        basis_mesh,
        basis_no_mesh,
    ]
    .into_iter()
    .collect();

    let ok = run1 == run2
        && decoded == run1
        && digest1 == digest2
        && basis_ref_1 == basis_ref_2
        && distinct_bases.len() == 6
        && w_roundtrip == witness
        && w_roundtrip.witness_digest() == witness.witness_digest();

    let rec = Record::new("canonical_digest_and_basis_stability")
        .check(
            "visibility_digest",
            digest1.to_string(),
            digest2.to_string(),
        )
        .check(
            "basis_digest",
            basis_ref_1.to_string(),
            basis_ref_2.to_string(),
        )
        .check("distinct_perturbed_bases", 6_usize, distinct_bases.len())
        .check(
            "witness_digest",
            witness.witness_digest().to_string(),
            w_roundtrip.witness_digest().to_string(),
        );
    assert!(rec.emit_checked(start.elapsed().as_millis(), ok));
    Ok(())
}

#[test]
fn differential_against_fss_geometry_handoff_prediction() -> TestResult {
    let start = Instant::now();
    let policy = VisibilityPolicy::default();
    let cam_west = down_camera()?;
    let cam_east = east_camera()?;

    // Both zones sit inside the overlapping frustums of cam_west ([0,96)) and cam_east ([28,124)),
    // on opposite sides of the opaque wall at x = 52.
    let west_zone = rectangle(32.0, 12.0, 16.0, 24.0);
    let east_zone = rectangle(56.0, 12.0, 16.0, 24.0);

    let (pkg_wall, digest_wall, src_wall) = build_twin_package(Some(52.0))?;
    let twin_wall = import_scene_mesh(&pkg_wall, digest_wall, src_wall)?;
    let wall_scene = SceneMesh {
        mesh: twin_wall.mesh(),
        package_digest: digest_wall,
    };

    let (pkg_clear, digest_clear, src_clear) = build_twin_package(Some(92.0))?;
    let twin_clear = import_scene_mesh(&pkg_clear, digest_clear, src_clear)?;
    let clear_scene = SceneMesh {
        mesh: twin_clear.mesh(),
        package_digest: digest_clear,
    };

    // Ground-visibility classifications on the walled scene and cleared scene.
    let gv_west_on_west = assess_ground_zone(
        VisibilityCamera::Pose(&cam_west),
        DIMENSIONS,
        &west_zone,
        Some(wall_scene),
        policy,
    )?;
    let gv_east_on_west = assess_ground_zone(
        VisibilityCamera::Pose(&cam_east),
        DIMENSIONS,
        &west_zone,
        Some(wall_scene),
        policy,
    )?;
    let gv_west_on_east = assess_ground_zone(
        VisibilityCamera::Pose(&cam_west),
        DIMENSIONS,
        &east_zone,
        Some(wall_scene),
        policy,
    )?;
    let gv_east_on_east = assess_ground_zone(
        VisibilityCamera::Pose(&cam_east),
        DIMENSIONS,
        &east_zone,
        Some(wall_scene),
        policy,
    )?;
    let gv_west_on_east_clear = assess_ground_zone(
        VisibilityCamera::Pose(&cam_west),
        DIMENSIONS,
        &east_zone,
        Some(clear_scene),
        policy,
    )?;

    // Differential against fss-geometry's visibility-aware handoff prediction on the exact same
    // mesh and camera poses.
    let mut budget = WorkBudget::new(500_000);
    let basis = ForecastBasis::new(twin_wall.mesh().basis(), 1, 1, 1, 1)?;
    let priors = RoutePriors::new([1_000_000, 0, 0, 0], 1)?;
    let west_points = [[36.0, 20.0, 0.0], [42.0, 24.0, 0.0]];
    let east_points = [[60.0, 20.0, 0.0], [66.0, 24.0, 0.0]];
    let routes = [
        RouteCandidate {
            id: 10,
            points: &west_points,
            speed: 4.0,
            initial_pause_ns: 0,
            end: RouteEnd::Stop,
            surface: RouteSurface::PedestrianPath,
            base_mass: 100,
            protected: true,
        },
        RouteCandidate {
            id: 20,
            points: &east_points,
            speed: 4.0,
            initial_pause_ns: 0,
            end: RouteEnd::Stop,
            surface: RouteSurface::PedestrianPath,
            base_mass: 100,
            protected: true,
        },
    ];
    let motion = forecast_routes(basis, 0, 2_000_000_000, priors, &routes, &mut budget)?;
    let body = BodySamples::new(1, &[[0.0, 0.0, 0.01], [4.0, 4.0, 0.01]], &mut budget)?;
    let bodies = [
        RouteBody {
            route: 10,
            body: &body,
        },
        RouteBody {
            route: 20,
            body: &body,
        },
    ];
    let valid = NanosecondInterval::new(0, 10_000_000_000)?;
    let schedule = CaptureSchedule::new(200_000_000, 0)?;
    let latency = NanosecondInterval::new(0, 10_000_000)?;
    let make_cams = |geom: GeometryBasis| -> [HandoffCamera<'static>; 2] {
        [
            HandoffCamera {
                id: 1,
                geometry: geom,
                clock: 1,
                observation_generation: 1,
                image_mode: 1,
                pose: cam_west.pose,
                intrinsics: cam_west.intrinsics,
                availability: CameraAvailability::Ready,
                already_observing: false,
                valid,
                schedule,
                latency,
                privacy_masks: &[],
                visible_per_mille: 1000,
                minimum_extent_px: [1.0, 1.0],
            },
            HandoffCamera {
                id: 2,
                geometry: geom,
                clock: 1,
                observation_generation: 1,
                image_mode: 1,
                pose: cam_east.pose,
                intrinsics: cam_east.intrinsics,
                availability: CameraAvailability::Ready,
                already_observing: false,
                valid,
                schedule,
                latency,
                privacy_masks: &[],
                visible_per_mille: 1000,
                minimum_extent_px: [1.0, 1.0],
            },
        ]
    };
    let options = HandoffOptions {
        max_samples_per_camera: 64,
        endpoint_margin: 1e-4,
    };

    let wall_cams = make_cams(twin_wall.mesh().basis());
    let handoff_wall = predict_camera_handoffs(
        basis,
        &motion,
        twin_wall.mesh(),
        &wall_cams,
        &bodies,
        options,
        &mut budget,
    )?;
    let clear_cams = make_cams(twin_clear.mesh().basis());
    let handoff_clear = predict_camera_handoffs(
        basis,
        &motion,
        twin_clear.mesh(),
        &clear_cams,
        &bodies,
        options,
        &mut budget,
    )?;

    let route_cams = |forecast: &fss_geometry::CameraHandoffForecast, route_id: u64| -> Vec<u64> {
        forecast
            .routes
            .iter()
            .find(|r| r.route == route_id)
            .map(|r| match &r.next {
                NextCameraOutcome::Predicted { cameras, .. } => cameras.clone(),
                _ => Vec::new(),
            })
            .unwrap_or_default()
    };
    let wall_west_cams = route_cams(&handoff_wall, 10);
    let wall_east_cams = route_cams(&handoff_wall, 20);
    let clear_east_cams = route_cams(&handoff_clear, 20);

    // Every ground-visibility decision must match fss-geometry's handoff camera set.
    let gv_wall_west_cams: Vec<u64> = [
        (1_u64, gv_west_on_west.observable()),
        (2_u64, gv_east_on_west.observable()),
    ]
    .into_iter()
    .filter_map(|(id, obs)| obs.then_some(id))
    .collect();
    let gv_wall_east_cams: Vec<u64> = [
        (1_u64, gv_west_on_east.observable()),
        (2_u64, gv_east_on_east.observable()),
    ]
    .into_iter()
    .filter_map(|(id, obs)| obs.then_some(id))
    .collect();
    let gv_clear_east_cams: Vec<u64> = [
        (1_u64, gv_west_on_east_clear.observable()),
        (2_u64, gv_east_on_east.observable()),
    ]
    .into_iter()
    .filter_map(|(id, obs)| obs.then_some(id))
    .collect();

    let ok = wall_west_cams == vec![1]
        && wall_east_cams == vec![2]
        && clear_east_cams == vec![1, 2]
        && wall_west_cams == gv_wall_west_cams
        && wall_east_cams == gv_wall_east_cams
        && clear_east_cams == gv_clear_east_cams;

    let rec = Record::new("differential_against_fss_geometry_handoff_prediction")
        .check("wall_west_route_cameras", gv_wall_west_cams, wall_west_cams)
        .check("wall_east_route_cameras", gv_wall_east_cams, wall_east_cams)
        .check(
            "clear_east_route_cameras",
            gv_clear_east_cams,
            clear_east_cams,
        );
    assert!(rec.emit_checked(start.elapsed().as_millis(), ok));
    Ok(())
}
