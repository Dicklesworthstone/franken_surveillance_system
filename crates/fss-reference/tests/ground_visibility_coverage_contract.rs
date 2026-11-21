#![forbid(unsafe_code)]
//! Geometric ground-zone coverage of `CorroborationReport` (fss-2h5zq.53) on real retained
//! recordings:
//!
//! 1. without a mesh (homography only) a zone fully in view is covered and every witness says the
//!    claim is frustum-only (`occlusion_unknown`); a zone outside the frustum is
//!    `outside_frustum` with no witness;
//! 2. with owner calibrated poses and an owner scene mesh (fss-twin package) the zone in view is
//!    covered with its recorded fraction and a mesh-checked occlusion model;
//! 3. behind an opaque mesh wall the zone is `occluded` and carries no witness;
//! 4. candidates and events never depend on the visibility inputs, the generation always does;
//! 5. a pose that disagrees with its homography or its frame size is a typed refusal;
//! 6. records round-trip canonically (version 2) and analyses are deterministic;
//! 7. with a privacy mask (fss-bgqkd) a zone partly masked and partly behind the wall counts each
//!    sample once (masked before occluded), is `privacy_masked` / not observable with no
//!    witness, round-trips as a version-3 record and is deterministic; the unmasked camera keeps
//!    its `occluded` reason.

#[path = "cascade_support/mod.rs"]
mod support;

use fss_core::ContentDigest;
use fss_core::SensorId;
use fss_geometry::{GeometryError, WorkBudget};
use fss_reference::ingest::FileFormatHint;
use fss_reference::ingest::ground_visibility::{
    CameraModel, CameraPose, NotVisibleCause, Occlusion, OcclusionUnknownReason, SceneMesh,
    VisibilityCamera, VisibilityPolicy, assess_ground_zone, import_scene_mesh, rectangle,
};
use fss_reference::ingest::privacy_mask::{PrivacyMaskPolicy, declare_mask, preview_mask};
use fss_reference::ingest::recorded_corroboration::{
    CorroborationCamera, CorroborationGates, CorroborationPlan, CorroborationReport,
    GroundHomography, GroundVisibilityPlan, GroundZone,
};
use fss_reference::ingest::recorded_coverage::{CoverageRecord, UncoveredReason, ZoneCoverage};
use fss_reference::ingest::recorded_decode::ComponentInterpretation;
use fss_reference::ingest::recorded_watch::{WatchDetectorConfig, WatchLimits, WatchTrackerConfig};
use fss_reference::media_fixture::jpeg::{JpegConfig, Subsampling, encode_jpeg};
use std::sync::atomic::AtomicBool;
use support::{Fixture, TestResult};

/// East sees the ground from above: `x = u`, `y = 48 - v`.
const EAST: [f64; 9] = [1.0, 0.0, 0.0, 0.0, -1.0, 48.0, 0.0, 0.0, 1.0];
/// West is rotated half a turn about the vertical: `x = 96 - u`, `y = v`.
const WEST: [f64; 9] = [-1.0, 0.0, 96.0, 0.0, 1.0, 0.0, 0.0, 0.0, 1.0];

fn scene(right: bool) -> TestResult<Vec<u8>> {
    let config = JpegConfig {
        quality: 90,
        subsampling: Subsampling::Grayscale,
        restart_interval: 0,
        custom_markers: Vec::new(),
    };
    let mut stream = Vec::new();
    for index in 0..14_usize {
        let mut pixels = vec![40_u8; 96 * 48];
        if index >= 3 {
            let left = if right {
                (index - 3) * 8
            } else {
                80 - (index - 3) * 8
            };
            for y in 8..24 {
                for x in left..left + 16 {
                    pixels[y * 96 + x] = 220;
                }
            }
        }
        stream.extend(encode_jpeg(96, 48, &pixels, &config)?);
    }
    Ok(stream)
}

/// Both cameras hang 10 units above (48, 24) looking straight down (f = 10 px).
fn poses() -> TestResult<[Option<CameraPose>; 2]> {
    let centre = [48.0, 24.0, 10.0];
    // World-to-camera translation `-R * centre`.
    let with_centre = |rotation: [[f64; 3]; 3]| -> TestResult<CameraPose> {
        let translation =
            rotation.map(|row| -(row[0] * centre[0] + row[1] * centre[1] + row[2] * centre[2]));
        Ok(CameraPose::from_parameters(
            [96, 48],
            [10.0, 10.0, 48.0, 24.0],
            rotation,
            translation,
        )?)
    };
    Ok([
        Some(with_centre([
            [1.0, 0.0, 0.0],
            [0.0, -1.0, 0.0],
            [0.0, 0.0, -1.0],
        ])?),
        Some(with_centre([
            [-1.0, 0.0, 0.0],
            [0.0, 1.0, 0.0],
            [0.0, 0.0, -1.0],
        ])?),
    ])
}

fn text(out: &mut Vec<u8>, value: &str) {
    out.extend_from_slice(&(value.len() as u16).to_le_bytes());
    out.extend_from_slice(value.as_bytes());
}

/// An fss-twin `FSSTWIN1` package: an opaque support ground plane at z = 0 and, optionally, an
/// opaque wall in the plane x = 52 (z 0..20) between the cameras and every ground point x > 52.
fn twin_package(wall: bool) -> Vec<u8> {
    placed_twin_package(wall.then_some(52.0), [0.0, 0.0])
}

fn placed_twin_package(wall_x: Option<f64>, shift: [f64; 2]) -> Vec<u8> {
    let mut body = vec![1_u8; 32];
    text(&mut body, "test/Z-up");
    text(&mut body, "synthetic");
    body.push(0);
    for value in [0.0_f64, -1.0, -1.0] {
        body.extend_from_slice(&value.to_le_bytes());
    }
    let mut vertices: Vec<[f64; 3]> = vec![
        [-100.0, -100.0, 0.0],
        [200.0, -100.0, 0.0],
        [200.0, 200.0, 0.0],
        [-100.0, 200.0, 0.0],
    ];
    let mut triangles: Vec<[u32; 4]> = vec![[0, 1, 2, 0], [0, 2, 3, 0]];
    let objects: u32 = if wall_x.is_some() { 2 } else { 1 };
    if let Some(x) = wall_x {
        vertices.extend([
            [x, -10.0, 0.0],
            [x, 60.0, 0.0],
            [x, 60.0, 20.0],
            [x, -10.0, 20.0],
        ]);
        triangles.extend([[4, 5, 6, 1], [4, 6, 7, 1]]);
    }
    for count in [
        objects,
        objects,
        vertices.len() as u32,
        triangles.len() as u32,
    ] {
        body.extend_from_slice(&count.to_le_bytes());
    }
    text(&mut body, "ground");
    body.push(1);
    if wall_x.is_some() {
        text(&mut body, "wall");
        body.push(5);
    }
    text(&mut body, "ground");
    body.extend_from_slice(&0_u32.to_le_bytes());
    body.extend_from_slice(&[1, 1]);
    if wall_x.is_some() {
        text(&mut body, "wall");
        body.extend_from_slice(&1_u32.to_le_bytes());
        body.extend_from_slice(&[0, 1]);
    }
    for [x, y, z] in vertices {
        for value in [x + shift[0], y + shift[1], z] {
            body.extend_from_slice(&value.to_le_bytes());
        }
    }
    for triangle in &triangles {
        for value in triangle {
            body.extend_from_slice(&value.to_le_bytes());
        }
    }
    let mut package = b"FSSTWIN1".to_vec();
    package.extend_from_slice(&(body.len() as u64).to_le_bytes());
    package.extend_from_slice(&body);
    let trailer = ContentDigest::sha256(&package).bytes();
    package.extend_from_slice(&trailer);
    package
}

#[test]
fn hand_derived_visibility_is_stable_when_the_ground_frame_moves() -> TestResult {
    let cases = [
        ("open_yard", None, [0.0, 0.0], false, [16, 0, 0]),
        ("half_wall", Some(52.0), [0.0, 0.0], false, [8, 8, 0]),
        (
            "translated_wall",
            Some(52.0),
            [25.0, -13.0],
            false,
            [8, 8, 0],
        ),
        ("moved_wall", Some(80.0), [0.0, 0.0], false, [16, 0, 0]),
        ("facing_away", None, [0.0, 0.0], true, [0, 0, 16]),
    ];
    for (step, wall, [dx, dy], away, [visible, occluded, outside]) in cases {
        let bytes = placed_twin_package(wall, [dx, dy]);
        let digest = ContentDigest::sha256(&bytes);
        let twin = import_scene_mesh(&bytes, digest, source_scene()?)?;
        let centre = [48.0 + dx, 24.0 + dy, 10.0];
        let direction = if away { 1.0 } else { -1.0 };
        let pose = CameraPose::from_parameters(
            [96, 48],
            [10.0, 10.0, 48.0, 24.0],
            [
                [1.0, 0.0, 0.0],
                [0.0, direction, 0.0],
                [0.0, 0.0, direction],
            ],
            [-centre[0], -direction * centre[1], -direction * centre[2]],
        )?;
        let mesh = SceneMesh {
            mesh: twin.mesh(),
            package_digest: digest,
        };
        let evaluate = || {
            assess_ground_zone(
                VisibilityCamera::Pose(&pose),
                [96, 48],
                &rectangle(44.0 + dx, 16.0 + dy, 16.0, 16.0),
                Some(mesh),
                VisibilityPolicy {
                    grid: 4,
                    threshold_ppm: 500_000,
                },
            )
        };
        let result = evaluate()?;
        assert_eq!(
            [result.visible, result.occluded, result.outside_frustum],
            [visible, occluded, outside]
        );
        assert_eq!(result.samples, 16);
        assert_eq!(result.observable(), visible >= 8);
        assert_eq!(result.occlusion, Occlusion::MeshChecked(digest));
        assert_eq!(evaluate()?, result);
        println!(
            "CAPLOG {{\"step\":\"{step}\",\"verdict\":\"pass\",\"observed\":{{\"visible\":{},\"occluded\":{},\"outside\":{},\"visible_ppm\":{},\"observable\":{},\"basis\":\"{digest}\"}}}}",
            result.visible,
            result.occluded,
            result.outside_frustum,
            result.visible_fraction_ppm(),
            result.observable(),
        );
    }
    Ok(())
}

#[test]
fn wall_ray_honors_exact_budget_and_cancellation() -> TestResult {
    let bytes = twin_package(true);
    let digest = ContentDigest::sha256(&bytes);
    let twin = import_scene_mesh(&bytes, digest, source_scene()?)?;
    let mesh = twin.mesh();
    let cast = |budget: &mut WorkBudget<'_>| {
        mesh.segment_occluded(
            mesh.basis(),
            [48.0, 24.0, 10.0],
            [58.0, 24.0, 0.0],
            0.0001,
            budget,
        )
    };
    let mut budget = WorkBudget::new(100);
    assert!(cast(&mut budget)?);
    let used = budget.used();
    assert!(used > 0);
    assert!(cast(&mut WorkBudget::new(used))?);
    assert_eq!(
        cast(&mut WorkBudget::new(used - 1)),
        Err(GeometryError::BudgetExhausted)
    );
    let cancelled = AtomicBool::new(true);
    let mut budget = WorkBudget::cancellable(used, &cancelled);
    assert_eq!(cast(&mut budget), Err(GeometryError::Cancelled));
    assert_eq!(budget.used(), 0);
    println!(
        "CAPLOG {{\"step\":\"wall_ray_budget\",\"verdict\":\"pass\",\"observed\":{{\"used\":{used},\"one_less_refused\":true,\"cancelled_without_work\":true,\"basis\":\"{digest}\"}}}}"
    );
    Ok(())
}

fn source_scene() -> TestResult<ContentDigest> {
    Ok(ContentDigest::parse(format!("sha256:{}", "01".repeat(32)))?)
}

struct Recordings {
    fixture: Fixture,
    plan: CorroborationPlan,
}

fn recordings(name: &str) -> TestResult<Recordings> {
    let mut fixture = Fixture::new(name)?;
    let east = fixture.ingest(
        &format!("sensor:{name}-east"),
        &scene(true)?,
        FileFormatHint::JpegStream,
        Some(1_000_000_000),
    )?;
    let west = fixture.ingest(
        &format!("sensor:{name}-west"),
        &scene(false)?,
        FileFormatHint::JpegStream,
        Some(1_000_000_000),
    )?;
    let zone = |id: &str, x: f64| GroundZone {
        zone_id: id.to_owned(),
        x,
        y: 0.0,
        width: 40.0,
        height: 48.0,
    };
    let plan = CorroborationPlan {
        cameras: [
            CorroborationCamera {
                name: "east".to_owned(),
                import_identity: east,
                homography: GroundHomography { matrix: EAST },
            },
            CorroborationCamera {
                name: "west".to_owned(),
                import_identity: west,
                homography: GroundHomography { matrix: WEST },
            },
        ],
        interpretation: ComponentInterpretation::Grayscale,
        zones: vec![zone("door", 56.0), zone("far", 200.0)],
        gates: CorroborationGates {
            time_gate_ns: 250_000_000,
            distance_gate: 16.0,
        },
        detector: WatchDetectorConfig::default(),
        tracker: WatchTrackerConfig::default(),
    };
    Ok(Recordings { fixture, plan })
}

fn analyze(
    recordings: &Recordings,
    visibility: &GroundVisibilityPlan<'_>,
) -> TestResult<CorroborationReport> {
    Ok(CorroborationReport::analyze_with_visibility(
        &recordings.fixture.deployment,
        &recordings.plan,
        &WatchLimits::default(),
        None,
        visibility,
        &recordings.fixture.cx,
    )?)
}

fn zone<'a>(record: &'a CoverageRecord, id: &str) -> TestResult<&'a ZoneCoverage> {
    record
        .zones
        .iter()
        .find(|zone| zone.zone_id == id)
        .ok_or_else(|| format!("no zone {id}").into())
}

fn reasons(zone: &ZoneCoverage) -> Vec<&'static str> {
    zone.uncovered
        .iter()
        .map(|gap| gap.reason.as_str())
        .collect()
}

#[test]
fn without_a_mesh_coverage_is_frustum_only_and_a_zone_outside_the_frustum_is_not_observable()
-> TestResult {
    let recordings = recordings("vis-frustum")?;
    let report = analyze(&recordings, &GroundVisibilityPlan::default())?;
    // The default visibility plan is exactly `analyze`.
    let plain = CorroborationReport::analyze(
        &recordings.fixture.deployment,
        &recordings.plan,
        &WatchLimits::default(),
        &recordings.fixture.cx,
    )?;
    assert_eq!(
        plain
            .coverage()
            .iter()
            .map(CoverageRecord::to_bytes)
            .collect::<Vec<_>>(),
        report
            .coverage()
            .iter()
            .map(CoverageRecord::to_bytes)
            .collect::<Vec<_>>()
    );
    assert_eq!(report.coverage().len(), 2);
    for record in report.coverage() {
        let door = zone(record, "door")?;
        let visibility = door.visibility.as_ref().ok_or("door visibility")?;
        assert_eq!(visibility.camera_model, CameraModel::OwnerHomography);
        assert_eq!((visibility.samples, visibility.visible), (64, 64));
        assert_eq!(visibility.visible_fraction_ppm(), 1_000_000);
        assert_eq!(
            visibility.occlusion,
            Occlusion::Unknown(OcclusionUnknownReason::NoSceneMesh)
        );
        assert!(visibility.frustum_only());
        assert!(!door.witnesses.is_empty());
        for witness in &door.witnesses {
            let predicate = &witness.witness.negative_predicate;
            assert!(predicate.contains("occlusion_unknown"), "{predicate}");
            assert!(predicate.contains("frustum-only"), "{predicate}");
            assert!(predicate.contains("64 of 64 ground samples"), "{predicate}");
        }
        let far = zone(record, "far")?;
        let visibility = far.visibility.as_ref().ok_or("far visibility")?;
        assert_eq!(visibility.visible, 0);
        assert_eq!(visibility.outside_frustum, 64);
        assert!(far.witnesses.is_empty());
        assert!(
            reasons(far)
                .iter()
                .all(|reason| *reason == "outside_frustum")
        );
        assert!(matches!(
            far.uncovered.first().map(|gap| &gap.reason),
            Some(UncoveredReason::OutsideFrustum)
        ));
        assert_eq!(
            CoverageRecord::from_bytes(&record.to_bytes(), record.digest())?,
            record.clone()
        );
    }
    Ok(())
}

#[test]
fn with_poses_and_a_scene_mesh_the_zone_in_view_is_covered_and_behind_a_wall_it_is_occluded()
-> TestResult {
    let recordings = recordings("vis-mesh")?;
    let poses = poses()?;
    let source = source_scene()?;
    let open = twin_package(false);
    let walled = twin_package(true);
    let open_twin = import_scene_mesh(&open, ContentDigest::sha256(&open), source)?;
    let walled_twin = import_scene_mesh(&walled, ContentDigest::sha256(&walled), source)?;
    fn plan<'a>(
        poses: [Option<CameraPose>; 2],
        twin: &'a fss_twin::PropertyTwin,
        bytes: &[u8],
    ) -> GroundVisibilityPlan<'a> {
        GroundVisibilityPlan {
            policy: VisibilityPolicy::default(),
            poses,
            mesh: Some(SceneMesh {
                mesh: twin.mesh(),
                package_digest: ContentDigest::sha256(bytes),
            }),
        }
    }
    let covered = analyze(&recordings, &plan(poses, &open_twin, &open))?;
    let occluded = analyze(&recordings, &plan(poses, &walled_twin, &walled))?;
    let frustum = analyze(&recordings, &GroundVisibilityPlan::default())?;
    for record in covered.coverage() {
        let door = zone(record, "door")?;
        let visibility = door.visibility.as_ref().ok_or("door visibility")?;
        assert_eq!(visibility.camera_model, CameraModel::CalibratedPose);
        assert_eq!((visibility.visible, visibility.occluded), (64, 0));
        assert_eq!(visibility.visible_fraction_ppm(), 1_000_000);
        assert_eq!(
            visibility.occlusion,
            Occlusion::MeshChecked(ContentDigest::sha256(&open))
        );
        assert_eq!(visibility.claim(), "frustum_and_mesh_occlusion");
        assert!(!door.witnesses.is_empty());
        for witness in &door.witnesses {
            let predicate = &witness.witness.negative_predicate;
            assert!(
                predicate.contains("occlusion checked against owner scene mesh"),
                "{predicate}"
            );
            assert!(!predicate.contains("frustum-only"), "{predicate}");
        }
    }
    for record in occluded.coverage() {
        let door = zone(record, "door")?;
        let visibility = door.visibility.as_ref().ok_or("door visibility")?;
        assert_eq!((visibility.visible, visibility.occluded), (0, 64));
        assert!(door.witnesses.is_empty());
        assert!(reasons(door).iter().all(|reason| *reason == "occluded"));
        assert_eq!(
            reasons(door).len(),
            1,
            "one interval over the whole recording"
        );
        assert_eq!(
            CoverageRecord::from_bytes(&record.to_bytes(), record.digest())?,
            record.clone()
        );
    }
    // Candidates and events never depend on the visibility inputs; generations always do.
    for other in [&occluded, &frustum] {
        assert_eq!(
            other.to_json(0, Some("rerun"), Some("alert")),
            covered.to_json(0, Some("rerun"), Some("alert"))
        );
        for (a, b) in other.coverage().iter().zip(covered.coverage()) {
            assert_ne!(
                zone(a, "door")?.pipeline_generation,
                zone(b, "door")?.pipeline_generation
            );
            assert_ne!(a.identity(), b.identity());
        }
    }
    assert!(!covered.candidates().is_empty());
    // Deterministic.
    let again = analyze(&recordings, &plan(poses, &walled_twin, &walled))?;
    assert_eq!(
        again
            .coverage()
            .iter()
            .map(CoverageRecord::to_bytes)
            .collect::<Vec<_>>(),
        occluded
            .coverage()
            .iter()
            .map(CoverageRecord::to_bytes)
            .collect::<Vec<_>>()
    );
    for (label, report) in [
        ("retained_open", &covered),
        ("retained_occluded", &occluded),
    ] {
        for record in report.coverage() {
            let door = zone(record, "door")?;
            let visibility = door.visibility.as_ref().ok_or("door visibility")?;
            let sensor = &record.sensor_id;
            println!(
                "CAPLOG {{\"step\":\"{label}_{sensor}\",\"verdict\":\"pass\",\"observed\":{{\"zone\":\"door\",\"visible_ppm\":{},\"observable\":{},\"record\":\"{}\"}}}}",
                visibility.visible_fraction_ppm(),
                visibility.observable(),
                record.digest(),
            );
        }
    }
    Ok(())
}

#[test]
fn a_pose_that_disagrees_with_its_homography_or_frame_is_refused() -> TestResult {
    let recordings = recordings("vis-pose")?;
    let [east, west] = poses()?;
    // Swapped poses: each disagrees with its camera's homography.
    let swapped = GroundVisibilityPlan {
        policy: VisibilityPolicy::default(),
        poses: [west, east],
        mesh: None,
    };
    let refusal = CorroborationReport::analyze_with_visibility(
        &recordings.fixture.deployment,
        &recordings.plan,
        &WatchLimits::default(),
        None,
        &swapped,
        &recordings.fixture.cx,
    )
    .err()
    .ok_or("a disagreeing pose must be refused")?;
    assert_eq!(refusal.stable_id(), "ERR-CORROBORATE-POSE-INVALID-001");
    assert!(refusal.to_string().contains("disagree"), "{refusal}");
    let wide = CameraPose::from_parameters(
        [128, 48],
        [10.0, 10.0, 48.0, 24.0],
        [[1.0, 0.0, 0.0], [0.0, -1.0, 0.0], [0.0, 0.0, -1.0]],
        [-48.0, 24.0, 10.0],
    )?;
    let refusal = CorroborationReport::analyze_with_visibility(
        &recordings.fixture.deployment,
        &recordings.plan,
        &WatchLimits::default(),
        None,
        &GroundVisibilityPlan {
            policy: VisibilityPolicy::default(),
            poses: [Some(wide), None],
            mesh: None,
        },
        &recordings.fixture.cx,
    )
    .err()
    .ok_or("a pose of another frame size must be refused")?;
    assert_eq!(refusal.stable_id(), "ERR-CORROBORATE-POSE-INVALID-001");
    let policy = CorroborationReport::analyze_with_visibility(
        &recordings.fixture.deployment,
        &recordings.plan,
        &WatchLimits::default(),
        None,
        &GroundVisibilityPlan {
            policy: VisibilityPolicy {
                grid: 64,
                threshold_ppm: 1_000_000,
            },
            poses: [None, None],
            mesh: None,
        },
        &recordings.fixture.cx,
    )
    .err()
    .ok_or("an unregistered grid must be refused")?;
    assert_eq!(policy.stable_id(), "ERR-CORROBORATE-VISIBILITY-001");
    // A package whose digest does not match is refused before any visibility query.
    let package = twin_package(true);
    assert!(import_scene_mesh(&package, ContentDigest::sha256(b"other"), source_scene()?).is_err());
    Ok(())
}

#[test]
fn a_ground_zone_partly_masked_and_partly_behind_a_wall_is_privacy_masked_and_deterministic()
-> TestResult {
    let mut recordings = recordings("vis-mask")?;
    // Ground x 40..72: samples at x = 42, 46, ..., 70 (8 columns of 8). The wall at x = 52
    // hides x > 52 from both cameras (both hang above x = 48).
    recordings.plan.zones = vec![GroundZone {
        zone_id: "straddle".to_owned(),
        x: 40.0,
        y: 0.0,
        width: 32.0,
        height: 48.0,
    }];
    let poses = poses()?;
    let source = source_scene()?;
    let walled = twin_package(true);
    let twin = import_scene_mesh(&walled, ContentDigest::sha256(&walled), source)?;
    let plan = GroundVisibilityPlan {
        policy: VisibilityPolicy::default(),
        poses,
        mesh: Some(SceneMesh {
            mesh: twin.mesh(),
            package_digest: ContentDigest::sha256(&walled),
        }),
    };
    let east = |report: &CorroborationReport| -> TestResult<CoverageRecord> {
        report
            .coverage()
            .iter()
            .find(|record| record.sensor_id.ends_with("-east"))
            .cloned()
            .ok_or_else(|| "no east record".into())
    };
    let west = |report: &CorroborationReport| -> TestResult<CoverageRecord> {
        report
            .coverage()
            .iter()
            .find(|record| record.sensor_id.ends_with("-west"))
            .cloned()
            .ok_or_else(|| "no west record".into())
    };
    // Before any mask: 24 samples visible (x = 42, 46, 50), 40 behind the wall (x = 54..70).
    let unmasked = analyze(&recordings, &plan)?;
    let before = east(&unmasked)?;
    let visibility = zone(&before, "straddle")?
        .visibility
        .clone()
        .ok_or("visibility")?;
    assert_eq!(
        (
            visibility.visible,
            visibility.occluded,
            visibility.outside_frustum,
            visibility.privacy_masked
        ),
        (24, 40, 0, 0)
    );
    // East image column u = ground x: mask u 44..56 (samples x = 46, 50 visible and x = 54
    // occluded before the mask).
    let sensor = SensorId::parse("sensor:vis-mask-east")?;
    let mask = PrivacyMaskPolicy::new(sensor, [96, 48], &[[44, 0, 12, 48]])?;
    let preview = preview_mask(&recordings.fixture.deployment, &mask)?;
    declare_mask(
        &mut recordings.fixture.deployment,
        &mask,
        preview.approval,
        &recordings.fixture.cx,
    )?;
    let masked = analyze(&recordings, &plan)?;
    let record = east(&masked)?;
    let straddle = zone(&record, "straddle")?;
    let visibility = straddle.visibility.as_ref().ok_or("visibility")?;
    // Each sample counted once: masked wins over occluded, the rest keep their class.
    assert_eq!(
        (
            visibility.visible,
            visibility.occluded,
            visibility.outside_frustum,
            visibility.privacy_masked
        ),
        (8, 32, 0, 24)
    );
    assert_eq!(visibility.samples, 64);
    assert!(!visibility.observable());
    assert_eq!(visibility.cause(), Some(NotVisibleCause::PrivacyMasked));
    assert!(straddle.witnesses.is_empty());
    assert!(!reasons(straddle).is_empty());
    assert!(
        reasons(straddle)
            .iter()
            .all(|reason| *reason == "privacy_masked"),
        "{:?}",
        reasons(straddle)
    );
    // Every analysed segment is accounted for exactly once.
    let mut segments: Vec<u64> = straddle
        .uncovered
        .iter()
        .flat_map(|gap| gap.first_segment..=gap.last_segment)
        .collect();
    segments.sort_unstable();
    assert_eq!(
        segments,
        (record.first_segment..=record.last_segment).collect::<Vec<_>>()
    );
    // The mask generation is bound into the pipeline generation.
    assert_ne!(
        straddle.pipeline_generation,
        zone(&before, "straddle")?.pipeline_generation
    );
    // Version 3 (a masked sample count), canonical round trip.
    let bytes = record.to_bytes();
    // (Length-prefixed magic `FSSCOV01`: bytes 0..16; version: bytes 16..20.)
    assert_eq!(
        bytes.get(16..20),
        Some(&3_u32.to_be_bytes()[..]),
        "record version"
    );
    assert_eq!(CoverageRecord::from_bytes(&bytes, record.digest())?, record);
    assert_eq!(
        before.to_bytes().get(16..20),
        Some(&2_u32.to_be_bytes()[..])
    );
    // Version 4 is unknown; a masked count under version 2 is not decodable either.
    for version in [4_u32, 2] {
        let mut probe = bytes.clone();
        probe[16..20].copy_from_slice(&version.to_be_bytes());
        assert!(
            CoverageRecord::from_bytes(&probe, ContentDigest::sha256(&probe)).is_err(),
            "version {version} must be refused"
        );
    }
    // The unmasked west camera keeps its geometric reason.
    let other = west(&masked)?;
    let far_side = zone(&other, "straddle")?;
    let west_visibility = far_side.visibility.as_ref().ok_or("west visibility")?;
    assert_eq!(west_visibility.privacy_masked, 0);
    assert_eq!(west_visibility.cause(), Some(NotVisibleCause::Occluded));
    assert!(reasons(far_side).iter().all(|reason| *reason == "occluded"));
    // Only the authority anchor moved (the mask declaration is a ledger batch): the west
    // analysis identity and every zone are unchanged.
    let west_before = west(&unmasked)?;
    assert_eq!(other.identity(), west_before.identity());
    assert_eq!(other.zones, west_before.zones);
    // Deterministic.
    let again = analyze(&recordings, &plan)?;
    assert_eq!(east(&again)?.to_bytes(), bytes);
    assert_eq!(
        again.to_json(0, Some("rerun"), Some("alert")),
        masked.to_json(0, Some("rerun"), Some("alert"))
    );
    Ok(())
}
