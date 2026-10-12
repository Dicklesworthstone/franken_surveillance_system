#![forbid(unsafe_code)]
//! Whole-recording geometry support through native media, retained artifacts, and real CLI
//! processes. Synthetic camera poses and covariance matrices prove the conservative support
//! boundary and replay contract; they do not qualify physical calibration or threat accuracy.

use std::ffi::OsString;
use std::fs;
use std::path::PathBuf;
use std::process::{Command, Output};

use fss_cli::json_input::{Value, parse};
use fss_core::{
    BudgetVector, ContentDigest, ContextAuthority, OperationId, RootAuthoritySpec, SensorId,
    StreamId, TimestampNs,
};
use fss_geometry::{BundleParameter, CameraGeneration};
use fss_reference::ingest::site_calibration::{
    CalibratedCamera, CalibrationInput, SeedMode, SiteCalibration,
};
use fss_reference::ingest::{CaptureHint, FileIngestAdapter, FileIngestLimits, FileIngestRequest};
use fss_reference::media_fixture::jpeg::{JpegConfig, Subsampling, encode_jpeg};
use fss_reference::{ReferenceDeployment, ReplayCx};

type Test<T = ()> = Result<T, Box<dyn std::error::Error>>;
const SITE: &str = "site:stream-corroborate-geometry-cli";
const FRAMES: usize = 170;
const APPEARANCE: usize = 150;
const EAST_GROUND: &str = "east:1,0,0,0,-1,48,0,0,1";
const WEST_GROUND: &str = "west:-1,0,96,0,1,0,0,0,1";
const EAST_POSE: &str = "east:96,48,10,10,48,24,1,0,0,0,-1,0,0,0,-1,-48,24,10";
const WEST_POSE: &str = "west:96,48,10,10,48,24,-1,0,0,0,1,0,0,0,-1,48,-24,10";
// The outer sample column is 1.56 pixels inside the nominal image. A translation sigma
// of 0.01 remains supported; a sigma of 1 makes the same nominal zone pose-sensitive.
const ZONE: &str = "door:86,4,9,40";
const SOURCE_SCENE: &str =
    "sha256:0101010101010101010101010101010101010101010101010101010101010101";

struct Directory(PathBuf);
impl Directory {
    fn new(label: &str) -> Test<Self> {
        for attempt in 0..100 {
            let path = std::env::temp_dir().join(format!(
                "fss-stream-corrob-geometry-cli-{label}-{}-{attempt}",
                std::process::id()
            ));
            match fs::create_dir(&path) {
                Ok(()) => return Ok(Self(path)),
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(error) => return Err(error.into()),
            }
        }
        Err("temporary-directory capacity".into())
    }
}
impl Drop for Directory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

struct Artifact {
    path: PathBuf,
    identity: ContentDigest,
    retained: PathBuf,
}

struct Fixture {
    directory: Directory,
    root: PathBuf,
    imports: [ContentDigest; 2],
    open_scene: Artifact,
    walled_scene: Artifact,
    tight_calibration: Artifact,
    inflated_calibration: Artifact,
}

impl Fixture {
    fn new(label: &str) -> Test<Self> {
        Self::with_luma_variation(label, false)
    }

    fn with_luma_variation(label: &str, varying: bool) -> Test<Self> {
        let directory = Directory::new(label)?;
        let root = directory.0.join("deployment with spaces");
        let authority = ContextAuthority::new_root(RootAuthoritySpec {
            trace_id: "trace:stream-corroborate-geometry-fixture".into(),
            operation_id: OperationId::parse("operation:stream-corroborate-geometry-fixture")?,
            principal: "principal:fixture".into(),
            capabilities: vec!["ADP-REPLAY-001".into()],
            deadline: None,
            priority: 10,
            budgets: BudgetVector::builder()
                .bytes(128 * 1024 * 1024)
                .storage_operations(65_536)
                .build()?,
            privacy_scope: "privacy:test".into(),
            retention_scope: "retention:test".into(),
            anchor_universe: ContentDigest::sha256(SITE.as_bytes()),
            generation: 1,
        })?;
        let cx = ReplayCx::from_context_authority(&authority, root.clone())?;
        let mut deployment = ReferenceDeployment::open(&root, SITE, &cx)?;
        let mut imports = Vec::new();
        for (index, name) in ["east", "west"].into_iter().enumerate() {
            let input = directory.0.join(format!("original-{name}.mjpeg"));
            fs::write(&input, scene(index == 1, varying)?)?;
            let mut limits = FileIngestLimits::standard();
            limits.max_segments = FRAMES + 1;
            limits.chunk_bytes = 4096;
            let request = FileIngestRequest::new(
                &input,
                SensorId::parse(format!("sensor:stream-corrob-geometry-{name}"))?,
                StreamId::parse(format!("stream:stream-corrob-geometry-{name}"))?,
            )
            .with_limits(limits)
            .with_receive_time(TimestampNs(1_000_000_000_000))
            .with_capture_hint(CaptureHint::new(
                TimestampNs(1_000_000_000),
                1_000_000,
                10.0,
            )?);
            imports.push(FileIngestAdapter::ingest(request, &cx, &mut deployment)?.import_identity);
            // Every analysis and cold replay must use the retained originals.
            fs::remove_file(input)?;
        }
        let artifact = |name: &str, bytes: &[u8], identity: ContentDigest| -> Test<Artifact> {
            let path = directory.0.join(name);
            fs::write(&path, bytes)?;
            Ok(Artifact {
                path,
                identity,
                retained: deployment
                    .publisher()
                    .spool()
                    .object_path(ContentDigest::sha256(bytes)),
            })
        };
        let open_bytes = twin_package(false);
        let open_scene = artifact(
            "open scene.fsstwin",
            &open_bytes,
            ContentDigest::sha256(&open_bytes),
        )?;
        let walled_bytes = twin_package(true);
        let walled_scene = artifact(
            "walled scene.fsstwin",
            &walled_bytes,
            ContentDigest::sha256(&walled_bytes),
        )?;
        let (tight_bytes, tight_digest) = calibration(open_scene.identity, 1e-4)?;
        let tight_calibration = artifact("tight calibration.fsscal", &tight_bytes, tight_digest)?;
        let (inflated_bytes, inflated_digest) = calibration(open_scene.identity, 1.0)?;
        let inflated_calibration = artifact(
            "inflated calibration.fsscal",
            &inflated_bytes,
            inflated_digest,
        )?;
        drop(deployment);
        cx.drain_and_finalize();
        Ok(Self {
            directory,
            root,
            imports: imports.try_into().map_err(|_| "two imports required")?,
            open_scene,
            walled_scene,
            tight_calibration,
            inflated_calibration,
        })
    }

    fn plain(&self) -> Vec<OsString> {
        vec![
            "corroborate".into(),
            "--root".into(),
            self.root.as_os_str().to_owned(),
            "--site".into(),
            SITE.into(),
            "--camera".into(),
            format!("east:{}", self.imports[0]).into(),
            "--camera".into(),
            format!("west:{}", self.imports[1]).into(),
            "--ground".into(),
            EAST_GROUND.into(),
            "--ground".into(),
            WEST_GROUND.into(),
            "--zone".into(),
            ZONE.into(),
            "--interpretation".into(),
            "gray".into(),
            "--time-gate-ns".into(),
            "250000000".into(),
            "--distance-gate".into(),
            "4".into(),
            "--stream-corroborate".into(),
        ]
    }

    fn posed(&self) -> Vec<OsString> {
        let mut args = self.plain();
        args.extend(["--pose", EAST_POSE, "--pose", WEST_POSE].map(OsString::from));
        args
    }

    fn calibrated(&self, calibration: &Artifact) -> Vec<OsString> {
        let mut args = self.plain();
        args.extend([
            "--calibration".into(),
            calibration.path.as_os_str().to_owned(),
            "--calibration-digest".into(),
            calibration.identity.to_text().into(),
            "--camera-generation".into(),
            "east:1:1".into(),
            "--camera-generation".into(),
            "west:1:1".into(),
        ]);
        args
    }

    fn adopt(&self, calibration: &Artifact) -> Vec<OsString> {
        vec![
            "calibration".into(),
            "adopt".into(),
            "--root".into(),
            self.root.as_os_str().to_owned(),
            "--site".into(),
            SITE.into(),
            "--calibration".into(),
            calibration.path.as_os_str().to_owned(),
            "--calibration-digest".into(),
            calibration.identity.to_text().into(),
            "--bind".into(),
            "east:sensor:stream-corrob-geometry-east".into(),
            "--bind".into(),
            "west:sensor:stream-corrob-geometry-west".into(),
        ]
    }

    fn read(&self, event: &str) -> Vec<OsString> {
        vec![
            "read".into(),
            "--root".into(),
            self.root.as_os_str().to_owned(),
            "--site".into(),
            SITE.into(),
            "--event-id".into(),
            event.into(),
        ]
    }

    fn verify(&self, event: &str, inspection: &Value) -> Test<Vec<OsString>> {
        Ok(vec![
            "verify".into(),
            "--root".into(),
            self.root.as_os_str().to_owned(),
            "--site".into(),
            SITE.into(),
            "--event-id".into(),
            event.into(),
            "--expected-event-revision".into(),
            text(inspection, "event_revision_digest")?.into(),
            "--expected-provenance-root".into(),
            text(inspection, "provenance_root")?.into(),
            "--execute-perception".into(),
            "yes".into(),
        ])
    }

    fn snapshot(&self) -> Test<(Vec<u8>, Vec<u8>)> {
        Ok((
            fs::read(self.root.join("ledger/journal.fssj"))?,
            fs::read(self.root.join("effects/journal.fssj"))?,
        ))
    }
}

fn with_scene(args: &mut Vec<OsString>, scene: &Artifact) {
    args.extend([
        "--scene-mesh".into(),
        scene.path.as_os_str().to_owned(),
        "--scene-mesh-digest".into(),
        scene.identity.to_text().into(),
        "--scene-source-digest".into(),
        SOURCE_SCENE.into(),
    ]);
}

fn scene(mirrored: bool, varying: bool) -> Test<Vec<u8>> {
    let config = JpegConfig {
        quality: 90,
        subsampling: Subsampling::Grayscale,
        restart_interval: 0,
        custom_markers: Vec::new(),
    };
    let left = if mirrored { 0 } else { 80 };
    let mut variants = Vec::new();
    for offset in [0_u8, 4] {
        let mut pixels = vec![40 + offset; 96 * 48];
        variants.push(encode_jpeg(96, 48, &pixels, &config)?);
        for y in 8..24 {
            for x in left..left + 16 {
                pixels[y * 96 + x] = 220 + offset;
            }
        }
        variants.push(encode_jpeg(96, 48, &pixels, &config)?);
    }
    let mut bytes = Vec::new();
    for index in 0..FRAMES {
        let phase = if varying { index % 2 } else { 0 };
        bytes.extend_from_slice(&variants[phase * 2 + usize::from(index >= APPEARANCE)]);
    }
    Ok(bytes)
}

fn put_text(out: &mut Vec<u8>, value: &str) {
    out.extend_from_slice(&(value.len() as u16).to_le_bytes());
    out.extend_from_slice(value.as_bytes());
}

/// Canonical native `FSSTWIN1`: the ground plane, optionally with an opaque x=52 wall
/// separating both cameras at (48,24,10) from the entire test zone.
fn twin_package(wall: bool) -> Vec<u8> {
    let mut body = vec![1_u8; 32];
    put_text(&mut body, "test/Z-up");
    put_text(&mut body, "synthetic");
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
    let objects: u32 = if wall { 2 } else { 1 };
    if wall {
        vertices.extend([
            [52.0, -10.0, 0.0],
            [52.0, 60.0, 0.0],
            [52.0, 60.0, 20.0],
            [52.0, -10.0, 20.0],
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
    put_text(&mut body, "ground");
    body.push(1);
    if wall {
        put_text(&mut body, "wall");
        body.push(5);
    }
    put_text(&mut body, "ground");
    body.extend_from_slice(&0_u32.to_le_bytes());
    body.extend_from_slice(&[1, 1]);
    if wall {
        put_text(&mut body, "wall");
        body.extend_from_slice(&1_u32.to_le_bytes());
        body.extend_from_slice(&[0, 1]);
    }
    for vertex in &vertices {
        for value in vertex {
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

/// The complete camera covariance partition is declared: six pose parameters are free,
/// while intrinsics and both radial coefficients are fixed. Only translation variance
/// changes between these otherwise identical calibration artifacts.
fn calibration(
    twin_package: ContentDigest,
    translation_variance: f64,
) -> Test<(Vec<u8>, ContentDigest)> {
    let input = ContentDigest::sha256(b"synthetic long corroboration calibration input");
    let pose_parameters = vec![
        BundleParameter::Rotation(0),
        BundleParameter::Rotation(1),
        BundleParameter::Rotation(2),
        BundleParameter::Translation(0),
        BundleParameter::Translation(1),
        BundleParameter::Translation(2),
    ];
    let mut covariance = vec![0.0_f64; 36];
    for index in 0..6 {
        covariance[index * 6 + index] = if index < 3 {
            1e-8
        } else {
            translation_variance
        };
    }
    let camera = |name: &str, handle: u64, rotation, translation| CalibratedCamera {
        name: name.to_owned(),
        identity: CameraGeneration {
            camera: handle,
            intrinsics: 1,
            extrinsics: 1,
        },
        observations: input,
        input: CalibrationInput::Correspondences,
        dimensions: [96, 48],
        mode: SeedMode::Fixed,
        seed_sample: None,
        seed_candidate: 0,
        seed_alternatives: 1,
        seed_inliers: 8,
        seed_fit_rms_px: 0.1,
        seed_intrinsics: [10.0, 10.0, 48.0, 24.0],
        seed_rotation: rotation,
        seed_translation: translation,
        intrinsics: [10.0, 10.0, 48.0, 24.0],
        distortion: [0.0, 0.0],
        rotation,
        translation,
        covariance_parameters: pose_parameters.clone(),
        covariance: covariance.clone(),
        fixed_parameters: vec![
            BundleParameter::Fx,
            BundleParameter::Fy,
            BundleParameter::Cx,
            BundleParameter::Cy,
            BundleParameter::K1,
            BundleParameter::K2,
        ],
        seed_rms_px: 0.1,
        refined_rms_px: 0.1,
        control_observations: 8,
        free_observations: 0,
    };
    let calibration = SiteCalibration {
        twin_package,
        twin_source: ContentDigest::parse(SOURCE_SCENE)?,
        atlas_package: ContentDigest::sha256(b"synthetic atlas"),
        atlas_fingerprint: [7; 32],
        atlas_provenance: ContentDigest::sha256(b"synthetic atlas provenance"),
        descriptor_domain: [9; 32],
        control_error_bound: None,
        initial_rms_px: 0.5,
        final_rms_px: 0.1,
        iterations: 3,
        accepted_steps: 3,
        convergence: "gradient".to_owned(),
        observation_sigma_px: 0.1,
        sigma_estimated: false,
        control_points: vec![1, 2, 3, 4],
        tie_points: vec![],
        excluded_points: vec![],
        frame_policy: None,
        cameras: vec![
            camera(
                "east",
                21,
                [[1.0, 0.0, 0.0], [0.0, -1.0, 0.0], [0.0, 0.0, -1.0]],
                [-48.0, 24.0, 10.0],
            ),
            camera(
                "west",
                22,
                [[-1.0, 0.0, 0.0], [0.0, 1.0, 0.0], [0.0, 0.0, -1.0]],
                [48.0, -24.0, 10.0],
            ),
        ],
    };
    Ok((calibration.encode()?, calibration.digest()?))
}

fn run(args: &[OsString]) -> Test<Output> {
    Ok(Command::new(env!("CARGO_BIN_EXE_fss-event"))
        .args(args)
        .output()?)
}
fn good(output: Output) -> Test<Value> {
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    Ok(parse(std::str::from_utf8(&output.stdout)?)?)
}
fn refuses(output: Output, reason: &str) {
    assert!(!output.status.success());
    assert!(output.stdout.is_empty(), "refusal emitted a success prefix");
    assert!(
        String::from_utf8_lossy(&output.stderr).contains(reason),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
}
fn member<'a>(value: &'a Value, key: &str) -> Test<&'a Value> {
    value
        .object()
        .and_then(|value| value.get(key))
        .ok_or_else(|| format!("missing field {key}").into())
}
fn text(value: &Value, key: &str) -> Test<String> {
    member(value, key)?
        .text()
        .map(str::to_owned)
        .ok_or_else(|| format!("missing string field {key}").into())
}
fn array<'a>(value: &'a Value, key: &str) -> Test<&'a [Value]> {
    member(value, key)?
        .array()
        .ok_or_else(|| format!("missing array field {key}").into())
}
fn count(value: &Value, key: &str) -> Test<i128> {
    member(value, key)?
        .integer()
        .ok_or_else(|| format!("missing integer field {key}").into())
}
fn candidate(report: &Value) -> Test<&Value> {
    let candidates = array(report, "candidates")?;
    assert_eq!(candidates.len(), 1, "{report:?}");
    Ok(&candidates[0])
}
fn geometry(camera: &Value) -> Test<&Value> {
    member(camera, "geometry_support")
}
fn zone(camera: &Value) -> Test<&Value> {
    let zones = array(geometry(camera)?, "zones")?;
    assert_eq!(zones.len(), 1);
    assert_eq!(text(&zones[0], "zone_id")?, "door");
    Ok(&zones[0])
}
fn set(args: &mut [OsString], key: &str, value: &str) -> Test {
    let index = args
        .iter()
        .position(|arg| arg == key)
        .ok_or("missing argument")?;
    *args.get_mut(index + 1).ok_or("missing argument value")? = value.into();
    Ok(())
}
fn assert_late_entries(report: &Value) -> Test {
    assert_eq!(count(report, "entry_count")?, 2);
    for camera in array(report, "cameras")? {
        assert_eq!(count(camera, "frames_decoded")?, FRAMES as i128);
    }
    for entry in array(report, "entries")? {
        assert!(count(entry, "entry_position")? >= APPEARANCE as i128);
    }
    assert_eq!(
        member(report, "physical_arrival_proved")?,
        &Value::Bool(false)
    );
    assert_eq!(member(report, "absence_certifiable")?, &Value::Bool(false));
    Ok(())
}

#[test]
fn owner_poses_support_late_entries_and_require_their_exact_geometry_approval() -> Test {
    let f = Fixture::new("owner-poses")?;
    let before = f.snapshot()?;
    let plain = good(run(&f.plain())?)?;
    let mut args = f.posed();
    let preview = good(run(&args)?)?;
    assert_late_entries(&preview)?;
    assert_eq!(text(candidate(&preview)?, "event_state")?, "corroborated");
    assert_eq!(
        text(candidate(&preview)?, "policy_action")?,
        "prepare_alert"
    );
    for camera in array(&preview, "cameras")? {
        assert_eq!(
            member(zone(camera)?, "support_available")?,
            &Value::Bool(true)
        );
        assert_eq!(member(zone(camera)?, "pose_robust")?, &Value::Null);
        assert_eq!(
            member(geometry(camera)?, "full_camera_guard")?,
            &Value::Null
        );
        assert_eq!(
            text(geometry(camera)?, "claim")?,
            "conditional_geometry_screen_not_physical_currency_or_absence"
        );
        ContentDigest::parse(text(geometry(camera)?, "recipe_digest")?)?;
        ContentDigest::parse(text(geometry(camera)?, "receipt_digest")?)?;
        assert_eq!(
            text(member(geometry(camera)?, "pose_provenance")?, "source")?,
            "owner_pose_argument"
        );
    }
    assert_ne!(
        text(&preview, "analysis_digest")?,
        text(&plain, "analysis_digest")?
    );
    assert_eq!(good(run(&args)?)?, preview);
    assert_eq!(f.snapshot()?, before);

    let approval = text(candidate(&preview)?, "proposal_digest")?;
    let mut stale_plain = args.clone();
    stale_plain.extend([
        "--approve".into(),
        text(candidate(&plain)?, "proposal_digest")?.into(),
    ]);
    refuses(run(&stale_plain)?, "ERR-CORROBORATE-APPROVAL-STALE-001");
    let mut changed_grid = args.clone();
    changed_grid.extend(["--visibility-grid", "4"].map(OsString::from));
    let changed = good(run(&changed_grid)?)?;
    assert_ne!(
        text(&changed, "analysis_digest")?,
        text(&preview, "analysis_digest")?
    );
    changed_grid.extend(["--approve".into(), approval.clone().into()]);
    refuses(run(&changed_grid)?, "ERR-CORROBORATE-APPROVAL-STALE-001");
    assert_eq!(f.snapshot()?, before);

    args.extend(["--approve".into(), approval.into()]);
    let published = good(run(&args)?)?;
    assert_eq!(text(candidate(&published)?, "status")?, "published");
    let after = f.snapshot()?;
    assert_ne!(after.0, before.0);
    assert_eq!(after.1, before.1, "publication does not dispatch an alert");
    let retry = good(run(&args)?)?;
    assert_eq!(text(candidate(&retry)?, "status")?, "already_published");
    assert_eq!(
        text(&retry, "analysis_digest")?,
        text(&preview, "analysis_digest")?
    );
    assert_eq!(f.snapshot()?, after);
    Ok(())
}

#[test]
fn disagreeing_pose_or_camera_dimensions_refuse_without_export_or_publication() -> Test {
    let f = Fixture::new("pose-refusals")?;
    let before = f.snapshot()?;
    let swapped = format!("east:{}", WEST_POSE.trim_start_matches("west:"));
    let wrong_dimensions = EAST_POSE.replacen("east:96,48", "east:95,48", 1);
    for (label, pose, reason) in [
        ("homography", swapped, "pose and ground homography disagree"),
        (
            "dimensions",
            wrong_dimensions,
            "pose dimensions differ from decoded source",
        ),
    ] {
        let output = f.directory.0.join(format!("refused-{label}.json"));
        let mut args = f.posed();
        set(&mut args, "--pose", &pose)?;
        args.extend(["--report-out".into(), output.as_os_str().to_owned()]);
        refuses(run(&args)?, reason);
        assert!(!output.exists());
        assert_eq!(f.snapshot()?, before);
    }
    Ok(())
}

#[test]
fn an_occluding_scene_preserves_ground_entries_but_removes_their_pairing_support() -> Test {
    let f = Fixture::new("occlusion")?;
    let before = f.snapshot()?;
    let mut args = f.posed();
    with_scene(&mut args, &f.walled_scene);
    let report = good(run(&args)?)?;
    assert_late_entries(&report)?;
    assert_eq!(count(&report, "candidate_count")?, 0);
    assert!(array(&report, "candidates")?.is_empty());
    for camera in array(&report, "cameras")? {
        assert_eq!(
            member(zone(camera)?, "support_available")?,
            &Value::Bool(false)
        );
        assert!(text(zone(camera)?, "visibility")?.contains("occluded"));
        assert_eq!(text(zone(camera)?, "claim")?, "frustum_and_mesh_occlusion");
    }
    for entry in array(&report, "entries")? {
        assert_eq!(text(entry, "disposition")?, "geometry_support_unavailable");
    }
    assert_eq!(good(run(&args)?)?, report);
    assert_eq!(f.snapshot()?, before);
    Ok(())
}

#[test]
fn calibration_uncertainty_withdraws_support_from_identical_nominal_ground_entries() -> Test {
    let f = Fixture::new("covariance")?;
    let before = f.snapshot()?;
    let tight = good(run(&f.calibrated(&f.tight_calibration))?)?;
    let inflated = good(run(&f.calibrated(&f.inflated_calibration))?)?;
    assert_late_entries(&tight)?;
    assert_late_entries(&inflated)?;
    // A shared calibration artifact supplies a common cause, even without a scene mesh.
    assert_eq!(text(candidate(&tight)?, "event_state")?, "witnessed");
    assert_eq!(text(candidate(&tight)?, "policy_action")?, "hold");
    assert_eq!(count(&tight, "dependency_cluster_count")?, 1);
    assert_eq!(count(&inflated, "candidate_count")?, 0);
    assert_ne!(
        text(&tight, "analysis_digest")?,
        text(&inflated, "analysis_digest")?
    );
    for (supported, unsupported) in array(&tight, "cameras")?
        .iter()
        .zip(array(&inflated, "cameras")?)
    {
        assert_eq!(
            member(zone(supported)?, "visibility")?,
            member(zone(unsupported)?, "visibility")?
        );
        assert_eq!(
            member(zone(supported)?, "support_available")?,
            &Value::Bool(true)
        );
        assert_eq!(member(zone(supported)?, "pose_robust")?, &Value::Bool(true));
        assert_eq!(
            member(zone(supported)?, "full_camera_requires_abstention")?,
            &Value::Bool(false)
        );
        assert_ne!(
            member(geometry(supported)?, "full_camera_guard")?,
            &Value::Null
        );
        assert_eq!(
            member(zone(unsupported)?, "support_available")?,
            &Value::Bool(false)
        );
        assert_eq!(
            member(zone(unsupported)?, "pose_robust")?,
            &Value::Bool(false)
        );
        assert_eq!(
            member(zone(unsupported)?, "full_camera_requires_abstention")?,
            &Value::Bool(true)
        );
    }
    for entry in array(&inflated, "entries")? {
        assert_eq!(text(entry, "disposition")?, "geometry_support_unavailable");
    }
    assert_eq!(f.snapshot()?, before);
    Ok(())
}

#[test]
fn mesh_source_and_calibration_generation_pins_refuse_mismatched_artifacts() -> Test {
    let f = Fixture::new("artifact-refusals")?;
    let before = f.snapshot()?;
    let other = ContentDigest::sha256(b"another geometry artifact").to_text();
    for key in ["--scene-mesh-digest", "--scene-source-digest"] {
        let mut args = f.posed();
        with_scene(&mut args, &f.open_scene);
        set(&mut args, key, &other)?;
        refuses(run(&args)?, "ERR-CORROBORATE-VISIBILITY-001");
        assert_eq!(f.snapshot()?, before);
    }
    let mut stale_generation = f.calibrated(&f.tight_calibration);
    set(&mut stale_generation, "--camera-generation", "east:1:2")?;
    refuses(
        run(&stale_generation)?,
        "ERR-SITE-CALIBRATION-GENERATION-STALE-001",
    );
    let mut wrong_calibration = f.calibrated(&f.tight_calibration);
    set(&mut wrong_calibration, "--calibration-digest", &other)?;
    refuses(run(&wrong_calibration)?, "ERR-SITE-CALIBRATION-");
    let mut wrong_frame = f.calibrated(&f.tight_calibration);
    with_scene(&mut wrong_frame, &f.walled_scene);
    refuses(
        run(&wrong_frame)?,
        "ERR-SITE-CALIBRATION-FRAME-MISMATCH-001",
    );
    assert_eq!(f.snapshot()?, before);
    Ok(())
}

#[test]
fn pinned_geometry_is_retained_and_cold_replayed_without_any_loose_input_files() -> Test {
    let f = Fixture::new("cold-replay")?;
    let before = f.snapshot()?;
    let mut args = f.calibrated(&f.tight_calibration);
    with_scene(&mut args, &f.open_scene);
    let preview = good(run(&args)?)?;
    assert_late_entries(&preview)?;
    assert_eq!(text(candidate(&preview)?, "event_state")?, "witnessed");
    assert_eq!(text(candidate(&preview)?, "policy_action")?, "hold");
    for camera in array(&preview, "cameras")? {
        assert_eq!(
            member(zone(camera)?, "support_available")?,
            &Value::Bool(true)
        );
    }
    args.extend([
        "--approve".into(),
        text(candidate(&preview)?, "proposal_digest")?.into(),
    ]);
    let published = good(run(&args)?)?;
    assert_eq!(text(candidate(&published)?, "status")?, "published");
    let after = f.snapshot()?;
    assert_ne!(after.0, before.0);
    assert_eq!(after.1, before.1);
    assert_eq!(
        text(candidate(&good(run(&args)?)?)?, "status")?,
        "already_published"
    );
    assert!(f.open_scene.retained.is_file());
    assert!(f.tight_calibration.retained.is_file());
    fs::remove_file(&f.open_scene.path)?;
    fs::remove_file(&f.tight_calibration.path)?;

    let event_id = text(candidate(&published)?, "event_id")?;
    let read_args = f.read(&event_id);
    let inspected = good(run(&read_args)?)?;
    assert_eq!(text(&inspected, "status")?, "inspected_not_replayed");
    assert_eq!(member(&inspected, "native_replayed")?, &Value::Bool(false));
    let event = member(&inspected, "event")?;
    let probability = member(event, "probability")?;
    assert_eq!(member(probability, "lower")?, &Value::Number("0.0".into()));
    assert_eq!(member(probability, "upper")?, &Value::Number("1.0".into()));
    assert_eq!(member(probability, "calibrationGeneration")?, &Value::Null);
    let verify_args = f.verify(&event_id, &inspected)?;
    let verified = good(run(&verify_args)?)?;
    assert_eq!(text(&verified, "status")?, "native_replay_matched");
    assert_eq!(count(&verified, "frames_replayed")?, (FRAMES * 2) as i128);
    assert_eq!(member(&verified, "event")?, event);
    assert_eq!(
        member(&verified, "physical_truth_verified")?,
        &Value::Bool(false)
    );
    assert_eq!(
        member(&verified, "persistent_verification_record_written")?,
        &Value::Bool(false)
    );
    assert_eq!(f.snapshot()?, after);

    // Both artifacts are required members of the retained proof closure, not optional
    // diagnostic files. A missing retained object refuses inspection as well as replay.
    for (label, retained) in [
        ("scene", &f.open_scene.retained),
        ("calibration", &f.tight_calibration.retained),
    ] {
        let removed = f.directory.0.join(format!("removed-retained-{label}"));
        fs::rename(retained, &removed)?;
        let missing_read = run(&read_args)?;
        let missing_verify = run(&verify_args)?;
        fs::rename(removed, retained)?;
        refuses(missing_read, "ERR-");
        refuses(missing_verify, "ERR-");
        assert_eq!(f.snapshot()?, after);
    }
    Ok(())
}

#[test]
fn a_new_sensor_adoption_invalidates_old_geometry_proof_and_requires_fresh_analysis() -> Test {
    let f = Fixture::new("adoption-currency")?;
    let before = f.snapshot()?;
    let mut args = f.calibrated(&f.tight_calibration);
    let owner_preview = good(run(&args)?)?;
    for camera in array(&owner_preview, "cameras")? {
        let provenance = member(geometry(camera)?, "pose_provenance")?;
        assert_eq!(text(provenance, "source")?, "site_calibration");
        assert_eq!(
            text(provenance, "generation_currency")?,
            "owner_asserted_not_observed"
        );
        assert_eq!(member(provenance, "adoption_receipt")?, &Value::Null);
        assert_eq!(
            text(provenance, "calibration_digest")?,
            f.tight_calibration.identity.to_text()
        );
    }
    let owner_approval = text(candidate(&owner_preview)?, "proposal_digest")?;
    args.extend(["--approve".into(), owner_approval.clone().into()]);
    let published = good(run(&args)?)?;
    assert_eq!(text(candidate(&published)?, "status")?, "published");
    let old_event = text(candidate(&published)?, "event_id")?;
    let old_read = f.read(&old_event);
    let old_inspection = good(run(&old_read)?)?;
    let old_verify = f.verify(&old_event, &old_inspection)?;
    let owner_state = f.snapshot()?;
    assert_eq!(owner_state.1, before.1);

    let mut adopt = f.adopt(&f.tight_calibration);
    let adoption_preview = good(run(&adopt)?)?;
    assert_eq!(text(&adoption_preview, "status")?, "proposed");
    assert_eq!(f.snapshot()?, owner_state);
    adopt.extend([
        "--approve".into(),
        text(&adoption_preview, "approval_digest")?.into(),
    ]);
    let adoption = good(run(&adopt)?)?;
    assert_eq!(text(&adoption, "status")?, "retained");
    let adopted_state = f.snapshot()?;
    assert_ne!(adopted_state.0, owner_state.0);
    assert_eq!(adopted_state.1, owner_state.1);

    // Even an identical calibration and asserted generation acquired new retained owner
    // authority. Its old owner-only proof must not silently become an adopted-current proof.
    refuses(
        run(&old_read)?,
        "calibration adoption basis changed; reanalyse",
    );
    refuses(
        run(&old_verify)?,
        "calibration adoption basis changed; reanalyse",
    );
    refuses(run(&args)?, "ERR-CORROBORATE-APPROVAL-STALE-001");
    assert_eq!(f.snapshot()?, adopted_state);

    let mut fresh_args = f.calibrated(&f.tight_calibration);
    let fresh = good(run(&fresh_args)?)?;
    assert_late_entries(&fresh)?;
    assert_ne!(
        text(&fresh, "analysis_digest")?,
        text(&owner_preview, "analysis_digest")?
    );
    assert_ne!(text(candidate(&fresh)?, "proposal_digest")?, owner_approval);
    assert_ne!(text(candidate(&fresh)?, "event_id")?, old_event);
    assert_eq!(text(candidate(&fresh)?, "event_state")?, "witnessed");
    for (camera, adoption_camera) in array(&fresh, "cameras")?
        .iter()
        .zip(array(&adoption, "cameras")?)
    {
        let provenance = member(geometry(camera)?, "pose_provenance")?;
        let receipt = member(adoption_camera, "receipt")?;
        assert_eq!(text(provenance, "generation_currency")?, "adopted_current");
        assert_eq!(
            text(provenance, "adoption_receipt")?,
            text(receipt, "receipt_digest")?
        );
        assert_eq!(
            count(provenance, "camera_handle")?,
            count(receipt, "camera_handle")?
        );
    }
    fresh_args.extend([
        "--approve".into(),
        text(candidate(&fresh)?, "proposal_digest")?.into(),
    ]);
    let freshly_published = good(run(&fresh_args)?)?;
    assert_eq!(text(candidate(&freshly_published)?, "status")?, "published");
    let new_event = text(candidate(&freshly_published)?, "event_id")?;
    let new_inspection = good(run(&f.read(&new_event))?)?;
    let verified = good(run(&f.verify(&new_event, &new_inspection)?)?)?;
    assert_eq!(text(&verified, "status")?, "native_replay_matched");
    assert_eq!(
        member(&verified, "event")?,
        member(&new_inspection, "event")?
    );
    assert_eq!(
        f.snapshot()?.1,
        before.1,
        "adoption and event retention dispatch no effects"
    );
    Ok(())
}

#[test]
fn health_detector_and_geometry_extensions_publish_and_replay_together() -> Test {
    // Alternating four luma levels keeps the full native screen free of clipping,
    // exact adjacent repetition, and contrast collapse without introducing new tracks.
    let f = Fixture::with_luma_variation("all-extensions", true)?;
    let package = f.directory.0.join("combined model.fmpk");
    fs::copy(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../models/yolox-nano/yolox_nano.fmpk"),
        &package,
    )?;
    const PACKAGE: &str = "sha256:5b6568750faa375de3742e5eb310fbd4e22ff26e1ba727f193b79ab984a68c74";
    let before = f.snapshot()?;
    let mut args = f.calibrated(&f.tight_calibration);
    with_scene(&mut args, &f.open_scene);
    args.extend([
        "--detector-package".into(),
        package.as_os_str().to_owned(),
        "--detector-digest".into(),
        PACKAGE.into(),
        "--detector-max-inferences".into(),
        "2".into(),
        "--detector-frames-per-track".into(),
        "1".into(),
        "--sensor-health".into(),
        "conservative-v1".into(),
    ]);
    let preview = good(run(&args)?)?;
    assert_late_entries(&preview)?;
    assert_eq!(
        member(&preview, "publication_blocked")?,
        &Value::Bool(false)
    );
    assert_eq!(text(candidate(&preview)?, "event_kind")?, "unclassified");
    assert_eq!(text(candidate(&preview)?, "event_state")?, "witnessed");
    assert_eq!(text(candidate(&preview)?, "policy_action")?, "hold");
    assert_eq!(
        count(
            member(&preview, "detector_cascade")?,
            "inferences_completed"
        )?,
        2
    );
    for camera in array(&preview, "cameras")? {
        let health = member(camera, "sensor_health")?;
        assert_eq!(text(health, "status")?, "no_findings");
        assert_eq!(member(health, "complete")?, &Value::Bool(true));
        assert_eq!(count(health, "frames_screened")?, FRAMES as i128);
        assert_eq!(member(health, "healthy_proved")?, &Value::Bool(false));
        assert_eq!(
            count(member(camera, "detector_cascade")?, "inference_count")?,
            1
        );
        assert_eq!(
            member(zone(camera)?, "support_available")?,
            &Value::Bool(true)
        );
        assert_ne!(
            member(geometry(camera)?, "full_camera_guard")?,
            &Value::Null
        );
    }
    for entry in array(&preview, "entries")? {
        assert_eq!(array(entry, "class_evidence")?.len(), 1);
    }
    assert_eq!(f.snapshot()?, before);
    args.extend([
        "--approve".into(),
        text(candidate(&preview)?, "proposal_digest")?.into(),
    ]);
    let published = good(run(&args)?)?;
    assert_eq!(text(candidate(&published)?, "status")?, "published");
    let after = f.snapshot()?;
    assert_ne!(after.0, before.0);
    assert_eq!(after.1, before.1);
    fs::remove_file(package)?;
    fs::remove_file(&f.tight_calibration.path)?;
    fs::remove_file(&f.open_scene.path)?;

    // Cold parsing must consume health, detector, and geometry in their canonical order;
    // native replay must reproduce all three from the same retained source/model/scene.
    let event_id = text(candidate(&published)?, "event_id")?;
    let inspected = good(run(&f.read(&event_id))?)?;
    assert_eq!(text(&inspected, "status")?, "inspected_not_replayed");
    assert_eq!(
        text(member(&inspected, "retained_detector")?, "package_digest")?,
        PACKAGE
    );
    let verified = good(run(&f.verify(&event_id, &inspected)?)?)?;
    assert_eq!(text(&verified, "status")?, "native_replay_matched");
    assert_eq!(count(&verified, "frames_replayed")?, (FRAMES * 2) as i128);
    let event = member(&verified, "event")?;
    assert_eq!(event, member(&inspected, "event")?);
    let probability = member(event, "probability")?;
    assert_eq!(member(probability, "lower")?, &Value::Number("0.0".into()));
    assert_eq!(member(probability, "upper")?, &Value::Number("1.0".into()));
    assert_eq!(member(probability, "calibrationGeneration")?, &Value::Null);
    assert!(array(event, "modelReceipts")?.is_empty());
    assert_eq!(f.snapshot()?, after);
    Ok(())
}
