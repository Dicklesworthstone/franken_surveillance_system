#![forbid(unsafe_code)]
//! `fss-event corroborate`: two recordings, two sensors, one corroborated ground-zone entry.
//!
//! Runs `fss_reference::ingest::recorded_corroboration`: per-recording model-free tracking, foot
//! points projected through owner-supplied image→ground homographies (not calibration
//! certificates), global cross-camera association under explicit time and distance gates, and the
//! zone-entry policy. Without `--approve` nothing is written and each prepared candidate lists the
//! exact rerun command that publishes it. With exact proposal digests it publishes those events;
//! policy may report the `prepare_alert` affordance, but no alert is prepared here. Each report
//! also proposes one coverage record per camera; `--retain-coverage DIGEST` retains both exactly.
//! The detector-cascade options of `watch` add uncalibrated class evidence to each ground entry
//! (one inference budget for both recordings); it never changes the policy's event or alert.
//! Ground-zone coverage is geometric: `--visibility-grid N` and `--visibility-threshold-ppm N`
//! set the sampling policy, `--pose NAME:W,H,fx,fy,cx,cy,r11..r33,tx,ty,tz` supplies an owner
//! calibrated pose for a camera, and `--scene-mesh PATH --scene-mesh-digest sha256:HEX
//! --scene-source-digest sha256:HEX` an owner scene mesh (fss-twin package) for occlusion. Without
//! a mesh (or without a pose for a camera) occlusion is `occlusion_unknown`: frustum-only.
//! `--calibration FILE --calibration-digest sha256:HEX` supplies refined pinhole poses from an
//! `fss-event calibrate` result instead: the file is verified against the pinned digest before
//! any source is read, each named camera takes its pose (a `--pose` for the same camera, a
//! distorted camera, or a twin other than `--scene-mesh` is a typed refusal), and the report's
//! `pose_provenance` records every camera's pose source with the calibration digest.
//! Each posed camera's retained coverage record binds the same provenance (record version 4):
//! `owner_pose_argument` for a `--pose`, or the calibration digest, camera handle and
//! intrinsics/extrinsics generations. No deployment retains a camera's current generation, so
//! currency is never observed: `--camera-generation NAME:INTRINSICS:EXTRINSICS` is the owner's
//! assertion that a calibrated camera still has exactly those generations. It must match the
//! calibration (otherwise `ERR-SITE-CALIBRATION-GENERATION-STALE-001` before any source is read)
//! and is recorded as `owner_asserted_not_observed`; a calibrated camera without one is recorded
//! as `unasserted_unknown`.
//!
//! `--tolerate-decode-refusals` explicitly enables bounded recovery for both recordings. Refused
//! segments and tracking restarts remain in the report and coverage; source gaps additionally
//! exclude later frame-index capture hints from association. Custody, privacy, cancellation and
//! budget failures still abort, as does a detector cascade over a gapped range. Recovery is kept
//! in every exact approval rerun and in the post-publication coverage reanalysis.

use std::collections::BTreeSet;
use std::ffi::OsString;
use std::fs;
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};

use fss_core::{ContentDigest, DigestAlgorithm, PrincipalId};
use fss_reference::ingest::detector_cascade::DetectorCascade;
use fss_reference::ingest::ground_visibility::{
    CameraPose, SceneMesh, VisibilityPolicy, import_scene_mesh,
};
use fss_reference::ingest::package_detect::PackageDetectLimits;
use fss_reference::ingest::recorded_corroboration::{
    CorroborationCamera, CorroborationError, CorroborationGates, CorroborationOptions,
    CorroborationPlan, CorroborationReport, GroundHomography, GroundVisibilityPlan, GroundZone,
    MAX_CORROBORATION_ZONES,
};
use fss_reference::ingest::recorded_coverage::{GenerationCurrency, PoseProvenance};
use fss_reference::ingest::recorded_decode::ComponentInterpretation;
use fss_reference::ingest::recorded_watch::{WatchDetectorConfig, WatchLimits, WatchTrackerConfig};
use fss_reference::ingest::site_calibration::{
    MAX_CALIBRATION_BYTES, SiteCalibration, SiteCalibrationError,
};
use fss_reference::{ReferenceDeployment, ReplayCx, ScalarExecCx};

use super::{RunResult, export};

const OPTIONS: &[&str] = &[
    "--root",
    "--site",
    "--principal",
    "--interpretation",
    "--time-gate-ns",
    "--distance-gate",
    "--pixel-threshold",
    "--threshold-sigma",
    "--learning-rate-num",
    "--learning-rate-den",
    "--min-region-pixels",
    "--confirmation-hits",
    "--maximum-missed-frames",
    "--minimum-iou-ppm",
    "--work-units",
    "--max-dimension",
    "--max-pixels",
    "--max-segment-bytes",
    "--approve",
    "--retain-coverage",
    "--report-out",
    "--visibility-grid",
    "--visibility-threshold-ppm",
    "--scene-mesh",
    "--scene-mesh-digest",
    "--scene-source-digest",
    "--calibration",
    "--calibration-digest",
];

/// Largest owner scene-mesh package read (the fss-twin format bound).
const MAX_SCENE_MESH_BYTES: u64 = 64 * 1024 * 1024;

/// Owner scene mesh named on the command line; read and verified only in `run`.
#[derive(Debug)]
struct SceneMeshOption {
    path: PathBuf,
    package: ContentDigest,
    source_scene: ContentDigest,
}

/// Owner site calibration named on the command line; read and verified only in `run`.
#[derive(Debug)]
struct CalibrationOption {
    path: PathBuf,
    digest: ContentDigest,
}

/// Where one camera's ground-visibility pose came from.
enum PoseSource {
    None,
    Argument,
    Calibration {
        handle: u64,
        intrinsics_generation: u64,
        extrinsics_generation: u64,
        refined_rms_px: f64,
        currency: GenerationCurrency,
    },
}

/// Fully parsed corroboration request; nothing here is authority until `run` validates it.
#[derive(Debug)]
pub(super) struct CorroborateAction {
    pub(super) root: PathBuf,
    pub(super) site: String,
    pub(super) principal: String,
    plan: CorroborationPlan,
    limits: WatchLimits,
    recovery: CorroborationOptions,
    approvals: BTreeSet<ContentDigest>,
    retain_coverage: Option<ContentDigest>,
    report_out: Option<PathBuf>,
    cascade: Option<super::detector::DetectorOptions>,
    policy: VisibilityPolicy,
    poses: [Option<CameraPose>; 2],
    mesh: Option<SceneMeshOption>,
    calibration: Option<CalibrationOption>,
    /// Owner-asserted current `(camera, intrinsics, extrinsics)` generations, in argument order.
    generations: Vec<(String, u64, u64)>,
    rerun: String,
}

fn find<'a>(values: &'a [(String, String)], key: &str) -> Option<&'a str> {
    values
        .iter()
        .find(|(k, _)| k == key)
        .map(|(_, v)| v.as_str())
}

fn required<'a>(values: &'a [(String, String)], key: &str) -> Result<&'a str, String> {
    find(values, key).ok_or_else(|| format!("required option {key}"))
}

fn number<T: std::str::FromStr>(
    values: &[(String, String)],
    key: &str,
    default: T,
) -> Result<T, String> {
    match find(values, key) {
        None => Ok(default),
        Some(value) => value
            .parse()
            .map_err(|_| format!("invalid numeric value for {key}")),
    }
}

fn digest(value: &str, key: &str) -> Result<ContentDigest, String> {
    let parsed = ContentDigest::parse(value).map_err(|_| format!("invalid digest for {key}"))?;
    if parsed.algorithm() != DigestAlgorithm::Sha256 {
        return Err(format!("{key} requires SHA-256"));
    }
    Ok(parsed)
}

fn finite(text: &str, what: &str) -> Result<f64, String> {
    let value: f64 = text
        .parse()
        .map_err(|_| format!("{what} must be a finite decimal number"))?;
    if value.is_finite() {
        Ok(value)
    } else {
        Err(format!("{what} must be a finite decimal number"))
    }
}

fn zone(value: &str) -> Result<GroundZone, String> {
    let (id, geometry) = value
        .split_once(':')
        .ok_or("zone must be ID:X,Y,W,H in ground units")?;
    let parts: Vec<f64> = geometry
        .split(',')
        .map(|part| finite(part, "zone geometry"))
        .collect::<Result<_, _>>()?;
    let [x, y, width, height] = parts[..] else {
        return Err("zone geometry must be four numbers X,Y,W,H".to_owned());
    };
    Ok(GroundZone {
        zone_id: id.to_owned(),
        x,
        y,
        width,
        height,
    })
}

/// `NAME:W,H,fx,fy,cx,cy,r11,r12,r13,r21,r22,r23,r31,r32,r33,tx,ty,tz`: undistorted pinhole
/// intrinsics of the decoded image mode and a proper world-to-camera rigid transform in the
/// ground frame (Z up, ground at z = 0).
fn pose(value: &str) -> Result<(String, CameraPose), String> {
    let (name, numbers) = value
        .split_once(':')
        .ok_or("pose must be NAME:W,H,fx,fy,cx,cy,r11,...,r33,tx,ty,tz")?;
    let parts: Vec<&str> = numbers.split(',').collect();
    if parts.len() != 18 {
        return Err("pose needs eighteen comma-separated values".to_owned());
    }
    let width: u32 = parts[0]
        .parse()
        .map_err(|_| "pose width must be an unsigned integer")?;
    let height: u32 = parts[1]
        .parse()
        .map_err(|_| "pose height must be an unsigned integer")?;
    let values: Vec<f64> = parts[2..]
        .iter()
        .map(|part| finite(part, "pose entry"))
        .collect::<Result<_, _>>()?;
    let [
        fx,
        fy,
        cx,
        cy,
        r11,
        r12,
        r13,
        r21,
        r22,
        r23,
        r31,
        r32,
        r33,
        tx,
        ty,
        tz,
    ] = values[..]
    else {
        return Err("pose needs eighteen comma-separated values".to_owned());
    };
    let parsed = CameraPose::from_parameters(
        [width, height],
        [fx, fy, cx, cy],
        [[r11, r12, r13], [r21, r22, r23], [r31, r32, r33]],
        [tx, ty, tz],
    )
    .map_err(|error| format!("invalid pose: {error}"))?;
    Ok((name.to_owned(), parsed))
}

/// `NAME:INTRINSICS:EXTRINSICS`: the owner's assertion of a camera's current (nonzero)
/// generations. An assertion, never an observation.
fn camera_generation(value: &str) -> Result<(String, u64, u64), String> {
    let usage = "camera generation must be NAME:INTRINSICS:EXTRINSICS (nonzero integers)";
    let (name, rest) = value.split_once(':').ok_or(usage)?;
    let (intrinsics, extrinsics) = rest.split_once(':').ok_or(usage)?;
    let parse = |text: &str| text.parse::<u64>().ok().filter(|value| *value != 0);
    match (parse(intrinsics), parse(extrinsics)) {
        (Some(intrinsics), Some(extrinsics)) if !name.is_empty() => {
            Ok((name.to_owned(), intrinsics, extrinsics))
        }
        _ => Err(usage.to_owned()),
    }
}

fn quote(argument: &str) -> String {
    if !argument.is_empty()
        && argument
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"-_:,./=@+".contains(&b))
    {
        argument.to_owned()
    } else {
        format!("'{}'", argument.replace('\'', "'\\''"))
    }
}

/// Parses the arguments after `corroborate`. `--tolerate-decode-refusals` is a bare flag;
/// every other option takes one separate value. `--camera`, `--ground` and `--zone` repeat.
/// Paths must be UTF-8 because the report echoes rerun commands.
pub(super) fn parse(args: &[OsString]) -> Result<CorroborateAction, String> {
    let mut values: Vec<(String, String)> = Vec::new();
    let mut cameras: Vec<(String, ContentDigest)> = Vec::new();
    let mut grounds: Vec<(String, GroundHomography)> = Vec::new();
    let mut zones = Vec::new();
    let mut poses: Vec<(String, CameraPose)> = Vec::new();
    let mut generations: Vec<(String, u64, u64)> = Vec::new();
    let mut rerun = vec!["fss-event".to_owned(), "corroborate".to_owned()];
    let mut recovery = CorroborationOptions::default();
    let mut index = 0;
    while index < args.len() {
        let key = args[index].to_str().ok_or("option names require UTF-8")?;
        if key == "--tolerate-decode-refusals" {
            if recovery.tolerate_decode_refusals {
                return Err(format!("duplicate {key}"));
            }
            recovery.tolerate_decode_refusals = true;
            rerun.push(quote(key));
            index += 1;
            continue;
        }
        let argument = args
            .get(index + 1)
            .ok_or_else(|| format!("missing value for {key}"))?
            .to_str()
            .ok_or_else(|| format!("{key} requires a UTF-8 value"))?;
        if argument.is_empty() || argument.starts_with("--") {
            return Err(format!("missing value for {key}"));
        }
        match key {
            "--camera" => {
                let (name, import) = argument
                    .split_once(':')
                    .ok_or("camera must be NAME:sha256:IMPORT")?;
                if cameras.len() == 2 {
                    return Err("exactly two --camera recordings are required".to_owned());
                }
                cameras.push((name.to_owned(), digest(import, "--camera")?));
            }
            "--ground" => {
                let (name, matrix) = argument
                    .split_once(':')
                    .ok_or("ground homography must be NAME:h11,h12,h13,h21,h22,h23,h31,h32,h33")?;
                let entries: Vec<f64> = matrix
                    .split(',')
                    .map(|part| finite(part, "homography entry"))
                    .collect::<Result<_, _>>()?;
                let matrix: [f64; 9] = entries
                    .try_into()
                    .map_err(|_| "ground homography needs exactly nine row-major entries")?;
                if grounds.iter().any(|(n, _)| n == name) {
                    return Err(format!("duplicate --ground for camera {name}"));
                }
                grounds.push((name.to_owned(), GroundHomography { matrix }));
            }
            "--zone" => {
                if zones.len() == MAX_CORROBORATION_ZONES {
                    return Err("at most sixteen zones".to_owned());
                }
                zones.push(zone(argument)?);
            }
            "--pose" => {
                let (name, parsed) = pose(argument)?;
                if poses.iter().any(|(n, _)| *n == name) {
                    return Err(format!("duplicate --pose for camera {name}"));
                }
                poses.push((name, parsed));
            }
            "--camera-generation" => {
                let parsed = camera_generation(argument)?;
                if generations.iter().any(|(n, _, _)| *n == parsed.0) {
                    return Err(format!(
                        "duplicate --camera-generation for camera {}",
                        parsed.0
                    ));
                }
                generations.push(parsed);
            }
            _ if !OPTIONS.contains(&key) && !super::detector::OPTIONS.contains(&key) => {
                return Err("unknown or inapplicable option".to_owned());
            }
            _ if values.iter().any(|(k, _)| k == key) => return Err(format!("duplicate {key}")),
            _ => values.push((key.to_owned(), argument.to_owned())),
        }
        if key != "--approve" && key != "--retain-coverage" && key != "--report-out" {
            rerun.push(quote(key));
            rerun.push(quote(argument));
        }
        index += 2;
    }
    let [first, second]: [(String, ContentDigest); 2] = cameras
        .try_into()
        .map_err(|_| "exactly two --camera NAME:sha256:IMPORT recordings are required")?;
    if grounds.len() != 2 {
        return Err(
            "each camera needs exactly one --ground NAME:h11,...,h33 homography".to_owned(),
        );
    }
    let homography = |name: &str| {
        grounds
            .iter()
            .find(|(n, _)| n == name)
            .map(|(_, h)| *h)
            .ok_or_else(|| format!("missing --ground homography for camera {name}"))
    };
    let cameras = [
        CorroborationCamera {
            homography: homography(&first.0)?,
            name: first.0,
            import_identity: first.1,
        },
        CorroborationCamera {
            homography: homography(&second.0)?,
            name: second.0,
            import_identity: second.1,
        },
    ];
    if zones.is_empty() {
        return Err("at least one --zone ID:X,Y,W,H (ground units) is required".to_owned());
    }
    let mut camera_poses: [Option<CameraPose>; 2] = [None, None];
    for (name, parsed) in poses {
        let slot = cameras
            .iter()
            .position(|camera| camera.name == name)
            .ok_or_else(|| format!("--pose names no --camera: {name}"))?;
        camera_poses[slot] = Some(parsed);
    }
    let defaults = VisibilityPolicy::default();
    let policy = VisibilityPolicy {
        grid: number(&values, "--visibility-grid", defaults.grid)?,
        threshold_ppm: number(
            &values,
            "--visibility-threshold-ppm",
            defaults.threshold_ppm,
        )?,
    };
    policy
        .validate()
        .map_err(|_| "visibility grid must be 2..32 and threshold 1..1000000 ppm".to_owned())?;
    let mesh = match (
        find(&values, "--scene-mesh"),
        find(&values, "--scene-mesh-digest"),
        find(&values, "--scene-source-digest"),
    ) {
        (None, None, None) => None,
        (Some(path), Some(package), Some(source)) => Some(SceneMeshOption {
            path: PathBuf::from(path),
            package: digest(package, "--scene-mesh-digest")?,
            source_scene: digest(source, "--scene-source-digest")?,
        }),
        _ => {
            return Err(
                "--scene-mesh, --scene-mesh-digest and --scene-source-digest go together"
                    .to_owned(),
            );
        }
    };
    let calibration = match (
        find(&values, "--calibration"),
        find(&values, "--calibration-digest"),
    ) {
        (None, None) => None,
        (Some(path), Some(pinned)) => Some(CalibrationOption {
            path: PathBuf::from(path),
            digest: digest(pinned, "--calibration-digest")?,
        }),
        _ => return Err("--calibration and --calibration-digest go together".to_owned()),
    };
    if !generations.is_empty() && calibration.is_none() {
        return Err(
            "--camera-generation asserts a calibrated camera; it requires --calibration".to_owned(),
        );
    }
    for (name, _, _) in &generations {
        if !cameras.iter().any(|camera| camera.name == *name) {
            return Err(format!("--camera-generation names no --camera: {name}"));
        }
    }
    let site = required(&values, "--site")?.to_owned();
    fss_reference::reference_deployment::validate_site_lineage(&site)
        .map_err(|_| "invalid site lineage")?;
    let principal = find(&values, "--principal")
        .unwrap_or("principal:local-operator")
        .to_owned();
    PrincipalId::parse(&principal).map_err(|_| "invalid principal ID")?;
    let interpretation = match required(&values, "--interpretation")? {
        "gray" => ComponentInterpretation::Grayscale,
        "ycbcr" => ComponentInterpretation::YCbCr,
        _ => return Err("interpretation must be explicitly gray or ycbcr".to_owned()),
    };
    let time_gate_ns: u64 = required(&values, "--time-gate-ns")?
        .parse()
        .map_err(|_| "invalid numeric value for --time-gate-ns")?;
    let distance_gate = finite(required(&values, "--distance-gate")?, "--distance-gate")?;
    let defaults = WatchDetectorConfig::default();
    let detector = WatchDetectorConfig {
        base_threshold: number(&values, "--pixel-threshold", defaults.base_threshold)?,
        threshold_sigma: number(&values, "--threshold-sigma", defaults.threshold_sigma)?,
        learning_rate_num: number(&values, "--learning-rate-num", defaults.learning_rate_num)?,
        learning_rate_den: number(&values, "--learning-rate-den", defaults.learning_rate_den)?,
        minimum_region_pixels: number(
            &values,
            "--min-region-pixels",
            defaults.minimum_region_pixels,
        )?,
    };
    let defaults = WatchTrackerConfig::default();
    let tracker = WatchTrackerConfig {
        confirmation_hits: number(&values, "--confirmation-hits", defaults.confirmation_hits)?,
        maximum_missed_frames: number(
            &values,
            "--maximum-missed-frames",
            defaults.maximum_missed_frames,
        )?,
        minimum_iou_ppm: number(&values, "--minimum-iou-ppm", defaults.minimum_iou_ppm)?,
    };
    let mut limits = WatchLimits::default();
    limits.jpeg_work_units = number(&values, "--work-units", limits.jpeg_work_units)?;
    limits.read_limits.max_segment_bytes = number(
        &values,
        "--max-segment-bytes",
        limits.read_limits.max_segment_bytes,
    )?;
    let dimension: u32 = number(&values, "--max-dimension", 4096)?;
    let pixels: usize = number(&values, "--max-pixels", 4_194_304)?;
    if !(16..=4096).contains(&dimension) || pixels == 0 || pixels > 4_194_304 {
        return Err("codec limits: dimension 16..4096, pixels 1..4194304".to_owned());
    }
    limits.jpeg_limits.maximum_dimension = dimension;
    limits.jpeg_limits.maximum_pixels = pixels;
    limits.h264_limits.max_width = dimension;
    limits.h264_limits.max_height = dimension;
    limits.h264_limits.max_macroblocks =
        u32::try_from(pixels.div_ceil(256)).map_err(|_| "pixel ceiling")?;
    limits.h265_limits.max_width = dimension;
    limits.h265_limits.max_height = dimension;
    limits.h265_limits.max_luma_samples = pixels as u64;
    let mut approvals = BTreeSet::new();
    if let Some(list) = find(&values, "--approve") {
        for item in list.split(',') {
            if !approvals.insert(digest(item, "--approve")?) {
                return Err("duplicate approval digest".to_owned());
            }
        }
    }
    Ok(CorroborateAction {
        root: PathBuf::from(required(&values, "--root")?),
        site,
        principal,
        plan: CorroborationPlan {
            cameras,
            interpretation,
            zones,
            gates: CorroborationGates {
                time_gate_ns,
                distance_gate,
            },
            detector,
            tracker,
        },
        limits,
        recovery,
        approvals,
        retain_coverage: match find(&values, "--retain-coverage") {
            Some(value) => Some(digest(value, "--retain-coverage")?),
            None => None,
        },
        report_out: find(&values, "--report-out").map(PathBuf::from),
        cascade: super::detector::parse(&values)?,
        policy,
        poses: camera_poses,
        mesh,
        calibration,
        generations,
        rerun: rerun.join(" "),
    })
}

/// Reads a bounded regular scene-mesh file (never a symlink).
fn read_scene_mesh(path: &Path) -> RunResult<Vec<u8>> {
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.file_type().is_file() || metadata.len() > MAX_SCENE_MESH_BYTES {
        return Err(
            io::Error::other("scene mesh must be a bounded regular file, not a symlink").into(),
        );
    }
    let mut bytes = Vec::new();
    fs::File::open(path)?
        .take(MAX_SCENE_MESH_BYTES + 1)
        .read_to_end(&mut bytes)?;
    Ok(bytes)
}

/// Per-camera poses, their sources, and the verified calibration identity (if any).
type ResolvedPoses = (
    [Option<CameraPose>; 2],
    [PoseSource; 2],
    Option<ContentDigest>,
);

/// The retained [`PoseProvenance`] of each plan camera (none for a camera without a pose).
fn retained_provenance(
    sources: &[PoseSource; 2],
    calibration: Option<ContentDigest>,
) -> [Option<PoseProvenance>; 2] {
    let one = |source: &PoseSource| match (source, calibration) {
        (PoseSource::Argument, _) => Some(PoseProvenance::OwnerPoseArgument),
        (
            PoseSource::Calibration {
                handle,
                intrinsics_generation,
                extrinsics_generation,
                currency,
                ..
            },
            Some(calibration_digest),
        ) => Some(PoseProvenance::SiteCalibration {
            calibration_digest,
            camera_handle: *handle,
            intrinsics_generation: *intrinsics_generation,
            extrinsics_generation: *extrinsics_generation,
            currency: *currency,
        }),
        _ => None,
    };
    [one(&sources[0]), one(&sources[1])]
}

/// Verifies the pinned calibration and merges its refined pinhole poses with the `--pose` ones.
/// Refuses a camera posed twice, a distorted camera, a calibration naming no plan camera, a
/// calibration whose world frame (twin package) is not the supplied scene mesh, an owner-asserted
/// camera generation that differs from the calibrated one (stale), and an assertion for a camera
/// the calibration does not pose. All of this happens before any source is read.
fn resolve_poses(action: &CorroborateAction) -> RunResult<ResolvedPoses> {
    let mut poses = action.poses;
    let mut sources = poses.map(|pose| {
        if pose.is_some() {
            PoseSource::Argument
        } else {
            PoseSource::None
        }
    });
    let Some(option) = &action.calibration else {
        return Ok((poses, sources, None));
    };
    let bytes = super::calibrate::read_bounded(&option.path, MAX_CALIBRATION_BYTES, "calibration")?;
    let (calibration, identity) = SiteCalibration::decode(&bytes, Some(option.digest))?;
    if let Some(mesh) = &action.mesh
        && mesh.package != calibration.twin_package
    {
        return Err(SiteCalibrationError::FrameMismatch.into());
    }
    let mut named = false;
    for (index, camera) in action.plan.cameras.iter().enumerate() {
        let Some(calibrated) = calibration.camera(&camera.name) else {
            continue;
        };
        named = true;
        if poses[index].is_some() {
            return Err(SiteCalibrationError::PoseSourceConflict {
                camera: camera.name.clone(),
            }
            .into());
        }
        poses[index] = Some(calibrated.pinhole_pose()?);
        let asserted = action
            .generations
            .iter()
            .find(|(name, _, _)| *name == camera.name);
        let calibrated_generation = (
            calibrated.identity.intrinsics,
            calibrated.identity.extrinsics,
        );
        if let Some((_, intrinsics, extrinsics)) = asserted
            && (*intrinsics, *extrinsics) != calibrated_generation
        {
            return Err(SiteCalibrationError::GenerationStale {
                camera: camera.name.clone(),
                asserted: (*intrinsics, *extrinsics),
                calibrated: calibrated_generation,
            }
            .into());
        }
        sources[index] = PoseSource::Calibration {
            handle: calibrated.identity.camera,
            intrinsics_generation: calibrated.identity.intrinsics,
            extrinsics_generation: calibrated.identity.extrinsics,
            refined_rms_px: calibrated.refined_rms_px,
            currency: if asserted.is_some() {
                GenerationCurrency::OwnerAsserted
            } else {
                GenerationCurrency::Unasserted
            },
        };
    }
    if !named {
        return Err(SiteCalibrationError::NoCalibratedCamera.into());
    }
    for (name, _, _) in &action.generations {
        let calibrated = action
            .plan
            .cameras
            .iter()
            .zip(&sources)
            .any(|(camera, source)| {
                camera.name == *name && matches!(source, PoseSource::Calibration { .. })
            });
        if !calibrated {
            return Err(SiteCalibrationError::GenerationUnbound {
                camera: name.clone(),
            }
            .into());
        }
    }
    Ok((poses, sources, Some(identity)))
}

/// `pose_provenance`: one entry per plan camera naming its pose source.
fn render_pose_provenance(
    action: &CorroborateAction,
    sources: &[PoseSource; 2],
    calibration: Option<ContentDigest>,
) -> String {
    let entries: Vec<String> = action
        .plan
        .cameras
        .iter()
        .zip(sources)
        .map(|(camera, source)| {
            let name = fss_cli::agent_json::string(&camera.name);
            match (source, calibration) {
                (
                    PoseSource::Calibration {
                        handle,
                        intrinsics_generation,
                        extrinsics_generation,
                        refined_rms_px,
                        currency,
                    },
                    Some(digest),
                ) => format!(
                    concat!(
                        "{{\"camera\":{},\"source\":\"site_calibration\",",
                        "\"calibration_digest\":\"{}\",\"camera_handle\":{},",
                        "\"intrinsics_generation\":{},\"extrinsics_generation\":{},",
                        "\"generation_currency\":\"{}\",",
                        "\"refined_rms_px\":{},",
                        "\"claim\":\"candidate_calibration_not_a_certificate\"}}"
                    ),
                    name,
                    digest,
                    handle,
                    intrinsics_generation,
                    extrinsics_generation,
                    currency.as_str(),
                    refined_rms_px
                ),
                (PoseSource::Argument, _) => {
                    format!("{{\"camera\":{name},\"source\":\"owner_pose_argument\"}}")
                }
                _ => format!("{{\"camera\":{name},\"source\":\"none\"}}"),
            }
        })
        .collect();
    format!("[{}]", entries.join(","))
}

/// Analyze, optionally publish exactly the approved proposals, and print the JSON report.
pub(super) fn run(
    action: &CorroborateAction,
    deployment: &mut ReferenceDeployment,
    root: &Path,
    cx: &ReplayCx,
    out: &mut impl Write,
) -> RunResult<()> {
    let scalar = ScalarExecCx::new();
    let result = run_with(action, deployment, root, cx, &scalar, out);
    scalar.drain_and_finalize();
    result
}

fn run_with(
    action: &CorroborateAction,
    deployment: &mut ReferenceDeployment,
    root: &Path,
    cx: &ReplayCx,
    scalar: &ScalarExecCx,
    out: &mut impl Write,
) -> RunResult<()> {
    // The calibration is verified against its pinned digest before any source is read.
    let (poses, sources, calibration) = resolve_poses(action)?;
    let provenance = retained_provenance(&sources, calibration);
    let package = match &action.cascade {
        Some(options) => Some(super::detector::load(options, cx, scalar)?),
        None => None,
    };
    // The scene mesh is verified against both owner digests before any source is read.
    let twin = match &action.mesh {
        Some(option) => {
            let bytes = read_scene_mesh(&option.path)?;
            Some(
                import_scene_mesh(&bytes, option.package, option.source_scene)
                    .map_err(CorroborationError::Visibility)?,
            )
        }
        None => None,
    };
    let visibility = GroundVisibilityPlan {
        policy: action.policy,
        poses,
        mesh: match (&twin, &action.mesh) {
            (Some(twin), Some(option)) => Some(SceneMesh {
                mesh: twin.mesh(),
                package_digest: option.package,
            }),
            _ => None,
        },
    };
    let mut cascade = match (&action.cascade, &package) {
        (Some(options), Some(package)) => Some(DetectorCascade::new(
            package,
            options.config,
            PackageDetectLimits::default(),
            scalar,
        )?),
        _ => None,
    };
    let mut report = CorroborationReport::analyze_with_provenance(
        deployment,
        &action.plan,
        &action.limits,
        cascade.as_mut(),
        &visibility,
        &provenance,
        action.recovery,
        cx,
    )?;
    // Both approvals are checked against the fresh analysis before anything is written.
    if let Some(approval) = action.retain_coverage {
        report.check_coverage_approval(deployment, approval)?;
    }
    let published = if action.approvals.is_empty() {
        0
    } else {
        report.publish(deployment, &action.approvals, cx)?
    };
    if let Some(approval) = action.retain_coverage {
        report.retain_coverage(deployment, approval, cx)?;
    }
    // A coverage proposal binds the authority anchor its analysis read; after this run published
    // candidates, the proposal is recomputed against the new anchor so its approval is current.
    let reproposed = if published > 0 && action.retain_coverage.is_none() {
        Some(CorroborationReport::analyze_with_provenance(
            deployment,
            &action.plan,
            &action.limits,
            cascade.as_mut(),
            &visibility,
            &provenance,
            action.recovery,
            cx,
        )?)
    } else {
        None
    };
    let proposal = reproposed.as_ref().unwrap_or(&report);
    let records: Vec<_> = proposal.coverage().iter().collect();
    let coverage = super::coverage::render(
        &records,
        proposal.coverage_status(),
        proposal.coverage_approval(),
        &action.rerun,
    );
    let alert_hint = format!(
        "fss-event alert --root {} --site {}",
        quote(&action.root.to_string_lossy()),
        quote(&action.site)
    );
    let json = report.to_json_with_coverage(
        deployment.current_anchor().commit_sequence,
        Some(&action.rerun),
        Some(&alert_hint),
        Some(&coverage),
    );
    // Pose provenance joins the report only when some camera has a pose, so reports without
    // poses keep their exact bytes.
    let json = if poses.iter().any(Option::is_some) {
        let body = json
            .strip_suffix('}')
            .ok_or_else(|| io::Error::other("report is not one JSON object"))?;
        format!(
            "{body},\"pose_provenance\":{}}}",
            render_pose_provenance(action, &sources, calibration)
        )
    } else {
        json
    };
    let json = format!("{json}\n");
    if let Some(path) = &action.report_out {
        export(path, json.as_bytes(), root, cx)?;
    }
    out.write_all(json.as_bytes())?;
    Ok(())
}

#[cfg(test)]
mod recovery_tests {
    use super::*;

    fn arguments() -> Vec<OsString> {
        [
            "--root".to_owned(),
            "/tmp/fss-corroboration-recovery".to_owned(),
            "--site".to_owned(),
            "site:recovery-cli".to_owned(),
            "--camera".to_owned(),
            format!("east:{}", ContentDigest::sha256(b"east recording")),
            "--camera".to_owned(),
            format!("west:{}", ContentDigest::sha256(b"west recording")),
            "--ground".to_owned(),
            "east:1,0,0,0,1,0,0,0,1".to_owned(),
            "--ground".to_owned(),
            "west:1,0,0,0,1,0,0,0,1".to_owned(),
            "--zone".to_owned(),
            "door:4,4,16,16".to_owned(),
            "--interpretation".to_owned(),
            "gray".to_owned(),
            "--time-gate-ns".to_owned(),
            "250000000".to_owned(),
            "--distance-gate".to_owned(),
            "16".to_owned(),
        ]
        .into_iter()
        .map(OsString::from)
        .collect()
    }

    #[test]
    fn recovery_remains_opt_in() -> Result<(), String> {
        let action = parse(&arguments())?;
        assert_eq!(action.recovery, CorroborationOptions::default());
        assert!(!action.rerun.contains("--tolerate-decode-refusals"));
        Ok(())
    }

    #[test]
    fn recovery_flag_is_accepted_at_every_option_boundary() -> Result<(), String> {
        let plain = arguments();
        let strict = parse(&plain)?;
        for index in (0..=plain.len()).step_by(2) {
            let mut args = plain.clone();
            args.insert(index, "--tolerate-decode-refusals".into());
            let action = parse(&args)?;
            assert!(action.recovery.tolerate_decode_refusals);
            assert_eq!(
                action.rerun.matches("--tolerate-decode-refusals").count(),
                1
            );
            // Opting in does not manufacture a different clean-source plan or an approval.
            assert_eq!(action.plan.digest(), strict.plan.digest());
            assert!(action.approvals.is_empty());
            assert!(action.retain_coverage.is_none());
        }
        Ok(())
    }

    #[test]
    fn duplicate_recovery_flags_are_refused() {
        let mut args = arguments();
        args.insert(0, "--tolerate-decode-refusals".into());
        args.push("--tolerate-decode-refusals".into());
        assert!(matches!(
            parse(&args),
            Err(message) if message == "duplicate --tolerate-decode-refusals"
        ));
    }

    #[test]
    fn recovery_flag_takes_no_value() {
        for value in ["true", "false", "1", "0", "yes", ""] {
            let mut args = arguments();
            args.push("--tolerate-decode-refusals".into());
            args.push(value.into());
            assert!(parse(&args).is_err());
        }
        let mut args = arguments();
        args.push("--tolerate-decode-refusals=true".into());
        assert!(parse(&args).is_err());
    }

    #[test]
    fn flag_cannot_supply_another_options_missing_value() {
        let mut args = arguments();
        args.extend(["--work-units".into(), "--tolerate-decode-refusals".into()]);
        assert!(matches!(
            parse(&args),
            Err(message) if message == "missing value for --work-units"
        ));
    }

    #[test]
    fn approval_rerun_keeps_recovery_but_drops_prior_authority_and_export() -> Result<(), String> {
        let mut args = arguments();
        let approval = ContentDigest::sha256(b"exact candidate proposal");
        let coverage = ContentDigest::sha256(b"exact coverage proposal");
        args.extend([
            "--approve".into(),
            approval.to_string().into(),
            "--tolerate-decode-refusals".into(),
            "--retain-coverage".into(),
            coverage.to_string().into(),
            "--report-out".into(),
            "/tmp/recovery-report.json".into(),
        ]);
        let action = parse(&args)?;
        assert_eq!(action.approvals, BTreeSet::from([approval]));
        assert_eq!(action.retain_coverage, Some(coverage));
        assert_eq!(
            action.rerun.matches("--tolerate-decode-refusals").count(),
            1
        );
        assert!(!action.rerun.contains("--approve"));
        assert!(!action.rerun.contains("--retain-coverage"));
        assert!(!action.rerun.contains("--report-out"));
        // All fixture arguments are shell-safe, so the displayed command can be parsed directly.
        let replay: Vec<OsString> = action
            .rerun
            .split_whitespace()
            .skip(2)
            .map(Into::into)
            .collect();
        let replayed = parse(&replay)?;
        assert_eq!(replayed.recovery, action.recovery);
        assert_eq!(replayed.plan.digest(), action.plan.digest());
        assert!(replayed.approvals.is_empty());
        assert!(replayed.retain_coverage.is_none());
        Ok(())
    }

    #[test]
    fn recovery_rerun_still_quotes_owner_paths() -> Result<(), String> {
        let mut args = arguments();
        args[1] = "/tmp/owner's camera archive".into();
        args.push("--tolerate-decode-refusals".into());
        let action = parse(&args)?;
        assert!(action.rerun.contains("'/tmp/owner'\\''s camera archive'"));
        assert!(action.rerun.ends_with("--tolerate-decode-refusals"));
        Ok(())
    }

    #[test]
    fn recovery_does_not_relax_duplicate_or_unknown_options() {
        let mut args = arguments();
        args.push("--tolerate-decode-refusals".into());
        args.extend(["--site".into(), "site:other".into()]);
        assert!(matches!(parse(&args), Err(message) if message == "duplicate --site"));
        args.truncate(args.len() - 2);
        args.extend(["--ignore-privacy".into(), "yes".into()]);
        assert!(matches!(
            parse(&args),
            Err(message) if message == "unknown or inapplicable option"
        ));
    }
}
