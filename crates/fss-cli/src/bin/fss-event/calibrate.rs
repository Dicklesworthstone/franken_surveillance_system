#![forbid(unsafe_code)]
//! `fss-event calibrate`: owner site calibration from an atlas and per-camera observation files.
//!
//! Reads the owner twin (`FSSTWIN1`, the world frame; the same package `corroborate
//! --scene-mesh` takes) and the surveyed atlas (`FSATLAS1`), each pinned by exact digests, plus
//! one `fss.site_camera_observations.v1` file per camera: owner-supplied feature pixels with
//! descriptors in the atlas generation, and tie-point pixels. It takes correspondences, NOT
//! images: no JPEG is decoded and no feature is extracted here. Each camera is localized with the
//! existing fss-twin single-camera path, all cameras are refined jointly, and the canonical
//! digest-bound calibration (`fss.site_calibration.v1`) is written create-only to `--out` only
//! after every step succeeded; any refusal writes nothing. No deployment is opened or changed:
//! this is an owner file-to-file transform, and the result is a candidate, never an activation.

use std::ffi::OsString;
use std::fs::{self, OpenOptions};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use fss_cli::agent_json::{array, object, string, strings};
use fss_cli::{ERR_CLI_MALFORMED_VALUE, ERR_CLI_RUNTIME_FAILURE, ExitIdentity};
use fss_core::{ContentDigest, DigestAlgorithm};
use fss_reference::ingest::site_calibration::{
    CalibrationRequest, CameraObservations, ControlSelection, DEFAULT_CALIBRATION_WORK,
    MAX_CALIBRATION_BYTES, MAX_OBSERVATION_BYTES, MAX_SITE_CAMERAS, SITE_CALIBRATION_DOMAIN,
    SiteCalibration, SiteCalibrationError, calibrate_site, parameter_label, valid_camera_name,
};

/// Largest twin or atlas package read (the fss-twin format bounds).
const MAX_PACKAGE_BYTES: usize = 64 * 1024 * 1024;

const HELP: &str = "fss-event calibrate --twin FILE --twin-digest sha256:HEX --twin-source-digest sha256:HEX\n\
  --atlas FILE --atlas-digest sha256:HEX --atlas-provenance sha256:HEX\n\
  --camera NAME:OBSERVATIONS (2..16, repeat) [--control-max-error E] [--work-units N] --out FILE\n\
  Owner site calibration. The twin (FSSTWIN1) is the world frame (Z up, ground z = 0; the same\n\
  package corroborate --scene-mesh takes); the atlas (FSATLAS1) holds surveyed landmarks with\n\
  descriptors. Each observation file (fss.site_camera_observations.v1) names the camera handle\n\
  and its intrinsics/extrinsics generations, the image size and identity, the descriptor\n\
  generation, fixed intrinsics or a focal scan, then `feature ID U V HEX64` and `tie HANDLE U V`\n\
  lines. This command takes correspondences, NOT images: no pixels are decoded or extracted.\n\
  Each camera is localized alone against the atlas (most inliers, then lowest RMS, seeds it),\n\
  then all are refined jointly with the atlas landmarks as fixed control points (all of them,\n\
  or with --control-max-error only those whose declared survey error is at most E) and shared\n\
  tie points coupling the cameras. Refusals are typed and write nothing: too few or collinear\n\
  control points, a camera without a tie-point path to the others, a failed localization.\n\
  --out is created (never overwritten) with the canonical calibration; stdout reports its digest,\n\
  per-camera pose, intrinsics, covariance, before/after RMS and generation invalidators. A\n\
  candidate, never an activation; synthetic sites do not prove accuracy on real footage.\n\
  Use it with: fss-event corroborate ... --calibration FILE --calibration-digest sha256:HEX\n";

/// Parsed calibrate request.
#[derive(Debug)]
struct Request {
    twin: PathBuf,
    twin_digest: ContentDigest,
    twin_source: ContentDigest,
    atlas: PathBuf,
    atlas_digest: ContentDigest,
    atlas_provenance: ContentDigest,
    cameras: Vec<(String, PathBuf)>,
    control: ControlSelection,
    work_units: u64,
    out: PathBuf,
}

fn sha256(value: &str, key: &str) -> Result<ContentDigest, String> {
    let parsed = ContentDigest::parse(value).map_err(|_| format!("invalid digest for {key}"))?;
    if parsed.algorithm() != DigestAlgorithm::Sha256 {
        return Err(format!("{key} requires SHA-256"));
    }
    Ok(parsed)
}

fn parse(args: &[OsString]) -> Result<Request, String> {
    const SINGLE: [&str; 9] = [
        "--twin",
        "--twin-digest",
        "--twin-source-digest",
        "--atlas",
        "--atlas-digest",
        "--atlas-provenance",
        "--control-max-error",
        "--work-units",
        "--out",
    ];
    let mut values: Vec<(&str, String)> = Vec::new();
    let mut cameras: Vec<(String, PathBuf)> = Vec::new();
    let mut index = 0;
    while index < args.len() {
        let key = args[index].to_str().ok_or("option names require UTF-8")?;
        let value = args
            .get(index + 1)
            .ok_or_else(|| format!("missing value for {key}"))?
            .to_str()
            .ok_or_else(|| format!("{key} requires a UTF-8 value"))?;
        if value.is_empty() || value.starts_with("--") {
            return Err(format!("missing value for {key}"));
        }
        if key == "--camera" {
            let (name, path) = value
                .split_once(':')
                .ok_or("camera must be NAME:OBSERVATIONS_FILE")?;
            if !valid_camera_name(name) {
                return Err("camera names are 1..64 bytes of [A-Za-z0-9_.-]".to_owned());
            }
            if cameras.iter().any(|(seen, _)| seen == name) {
                return Err(format!("duplicate --camera {name}"));
            }
            if cameras.len() == MAX_SITE_CAMERAS {
                return Err("at most sixteen cameras".to_owned());
            }
            cameras.push((name.to_owned(), PathBuf::from(path)));
        } else if let Some(known) = SINGLE.iter().find(|known| **known == key) {
            if values.iter().any(|(seen, _)| seen == known) {
                return Err(format!("duplicate {key}"));
            }
            values.push((known, value.to_owned()));
        } else {
            return Err("unknown or inapplicable option".to_owned());
        }
        index += 2;
    }
    let get = |key: &str| {
        values
            .iter()
            .find(|(seen, _)| *seen == key)
            .map(|(_, value)| value.as_str())
    };
    let required = |key: &str| get(key).ok_or_else(|| format!("required option {key}"));
    if cameras.len() < 2 {
        return Err("at least two --camera NAME:OBSERVATIONS are required".to_owned());
    }
    let control = match get("--control-max-error") {
        None => ControlSelection::AllAtlasLandmarks,
        Some(text) => {
            let bound: f64 = text
                .parse()
                .map_err(|_| "--control-max-error must be a finite non-negative number")?;
            if !(bound.is_finite() && bound >= 0.0) {
                return Err("--control-max-error must be a finite non-negative number".to_owned());
            }
            ControlSelection::DeclaredErrorAtMost(bound)
        }
    };
    let work_units = match get("--work-units") {
        None => DEFAULT_CALIBRATION_WORK,
        Some(text) => text
            .parse()
            .ok()
            .filter(|units| *units > 0)
            .ok_or("--work-units must be a positive integer")?,
    };
    Ok(Request {
        twin: PathBuf::from(required("--twin")?),
        twin_digest: sha256(required("--twin-digest")?, "--twin-digest")?,
        twin_source: sha256(required("--twin-source-digest")?, "--twin-source-digest")?,
        atlas: PathBuf::from(required("--atlas")?),
        atlas_digest: sha256(required("--atlas-digest")?, "--atlas-digest")?,
        atlas_provenance: sha256(required("--atlas-provenance")?, "--atlas-provenance")?,
        cameras,
        control,
        work_units,
        out: PathBuf::from(required("--out")?),
    })
}

/// Reads a bounded regular file (never a symlink).
pub(super) fn read_bounded(path: &Path, maximum: usize, what: &str) -> io::Result<Vec<u8>> {
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.file_type().is_file() || metadata.len() > maximum as u64 {
        return Err(io::Error::other(format!(
            "{what} must be a bounded regular file, not a symlink"
        )));
    }
    let mut bytes = Vec::new();
    fs::File::open(path)?
        .take(maximum as u64 + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() > maximum {
        return Err(io::Error::other(format!("{what} exceeds its size bound")));
    }
    Ok(bytes)
}

fn number(value: f64) -> String {
    format!("{value}")
}

fn numbers(values: &[f64]) -> String {
    array(
        &values
            .iter()
            .map(|value| number(*value))
            .collect::<Vec<_>>(),
    )
}

fn hex(bytes: &[u8; 32]) -> String {
    ContentDigest::new(DigestAlgorithm::Sha256, *bytes).to_text()
}

/// Deterministic JSON summary of a calibration and its identity.
fn render(calibration: &SiteCalibration, identity: ContentDigest) -> String {
    let cameras: Vec<String> = calibration
        .cameras
        .iter()
        .map(|camera| {
            let r = camera.rotation;
            let t = camera.translation;
            let center: Vec<f64> = (0..3)
                .map(|k| -(r[0][k] * t[0] + r[1][k] * t[1] + r[2][k] * t[2]))
                .collect();
            object(&[
                ("camera", string(&camera.name)),
                ("camera_handle", camera.identity.camera.to_string()),
                (
                    "invalidated_by",
                    object(&[
                        (
                            "intrinsics_generation",
                            camera.identity.intrinsics.to_string(),
                        ),
                        (
                            "extrinsics_generation",
                            camera.identity.extrinsics.to_string(),
                        ),
                        (
                            "rule",
                            string("any change of either generation (zoom, crop, lens, move) invalidates this camera"),
                        ),
                    ]),
                ),
                ("observations_digest", string(&camera.observations.to_text())),
                (
                    "image_size",
                    array(&[
                        camera.dimensions[0].to_string(),
                        camera.dimensions[1].to_string(),
                    ]),
                ),
                ("seed_mode", string(camera.mode.as_str())),
                (
                    "seed",
                    object(&[
                        (
                            "focal_sample",
                            camera
                                .seed_sample
                                .map_or_else(|| "null".to_owned(), |s| s.to_string()),
                        ),
                        ("candidate", camera.seed_candidate.to_string()),
                        ("candidates_total", camera.seed_alternatives.to_string()),
                        ("inliers", camera.seed_inliers.to_string()),
                        ("fit_rms_px", number(camera.seed_fit_rms_px)),
                        ("selection", string("most_inliers_then_lowest_rms_then_lowest_index")),
                        ("intrinsics_fx_fy_cx_cy", numbers(&camera.seed_intrinsics)),
                    ]),
                ),
                ("intrinsics_fx_fy_cx_cy", numbers(&camera.intrinsics)),
                ("radial_k1_k2", numbers(&camera.distortion)),
                (
                    "pinhole",
                    (camera.distortion == [0.0, 0.0]).to_string(),
                ),
                (
                    "rotation_world_to_camera",
                    array(&r.iter().map(|row| numbers(row)).collect::<Vec<_>>()),
                ),
                ("translation_world_to_camera", numbers(&t)),
                ("center_world", numbers(&center)),
                (
                    "covariance",
                    object(&[
                        (
                            "parameters",
                            strings(
                                camera
                                    .covariance_parameters
                                    .iter()
                                    .map(|p| parameter_label(*p)),
                            ),
                        ),
                        ("matrix_row_major", numbers(&camera.covariance)),
                        (
                            "fixed",
                            strings(camera.fixed_parameters.iter().map(|p| parameter_label(*p))),
                        ),
                        ("model", string("local_gauss_newton_approximation")),
                    ]),
                ),
                ("seed_rms_px", number(camera.seed_rms_px)),
                ("refined_rms_px", number(camera.refined_rms_px)),
                (
                    "control_observations",
                    camera.control_observations.to_string(),
                ),
                ("tie_observations", camera.free_observations.to_string()),
            ])
        })
        .collect();
    let list = |values: &[u64]| array(&values.iter().map(u64::to_string).collect::<Vec<_>>());
    object(&[
        ("format", string(SITE_CALIBRATION_DOMAIN)),
        ("calibration_digest", string(&identity.to_text())),
        ("status", string("candidate_calibration_not_activated")),
        (
            "twin_package_digest",
            string(&calibration.twin_package.to_text()),
        ),
        (
            "twin_source_digest",
            string(&calibration.twin_source.to_text()),
        ),
        (
            "atlas_package_digest",
            string(&calibration.atlas_package.to_text()),
        ),
        (
            "atlas_fingerprint",
            string(&hex(&calibration.atlas_fingerprint)),
        ),
        (
            "atlas_provenance_digest",
            string(&calibration.atlas_provenance.to_text()),
        ),
        (
            "descriptor_domain",
            string(&hex(&calibration.descriptor_domain)),
        ),
        (
            "control_policy",
            match calibration.control_error_bound {
                None => string("all_atlas_landmarks"),
                Some(bound) => object(&[("declared_error_at_most", number(bound))]),
            },
        ),
        ("control_points", list(&calibration.control_points)),
        ("tie_points", list(&calibration.tie_points)),
        ("excluded_points", list(&calibration.excluded_points)),
        (
            "joint_solve",
            object(&[
                ("initial_rms_px", number(calibration.initial_rms_px)),
                ("final_rms_px", number(calibration.final_rms_px)),
                ("iterations", calibration.iterations.to_string()),
                ("accepted_steps", calibration.accepted_steps.to_string()),
                ("convergence", string(&calibration.convergence)),
                (
                    "observation_sigma_px",
                    number(calibration.observation_sigma_px),
                ),
                ("sigma_estimated", calibration.sigma_estimated.to_string()),
            ]),
        ),
        ("cameras", array(&cameras)),
        (
            "non_claims",
            strings([
                "inputs are owner correspondences, not decoded images",
                "atlas control positions are treated as exact",
                "covariance is a local Gauss-Newton approximation",
                "synthetic sites do not establish accuracy on real site footage",
            ]),
        ),
    ])
}

fn write_new(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(path)?;
    file.write_all(bytes)?;
    file.sync_all()
}

fn run(request: &Request) -> Result<String, Box<dyn std::error::Error>> {
    // Refuse an existing output before any work, so a refusal never follows a write.
    if fs::symlink_metadata(&request.out).is_ok() {
        return Err(
            io::Error::other("--out already exists; calibrations are never overwritten").into(),
        );
    }
    let twin = read_bounded(&request.twin, MAX_PACKAGE_BYTES, "twin package")?;
    let atlas = read_bounded(&request.atlas, MAX_PACKAGE_BYTES, "atlas package")?;
    let mut observations = Vec::with_capacity(request.cameras.len());
    for (name, path) in &request.cameras {
        let bytes = read_bounded(path, MAX_OBSERVATION_BYTES, "observation file")?;
        observations.push(CameraObservations::parse(name, &bytes)?);
    }
    let calibration = calibrate_site(
        &CalibrationRequest {
            twin_package: &twin,
            twin_digest: request.twin_digest,
            twin_source: request.twin_source,
            atlas_package: &atlas,
            atlas_digest: request.atlas_digest,
            atlas_provenance: request.atlas_provenance,
            control: request.control,
            work_units: request.work_units,
        },
        &observations,
    )?;
    let bytes = calibration.encode()?;
    // Self-check: the written bytes decode to the same record under their own identity.
    let (decoded, identity) = SiteCalibration::decode(&bytes, None)?;
    if decoded != calibration || bytes.len() > MAX_CALIBRATION_BYTES {
        return Err(SiteCalibrationError::Format("calibration failed its own round trip").into());
    }
    let summary = render(&calibration, identity);
    write_new(&request.out, &bytes)?;
    Ok(summary)
}

/// Runs `fss-event calibrate ...` with the arguments after `calibrate`.
pub(super) fn main(args: &[OsString]) -> ExitCode {
    if matches!(args, [flag] if matches!(flag.to_str(), Some("help" | "--help" | "-h"))) {
        return match io::stdout().lock().write_all(HELP.as_bytes()) {
            Ok(()) => ExitCode::from(ExitIdentity::SUCCESS.code),
            Err(_) => ExitCode::from(ExitIdentity::RUNTIME_FAILURE.code),
        };
    }
    let request = match parse(args) {
        Ok(request) => request,
        Err(reason) => {
            eprintln!("{ERR_CLI_MALFORMED_VALUE}: {reason}; use fss-event calibrate --help");
            return ExitCode::from(ExitIdentity::MALFORMED_VALUE.code);
        }
    };
    match run(&request) {
        Ok(summary) => match writeln!(io::stdout().lock(), "{summary}") {
            Ok(()) => ExitCode::from(ExitIdentity::SUCCESS.code),
            Err(_) => ExitCode::from(ExitIdentity::RUNTIME_FAILURE.code),
        },
        Err(error) => {
            eprintln!("{ERR_CLI_RUNTIME_FAILURE}: {error}");
            if let Some(refusal) = error.downcast_ref::<SiteCalibrationError>() {
                eprintln!("refusal_id={}", refusal.stable_id());
            }
            eprintln!("No calibration was written.");
            ExitCode::from(ExitIdentity::RUNTIME_FAILURE.code)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn arguments() -> Vec<OsString> {
        let digest = ContentDigest::sha256(b"pin").to_text();
        [
            "--twin",
            "twin.fsstwin",
            "--twin-digest",
            &digest,
            "--twin-source-digest",
            &digest,
            "--atlas",
            "site.fsatlas",
            "--atlas-digest",
            &digest,
            "--atlas-provenance",
            &digest,
            "--camera",
            "east:east.obs",
            "--camera",
            "west:west.obs",
            "--out",
            "site.fsscal",
        ]
        .into_iter()
        .map(OsString::from)
        .collect()
    }

    #[test]
    fn parse_requires_pins_two_cameras_and_an_output() -> Result<(), String> {
        let request = parse(&arguments())?;
        assert_eq!(request.cameras.len(), 2);
        assert_eq!(request.control, ControlSelection::AllAtlasLandmarks);
        for drop in ["--twin-digest", "--atlas-provenance", "--out"] {
            let args = arguments();
            let position = args
                .iter()
                .position(|arg| arg == drop)
                .ok_or("fixture option")?;
            let mut shorter = args.clone();
            shorter.drain(position..position + 2);
            assert!(parse(&shorter).is_err(), "{drop}");
        }
        let mut one = arguments();
        let position = one
            .iter()
            .position(|arg| arg == "west:west.obs")
            .ok_or("fixture camera")?;
        one.drain(position - 1..=position);
        assert!(parse(&one).is_err());
        let mut duplicate = arguments();
        duplicate.extend(["--camera".into(), "east:other.obs".into()]);
        assert!(parse(&duplicate).is_err());
        let mut bounded = arguments();
        bounded.extend(["--control-max-error".into(), "0.01".into()]);
        assert_eq!(
            parse(&bounded)?.control,
            ControlSelection::DeclaredErrorAtMost(0.01)
        );
        let mut negative = arguments();
        negative.extend(["--control-max-error".into(), "-1".into()]);
        assert!(parse(&negative).is_err());
        Ok(())
    }
}
