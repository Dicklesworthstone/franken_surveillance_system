#![forbid(unsafe_code)]
//! `fss-event calibrate`: owner site calibration from an atlas and per-camera observation files
//! or still JPEG frames.
//!
//! Reads the owner twin (`FSSTWIN1`, the world frame; the same package `corroborate
//! --scene-mesh` takes) and the surveyed atlas (`FSATLAS1`), each pinned by exact digests, plus
//! per camera either one `fss.site_camera_observations.v1` file (owner-supplied feature pixels
//! with descriptors in the atlas generation, and tie-point pixels) or one loose baseline JPEG
//! frame with a `fss.site_camera_frame.v1` metadata file. Frames are decoded by the first-party
//! JPEG decoder and their features extracted by the fss-twin native extractor; ties between
//! frame cameras are derived by descriptor matching and gated at the seeded poses. Frames are
//! loose owner files, not retained imports: reading one frame of a retained import would need a
//! deployment and its privacy-mask decode path, which publishes derived objects, so this
//! file-to-file command does not do it. Each camera is localized with the existing fss-twin
//! single-camera path, all cameras are refined jointly, and the canonical digest-bound
//! calibration (`fss.site_calibration.v1`, or `v2` when a frame took part) is written
//! create-only to `--out` only after every step succeeded; any refusal writes nothing. No
//! deployment is opened or changed: the result is a candidate, never an activation.

use std::ffi::OsString;
use std::fs::{self, OpenOptions};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use fss_cli::agent_json::{array, object, string, strings};
use fss_cli::{ERR_CLI_MALFORMED_VALUE, ERR_CLI_RUNTIME_FAILURE, ExitIdentity};
use fss_core::{ContentDigest, DigestAlgorithm};
use fss_reference::ingest::recorded_decode::ComponentInterpretation;
use fss_reference::ingest::site_calibration::{
    CalibrationInput, CalibrationRequest, CameraFrame, CameraInput, CameraObservations,
    ControlSelection, DEFAULT_CALIBRATION_WORK, MAX_CALIBRATION_BYTES, MAX_FRAME_BYTES,
    MAX_OBSERVATION_BYTES, MAX_SITE_CAMERAS, SITE_CALIBRATION_DOMAIN, SITE_CALIBRATION_DOMAIN_V2,
    SiteCalibration, SiteCalibrationError, calibrate_site_inputs, parameter_label,
    valid_camera_name,
};

/// Largest twin or atlas package read (the fss-twin format bounds).
const MAX_PACKAGE_BYTES: usize = 64 * 1024 * 1024;

const HELP: &str = "fss-event calibrate --twin FILE --twin-digest sha256:HEX --twin-source-digest sha256:HEX\n\
  --atlas FILE --atlas-digest sha256:HEX --atlas-provenance sha256:HEX\n\
  (--camera NAME:OBSERVATIONS | --frame NAME:JPEG --frame-metadata NAME:METADATA) (2..16 cameras)\n\
  [--control-max-error E] [--work-units N] --out FILE\n\
  Owner site calibration. The twin (FSSTWIN1) is the world frame (Z up, ground z = 0; the same\n\
  package corroborate --scene-mesh takes); the atlas (FSATLAS1) holds surveyed landmarks with\n\
  descriptors. Each observation file (fss.site_camera_observations.v1) names the camera handle\n\
  and its intrinsics/extrinsics generations, the image size and identity, the descriptor\n\
  generation, fixed intrinsics or a focal scan, then `feature ID U V HEX64` and `tie HANDLE U V`\n\
  lines (owner correspondences, no pixels). A frame is one loose baseline JPEG; its metadata\n\
  file (fss.site_camera_frame.v1) has the same camera, image, exposure, image-domain and\n\
  intrinsics lines plus `interpretation gray|ycbcr`, and no pixels/descriptor/feature/tie lines:\n\
  the frame is decoded to luma (first-party decoder), features are extracted by the native\n\
  FAST-9/BRIEF extractor (the atlas must be in that descriptor generation), and ties between\n\
  frame cameras are descriptor matches of features no atlas landmark claimed, kept only when\n\
  they reproject within 2 px at the seeded poses (a lone frame camera has no tie path).\n\
  Each camera is localized alone against the atlas (most inliers, then lowest RMS, seeds it),\n\
  then all are refined jointly with the atlas landmarks as fixed control points (all of them,\n\
  or with --control-max-error only those whose declared survey error is at most E) and shared\n\
  tie points coupling the cameras. Refusals are typed and write nothing: too few or collinear\n\
  control points, a camera without a tie-point path to the others, a failed localization, a JPEG\n\
  frame the decoder refuses (ERR-SITE-CALIBRATION-FRAME-DECODE-001) or of another size than\n\
  declared. --out is created (never overwritten) with the canonical calibration; stdout reports its digest,\n\
  per-camera input kind, pose, intrinsics, covariance, before/after RMS and generation\n\
  invalidators; with a frame the record is fss.site_calibration.v2 (FSSCAL02), binding the JPEG,\n\
  metadata and luma digests and the decoder/extraction/tie policy. A\n\
  candidate, never an activation; synthetic sites do not prove accuracy on real footage.\n\
  Use it with: fss-event corroborate ... --calibration FILE --calibration-digest sha256:HEX\n";

/// One camera's input files.
#[derive(Debug)]
enum CameraSource {
    /// A `fss.site_camera_observations.v1` correspondence file.
    Observations(PathBuf),
    /// A loose JPEG frame and its `fss.site_camera_frame.v1` metadata.
    Frame { jpeg: PathBuf, metadata: PathBuf },
}

/// Parsed calibrate request.
#[derive(Debug)]
struct Request {
    twin: PathBuf,
    twin_digest: ContentDigest,
    twin_source: ContentDigest,
    atlas: PathBuf,
    atlas_digest: ContentDigest,
    atlas_provenance: ContentDigest,
    cameras: Vec<(String, CameraSource)>,
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
    let mut cameras: Vec<(String, CameraSource)> = Vec::new();
    let mut metadata: Vec<(String, PathBuf)> = Vec::new();
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
        if matches!(key, "--camera" | "--frame" | "--frame-metadata") {
            let (name, path) = value.split_once(':').ok_or(match key {
                "--camera" => "camera must be NAME:OBSERVATIONS_FILE",
                "--frame" => "frame must be NAME:JPEG_FILE",
                _ => "frame metadata must be NAME:METADATA_FILE",
            })?;
            if !valid_camera_name(name) || path.is_empty() {
                return Err("camera names are 1..64 bytes of [A-Za-z0-9_.-]".to_owned());
            }
            if key == "--frame-metadata" {
                if metadata.iter().any(|(seen, _)| seen == name) {
                    return Err(format!("duplicate --frame-metadata {name}"));
                }
                metadata.push((name.to_owned(), PathBuf::from(path)));
            } else {
                if cameras.iter().any(|(seen, _)| seen == name) {
                    return Err(format!("duplicate camera {name} (--camera or --frame)"));
                }
                if cameras.len() == MAX_SITE_CAMERAS {
                    return Err("at most sixteen cameras".to_owned());
                }
                let source = if key == "--camera" {
                    CameraSource::Observations(PathBuf::from(path))
                } else {
                    CameraSource::Frame {
                        jpeg: PathBuf::from(path),
                        metadata: PathBuf::new(),
                    }
                };
                cameras.push((name.to_owned(), source));
            }
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
    // Every frame takes exactly its own metadata file; metadata names no other camera.
    for (name, path) in metadata {
        match cameras.iter_mut().find(|(seen, _)| *seen == name) {
            Some((_, CameraSource::Frame { metadata, .. })) => *metadata = path,
            _ => return Err(format!("--frame-metadata {name} names no --frame")),
        }
    }
    if let Some((name, _)) = cameras.iter().find(|(_, source)| {
        matches!(source, CameraSource::Frame { metadata, .. } if metadata.as_os_str().is_empty())
    }) {
        return Err(format!("--frame {name} requires --frame-metadata {name}:FILE"));
    }
    if cameras.len() < 2 {
        return Err(
            "at least two cameras (--camera NAME:OBSERVATIONS or --frame NAME:JPEG) are required"
                .to_owned(),
        );
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

/// The input kind of one camera and, for a frame, its derivation identities and counts.
fn input(input: CalibrationInput) -> String {
    match input {
        CalibrationInput::Correspondences => object(&[("kind", string(input.as_str()))]),
        CalibrationInput::Frame(frame) => object(&[
            ("kind", string(input.as_str())),
            ("metadata_digest", string(&frame.metadata.to_text())),
            ("luma_digest", string(&frame.luma.to_text())),
            (
                "interpretation",
                string(match frame.interpretation {
                    ComponentInterpretation::Grayscale => "gray",
                    ComponentInterpretation::YCbCr => "ycbcr",
                }),
            ),
            ("extracted_features", frame.extracted_features.to_string()),
            ("atlas_matches", frame.atlas_matches.to_string()),
            ("tie_observations", frame.tie_observations.to_string()),
        ]),
    }
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
                // The camera's input digest: the observation file, or the JPEG bytes.
                ("observations_digest", string(&camera.observations.to_text())),
                ("input", input(camera.input)),
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
    let frames = calibration.frame_policy.is_some();
    let mut non_claims = vec![if frames {
        "frame inputs are loose owner JPEG files, not retained custody; no privacy mask was applied"
    } else {
        "inputs are owner correspondences, not decoded images"
    }];
    if frames {
        non_claims.push(
            "frame tie points are gated descriptor matches between frame cameras, not owner assertions",
        );
    }
    non_claims.extend([
        "atlas control positions are treated as exact",
        "covariance is a local Gauss-Newton approximation",
        "synthetic sites do not establish accuracy on real site footage",
    ]);
    let mut fields = vec![
        (
            "format",
            string(if frames {
                SITE_CALIBRATION_DOMAIN_V2
            } else {
                SITE_CALIBRATION_DOMAIN
            }),
        ),
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
        ("non_claims", strings(non_claims)),
    ];
    if let Some(policy) = calibration.frame_policy {
        fields.push((
            "frame_policy",
            object(&[
                ("decoder_identity", string(&hex(&policy.decoder))),
                ("fast_threshold", policy.extraction.threshold.to_string()),
                (
                    "maximum_features",
                    policy.extraction.maximum_features.to_string(),
                ),
                ("separation_px", policy.extraction.separation.to_string()),
                ("tie_max_hamming", policy.tie_max_distance.to_string()),
                ("tie_ratio_percent", policy.tie_ratio_percent.to_string()),
                ("tie_gate_px", number(policy.tie_gate_px)),
            ]),
        ));
    }
    object(&fields)
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
    let mut inputs = Vec::with_capacity(request.cameras.len());
    for (name, source) in &request.cameras {
        inputs.push(match source {
            CameraSource::Observations(path) => {
                let bytes = read_bounded(path, MAX_OBSERVATION_BYTES, "observation file")?;
                CameraInput::Correspondences(CameraObservations::parse(name, &bytes)?)
            }
            CameraSource::Frame { jpeg, metadata } => {
                let metadata = read_bounded(metadata, MAX_OBSERVATION_BYTES, "frame metadata")?;
                let jpeg = read_bounded(jpeg, MAX_FRAME_BYTES, "JPEG frame")?;
                CameraInput::Frame(CameraFrame::decode(name, &metadata, &jpeg)?)
            }
        });
    }
    let calibration = calibrate_site_inputs(
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
        &inputs,
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
