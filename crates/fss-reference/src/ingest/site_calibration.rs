#![forbid(unsafe_code)]
//! Owner site calibration: per-camera atlas localization, joint refinement, and a canonical
//! digest-bound calibration record that ground-zone visibility can consume.
//!
//! Inputs are the owner's property twin (`FSSTWIN1`), a surveyed localization atlas
//! (`FSATLAS1`, fss-twin `atlas_archive`), each pinned by exact digests, and one observation
//! file per camera (`fss.site_camera_observations.v1`, documented on
//! [`CameraObservations::parse`]). An observation file carries owner-supplied image features
//! (pixel plus 256-bit descriptor in the atlas descriptor generation) and tie-point pixels; it is
//! NOT an image. This module decodes no pixels and extracts no features: the fss-twin native
//! extractor exists but is not wired here, so every feature is an owner assertion.
//!
//! Each camera is localized independently through the existing fss-twin single-camera path
//! (`LocalizationAtlas::localize` for fixed intrinsics, `localize_focal_scan` for a focal scan);
//! the candidate with the most inliers (then lowest RMS, then lowest index) seeds
//! `refine_site_jointly`, which anchors the gauge on the atlas control points and couples cameras
//! through shared tie points. Every failure is a typed refusal and no partial calibration exists:
//! [`calibrate_site`] returns a [`SiteCalibration`] only after every camera localized and the
//! joint solve converged.
//!
//! The record (`FSSCAL01`, digest domain `fss.site_calibration.v1`) carries per camera the
//! refined pinhole intrinsics, radial distortion, world-to-camera pose, the adjuster's local
//! covariance, seed and refined RMS, its `CameraGeneration` invalidators and the observation-file
//! digest, plus the twin and atlas digests and the joint solve report. Its identity is the
//! trailing SHA-256 over the domain tag and the exact bytes; [`SiteCalibration::decode`]
//! refuses any byte change, any noncanonical encoding and any expected-digest mismatch.
//!
//! Non-claims: a candidate calibration, never an activation or accuracy certificate; atlas
//! control positions are treated as exact; covariance is a local Gauss-Newton approximation;
//! synthetic sites do not establish accuracy on real site footage.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use fss_core::{CanonicalDecoder, CanonicalEncoder, ContentDigest, DigestAlgorithm};
use fss_geometry::{
    BundleParameter, CameraGeneration, Convergence, FocalSampleOutcome, FocalScanOptions,
    PinholeIntrinsics, PoseSearch, PoseSolverOptions, RadialDistortion, RigidPose, WorkBudget,
};
use fss_twin::atlas_archive::{ArchiveExpectation, decode_atlas};
use fss_twin::focal_localization::{FocalLocalizationOutcome, localize_focal_scan};
use fss_twin::joint_refinement::{
    JointCamera, JointOptions, JointRefinementError, LocalizationSeed, TieObservation,
    refine_site_jointly,
};
use fss_twin::localization::{
    BinaryDescriptor, CameraLocalization, FeatureFrame, ImageFeature, ImageIdentity,
    LocalizationCamera, LocalizationOutcome, MAX_IMAGE_FEATURES, MatchOptions,
};

use super::ground_visibility::{CameraPose, import_scene_mesh};

/// Control-point selection of the joint solve (fss-twin), re-exported for callers.
pub use fss_twin::joint_refinement::ControlSelection;

/// Registered digest domain of the calibration record (`SCHEMA-DOMAIN-SITE-CALIBRATION-001`).
pub const SITE_CALIBRATION_DOMAIN: &str = "fss.site_calibration.v1";
/// Leading magic of a calibration file.
pub const SITE_CALIBRATION_MAGIC: &[u8; 8] = b"FSSCAL01";
/// First line of a camera observation file.
pub const OBSERVATIONS_FORMAT: &str = "fss.site_camera_observations.v1";
/// Largest calibration file read or written.
pub const MAX_CALIBRATION_BYTES: usize = 4 * 1024 * 1024;
/// Largest camera observation file read.
pub const MAX_OBSERVATION_BYTES: usize = 1024 * 1024;
/// Cameras of one site calibration.
pub const MAX_SITE_CAMERAS: usize = 16;
/// Tie observations of one camera.
pub const MAX_CAMERA_TIES: usize = 1024;
/// Default geometry work units of one calibration.
pub const DEFAULT_CALIBRATION_WORK: u64 = 4_000_000_000;

/// Typed calibration refusal (production or consumption). Nothing partial is ever returned.
#[derive(Clone, Debug, PartialEq)]
pub enum SiteCalibrationError {
    /// A camera list, name or observation file is malformed or out of bounds.
    InvalidInput {
        /// Camera name, or empty for request-level input.
        camera: String,
        /// Why.
        reason: String,
    },
    /// The twin or atlas package was refused (digest, format, basis, descriptor generation).
    Basis(String),
    /// A camera could not be localized against the atlas.
    LocalizationFailed {
        /// Camera name.
        camera: String,
        /// Why (insufficient matches, geometric failure, no candidate).
        reason: String,
    },
    /// Fewer than three (or collinear) atlas control points constrain the joint solve.
    TooFewControlPoints {
        /// Distinct control points observed (0 when collinear).
        observed: usize,
        /// Whether the refusal is collinearity rather than count.
        collinear: bool,
    },
    /// Shared tie points do not connect this camera to the others.
    DisconnectedCameras {
        /// Camera name.
        camera: String,
    },
    /// The joint refinement refused (bundle adjuster, degenerate tie, budget, limits).
    Refinement(String),
    /// Calibration bytes are malformed or not canonical.
    Format(&'static str),
    /// The calibration identity differs from its bytes or from the owner-pinned digest.
    Digest,
    /// A camera's refined model carries radial distortion; a pinhole consumer cannot use it.
    Distorted {
        /// Camera name.
        camera: String,
    },
    /// A camera received a pose from both `--pose` and the calibration.
    PoseSourceConflict {
        /// Camera name.
        camera: String,
    },
    /// The calibration names none of the consumer's cameras.
    NoCalibratedCamera,
    /// The calibration world frame (twin package) differs from the consumer's scene mesh.
    FrameMismatch,
}

impl SiteCalibrationError {
    /// Registered stable error identity (`registries/ERRORS.md`).
    #[must_use]
    pub fn stable_id(&self) -> &'static str {
        match self {
            Self::InvalidInput { .. } => "ERR-SITE-CALIBRATION-INPUT-INVALID-001",
            Self::Basis(_) => "ERR-SITE-CALIBRATION-BASIS-001",
            Self::LocalizationFailed { .. } => "ERR-SITE-CALIBRATION-LOCALIZATION-FAILED-001",
            Self::TooFewControlPoints { .. } => "ERR-SITE-CALIBRATION-CONTROL-POINTS-001",
            Self::DisconnectedCameras { .. } => "ERR-SITE-CALIBRATION-DISCONNECTED-001",
            Self::Refinement(_) => "ERR-SITE-CALIBRATION-REFINEMENT-001",
            Self::Format(_) => "ERR-SITE-CALIBRATION-FORMAT-001",
            Self::Digest => "ERR-SITE-CALIBRATION-DIGEST-001",
            Self::Distorted { .. } => "ERR-SITE-CALIBRATION-DISTORTED-001",
            Self::PoseSourceConflict { .. } => "ERR-CORROBORATE-POSE-SOURCE-CONFLICT-001",
            Self::NoCalibratedCamera => "ERR-SITE-CALIBRATION-CAMERA-UNBOUND-001",
            Self::FrameMismatch => "ERR-SITE-CALIBRATION-FRAME-MISMATCH-001",
        }
    }
}

impl fmt::Display for SiteCalibrationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidInput { camera, reason } if camera.is_empty() => {
                write!(f, "invalid calibration input: {reason}")
            }
            Self::InvalidInput { camera, reason } => {
                write!(f, "invalid observations of camera {camera}: {reason}")
            }
            Self::Basis(reason) => write!(f, "twin or atlas refused: {reason}"),
            Self::LocalizationFailed { camera, reason } => {
                write!(f, "camera {camera} could not be localized: {reason}")
            }
            Self::TooFewControlPoints {
                collinear: true, ..
            } => f.write_str("atlas control points are collinear; the metric gauge is not fixed"),
            Self::TooFewControlPoints { observed, .. } => write!(
                f,
                "{observed} atlas control point(s) constrain the solve; at least 3 are required"
            ),
            Self::DisconnectedCameras { camera } => write!(
                f,
                "camera {camera} shares no tie-point path with the other cameras"
            ),
            Self::Refinement(reason) => write!(f, "joint refinement refused: {reason}"),
            Self::Format(reason) => write!(f, "malformed site calibration: {reason}"),
            Self::Digest => f.write_str(
                "site calibration digest mismatch (bytes changed or another calibration)",
            ),
            Self::Distorted { camera } => write!(
                f,
                "camera {camera} was refined with radial distortion; a pinhole pose cannot represent it"
            ),
            Self::PoseSourceConflict { camera } => write!(
                f,
                "camera {camera} has both a --pose and a calibrated pose; supply exactly one"
            ),
            Self::NoCalibratedCamera => {
                f.write_str("the calibration names none of the corroborated cameras")
            }
            Self::FrameMismatch => f.write_str(
                "the calibration world frame (twin package) differs from the scene mesh",
            ),
        }
    }
}

impl std::error::Error for SiteCalibrationError {}

fn invalid(camera: &str, reason: impl Into<String>) -> SiteCalibrationError {
    SiteCalibrationError::InvalidInput {
        camera: camera.to_owned(),
        reason: reason.into(),
    }
}

/// How one camera's intrinsics enter localization.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum IntrinsicsSpec {
    /// Known undistorted pinhole intrinsics, held fixed through the joint solve.
    Fixed {
        /// `[fx, fy, cx, cy]` in pixels.
        parameters: [f64; 4],
    },
    /// Unknown focal length scanned over a range; the joint solve refines it aspect-held.
    Focal {
        /// Lowest scanned `fx`.
        minimum_fx: f64,
        /// Highest scanned `fx`.
        maximum_fx: f64,
        /// Logarithmic samples, 3..=129.
        samples: usize,
        /// Held `fy / fx`.
        y_over_x: f64,
        /// Held principal point.
        principal_point: [f64; 2],
    },
}

/// One camera's owner-supplied localization observations (not an image).
#[derive(Clone, Debug)]
pub struct CameraObservations {
    /// Owner camera name (matches `fss-event corroborate --camera NAME`).
    pub name: String,
    /// Camera handle and immutable intrinsics/extrinsics generations.
    pub identity: CameraGeneration,
    /// Source image identity the observations were taken from.
    pub image: ImageIdentity,
    /// Descriptor generation of every feature (must equal the atlas generation).
    pub descriptor_domain: [u8; 32],
    /// Intrinsics handling.
    pub intrinsics: IntrinsicsSpec,
    /// Image features matched against the atlas by descriptor.
    pub features: Vec<ImageFeature>,
    /// Tie observations `(tie handle, pixel)` of non-atlas points shared with other cameras.
    pub ties: Vec<(u64, [f64; 2])>,
    /// SHA-256 of the exact observation-file bytes.
    pub file_digest: ContentDigest,
}

fn parse_digest(camera: &str, value: &str) -> Result<[u8; 32], SiteCalibrationError> {
    let digest = ContentDigest::parse(value).map_err(|_| invalid(camera, "invalid digest"))?;
    if digest.algorithm() != DigestAlgorithm::Sha256 || digest.bytes() == [0; 32] {
        return Err(invalid(camera, "digests must be nonzero SHA-256"));
    }
    Ok(digest.bytes())
}

fn parse_finite(camera: &str, value: &str) -> Result<f64, SiteCalibrationError> {
    let parsed: f64 = value
        .parse()
        .map_err(|_| invalid(camera, "numbers must be finite decimals"))?;
    if parsed.is_finite() {
        Ok(parsed)
    } else {
        Err(invalid(camera, "numbers must be finite decimals"))
    }
}

fn parse_integer<T: std::str::FromStr>(
    camera: &str,
    value: &str,
) -> Result<T, SiteCalibrationError> {
    value
        .parse()
        .map_err(|_| invalid(camera, "handles and sizes must be unsigned integers"))
}

fn parse_descriptor(camera: &str, value: &str) -> Result<BinaryDescriptor, SiteCalibrationError> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
    {
        return Err(invalid(
            camera,
            "descriptors must be 64 lower-case hex digits",
        ));
    }
    let mut words = [0_u64; 4];
    for (index, word) in words.iter_mut().enumerate() {
        let chunk = value
            .get(index * 16..index * 16 + 16)
            .ok_or_else(|| invalid(camera, "descriptor length"))?;
        *word = u64::from_str_radix(chunk, 16).map_err(|_| invalid(camera, "descriptor hex"))?;
    }
    Ok(BinaryDescriptor(words))
}

/// Valid owner camera name: 1..=64 bytes of `[A-Za-z0-9_.-]`.
#[must_use]
pub fn valid_camera_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 64
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"_.-".contains(&b))
}

impl CameraObservations {
    /// Parses one observation file. UTF-8 lines; blank lines and `#` comments are ignored; the
    /// first content line is `fss.site_camera_observations.v1`; then, each exactly once:
    ///
    /// ```text
    /// camera HANDLE INTRINSICS_GENERATION EXTRINSICS_GENERATION   (all nonzero)
    /// image WIDTH HEIGHT                                          (undistorted pixel grid)
    /// exposure sha256:HEX          pixels sha256:HEX              (source image identity)
    /// image-domain sha256:HEX      descriptor-domain sha256:HEX
    /// intrinsics fixed FX FY CX CY
    ///   or intrinsics focal MIN_FX MAX_FX SAMPLES Y_OVER_X CX CY
    /// ```
    ///
    /// then any number of `feature ID U V DESCRIPTOR` (pixel centres, 64 lower-case hex digits;
    /// at most 512) and `tie HANDLE U V` (at most 1024) lines. Unknown or repeated keywords,
    /// non-finite numbers and zero handles are refused.
    pub fn parse(name: &str, bytes: &[u8]) -> Result<Self, SiteCalibrationError> {
        if !valid_camera_name(name) {
            return Err(invalid(
                name,
                "camera names are 1..64 bytes of [A-Za-z0-9_.-]",
            ));
        }
        if bytes.len() > MAX_OBSERVATION_BYTES {
            return Err(invalid(name, "observation file exceeds 1 MiB"));
        }
        let text = std::str::from_utf8(bytes).map_err(|_| invalid(name, "not UTF-8"))?;
        let mut lines = text
            .lines()
            .map(str::trim)
            .filter(|line| !line.is_empty() && !line.starts_with('#'));
        if lines.next() != Some(OBSERVATIONS_FORMAT) {
            return Err(invalid(
                name,
                "first line must be fss.site_camera_observations.v1",
            ));
        }
        let mut identity = None;
        let mut dimensions = None;
        let mut exposure = None;
        let mut pixels = None;
        let mut image_domain = None;
        let mut descriptor_domain = None;
        let mut intrinsics = None;
        let mut features = Vec::new();
        let mut ties: Vec<(u64, [f64; 2])> = Vec::new();
        fn once<T>(slot: &mut Option<T>, value: T, name: &str) -> Result<(), SiteCalibrationError> {
            if slot.is_some() {
                return Err(invalid(name, "a header keyword is repeated"));
            }
            *slot = Some(value);
            Ok(())
        }
        for line in lines {
            let fields: Vec<&str> = line.split_ascii_whitespace().collect();
            match fields.as_slice() {
                ["camera", handle, intrinsic, extrinsic] => {
                    let generation = CameraGeneration {
                        camera: parse_integer(name, handle)?,
                        intrinsics: parse_integer(name, intrinsic)?,
                        extrinsics: parse_integer(name, extrinsic)?,
                    };
                    if generation.camera == 0
                        || generation.intrinsics == 0
                        || generation.extrinsics == 0
                    {
                        return Err(invalid(name, "camera handle and generations are nonzero"));
                    }
                    once(&mut identity, generation, name)?;
                }
                ["image", width, height] => {
                    let size: [u32; 2] =
                        [parse_integer(name, width)?, parse_integer(name, height)?];
                    if size.iter().any(|n| *n == 0 || *n > 65_536) {
                        return Err(invalid(name, "image size must be 1..65536"));
                    }
                    once(&mut dimensions, size, name)?;
                }
                ["exposure", value] => once(&mut exposure, parse_digest(name, value)?, name)?,
                ["pixels", value] => once(&mut pixels, parse_digest(name, value)?, name)?,
                ["image-domain", value] => {
                    once(&mut image_domain, parse_digest(name, value)?, name)?;
                }
                ["descriptor-domain", value] => {
                    once(&mut descriptor_domain, parse_digest(name, value)?, name)?;
                }
                ["intrinsics", "fixed", fx, fy, cx, cy] => {
                    let parameters = [
                        parse_finite(name, fx)?,
                        parse_finite(name, fy)?,
                        parse_finite(name, cx)?,
                        parse_finite(name, cy)?,
                    ];
                    once(&mut intrinsics, IntrinsicsSpec::Fixed { parameters }, name)?;
                }
                ["intrinsics", "focal", low, high, samples, ratio, cx, cy] => {
                    let spec = IntrinsicsSpec::Focal {
                        minimum_fx: parse_finite(name, low)?,
                        maximum_fx: parse_finite(name, high)?,
                        samples: parse_integer(name, samples)?,
                        y_over_x: parse_finite(name, ratio)?,
                        principal_point: [parse_finite(name, cx)?, parse_finite(name, cy)?],
                    };
                    once(&mut intrinsics, spec, name)?;
                }
                ["feature", id, u, v, descriptor] => {
                    if features.len() == MAX_IMAGE_FEATURES {
                        return Err(invalid(name, "at most 512 features"));
                    }
                    features.push(ImageFeature {
                        id: parse_integer(name, id)?,
                        pixel: [parse_finite(name, u)?, parse_finite(name, v)?],
                        descriptor: parse_descriptor(name, descriptor)?,
                    });
                }
                ["tie", handle, u, v] => {
                    if ties.len() == MAX_CAMERA_TIES {
                        return Err(invalid(name, "at most 1024 tie observations"));
                    }
                    let tie: u64 = parse_integer(name, handle)?;
                    if tie == 0 || ties.iter().any(|(seen, _)| *seen == tie) {
                        return Err(invalid(name, "tie handles are nonzero and unique"));
                    }
                    ties.push((tie, [parse_finite(name, u)?, parse_finite(name, v)?]));
                }
                _ => {
                    return Err(invalid(
                        name,
                        format!(
                            "unrecognized line: {}",
                            fields.first().copied().unwrap_or("")
                        ),
                    ));
                }
            }
        }
        let missing = |what: &str| invalid(name, format!("missing {what} line"));
        let dimensions = dimensions.ok_or_else(|| missing("image"))?;
        for (_, pixel) in &ties {
            if (0..2).any(|axis| pixel[axis] < 0.0 || pixel[axis] >= f64::from(dimensions[axis])) {
                return Err(invalid(name, "tie pixel outside the image"));
            }
        }
        ties.sort_by_key(|(tie, _)| *tie);
        Ok(Self {
            name: name.to_owned(),
            identity: identity.ok_or_else(|| missing("camera"))?,
            image: ImageIdentity {
                exposure: exposure.ok_or_else(|| missing("exposure"))?,
                pixels: pixels.ok_or_else(|| missing("pixels"))?,
                image_domain: image_domain.ok_or_else(|| missing("image-domain"))?,
                dimensions,
            },
            descriptor_domain: descriptor_domain.ok_or_else(|| missing("descriptor-domain"))?,
            intrinsics: intrinsics.ok_or_else(|| missing("intrinsics"))?,
            features,
            ties,
            file_digest: ContentDigest::sha256(bytes),
        })
    }
}

/// Owner request of one site calibration; every package is pinned by exact digests.
#[derive(Clone, Copy, Debug)]
pub struct CalibrationRequest<'a> {
    /// `FSSTWIN1` property twin bytes (the world frame; the same package corroborate's
    /// `--scene-mesh` takes).
    pub twin_package: &'a [u8],
    /// Owner-pinned SHA-256 of the twin package.
    pub twin_digest: ContentDigest,
    /// Owner-pinned source-scene digest of the twin.
    pub twin_source: ContentDigest,
    /// `FSATLAS1` atlas bytes built against that twin.
    pub atlas_package: &'a [u8],
    /// Owner-pinned SHA-256 of the atlas package.
    pub atlas_digest: ContentDigest,
    /// Owner-pinned atlas provenance manifest digest.
    pub atlas_provenance: ContentDigest,
    /// Control-point selection over atlas landmarks.
    pub control: ControlSelection,
    /// Geometry work units for the whole calibration.
    pub work_units: u64,
}

/// Which intrinsics mode seeded a camera.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SeedMode {
    /// Fixed intrinsics (held through the joint solve).
    Fixed,
    /// Focal scan (aspect-held focal refined jointly).
    Focal,
}

impl SeedMode {
    /// Stable label.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Fixed => "fixed_intrinsics",
            Self::Focal => "focal_scan",
        }
    }
}

/// One calibrated camera of the record.
#[derive(Clone, Debug, PartialEq)]
pub struct CalibratedCamera {
    /// Owner camera name.
    pub name: String,
    /// Generation the estimate depends on: a changed intrinsics or extrinsics generation
    /// (zoom, crop, lens, move) invalidates this camera's entry.
    pub identity: CameraGeneration,
    /// SHA-256 of the exact observation file.
    pub observations: ContentDigest,
    /// Undistorted pixel grid.
    pub dimensions: [u32; 2],
    /// Seed intrinsics mode.
    pub mode: SeedMode,
    /// Focal sample of the selected seed (focal scans only).
    pub seed_sample: Option<u64>,
    /// Candidate index of the selected seed in its pose search.
    pub seed_candidate: u64,
    /// Candidates the localization produced in total (the selection is the caller policy:
    /// most inliers, then lowest RMS, then lowest index).
    pub seed_alternatives: u64,
    /// Inlier landmarks of the selected seed.
    pub seed_inliers: u64,
    /// Single-camera fit RMS (px) of the selected seed.
    pub seed_fit_rms_px: f64,
    /// Seed `[fx, fy, cx, cy]`.
    pub seed_intrinsics: [f64; 4],
    /// Seed world-to-camera rotation (row-major).
    pub seed_rotation: [[f64; 3]; 3],
    /// Seed world-to-camera translation.
    pub seed_translation: [f64; 3],
    /// Refined `[fx, fy, cx, cy]`.
    pub intrinsics: [f64; 4],
    /// Refined radial `[k1, k2]` (both zero for a pinhole camera).
    pub distortion: [f64; 2],
    /// Refined world-to-camera rotation (row-major).
    pub rotation: [[f64; 3]; 3],
    /// Refined world-to-camera translation.
    pub translation: [f64; 3],
    /// Free parameters of the covariance, in block order.
    pub covariance_parameters: Vec<BundleParameter>,
    /// Row-major `k x k` covariance.
    pub covariance: Vec<f64>,
    /// Parameters held fixed by the gauge or the refinement choice.
    pub fixed_parameters: Vec<BundleParameter>,
    /// RMS (px) of this camera's joint observations at the seed.
    pub seed_rms_px: f64,
    /// RMS (px) of the same observations after refinement.
    pub refined_rms_px: f64,
    /// Fixed control-point observations.
    pub control_observations: u64,
    /// Free-landmark (tie) observations.
    pub free_observations: u64,
}

impl CalibratedCamera {
    /// World-to-camera pinhole pose for ground-zone visibility; refuses a distorted camera.
    pub fn pinhole_pose(&self) -> Result<CameraPose, SiteCalibrationError> {
        if self.distortion != [0.0, 0.0] {
            return Err(SiteCalibrationError::Distorted {
                camera: self.name.clone(),
            });
        }
        let [fx, fy, cx, cy] = self.intrinsics;
        let format =
            |_| SiteCalibrationError::Format("camera geometry is not a valid pinhole pose");
        Ok(CameraPose {
            intrinsics: PinholeIntrinsics::new(
                self.dimensions[0],
                self.dimensions[1],
                fx,
                fy,
                cx,
                cy,
            )
            .map_err(format)?,
            pose: RigidPose::new(self.rotation, self.translation).map_err(format)?,
        })
    }
}

/// A converged candidate site calibration; never an activation.
#[derive(Clone, Debug, PartialEq)]
pub struct SiteCalibration {
    /// SHA-256 of the twin package (the world frame).
    pub twin_package: ContentDigest,
    /// Twin source-scene digest.
    pub twin_source: ContentDigest,
    /// SHA-256 of the atlas package.
    pub atlas_package: ContentDigest,
    /// Normalized atlas fingerprint (fss-twin `LocalizationAtlas::digest`).
    pub atlas_fingerprint: [u8; 32],
    /// Atlas provenance manifest digest.
    pub atlas_provenance: ContentDigest,
    /// Descriptor generation of the atlas and every observation.
    pub descriptor_domain: [u8; 32],
    /// Control policy: `None` holds every used atlas landmark fixed; `Some(bound)` only those
    /// with a declared per-axis survey error at most `bound`.
    pub control_error_bound: Option<f64>,
    /// Joint RMS (px) at the seeds.
    pub initial_rms_px: f64,
    /// Joint RMS (px) after refinement.
    pub final_rms_px: f64,
    /// Linear-solve attempts.
    pub iterations: u64,
    /// Accepted LM steps.
    pub accepted_steps: u64,
    /// Convergence label.
    pub convergence: String,
    /// Observation sigma (px) that scaled the covariance.
    pub observation_sigma_px: f64,
    /// Whether the sigma was estimated from residuals.
    pub sigma_estimated: bool,
    /// Atlas landmarks held fixed as control points.
    pub control_points: Vec<u64>,
    /// Tie handles adjusted as free landmarks.
    pub tie_points: Vec<u64>,
    /// Points seen by fewer than two cameras and therefore not used.
    pub excluded_points: Vec<u64>,
    /// Calibrated cameras, sorted by camera handle.
    pub cameras: Vec<CalibratedCamera>,
}

fn parameter_code(parameter: BundleParameter) -> u8 {
    match parameter {
        BundleParameter::Rotation(axis) => axis.min(2) as u8,
        BundleParameter::Translation(axis) => 3 + axis.min(2) as u8,
        BundleParameter::Focal => 6,
        BundleParameter::Fx => 7,
        BundleParameter::Fy => 8,
        BundleParameter::Cx => 9,
        BundleParameter::Cy => 10,
        BundleParameter::K1 => 11,
        BundleParameter::K2 => 12,
    }
}

fn parameter_from_code(code: u8) -> Option<BundleParameter> {
    Some(match code {
        0..=2 => BundleParameter::Rotation(usize::from(code)),
        3..=5 => BundleParameter::Translation(usize::from(code - 3)),
        6 => BundleParameter::Focal,
        7 => BundleParameter::Fx,
        8 => BundleParameter::Fy,
        9 => BundleParameter::Cx,
        10 => BundleParameter::Cy,
        11 => BundleParameter::K1,
        12 => BundleParameter::K2,
        _ => return None,
    })
}

/// Stable label of a covariance parameter.
#[must_use]
pub fn parameter_label(parameter: BundleParameter) -> &'static str {
    match parameter_code(parameter) {
        0 => "rotation_x",
        1 => "rotation_y",
        2 => "rotation_z",
        3 => "translation_x",
        4 => "translation_y",
        5 => "translation_z",
        6 => "focal",
        7 => "fx",
        8 => "fy",
        9 => "cx",
        10 => "cy",
        11 => "k1",
        _ => "k2",
    }
}

fn convergence_label(convergence: Convergence) -> &'static str {
    match convergence {
        Convergence::Gradient => "gradient",
        Convergence::CostStalled => "cost_stalled",
        Convergence::StepTolerance => "step_tolerance",
        Convergence::ZeroResidual => "zero_residual",
    }
}

const CONVERGENCE_LABELS: [&str; 4] = [
    "gradient",
    "cost_stalled",
    "step_tolerance",
    "zero_residual",
];

fn put_f64(e: &mut CanonicalEncoder, value: f64) {
    e.u64(value.to_bits());
}

fn put_raw(e: &mut CanonicalEncoder, value: &[u8; 32]) {
    e.bytes(value);
}

fn put_list(e: &mut CanonicalEncoder, values: &[u64]) {
    e.u64(values.len() as u64);
    for value in values {
        e.u64(*value);
    }
}

fn domain_digest(framed: &[u8]) -> ContentDigest {
    let mut tagged = Vec::with_capacity(SITE_CALIBRATION_DOMAIN.len() + 1 + framed.len());
    tagged.extend_from_slice(SITE_CALIBRATION_DOMAIN.as_bytes());
    tagged.push(0);
    tagged.extend_from_slice(framed);
    ContentDigest::sha256(&tagged)
}

impl SiteCalibration {
    fn validate(&self) -> Result<(), SiteCalibrationError> {
        let format = SiteCalibrationError::Format;
        let finite = |values: &[f64]| values.iter().all(|x| x.is_finite());
        if self.cameras.is_empty() || self.cameras.len() > MAX_SITE_CAMERAS {
            return Err(format("camera count outside 1..16"));
        }
        if !finite(&[
            self.initial_rms_px,
            self.final_rms_px,
            self.observation_sigma_px,
        ]) || self
            .control_error_bound
            .is_some_and(|b| !b.is_finite() || b < 0.0)
            || !CONVERGENCE_LABELS.contains(&self.convergence.as_str())
        {
            return Err(format("solve report is not finite or not registered"));
        }
        let mut names = BTreeSet::new();
        for (index, camera) in self.cameras.iter().enumerate() {
            if !valid_camera_name(&camera.name) || !names.insert(camera.name.as_str()) {
                return Err(format("camera names must be valid and unique"));
            }
            if index > 0 && self.cameras[index - 1].identity.camera >= camera.identity.camera {
                return Err(format("cameras must be in strictly ascending handle order"));
            }
            let k = camera.covariance_parameters.len();
            let geometry: Vec<f64> = camera
                .seed_intrinsics
                .iter()
                .chain(&camera.intrinsics)
                .chain(&camera.distortion)
                .chain(camera.seed_rotation.iter().flatten())
                .chain(&camera.seed_translation)
                .chain(camera.rotation.iter().flatten())
                .chain(&camera.translation)
                .chain(&camera.covariance)
                .copied()
                .chain([
                    camera.seed_fit_rms_px,
                    camera.seed_rms_px,
                    camera.refined_rms_px,
                ])
                .collect();
            if !finite(&geometry)
                || camera.covariance.len() != k * k
                || camera.identity.camera == 0
                || camera.identity.intrinsics == 0
                || camera.identity.extrinsics == 0
                || camera.dimensions.iter().any(|n| *n == 0 || *n > 65_536)
            {
                return Err(format("camera geometry is not finite or not well formed"));
            }
        }
        Ok(())
    }

    fn encode_body(&self) -> Result<Vec<u8>, SiteCalibrationError> {
        self.validate()?;
        let mut e = CanonicalEncoder::new();
        e.text(SITE_CALIBRATION_DOMAIN);
        e.digest(self.twin_package);
        e.digest(self.twin_source);
        e.digest(self.atlas_package);
        put_raw(&mut e, &self.atlas_fingerprint);
        e.digest(self.atlas_provenance);
        put_raw(&mut e, &self.descriptor_domain);
        match self.control_error_bound {
            None => e.tag(0),
            Some(bound) => {
                e.tag(1);
                put_f64(&mut e, bound);
            }
        }
        put_f64(&mut e, self.initial_rms_px);
        put_f64(&mut e, self.final_rms_px);
        e.u64(self.iterations);
        e.u64(self.accepted_steps);
        e.text(&self.convergence);
        put_f64(&mut e, self.observation_sigma_px);
        e.bool(self.sigma_estimated);
        put_list(&mut e, &self.control_points);
        put_list(&mut e, &self.tie_points);
        put_list(&mut e, &self.excluded_points);
        e.u64(self.cameras.len() as u64);
        for camera in &self.cameras {
            e.text(&camera.name);
            e.u64(camera.identity.camera);
            e.u64(camera.identity.intrinsics);
            e.u64(camera.identity.extrinsics);
            e.digest(camera.observations);
            e.u32(camera.dimensions[0]);
            e.u32(camera.dimensions[1]);
            e.tag(match camera.mode {
                SeedMode::Fixed => 0,
                SeedMode::Focal => 1,
            });
            match camera.seed_sample {
                None => e.tag(0),
                Some(sample) => {
                    e.tag(1);
                    e.u64(sample);
                }
            }
            e.u64(camera.seed_candidate);
            e.u64(camera.seed_alternatives);
            e.u64(camera.seed_inliers);
            put_f64(&mut e, camera.seed_fit_rms_px);
            for value in camera
                .seed_intrinsics
                .iter()
                .chain(camera.seed_rotation.iter().flatten())
                .chain(&camera.seed_translation)
                .chain(&camera.intrinsics)
                .chain(&camera.distortion)
                .chain(camera.rotation.iter().flatten())
                .chain(&camera.translation)
            {
                put_f64(&mut e, *value);
            }
            e.u64(camera.covariance_parameters.len() as u64);
            for parameter in &camera.covariance_parameters {
                e.u8(parameter_code(*parameter));
            }
            for value in &camera.covariance {
                put_f64(&mut e, *value);
            }
            e.u64(camera.fixed_parameters.len() as u64);
            for parameter in &camera.fixed_parameters {
                e.u8(parameter_code(*parameter));
            }
            put_f64(&mut e, camera.seed_rms_px);
            put_f64(&mut e, camera.refined_rms_px);
            e.u64(camera.control_observations);
            e.u64(camera.free_observations);
        }
        e.finish_checked()
            .map_err(|_| SiteCalibrationError::Format("calibration exceeds canonical bounds"))
    }

    /// Canonical file bytes: magic, body length, body, then the 32-byte identity
    /// `SHA-256("fss.site_calibration.v1\0" || magic || length || body)`.
    pub fn encode(&self) -> Result<Vec<u8>, SiteCalibrationError> {
        let body = self.encode_body()?;
        let mut bytes = Vec::with_capacity(body.len() + 48);
        bytes.extend_from_slice(SITE_CALIBRATION_MAGIC);
        bytes.extend_from_slice(&(body.len() as u64).to_be_bytes());
        bytes.extend_from_slice(&body);
        if bytes.len() + 32 > MAX_CALIBRATION_BYTES {
            return Err(SiteCalibrationError::Format("calibration exceeds 4 MiB"));
        }
        let identity = domain_digest(&bytes).bytes();
        bytes.extend_from_slice(&identity);
        Ok(bytes)
    }

    /// Calibration identity (the trailing domain-tagged SHA-256 of [`Self::encode`]).
    pub fn digest(&self) -> Result<ContentDigest, SiteCalibrationError> {
        let bytes = self.encode()?;
        let start = bytes.len() - 32;
        let mut identity = [0_u8; 32];
        identity.copy_from_slice(&bytes[start..]);
        Ok(ContentDigest::new(DigestAlgorithm::Sha256, identity))
    }

    /// Verifies and decodes exact calibration bytes. The trailing identity must equal the
    /// recomputed domain digest (and `expected`, when pinned), the body must decode completely
    /// and re-encode to the identical bytes. Returns the record and its identity.
    pub fn decode(
        bytes: &[u8],
        expected: Option<ContentDigest>,
    ) -> Result<(Self, ContentDigest), SiteCalibrationError> {
        let format = SiteCalibrationError::Format;
        if bytes.len() > MAX_CALIBRATION_BYTES {
            return Err(format("calibration exceeds 4 MiB"));
        }
        if bytes.len() < 48 || !bytes.starts_with(SITE_CALIBRATION_MAGIC) {
            return Err(format("not an FSSCAL01 site calibration"));
        }
        let end = bytes.len() - 32;
        let framed = &bytes[..end];
        let identity = domain_digest(framed);
        if identity.bytes().as_slice() != &bytes[end..] {
            return Err(SiteCalibrationError::Digest);
        }
        if expected.is_some_and(|pinned| pinned != identity) {
            return Err(SiteCalibrationError::Digest);
        }
        let mut length = [0_u8; 8];
        length.copy_from_slice(&framed[8..16]);
        if u64::from_be_bytes(length) != (framed.len() - 16) as u64 {
            return Err(format("body length mismatch"));
        }
        let record = Self::decode_body(&framed[16..])?;
        if record.encode()? != bytes {
            return Err(format("noncanonical encoding"));
        }
        Ok((record, identity))
    }

    fn decode_body(body: &[u8]) -> Result<Self, SiteCalibrationError> {
        let malformed = |_| SiteCalibrationError::Format("truncated or malformed body");
        let mut d = CanonicalDecoder::new(body);
        if d.text().map_err(malformed)? != SITE_CALIBRATION_DOMAIN {
            return Err(SiteCalibrationError::Format("unknown calibration domain"));
        }
        fn f64_of(d: &mut CanonicalDecoder<'_>) -> Result<f64, SiteCalibrationError> {
            let value = f64::from_bits(
                d.u64()
                    .map_err(|_| SiteCalibrationError::Format("truncated number"))?,
            );
            if value.is_finite() {
                Ok(value)
            } else {
                Err(SiteCalibrationError::Format("non-finite number"))
            }
        }
        fn raw(d: &mut CanonicalDecoder<'_>) -> Result<[u8; 32], SiteCalibrationError> {
            let bytes = d
                .bytes()
                .map_err(|_| SiteCalibrationError::Format("truncated identity"))?;
            bytes
                .try_into()
                .map_err(|_| SiteCalibrationError::Format("identity is not 32 bytes"))
        }
        fn list(d: &mut CanonicalDecoder<'_>) -> Result<Vec<u64>, SiteCalibrationError> {
            let count = d
                .u64()
                .map_err(|_| SiteCalibrationError::Format("truncated list"))?;
            if count > 65_536 {
                return Err(SiteCalibrationError::Format("list too long"));
            }
            (0..count)
                .map(|_| {
                    d.u64()
                        .map_err(|_| SiteCalibrationError::Format("truncated list"))
                })
                .collect()
        }
        fn parameters(
            d: &mut CanonicalDecoder<'_>,
        ) -> Result<Vec<BundleParameter>, SiteCalibrationError> {
            let count = d
                .u64()
                .map_err(|_| SiteCalibrationError::Format("truncated parameters"))?;
            if count > 13 {
                return Err(SiteCalibrationError::Format("too many camera parameters"));
            }
            (0..count)
                .map(|_| {
                    d.u8()
                        .ok()
                        .and_then(parameter_from_code)
                        .ok_or(SiteCalibrationError::Format("unknown camera parameter"))
                })
                .collect()
        }
        let twin_package = d.digest().map_err(malformed)?;
        let twin_source = d.digest().map_err(malformed)?;
        let atlas_package = d.digest().map_err(malformed)?;
        let atlas_fingerprint = raw(&mut d)?;
        let atlas_provenance = d.digest().map_err(malformed)?;
        let descriptor_domain = raw(&mut d)?;
        let control_error_bound = match d.tag().map_err(malformed)? {
            0 => None,
            1 => Some(f64_of(&mut d)?),
            _ => return Err(SiteCalibrationError::Format("unknown control policy")),
        };
        let initial_rms_px = f64_of(&mut d)?;
        let final_rms_px = f64_of(&mut d)?;
        let iterations = d.u64().map_err(malformed)?;
        let accepted_steps = d.u64().map_err(malformed)?;
        let convergence = d.text().map_err(malformed)?.to_owned();
        let observation_sigma_px = f64_of(&mut d)?;
        let sigma_estimated = d.bool().map_err(malformed)?;
        let control_points = list(&mut d)?;
        let tie_points = list(&mut d)?;
        let excluded_points = list(&mut d)?;
        let count = d.u64().map_err(malformed)?;
        if count == 0 || count > MAX_SITE_CAMERAS as u64 {
            return Err(SiteCalibrationError::Format("camera count outside 1..16"));
        }
        let mut cameras = Vec::new();
        for _ in 0..count {
            let name = d.text().map_err(malformed)?.to_owned();
            let identity = CameraGeneration {
                camera: d.u64().map_err(malformed)?,
                intrinsics: d.u64().map_err(malformed)?,
                extrinsics: d.u64().map_err(malformed)?,
            };
            let observations = d.digest().map_err(malformed)?;
            let dimensions = [d.u32().map_err(malformed)?, d.u32().map_err(malformed)?];
            let mode = match d.tag().map_err(malformed)? {
                0 => SeedMode::Fixed,
                1 => SeedMode::Focal,
                _ => return Err(SiteCalibrationError::Format("unknown seed mode")),
            };
            let seed_sample = match d.tag().map_err(malformed)? {
                0 => None,
                1 => Some(d.u64().map_err(malformed)?),
                _ => return Err(SiteCalibrationError::Format("unknown seed sample tag")),
            };
            let seed_candidate = d.u64().map_err(malformed)?;
            let seed_alternatives = d.u64().map_err(malformed)?;
            let seed_inliers = d.u64().map_err(malformed)?;
            let seed_fit_rms_px = f64_of(&mut d)?;
            let mut values = [0.0_f64; 34];
            for value in &mut values {
                *value = f64_of(&mut d)?;
            }
            let matrix = |offset: usize| -> [[f64; 3]; 3] {
                std::array::from_fn(|r| std::array::from_fn(|c| values[offset + 3 * r + c]))
            };
            let vector =
                |offset: usize| -> [f64; 3] { std::array::from_fn(|i| values[offset + i]) };
            let covariance_parameters = parameters(&mut d)?;
            let k = covariance_parameters.len();
            let mut covariance = Vec::with_capacity(k * k);
            for _ in 0..k * k {
                covariance.push(f64_of(&mut d)?);
            }
            let fixed_parameters = parameters(&mut d)?;
            cameras.push(CalibratedCamera {
                name,
                identity,
                observations,
                dimensions,
                mode,
                seed_sample,
                seed_candidate,
                seed_alternatives,
                seed_inliers,
                seed_fit_rms_px,
                seed_intrinsics: [values[0], values[1], values[2], values[3]],
                seed_rotation: matrix(4),
                seed_translation: vector(13),
                intrinsics: [values[16], values[17], values[18], values[19]],
                distortion: [values[20], values[21]],
                rotation: matrix(22),
                translation: vector(31),
                covariance_parameters,
                covariance,
                fixed_parameters,
                seed_rms_px: f64_of(&mut d)?,
                refined_rms_px: f64_of(&mut d)?,
                control_observations: d.u64().map_err(malformed)?,
                free_observations: d.u64().map_err(malformed)?,
            });
        }
        d.ensure_finished()
            .map_err(|_| SiteCalibrationError::Format("trailing bytes"))?;
        let record = Self {
            twin_package,
            twin_source,
            atlas_package,
            atlas_fingerprint,
            atlas_provenance,
            descriptor_domain,
            control_error_bound,
            initial_rms_px,
            final_rms_px,
            iterations,
            accepted_steps,
            convergence,
            observation_sigma_px,
            sigma_estimated,
            control_points,
            tie_points,
            excluded_points,
            cameras,
        };
        record.validate()?;
        Ok(record)
    }

    /// The named camera, if calibrated.
    #[must_use]
    pub fn camera(&self, name: &str) -> Option<&CalibratedCamera> {
        self.cameras.iter().find(|camera| camera.name == name)
    }
}

/// A localization kept alive for the joint seeds, with the selected candidate.
enum Localized {
    Fixed(CameraLocalization),
    Focal(fss_twin::focal_localization::FocalLocalization),
}

/// Selection: most inliers, then lowest fit RMS, then lowest (sample, candidate) index.
#[derive(Clone, Copy)]
struct Selection {
    sample: Option<usize>,
    candidate: usize,
    inliers: usize,
    rms: f64,
    alternatives: usize,
}

fn select<'a>(
    searches: impl Iterator<Item = (Option<usize>, &'a PoseSearch)>,
) -> Option<Selection> {
    let mut best: Option<Selection> = None;
    let mut alternatives = 0;
    for (sample, search) in searches {
        for (index, candidate) in search.candidates().iter().enumerate() {
            alternatives += 1;
            let inliers = candidate.inlier_landmarks().len();
            let rms = candidate.rms_px();
            let better =
                best.is_none_or(|b| inliers > b.inliers || (inliers == b.inliers && rms < b.rms));
            if better && rms.is_finite() {
                best = Some(Selection {
                    sample,
                    candidate: index,
                    inliers,
                    rms,
                    alternatives: 0,
                });
            }
        }
    }
    best.map(|b| Selection { alternatives, ..b })
}

fn geometry_values(intrinsics: PinholeIntrinsics) -> [f64; 4] {
    let [fx, fy] = intrinsics.focal_lengths();
    let [cx, cy] = intrinsics.principal_point();
    [fx, fy, cx, cy]
}

/// Localizes every camera independently, refines them jointly and returns the record.
/// Refusals are typed; no partial calibration is ever returned.
pub fn calibrate_site(
    request: &CalibrationRequest<'_>,
    observations: &[CameraObservations],
) -> Result<SiteCalibration, SiteCalibrationError> {
    if observations.len() < 2 || observations.len() > MAX_SITE_CAMERAS {
        return Err(invalid("", "a site calibration takes 2..16 cameras"));
    }
    let mut names = BTreeSet::new();
    let mut handles = BTreeSet::new();
    for camera in observations {
        if !names.insert(camera.name.as_str()) {
            return Err(invalid(&camera.name, "camera names must be unique"));
        }
        if !handles.insert(camera.identity.camera) {
            return Err(invalid(&camera.name, "camera handles must be unique"));
        }
    }
    let descriptor_domain = observations[0].descriptor_domain;
    if observations
        .iter()
        .any(|camera| camera.descriptor_domain != descriptor_domain)
    {
        return Err(invalid(
            "",
            "every camera must use one descriptor generation",
        ));
    }
    if let ControlSelection::DeclaredErrorAtMost(bound) = request.control
        && !(bound.is_finite() && bound >= 0.0)
    {
        return Err(invalid(
            "",
            "control error bound must be finite and non-negative",
        ));
    }
    let twin = import_scene_mesh(
        request.twin_package,
        request.twin_digest,
        request.twin_source,
    )
    .map_err(|error| SiteCalibrationError::Basis(format!("twin package: {error}")))?;
    let mut budget = WorkBudget::new(request.work_units);
    let archived = decode_atlas(
        request.atlas_package,
        &twin,
        ArchiveExpectation {
            package: request.atlas_digest.bytes(),
            provenance: request.atlas_provenance.bytes(),
            descriptor: descriptor_domain,
        },
        &mut budget,
    )
    .map_err(|error| SiteCalibrationError::Basis(format!("atlas package: {error}")))?;
    let atlas = archived.atlas();

    let mut localized = Vec::with_capacity(observations.len());
    for camera in observations {
        let name = camera.name.as_str();
        let frame = FeatureFrame::new(
            camera.image,
            camera.descriptor_domain,
            camera.features.clone(),
            &mut budget,
        )
        .map_err(|error| invalid(name, format!("features refused: {error}")))?;
        let failed = |reason: String| SiteCalibrationError::LocalizationFailed {
            camera: name.to_owned(),
            reason,
        };
        let entry = match camera.intrinsics {
            IntrinsicsSpec::Fixed { parameters } => {
                let [fx, fy, cx, cy] = parameters;
                let intrinsics = PinholeIntrinsics::new(
                    camera.image.dimensions[0],
                    camera.image.dimensions[1],
                    fx,
                    fy,
                    cx,
                    cy,
                )
                .map_err(|error| invalid(name, format!("intrinsics refused: {error}")))?;
                let result = atlas
                    .localize(
                        &twin,
                        &frame,
                        LocalizationCamera {
                            intrinsics,
                            image_domain: camera.image.image_domain,
                        },
                        MatchOptions::default(),
                        PoseSolverOptions::default(),
                        &mut budget,
                    )
                    .map_err(|error| failed(error.to_string()))?;
                let selection = match &result.outcome {
                    LocalizationOutcome::Candidates(search) => {
                        select(std::iter::once((None, search.as_ref())))
                    }
                    LocalizationOutcome::InsufficientMatches => {
                        return Err(failed(format!(
                            "{} descriptor match(es); at least 8 are required",
                            result.matches.correspondences.len()
                        )));
                    }
                    LocalizationOutcome::GeometricFailure(error) => {
                        return Err(failed(format!("pose solver: {error}")));
                    }
                };
                let selection = selection.ok_or_else(|| failed("no pose candidate".to_owned()))?;
                (Localized::Fixed(result), selection, SeedMode::Fixed)
            }
            IntrinsicsSpec::Focal {
                minimum_fx,
                maximum_fx,
                samples,
                y_over_x,
                principal_point,
            } => {
                let result = localize_focal_scan(
                    atlas,
                    &twin,
                    &frame,
                    camera.image.image_domain,
                    MatchOptions::default(),
                    FocalScanOptions {
                        minimum_fx_px: minimum_fx,
                        maximum_fx_px: maximum_fx,
                        y_over_x,
                        principal_point,
                        samples,
                        pose: PoseSolverOptions::default(),
                    },
                    &mut budget,
                )
                .map_err(|error| failed(error.to_string()))?;
                let selection = match &result.outcome {
                    FocalLocalizationOutcome::Scan(scan) => select(
                        scan.samples().iter().enumerate().filter_map(
                            |(index, sample)| match sample.outcome() {
                                FocalSampleOutcome::Candidates(search) => {
                                    Some((Some(index), search.as_ref()))
                                }
                                FocalSampleOutcome::GeometricFailure(_) => None,
                            },
                        ),
                    ),
                    FocalLocalizationOutcome::InsufficientMatches { found, required } => {
                        return Err(failed(format!(
                            "{found} descriptor match(es); at least {required} are required"
                        )));
                    }
                };
                let selection = selection
                    .ok_or_else(|| failed("no focal sample produced a pose".to_owned()))?;
                (Localized::Focal(result), selection, SeedMode::Focal)
            }
        };
        localized.push(entry);
    }

    let seeds: Vec<JointCamera<'_>> = observations
        .iter()
        .zip(&localized)
        .map(|(camera, (result, selection, _))| JointCamera {
            identity: camera.identity,
            seed: match result {
                Localized::Fixed(localization) => LocalizationSeed::Fixed {
                    localization,
                    candidate: selection.candidate,
                },
                Localized::Focal(localization) => LocalizationSeed::Focal {
                    localization,
                    sample: selection.sample.unwrap_or(0),
                    candidate: selection.candidate,
                },
            },
        })
        .collect();
    let ties: Vec<TieObservation> = observations
        .iter()
        .flat_map(|camera| {
            camera.ties.iter().map(|(tie, pixel)| TieObservation {
                camera: camera.identity.camera,
                tie: *tie,
                pixel: *pixel,
            })
        })
        .collect();
    let by_handle: BTreeMap<u64, &CameraObservations> = observations
        .iter()
        .map(|camera| (camera.identity.camera, camera))
        .collect();
    let refinement = refine_site_jointly(
        &twin,
        atlas,
        &seeds,
        &ties,
        JointOptions {
            control: request.control,
            ..JointOptions::default()
        },
        &mut budget,
    )
    .map_err(|error| match error {
        JointRefinementError::TooFewControlPoints { observed } => {
            SiteCalibrationError::TooFewControlPoints {
                observed,
                collinear: false,
            }
        }
        JointRefinementError::CollinearControlPoints => SiteCalibrationError::TooFewControlPoints {
            observed: 0,
            collinear: true,
        },
        JointRefinementError::DisconnectedCameras { camera } => {
            SiteCalibrationError::DisconnectedCameras {
                camera: by_handle
                    .get(&camera)
                    .map_or_else(|| camera.to_string(), |c| c.name.clone()),
            }
        }
        other => SiteCalibrationError::Refinement(other.to_string()),
    })?;

    let report = refinement.adjustment.report();
    let convergence = report
        .convergence
        .ok_or_else(|| SiteCalibrationError::Refinement("solve did not converge".to_owned()))?;
    let (sigma, estimated) = refinement.adjustment.observation_sigma_px();
    let tie_handles: BTreeSet<u64> = ties.iter().map(|tie| tie.tie).collect();
    let mut cameras = Vec::with_capacity(observations.len());
    for summary in &refinement.cameras {
        let handle = summary.identity.camera;
        let (index, camera) = observations
            .iter()
            .enumerate()
            .find(|(_, c)| c.identity.camera == handle)
            .ok_or_else(|| SiteCalibrationError::Refinement("unknown refined camera".to_owned()))?;
        let adjusted = refinement
            .adjustment
            .camera(handle)
            .ok_or_else(|| SiteCalibrationError::Refinement("refined camera missing".to_owned()))?;
        let (_, selection, mode) = &localized[index];
        let seed_pose = summary.seed_pose;
        cameras.push(CalibratedCamera {
            name: camera.name.clone(),
            identity: summary.identity,
            observations: camera.file_digest,
            dimensions: camera.image.dimensions,
            mode: *mode,
            seed_sample: selection.sample.map(|s| s as u64),
            seed_candidate: selection.candidate as u64,
            seed_alternatives: selection.alternatives as u64,
            seed_inliers: selection.inliers as u64,
            seed_fit_rms_px: selection.rms,
            seed_intrinsics: geometry_values(summary.seed_intrinsics),
            seed_rotation: seed_pose.rotation(),
            seed_translation: seed_pose.translation(),
            intrinsics: geometry_values(adjusted.intrinsics),
            distortion: if adjusted.distortion == RadialDistortion::NONE {
                [0.0, 0.0]
            } else {
                [adjusted.distortion.k1, adjusted.distortion.k2]
            },
            rotation: adjusted.pose.rotation(),
            translation: adjusted.pose.translation(),
            covariance_parameters: adjusted.covariance.parameters.clone(),
            covariance: adjusted.covariance.matrix.clone(),
            fixed_parameters: adjusted.covariance.fixed.clone(),
            seed_rms_px: summary.seed_rms_px,
            refined_rms_px: summary.refined_rms_px,
            control_observations: summary.control_observations as u64,
            free_observations: summary.free_observations as u64,
        });
    }
    let record = SiteCalibration {
        twin_package: request.twin_digest,
        twin_source: request.twin_source,
        atlas_package: request.atlas_digest,
        atlas_fingerprint: atlas.digest(),
        atlas_provenance: request.atlas_provenance,
        descriptor_domain,
        control_error_bound: match request.control {
            ControlSelection::AllAtlasLandmarks => None,
            ControlSelection::DeclaredErrorAtMost(bound) => Some(bound),
        },
        initial_rms_px: report.initial_rms_px,
        final_rms_px: report.final_rms_px,
        iterations: report.iterations as u64,
        accepted_steps: report.accepted_steps as u64,
        convergence: convergence_label(convergence).to_owned(),
        observation_sigma_px: sigma,
        sigma_estimated: estimated,
        control_points: refinement
            .adjustment
            .control_points()
            .iter()
            .map(|point| point.landmark)
            .collect(),
        tie_points: refinement
            .adjustment
            .landmarks()
            .iter()
            .map(|landmark| landmark.landmark)
            .filter(|handle| tie_handles.contains(handle))
            .collect(),
        excluded_points: refinement.excluded_points.clone(),
        cameras,
    };
    // Round-trips through the canonical encoding so a record that cannot be written (for
    // example a non-finite covariance) is refused here rather than half-published later.
    record
        .encode()
        .map_err(|error| SiteCalibrationError::Refinement(error.to_string()))?;
    Ok(record)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn record(distortion: [f64; 2]) -> SiteCalibration {
        let digest = ContentDigest::sha256(b"x");
        SiteCalibration {
            twin_package: digest,
            twin_source: digest,
            atlas_package: digest,
            atlas_fingerprint: [4; 32],
            atlas_provenance: digest,
            descriptor_domain: [5; 32],
            control_error_bound: Some(0.01),
            initial_rms_px: 1.5,
            final_rms_px: 0.25,
            iterations: 7,
            accepted_steps: 6,
            convergence: "gradient".to_owned(),
            observation_sigma_px: 0.3,
            sigma_estimated: true,
            control_points: vec![1, 2, 3],
            tie_points: vec![1001],
            excluded_points: vec![],
            cameras: vec![CalibratedCamera {
                name: "east".to_owned(),
                identity: CameraGeneration {
                    camera: 1,
                    intrinsics: 2,
                    extrinsics: 3,
                },
                observations: digest,
                dimensions: [96, 48],
                mode: SeedMode::Focal,
                seed_sample: Some(4),
                seed_candidate: 0,
                seed_alternatives: 3,
                seed_inliers: 10,
                seed_fit_rms_px: 0.5,
                seed_intrinsics: [10.0, 10.0, 48.0, 24.0],
                seed_rotation: [[1.0, 0.0, 0.0], [0.0, -1.0, 0.0], [0.0, 0.0, -1.0]],
                seed_translation: [-48.0, 24.0, 10.0],
                intrinsics: [10.0, 10.0, 48.0, 24.0],
                distortion,
                rotation: [[1.0, 0.0, 0.0], [0.0, -1.0, 0.0], [0.0, 0.0, -1.0]],
                translation: [-48.0, 24.0, 10.0],
                covariance_parameters: vec![BundleParameter::Rotation(0), BundleParameter::Focal],
                covariance: vec![1e-6, 0.0, 0.0, 1e-4],
                fixed_parameters: vec![BundleParameter::Cx, BundleParameter::Cy],
                seed_rms_px: 1.0,
                refined_rms_px: 0.2,
                control_observations: 10,
                free_observations: 4,
            }],
        }
    }

    #[test]
    fn round_trip_is_exact_and_every_byte_is_bound() -> Result<(), SiteCalibrationError> {
        let value = record([0.0, 0.0]);
        let bytes = value.encode()?;
        let (decoded, identity) = SiteCalibration::decode(&bytes, Some(value.digest()?))?;
        assert_eq!(decoded, value);
        assert_eq!(identity, value.digest()?);
        for index in 0..bytes.len() {
            let mut changed = bytes.clone();
            changed[index] ^= 0x01;
            assert!(
                SiteCalibration::decode(&changed, None).is_err(),
                "byte {index}"
            );
        }
        let other = ContentDigest::sha256(b"another calibration");
        assert_eq!(
            SiteCalibration::decode(&bytes, Some(other)),
            Err(SiteCalibrationError::Digest)
        );
        Ok(())
    }

    #[test]
    fn distorted_cameras_have_no_pinhole_pose() -> Result<(), SiteCalibrationError> {
        let pinhole = record([0.0, 0.0]);
        assert!(pinhole.cameras[0].pinhole_pose().is_ok());
        let distorted = record([-0.05, 0.0]);
        let error = distorted.cameras[0].pinhole_pose();
        assert_eq!(
            error,
            Err(SiteCalibrationError::Distorted {
                camera: "east".to_owned()
            })
        );
        assert_eq!(
            SiteCalibrationError::Distorted {
                camera: String::new()
            }
            .stable_id(),
            "ERR-SITE-CALIBRATION-DISTORTED-001"
        );
        Ok(())
    }

    #[test]
    fn observation_files_are_strict() {
        let good = "fss.site_camera_observations.v1\ncamera 1 2 3\nimage 96 48\n\
            exposure sha256:0101010101010101010101010101010101010101010101010101010101010101\n\
            pixels sha256:0202020202020202020202020202020202020202020202020202020202020202\n\
            image-domain sha256:0303030303030303030303030303030303030303030303030303030303030303\n\
            descriptor-domain sha256:0404040404040404040404040404040404040404040404040404040404040404\n\
            intrinsics fixed 10 10 48 24\n\
            feature 1 10.5 20.5 00000000000000010000000000000002000000000000000300000000000000ff\n\
            tie 7 3 4\n";
        let parsed = CameraObservations::parse("east", good.as_bytes());
        assert!(parsed.is_ok(), "{parsed:?}");
        for broken in [
            good.replace("camera 1 2 3", "camera 0 2 3"),
            good.replace("image 96 48\n", ""),
            good.replace("tie 7 3 4", "tie 7 3 99"),
            good.replace("10.5", "NaN"),
            good.replace("00ff", "00FF"),
            format!("{good}camera 1 2 3\n"),
            format!("{good}unknown line\n"),
        ] {
            assert!(
                CameraObservations::parse("east", broken.as_bytes()).is_err(),
                "{broken}"
            );
        }
        assert!(CameraObservations::parse("bad name", good.as_bytes()).is_err());
    }
}
