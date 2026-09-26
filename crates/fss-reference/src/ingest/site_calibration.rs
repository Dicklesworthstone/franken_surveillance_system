#![forbid(unsafe_code)]
//! Owner site calibration: per-camera atlas localization, joint refinement, and a canonical
//! digest-bound calibration record that ground-zone visibility can consume.
//!
//! Inputs are the owner's property twin (`FSSTWIN1`), a surveyed localization atlas
//! (`FSATLAS1`, fss-twin `atlas_archive`), each pinned by exact digests, and per camera either
//! an observation file or a still JPEG frame:
//!
//! - Correspondence input (`fss.site_camera_observations.v1`, documented on
//!   [`CameraObservations::parse`]) carries owner-supplied image features (pixel plus 256-bit
//!   descriptor in the atlas descriptor generation) and tie-point pixels; it is NOT an image and
//!   every feature is an owner assertion.
//! - Frame input ([`CameraFrame::decode`]) is one complete baseline JPEG plus a
//!   `fss.site_camera_frame.v1` metadata file with the same camera, image, exposure,
//!   image-domain and intrinsics header lines. The frame is decoded to luma by the first-party
//!   `fss-codec-mjpeg` decoder and its features are extracted by the fss-twin native FAST-9 /
//!   oriented-BRIEF extractor ([`fss_twin::localization::native`]) under the fixed
//!   [`FRAME_EXTRACTION`] policy; the atlas must therefore be in the native descriptor
//!   generation. Tie points between frame cameras are derived, not asserted: features that
//!   matched no atlas landmark are matched pairwise between frame cameras (mutual nearest
//!   neighbours under the atlas matcher's distance and ratio rules), joined into tracks, and a
//!   track is kept only when its least-squares triangulation from the seeded poses reprojects
//!   within [`FRAME_TIE_GATE_PX`] in every view. A loose frame is not retained custody and no
//!   privacy mask is applied to it (the owner supplies the file).
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
//! covariance, seed and refined RMS, its `CameraGeneration` invalidators and the input digest,
//! plus the twin and atlas digests and the joint solve report. Its identity is the trailing
//! SHA-256 over the domain tag and the exact bytes; [`SiteCalibration::decode`] refuses any
//! byte change, any noncanonical encoding and any expected-digest mismatch. A calibration with
//! at least one frame camera is written as `FSSCAL02` (digest domain `fss.site_calibration.v2`):
//! the v1 body plus the frame policy (decoder identity, extraction and tie-derivation
//! parameters) and, per camera, an input-kind tag with, for frames, the metadata-file and
//! decoded-luma digests and the extracted / atlas-matched / tie feature counts. A calibration
//! whose cameras all took correspondence input is always `FSSCAL01`, byte-identical to the
//! records written before frame input existed; a `FSSCAL02` record without a frame camera is
//! noncanonical and refused.
//!
//! Non-claims: a candidate calibration, never an activation or accuracy certificate; atlas
//! control positions are treated as exact; covariance is a local Gauss-Newton approximation;
//! synthetic sites do not establish accuracy on real site footage.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use fss_codec_mjpeg::{
    ComponentInterpretation, DecodeBudget, DecodeLimits, decode_luma, decoder_identity,
};
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
use fss_twin::localization::native::{
    ExtractionOptions, GrayImage, descriptor_domain as native_descriptor_domain, extract_gray,
};
use fss_twin::localization::{
    BinaryDescriptor, CameraLocalization, FeatureFrame, ImageFeature, ImageIdentity,
    LocalizationCamera, LocalizationError, LocalizationOutcome, MAX_IMAGE_FEATURES, MatchOptions,
    MatchReport,
};

use super::ground_visibility::{CameraPose, import_scene_mesh};

/// Control-point selection of the joint solve (fss-twin), re-exported for callers.
pub use fss_twin::joint_refinement::ControlSelection;

/// Registered digest domain of the calibration record (`SCHEMA-DOMAIN-SITE-CALIBRATION-001`).
pub const SITE_CALIBRATION_DOMAIN: &str = "fss.site_calibration.v1";
/// Leading magic of a calibration file.
pub const SITE_CALIBRATION_MAGIC: &[u8; 8] = b"FSSCAL01";
/// Registered digest domain of a calibration with frame input
/// (`SCHEMA-DOMAIN-SITE-CALIBRATION-002`).
pub const SITE_CALIBRATION_DOMAIN_V2: &str = "fss.site_calibration.v2";
/// Leading magic of a calibration file with frame input.
pub const SITE_CALIBRATION_MAGIC_V2: &[u8; 8] = b"FSSCAL02";
/// First line of a camera observation file.
pub const OBSERVATIONS_FORMAT: &str = "fss.site_camera_observations.v1";
/// First line of a camera frame metadata file.
pub const FRAME_METADATA_FORMAT: &str = "fss.site_camera_frame.v1";
/// Largest JPEG frame read (the fss-codec-mjpeg bound).
pub const MAX_FRAME_BYTES: usize = 16 * 1024 * 1024;
/// Decoder work units granted to one frame decode.
pub const FRAME_DECODE_WORK: u64 = 1_000_000_000;
/// Native extraction policy of every frame camera: FAST-9 threshold, feature ceiling and
/// pixel-centre separation (the fss-twin defaults, fixed here so the record can bind them).
pub const FRAME_EXTRACTION: FrameExtraction = FrameExtraction {
    threshold: 20,
    maximum_features: 512,
    separation: 6,
};
/// Largest Hamming distance of a frame-to-frame tie match (the atlas matcher default).
pub const FRAME_TIE_MAX_DISTANCE: u16 = 64;
/// Strict best / runner-up ratio, in percent, of a frame-to-frame tie match (the atlas matcher
/// default).
pub const FRAME_TIE_RATIO_PERCENT: u8 = 80;
/// Largest reprojection error (px), at the seeded poses, of every view of a kept frame tie.
pub const FRAME_TIE_GATE_PX: f64 = 2.0;

/// Native extraction parameters bound into a frame calibration.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FrameExtraction {
    /// Strict FAST-9 contrast threshold.
    pub threshold: u8,
    /// Selected feature ceiling.
    pub maximum_features: u32,
    /// Minimum pixel-centre separation.
    pub separation: u16,
}
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
    /// A camera's JPEG frame could not be decoded, or its decoded size differs from the
    /// metadata's declared image size.
    FrameDecode {
        /// Camera name.
        camera: String,
        /// Why (the decoder's typed failure, or the size mismatch).
        reason: String,
    },
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
    /// The owner asserted a current camera generation (`--camera-generation`) that differs from
    /// the generation the calibrated pose depends on: the calibration is stale for that camera
    /// (moved, cropped, zoomed or relensed since). The assertion is the owner's, not observed.
    GenerationStale {
        /// Camera name.
        camera: String,
        /// Owner-asserted current `(intrinsics, extrinsics)` generations.
        asserted: (u64, u64),
        /// Generations the calibrated pose depends on.
        calibrated: (u64, u64),
    },
    /// A camera generation was asserted for a camera whose pose does not come from the
    /// calibration, so there is nothing for the assertion to bind.
    GenerationUnbound {
        /// Camera name.
        camera: String,
    },
}

impl SiteCalibrationError {
    /// Registered stable error identity (`registries/ERRORS.md`).
    #[must_use]
    pub fn stable_id(&self) -> &'static str {
        match self {
            Self::InvalidInput { .. } => "ERR-SITE-CALIBRATION-INPUT-INVALID-001",
            Self::Basis(_) => "ERR-SITE-CALIBRATION-BASIS-001",
            Self::FrameDecode { .. } => "ERR-SITE-CALIBRATION-FRAME-DECODE-001",
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
            Self::GenerationStale { .. } => "ERR-SITE-CALIBRATION-GENERATION-STALE-001",
            Self::GenerationUnbound { .. } => "ERR-SITE-CALIBRATION-GENERATION-UNBOUND-001",
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
            Self::FrameDecode { camera, reason } => {
                write!(f, "frame of camera {camera} refused: {reason}")
            }
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
            Self::GenerationStale {
                camera,
                asserted,
                calibrated,
            } => write!(
                f,
                "camera {camera}: owner-asserted current generation intrinsics {} extrinsics {} \
                 differs from the calibrated generation intrinsics {} extrinsics {}; the \
                 calibration is stale for this camera",
                asserted.0, asserted.1, calibrated.0, calibrated.1
            ),
            Self::GenerationUnbound { camera } => write!(
                f,
                "--camera-generation names camera {camera}, whose pose does not come from the \
                 calibration"
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

/// Which camera text a line parser reads.
#[derive(Clone, Copy, Eq, PartialEq)]
enum CameraText {
    /// `fss.site_camera_observations.v1`: header plus `feature` and `tie` lines.
    Observations,
    /// `fss.site_camera_frame.v1`: header plus `interpretation`; pixels and features come from
    /// the frame itself.
    Frame,
}

/// Parsed camera text (observation file or frame metadata).
struct CameraHeader {
    identity: CameraGeneration,
    dimensions: [u32; 2],
    exposure: [u8; 32],
    pixels: Option<[u8; 32]>,
    image_domain: [u8; 32],
    descriptor_domain: Option<[u8; 32]>,
    interpretation: Option<ComponentInterpretation>,
    intrinsics: IntrinsicsSpec,
    features: Vec<ImageFeature>,
    ties: Vec<(u64, [f64; 2])>,
}

fn parse_camera_text(
    name: &str,
    bytes: &[u8],
    kind: CameraText,
) -> Result<CameraHeader, SiteCalibrationError> {
    let observations = kind == CameraText::Observations;
    if !valid_camera_name(name) {
        return Err(invalid(
            name,
            "camera names are 1..64 bytes of [A-Za-z0-9_.-]",
        ));
    }
    if bytes.len() > MAX_OBSERVATION_BYTES {
        return Err(invalid(
            name,
            if observations {
                "observation file exceeds 1 MiB"
            } else {
                "frame metadata exceeds 1 MiB"
            },
        ));
    }
    let text = std::str::from_utf8(bytes).map_err(|_| invalid(name, "not UTF-8"))?;
    let mut lines = text
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('#'));
    let format = if observations {
        OBSERVATIONS_FORMAT
    } else {
        FRAME_METADATA_FORMAT
    };
    if lines.next() != Some(format) {
        return Err(invalid(name, format!("first line must be {format}")));
    }
    let mut identity = None;
    let mut dimensions = None;
    let mut exposure = None;
    let mut pixels = None;
    let mut image_domain = None;
    let mut descriptor_domain = None;
    let mut interpretation = None;
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
                let size: [u32; 2] = [parse_integer(name, width)?, parse_integer(name, height)?];
                if size.iter().any(|n| *n == 0 || *n > 65_536) {
                    return Err(invalid(name, "image size must be 1..65536"));
                }
                once(&mut dimensions, size, name)?;
            }
            ["exposure", value] => once(&mut exposure, parse_digest(name, value)?, name)?,
            ["pixels", value] if observations => {
                once(&mut pixels, parse_digest(name, value)?, name)?;
            }
            ["image-domain", value] => {
                once(&mut image_domain, parse_digest(name, value)?, name)?;
            }
            ["descriptor-domain", value] if observations => {
                once(&mut descriptor_domain, parse_digest(name, value)?, name)?;
            }
            ["interpretation", value] if !observations => {
                let parsed = match *value {
                    "gray" => ComponentInterpretation::Grayscale,
                    "ycbcr" => ComponentInterpretation::YCbCr,
                    _ => return Err(invalid(name, "interpretation must be gray or ycbcr")),
                };
                once(&mut interpretation, parsed, name)?;
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
            ["feature", id, u, v, descriptor] if observations => {
                if features.len() == MAX_IMAGE_FEATURES {
                    return Err(invalid(name, "at most 512 features"));
                }
                features.push(ImageFeature {
                    id: parse_integer(name, id)?,
                    pixel: [parse_finite(name, u)?, parse_finite(name, v)?],
                    descriptor: parse_descriptor(name, descriptor)?,
                });
            }
            ["tie", handle, u, v] if observations => {
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
    let identity = identity.ok_or_else(|| missing("camera"))?;
    let exposure = exposure.ok_or_else(|| missing("exposure"))?;
    let pixels = if observations {
        Some(pixels.ok_or_else(|| missing("pixels"))?)
    } else {
        None
    };
    let image_domain = image_domain.ok_or_else(|| missing("image-domain"))?;
    let descriptor_domain = if observations {
        Some(descriptor_domain.ok_or_else(|| missing("descriptor-domain"))?)
    } else {
        None
    };
    let interpretation = if observations {
        None
    } else {
        Some(interpretation.ok_or_else(|| missing("interpretation"))?)
    };
    Ok(CameraHeader {
        identity,
        dimensions,
        exposure,
        pixels,
        image_domain,
        descriptor_domain,
        interpretation,
        intrinsics: intrinsics.ok_or_else(|| missing("intrinsics"))?,
        features,
        ties,
    })
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
        let header = parse_camera_text(name, bytes, CameraText::Observations)?;
        Ok(Self {
            name: name.to_owned(),
            identity: header.identity,
            image: ImageIdentity {
                exposure: header.exposure,
                pixels: header
                    .pixels
                    .ok_or_else(|| invalid(name, "missing pixels line"))?,
                image_domain: header.image_domain,
                dimensions: header.dimensions,
            },
            descriptor_domain: header
                .descriptor_domain
                .ok_or_else(|| invalid(name, "missing descriptor-domain line"))?,
            intrinsics: header.intrinsics,
            features: header.features,
            ties: header.ties,
            file_digest: ContentDigest::sha256(bytes),
        })
    }
}

/// One camera's still JPEG frame with its owner metadata, decoded to luma (not yet extracted).
#[derive(Clone)]
pub struct CameraFrame {
    /// Owner camera name (matches `fss-event corroborate --camera NAME`).
    pub name: String,
    /// Camera handle and immutable intrinsics/extrinsics generations.
    pub identity: CameraGeneration,
    /// Owner-declared source exposure identity (must differ from every atlas reference).
    pub exposure: [u8; 32],
    /// Owner-declared image-domain chain identity.
    pub image_domain: [u8; 32],
    /// Decoded (and declared) pixel grid.
    pub dimensions: [u32; 2],
    /// Declared component interpretation the decoder enforced.
    pub interpretation: ComponentInterpretation,
    /// Intrinsics handling.
    pub intrinsics: IntrinsicsSpec,
    /// SHA-256 of the exact frame metadata bytes.
    pub metadata_digest: ContentDigest,
    /// SHA-256 of the exact JPEG bytes (the camera's input digest).
    pub frame_digest: ContentDigest,
    /// SHA-256 of the decoded luma (the image identity of the extracted features).
    pub luma_digest: ContentDigest,
    luma: Vec<u8>,
}

impl fmt::Debug for CameraFrame {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CameraFrame")
            .field("name", &self.name)
            .field("dimensions", &self.dimensions)
            .finish_non_exhaustive()
    }
}

impl CameraFrame {
    /// Parses one frame metadata file and decodes its JPEG to luma. The metadata is UTF-8
    /// lines (blank lines and `#` comments ignored); the first content line is
    /// `fss.site_camera_frame.v1`; then, each exactly once:
    ///
    /// ```text
    /// camera HANDLE INTRINSICS_GENERATION EXTRINSICS_GENERATION   (all nonzero)
    /// image WIDTH HEIGHT                                          (must equal the decoded frame)
    /// exposure sha256:HEX                                         (source exposure identity)
    /// image-domain sha256:HEX
    /// interpretation gray|ycbcr                                   (JPEG component contract)
    /// intrinsics fixed FX FY CX CY
    ///   or intrinsics focal MIN_FX MAX_FX SAMPLES Y_OVER_X CX CY
    /// ```
    ///
    /// `pixels`, `descriptor-domain`, `feature` and `tie` lines are refused: the pixel
    /// identity is the decoded luma digest, the descriptor generation is the native extractor's,
    /// and features and ties are derived. The JPEG must be one complete baseline frame
    /// ([`decode_luma`]); any decoder failure or a decoded size other than the declared one is
    /// a [`SiteCalibrationError::FrameDecode`] refusal.
    pub fn decode(name: &str, metadata: &[u8], jpeg: &[u8]) -> Result<Self, SiteCalibrationError> {
        let header = parse_camera_text(name, metadata, CameraText::Frame)?;
        let interpretation = header
            .interpretation
            .ok_or_else(|| invalid(name, "missing interpretation line"))?;
        let refused = |reason: String| SiteCalibrationError::FrameDecode {
            camera: name.to_owned(),
            reason,
        };
        if jpeg.len() > MAX_FRAME_BYTES {
            return Err(refused("frame exceeds 16 MiB".to_owned()));
        }
        let frame_digest = ContentDigest::sha256(jpeg);
        let decoded = decode_luma(
            jpeg,
            frame_digest.bytes(),
            interpretation,
            DecodeLimits::default(),
            &mut DecodeBudget::new(FRAME_DECODE_WORK),
        )
        .map_err(|error| refused(error.to_string()))?;
        if decoded.dimensions() != header.dimensions {
            return Err(refused(format!(
                "decoded frame is {}x{}, metadata declares {}x{}",
                decoded.dimensions()[0],
                decoded.dimensions()[1],
                header.dimensions[0],
                header.dimensions[1]
            )));
        }
        let luma = decoded.pixels().to_vec();
        Ok(Self {
            name: name.to_owned(),
            identity: header.identity,
            exposure: header.exposure,
            image_domain: header.image_domain,
            dimensions: header.dimensions,
            interpretation,
            intrinsics: header.intrinsics,
            metadata_digest: ContentDigest::sha256(metadata),
            frame_digest,
            luma_digest: ContentDigest::new(DigestAlgorithm::Sha256, decoded.receipt().luma_sha256),
            luma,
        })
    }

    /// Decoded luma, row-major, `width * height` bytes.
    #[must_use]
    pub fn luma(&self) -> &[u8] {
        &self.luma
    }
}

/// One camera's calibration input.
#[derive(Clone, Debug)]
pub enum CameraInput {
    /// Owner correspondences (`fss.site_camera_observations.v1`).
    Correspondences(CameraObservations),
    /// A decoded still JPEG frame with its metadata.
    Frame(CameraFrame),
}

impl CameraInput {
    fn name(&self) -> &str {
        match self {
            Self::Correspondences(observations) => &observations.name,
            Self::Frame(frame) => &frame.name,
        }
    }
    fn identity(&self) -> CameraGeneration {
        match self {
            Self::Correspondences(observations) => observations.identity,
            Self::Frame(frame) => frame.identity,
        }
    }
    fn descriptor_domain(&self) -> [u8; 32] {
        match self {
            Self::Correspondences(observations) => observations.descriptor_domain,
            Self::Frame(_) => native_descriptor_domain(),
        }
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
    /// SHA-256 of the camera's exact input: the observation file for correspondence input, the
    /// JPEG bytes for frame input.
    pub observations: ContentDigest,
    /// Which kind of input the camera took (and, for a frame, its derivation identities).
    pub input: CalibrationInput,
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
    /// Decoder, extraction and tie-derivation policy; present exactly when some camera took
    /// frame input (and then the record is `FSSCAL02`).
    pub frame_policy: Option<FramePolicy>,
    /// Calibrated cameras, sorted by camera handle.
    pub cameras: Vec<CalibratedCamera>,
}

/// How one calibrated camera's input entered the calibration.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum CalibrationInput {
    /// Owner correspondences; the camera's input digest is the observation-file digest.
    Correspondences,
    /// A still JPEG frame; the camera's input digest is the JPEG-bytes digest.
    Frame(FrameInput),
}

impl CalibrationInput {
    /// Stable label.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Correspondences => "correspondences",
            Self::Frame(_) => "jpeg_frame",
        }
    }
}

/// Derivation identities and counts of one frame camera.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FrameInput {
    /// SHA-256 of the exact frame metadata file.
    pub metadata: ContentDigest,
    /// SHA-256 of the decoded luma the features were extracted from.
    pub luma: ContentDigest,
    /// Component interpretation the decoder enforced.
    pub interpretation: ComponentInterpretation,
    /// Features the native extractor selected.
    pub extracted_features: u64,
    /// Features accepted as atlas correspondences (before pose inlier selection).
    pub atlas_matches: u64,
    /// Features that became verified frame-derived tie observations.
    pub tie_observations: u64,
}

/// Decoder, extraction and tie-derivation policy of every frame camera of a calibration.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct FramePolicy {
    /// fss-codec-mjpeg decoder identity.
    pub decoder: [u8; 32],
    /// Native extraction parameters.
    pub extraction: FrameExtraction,
    /// Largest Hamming distance of a frame-to-frame tie match.
    pub tie_max_distance: u16,
    /// Strict best / runner-up ratio (percent) of a frame-to-frame tie match.
    pub tie_ratio_percent: u8,
    /// Reprojection gate (px) of every view of a kept frame tie at the seeded poses.
    pub tie_gate_px: f64,
}

impl FramePolicy {
    /// The policy this build applies to frame input.
    #[must_use]
    pub fn current() -> Self {
        Self {
            decoder: decoder_identity(),
            extraction: FRAME_EXTRACTION,
            tie_max_distance: FRAME_TIE_MAX_DISTANCE,
            tie_ratio_percent: FRAME_TIE_RATIO_PERCENT,
            tie_gate_px: FRAME_TIE_GATE_PX,
        }
    }

    fn valid(&self) -> bool {
        let e = self.extraction;
        (1..=254).contains(&e.threshold)
            && (1..=MAX_IMAGE_FEATURES as u32).contains(&e.maximum_features)
            && (1..=128).contains(&e.separation)
            && self.tie_max_distance <= 256
            && (1..100).contains(&self.tie_ratio_percent)
            && self.tie_gate_px.is_finite()
            && self.tie_gate_px > 0.0
    }
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

/// Record encoding version: 1 (`FSSCAL01`, correspondence input only) or 2 (`FSSCAL02`, some
/// frame input).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RecordVersion {
    V1,
    V2,
}

impl RecordVersion {
    fn domain(self) -> &'static str {
        match self {
            Self::V1 => SITE_CALIBRATION_DOMAIN,
            Self::V2 => SITE_CALIBRATION_DOMAIN_V2,
        }
    }
    fn magic(self) -> &'static [u8; 8] {
        match self {
            Self::V1 => SITE_CALIBRATION_MAGIC,
            Self::V2 => SITE_CALIBRATION_MAGIC_V2,
        }
    }
}

fn domain_digest(version: RecordVersion, framed: &[u8]) -> ContentDigest {
    let domain = version.domain();
    let mut tagged = Vec::with_capacity(domain.len() + 1 + framed.len());
    tagged.extend_from_slice(domain.as_bytes());
    tagged.push(0);
    tagged.extend_from_slice(framed);
    ContentDigest::sha256(&tagged)
}

fn interpretation_code(interpretation: ComponentInterpretation) -> u8 {
    match interpretation {
        ComponentInterpretation::Grayscale => 0,
        ComponentInterpretation::YCbCr => 1,
    }
}

impl SiteCalibration {
    fn version(&self) -> RecordVersion {
        if self.frame_policy.is_some() {
            RecordVersion::V2
        } else {
            RecordVersion::V1
        }
    }

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
        let frames = self
            .cameras
            .iter()
            .any(|camera| matches!(camera.input, CalibrationInput::Frame(_)));
        if frames != self.frame_policy.is_some()
            || self.frame_policy.is_some_and(|policy| !policy.valid())
        {
            return Err(format(
                "a frame policy is present exactly when a camera took frame input",
            ));
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
        let version = self.version();
        let mut e = CanonicalEncoder::new();
        e.text(version.domain());
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
        // Version 2 only: the frame policy (validate() guarantees it is present).
        if let Some(policy) = self.frame_policy {
            put_raw(&mut e, &policy.decoder);
            e.u8(policy.extraction.threshold);
            e.u32(policy.extraction.maximum_features);
            e.u32(u32::from(policy.extraction.separation));
            e.u32(u32::from(policy.tie_max_distance));
            e.u8(policy.tie_ratio_percent);
            put_f64(&mut e, policy.tie_gate_px);
        }
        e.u64(self.cameras.len() as u64);
        for camera in &self.cameras {
            e.text(&camera.name);
            e.u64(camera.identity.camera);
            e.u64(camera.identity.intrinsics);
            e.u64(camera.identity.extrinsics);
            e.digest(camera.observations);
            if version == RecordVersion::V2 {
                match camera.input {
                    CalibrationInput::Correspondences => e.tag(0),
                    CalibrationInput::Frame(frame) => {
                        e.tag(1);
                        e.digest(frame.metadata);
                        e.digest(frame.luma);
                        e.tag(interpretation_code(frame.interpretation));
                        e.u64(frame.extracted_features);
                        e.u64(frame.atlas_matches);
                        e.u64(frame.tie_observations);
                    }
                }
            }
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
    /// `SHA-256(DOMAIN "\0" || magic || length || body)`, where magic and domain are
    /// `FSSCAL01` / `fss.site_calibration.v1` when every camera took correspondence input and
    /// `FSSCAL02` / `fss.site_calibration.v2` when some camera took frame input.
    pub fn encode(&self) -> Result<Vec<u8>, SiteCalibrationError> {
        let body = self.encode_body()?;
        let version = self.version();
        let mut bytes = Vec::with_capacity(body.len() + 48);
        bytes.extend_from_slice(version.magic());
        bytes.extend_from_slice(&(body.len() as u64).to_be_bytes());
        bytes.extend_from_slice(&body);
        if bytes.len() + 32 > MAX_CALIBRATION_BYTES {
            return Err(SiteCalibrationError::Format("calibration exceeds 4 MiB"));
        }
        let identity = domain_digest(version, &bytes).bytes();
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
        let version = if bytes.len() < 48 {
            return Err(format("not an FSSCAL01 or FSSCAL02 site calibration"));
        } else if bytes.starts_with(SITE_CALIBRATION_MAGIC) {
            RecordVersion::V1
        } else if bytes.starts_with(SITE_CALIBRATION_MAGIC_V2) {
            RecordVersion::V2
        } else {
            return Err(format("not an FSSCAL01 or FSSCAL02 site calibration"));
        };
        let end = bytes.len() - 32;
        let framed = &bytes[..end];
        let identity = domain_digest(version, framed);
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
        let record = Self::decode_body(&framed[16..], version)?;
        if record.encode()? != bytes {
            return Err(format("noncanonical encoding"));
        }
        Ok((record, identity))
    }

    fn decode_body(body: &[u8], version: RecordVersion) -> Result<Self, SiteCalibrationError> {
        let malformed = |_| SiteCalibrationError::Format("truncated or malformed body");
        let mut d = CanonicalDecoder::new(body);
        if d.text().map_err(malformed)? != version.domain() {
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
        let frame_policy = if version == RecordVersion::V2 {
            let decoder = raw(&mut d)?;
            let threshold = d.u8().map_err(malformed)?;
            let maximum_features = d.u32().map_err(malformed)?;
            let separation = u16::try_from(d.u32().map_err(malformed)?)
                .map_err(|_| SiteCalibrationError::Format("separation out of range"))?;
            let tie_max_distance = u16::try_from(d.u32().map_err(malformed)?)
                .map_err(|_| SiteCalibrationError::Format("tie distance out of range"))?;
            Some(FramePolicy {
                decoder,
                extraction: FrameExtraction {
                    threshold,
                    maximum_features,
                    separation,
                },
                tie_max_distance,
                tie_ratio_percent: d.u8().map_err(malformed)?,
                tie_gate_px: f64_of(&mut d)?,
            })
        } else {
            None
        };
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
            let input = if version == RecordVersion::V1 {
                CalibrationInput::Correspondences
            } else {
                match d.tag().map_err(malformed)? {
                    0 => CalibrationInput::Correspondences,
                    1 => CalibrationInput::Frame(FrameInput {
                        metadata: d.digest().map_err(malformed)?,
                        luma: d.digest().map_err(malformed)?,
                        interpretation: match d.tag().map_err(malformed)? {
                            0 => ComponentInterpretation::Grayscale,
                            1 => ComponentInterpretation::YCbCr,
                            _ => {
                                return Err(SiteCalibrationError::Format(
                                    "unknown frame interpretation",
                                ));
                            }
                        },
                        extracted_features: d.u64().map_err(malformed)?,
                        atlas_matches: d.u64().map_err(malformed)?,
                        tie_observations: d.u64().map_err(malformed)?,
                    }),
                    _ => return Err(SiteCalibrationError::Format("unknown camera input kind")),
                }
            };
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
                input,
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
            frame_policy,
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

/// Native extraction of one decoded frame into feature observations (no declared ties).
fn extract_frame(
    frame: &CameraFrame,
    budget: &mut WorkBudget<'_>,
) -> Result<CameraObservations, SiteCalibrationError> {
    let name = frame.name.as_str();
    let refused = |error: LocalizationError| match error {
        LocalizationError::Geometry(_) => SiteCalibrationError::LocalizationFailed {
            camera: name.to_owned(),
            reason: format!("feature extraction: {error}"),
        },
        other => invalid(name, format!("frame feature extraction refused: {other}")),
    };
    let image = ImageIdentity {
        exposure: frame.exposure,
        pixels: frame.luma_digest.bytes(),
        image_domain: frame.image_domain,
        dimensions: frame.dimensions,
    };
    // The whole decoded frame is admitted: the owner supplied it for calibration.
    let allowed = vec![1_u8; frame.luma.len()];
    let gray = GrayImage::new(image, &frame.luma, &allowed, budget).map_err(refused)?;
    let options = ExtractionOptions {
        threshold: FRAME_EXTRACTION.threshold,
        maximum_features: FRAME_EXTRACTION.maximum_features as usize,
        separation: FRAME_EXTRACTION.separation,
    };
    let extracted = extract_gray(&gray, options, budget).map_err(refused)?;
    Ok(CameraObservations {
        name: frame.name.clone(),
        identity: frame.identity,
        image,
        descriptor_domain: extracted.frame.descriptor_domain(),
        intrinsics: frame.intrinsics,
        features: extracted.frame.features().to_vec(),
        ties: Vec::new(),
        file_digest: frame.frame_digest,
    })
}

/// The atlas match report of a localization (every query feature's decision).
fn match_report(localized: &Localized) -> &MatchReport {
    match localized {
        Localized::Fixed(localization) => &localization.matches,
        Localized::Focal(localization) => &localization.matches,
    }
}

/// Intrinsics and pose of the selected seed candidate.
fn seed_geometry(
    localized: &Localized,
    selection: &Selection,
) -> Option<(PinholeIntrinsics, RigidPose)> {
    match localized {
        Localized::Fixed(localization) => match &localization.outcome {
            LocalizationOutcome::Candidates(search) => search
                .candidates()
                .get(selection.candidate)
                .map(|candidate| (search.intrinsics(), candidate.pose())),
            _ => None,
        },
        Localized::Focal(localization) => match &localization.outcome {
            FocalLocalizationOutcome::Scan(scan) => {
                let sample = scan.samples().get(selection.sample?)?;
                match sample.outcome() {
                    FocalSampleOutcome::Candidates(search) => search
                        .candidates()
                        .get(selection.candidate)
                        .map(|candidate| (sample.intrinsics(), candidate.pose())),
                    FocalSampleOutcome::GeometricFailure(_) => None,
                }
            }
            FocalLocalizationOutcome::InsufficientMatches { .. } => None,
        },
    }
}

/// Mutual nearest-neighbour descriptor matches between two free-feature sets, under the atlas
/// matcher's rules: best distance at most [`FRAME_TIE_MAX_DISTANCE`], a distinct runner-up with
/// `best * 100 < runner_up * FRAME_TIE_RATIO_PERCENT`, and a unique reverse nearest neighbour.
fn mutual_matches(
    a: &[ImageFeature],
    b: &[ImageFeature],
    budget: &mut WorkBudget<'_>,
) -> Result<Vec<(usize, usize)>, SiteCalibrationError> {
    let exhausted =
        |error| SiteCalibrationError::Refinement(format!("frame tie matching: {error}"));
    budget
        .charge((a.len() * b.len()) as u64 * 4)
        .map_err(exhausted)?;
    let distances: Vec<u16> = a
        .iter()
        .flat_map(|x| b.iter().map(move |y| x.descriptor.distance(y.descriptor)))
        .collect();
    let mut reverse: Vec<Option<usize>> = vec![None; b.len()];
    for (j, slot) in reverse.iter_mut().enumerate() {
        let mut best = u16::MAX;
        for i in 0..a.len() {
            let d = distances[i * b.len() + j];
            if d < best {
                best = d;
                *slot = Some(i);
            } else if d == best {
                *slot = None;
            }
        }
    }
    let mut pairs = Vec::new();
    for i in 0..a.len() {
        let mut first = (u16::MAX, 0_usize);
        let mut second = u16::MAX;
        for j in 0..b.len() {
            let d = distances[i * b.len() + j];
            if d < first.0 {
                second = first.0;
                first = (d, j);
            } else {
                second = second.min(d);
            }
        }
        let accepted = first.0 <= FRAME_TIE_MAX_DISTANCE
            && second != u16::MAX
            && first.0 != second
            && u32::from(first.0) * 100 < u32::from(second) * u32::from(FRAME_TIE_RATIO_PERCENT)
            && reverse[first.1] == Some(i);
        if accepted {
            pairs.push((i, first.1));
        }
    }
    Ok(pairs)
}

/// Least-squares intersection of rays `(origin, unit direction)`; `None` when (near) parallel.
fn triangulate(rays: &[([f64; 3], [f64; 3])]) -> Option<[f64; 3]> {
    let mut a = [[0.0_f64; 3]; 3];
    let mut b = [0.0_f64; 3];
    for (origin, direction) in rays {
        for r in 0..3 {
            for c in 0..3 {
                let projector = f64::from(u8::from(r == c)) - direction[r] * direction[c];
                a[r][c] += projector;
                b[r] += projector * origin[c];
            }
        }
    }
    let det = |m: [[f64; 3]; 3]| {
        m[0][0] * (m[1][1] * m[2][2] - m[1][2] * m[2][1])
            - m[0][1] * (m[1][0] * m[2][2] - m[1][2] * m[2][0])
            + m[0][2] * (m[1][0] * m[2][1] - m[1][1] * m[2][0])
    };
    let whole = det(a);
    let trace = a[0][0] + a[1][1] + a[2][2];
    if !whole.is_finite() || whole.abs() <= 1e-9 * (trace / 3.0).powi(3) {
        return None;
    }
    let mut point = [0.0; 3];
    for (k, value) in point.iter_mut().enumerate() {
        let mut replaced = a;
        for r in 0..3 {
            replaced[r][k] = b[r];
        }
        *value = det(replaced) / whole;
    }
    point.iter().all(|x| x.is_finite()).then_some(point)
}

/// Derives tie observations between frame cameras: features that matched no atlas landmark are
/// matched pairwise (cameras in handle order, [`mutual_matches`]), joined into tracks by union,
/// and a track is kept when it has at most one feature per camera, its rays triangulate, and
/// every view reprojects within [`FRAME_TIE_GATE_PX`] at the seeded poses. Kept tracks are
/// numbered `base, base + 1, ...` in the order of their first (camera handle, feature id).
/// Returns `(camera index, tie)` pairs.
fn derive_frame_ties(
    observations: &[CameraObservations],
    localized: &[(Localized, Selection, SeedMode)],
    frames: &[usize],
    base: u64,
    budget: &mut WorkBudget<'_>,
) -> Result<Vec<(usize, TieObservation)>, SiteCalibrationError> {
    let mut order = frames.to_vec();
    order.sort_by_key(|&index| observations[index].identity.camera);
    let mut free: Vec<Vec<ImageFeature>> = Vec::with_capacity(order.len());
    let mut seeds = Vec::with_capacity(order.len());
    for &index in &order {
        let (result, selection, _) = &localized[index];
        let matched: BTreeSet<u64> = match_report(result)
            .decisions
            .iter()
            .filter(|decision| decision.landmark.is_some())
            .map(|decision| decision.image_feature)
            .collect();
        free.push(
            observations[index]
                .features
                .iter()
                .filter(|feature| !matched.contains(&feature.id))
                .copied()
                .collect(),
        );
        seeds.push(seed_geometry(result, selection).ok_or_else(|| {
            SiteCalibrationError::Refinement("a frame camera has no seed pose".to_owned())
        })?);
    }
    let mut offsets = Vec::with_capacity(order.len() + 1);
    offsets.push(0_usize);
    for features in &free {
        offsets.push(offsets[offsets.len() - 1] + features.len());
    }
    let total = offsets[order.len()];
    let mut parent: Vec<usize> = (0..total).collect();
    fn root(parent: &mut [usize], mut node: usize) -> usize {
        while parent[node] != node {
            parent[node] = parent[parent[node]];
            node = parent[node];
        }
        node
    }
    for a in 0..order.len() {
        for b in a + 1..order.len() {
            for (i, j) in mutual_matches(&free[a], &free[b], budget)? {
                let x = root(&mut parent, offsets[a] + i);
                let y = root(&mut parent, offsets[b] + j);
                if x != y {
                    parent[x.max(y)] = x.min(y);
                }
            }
        }
    }
    let mut tracks: BTreeMap<usize, Vec<usize>> = BTreeMap::new();
    for node in 0..total {
        let key = root(&mut parent, node);
        tracks.entry(key).or_default().push(node);
    }
    let slot_of = |node: usize| offsets.partition_point(|&start| start <= node) - 1;
    let mut ties = Vec::new();
    let mut next = base;
    // The union keeps the smallest node as each root, so key order is first-member order.
    for members in tracks.values().filter(|members| members.len() >= 2) {
        budget
            .charge(16 * members.len() as u64)
            .map_err(|error| SiteCalibrationError::Refinement(format!("frame ties: {error}")))?;
        let views: Vec<(usize, [f64; 2])> = members
            .iter()
            .map(|&node| {
                let slot = slot_of(node);
                (slot, free[slot][node - offsets[slot]].pixel)
            })
            .collect();
        if views.windows(2).any(|pair| pair[0].0 == pair[1].0) {
            continue;
        }
        let rays: Option<Vec<([f64; 3], [f64; 3])>> = views
            .iter()
            .map(|&(slot, pixel)| {
                let (intrinsics, pose) = seeds[slot];
                pose.ray(intrinsics, pixel)
                    .ok()
                    .map(|ray| (ray.origin(), ray.direction()))
            })
            .collect();
        let Some(point) = rays.as_deref().and_then(triangulate) else {
            continue;
        };
        let consistent = views.iter().all(|&(slot, pixel)| {
            let (intrinsics, pose) = seeds[slot];
            pose.project(intrinsics, point).is_ok_and(|projected| {
                (projected[0] - pixel[0]).hypot(projected[1] - pixel[1]) <= FRAME_TIE_GATE_PX
            })
        });
        if !consistent {
            continue;
        }
        for &(slot, pixel) in &views {
            let index = order[slot];
            ties.push((
                index,
                TieObservation {
                    camera: observations[index].identity.camera,
                    tie: next,
                    pixel,
                },
            ));
        }
        next = next
            .checked_add(1)
            .ok_or_else(|| invalid("", "no tie handle remains above the atlas handles"))?;
    }
    Ok(ties)
}

/// Localizes every camera independently, refines them jointly and returns the record.
/// Refusals are typed; no partial calibration is ever returned. Correspondence input only (the
/// record is `FSSCAL01`); [`calibrate_site_inputs`] also takes frames.
pub fn calibrate_site(
    request: &CalibrationRequest<'_>,
    observations: &[CameraObservations],
) -> Result<SiteCalibration, SiteCalibrationError> {
    let inputs: Vec<CameraInput> = observations
        .iter()
        .cloned()
        .map(CameraInput::Correspondences)
        .collect();
    calibrate_site_inputs(request, &inputs)
}

/// [`calibrate_site`] over correspondence and/or frame input. Frame cameras are extracted with
/// the native extractor ([`FRAME_EXTRACTION`]) against the decoded luma, localized through the
/// same atlas matcher and pose search as correspondence cameras, and coupled by derived tie
/// points (see the module documentation). Frame-derived ties couple frame cameras only: a
/// single frame camera among correspondence cameras has no tie path and is refused as
/// disconnected. Refusals are typed; no partial calibration is ever returned.
pub fn calibrate_site_inputs(
    request: &CalibrationRequest<'_>,
    inputs: &[CameraInput],
) -> Result<SiteCalibration, SiteCalibrationError> {
    if inputs.len() < 2 || inputs.len() > MAX_SITE_CAMERAS {
        return Err(invalid("", "a site calibration takes 2..16 cameras"));
    }
    let mut names = BTreeSet::new();
    let mut handles = BTreeSet::new();
    for camera in inputs {
        if !names.insert(camera.name()) {
            return Err(invalid(camera.name(), "camera names must be unique"));
        }
        if !handles.insert(camera.identity().camera) {
            return Err(invalid(camera.name(), "camera handles must be unique"));
        }
    }
    let descriptor_domain = inputs[0].descriptor_domain();
    if inputs
        .iter()
        .any(|camera| camera.descriptor_domain() != descriptor_domain)
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

    // Frame cameras become feature observations through the native extractor, charged to the
    // calibration budget; correspondence cameras are used as supplied.
    let mut prepared = Vec::with_capacity(inputs.len());
    let mut extracted = vec![0_u64; inputs.len()];
    for (index, input) in inputs.iter().enumerate() {
        match input {
            CameraInput::Correspondences(observations) => prepared.push(observations.clone()),
            CameraInput::Frame(frame) => {
                let observations = extract_frame(frame, &mut budget)?;
                extracted[index] = observations.features.len() as u64;
                prepared.push(observations);
            }
        }
    }
    let observations = prepared.as_slice();

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
    let mut ties: Vec<TieObservation> = observations
        .iter()
        .flat_map(|camera| {
            camera.ties.iter().map(|(tie, pixel)| TieObservation {
                camera: camera.identity.camera,
                tie: *tie,
                pixel: *pixel,
            })
        })
        .collect();
    // Frame-derived ties: handles above every atlas landmark and declared tie handle.
    let frames: Vec<usize> = inputs
        .iter()
        .enumerate()
        .filter(|(_, input)| matches!(input, CameraInput::Frame(_)))
        .map(|(index, _)| index)
        .collect();
    let mut frame_ties = vec![0_u64; inputs.len()];
    if frames.len() >= 2 {
        let highest = atlas
            .landmarks()
            .iter()
            .map(|landmark| landmark.id)
            .chain(ties.iter().map(|tie| tie.tie))
            .max()
            .unwrap_or(0);
        let base = highest
            .checked_add(1)
            .ok_or_else(|| invalid("", "no tie handle remains above the atlas handles"))?;
        for (index, tie) in derive_frame_ties(observations, &localized, &frames, base, &mut budget)?
        {
            frame_ties[index] += 1;
            ties.push(tie);
        }
    }
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
            input: match &inputs[index] {
                CameraInput::Correspondences(_) => CalibrationInput::Correspondences,
                CameraInput::Frame(frame) => CalibrationInput::Frame(FrameInput {
                    metadata: frame.metadata_digest,
                    luma: frame.luma_digest,
                    interpretation: frame.interpretation,
                    extracted_features: extracted[index],
                    atlas_matches: match_report(&localized[index].0).correspondences.len() as u64,
                    tie_observations: frame_ties[index],
                }),
            },
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
        frame_policy: (!frames.is_empty()).then(FramePolicy::current),
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
            frame_policy: None,
            cameras: vec![CalibratedCamera {
                name: "east".to_owned(),
                identity: CameraGeneration {
                    camera: 1,
                    intrinsics: 2,
                    extrinsics: 3,
                },
                observations: digest,
                input: CalibrationInput::Correspondences,
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

    /// Correspondence-input records are byte-identical to those written before frame input
    /// existed: these digests were produced by the pre-frame encoder (commit 837ead8) on the
    /// same records.
    #[test]
    fn correspondence_records_keep_their_pre_frame_v1_bytes() -> Result<(), SiteCalibrationError> {
        for (distortion, file, identity) in [
            (
                [0.0, 0.0],
                "sha256:40c57d5801c9d92e8ef45456c2845c9e0ea0789ac7efe5619d32e8259aefb3ae",
                "sha256:120ccbf217d5dabb518124f20446b6d3fe126f20def203dc590c172541f52bfd",
            ),
            (
                [-0.05, 0.0],
                "sha256:eb21b612871a1930f3e8852bc7028f7be2e211e1f41e92df30360e321efd3e31",
                "sha256:4f032126391d457c2c352a68da5b423bab6619066cabe976333309406158ff5f",
            ),
        ] {
            let value = record(distortion);
            let bytes = value.encode()?;
            assert_eq!(bytes.len(), 896);
            assert!(bytes.starts_with(SITE_CALIBRATION_MAGIC));
            assert_eq!(ContentDigest::sha256(&bytes).to_text(), file);
            assert_eq!(value.digest()?.to_text(), identity);
        }
        Ok(())
    }

    fn frame_record() -> SiteCalibration {
        let mut value = record([0.0, 0.0]);
        value.frame_policy = Some(FramePolicy::current());
        value.cameras[0].input = CalibrationInput::Frame(FrameInput {
            metadata: ContentDigest::sha256(b"metadata"),
            luma: ContentDigest::sha256(b"luma"),
            interpretation: ComponentInterpretation::Grayscale,
            extracted_features: 300,
            atlas_matches: 40,
            tie_observations: 25,
        });
        value
    }

    #[test]
    fn frame_records_are_v2_exact_and_every_byte_is_bound() -> Result<(), SiteCalibrationError> {
        let value = frame_record();
        let bytes = value.encode()?;
        assert!(bytes.starts_with(SITE_CALIBRATION_MAGIC_V2));
        let (decoded, identity) = SiteCalibration::decode(&bytes, Some(value.digest()?))?;
        assert_eq!(decoded, value);
        assert_eq!(identity, value.digest()?);
        // The v2 identity is taken under the v2 domain, never the v1 one.
        assert_ne!(
            identity,
            domain_digest(RecordVersion::V1, &bytes[..bytes.len() - 32])
        );
        for index in 0..bytes.len() {
            let mut changed = bytes.clone();
            changed[index] ^= 0x01;
            assert!(
                SiteCalibration::decode(&changed, None).is_err(),
                "byte {index}"
            );
        }
        Ok(())
    }

    #[test]
    fn frame_policy_and_frame_cameras_go_together() {
        // A frame policy without a frame camera (which would be a v2 record of correspondence
        // input) and a frame camera without a policy are both refused before encoding.
        let mut policy_only = record([0.0, 0.0]);
        policy_only.frame_policy = Some(FramePolicy::current());
        assert!(matches!(
            policy_only.encode(),
            Err(SiteCalibrationError::Format(_))
        ));
        let mut frame_only = frame_record();
        frame_only.frame_policy = None;
        assert!(matches!(
            frame_only.encode(),
            Err(SiteCalibrationError::Format(_))
        ));
    }

    fn gray_jpeg(width: u32, height: u32) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        use crate::media_fixture::jpeg::{JpegConfig, Subsampling, encode_jpeg};
        let pixels: Vec<u8> = (0..width * height)
            .map(|i| (i.wrapping_mul(2_654_435_761) >> 24) as u8)
            .collect();
        Ok(encode_jpeg(
            width,
            height,
            &pixels,
            &JpegConfig {
                quality: 90,
                subsampling: Subsampling::Grayscale,
                restart_interval: 0,
                custom_markers: Vec::new(),
            },
        )?)
    }

    const FRAME_METADATA: &str = "fss.site_camera_frame.v1\ncamera 1 2 3\nimage 64 48\n\
        exposure sha256:0101010101010101010101010101010101010101010101010101010101010101\n\
        image-domain sha256:0303030303030303030303030303030303030303030303030303030303030303\n\
        interpretation gray\n\
        intrinsics fixed 50 50 32 24\n";

    #[test]
    fn frame_metadata_is_strict_and_frames_decode_or_refuse_typed()
    -> Result<(), Box<dyn std::error::Error>> {
        let jpeg = gray_jpeg(64, 48)?;
        let frame = CameraFrame::decode("east", FRAME_METADATA.as_bytes(), &jpeg)?;
        assert_eq!(frame.dimensions, [64, 48]);
        assert_eq!(frame.luma().len(), 64 * 48);
        assert_eq!(frame.frame_digest, ContentDigest::sha256(&jpeg));
        assert_eq!(frame.luma_digest, ContentDigest::sha256(frame.luma()));
        assert_eq!(
            frame.metadata_digest,
            ContentDigest::sha256(FRAME_METADATA.as_bytes())
        );
        // Truncated or foreign bytes are typed decode refusals.
        for broken in [&jpeg[..jpeg.len() - 40], b"not a jpeg".as_slice()] {
            let refused = CameraFrame::decode("east", FRAME_METADATA.as_bytes(), broken);
            assert!(
                matches!(refused, Err(SiteCalibrationError::FrameDecode { .. })),
                "{refused:?}"
            );
            if let Err(error) = refused {
                assert_eq!(error.stable_id(), "ERR-SITE-CALIBRATION-FRAME-DECODE-001");
            }
        }
        // A frame of another size than declared is refused.
        let other = gray_jpeg(64, 40)?;
        assert!(matches!(
            CameraFrame::decode("east", FRAME_METADATA.as_bytes(), &other),
            Err(SiteCalibrationError::FrameDecode { .. })
        ));
        // Pixel, descriptor, feature and tie lines belong to correspondence input only, and the
        // interpretation line is required.
        for broken in [
            format!(
                "{FRAME_METADATA}pixels sha256:0202020202020202020202020202020202020202020202020202020202020202\n"
            ),
            format!(
                "{FRAME_METADATA}descriptor-domain sha256:0404040404040404040404040404040404040404040404040404040404040404\n"
            ),
            format!("{FRAME_METADATA}tie 7 3 4\n"),
            FRAME_METADATA.replace("interpretation gray\n", ""),
            FRAME_METADATA.replace("interpretation gray", "interpretation rgb"),
            FRAME_METADATA.replace(
                "fss.site_camera_frame.v1",
                "fss.site_camera_observations.v1",
            ),
        ] {
            assert!(
                matches!(
                    CameraFrame::decode("east", broken.as_bytes(), &jpeg),
                    Err(SiteCalibrationError::InvalidInput { .. })
                ),
                "{broken}"
            );
        }
        Ok(())
    }

    #[test]
    fn rays_triangulate_and_parallel_rays_do_not() {
        let point = [3.0_f64, -2.0, 1.5];
        let origins = [[0.0_f64, 0.0, 10.0], [4.0, 1.0, 9.0], [-2.0, 5.0, 12.0]];
        let rays: Vec<([f64; 3], [f64; 3])> = origins
            .iter()
            .map(|o| {
                let d = [point[0] - o[0], point[1] - o[1], point[2] - o[2]];
                let n = (d[0] * d[0] + d[1] * d[1] + d[2] * d[2]).sqrt();
                (*o, [d[0] / n, d[1] / n, d[2] / n])
            })
            .collect();
        let found = triangulate(&rays);
        assert!(found.is_some());
        if let Some(found) = found {
            assert!(
                (0..3).all(|k| (found[k] - point[k]).abs() < 1e-9),
                "{found:?}"
            );
        }
        let parallel = [
            ([0.0, 0.0, 0.0], [0.0, 0.0, 1.0]),
            ([1.0, 0.0, 0.0], [0.0, 0.0, 1.0]),
        ];
        assert!(triangulate(&parallel).is_none());
    }
}
