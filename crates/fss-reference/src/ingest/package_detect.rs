#![forbid(unsafe_code)]
//! Retained recording -> verified RGB detector package -> source-space detector proposals.
//!
//! Reads completed retained imports only (JPEG/MJPEG, H.264 Annex-B, H.265/HEVC Annex-B)
//! through the canonical codecs. JPEG frames are decoded to RGB with the native color decoder;
//! H.264/H.265 frames are converted from their decoded 4:2:0 planes (luma and chroma) through the
//! declared BT.601 limited-range transform ([`super::recorded_decode::video_rgb`]). Nothing is
//! published, activated or alerted: the result is a complete, deterministic JSON report of
//! uncalibrated proposals with exact source, inference, contract and package identities. An
//! empty frame is not evidence of absence. The sensor's current privacy mask
//! ([`super::privacy_mask`]) is applied to every decoded RGB frame before the model sees it, and
//! the same mask is the per-pixel permission of the RGB privacy projection, so no detection may
//! touch a masked pixel; the report names the binding. [`super::package_event`] can retain a report as
//! cognition-plane evidence for the recorded-event workflow.

use std::collections::BTreeSet;
use std::error::Error;
use std::fmt;
use std::fmt::Write as _;

use fss_codec_mjpeg::color::{DecodedRgb, RgbDecodeLimits, RgbDecodeReceipt, decode_rgb};
use fss_codec_mjpeg::{ComponentInterpretation, DecodeBudget};
use fss_core::{ContentDigest, DigestAlgorithm, SensorCapsule};

use super::privacy_mask::{MaskBinding, current_mask};
use super::recorded_decode::h264::{DecoderLimits, RecordedH264Range, RecordedH264Request};
use super::recorded_decode::h265::{
    DecoderLimits as H265DecoderLimits, RecordedH265Range, RecordedH265Request,
};
use super::recorded_decode::video_rgb::{VIDEO_RGB_COLOR, video_rgb_receipt};
use super::recorded_decode::{RecordedDecodeError, source_capsule};
use super::rgb_detections::{
    RgbDetectionBudget, RgbDetectionContract, RgbDetectionReport, project_rgb_detections,
};
use super::rgb_inference::{RgbInference, RgbRunLimits, RgbSourceBinding};
use super::rgb_package::RgbDetectorPackage;
use super::{RetainedFileImport, RetainedReadLimits};
use crate::{ExecBudget, ReferenceDeployment, ReplayCx, ScalarExecCx};

/// Motion-independent, budgeted detector bursts with no tracking across sampling gaps.
pub mod sentinel;

/// Report schema identity (also its digest domain; the digest is SHA-256 of the JSON bytes).
pub const PACKAGE_DETECTION_REPORT_SCHEMA: &str = "fss.package_detection_report.v1";
/// Largest admitted frame range for one bounded invocation.
pub const MAX_PACKAGE_DETECT_FRAMES: usize = 64;

/// Exact retained source range and optional explicit threshold override.
#[derive(Clone, Debug)]
pub struct PackageDetectRequest {
    /// Completed retained import.
    pub import_identity: ContentDigest,
    /// First zero-based segment (H.264: an IDR; H.265: an IRAP).
    pub first_segment: usize,
    /// Number of contiguous segments, 1..=[`MAX_PACKAGE_DETECT_FRAMES`].
    pub segment_count: usize,
    /// Explicit JPEG component interpretation; H.264/H.265 require YCbCr.
    pub interpretation: ComponentInterpretation,
    /// `None` uses the package's own threshold; `Some` is an explicit operator override.
    pub minimum_score_ppm: Option<u32>,
}

/// Independent read, decode, inference and detection bounds.
#[derive(Clone, Copy, Debug)]
pub struct PackageDetectLimits {
    /// Custody-read ceilings per segment.
    pub read: RetainedReadLimits,
    /// JPEG RGB decode ceilings.
    pub jpeg: RgbDecodeLimits,
    /// Cumulative JPEG codec work.
    pub jpeg_work_units: u64,
    /// H.264 codec ceilings (`max_pictures` is narrowed to the range).
    pub h264: DecoderLimits,
    /// H.265 codec ceilings (`max_pictures` is narrowed to the range).
    pub h265: H265DecoderLimits,
    /// Per-frame preprocessing and model-execution ceilings.
    pub run: RgbRunLimits,
    /// Cumulative detection-head work units.
    pub detection_work_units: u64,
    /// Per-frame detection scratch bytes.
    pub detection_scratch_bytes: usize,
}
impl Default for PackageDetectLimits {
    fn default() -> Self {
        Self {
            read: RetainedReadLimits::default(),
            jpeg: RgbDecodeLimits::default(),
            jpeg_work_units: 1_000_000_000,
            h264: DecoderLimits::default(),
            h265: H265DecoderLimits::default(),
            run: RgbRunLimits {
                decode: RgbDecodeLimits::default(),
                preprocess: ExecBudget::new(2_000_000_000, 256 * 1024 * 1024),
                execution: ExecBudget::new(8_000_000_000, 256 * 1024 * 1024),
                maximum_output_bytes: 16 * 1024 * 1024,
            },
            detection_work_units: 2_000_000_000,
            detection_scratch_bytes: 256 * 1024 * 1024,
        }
    }
}

/// Typed refusal; no partial report is returned.
#[derive(Debug)]
pub enum PackageDetectError {
    /// Range, interpretation or format outside this operation's contract.
    InvalidRequest,
    /// Retained custody, decode, inference or detection refused; see the source error.
    Frame {
        /// Segment being processed.
        segment: usize,
        /// Underlying refusal.
        source: Box<dyn Error>,
    },
    /// Owner cancellation.
    Cancelled,
}
impl PackageDetectError {
    /// Registered stable error identity (registries/ERRORS.md).
    #[must_use]
    pub fn stable_id(&self) -> &'static str {
        match self {
            Self::InvalidRequest => "ERR-PACKAGE-DETECT-REQUEST-001",
            Self::Frame { .. } => "ERR-PACKAGE-DETECT-001",
            Self::Cancelled => "ERR-PACKAGE-DETECT-CANCELLED-001",
        }
    }
}
impl fmt::Display for PackageDetectError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidRequest => f.write_str("package detection request outside its contract"),
            Self::Frame { segment, source } => write!(
                f,
                "package detection refused at segment {segment}: {source}"
            ),
            Self::Cancelled => f.write_str("package detection cancelled"),
        }
    }
}
impl Error for PackageDetectError {}

/// One completed frame: exact source, inference and complete head projection.
#[derive(Debug)]
pub struct PackageDetectFrame {
    /// Retained segment index.
    pub segment: usize,
    /// Retained source capsule.
    pub capsule: SensorCapsule,
    /// Retained source-capsule payload digest.
    pub capsule_digest: ContentDigest,
    /// `jpeg_rgb` (native color decode) or `ycbcr420_bt601_limited_rgb` (declared video
    /// transform over decoded luma and chroma).
    pub color: &'static str,
    /// Coded width and height.
    pub dimensions: [u32; 2],
    /// Complete numerical inference (all output tensors retained).
    pub inference: RgbInference,
    /// Complete head projection (rows, candidates, survivors).
    pub detections: RgbDetectionReport,
}

/// Complete report over the requested range.
#[derive(Debug)]
pub struct PackageDetectReport {
    /// Exact completed import.
    pub import_identity: ContentDigest,
    /// Published import root.
    pub import_root: ContentDigest,
    /// Retained media format (`mjpeg`, `annexb` or `hevc`).
    pub media_format: String,
    /// First requested segment.
    pub first_segment: usize,
    /// Requested segment count.
    pub segment_count: usize,
    /// Applied inclusive score threshold (package default or explicit override), ppm.
    pub minimum_score_ppm: u32,
    /// Completed frames in decode/display order.
    pub frames: Vec<PackageDetectFrame>,
    /// Contract actually applied.
    pub contract: ContentDigest,
    /// Canonical JSON rendering.
    pub json: String,
    /// SHA-256 of the JSON bytes.
    pub digest: ContentDigest,
    /// Privacy mask binding applied to every frame.
    pub privacy: MaskBinding,
}

fn frame_error<E: Error + 'static>(segment: usize) -> impl FnOnce(E) -> PackageDetectError {
    move |e| PackageDetectError::Frame {
        segment,
        source: Box::new(e),
    }
}

fn nonzero_u64(digest: ContentDigest) -> u64 {
    let b = digest.bytes();
    u64::from_be_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]]).max(1)
}

fn binding(
    capsule: &SensorCapsule,
    capsule_digest: ContentDigest,
    import_root: ContentDigest,
    permission: ContentDigest,
    segment: usize,
) -> Result<RgbSourceBinding, PackageDetectError> {
    let time = |t: i128| {
        u64::try_from(t).map_err(|_| PackageDetectError::Frame {
            segment,
            source: "capture time outside the unsigned nanosecond range".into(),
        })
    };
    Ok(RgbSourceBinding {
        encoded_sha256: capsule.source_digest.bytes(),
        exposure: capsule_digest.bytes(),
        camera: nonzero_u64(ContentDigest::sha256(capsule.sensor_id.as_str().as_bytes())),
        clock: nonzero_u64(ContentDigest::sha256(
            capsule.clock_basis.as_str().as_bytes(),
        )),
        capture: [
            time(capsule.capture.earliest.0)?,
            time(capsule.capture.latest.0)?,
        ],
        image_domain: import_root.bytes(),
        // No calibration exists for a retained file import: a fixed, explicit sentinel.
        calibration: ContentDigest::sha256(b"fss.package_detection.uncalibrated").bytes(),
        permission_mask: permission.bytes(),
    })
}

/// Decoded RGB of one retained frame: native JPEG color or the declared video transform.
pub(crate) enum FramePixels {
    /// Native JPEG color decode (no mask policy: explicitly unmasked).
    Jpeg(DecodedRgb),
    /// Native JPEG color decode with the sensor's privacy mask applied.
    MaskedJpeg {
        rgb: Vec<u8>,
        receipt: RgbDecodeReceipt,
    },
    /// H.264/H.265 4:2:0 planes through the declared BT.601 limited-range transform.
    Video {
        rgb: Vec<u8>,
        receipt: RgbDecodeReceipt,
    },
}

/// One decoded retained frame ready for inference.
pub(crate) struct DecodedFrame {
    pub(crate) segment: usize,
    pub(crate) capsule: SensorCapsule,
    pub(crate) capsule_digest: ContentDigest,
    pub(crate) dimensions: [u32; 2],
    pub(crate) pixels: FramePixels,
    pub(crate) mask: MaskBinding,
}

/// Retained video picture identities needed to convert and bind its RGB.
pub(crate) struct VideoPicture<'a> {
    pub(crate) segment: u64,
    pub(crate) capsule: &'a SensorCapsule,
    pub(crate) capsule_digest: ContentDigest,
    pub(crate) dimensions: [u32; 2],
    pub(crate) codec_receipt: ContentDigest,
    pub(crate) i420: ContentDigest,
    pub(crate) rgb: Result<Vec<u8>, RecordedDecodeError>,
    pub(crate) mask: MaskBinding,
}

impl DecodedFrame {
    /// Binds converted video RGB to its retained frame receipt.
    pub(crate) fn video(picture: VideoPicture<'_>) -> Result<Self, PackageDetectError> {
        let segment =
            usize::try_from(picture.segment).map_err(|_| PackageDetectError::InvalidRequest)?;
        let rgb = picture.rgb.map_err(frame_error(segment))?;
        let receipt = video_rgb_receipt(
            picture.capsule.source_digest.bytes(),
            picture.codec_receipt,
            picture.i420,
            picture.dimensions,
            &rgb,
        );
        Ok(Self {
            segment,
            capsule: picture.capsule.clone(),
            capsule_digest: picture.capsule_digest,
            dimensions: picture.dimensions,
            pixels: FramePixels::Video { rgb, receipt },
            mask: picture.mask,
        })
    }
    /// Native JPEG RGB decode with `mask` applied before any consumer sees it.
    pub(crate) fn jpeg(
        segment: usize,
        capsule: SensorCapsule,
        capsule_digest: ContentDigest,
        image: DecodedRgb,
        mask: MaskBinding,
    ) -> Result<Self, PackageDetectError> {
        let dimensions = image.dimensions();
        let pixels = match mask
            .mask_rgb_decode(image.pixels(), image.receipt())
            .map_err(frame_error(segment))?
        {
            None => FramePixels::Jpeg(image),
            Some((rgb, receipt)) => FramePixels::MaskedJpeg { rgb, receipt },
        };
        Ok(Self {
            segment,
            capsule,
            capsule_digest,
            dimensions,
            pixels,
            mask,
        })
    }
    /// SHA-256 of the packed RGB the model sees before privacy projection and resize.
    pub(crate) fn rgb_digest(&self) -> ContentDigest {
        let bytes = match &self.pixels {
            FramePixels::Jpeg(image) => image.receipt().rgb_sha256,
            FramePixels::MaskedJpeg { receipt, .. } | FramePixels::Video { receipt, .. } => {
                receipt.rgb_sha256
            }
        };
        ContentDigest::new(DigestAlgorithm::Sha256, bytes)
    }
}

/// Inference and head projection of decoded frames through one verified package.
pub(crate) struct FrameRun<'a> {
    pub(crate) package: &'a RgbDetectorPackage,
    pub(crate) contract: &'a RgbDetectionContract,
    pub(crate) run: RgbRunLimits,
    pub(crate) import_root: ContentDigest,
    pub(crate) budget: RgbDetectionBudget,
    pub(crate) scalar: &'a ScalarExecCx,
    pub(crate) cx: &'a ReplayCx,
}
impl FrameRun<'_> {
    pub(crate) fn infer(
        &mut self,
        d: DecodedFrame,
    ) -> Result<PackageDetectFrame, PackageDetectError> {
        self.cx
            .checkpoint("package_detect:frame")
            .map_err(|_| PackageDetectError::Cancelled)?;
        // The sensor's retained privacy mask is the per-pixel permission: masked pixels are
        // projected out again before the model and screen every detection. Without a policy
        // every pixel is admitted, and that choice is bound into the source binding as a digest.
        let allowed = d
            .mask
            .allowed(d.dimensions)
            .map_err(frame_error(d.segment))?;
        let source = binding(
            &d.capsule,
            d.capsule_digest,
            self.import_root,
            ContentDigest::sha256(&allowed),
            d.segment,
        )?;
        let model = self.package.model();
        let (inference, color) = match &d.pixels {
            FramePixels::Jpeg(image) => (
                model.run_decoded(image, source, &allowed, self.run, self.scalar),
                "jpeg_rgb",
            ),
            FramePixels::MaskedJpeg { rgb, receipt } => (
                model.run_rgb_pixels(rgb, *receipt, source, &allowed, self.run, self.scalar),
                "jpeg_rgb",
            ),
            FramePixels::Video { rgb, receipt } => (
                model.run_rgb_pixels(rgb, *receipt, source, &allowed, self.run, self.scalar),
                VIDEO_RGB_COLOR,
            ),
        };
        let inference = inference.map_err(frame_error(d.segment))?;
        let detections = project_rgb_detections(
            &inference,
            self.contract,
            &allowed,
            &mut self.budget,
            self.scalar,
        )
        .map_err(frame_error(d.segment))?;
        Ok(PackageDetectFrame {
            segment: d.segment,
            capsule: d.capsule,
            capsule_digest: d.capsule_digest,
            color,
            dimensions: d.dimensions,
            inference,
            detections,
        })
    }
}

/// Run a verified package over a retained range. `scalar` owns inference cancellation.
/// Frames are decoded and inferred one at a time; no decoded range is buffered.
pub fn run_package_detection(
    deployment: &ReferenceDeployment,
    package: &RgbDetectorPackage,
    request: &PackageDetectRequest,
    limits: &PackageDetectLimits,
    cx: &ReplayCx,
    scalar: &ScalarExecCx,
) -> Result<PackageDetectReport, PackageDetectError> {
    run_selected_detection(
        deployment,
        package,
        request,
        limits,
        cx,
        scalar,
        None,
        |contract, import_root, media_format, frames, privacy| {
            finish_report(
                package,
                request,
                contract,
                import_root,
                media_format,
                frames,
                privacy,
            )
        },
    )
}

// A sparse selection is an internal execution primitive, never a sparse report labelled
// complete. Its caller must partition the outputs into fully observed contiguous bursts.
#[allow(clippy::too_many_arguments)]
fn run_selected_detection<T>(
    deployment: &ReferenceDeployment,
    package: &RgbDetectorPackage,
    request: &PackageDetectRequest,
    limits: &PackageDetectLimits,
    cx: &ReplayCx,
    scalar: &ScalarExecCx,
    selection: Option<&BTreeSet<usize>>,
    finish: impl FnOnce(
        &RgbDetectionContract,
        ContentDigest,
        String,
        Vec<PackageDetectFrame>,
        MaskBinding,
    ) -> Result<T, PackageDetectError>,
) -> Result<T, PackageDetectError> {
    cx.checkpoint("package_detect:begin")
        .map_err(|_| PackageDetectError::Cancelled)?;
    if request.segment_count == 0
        || request.segment_count > MAX_PACKAGE_DETECT_FRAMES
        || request
            .first_segment
            .checked_add(request.segment_count)
            .is_none()
    {
        return Err(PackageDetectError::InvalidRequest);
    }
    let end = request.first_segment + request.segment_count;
    if selection.is_some_and(|segments| {
        segments
            .iter()
            .any(|segment| *segment < request.first_segment || *segment >= end)
    }) {
        return Err(PackageDetectError::InvalidRequest);
    }
    let mut admission = FrameAdmission::new(selection);
    let owned;
    let contract: &RgbDetectionContract = match request.minimum_score_ppm {
        None => package.contract(),
        Some(ppm) => {
            owned = package
                .contract_with_threshold(ppm)
                .map_err(frame_error(request.first_segment))?;
            &owned
        }
    };
    let first = request.first_segment;
    let retained = RetainedFileImport::open(deployment, request.import_identity, limits.read, cx)
        .map_err(frame_error(first))?;
    let end = first + request.segment_count;
    if end > retained.manifest().segment_spans.len() {
        return Err(PackageDetectError::InvalidRequest);
    }
    let media_format = retained.manifest().format.clone();
    let import_root = retained.import_root();
    let (first_capsule, _) =
        source_capsule(deployment, &retained, first).map_err(frame_error(first))?;
    let privacy = current_mask(deployment, &first_capsule.sensor_id).map_err(frame_error(first))?;
    let mut run = FrameRun {
        package,
        contract,
        run: limits.run,
        import_root,
        budget: RgbDetectionBudget::new(
            limits.detection_work_units,
            limits.detection_scratch_bytes,
        ),
        scalar,
        cx,
    };
    let mut frames = Vec::with_capacity(request.segment_count);
    match media_format.as_str() {
        "mjpeg" => {
            let mut budget = DecodeBudget::new(limits.jpeg_work_units);
            for segment in first..end {
                if !admission.admit(segment)? {
                    continue;
                }
                let (capsule, capsule_digest) =
                    source_capsule(deployment, &retained, segment).map_err(frame_error(segment))?;
                let bytes = retained
                    .read_segment(deployment, segment, limits.read, cx)
                    .map_err(frame_error(segment))?;
                let image = decode_rgb(
                    &bytes,
                    capsule.source_digest.bytes(),
                    request.interpretation,
                    limits.jpeg,
                    &mut budget,
                )
                .map_err(frame_error(segment))?;
                if capsule.sensor_id != first_capsule.sensor_id {
                    return Err(PackageDetectError::InvalidRequest);
                }
                frames.push(run.infer(DecodedFrame::jpeg(
                    segment,
                    capsule,
                    capsule_digest,
                    image,
                    privacy.clone(),
                )?)?);
            }
        }
        "annexb" => {
            let h264 = DecoderLimits {
                max_pictures: request.segment_count as u64,
                ..limits.h264
            };
            let mut range = RecordedH264Range::open(
                deployment,
                RecordedH264Request {
                    import_identity: request.import_identity,
                    first_segment: first,
                    segment_count: request.segment_count,
                    interpretation: request.interpretation,
                    read_limits: limits.read,
                    decoder_limits: h264,
                },
                cx,
            )
            .map_err(frame_error(first))?;
            while let Some(frame) = range
                .next_frame(deployment, cx)
                .map_err(frame_error(first))?
            {
                let r = frame.receipt();
                let segment = usize::try_from(r.segment_index())
                    .map_err(|_| PackageDetectError::InvalidRequest)?;
                if !admission.admit(segment)? {
                    continue;
                }
                frames.push(run.infer(DecodedFrame::video(VideoPicture {
                    segment: r.segment_index(),
                    capsule: r.capsule(),
                    capsule_digest: r.capsule_digest(),
                    dimensions: r.dimensions(),
                    codec_receipt: r.digest(),
                    i420: r.i420_sha256(),
                    rgb: frame.to_rgb(),
                    mask: frame.mask().clone(),
                })?)?);
            }
        }
        "hevc" => {
            let h265 = H265DecoderLimits {
                max_pictures: request.segment_count as u64,
                ..limits.h265
            };
            let mut range = RecordedH265Range::open(
                deployment,
                RecordedH265Request {
                    import_identity: request.import_identity,
                    first_segment: first,
                    segment_count: request.segment_count,
                    interpretation: request.interpretation,
                    read_limits: limits.read,
                    decoder_limits: h265,
                },
                cx,
            )
            .map_err(frame_error(first))?;
            while let Some(frame) = range
                .next_frame(deployment, cx)
                .map_err(frame_error(first))?
            {
                let r = frame.receipt();
                let segment = usize::try_from(r.segment_index())
                    .map_err(|_| PackageDetectError::InvalidRequest)?;
                if !admission.admit(segment)? {
                    continue;
                }
                frames.push(run.infer(DecodedFrame::video(VideoPicture {
                    segment: r.segment_index(),
                    capsule: r.capsule(),
                    capsule_digest: r.capsule_digest(),
                    dimensions: r.dimensions(),
                    codec_receipt: r.digest(),
                    i420: r.i420_sha256(),
                    rgb: frame.to_rgb(),
                    mask: frame.mask().clone(),
                })?)?);
            }
        }
        _ => return Err(PackageDetectError::InvalidRequest),
    }
    admission.finish()?;
    let result = finish(contract, import_root, media_format, frames, privacy)?;
    cx.checkpoint("package_detect:complete")
        .map_err(|_| PackageDetectError::Cancelled)?;
    Ok(result)
}

// Shared canonical rendering: ordinary detection and every sentinel burst use identical bytes.
fn finish_report(
    package: &RgbDetectorPackage,
    request: &PackageDetectRequest,
    contract: &RgbDetectionContract,
    import_root: ContentDigest,
    media_format: String,
    frames: Vec<PackageDetectFrame>,
    privacy: MaskBinding,
) -> Result<PackageDetectReport, PackageDetectError> {
    let json = render(package, request, contract, &media_format, &frames, &privacy)
        .map_err(|_| PackageDetectError::InvalidRequest)?;
    Ok(PackageDetectReport {
        import_identity: request.import_identity,
        import_root,
        media_format,
        first_segment: request.first_segment,
        segment_count: request.segment_count,
        minimum_score_ppm: contract.spec().minimum_score_ppm,
        contract: contract.digest(),
        digest: ContentDigest::sha256(json.as_bytes()),
        json,
        frames,
        privacy,
    })
}

// Enforce exact selected identities before RGB conversion/inference, including when a video
// decoder emits display order rather than segment order. Duplicates cannot spend extra budget;
// missing selected pictures (including suppressed CRA leading pictures) refuse the whole run.
struct FrameAdmission<'a> {
    selection: Option<&'a BTreeSet<usize>>,
    seen: BTreeSet<usize>,
}
impl<'a> FrameAdmission<'a> {
    fn new(selection: Option<&'a BTreeSet<usize>>) -> Self {
        Self {
            selection,
            seen: BTreeSet::new(),
        }
    }
    fn admit(&mut self, segment: usize) -> Result<bool, PackageDetectError> {
        let Some(selection) = self.selection else {
            return Ok(true);
        };
        if !selection.contains(&segment) {
            return Ok(false);
        }
        if !self.seen.insert(segment) {
            return Err(PackageDetectError::Frame {
                segment,
                source: "selected picture was emitted more than once".into(),
            });
        }
        Ok(true)
    }
    fn finish(&self) -> Result<(), PackageDetectError> {
        if let Some(selection) = self.selection
            && let Some(segment) = selection.difference(&self.seen).next()
        {
            return Err(PackageDetectError::Frame {
                segment: *segment,
                source:
                    "selected sentinel picture was not decoded; no complete burst report exists"
                        .into(),
            });
        }
        Ok(())
    }
}

fn json_string(value: &str) -> String {
    let mut out = String::from("\"");
    for c in value.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            c if u32::from(c) < 0x20 => {
                let _ = write!(out, "\\u{:04x}", u32::from(c));
            }
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

fn render(
    package: &RgbDetectorPackage,
    request: &PackageDetectRequest,
    contract: &RgbDetectionContract,
    media_format: &str,
    frames: &[PackageDetectFrame],
    privacy: &MaskBinding,
) -> Result<String, fmt::Error> {
    let spec = contract.spec();
    let mut s = String::new();
    write!(
        s,
        "{{\"schema\":\"{PACKAGE_DETECTION_REPORT_SCHEMA}\",\"package_digest\":\"{}\",\"manifest_digest\":\"{}\",\"model_id\":{},\"generation\":{},\"model_digest\":\"{}\",\"graph_digest\":\"{}\",\"contract_digest\":\"{}\",\"source_import\":\"{}\",\"media_format\":{},\"first_segment\":{},\"segment_count\":{},\"privacy_mask\":{},\"minimum_score_ppm\":{},\"nms_iou_ppm\":{},\"box_subpixels\":{},\"labels\":[",
        package.archive_digest(),
        package.manifest_digest(),
        json_string(package.manifest().model_id().as_str()),
        json_string(package.manifest().generation().as_str()),
        package.model().digest(),
        package.graph_digest(),
        contract.digest(),
        request.import_identity,
        json_string(media_format),
        request.first_segment,
        request.segment_count,
        privacy.to_json(),
        spec.minimum_score_ppm,
        spec.nms_iou_ppm,
        super::detections::BOX_SUBPIXELS
    )?;
    for (i, label) in spec.labels.iter().enumerate() {
        if i != 0 {
            s.push(',');
        }
        s.push_str(&json_string(label));
    }
    s.push_str("],\"frames\":[");
    for (i, f) in frames.iter().enumerate() {
        if i != 0 {
            s.push(',');
        }
        let c = &f.capsule;
        let g = f.detections.geometry();
        let suppressed = f
            .detections
            .candidates()
            .iter()
            .filter(|c| c.suppressed_by.is_some())
            .count();
        write!(
            s,
            "{{\"segment\":{},\"capsule_id\":{},\"capsule_digest\":\"{}\",\"sensor_id\":{},\"sequence\":{},\"capture\":{{\"earliest_ns\":\"{}\",\"latest_ns\":\"{}\",\"clock_basis\":{},\"gap_before\":{}}},\"color\":\"{}\",\"dimensions\":[{},{}],\"letterbox\":{{\"image\":[{},{}],\"left\":{},\"top\":{}}},\"inference_identity\":\"{}\",\"input_digest\":\"{}\",\"output_digest\":\"{}\",\"executed_macs\":{},\"detection_report_digest\":\"{}\",\"rows\":{},\"candidates\":{},\"suppressed\":{},\"detections\":[",
            f.segment,
            json_string(c.capsule_id.as_str()),
            f.capsule_digest,
            json_string(c.sensor_id.as_str()),
            c.sequence,
            c.capture.earliest.0,
            c.capture.latest.0,
            json_string(c.clock_basis.as_str()),
            c.gap_before,
            f.color,
            f.dimensions[0],
            f.dimensions[1],
            g.image_width,
            g.image_height,
            g.left,
            g.top,
            f.inference.identity(),
            f.inference.input_digest(),
            f.inference.output_digest(),
            f.inference.executed_macs(),
            f.detections.digest(),
            f.detections.rows().len(),
            f.detections.candidates().len(),
            suppressed
        )?;
        for (j, d) in f.detections.detections().iter().enumerate() {
            if j != 0 {
                s.push(',');
            }
            let label = spec.labels.get(d.class_index()).map_or("", String::as_str);
            write!(
                s,
                "{{\"row\":{},\"class_index\":{},\"label\":{},\"score\":{},\"bounds_subpixel\":[{},{},{},{}],\"clipped\":{}}}",
                d.row(),
                d.class_index(),
                json_string(label),
                d.score(),
                d.bounds()[0],
                d.bounds()[1],
                d.bounds()[2],
                d.bounds()[3],
                d.clipped()
            )?;
        }
        s.push_str("]}");
    }
    s.push_str("],\"complete\":true,\"model_outputs\":\"uncalibrated\",\"quality_claim\":\"none\",\"absence_certifiable\":false,\"effects_authorized\":false}\n");
    Ok(s)
}
