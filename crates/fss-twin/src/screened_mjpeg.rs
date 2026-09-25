#![forbid(unsafe_code)]
//! Real compressed input -> native rectification -> foreground -> health/admission.
//! Health work has its own allowance, so an unavailable/over-budget foreground stage
//! cannot be laundered into a quiet image or starve the sensor-health floor.

use crate::foreground::pipeline::FrameCapture;
use crate::foreground::{
    ForegroundError, ForegroundFrame, ForegroundPolicy, ForegroundReport, ForegroundSource,
};
use crate::mjpeg::stream::{FramedQuery, StreamFrameReceipt};
use crate::mjpeg::{
    JpegBackground, JpegDecodeRequest, JpegFrameBinding, JpegPipelineError, JpegReceipt,
    JpegRectified, decode_rectified_redacted,
};
use crate::rectification::{RectificationPlan, RectifiedFrame};
use crate::redaction::LumaRedaction;
use crate::screening::{
    ScreeningError, ScreeningHealth, ScreeningMonitor, ScreeningReport, ScreeningStamp,
};
use fss_codec_mjpeg::{DecodeBudget, DecodeLimits};
use fss_core::{CanonicalEncoder, ContentDigest};
use fss_geometry::{GeometryError, WorkBudget};

/// Owner-bound complete JPEG input. There is no inferred capture time or default permission.
#[derive(Clone, Copy)]
pub struct JpegScreeningQuery<'a> {
    /// Exactly one complete compressed frame.
    pub bytes: &'a [u8],
    /// Complete coded-grid 0/1 permission mask.
    pub mask: &'a [u8],
    /// Independent source, mask, calibration and decoder-interpretation bindings.
    pub binding: JpegFrameBinding,
    /// Independently admitted physical camera and capture-clock interval.
    pub capture: FrameCapture,
    /// Existing frozen-background thresholds; no online background mutation occurs.
    pub foreground_policy: ForegroundPolicy,
    /// Native decoder ceilings.
    pub decode_limits: DecodeLimits,
    /// Original sequence and receive-clock evidence.
    pub stamp: ScreeningStamp,
    /// Owner redaction applied to the decoded plane before rectification, foreground, health or
    /// any digest (the reference composition passes the sensor's privacy mask); `None` leaves
    /// the decoder output and every fingerprint unchanged.
    pub redaction: Option<&'a dyn LumaRedaction>,
}

/// The candidate stage can fail without erasing a valid decoded image or its health evidence.
#[derive(Debug)]
pub enum ForegroundStage<'a> {
    /// Complete actual-pixel comparison, including omitted small components.
    Complete(&'a ForegroundReport),
    /// Typed refusal, not an empty successful detection list.
    Refused(ForegroundError),
    /// No admitted frozen model was supplied.
    NotConfigured,
}
/// Input/rectification, cancellation or health-screen failure. No state is advanced on error.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum JpegScreeningError {
    /// Existing compressed-source or rectification boundary refused the input.
    Image(JpegPipelineError),
    /// Screening basis, timing, resource or acknowledgement boundary refused the input.
    Screening(ScreeningError),
    /// Foreground cancellation aborts the complete owner operation, not just its candidate list.
    Cancelled,
}
impl From<JpegPipelineError> for JpegScreeningError {
    fn from(error: JpegPipelineError) -> Self {
        Self::Image(error)
    }
}
impl From<ScreeningError> for JpegScreeningError {
    fn from(error: ScreeningError) -> Self {
        Self::Screening(error)
    }
}
impl std::fmt::Display for JpegScreeningError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Image(_) => "JPEG screening image refused",
            Self::Screening(_) => "JPEG screening state refused",
            Self::Cancelled => "JPEG screening cancelled",
        })
    }
}
impl std::error::Error for JpegScreeningError {}

/// One immutable compound result, retaining real compressed and corrected-image provenance.
/// Its fingerprint is a local reference derivation, not a new canonical durable format.
pub struct ScreenedJpeg {
    image: JpegRectified,
    foreground: Option<ForegroundReport>,
    refusal: Option<ForegroundError>,
    screening: ScreeningReport,
    attempted_background: Option<[u8; 32]>,
    foreground_policy: ForegroundPolicy,
    foreground_allowance: u64,
    foreground_units: u64,
    digest: [u8; 32],
}
impl std::fmt::Debug for ScreenedJpeg {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ScreenedJpeg")
            .field("health", &self.screening.health())
            .field("analysis_due", &self.screening.analysis_due())
            .finish_non_exhaustive()
    }
}
impl ScreenedJpeg {
    /// Complete coupled source/codec/foreground/screening identity.
    pub fn digest(&self) -> [u8; 32] {
        self.digest
    }
    /// Original encoded-source, decode and raw-plane bindings.
    pub fn source_receipt(&self) -> JpegReceipt {
        self.image.receipt()
    }
    /// Masked, corrected source frame. Pixels behind denied samples remain zero and denied.
    pub fn image(&self) -> &JpegRectified {
        &self.image
    }
    /// Typed successful, refused or unconfigured foreground stage.
    pub fn foreground(&self) -> ForegroundStage<'_> {
        match (&self.foreground, self.refusal) {
            (Some(report), _) => ForegroundStage::Complete(report),
            (None, Some(error)) => ForegroundStage::Refused(error),
            (None, None) => ForegroundStage::NotConfigured,
        }
    }
    /// Exact attempted frozen model, including when that stage refused the input.
    pub fn attempted_background(&self) -> Option<[u8; 32]> {
        self.attempted_background
    }
    /// Actual candidate-stage thresholds, retained even when validation refused them.
    pub fn foreground_policy(&self) -> ForegroundPolicy {
        self.foreground_policy
    }
    /// Deterministic candidate work allowance at admission; not elapsed time or energy.
    pub fn foreground_allowance(&self) -> u64 {
        self.foreground_allowance
    }
    /// Candidate work charged, including a refused attempt.
    pub fn foreground_units(&self) -> u64 {
        self.foreground_units
    }
    /// Full always-on health and downstream-sampling decision.
    pub fn screening(&self) -> &ScreeningReport {
        &self.screening
    }
    /// Recommended downstream image, absent for a skip OR insufficient visible input.
    /// Inspect the screen to distinguish those cases. An absent image is never evidence of absence.
    /// Returning this reference does not complete analysis or move the sentinel deadline.
    pub fn analysis_frame(&self) -> Option<&RectifiedFrame> {
        (self.screening.analysis_due() && self.screening.health() != ScreeningHealth::NotObservable)
            .then(|| self.image.frame())
    }
}

/// Screen one actual JPEG with separate bounded decode, rectification, candidate and health work.
///
/// All budgets belong to one owner and should share its cancellation flag. Foreground resource
/// failure returns a typed degraded stage alongside health; cancellation aborts without mutation.
/// This function never acknowledges semantic analysis, updates the background or causes an effect.
#[allow(clippy::too_many_arguments)]
pub fn screen_jpeg(
    monitor: &mut ScreeningMonitor,
    background: Option<&JpegBackground>,
    plan: &RectificationPlan,
    query: JpegScreeningQuery<'_>,
    decode: &mut DecodeBudget<'_>,
    rectification: &mut WorkBudget<'_>,
    foreground_work: &mut WorkBudget<'_>,
    health_work: &mut WorkBudget<'_>,
) -> Result<ScreenedJpeg, JpegScreeningError> {
    health_work.charge(0).map_err(ScreeningError::from)?;
    let image = decode_rectified_redacted(
        plan,
        JpegDecodeRequest {
            bytes: query.bytes,
            mask: query.mask,
            source: query.binding,
            limits: query.decode_limits,
            redaction: query.redaction,
        },
        decode,
        rectification,
    )?;
    let frame = image.frame();
    let source = ForegroundSource {
        image: frame.identity(),
        camera: query.capture.camera,
        clock: query.capture.clock,
        capture: query.capture.capture,
        calibration: query.binding.calibration,
    };
    let attempted_background = background.map(|model| model.background().model().digest());
    let foreground_allowance = foreground_work.remaining();
    let work_before = foreground_work.used();
    let result = background.map(|model| {
        ForegroundFrame::new(source, frame.pixels(), frame.allowed(), foreground_work).and_then(
            |input| {
                model
                    .background()
                    .model()
                    .detect(&input, query.foreground_policy, foreground_work)
            },
        )
    });
    let (foreground, refusal) = match result {
        Some(Ok(report)) => (Some(report), None),
        Some(Err(ForegroundError::Geometry(GeometryError::Cancelled))) => {
            return Err(JpegScreeningError::Cancelled);
        }
        Some(Err(error)) => (None, Some(error)),
        None => (None, None),
    };
    let foreground_units = foreground_work.used() - work_before;
    // Build the fixed provenance prefix before the monitor's atomic commit. No fallible
    // operation follows a successful observe, so an error cannot leave hidden frame credit.
    let receipt = image.receipt();
    let mut e = CanonicalEncoder::new();
    e.text("fss.screened_jpeg.reference.v1");
    for id in [
        receipt.source.encoded_sha256,
        receipt.source.exposure,
        receipt.source.allowed_mask,
        receipt.source.camera_image_domain,
        receipt.source.calibration,
        receipt.decode.decoder,
        receipt.decode.luma_sha256,
        frame.receipt().map_digest,
    ] {
        e.digest(ContentDigest::sha256(&id));
    }
    // Only a redacted decode adds this field, so unredacted fingerprints are unchanged.
    if let Some(identity) = receipt.redaction {
        e.text("redaction");
        e.digest(ContentDigest::sha256(&identity));
    }
    e.bool(attempted_background.is_some());
    if let Some(id) = attempted_background {
        e.digest(ContentDigest::sha256(&id));
    }
    e.u8(query.foreground_policy.minimum_change);
    for n in [
        query.foreground_policy.minimum_area as u64,
        query.foreground_policy.maximum_regions as u64,
        u64::from(query.foreground_policy.widespread_per_mille),
        foreground_allowance,
        foreground_units,
    ] {
        e.u64(n);
    }
    e.u8(match (&foreground, refusal) {
        (Some(_), _) => 1,
        (_, Some(_)) => 2,
        _ => 0,
    });
    if let Some(error) = refusal {
        e.text(&error.to_string());
        if let ForegroundError::Geometry(geometry) = error {
            e.text(&geometry.to_string());
        }
    }
    let screening = monitor.observe(
        source,
        frame.pixels(),
        frame.allowed(),
        foreground.as_ref(),
        query.stamp,
        health_work,
    )?;
    e.digest(ContentDigest::sha256(&screening.digest()));
    let digest = ContentDigest::sha256(&e.finish()).bytes();
    Ok(ScreenedJpeg {
        image,
        foreground,
        refusal,
        screening,
        attempted_background,
        foreground_policy: query.foreground_policy,
        foreground_allowance,
        foreground_units,
        digest,
    })
}

/// Source-offset-preserving version of the same pipeline for a completed MJPEG stream frame.
pub struct FramedScreenedJpeg {
    source: StreamFrameReceipt,
    result: ScreenedJpeg,
    digest: [u8; 32],
}
impl FramedScreenedJpeg {
    /// Original immutable stream record, generation, ordinal and compressed-byte range.
    pub fn source(&self) -> StreamFrameReceipt {
        self.source
    }
    /// Same native JPEG, foreground, health and masked-analysis result.
    pub fn result(&self) -> &ScreenedJpeg {
        &self.result
    }
    /// Local compound fingerprint binding the stream range as well as image processing.
    pub fn digest(&self) -> [u8; 32] {
        self.digest
    }
}
/// Screen an already framed source. Neither ordinal nor receive time becomes capture time.
/// The caller must pin `expected_stream` to its admitted source record across the session.
#[allow(clippy::too_many_arguments)]
pub fn screen_framed_jpeg(
    monitor: &mut ScreeningMonitor,
    background: Option<&JpegBackground>,
    plan: &RectificationPlan,
    query: FramedQuery<'_>,
    stamp: ScreeningStamp,
    decode: &mut DecodeBudget<'_>,
    rectification: &mut WorkBudget<'_>,
    foreground_work: &mut WorkBudget<'_>,
    health_work: &mut WorkBudget<'_>,
) -> Result<FramedScreenedJpeg, JpegScreeningError> {
    health_work.charge(0).map_err(ScreeningError::from)?;
    if query.expected_stream != query.frame.basis()
        || query.binding.encoded_sha256 != query.frame.encoded_sha256()
        || stamp.sequence != query.frame.ordinal()
        || stamp.stream_generation != query.frame.basis().generation
    {
        return Err(JpegScreeningError::Image(JpegPipelineError::BasisMismatch));
    }
    let source = StreamFrameReceipt {
        basis: query.frame.basis(),
        ordinal: query.frame.ordinal(),
        byte_range: query.frame.byte_range(),
        encoded_sha256: query.frame.encoded_sha256(),
    };
    let result = screen_jpeg(
        monitor,
        background,
        plan,
        JpegScreeningQuery {
            bytes: query.frame.bytes(),
            mask: query.mask,
            binding: query.binding,
            capture: query.capture,
            foreground_policy: query.policy,
            decode_limits: query.limits,
            stamp,
            redaction: None,
        },
        decode,
        rectification,
        foreground_work,
        health_work,
    )?;
    let mut e = CanonicalEncoder::new();
    e.text("fss.framed_screened_jpeg.reference.v1");
    e.digest(ContentDigest::sha256(&source.basis.source));
    e.u64(source.basis.generation);
    e.u64(source.ordinal);
    e.u64(source.byte_range[0]);
    e.u64(source.byte_range[1]);
    e.digest(ContentDigest::sha256(&result.digest()));
    let digest = ContentDigest::sha256(&e.finish()).bytes();
    Ok(FramedScreenedJpeg {
        source,
        result,
        digest,
    })
}
