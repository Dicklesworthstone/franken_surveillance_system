#![forbid(unsafe_code)]
//! Retained RTP -> checked native color frames -> verified neural package -> proposals.
//!
//! Owns the receipted decoder, never accepts caller-assembled pixels/receipts, and uses the
//! existing RGB transform, inference and detector-head projection. The default detector considers
//! every decoded frame independently. The explicit `cascade` preserves source receipts and reasons
//! when skipping inference; recovery never refills either owner's allowances.
//! Results are uncalibrated cognition, not tracking, physical absence, or effect authority.

/// Explicit opt-in activity/sentinel admission over this same native detector owner.
pub mod cascade;

use super::decode::RtpDecodeEffect;
use super::recovery::RecoveredRtpImport;
use super::recovery::checked_decode::RtpCustodyDecodeLimits;
use super::recovery::checked_decode::receipt::{
    ReceiptedRetainedRtpH264Decoder, ReceiptedRtpDecodeStep, RetainedRtpFrameReceipt,
    RtpFrameReceiptError, RtpFrameReceiptLimits,
};
use super::recovery::decode::{
    RetainedRtpDecodeRequest, RetainedRtpDecodeStats, RetainedRtpEvent, RetainedRtpH264Frame,
};
use crate::ingest::package_detect::PackageDetectLimits;
use crate::ingest::privacy_mask::PrivacyMaskError;
use crate::ingest::recorded_decode::RecordedDecodeError;
use crate::ingest::recorded_decode::video_rgb::{
    i420_to_rgb, video_rgb_receipt, video_rgb_transform_identity,
};
use crate::ingest::rgb_detections::{
    RgbDetectionBudget, RgbDetectionContract, RgbDetectionError, RgbDetectionReport,
    project_rgb_detections,
};
use crate::ingest::rgb_inference::{
    RgbInference, RgbInferenceError, RgbRunLimits, RgbSourceBinding,
};
use crate::ingest::rgb_package::{RgbDetectorPackage, RgbPackageError};
use crate::{ReferenceDeployment, ReplayCx, ScalarExecCx};
use fss_core::{
    CanonicalEncoder, CaptureInterval, ContentDigest, LedgerAnchor, SensorId, StreamId,
};

/// Versioned interpretation of a verified package over current-custody native RTP frames.
pub const RTP_DETECTION_RECIPE_DOMAIN: &str = "fss.rtp_package_detection_recipe.v1";
/// Versioned identity of one complete source-linked numerical and detector-head result.
pub const RTP_DETECTION_FRAME_DOMAIN: &str = "fss.rtp_package_detection_frame.v1";

/// Cumulative analysis allowances, separate from decoder, receipt and custody resources.
#[derive(Clone, Copy, Debug)]
pub struct RtpDetectionLimits {
    /// Per-frame preprocessing/executor/output limits. JPEG decode settings are unused.
    pub run: RgbRunLimits,
    /// Maximum admitted neural attempts, 1..=1024; no implicit sampling or prefix success.
    pub max_frames: usize,
    /// Cumulative original-image pixels admitted for color conversion and permission setup.
    pub max_color_pixels: u64,
    /// Cumulative preprocessing work. Failed inference retains its whole per-frame reservation.
    pub max_preprocess_work: u64,
    /// Cumulative neural work. Failed inference retains its whole per-frame reservation.
    pub max_execution_macs: u64,
    /// Cumulative tensor allocation allowance, not peak resident memory.
    pub max_tensor_bytes: u64,
    /// Shared detector-head work, including privacy checks, sorting, NMS and result hashing.
    pub detection_work: u64,
    /// Per-frame logical postprocessing scratch ceiling, at most 256 MiB.
    pub detection_scratch_bytes: usize,
}
impl Default for RtpDetectionLimits {
    fn default() -> Self {
        let base = PackageDetectLimits::default();
        Self {
            run: base.run,
            max_frames: 1024,
            max_color_pixels: 256 * 1024 * 1024,
            max_preprocess_work: 64_000_000_000,
            max_execution_macs: 64_000_000_000,
            max_tensor_bytes: 4 * 1024 * 1024 * 1024,
            detection_work: base.detection_work_units,
            detection_scratch_bytes: base.detection_scratch_bytes,
        }
    }
}

/// Independent parameter selection, current-custody admission and analysis limits.
#[derive(Clone, Copy, Debug)]
pub struct RtpDetectionRequest {
    /// Exact in-source SPS/PPS and native receiver/decoder policy.
    pub decode: RetainedRtpDecodeRequest,
    /// Current-custody read limits; there is no snapshot fallback.
    pub custody: RtpCustodyDecodeLimits,
    /// Native frame-receipt limits.
    pub receipts: RtpFrameReceiptLimits,
    /// Explicit override, or the verified package's own score threshold.
    pub minimum_score_ppm: Option<u32>,
    /// Independent cumulative analysis admission.
    pub analysis: RtpDetectionLimits,
}
impl RtpDetectionRequest {
    /// Defaults with explicitly selected native parameters; no package is loaded implicitly.
    pub fn new(decode: RetainedRtpDecodeRequest) -> Self {
        Self {
            decode,
            custody: RtpCustodyDecodeLimits::default(),
            receipts: RtpFrameReceiptLimits::default(),
            minimum_score_ppm: None,
            analysis: RtpDetectionLimits::default(),
        }
    }
}

/// Terminal, payload-free failure; no variant contains partial inference or media.
#[derive(Debug)]
pub enum RtpDetectionError {
    /// Invalid analysis admission or unsupported conservative capture interval.
    InvalidRequest,
    /// A named lifetime allowance could not admit the next complete attempt.
    Limit(&'static str),
    /// Source, native decode, privacy or receipt admission failed.
    Source(RtpFrameReceiptError),
    /// The package's head contract could not be selected.
    Package(RgbPackageError),
    /// The existing color transform refused the native planes.
    Color(RecordedDecodeError),
    /// The existing privacy owner refused the source grid.
    Privacy(PrivacyMaskError),
    /// Existing numerical preprocessing/execution failed; not an empty detection result.
    Inference(RgbInferenceError),
    /// Complete head projection failed; not an empty detection result.
    Detection(RgbDetectionError),
    /// The deployment changed since this attempt was admitted.
    StaleBasis,
    /// Either caller-owned cancellation context requested cancellation.
    Cancelled,
    /// Canonical encoding or stage resource accounting was inconsistent.
    Encoding,
}
impl std::fmt::Display for RtpDetectionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Limit(name) => write!(f, "RTP detection allowance exhausted: {name}"),
            _ => f.write_str("RTP package detection refused; no complete result delivered"),
        }
    }
}
impl std::error::Error for RtpDetectionError {}
type Result<T> = std::result::Result<T, RtpDetectionError>;

/// Stage accounting: native delivery and completed inference are deliberately distinct.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct RtpDetectionStats {
    /// Original decoder accounting, including every refusal and skipped group.
    pub native: RetainedRtpDecodeStats,
    /// Admitted neural attempts, including failed attempts.
    pub attempts: usize,
    /// Complete inferred frames actually delivered.
    pub frames: usize,
    /// Delivered uncalibrated class proposals; zero never certifies absence.
    pub proposals: usize,
    /// Analysis-stage failures; source refusal history remains in `native`.
    pub failures: usize,
    /// Admitted color-conversion pixels.
    pub color_pixels: u64,
    /// Charged preprocessing work, with full reservation retained on inference failure.
    pub preprocess_work: u64,
    /// Charged neural work, with full reservation retained on inference failure.
    pub execution_macs: u64,
    /// Charged cumulative tensor bytes, with full reservation retained on inference failure.
    pub tensor_bytes: u64,
    /// Postprocessing work charged by the existing shared budget.
    pub detection_work: u64,
    /// Lifetime source-custody reads.
    pub custody_read_bytes: u64,
    /// Lifetime native frame-receipt bytes.
    pub receipt_bytes: u64,
    /// The attempt ended, whether successfully or with a refusal.
    pub ended: bool,
}
impl RtpDetectionStats {
    /// All native frames inferred and drained, with no source gap or analysis failure.
    pub fn complete(&self) -> bool {
        self.ended
            && self.failures == 0
            && self.native.complete()
            && self.frames == self.native.frames
    }
}

/// Metadata of a complete neural result, without inventing a source capsule or trusted clock.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RtpDetectionSource {
    /// Original completed retained root.
    pub root: ContentDigest,
    /// Original retained sensor.
    pub sensor: SensorId,
    /// Original retained stream.
    pub stream: StreamId,
    /// Original conservative capture interval; RTP time does not narrow it.
    pub capture: CaptureInterval,
    /// Original image dimensions.
    pub dimensions: [u32; 2],
    /// Zero-based native display position, independent of coding-order group.
    pub output_index: usize,
    /// Native source picture group.
    pub group: usize,
    /// Decoder recovery epoch; no tracking crosses it implicitly.
    pub decoder_epoch: usize,
    /// Untrusted sender timestamp, not converted to wall time.
    pub rtp_timestamp: u32,
    /// Exact applied privacy binding.
    pub privacy: ContentDigest,
    /// Applied retained policy, or the explicit no-policy marker.
    pub policy: Option<ContentDigest>,
}

/// Privately constructed result coupling the native receipt, full inference and head projection.
#[derive(Debug)]
pub struct RtpDetectedFrame {
    source: RtpDetectionSource,
    receipt: RetainedRtpFrameReceipt,
    inference: RgbInference,
    detections: RgbDetectionReport,
    recipe: ContentDigest,
    digest: ContentDigest,
}
impl RtpDetectedFrame {
    /// Original source and current-at-decode privacy metadata.
    pub fn source(&self) -> &RtpDetectionSource {
        &self.source
    }
    /// Exact native source-to-pixels receipt, not caller-attested pixels.
    pub fn receipt(&self) -> &RetainedRtpFrameReceipt {
        &self.receipt
    }
    /// Complete finite model outputs and resize/color/source identities.
    pub fn inference(&self) -> &RgbInference {
        &self.inference
    }
    /// Complete source-space projection, including rejected rows and suppression links.
    pub fn detections(&self) -> &RgbDetectionReport {
        &self.detections
    }
    /// Package, head, color transform and per-frame execution policy identity.
    pub fn recipe(&self) -> ContentDigest {
        self.recipe
    }
    /// Canonical identity of the complete coupled result.
    pub fn digest(&self) -> ContentDigest {
        self.digest
    }
}

/// Source progress, one complete neural result, or terminal stage accounting.
#[derive(Debug)]
pub enum RtpDetectionStep {
    /// Original receiver facts and decode consequences, including gaps and recovery.
    Progress {
        /// Existing payload-free receiver event.
        event: RetainedRtpEvent,
        /// Existing decoder consequence.
        effect: RtpDecodeEffect,
    },
    /// Complete receipt-linked uncalibrated proposals; never raw pixels.
    Frame(RtpDetectedFrame),
    /// Complete/partial/failed accounting is explicit.
    Ended(RtpDetectionStats),
}

/// Request-owned synchronous composition. No threads, effects, activation, or implicit sampling.
pub struct RtpPackageDetector<'a> {
    decoder: Option<ReceiptedRetainedRtpH264Decoder<'a>>,
    package: &'a RgbDetectorPackage,
    contract: RgbDetectionContract,
    recipe: ContentDigest,
    basis: LedgerAnchor,
    limits: RtpDetectionLimits,
    budget: RgbDetectionBudget,
    stats: RtpDetectionStats,
}
impl<'a> RtpPackageDetector<'a> {
    /// Open an independently authorized completed root and already verified package.
    pub fn new(
        retained: &'a RecoveredRtpImport,
        package: &'a RgbDetectorPackage,
        request: RtpDetectionRequest,
        deployment: &ReferenceDeployment,
        cx: &ReplayCx,
        scalar: &ScalarExecCx,
    ) -> Result<Self> {
        checkpoint(cx, scalar, "rtp_detect:open")?;
        let limits = request.analysis;
        if !(1..=1024).contains(&limits.max_frames)
            || limits.run.preprocess.max_bytes > 256 * 1024 * 1024
            || limits.run.execution.max_bytes > 256 * 1024 * 1024
            || !(1..=16 * 1024 * 1024).contains(&limits.run.maximum_output_bytes)
            || limits.detection_scratch_bytes > 256 * 1024 * 1024
        {
            return Err(RtpDetectionError::InvalidRequest);
        }
        let threshold = request
            .minimum_score_ppm
            .unwrap_or(package.spec().head.minimum_score_ppm);
        let contract = package
            .contract_with_threshold(threshold)
            .map_err(RtpDetectionError::Package)?;
        let recipe = recipe(package, &contract, limits.run)?;
        let decoder = retained
            .decode_h264_receipted(
                request.decode,
                request.custody,
                request.receipts,
                deployment,
                cx,
            )
            .map_err(RtpDetectionError::Source)?;
        let stats = RtpDetectionStats {
            custody_read_bytes: decoder.read_bytes(),
            ..Default::default()
        };
        Ok(Self {
            decoder: Some(decoder),
            package,
            contract,
            recipe,
            basis: deployment.current_anchor().clone(),
            limits,
            budget: RgbDetectionBudget::new(limits.detection_work, limits.detection_scratch_bytes),
            stats,
        })
    }
    /// Separate source, inference, head and resource accounting.
    pub fn stats(&self) -> RtpDetectionStats {
        self.stats
    }
    /// Exact package/head/color/per-frame policy identity.
    pub fn recipe(&self) -> ContentDigest {
        self.recipe
    }
    /// Any error is terminal, drops queued pixels, and cannot be retried with fresh allowances.
    pub fn step(
        &mut self,
        deployment: &ReferenceDeployment,
        cx: &ReplayCx,
        scalar: &ScalarExecCx,
    ) -> Result<RtpDetectionStep> {
        if self.decoder.is_none() {
            return Ok(RtpDetectionStep::Ended(self.stats));
        }
        let result = self.advance(deployment, cx, scalar);
        self.finish_step(result, cx, scalar)
    }
    // Both exhaustive and explicitly sampled inference use this one failure/cancellation owner.
    fn finish_step<T>(
        &mut self,
        mut result: Result<T>,
        cx: &ReplayCx,
        scalar: &ScalarExecCx,
    ) -> Result<T> {
        self.stats.detection_work = self.budget.used();
        if result.is_err() {
            if cx.is_cancelled() || scalar.is_cancelled() {
                cx.drain_and_finalize();
                scalar.request_cancellation();
                scalar.drain_and_finalize();
                result = Err(RtpDetectionError::Cancelled);
            }
            self.decoder = None;
            self.stats.failures += 1;
            self.stats.ended = true;
        }
        result
    }
    // The same current-custody decoder supplies every sampling position, including skips.
    fn next_native(
        &mut self,
        deployment: &ReferenceDeployment,
        cx: &ReplayCx,
        scalar: &ScalarExecCx,
    ) -> Result<ReceiptedRtpDecodeStep> {
        checkpoint(cx, scalar, "rtp_detect:step")?;
        if deployment.current_anchor() != &self.basis {
            return Err(RtpDetectionError::StaleBasis);
        }
        let decoder = self.decoder.as_mut().ok_or(RtpDetectionError::Encoding)?;
        let result = decoder.step(deployment, cx);
        self.stats.native = decoder.stats();
        self.stats.custody_read_bytes = decoder.read_bytes();
        self.stats.receipt_bytes = decoder.receipt_bytes();
        result.map_err(RtpDetectionError::Source)
    }
    fn advance(
        &mut self,
        deployment: &ReferenceDeployment,
        cx: &ReplayCx,
        scalar: &ScalarExecCx,
    ) -> Result<RtpDetectionStep> {
        match self.next_native(deployment, cx, scalar)? {
            ReceiptedRtpDecodeStep::Progress { event, effect } => {
                Ok(RtpDetectionStep::Progress { event, effect })
            }
            ReceiptedRtpDecodeStep::Ended(_) => {
                self.stats.ended = true;
                self.decoder = None;
                Ok(RtpDetectionStep::Ended(self.stats))
            }
            ReceiptedRtpDecodeStep::Frame { frame, receipt } => {
                let result = self.infer(frame, receipt, cx, scalar)?;
                checkpoint(cx, scalar, "rtp_detect:deliver")?;
                if deployment.current_anchor() != &self.basis {
                    return Err(RtpDetectionError::StaleBasis);
                }
                self.stats.frames += 1;
                self.stats.proposals += result.detections.detections().len();
                Ok(RtpDetectionStep::Frame(result))
            }
        }
    }
    fn reserve(&mut self, pixels: u64) -> Result<()> {
        let add = |used: u64, count: u64, limit: u64, label| {
            used.checked_add(count)
                .filter(|n| *n <= limit)
                .ok_or(RtpDetectionError::Limit(label))
        };
        if self.stats.attempts >= self.limits.max_frames {
            return Err(RtpDetectionError::Limit("inference_frames"));
        }
        let color = add(
            self.stats.color_pixels,
            pixels,
            self.limits.max_color_pixels,
            "color_pixels",
        )?;
        let prep = add(
            self.stats.preprocess_work,
            self.limits.run.preprocess.max_macs,
            self.limits.max_preprocess_work,
            "preprocess_work",
        )?;
        let macs = add(
            self.stats.execution_macs,
            self.limits.run.execution.max_macs,
            self.limits.max_execution_macs,
            "execution_macs",
        )?;
        let bytes = add(
            self.stats.tensor_bytes,
            self.limits.run.execution.max_bytes as u64,
            self.limits.max_tensor_bytes,
            "tensor_bytes",
        )?;
        self.stats.attempts += 1;
        self.stats.color_pixels = color;
        self.stats.preprocess_work = prep;
        self.stats.execution_macs = macs;
        self.stats.tensor_bytes = bytes;
        Ok(())
    }
    fn infer(
        &mut self,
        frame: RetainedRtpH264Frame,
        receipt: RetainedRtpFrameReceipt,
        cx: &ReplayCx,
        scalar: &ScalarExecCx,
    ) -> Result<RtpDetectedFrame> {
        checkpoint(cx, scalar, "rtp_detect:admit")?;
        let dimensions = frame.dimensions();
        let pixels = u64::from(dimensions[0]) * u64::from(dimensions[1]);
        if pixels == 0 || pixels > 4_194_304 {
            return Err(RtpDetectionError::InvalidRequest);
        }
        self.reserve(pixels)?;
        let allowed = frame
            .mask()
            .allowed(dimensions)
            .map_err(RtpDetectionError::Privacy)?;
        let mut rgb = i420_to_rgb(frame.pixels(), frame.cb(), frame.cr(), dimensions)
            .map_err(RtpDetectionError::Color)?;
        frame
            .mask()
            .apply_rgb(&mut rgb, dimensions)
            .map_err(RtpDetectionError::Privacy)?;
        checkpoint(cx, scalar, "rtp_detect:inference")?;
        let native = video_rgb_receipt(
            frame.source().recording.bytes(),
            receipt.digest(),
            receipt.plane_digests()[3],
            dimensions,
            &rgb,
        );
        let capture = frame.capture();
        let as_u64 = |time| u64::try_from(time).map_err(|_| RtpDetectionError::InvalidRequest);
        let source = RgbSourceBinding {
            encoded_sha256: frame.source().recording.bytes(),
            exposure: receipt.digest().bytes(),
            camera: nonzero(ContentDigest::sha256(frame.sensor().as_str().as_bytes())),
            // Explicit unknown-clock and uncalibrated sentinels, never inferred from RTP time.
            clock: nonzero(ContentDigest::sha256(
                b"fss.rtp_detection.capture_clock_unknown.v1",
            )),
            capture: [as_u64(capture.earliest.0)?, as_u64(capture.latest.0)?],
            image_domain: frame.root().bytes(),
            calibration: ContentDigest::sha256(b"fss.package_detection.uncalibrated").bytes(),
            permission_mask: ContentDigest::sha256(&allowed).bytes(),
        };
        let inference = self
            .package
            .model()
            .run_rgb_pixels(&rgb, native, source, &allowed, self.limits.run, scalar)
            .map_err(RtpDetectionError::Inference)?;
        // Success refunds only demonstrably unused capacity. Any earlier failure keeps the
        // full reservation; no failed attempt or decoder restart can mint fresh work.
        self.stats.preprocess_work -= self
            .limits
            .run
            .preprocess
            .max_macs
            .checked_sub(inference.preprocess_work())
            .ok_or(RtpDetectionError::Encoding)?;
        self.stats.execution_macs -= self
            .limits
            .run
            .execution
            .max_macs
            .checked_sub(inference.executed_macs())
            .ok_or(RtpDetectionError::Encoding)?;
        self.stats.tensor_bytes -= self
            .limits
            .run
            .execution
            .max_bytes
            .checked_sub(inference.allocated_tensor_bytes())
            .ok_or(RtpDetectionError::Encoding)? as u64;
        drop(rgb);
        checkpoint(cx, scalar, "rtp_detect:projection")?;
        let detections = project_rgb_detections(
            &inference,
            &self.contract,
            &allowed,
            &mut self.budget,
            scalar,
        )
        .map_err(RtpDetectionError::Detection)?;
        let source = RtpDetectionSource {
            root: frame.root(),
            sensor: frame.sensor().clone(),
            stream: frame.stream().clone(),
            capture,
            dimensions,
            output_index: self
                .stats
                .native
                .frames
                .checked_sub(1)
                .ok_or(RtpDetectionError::Encoding)?,
            group: frame.source().group,
            decoder_epoch: frame.source().decoder_epoch,
            rtp_timestamp: frame.source().timestamp,
            privacy: frame.mask().digest(),
            policy: frame.mask().policy_digest(),
        };
        let mut e = CanonicalEncoder::new();
        e.text(RTP_DETECTION_FRAME_DOMAIN);
        for d in [
            self.recipe,
            receipt.digest(),
            inference.identity(),
            detections.digest(),
        ] {
            e.digest(d);
        }
        e.u64(source.output_index as u64);
        let bytes = e
            .finish_checked()
            .map_err(|_| RtpDetectionError::Encoding)?;
        Ok(RtpDetectedFrame {
            source,
            receipt,
            inference,
            detections,
            recipe: self.recipe,
            digest: ContentDigest::sha256(&bytes),
        })
    }
}
fn nonzero(digest: ContentDigest) -> u64 {
    let b = digest.bytes();
    u64::from_be_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]]).max(1)
}
fn checkpoint(cx: &ReplayCx, scalar: &ScalarExecCx, stage: &'static str) -> Result<()> {
    if cx.checkpoint(stage).is_err() || scalar.checkpoint(stage).is_err() {
        cx.drain_and_finalize();
        scalar.request_cancellation();
        scalar.drain_and_finalize();
        return Err(RtpDetectionError::Cancelled);
    }
    Ok(())
}
fn recipe(
    package: &RgbDetectorPackage,
    contract: &RgbDetectionContract,
    run: RgbRunLimits,
) -> Result<ContentDigest> {
    let mut e = CanonicalEncoder::new();
    e.text(RTP_DETECTION_RECIPE_DOMAIN);
    for d in [
        package.archive_digest(),
        package.manifest_digest(),
        package.model().digest(),
        contract.digest(),
        video_rgb_transform_identity(),
    ] {
        e.digest(d);
    }
    for n in [
        run.preprocess.max_macs,
        run.preprocess.max_bytes as u64,
        run.execution.max_macs,
        run.execution.max_bytes as u64,
        run.maximum_output_bytes as u64,
    ] {
        e.u64(n);
    }
    let bytes = e
        .finish_checked()
        .map_err(|_| RtpDetectionError::Encoding)?;
    Ok(ContentDigest::sha256(&bytes))
}
