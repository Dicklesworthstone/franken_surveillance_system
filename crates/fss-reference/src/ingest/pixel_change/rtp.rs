#![forbid(unsafe_code)]
//! Motion measurements from current-custody, privacy-projected recorded RTP.
//!
//! The analyzer owns the native receipt decoder: callers cannot pair arbitrary pixels with a
//! different receipt. It shares the file-video comparison kernel, consumes display order, and
//! never compares across a damaged reference chain. Measurements are cognition, not live
//! continuity, presence/absence, a published decode, or effect authority.

use super::{
    PixelChangeConfig, PixelChangeError, PixelChangeReset, PixelChangeStatistics, compare_pixels,
};
use crate::ingest::rtpdump::decode::RtpDecodeEffect;
use crate::ingest::rtpdump::recovery::RecoveredRtpImport;
use crate::ingest::rtpdump::recovery::checked_decode::RtpCustodyDecodeLimits;
use crate::ingest::rtpdump::recovery::checked_decode::receipt::{
    ReceiptedRetainedRtpH264Decoder, ReceiptedRtpDecodeStep, RtpFrameReceiptError,
    RtpFrameReceiptLimits,
};
use crate::ingest::rtpdump::recovery::decode::{
    RetainedRtpDecodeRequest, RetainedRtpDecodeStats, RetainedRtpEvent,
};
use crate::{ReferenceDeployment, ReplayCx};
use fss_core::{CanonicalEncode, CanonicalEncoder, CaptureInterval, ContentDigest};
use std::collections::BTreeSet;

/// Versioned, domain-separated identity of a derived RTP pixel-change observation.
pub const RTP_MOTION_DOMAIN: &str = "fss.retained_rtp_pixel_change.v1";

/// Explicit interpretation and independent resource allowances; no thresholds are learned.
#[derive(Clone, Copy, Debug)]
pub struct RtpMotionRequest {
    /// Exact source-selected AVC parameters and native receiver/decoder limits.
    pub decode: RetainedRtpDecodeRequest,
    /// Current-custody readback and progress limits, separate from initial inspection.
    pub custody: RtpCustodyDecodeLimits,
    /// Canonical frame-receipt limits; IDs name actual native reproduction.
    pub receipts: RtpFrameReceiptLimits,
    /// Same integer threshold semantics as JPEG and file-video pixel change.
    pub thresholds: PixelChangeConfig,
    /// Cumulative pixel comparisons, never replenished by IDR recovery. Zero admits a baseline.
    pub max_comparisons: u64,
}
impl RtpMotionRequest {
    /// Existing decode/custody/receipt defaults with an explicit comparison allowance.
    pub fn new(
        decode: RetainedRtpDecodeRequest,
        thresholds: PixelChangeConfig,
        max_comparisons: u64,
    ) -> Self {
        Self {
            decode,
            custody: RtpCustodyDecodeLimits::default(),
            receipts: RtpFrameReceiptLimits::default(),
            thresholds,
            max_comparisons,
        }
    }
}

/// Receipt-linked cognition. A reset is unmeasured, never encoded as zero change.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RtpPixelChangeObservation {
    /// Complete retained source root, including prediction dependencies.
    pub source_root: ContentDigest,
    /// Exact native source-to-pixels frame receipt (not a decoded publication root).
    pub frame_receipt: ContentDigest,
    /// Exact predecessor actually compared, absent on a reset.
    pub predecessor_receipt: Option<ContentDigest>,
    /// Native receiver/decoder interpretation of both frame receipts.
    pub recipe: ContentDigest,
    /// Zero-based display-order position served by this analyzer.
    pub output_index: u64,
    /// Original coding-order group, which need not increase in display order.
    pub source_group: u64,
    /// Decoder restart counter, not a source generation or continuity certificate.
    pub decoder_epoch: u64,
    /// Original sender timestamp; no capture clock is inferred.
    pub rtp_timestamp: u32,
    /// Original conservative capture interval.
    pub capture: CaptureInterval,
    /// Visible luma dimensions, bounded by the shared comparison kernel.
    pub dimensions: [u32; 2],
    /// Current-at-admission privacy binding applied before comparison.
    pub mask_binding: ContentDigest,
    /// Exact caller-selected thresholds.
    pub configuration_digest: ContentDigest,
    /// All invalidators of this pair; recovery preserves the source-gap reason.
    pub reset_reasons: BTreeSet<PixelChangeReset>,
    /// Complete comparable-pair statistics, or no measurement on a reset.
    pub statistics: Option<PixelChangeStatistics>,
}
impl RtpPixelChangeObservation {
    /// Deterministic derived identity, reproducible after a fresh ingress allocation.
    pub fn digest(&self) -> ContentDigest {
        self.canonical_digest(RTP_MOTION_DOMAIN)
    }
}
impl CanonicalEncode for RtpPixelChangeObservation {
    fn encode_canonical(&self, e: &mut CanonicalEncoder) {
        e.u32(1);
        e.digest(self.source_root);
        e.digest(self.frame_receipt);
        e.bool(self.predecessor_receipt.is_some());
        if let Some(previous) = self.predecessor_receipt {
            e.digest(previous);
        }
        e.digest(self.recipe);
        for n in [self.output_index, self.source_group, self.decoder_epoch] {
            e.u64(n);
        }
        e.u32(self.rtp_timestamp);
        e.i128(self.capture.earliest.0);
        e.i128(self.capture.latest.0);
        for n in self.dimensions {
            e.u32(n);
        }
        e.digest(self.mask_binding);
        e.digest(self.configuration_digest);
        e.u64(self.reset_reasons.len() as u64);
        for reason in &self.reset_reasons {
            e.text(reason.as_str());
        }
        e.bool(self.statistics.is_some());
        if let Some(s) = &self.statistics {
            e.u64(s.compared_pixels);
            e.u64(s.changed_pixels);
            e.u64(s.absolute_difference_sum);
            e.u8(s.maximum_difference);
            e.bool(s.candidate);
            e.bool(s.changed_bounds.is_some());
            if let Some(b) = &s.changed_bounds {
                for n in [b.left, b.top, b.right, b.bottom] {
                    e.u32(n);
                }
            }
        }
    }
}

/// Independent decode, measurement and resource accounting; never evidence of absence.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct RtpMotionStats {
    /// Actual native receipt-decoder accounting, including all refusals/skipped groups.
    pub decode: RetainedRtpDecodeStats,
    /// Measurements or explicit baselines actually delivered by the analyzer.
    pub observations: usize,
    /// Comparable pairs, including pairs below the selected thresholds.
    pub measured_pairs: usize,
    /// Pairs meeting the selected thresholds, not a count of objects or events.
    pub candidate_pairs: usize,
    /// Unmeasured baselines, including initial admission and post-gap recovery.
    pub resets: usize,
    /// Cumulative charged pixel comparisons, including work preceding cancellation.
    pub comparisons: u64,
    /// Current-custody read cost, never renewed after recovery.
    pub custody_read_bytes: u64,
    /// Cumulative admitted native frame-receipt bytes.
    pub receipt_bytes: u64,
    /// Progress calls charged by the current-custody decoder.
    pub steps: usize,
    /// Terminal analyzer errors, distinct from upstream progress refusals.
    pub failures: usize,
    /// The analyzer has drained or stopped permanently.
    pub ended: bool,
}
impl RtpMotionStats {
    /// All native output was analyzed and drained without missing/refused inputs or errors.
    /// One initial baseline is permitted; no camera coverage or absence claim follows.
    pub fn complete(&self) -> bool {
        self.ended
            && self.failures == 0
            && self.decode.complete()
            && self.observations == self.decode.frames
    }
}

/// A source/decoder event, one bounded observation, or terminal accounting. No pixels escape.
#[derive(Debug)]
pub enum RtpMotionStep {
    /// Existing payload-free progress, including native retirement and recovery decisions.
    Progress {
        /// Original receiver event projection.
        event: RetainedRtpEvent,
        /// Original native decoder effect.
        effect: RtpDecodeEffect,
    },
    /// Receipt-linked measured pair or explicit baseline reset.
    Observation(RtpPixelChangeObservation),
    /// Terminal accounting; completion remains separate from exhaustion.
    Ended(RtpMotionStats),
}

/// Typed terminal refusal. Earlier observations remain historical, not a successful scan.
#[derive(Debug)]
pub enum RtpMotionError {
    /// Existing native decoder, custody, privacy, or frame receipt refusal.
    Decode(RtpFrameReceiptError),
    /// Shared pixel-change configuration, image, comparison-budget or cancellation refusal.
    Pixel(PixelChangeError),
    /// Bounded baseline allocation failed.
    Allocation,
}
impl std::fmt::Display for RtpMotionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "retained RTP motion refused: {self:?}")
    }
}
impl std::error::Error for RtpMotionError {}
impl From<RtpFrameReceiptError> for RtpMotionError {
    fn from(e: RtpFrameReceiptError) -> Self {
        Self::Decode(e)
    }
}
impl From<PixelChangeError> for RtpMotionError {
    fn from(e: PixelChangeError) -> Self {
        Self::Pixel(e)
    }
}
type Result<T> = std::result::Result<T, RtpMotionError>;

struct Previous {
    receipt: ContentDigest,
    epoch: usize,
    dimensions: [u32; 2],
    mask: ContentDigest,
    pixels: Vec<u8>,
}

/// One request-owned native decoder and at most one previous luma image. No I/O is detached.
/// Failures drop both decoder and baseline; retry requires fresh inspection and admission.
pub struct RtpMotionAnalyzer<'a> {
    decoder: Option<ReceiptedRetainedRtpH264Decoder<'a>>,
    request: RtpMotionRequest,
    previous: Option<Previous>,
    gap_pending: bool,
    stats: RtpMotionStats,
}
impl<'a> RtpMotionAnalyzer<'a> {
    /// Open only through the canonical current-custody receipt owner. Authorize access first.
    pub fn open(
        retained: &'a RecoveredRtpImport,
        request: RtpMotionRequest,
        deployment: &ReferenceDeployment,
        cx: &ReplayCx,
    ) -> Result<Self> {
        checkpoint(cx)?;
        request.thresholds.validate()?;
        let decoder = retained.decode_h264_receipted(
            request.decode,
            request.custody,
            request.receipts,
            deployment,
            cx,
        )?;
        let stats = RtpMotionStats {
            custody_read_bytes: decoder.read_bytes(),
            ..RtpMotionStats::default()
        };
        Ok(Self {
            decoder: Some(decoder),
            request,
            previous: None,
            gap_pending: false,
            stats,
        })
    }
    /// Actual progress and charged work, including failed analyzer delivery.
    pub fn stats(&self) -> RtpMotionStats {
        self.stats
    }

    /// Execute one bounded step. B-picture display order is not confused with source order.
    pub fn step(
        &mut self,
        deployment: &ReferenceDeployment,
        cx: &ReplayCx,
    ) -> Result<RtpMotionStep> {
        if self.decoder.is_none() {
            return Ok(RtpMotionStep::Ended(self.stats));
        }
        let result = self.advance(deployment, cx);
        if result.is_err() {
            self.decoder = None;
            self.previous = None;
            self.stats.failures += 1;
            self.stats.ended = true;
        }
        result
    }
    fn advance(
        &mut self,
        deployment: &ReferenceDeployment,
        cx: &ReplayCx,
    ) -> Result<RtpMotionStep> {
        checkpoint(cx)?;
        let decoder = self
            .decoder
            .as_mut()
            .ok_or(PixelChangeError::InvalidImage)?;
        let step = decoder.step(deployment, cx);
        self.stats.decode = decoder.stats();
        self.stats.custody_read_bytes = decoder.read_bytes();
        self.stats.receipt_bytes = decoder.receipt_bytes();
        self.stats.steps = decoder.steps();
        match step? {
            ReceiptedRtpDecodeStep::Progress { event, effect } => {
                if matches!(
                    effect,
                    RtpDecodeEffect::Refused { .. }
                        | RtpDecodeEffect::WaitingForIdr { .. }
                        | RtpDecodeEffect::Fenced
                ) {
                    self.previous = None;
                    self.gap_pending = true;
                }
                Ok(RtpMotionStep::Progress { event, effect })
            }
            ReceiptedRtpDecodeStep::Ended(_) => {
                self.decoder = None;
                self.previous = None;
                self.stats.ended = true;
                Ok(RtpMotionStep::Ended(self.stats))
            }
            ReceiptedRtpDecodeStep::Frame { frame, receipt } => {
                let dimensions = frame.dimensions();
                let [w, h] = dimensions;
                let count = u64::from(w) * u64::from(h);
                if w == 0
                    || h == 0
                    || w > 4096
                    || h > 4096
                    || count > 4_194_304
                    || count != frame.pixels().len() as u64
                {
                    return Err(PixelChangeError::InvalidImage.into());
                }
                let mut reset_reasons = BTreeSet::new();
                if let Some(previous) = &self.previous {
                    if previous.epoch != frame.source().decoder_epoch {
                        reset_reasons.insert(PixelChangeReset::SourceGap);
                    }
                    if previous.dimensions != dimensions {
                        reset_reasons.insert(PixelChangeReset::DimensionsChanged);
                    }
                    if previous.mask != frame.mask().digest() {
                        reset_reasons.insert(PixelChangeReset::InterpretationChanged);
                    }
                } else {
                    reset_reasons.insert(PixelChangeReset::NoPredecessor);
                }
                if self.gap_pending {
                    reset_reasons.insert(PixelChangeReset::SourceGap);
                }
                // Reserve the next baseline before comparisons. No partial observation advances it.
                let mut pixels = Vec::new();
                pixels
                    .try_reserve_exact(frame.pixels().len())
                    .map_err(|_| RtpMotionError::Allocation)?;
                let mut predecessor_receipt = None;
                let statistics = if reset_reasons.is_empty() {
                    let previous = self
                        .previous
                        .as_ref()
                        .ok_or(PixelChangeError::InvalidImage)?;
                    predecessor_receipt = Some(previous.receipt);
                    Some(compare_pixels(
                        &previous.pixels,
                        frame.pixels(),
                        dimensions,
                        self.request.thresholds,
                        self.request.max_comparisons,
                        &mut self.stats.comparisons,
                        &mut || checkpoint(cx),
                    )?)
                } else {
                    None
                };
                pixels.extend_from_slice(frame.pixels());
                checkpoint(cx)?;
                let observation = RtpPixelChangeObservation {
                    source_root: frame.root(),
                    frame_receipt: receipt.digest(),
                    predecessor_receipt,
                    recipe: receipt.recipe(),
                    output_index: self.stats.observations as u64,
                    source_group: frame.source().group as u64,
                    decoder_epoch: frame.source().decoder_epoch as u64,
                    rtp_timestamp: frame.source().timestamp,
                    capture: frame.capture(),
                    dimensions,
                    mask_binding: frame.mask().digest(),
                    configuration_digest: self.request.thresholds.digest(),
                    reset_reasons,
                    statistics,
                };
                self.previous = Some(Previous {
                    receipt: receipt.digest(),
                    epoch: frame.source().decoder_epoch,
                    dimensions,
                    mask: frame.mask().digest(),
                    pixels,
                });
                self.gap_pending = false;
                self.stats.observations += 1;
                if let Some(s) = &observation.statistics {
                    self.stats.measured_pairs += 1;
                    self.stats.candidate_pairs += usize::from(s.candidate);
                } else {
                    self.stats.resets += 1;
                }
                Ok(RtpMotionStep::Observation(observation))
            }
        }
    }
}
fn checkpoint(cx: &ReplayCx) -> std::result::Result<(), PixelChangeError> {
    cx.checkpoint("rtpdump:motion")
        .map_err(|_| PixelChangeError::Cancelled)
}
