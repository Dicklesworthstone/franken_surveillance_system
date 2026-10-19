#![forbid(unsafe_code)]
//! Explicit activity/sentinel admission before native RTP neural inference.
//!
//! All frames still pass through the existing current-custody, privacy and receipt owners.
//! Only RGB conversion and neural work are skipped. Every decoded position gets a chained
//! result; an unmeasured comparison selects inference, and gaps never become empty detections.
//! This is not a tracker, a live coverage certificate or an automatic policy activation.

use std::collections::{BTreeMap, BTreeSet};

use super::*;
use crate::ingest::activity::{ActivityPolicy, SamplingReason, Signal, schedule};
use crate::ingest::pixel_change::rtp::RtpPixelChangeObservation;
use crate::ingest::pixel_change::{PixelChangeError, PixelChangeReset, compare_pixels};
use fss_core::{CanonicalEncode, DigestAlgorithm};

/// Identity of the explicit sampling configuration and its independent allowances.
pub const RTP_CASCADE_RECIPE_DOMAIN: &str = "fss.rtp_activity_cascade_recipe.v1";
/// Identity of every included or skipped native output in the result chain.
pub const RTP_CASCADE_FRAME_DOMAIN: &str = "fss.rtp_activity_cascade_frame.v1";
const DECISION_RESERVATION: u64 = 4096;
const MAX_REQUIRED: usize = 4096;

/// Explicit opt-in; ordinary `RtpPackageDetector` still analyzes every native output.
#[derive(Clone, Debug)]
pub struct RtpCascadeRequest {
    /// The unchanged native decode, custody, receipt and neural request.
    pub detection: RtpDetectionRequest,
    /// Existing exact integer motion thresholds, fixed sentinels and follow-up bursts.
    pub policy: ActivityPolicy,
    /// Lifetime pixel comparisons. Exhaustion selects inference, never a quiet result.
    pub max_comparisons: u64,
    /// Maximum previous luma image, 0..=4,194,304 bytes. Zero disables comparisons.
    /// An image above this bound selects inference without retaining a baseline.
    pub max_baseline_bytes: usize,
    /// Lifetime decision encoding allowance, 4 KiB..=64 MiB, independent of report I/O.
    /// A complete 4 KiB reservation precedes each comparison; successful encoding refunds
    /// unused bytes. Failures retain their reservation and end the owner.
    pub max_decision_bytes: u64,
    /// Exact display positions that must reach inference, with owner-supplied reason identities.
    /// At most 4,096 unique positions below 4,096. Input order does not change the recipe.
    /// These are inclusion constraints, not source, model, tracking or effect authority.
    pub required_frames: Vec<(usize, ContentDigest)>,
}
impl RtpCascadeRequest {
    /// Construct an explicit policy with bounded comparison storage and decision encoding.
    pub fn new(
        detection: RtpDetectionRequest,
        policy: ActivityPolicy,
        max_comparisons: u64,
    ) -> Self {
        Self {
            detection,
            policy,
            max_comparisons,
            max_baseline_bytes: 4_194_304,
            max_decision_bytes: 16 * 1024 * 1024,
            required_frames: Vec::new(),
        }
    }
}

/// Why comparison could not be performed. Neither variant is evidence of quiet pixels.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RtpComparisonUnavailable {
    /// The remaining lifetime work allowance cannot admit this complete pair.
    WorkBudget,
    /// This image exceeds the caller's explicit previous-image storage allowance.
    BaselineLimit,
}

/// Privately constructed decision over one actual native frame receipt.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RtpSamplingDecision {
    observation: RtpPixelChangeObservation,
    reasons: BTreeSet<SamplingReason>,
    unavailable: Option<RtpComparisonUnavailable>,
    required_basis: Option<ContentDigest>,
    policy: ContentDigest,
    recipe: ContentDigest,
    predecessor: Option<ContentDigest>,
    hold_remaining: u32,
    bytes: Vec<u8>,
    digest: ContentDigest,
}
impl RtpSamplingDecision {
    /// Complete source-linked comparison or explicit unmeasured baseline.
    pub fn observation(&self) -> &RtpPixelChangeObservation {
        &self.observation
    }
    /// All simultaneous inclusion reasons, using the existing sampling vocabulary.
    pub fn reasons(&self) -> &BTreeSet<SamplingReason> {
        &self.reasons
    }
    /// Inference is required, not necessarily completed.
    pub fn selected(&self) -> bool {
        !self.reasons.is_empty()
    }
    /// Explicit resource fallback; never confused with a measured zero difference.
    pub fn comparison_unavailable(&self) -> Option<RtpComparisonUnavailable> {
        self.unavailable
    }
    /// Owner inclusion constraint applied to this exact native display position.
    pub fn required_basis(&self) -> Option<ContentDigest> {
        self.required_basis
    }
    /// Exact preceding delivered cascade result, including a preceding skipped result.
    pub fn predecessor(&self) -> Option<ContentDigest> {
        self.predecessor
    }
    /// Existing immutable activity policy identity.
    pub fn policy(&self) -> ContentDigest {
        self.policy
    }
    /// Configuration, inclusion constraints and allowances for this invocation.
    pub fn recipe(&self) -> ContentDigest {
        self.recipe
    }
    /// Original canonical decision bytes, with no pixels or secrets.
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }
    /// Identity of the complete decision, distinct from its native frame receipt.
    pub fn digest(&self) -> ContentDigest {
        self.digest
    }
    fn seal(&mut self) -> Result<()> {
        let mut e = CanonicalEncoder::new();
        e.text("fss.rtp_activity_sampling_decision.v1");
        e.digest(self.recipe);
        e.digest(self.policy);
        optional(&mut e, self.predecessor);
        optional(&mut e, self.required_basis);
        self.observation.encode_canonical(&mut e);
        e.u8(match self.unavailable {
            None => 0,
            Some(RtpComparisonUnavailable::WorkBudget) => 1,
            Some(RtpComparisonUnavailable::BaselineLimit) => 2,
        });
        e.u64(self.reasons.len() as u64);
        for reason in &self.reasons {
            e.u8(*reason as u8);
        }
        e.u32(self.hold_remaining);
        self.bytes = e
            .finish_checked()
            .map_err(|_| RtpDetectionError::Encoding)?;
        if self.bytes.len() as u64 > DECISION_RESERVATION {
            return Err(RtpDetectionError::Encoding);
        }
        self.digest = ContentDigest::sha256(&self.bytes);
        Ok(())
    }
}

enum FrameResult {
    Inferred(RtpDetectedFrame),
    Skipped(RetainedRtpFrameReceipt),
}

/// One source-linked result for every decoded position, including intentionally skipped ones.
pub struct RtpCascadeFrame {
    decision: RtpSamplingDecision,
    result: FrameResult,
    digest: ContentDigest,
}
impl std::fmt::Debug for RtpCascadeFrame {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RtpCascadeFrame")
            .field("digest", &self.digest)
            .field("decision", &self.decision.digest())
            .field("selected", &self.decision.selected())
            .finish_non_exhaustive()
    }
}
impl RtpCascadeFrame {
    /// The immutable admission/skip decision.
    pub fn decision(&self) -> &RtpSamplingDecision {
        &self.decision
    }
    /// Actual native receipt, available even when no neural invocation was selected.
    pub fn receipt(&self) -> &RetainedRtpFrameReceipt {
        match &self.result {
            FrameResult::Inferred(frame) => frame.receipt(),
            FrameResult::Skipped(receipt) => receipt,
        }
    }
    /// None means "not executed", not "executed and found no objects".
    pub fn detection(&self) -> Option<&RtpDetectedFrame> {
        match &self.result {
            FrameResult::Inferred(frame) => Some(frame),
            FrameResult::Skipped(_) => None,
        }
    }
    /// Joint identity of this selection and its exact neural result or explicit omission.
    pub fn digest(&self) -> ContentDigest {
        self.digest
    }
}

/// Independent sampling accounting plus the existing native/neural accounting.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct RtpCascadeStats {
    /// Unchanged inference accounting. Its `complete` stays false when outputs were skipped.
    pub detection: RtpDetectionStats,
    /// Sampling decisions admitted, including a later failed required inference.
    pub considered: usize,
    /// Frames selected by the fixed policy or owner inclusion constraint.
    pub selected: usize,
    /// Complete paired results delivered, including explicit skips.
    pub delivered: usize,
    /// Intentionally unexecuted model invocations with delivered native receipts.
    pub skipped: usize,
    /// Actual pixel comparisons, including work before cancellation; no reset refills it.
    pub comparisons: u64,
    /// Decisions using explicit inference fallback after comparison resource refusal.
    pub comparison_fallbacks: usize,
    /// Cumulative charged decision encoding bytes, including failed reservations.
    pub decision_bytes: u64,
    /// Required positions not yet delivered with successful inference.
    pub unobserved_required: usize,
    /// Exact last delivered result; no synthetic terminal or missing-frame result is added.
    pub last_result: Option<ContentDigest>,
}
impl RtpCascadeStats {
    /// Every native output was accounted for and every selected invocation completed.
    /// This does NOT mean every frame was inferred, physical absence, or measured recall.
    pub fn complete(&self) -> bool {
        self.detection.ended
            && self.detection.failures == 0
            && self.detection.native.complete()
            && self.considered == self.detection.native.frames
            && self.delivered == self.considered
            && self.selected == self.detection.frames
            && self.delivered.checked_sub(self.skipped) == Some(self.selected)
            && self.unobserved_required == 0
    }
    /// Separate all-frames-inferred statement; never silently inferred from scan completion.
    pub fn exhaustive(&self) -> bool {
        self.complete() && self.skipped == 0 && self.detection.complete()
    }
}

/// Source progress is never filtered by the activity policy.
#[derive(Debug)]
pub enum RtpCascadeStep {
    /// Existing receiver/decoder facts and consequences, including every gap or refusal.
    Progress {
        /// Original payload-free source fact.
        event: RetainedRtpEvent,
        /// Original decoder consequence.
        effect: RtpDecodeEffect,
    },
    /// Exactly one source-receipted sampling result for an actual decoded frame.
    Frame(RtpCascadeFrame),
    /// Complete, incomplete and exhaustive remain independently inspectable.
    Ended(RtpCascadeStats),
}

struct Previous {
    receipt: ContentDigest,
    recipe: ContentDigest,
    root: ContentDigest,
    epoch: usize,
    dimensions: [u32; 2],
    mask: ContentDigest,
    pixels: Vec<u8>,
}

/// Owns one native decoder and the existing numerical inference engine, not two scans.
/// Admission is fixed at construction. No frame/receipt pairs or model scores are supplied
/// by callers, and no model, privacy policy or source record is published or activated.
pub struct RtpDetectionCascade<'a> {
    inner: RtpPackageDetector<'a>,
    policy: ActivityPolicy,
    required: BTreeMap<usize, ContentDigest>,
    recipe: ContentDigest,
    max_comparisons: u64,
    max_baseline_bytes: usize,
    max_decision_bytes: u64,
    previous: Option<Previous>,
    gap_pending: bool,
    hold_remaining: u32,
    stats: RtpCascadeStats,
}
impl<'a> RtpDetectionCascade<'a> {
    /// Explicit native/source/model admission; validates the sampling request before source I/O.
    pub fn new(
        retained: &'a RecoveredRtpImport,
        package: &'a RgbDetectorPackage,
        request: RtpCascadeRequest,
        deployment: &ReferenceDeployment,
        cx: &ReplayCx,
        scalar: &ScalarExecCx,
    ) -> Result<Self> {
        checkpoint(cx, scalar, "rtp_cascade:open")?;
        request
            .policy
            .validate()
            .map_err(|_| RtpDetectionError::InvalidRequest)?;
        if request.max_baseline_bytes > 4_194_304
            || !(DECISION_RESERVATION..=64 * 1024 * 1024).contains(&request.max_decision_bytes)
            || request.required_frames.len() > MAX_REQUIRED
        {
            return Err(RtpDetectionError::InvalidRequest);
        }
        let mut required = BTreeMap::new();
        for &(index, basis) in &request.required_frames {
            if index >= MAX_REQUIRED
                || basis.algorithm() != DigestAlgorithm::Sha256
                || required.insert(index, basis).is_some()
            {
                return Err(RtpDetectionError::InvalidRequest);
            }
        }
        let inner =
            RtpPackageDetector::new(retained, package, request.detection, deployment, cx, scalar)?;
        let mut e = CanonicalEncoder::new();
        e.text(RTP_CASCADE_RECIPE_DOMAIN);
        e.digest(inner.recipe());
        e.digest(request.policy.digest());
        // Sampling cannot silently reprice its required inference floor or source checks.
        // The original numerical recipe remains unchanged for compatible selected frames.
        let detection = request.detection;
        for limit in [
            detection.analysis.max_frames as u64,
            detection.analysis.max_color_pixels,
            detection.analysis.max_preprocess_work,
            detection.analysis.max_execution_macs,
            detection.analysis.max_tensor_bytes,
            detection.analysis.detection_work,
            detection.analysis.detection_scratch_bytes as u64,
            detection.custody.max_source_bytes as u64,
            detection.custody.max_records as u64,
            detection.custody.max_object_bytes as u64,
            detection.custody.max_read_bytes,
            detection.custody.max_steps as u64,
            detection.custody.max_graph_objects as u64,
            detection.receipts.max_receipt_bytes as u64,
            detection.receipts.max_total_bytes,
        ] {
            e.u64(limit);
        }
        e.u64(request.max_comparisons);
        e.u64(request.max_baseline_bytes as u64);
        e.u64(request.max_decision_bytes);
        e.u64(DECISION_RESERVATION);
        e.u64(required.len() as u64);
        for (&index, &basis) in &required {
            e.u64(index as u64);
            e.digest(basis);
        }
        let recipe = ContentDigest::sha256(
            &e.finish_checked()
                .map_err(|_| RtpDetectionError::Encoding)?,
        );
        let stats = RtpCascadeStats {
            detection: inner.stats(),
            unobserved_required: required.len(),
            ..Default::default()
        };
        Ok(Self {
            inner,
            policy: request.policy,
            required,
            recipe,
            max_comparisons: request.max_comparisons,
            max_baseline_bytes: request.max_baseline_bytes,
            max_decision_bytes: request.max_decision_bytes,
            previous: None,
            gap_pending: false,
            hold_remaining: 0,
            stats,
        })
    }
    /// Exact opt-in sampling identity; the numerical detector recipe remains separate.
    pub fn recipe(&self) -> ContentDigest {
        self.recipe
    }
    /// Current charged work and delivered results, including failures and unobserved floors.
    pub fn stats(&self) -> RtpCascadeStats {
        RtpCascadeStats {
            detection: self.inner.stats(),
            ..self.stats
        }
    }
    /// One bounded progress/result. Any error retires decoder and comparison state permanently.
    pub fn step(
        &mut self,
        deployment: &ReferenceDeployment,
        cx: &ReplayCx,
        scalar: &ScalarExecCx,
    ) -> Result<RtpCascadeStep> {
        if self.inner.decoder.is_none() {
            return Ok(RtpCascadeStep::Ended(self.stats()));
        }
        let result = self.advance(deployment, cx, scalar);
        let result = self.inner.finish_step(result, cx, scalar);
        if result.is_err() || self.inner.decoder.is_none() {
            self.previous = None;
        }
        result
    }
    fn advance(
        &mut self,
        deployment: &ReferenceDeployment,
        cx: &ReplayCx,
        scalar: &ScalarExecCx,
    ) -> Result<RtpCascadeStep> {
        match self.inner.next_native(deployment, cx, scalar)? {
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
                Ok(RtpCascadeStep::Progress { event, effect })
            }
            ReceiptedRtpDecodeStep::Ended(_) => {
                self.inner.decoder = None;
                self.inner.stats.ended = true;
                Ok(RtpCascadeStep::Ended(self.stats()))
            }
            ReceiptedRtpDecodeStep::Frame { frame, receipt } => {
                let index = self
                    .inner
                    .stats
                    .native
                    .frames
                    .checked_sub(1)
                    .ok_or(RtpDetectionError::Encoding)?;
                if index != self.stats.considered {
                    return Err(RtpDetectionError::Encoding);
                }
                let decision = self.decide(&frame, &receipt, index, cx, scalar)?;
                self.stats.considered += 1;
                self.stats.selected += usize::from(decision.selected());
                let result = if decision.selected() {
                    FrameResult::Inferred(self.inner.infer(frame, receipt, cx, scalar)?)
                } else {
                    drop(frame);
                    FrameResult::Skipped(receipt)
                };
                checkpoint(cx, scalar, "rtp_cascade:deliver")?;
                if deployment.current_anchor() != &self.inner.basis {
                    return Err(RtpDetectionError::StaleBasis);
                }
                let mut e = CanonicalEncoder::new();
                e.text(RTP_CASCADE_FRAME_DOMAIN);
                e.digest(self.recipe);
                e.digest(decision.digest());
                e.bool(decision.selected());
                match &result {
                    FrameResult::Inferred(frame) => e.digest(frame.digest()),
                    FrameResult::Skipped(receipt) => e.digest(receipt.digest()),
                }
                let digest = ContentDigest::sha256(
                    &e.finish_checked()
                        .map_err(|_| RtpDetectionError::Encoding)?,
                );
                match &result {
                    FrameResult::Inferred(frame) => {
                        self.inner.stats.frames += 1;
                        self.inner.stats.proposals += frame.detections().detections().len();
                        if decision.required_basis().is_some() {
                            self.stats.unobserved_required -= 1;
                        }
                    }
                    FrameResult::Skipped(_) => self.stats.skipped += 1,
                }
                self.stats.delivered += 1;
                self.stats.last_result = Some(digest);
                Ok(RtpCascadeStep::Frame(RtpCascadeFrame {
                    decision,
                    result,
                    digest,
                }))
            }
        }
    }
    fn decide(
        &mut self,
        frame: &RetainedRtpH264Frame,
        receipt: &RetainedRtpFrameReceipt,
        index: usize,
        cx: &ReplayCx,
        scalar: &ScalarExecCx,
    ) -> Result<RtpSamplingDecision> {
        checkpoint(cx, scalar, "rtp_cascade:admit")?;
        let dimensions = frame.dimensions();
        let [w, h] = dimensions;
        let pixels = u64::from(w) * u64::from(h);
        if w == 0
            || h == 0
            || w > 4096
            || h > 4096
            || pixels > 4_194_304
            || pixels != frame.pixels().len() as u64
        {
            return Err(RtpDetectionError::InvalidRequest);
        }
        self.stats.decision_bytes = self
            .stats
            .decision_bytes
            .checked_add(DECISION_RESERVATION)
            .filter(|next| *next <= self.max_decision_bytes)
            .ok_or(RtpDetectionError::Limit("sampling_decisions"))?;
        let mut resets = BTreeSet::new();
        if let Some(previous) = &self.previous {
            if previous.root != frame.root() {
                resets.insert(PixelChangeReset::RecordingChanged);
            }
            if previous.epoch != frame.source().decoder_epoch {
                resets.insert(PixelChangeReset::SourceGap);
            }
            if previous.dimensions != dimensions {
                resets.insert(PixelChangeReset::DimensionsChanged);
            }
            if previous.mask != frame.mask().digest() || previous.recipe != receipt.recipe() {
                resets.insert(PixelChangeReset::InterpretationChanged);
            }
        } else {
            resets.insert(PixelChangeReset::NoPredecessor);
        }
        if self.gap_pending {
            resets.insert(PixelChangeReset::SourceGap);
        }
        let mut unavailable = None;
        let mut predecessor_receipt = None;
        let mut statistics = None;
        if pixels > self.max_baseline_bytes as u64 {
            unavailable = Some(RtpComparisonUnavailable::BaselineLimit);
        } else if resets.is_empty() {
            let previous = self.previous.as_ref().ok_or(RtpDetectionError::Encoding)?;
            match compare_pixels(
                &previous.pixels,
                frame.pixels(),
                dimensions,
                self.policy.change,
                self.max_comparisons,
                &mut self.stats.comparisons,
                &mut || {
                    checkpoint(cx, scalar, "rtp_cascade:row")
                        .map_err(|_| PixelChangeError::Cancelled)
                },
            ) {
                Ok(measured) => {
                    predecessor_receipt = Some(previous.receipt);
                    statistics = Some(measured);
                }
                Err(PixelChangeError::BudgetExceeded) => {
                    unavailable = Some(RtpComparisonUnavailable::WorkBudget);
                }
                Err(PixelChangeError::Cancelled) => return Err(RtpDetectionError::Cancelled),
                Err(_) => return Err(RtpDetectionError::InvalidRequest),
            }
        }
        let signal = if unavailable.is_some() {
            Signal::Unavailable
        } else if !resets.is_empty() {
            Signal::Reset
        } else if statistics.as_ref().is_some_and(|s| s.candidate) {
            Signal::Motion
        } else {
            Signal::Quiet
        };
        let required_basis = self.required.get(&index).copied();
        let (reasons, hold_remaining) = schedule(
            self.policy,
            index as u64,
            self.hold_remaining,
            signal,
            required_basis.is_some(),
        );
        let mut decision = RtpSamplingDecision {
            observation: RtpPixelChangeObservation {
                source_root: frame.root(),
                frame_receipt: receipt.digest(),
                predecessor_receipt,
                recipe: receipt.recipe(),
                output_index: index as u64,
                source_group: frame.source().group as u64,
                decoder_epoch: frame.source().decoder_epoch as u64,
                rtp_timestamp: frame.source().timestamp,
                capture: frame.capture(),
                dimensions,
                mask_binding: frame.mask().digest(),
                configuration_digest: self.policy.change.digest(),
                reset_reasons: resets,
                statistics,
            },
            reasons,
            unavailable,
            required_basis,
            policy: self.policy.digest(),
            recipe: self.recipe,
            predecessor: self.stats.last_result,
            hold_remaining,
            bytes: Vec::new(),
            digest: ContentDigest::sha256(&[]),
        };
        decision.seal()?;
        checkpoint(cx, scalar, "rtp_cascade:baseline")?;
        if pixels <= self.max_baseline_bytes as u64 {
            // Reuse the old luma allocation after comparison; do not retain another image.
            let mut previous_pixels = self.previous.take().map(|p| p.pixels).unwrap_or_default();
            previous_pixels.clear();
            previous_pixels
                .try_reserve_exact(frame.pixels().len())
                .map_err(|_| RtpDetectionError::Limit("sampling_baseline_allocation"))?;
            previous_pixels.extend_from_slice(frame.pixels());
            self.previous = Some(Previous {
                receipt: receipt.digest(),
                recipe: receipt.recipe(),
                root: frame.root(),
                epoch: frame.source().decoder_epoch,
                dimensions,
                mask: frame.mask().digest(),
                pixels: previous_pixels,
            });
        } else {
            self.previous = None;
        }
        self.gap_pending = false;
        self.hold_remaining = hold_remaining;
        self.stats.decision_bytes -= DECISION_RESERVATION - decision.bytes.len() as u64;
        self.stats.comparison_fallbacks += usize::from(unavailable.is_some());
        Ok(decision)
    }
}
fn optional(e: &mut CanonicalEncoder, digest: Option<ContentDigest>) {
    e.bool(digest.is_some());
    if let Some(digest) = digest {
        e.digest(digest);
    }
}
