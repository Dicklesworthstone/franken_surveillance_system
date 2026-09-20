#![forbid(unsafe_code)]
//! Opt-in, source-linked activity/sentinel sampling for recorded perception.
//!
//! Sampling omits model invocations, never retained source or decode evidence. A quiet
//! comparison is not absence, a sentinel cadence is not a measured recall guarantee, and
//! a required-frame basis is an inclusion constraint, not permission to read or act.

use std::collections::BTreeSet;
use std::fmt;

use fss_core::{CanonicalEncode, CanonicalEncoder, ContentDigest, DigestAlgorithm};

use super::pixel_change::{PixelChangeConfig, PixelChangeDetector, PixelChangeError, PixelChangeObservation};
use super::recorded_decode::RecordedFrame;
use crate::ReplayCx;

/// Maximum distance between fixed sentinel positions in this reference policy.
pub const MAX_SENTINEL_STRIDE: u32 = 256;
/// Maximum number of consecutive follow-up frames after activity or a comparison reset.
pub const MAX_ACTIVITY_HOLD: u32 = 256;

/// Explicit immutable sampling policy. There is deliberately no automatic sampling default.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ActivityPolicy {
    /// Existing exact integer pixel-change measurement thresholds.
    pub change: PixelChangeConfig,
    /// Select ordinals 0, stride, 2*stride, ... independently of motion and holds.
    /// Counts source frames inspected by this sampler, not seconds or decoded model frames.
    pub sentinel_stride: u32,
    /// Additional frames to select after motion or an unmeasured comparison reset.
    pub post_activity_frames: u32,
}
impl ActivityPolicy {
    /// Reject invalid policy rather than weakening the sentinel floor.
    pub fn validate(self) -> Result<(), ActivityError> {
        self.change.validate().map_err(ActivityError::Measurement)?;
        if !(1..=MAX_SENTINEL_STRIDE).contains(&self.sentinel_stride)
            || self.post_activity_frames > MAX_ACTIVITY_HOLD
        { return Err(ActivityError::InvalidPolicy); }
        Ok(())
    }
    /// Identity of the exact policy, independent of any admission or effect authority.
    #[must_use]
    pub fn digest(self) -> ContentDigest { self.canonical_digest("fss.recorded_activity_policy.v1") }
}
impl CanonicalEncode for ActivityPolicy {
    fn encode_canonical(&self, e: &mut CanonicalEncoder) {
        self.change.encode_canonical(e);
        e.u32(self.sentinel_stride);
        e.u32(self.post_activity_frames);
    }
}

/// Inclusion reasons; simultaneous reasons are retained in this stable order.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
#[repr(u8)]
pub enum SamplingReason {
    /// A new sampler always selects its first input.
    FirstFrame = 0,
    /// Missing predecessor, source gap, or changed recording/geometry/interpretation.
    ComparisonReset = 1,
    /// Both configured exact change thresholds were met.
    PixelChange = 2,
    /// Fixed periodic sentinel, even when a quiet comparison is available.
    Sentinel = 3,
    /// Still inside the configured follow-up burst.
    ActivityHold = 4,
    /// An explicit owner inclusion constraint forbids skipping this frame.
    Required = 5,
    /// Comparison work was unavailable; fail open to inference, never to quiet.
    ComparisonBudgetFloor = 6,
}

/// Immutable decision over a verified frame. An empty reason set means only "model skipped".
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SamplingDecision {
    ordinal: u64,
    import_identity: ContentDigest,
    segment_index: u64,
    frame_root: ContentDigest,
    policy_digest: ContentDigest,
    predecessor: Option<ContentDigest>,
    required_basis: Option<ContentDigest>,
    measurement: Option<PixelChangeObservation>,
    reasons: BTreeSet<SamplingReason>,
    hold_remaining: u32,
}
impl SamplingDecision {
    /// Zero-based position in this exact sampler invocation.
    #[must_use]
    pub fn ordinal(&self) -> u64 { self.ordinal }
    /// Original immutable recording identity.
    #[must_use]
    pub fn import_identity(&self) -> ContentDigest { self.import_identity }
    /// Exact source segment, including segments whose model execution was skipped.
    #[must_use]
    pub fn segment_index(&self) -> u64 { self.segment_index }
    /// Canonical decoded publication binding source bytes, capture uncertainty and decoder.
    #[must_use]
    pub fn frame_root(&self) -> ContentDigest { self.frame_root }
    /// Whether inference is required by this sampling decision, not whether it completed.
    #[must_use]
    pub fn selected(&self) -> bool { !self.reasons.is_empty() }
    /// All inclusion reasons. A skipped model invocation does not certify scene absence.
    #[must_use]
    pub fn reasons(&self) -> &BTreeSet<SamplingReason> { &self.reasons }
    /// Exact previous decision, including skipped frames, or None at the beginning.
    #[must_use]
    pub fn predecessor(&self) -> Option<ContentDigest> { self.predecessor }
    /// Existing source-linked measurement; None only on explicit comparison-budget fallback.
    #[must_use]
    pub fn measurement(&self) -> Option<&PixelChangeObservation> { self.measurement.as_ref() }
    /// Stable complete decision identity, not a coverage or authorization certificate.
    #[must_use]
    pub fn digest(&self) -> ContentDigest { ContentDigest::sha256(&self.encoded()) }
    /// Versioned decision bytes. Source metadata is bound by the exact frame publication root.
    /// Every field is fixed-size or comes from a bounded, privately constructed measurement;
    /// no caller string or media payload is embedded in this encoding.
    #[must_use]
    pub fn encoded(&self) -> Vec<u8> {
        let mut e = CanonicalEncoder::new();
        e.bytes(b"FSSASMP1"); e.u32(1); e.text("fss.recorded_activity_decision.v1");
        e.u64(self.ordinal); e.digest(self.import_identity); e.u64(self.segment_index);
        e.digest(self.frame_root); e.digest(self.policy_digest);
        encode_optional_digest(&mut e, self.predecessor);
        encode_optional_digest(&mut e, self.required_basis);
        e.u64(self.reasons.len() as u64);
        for reason in &self.reasons { e.u8(*reason as u8); }
        e.u32(self.hold_remaining);
        e.bool(self.measurement.is_some());
        if let Some(measured) = &self.measurement {
            e.digest(measured.configuration_digest);
            encode_optional_digest(&mut e, measured.predecessor_root);
            e.u64(measured.reset_reasons.len() as u64);
            for reason in &measured.reset_reasons { e.text(reason.as_str()); }
            e.bool(measured.statistics.is_some());
            if let Some(stats) = &measured.statistics {
                e.u64(stats.compared_pixels); e.u64(stats.changed_pixels);
                e.u64(stats.absolute_difference_sum); e.u8(stats.maximum_difference);
                e.bool(stats.changed_bounds.is_some());
                if let Some(bounds) = stats.changed_bounds {
                    e.u32(bounds.left); e.u32(bounds.top); e.u32(bounds.right); e.u32(bounds.bottom);
                }
                e.bool(stats.candidate);
            }
        }
        // Only fixed-size fields and bounded enum spellings were encoded above.
        e.finish()
    }
}
fn encode_optional_digest(e: &mut CanonicalEncoder, value: Option<ContentDigest>) {
    e.bool(value.is_some());
    if let Some(value) = value { e.digest(value); }
}

/// Refusal never means the frame was safely skipped.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ActivityError {
    /// Invalid sentinel or burst bounds.
    InvalidPolicy,
    /// Required-frame provenance must use the canonical SHA-256 identity.
    InvalidRequirement,
    /// Same recording was traversed backwards or a source segment was substituted.
    OutOfOrder,
    /// Repeated frame supplied with a different inclusion constraint.
    ReplayConflict,
    /// The bounded ordinal can no longer advance.
    Exhausted,
    /// Measurement failed or was cancelled; budget exhaustion alone uses explicit inference fallback.
    Measurement(PixelChangeError),
}
impl fmt::Display for ActivityError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result { write!(f, "activity sampling refusal: {self:?}") }
}
impl std::error::Error for ActivityError {}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Signal { Quiet, Motion, Reset, Unavailable }

fn schedule(policy: ActivityPolicy, ordinal: u64, hold: u32, signal: Signal, required: bool)
    -> (BTreeSet<SamplingReason>, u32)
{
    let mut reasons = BTreeSet::new();
    if ordinal == 0 { reasons.insert(SamplingReason::FirstFrame); }
    if ordinal.is_multiple_of(u64::from(policy.sentinel_stride)) { reasons.insert(SamplingReason::Sentinel); }
    if hold > 0 { reasons.insert(SamplingReason::ActivityHold); }
    if required { reasons.insert(SamplingReason::Required); }
    match signal {
        Signal::Quiet => {},
        Signal::Motion => { reasons.insert(SamplingReason::PixelChange); },
        Signal::Reset => { reasons.insert(SamplingReason::ComparisonReset); },
        Signal::Unavailable => { reasons.insert(SamplingReason::ComparisonBudgetFloor); },
    }
    let remaining = if matches!(signal, Signal::Motion | Signal::Reset) {
        policy.post_activity_frames
    } else { hold.saturating_sub(1) };
    (reasons, remaining)
}

/// One-frame-memory sampler composed with the existing verified-luma measurement owner.
/// The fixed sentinel phase is never reset by motion, source gaps, or budget pressure.
#[derive(Debug)]
pub struct ActivitySampler {
    policy: ActivityPolicy,
    detector: PixelChangeDetector,
    next_ordinal: u64,
    hold_remaining: u32,
    last: Option<SamplingDecision>,
}
impl ActivitySampler {
    /// Allocate an explicit cumulative comparison budget; source/model budgets are separate.
    pub fn new(policy: ActivityPolicy, maximum_comparisons: u64) -> Result<Self, ActivityError> {
        policy.validate()?;
        let detector = PixelChangeDetector::new(policy.change, maximum_comparisons)
            .map_err(ActivityError::Measurement)?;
        Ok(Self { policy, detector, next_ordinal: 0, hold_remaining: 0, last: None })
    }
    /// Actual charged pixel comparisons, including rows processed before cancellation.
    #[must_use]
    pub fn comparisons_used(&self) -> u64 { self.detector.comparisons_used() }
    /// Remaining cumulative measurement allowance; a reset does not refill it.
    #[must_use]
    pub fn comparisons_remaining(&self) -> u64 { self.detector.comparisons_remaining() }
    /// Decide over exact retained decoded evidence. An optional required basis forces inclusion
    /// but does not grant source, model or effect authority. Repeated identical input is idempotent.
    /// If comparison work runs out, select inference explicitly rather than assuming quiet.
    pub fn push(&mut self, frame: &RecordedFrame, required_basis: Option<ContentDigest>, cx: &ReplayCx)
        -> Result<SamplingDecision, ActivityError>
    {
        cx.checkpoint("activity_sampler:frame")
            .map_err(|_| ActivityError::Measurement(PixelChangeError::Cancelled))?;
        if required_basis.is_some_and(|d| d.algorithm() != DigestAlgorithm::Sha256) {
            return Err(ActivityError::InvalidRequirement);
        }
        let root = frame.publication_root();
        let import = frame.receipt().import_identity();
        let segment = frame.receipt().segment_index();
        if let Some(last) = &self.last {
            if last.frame_root == root {
                if last.required_basis != required_basis { return Err(ActivityError::ReplayConflict); }
                return Ok(last.clone());
            }
            if last.import_identity == import && segment <= last.segment_index {
                return Err(ActivityError::OutOfOrder);
            }
        }
        let next = self.next_ordinal.checked_add(1).ok_or(ActivityError::Exhausted)?;
        let (measurement, signal) = match self.detector.push(frame, cx) {
            Ok(observation) => {
                let signal = if !observation.reset_reasons.is_empty() { Signal::Reset }
                    else if observation.statistics.as_ref().is_some_and(|s| s.candidate) { Signal::Motion }
                    else { Signal::Quiet };
                (Some(observation), signal)
            }
            Err(PixelChangeError::BudgetExceeded) => (None, Signal::Unavailable),
            Err(error) => return Err(ActivityError::Measurement(error)),
        };
        // No fallible operation follows measurement admission. A cancelled comparison above
        // leaves the existing baseline unchanged and retains its owner's charged work.
        let (reasons, remaining) = schedule(self.policy, self.next_ordinal, self.hold_remaining,
            signal, required_basis.is_some());
        let decision = SamplingDecision {
            ordinal: self.next_ordinal, import_identity: import, segment_index: segment,
            frame_root: root, policy_digest: self.policy.digest(),
            predecessor: self.last.as_ref().map(SamplingDecision::digest), required_basis,
            measurement, reasons, hold_remaining: remaining,
        };
        self.next_ordinal = next;
        self.hold_remaining = remaining;
        self.last = Some(decision.clone());
        Ok(decision)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn policy(stride: u32, hold: u32) -> ActivityPolicy {
        ActivityPolicy { change: PixelChangeConfig { minimum_delta: 20,
            minimum_changed_pixels: 1, minimum_changed_fraction_ppm: 0 },
            sentinel_stride: stride, post_activity_frames: hold }
    }
    #[test]
    fn quiet_sequences_have_fixed_sentinels_for_every_supported_stride() {
        for stride in 1..=MAX_SENTINEL_STRIDE {
            let p = policy(stride, 0);
            for ordinal in 0..u64::from(stride) * 3 + 1 {
                let (reasons, hold) = schedule(p, ordinal, 0, Signal::Quiet, false);
                assert_eq!(!reasons.is_empty(), ordinal % u64::from(stride) == 0);
                assert_eq!(hold, 0);
            }
        }
    }
    #[test]
    fn motion_and_reset_preserve_complete_burst_without_shifting_sentinels() {
        for trigger in [Signal::Motion, Signal::Reset] {
            let p = policy(5, 2);
            let mut hold = 0;
            let mut selected = Vec::new();
            for ordinal in 0..12 {
                let signal = if ordinal == 3 { trigger } else { Signal::Quiet };
                let (reasons, remaining) = schedule(p, ordinal, hold, signal, false);
                if !reasons.is_empty() { selected.push(ordinal); }
                assert_eq!(reasons.contains(&SamplingReason::Sentinel), ordinal % 5 == 0);
                hold = remaining;
            }
            assert_eq!(selected, [0, 3, 4, 5, 10]);
        }
    }
    #[test]
    fn required_and_unmeasured_inputs_are_never_skipped() {
        for ordinal in 1..512 {
            for signal in [Signal::Quiet, Signal::Motion, Signal::Reset, Signal::Unavailable] {
                let (reasons, _) = schedule(policy(256, 0), ordinal, 0, signal, true);
                assert!(reasons.contains(&SamplingReason::Required));
                let (reasons, _) = schedule(policy(256, 0), ordinal, 0, Signal::Unavailable, false);
                assert!(reasons.contains(&SamplingReason::ComparisonBudgetFloor));
            }
        }
    }
    #[test]
    fn simultaneous_inclusions_are_not_coalesced() {
        let (reasons, remaining) = schedule(policy(1, 2), 0, 1, Signal::Motion, true);
        assert_eq!(reasons, BTreeSet::from([SamplingReason::FirstFrame, SamplingReason::PixelChange,
            SamplingReason::Sentinel, SamplingReason::ActivityHold, SamplingReason::Required]));
        assert_eq!(remaining, 2);
    }
    #[test]
    fn invalid_policies_do_not_construct_a_sampler() {
        for p in [policy(0, 0), policy(257, 0), policy(1, 257)] {
            assert!(ActivitySampler::new(p, 1).is_err());
        }
        let mut p = policy(1, 0); p.change.minimum_delta = 0;
        assert!(ActivitySampler::new(p, 1).is_err());
        assert_ne!(policy(1, 0).digest(), policy(2, 0).digest());
        assert_ne!(policy(1, 0).digest(), policy(1, 1).digest());
    }
}
