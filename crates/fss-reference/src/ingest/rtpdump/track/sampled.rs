#![forbid(unsafe_code)]
//! Native sampled inference and anonymous association in one request-owned pipeline.
//!
//! Every decoded position retains its cascade receipt. An unexecuted model is NOT a
//! negative detection: no tracker update occurs, existing hypotheses retire, and the next
//! selected position starts a disjoint association epoch. Contiguous selected bursts use
//! exactly the exhaustive owner's projection, budget admission and assignment solver.

use super::*;
use crate::ingest::rtpdump::detect::cascade::{
    RtpCascadeFrame, RtpCascadeRequest, RtpCascadeStats, RtpCascadeStep, RtpDetectionCascade,
};

/// Stable interpretation of intentional inference omissions; never an effect authority.
pub const RTP_SAMPLED_TRACKING_DOMAIN: &str =
    "fss.rtp_sampled_tracking.v1:no-update-on-skip:retire-on-skip:no-gap-association";

/// Immutable sampling, class and numerical policy with independent lifetime allowances.
#[derive(Clone, Debug)]
pub struct RtpSampledTrackingRequest {
    /// Exact activity/sentinel policy, required positions and native/inference admissions.
    pub cascade: RtpCascadeRequest,
    /// Explicit verified vocabulary index, not a person identity or label lookup.
    pub class_index: usize,
    /// The same sample-step numerical policy as exhaustive native RTP tracking.
    pub tracker: TrackerConfig,
    /// Counts selected updates, including executed frames with zero selected proposals.
    /// Skips still consume the cascade's native and decision allowances.
    pub limits: RtpTrackingLimits,
}

/// A complete actual association, present only after successful selected inference.
#[derive(Debug)]
pub struct RtpSampledAssociation {
    observations: Vec<RtpTrackObservation>,
    epoch: u64,
    reset: Option<RtpTrackReset>,
    active_tracks: usize,
    deleted_tracks: usize,
}
impl RtpSampledAssociation {
    /// Actual assignments to complete-report indices, never coasting predictions.
    pub fn observations(&self) -> &[RtpTrackObservation] { &self.observations }
    /// Disjoint association namespace after an intentional or source gap.
    pub fn epoch(&self) -> u64 { self.epoch }
    /// Why this selected position cannot continue the preceding association epoch.
    pub fn reset(&self) -> Option<RtpTrackReset> { self.reset }
    /// Includes unobserved numerical predictions; it is not an object-presence count.
    pub fn active_tracks(&self) -> usize { self.active_tracks }
    /// Normal selected-update lifecycle retirements, not source or sampling resets.
    pub fn deleted_tracks(&self) -> usize { self.deleted_tracks }
}

/// Joint native sampling and temporal result, including positions without inference.
#[derive(Debug)]
pub struct RtpSampledTrackFrame {
    sample: RtpCascadeFrame,
    association: Option<RtpSampledAssociation>,
    retired_on_skip: usize,
    predecessor: Option<ContentDigest>,
    recipe: ContentDigest,
    digest: ContentDigest,
}
impl RtpSampledTrackFrame {
    /// Original cascade result and exact source-to-pixels receipt; no relabelled positions.
    pub fn sample(&self) -> &RtpCascadeFrame { &self.sample }
    /// None means association was NOT executed, not an empty observation update.
    pub fn association(&self) -> Option<&RtpSampledAssociation> { self.association.as_ref() }
    /// Hypotheses retired on this explicit skip; they are not detector misses or exits.
    pub fn retired_on_skip(&self) -> usize { self.retired_on_skip }
    /// Previous joint result, including every intentional inference omission.
    pub fn predecessor(&self) -> Option<ContentDigest> { self.predecessor }
    /// Exact sampling, class, source implementation and association admission identity.
    pub fn recipe(&self) -> ContentDigest { self.recipe }
    /// Complete source-linked joint result identity, not a publication or signature.
    pub fn digest(&self) -> ContentDigest { self.digest }
}

/// Independent upstream and temporal accounting. No inference budget is replenished here.
#[derive(Clone, Copy, Debug, Default)]
pub struct RtpSampledTrackingStats {
    /// Native, sampling and neural work, including results refused by this outer owner.
    pub sampling: RtpCascadeStats,
    /// Actual delivered associations and reserved solver work. Its exhaustive `complete()`
    /// intentionally remains false after inference skips; use this type's `complete()`.
    pub tracking: RtpTrackingStats,
    /// Delivered joint positions, including skips.
    pub delivered: usize,
    /// Delivered positions with no neural or association update.
    pub skipped: usize,
    /// Hypotheses retired by delivered skip positions, not confirmed physical departures.
    pub retired_on_skip: u64,
    /// Last complete joint result; failed delivery never advances it.
    pub last_result: Option<ContentDigest>,
}
impl RtpSampledTrackingStats {
    /// Every native output was accounted for and every selected result was associated.
    /// Source gaps, failed inference, missing required frames or outer failures prevent success.
    pub fn complete(&self) -> bool {
        self.tracking.ended && self.tracking.failures == 0 && self.sampling.complete()
            && self.delivered == self.sampling.delivered
            && self.skipped == self.sampling.skipped
            && self.tracking.frames == self.sampling.detection.frames
            && self.delivered.checked_sub(self.skipped) == Some(self.tracking.frames)
    }
    /// True only for successful runs that actually inferred and associated every native output.
    pub fn exhaustive(&self) -> bool { self.complete() && self.skipped == 0 }
}

/// One original source fact, one joint sampled position, or explicit terminal accounting.
#[derive(Debug)]
pub enum RtpSampledTrackingStep {
    /// Unmodified source/decode progress; intentional sampling never suppresses these facts.
    Progress { event: RetainedRtpEvent, effect: RtpDecodeEffect },
    /// Selected association or explicit skip with original receipts and chained identity.
    Frame(RtpSampledTrackFrame),
    /// Terminal queries cannot restart the owner or restore allowances.
    Ended(RtpSampledTrackingStats),
}

/// One synchronous owner: native custody -> sampled inference -> shared actual association.
/// It never consumes external detector reports or promotes predictions into observations.
pub struct RtpSampledTracker<'a> {
    cascade: Option<RtpDetectionCascade<'a>>,
    core: TrackCore,
    class_index: usize,
    recipe: ContentDigest,
    basis: LedgerAnchor,
    stats: RtpSampledTrackingStats,
}
impl<'a> RtpSampledTracker<'a> {
    /// Validate class and association ceilings before opening the native cascade.
    pub fn new(
        retained: &'a RecoveredRtpImport,
        package: &'a RgbDetectorPackage,
        request: RtpSampledTrackingRequest,
        deployment: &ReferenceDeployment,
        cx: &ReplayCx,
        scalar: &ScalarExecCx,
    ) -> Result<Self> {
        checkpoint(cx, scalar, "rtp_sampled_track:open")?;
        if request.class_index >= package.spec().labels.len() {
            return Err(RtpTrackingError::InvalidRequest);
        }
        let core = TrackCore::new(request.tracker, request.limits)?;
        let cascade = RtpDetectionCascade::new(retained, package, request.cascade,
            deployment, cx, scalar).map_err(RtpTrackingError::Detection)?;
        let mut e = CanonicalEncoder::new();
        e.text(RTP_SAMPLED_TRACKING_DOMAIN);
        e.digest(ContentDigest::sha256(include_bytes!("sampled.rs")));
        e.digest(tracking_recipe(cascade.recipe(), request.class_index, &core)?);
        let recipe = digest(e)?;
        let stats = RtpSampledTrackingStats {
            sampling: cascade.stats(),
            tracking: RtpTrackingStats { detection: cascade.stats().detection, ..Default::default() },
            ..Default::default()
        };
        Ok(Self { cascade: Some(cascade), core, class_index: request.class_index,
            recipe, basis: deployment.current_anchor().clone(), stats })
    }
    /// Complete immutable interpretation including intentional observation gaps.
    pub fn recipe(&self) -> ContentDigest { self.recipe }
    /// Current lifetime accounting, including work reserved before a failed delivery.
    pub fn stats(&self) -> RtpSampledTrackingStats { self.stats }
    /// Any refusal terminates the entire owner and drops queued media and numerical state.
    pub fn step(&mut self, deployment: &ReferenceDeployment, cx: &ReplayCx,
        scalar: &ScalarExecCx) -> Result<RtpSampledTrackingStep>
    {
        if self.cascade.is_none() { return Ok(RtpSampledTrackingStep::Ended(self.stats)); }
        let mut result = self.advance(deployment, cx, scalar);
        self.stats.tracking.assignments_reserved = self.core.assignments;
        self.stats.tracking.assignment_work_reserved = self.core.work;
        self.stats.tracking.resets = self.core.epoch;
        if result.is_err() {
            self.cascade = None;
            self.stats.tracking.failures += 1;
            self.stats.tracking.ended = true;
            if cx.is_cancelled() || scalar.is_cancelled() {
                cx.drain_and_finalize();
                scalar.request_cancellation();
                scalar.drain_and_finalize();
                result = Err(RtpTrackingError::Cancelled);
            }
        }
        match result {
            Ok(RtpSampledTrackingStep::Ended(_)) => Ok(RtpSampledTrackingStep::Ended(self.stats)),
            other => other,
        }
    }
    fn advance(&mut self, deployment: &ReferenceDeployment, cx: &ReplayCx,
        scalar: &ScalarExecCx) -> Result<RtpSampledTrackingStep>
    {
        checkpoint(cx, scalar, "rtp_sampled_track:step")?;
        if deployment.current_anchor() != &self.basis { return Err(RtpTrackingError::StaleBasis); }
        let cascade = self.cascade.as_mut().ok_or(RtpTrackingError::Encoding)?;
        let result = cascade.step(deployment, cx, scalar);
        self.stats.sampling = cascade.stats();
        self.stats.tracking.detection = self.stats.sampling.detection;
        match result.map_err(RtpTrackingError::Detection)? {
            RtpCascadeStep::Progress { event, effect } => {
                if matches!(&effect, RtpDecodeEffect::Refused { .. }
                    | RtpDecodeEffect::WaitingForIdr { .. } | RtpDecodeEffect::Fenced)
                { self.core.gap = true; }
                Ok(RtpSampledTrackingStep::Progress { event, effect })
            }
            RtpCascadeStep::Ended(_) => {
                self.cascade = None;
                self.stats.tracking.ended = true;
                Ok(RtpSampledTrackingStep::Ended(self.stats))
            }
            RtpCascadeStep::Frame(sample) => {
                if sample.decision().observation().output_index != self.stats.delivered as u64 {
                    return Err(RtpTrackingError::SourceOrder);
                }
                if sample.decision().selected() != sample.detection().is_some() {
                    return Err(RtpTrackingError::Encoding);
                }
                let (association, retired_on_skip) = if let Some(detected) = sample.detection() {
                    let (assigned, reset, observations) =
                        associate(&mut self.core, detected, self.class_index, self.recipe)?;
                    (Some(RtpSampledAssociation { observations, epoch: self.core.epoch, reset,
                        active_tracks: assigned.output.tracks.len(),
                        deleted_tracks: assigned.output.deleted_tracks }), 0)
                } else {
                    // No empty tracker step: retire stale hypotheses without adding misses,
                    // hits, sample-step velocities, frame charges or synthetic observations.
                    // Keep order and lifetime reservations so the next selected native index
                    // triggers the shared DisplayGap reset and cannot reuse an old identity.
                    (None, retire_on_skip(&mut self.core)?)
                };
                let mut frame = RtpSampledTrackFrame { sample, association, retired_on_skip,
                    predecessor: self.stats.last_result, recipe: self.recipe,
                    digest: ContentDigest::sha256(&[]) };
                let mut e = CanonicalEncoder::new();
                e.text("fss.rtp_sampled_tracked_frame.v1");
                e.digest(self.recipe);
                e.digest(frame.sample.digest());
                e.bool(frame.predecessor.is_some());
                if let Some(previous) = frame.predecessor { e.digest(previous); }
                e.u64(retired_on_skip as u64);
                e.u64(self.core.work);
                e.u64(self.core.assignments);
                e.bool(frame.association.is_some());
                if let Some(a) = &frame.association {
                    e.u64(a.epoch);
                    e.u8(match a.reset { None => 0, Some(RtpTrackReset::Baseline) => 1,
                        Some(RtpTrackReset::SourceGap) => 2, Some(RtpTrackReset::DisplayGap) => 3,
                        Some(RtpTrackReset::ProjectionChanged) => 4 });
                    e.u64(a.active_tracks as u64);
                    e.u64(a.deleted_tracks as u64);
                    encode_observations(&mut e, &a.observations)?;
                }
                frame.digest = digest(e)?;
                checkpoint(cx, scalar, "rtp_sampled_track:deliver")?;
                if deployment.current_anchor() != &self.basis { return Err(RtpTrackingError::StaleBasis); }
                self.stats.delivered += 1;
                self.stats.skipped += usize::from(frame.association.is_none());
                self.stats.tracking.frames += usize::from(frame.association.is_some());
                self.stats.retired_on_skip += retired_on_skip as u64;
                self.stats.last_result = Some(frame.digest);
                Ok(RtpSampledTrackingStep::Frame(frame))
            }
        }
    }
}

fn retire_on_skip(core: &mut TrackCore) -> Result<usize> {
    let retired = core.active;
    core.tracker = MultiObjectTracker::new(core.config.clone())
        .map_err(|_| RtpTrackingError::InvalidRequest)?;
    core.active = 0;
    Ok(retired)
}

#[cfg(test)]
mod tests {
    use super::*;
    type Test = std::result::Result<(), Box<dyn std::error::Error>>;
    fn core(limits: RtpTrackingLimits) -> Result<TrackCore> {
        TrackCore::new(TrackerConfig { min_hits: 2, max_misses: 2, iou_threshold: 0.1,
            process_noise: 1.0, measurement_noise: 1.0 }, limits)
    }
    fn order(index: usize) -> FrameOrder {
        FrameOrder { index, decoder_epoch: 0, dimensions: [640, 480], policy: None }
    }
    fn boxes() -> [Detection; 1] {
        [Detection { box_x: 0.0, box_y: 0.0, box_w: 20.0, box_h: 20.0 }]
    }
    #[test]
    fn skips_retire_without_negative_updates_or_replenishing_any_allowance() -> Test {
        let mut c = core(RtpTrackingLimits { max_assignments: 3, ..Default::default() })?;
        c.advance(order(0), &boxes())?;
        let (confirmed, _) = c.advance(order(1), &boxes())?;
        assert_eq!(confirmed.output.tracks[0].status, TrackStatus::Confirmed);
        let accounting = (c.frames, c.assignments, c.work, c.epoch);
        assert_eq!(retire_on_skip(&mut c)?, 1);
        assert_eq!(retire_on_skip(&mut c)?, 0);
        assert_eq!((c.frames, c.assignments, c.work, c.epoch), accounting);
        let (fresh, reset) = c.advance(order(4), &boxes())?;
        assert_eq!(reset, Some(RtpTrackReset::DisplayGap));
        assert_eq!(c.epoch, 1);
        assert_eq!(fresh.output.tracks[0].hits, 1);
        assert_eq!(fresh.output.tracks[0].status, TrackStatus::Tentative);
        assert!(matches!(c.advance(order(5), &boxes()), Err(RtpTrackingError::Limit)));
        assert_eq!(c.assignments, 3);
        Ok(())
    }
    #[test]
    fn executed_empty_frames_are_misses_but_unexecuted_frames_are_not() -> Test {
        let mut c = core(RtpTrackingLimits::default())?;
        c.advance(order(0), &boxes())?;
        let (missed, _) = c.advance(order(1), &[])?;
        assert_eq!(missed.output.tracks[0].status, TrackStatus::Lost);
        assert!(missed.assignments.is_empty());
        assert_eq!(c.frames, 2);
        assert_eq!(retire_on_skip(&mut c)?, 1);
        assert_eq!(c.frames, 2);
        assert_eq!(c.active, 0);
        Ok(())
    }
    #[test]
    fn skipping_preserves_source_gap_and_does_not_refill_selected_frame_limit() -> Test {
        let mut c = core(RtpTrackingLimits { max_frames: 2, ..Default::default() })?;
        c.advance(order(0), &boxes())?;
        c.gap = true;
        retire_on_skip(&mut c)?;
        let (_, reset) = c.advance(order(3), &boxes())?;
        assert_eq!(reset, Some(RtpTrackReset::SourceGap));
        retire_on_skip(&mut c)?;
        assert!(matches!(c.advance(order(5), &[]), Err(RtpTrackingError::Limit)));
        assert_eq!(c.frames, 2);
        Ok(())
    }
}
