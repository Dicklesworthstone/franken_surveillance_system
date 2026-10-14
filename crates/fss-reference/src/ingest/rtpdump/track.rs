#![forbid(unsafe_code)]
//! Native retained RTP -> verified detector -> source-witnessed anonymous tracks.
//!
//! One explicitly selected model class is associated in native display order. Motion is
//! measured in observed-frame steps, NOT seconds: sender RTP timestamps and the recording's
//! capture interval do not establish a trustworthy per-picture clock. Tracks are camera-local
//! hypotheses, not identities, visibility, physical absence, or effect authority. Only actual
//! assignments are exposed as observations; coasting predictions never acquire source evidence.

use super::decode::RtpDecodeEffect;
use super::detect::{
    RtpDetectedFrame, RtpDetectionError, RtpDetectionRequest, RtpDetectionStats,
    RtpDetectionStep, RtpPackageDetector,
};
use super::recovery::RecoveredRtpImport;
use super::recovery::decode::RetainedRtpEvent;
use crate::ingest::detections::BOX_SUBPIXELS;
use crate::ingest::rgb_package::RgbDetectorPackage;
use crate::ingest::tracker::{
    AssignedTrackerOutput, Detection, MAX_ASSIGNMENT_WORK, MAX_CHECKED_TRACKS,
    MultiObjectTracker, TRACK_ASSIGNMENT_POLICY, TRACKER_ALGORITHM, TrackStatus,
    TrackerConfig, TrackerLimits, TrackerStepError,
};
use crate::{ReferenceDeployment, ReplayCx, ScalarExecCx};
use fss_core::{CanonicalEncoder, ContentDigest, LedgerAnchor};

/// Numerical/time/observation semantics, separate from detector and source receipt identities.
pub const RTP_TRACKING_DOMAIN: &str = "fss.rtp_tracking.v1:sample-step:one-class:observed-only";

/// Independent lifetime tracking ceilings. A recovery never replenishes these allowances.
#[derive(Clone, Copy, Debug)]
pub struct RtpTrackingLimits {
    /// Complete per-frame association admission; no selected detections are truncated.
    pub step: TrackerLimits,
    /// Maximum complete frame updates, including frames with no selected detections (1..=1024).
    pub max_frames: usize,
    /// Maximum selected detections admitted over this owner's entire lifetime.
    pub max_assignments: u64,
    /// Cumulative conservative Hungarian work reservation, not elapsed CPU time.
    pub max_assignment_work: u64,
}
impl Default for RtpTrackingLimits {
    fn default() -> Self {
        Self {
            step: TrackerLimits::default(),
            max_frames: 1024,
            max_assignments: 131_072,
            max_assignment_work: 64 * MAX_ASSIGNMENT_WORK,
        }
    }
}

/// Explicit class, numerical policy and independent source/inference/tracking admissions.
#[derive(Clone, Debug)]
pub struct RtpTrackingRequest {
    /// Existing native detector request; owns source, privacy and numerical execution semantics.
    pub detection: RtpDetectionRequest,
    /// Exact index in the verified package vocabulary, never inferred from a label string.
    pub class_index: usize,
    /// Existing bounded reference tracker; velocities are in observed-frame steps.
    pub tracker: TrackerConfig,
    /// Lifetime tracking admission in addition to native/inference budgets.
    pub limits: RtpTrackingLimits,
}

/// No error is converted into an empty observation, successful EOF or automatic retry.
#[derive(Debug)]
pub enum RtpTrackingError {
    /// Invalid class, numerical policy or ceilings; rejected before source reads.
    InvalidRequest,
    /// A complete frame could not be admitted under a lifetime tracking bound.
    Limit,
    /// Native custody, decoder, privacy, inference or head projection refused.
    Detection(RtpDetectionError),
    /// The existing atomic numerical/association owner refused.
    Tracker(TrackerStepError),
    /// Source order or interpretation changed outside an explicit recovery boundary.
    SourceOrder,
    /// Deployment authority changed after opening this owner.
    StaleBasis,
    /// Either explicit cancellation owner refused progress or delivery.
    Cancelled,
    /// Bounded canonical encoding failed.
    Encoding,
}
impl std::fmt::Display for RtpTrackingError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("native RTP tracking refused; no complete observation delivered")
    }
}
impl std::error::Error for RtpTrackingError {}
type Result<T> = std::result::Result<T, RtpTrackingError>;

/// Why this frame starts a new anonymous association namespace.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RtpTrackReset {
    /// First observed frame, not a previous-frame association.
    Baseline,
    /// An explicit decode refusal/fence or changed decoder epoch broke continuity.
    SourceGap,
    /// The native output sequence skipped one or more observations.
    DisplayGap,
    /// Image dimensions or current retained privacy policy changed.
    ProjectionChanged,
}

/// Exact assignment from the existing global solve; no filtered-box rematching.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RtpTrackObservation {
    /// Anonymous identity bound to source root, tracking recipe, reset epoch and local ID.
    pub identity: ContentDigest,
    /// Existing numerical tracker ID, meaningful only in this frame's association epoch.
    pub local_id: u64,
    /// Index in the COMPLETE detector report, not its class-filtered subset.
    pub detection_index: usize,
    /// Tentative/Confirmed describes sample association, never physical identity confidence.
    pub status: TrackStatus,
    /// Actual assigned hits in this association epoch.
    pub hits: u32,
}

/// Complete immutable frame result; original other-class proposals remain available.
#[derive(Debug)]
pub struct RtpTrackedFrame {
    detected: RtpDetectedFrame,
    observations: Vec<RtpTrackObservation>,
    recipe: ContentDigest,
    digest: ContentDigest,
    predecessor: Option<ContentDigest>,
    epoch: u64,
    reset: Option<RtpTrackReset>,
    active_tracks: usize,
    deleted_tracks: usize,
}
impl RtpTrackedFrame {
    /// Full native receipt, inference and detector report, including nonselected classes.
    pub fn detected(&self) -> &RtpDetectedFrame { &self.detected }
    /// Only actual observations, ordered by local track ID. Lost predictions are absent.
    pub fn observations(&self) -> &[RtpTrackObservation] { &self.observations }
    /// Exact detector, class, numerical, time-unit, source-code and admission contract.
    pub fn recipe(&self) -> ContentDigest { self.recipe }
    /// History-linked result identity; not a durable custody publication.
    pub fn digest(&self) -> ContentDigest { self.digest }
    /// Previous complete result, retained even across an association reset.
    pub fn predecessor(&self) -> Option<ContentDigest> { self.predecessor }
    /// Disjoint anonymous-ID namespace; zero for the initial baseline.
    pub fn epoch(&self) -> u64 { self.epoch }
    /// Explicit break in association history, without hiding source progress events.
    pub fn reset(&self) -> Option<RtpTrackReset> { self.reset }
    /// Includes coasting tracks but exposes no unobserved location as evidence.
    pub fn active_tracks(&self) -> usize { self.active_tracks }
    /// Tracks deleted by this frame's normal lifecycle, excluding reset retirement.
    pub fn deleted_tracks(&self) -> usize { self.deleted_tracks }
}

/// Separate original detector accounting and lifetime tracking reservations.
#[derive(Clone, Copy, Debug, Default)]
pub struct RtpTrackingStats {
    /// Unchanged source, inference, privacy, receipt and detector-stage accounting.
    pub detection: RtpDetectionStats,
    /// Complete delivered tracking frames.
    pub frames: usize,
    /// Selected detections reserved, including a terminal refused tracking attempt.
    pub assignments_reserved: u64,
    /// Conservative assignment work reserved, including failed numerical updates.
    pub assignment_work_reserved: u64,
    /// Association resets after the first baseline.
    pub resets: u64,
    /// Terminal outer failures; detector failures retain their own accounting too.
    pub failures: usize,
    /// This owner has ended or refused and cannot resume with replenished allowances.
    pub ended: bool,
}
impl RtpTrackingStats {
    /// All detector results were tracked; NOT a coverage or absence certificate.
    pub fn complete(&self) -> bool {
        self.ended && self.failures == 0 && self.detection.complete()
            && self.frames == self.detection.frames
    }
}

/// Source progress remains separate from tracking evidence and terminal completeness.
#[derive(Debug)]
pub enum RtpTrackingStep {
    /// Original payload-free event and exact decoder consequence.
    Progress { event: RetainedRtpEvent, effect: RtpDecodeEffect },
    /// Full original detector result plus its actual anonymous track observations.
    Frame(RtpTrackedFrame),
    /// Repeated terminal queries return unchanged accounting, not a restart.
    Ended(RtpTrackingStats),
}

#[derive(Clone, Copy)]
struct FrameOrder {
    index: usize,
    decoder_epoch: usize,
    dimensions: [u32; 2],
    policy: Option<ContentDigest>,
}
struct TrackCore {
    config: TrackerConfig,
    limits: RtpTrackingLimits,
    tracker: MultiObjectTracker,
    last: Option<FrameOrder>,
    active: usize,
    epoch: u64,
    frames: usize,
    assignments: u64,
    work: u64,
    gap: bool,
}
impl TrackCore {
    fn new(config: TrackerConfig, limits: RtpTrackingLimits) -> Result<Self> {
        if !(1..=1024).contains(&limits.max_frames)
            || !(1..=MAX_CHECKED_TRACKS).contains(&limits.step.max_tracks)
            || !(1..=MAX_CHECKED_TRACKS).contains(&limits.step.max_detections)
            || limits.step.max_assignment_work > MAX_ASSIGNMENT_WORK
        { return Err(RtpTrackingError::InvalidRequest); }
        let tracker = MultiObjectTracker::new(config.clone())
            .map_err(|_| RtpTrackingError::InvalidRequest)?;
        Ok(Self { config, limits, tracker, last: None, active: 0, epoch: 0,
            frames: 0, assignments: 0, work: 0, gap: false })
    }
    fn advance(&mut self, order: FrameOrder, detections: &[Detection])
        -> Result<(AssignedTrackerOutput, Option<RtpTrackReset>)>
    {
        if self.frames >= self.limits.max_frames
            || detections.len() > self.limits.step.max_detections
        { return Err(RtpTrackingError::Limit); }
        let reset = match self.last {
            None => Some(RtpTrackReset::Baseline),
            Some(last) => {
                if order.index <= last.index || order.decoder_epoch < last.decoder_epoch {
                    return Err(RtpTrackingError::SourceOrder);
                }
                if self.gap || order.decoder_epoch != last.decoder_epoch {
                    Some(RtpTrackReset::SourceGap)
                } else if last.index.checked_add(1) != Some(order.index) {
                    Some(RtpTrackReset::DisplayGap)
                } else if order.dimensions != last.dimensions || order.policy != last.policy {
                    Some(RtpTrackReset::ProjectionChanged)
                } else { None }
            }
        };
        let rows = if reset.is_some() { 0 } else { self.active as u64 };
        let work = if detections.is_empty() { 0 }
            else { rows * rows * (rows + detections.len() as u64) };
        let reserved = self.work.checked_add(work).ok_or(RtpTrackingError::Limit)?;
        let assignments = self.assignments.checked_add(detections.len() as u64)
            .ok_or(RtpTrackingError::Limit)?;
        if work > self.limits.step.max_assignment_work
            || reserved > self.limits.max_assignment_work
            || assignments > self.limits.max_assignments
        { return Err(RtpTrackingError::Limit); }
        self.work = reserved;
        self.assignments = assignments;
        let mut candidate = if reset.is_some() {
            MultiObjectTracker::new(self.config.clone()).map_err(|_| RtpTrackingError::InvalidRequest)?
        } else { self.tracker.clone() };
        let output = candidate.try_step_assigned(detections, self.limits.step)
            .map_err(RtpTrackingError::Tracker)?;
        if reset.is_some() && self.last.is_some() { self.epoch += 1; }
        self.tracker = candidate;
        self.active = output.output.tracks.len();
        self.frames += 1;
        self.last = Some(order);
        self.gap = false;
        Ok((output, reset))
    }
}

/// Owns native decode/inference/association together; no caller-assembled pixels or reports.
pub struct RtpPackageTracker<'a> {
    detector: Option<RtpPackageDetector<'a>>,
    core: TrackCore,
    class_index: usize,
    recipe: ContentDigest,
    basis: LedgerAnchor,
    previous: Option<ContentDigest>,
    stats: RtpTrackingStats,
}
impl<'a> RtpPackageTracker<'a> {
    /// Validate all tracking admission before opening the current-custody detector.
    pub fn new(retained: &'a RecoveredRtpImport, package: &'a RgbDetectorPackage,
        request: RtpTrackingRequest, deployment: &ReferenceDeployment,
        cx: &ReplayCx, scalar: &ScalarExecCx) -> Result<Self>
    {
        if request.class_index >= package.spec().labels.len() {
            return Err(RtpTrackingError::InvalidRequest);
        }
        let core = TrackCore::new(request.tracker, request.limits)?;
        let detector = RtpPackageDetector::new(retained, package, request.detection,
            deployment, cx, scalar).map_err(RtpTrackingError::Detection)?;
        let mut e = CanonicalEncoder::new();
        e.text(RTP_TRACKING_DOMAIN);
        e.text(TRACKER_ALGORITHM);
        e.text(TRACK_ASSIGNMENT_POLICY);
        e.digest(ContentDigest::sha256(include_bytes!("track.rs")));
        e.digest(ContentDigest::sha256(include_bytes!("../tracker.rs")));
        e.digest(ContentDigest::sha256(include_bytes!("../tracker/assignment.rs")));
        e.digest(ContentDigest::sha256(include_bytes!("../tracker/checked.rs")));
        e.digest(ContentDigest::sha256(include_bytes!("../tracker/observation.rs")));
        e.digest(detector.recipe());
        e.u64(request.class_index as u64);
        e.u32(core.config.min_hits);
        e.u32(core.config.max_misses);
        for n in [core.config.iou_threshold, core.config.process_noise, core.config.measurement_noise] {
            e.u64(n.to_bits());
        }
        for n in [request.limits.step.max_tracks as u64, request.limits.step.max_detections as u64,
            request.limits.step.max_assignment_work, request.limits.max_frames as u64,
            request.limits.max_assignments, request.limits.max_assignment_work] { e.u64(n); }
        let recipe = digest(e)?;
        let stats = RtpTrackingStats { detection: detector.stats(), ..Default::default() };
        Ok(Self { detector: Some(detector), core, class_index: request.class_index,
            recipe, basis: deployment.current_anchor().clone(), previous: None, stats })
    }
    /// Exact tracking interpretation and complete owner-selected admissions.
    pub fn recipe(&self) -> ContentDigest { self.recipe }
    /// Independent lifetime accounting; resets do not zero counters.
    pub fn stats(&self) -> RtpTrackingStats { self.stats }
    /// A refusal is terminal, drops queued numerical results and exposes no partial frame.
    pub fn step(&mut self, deployment: &ReferenceDeployment, cx: &ReplayCx,
        scalar: &ScalarExecCx) -> Result<RtpTrackingStep>
    {
        if self.detector.is_none() { return Ok(RtpTrackingStep::Ended(self.stats)); }
        let result = self.advance(deployment, cx, scalar);
        self.stats.assignments_reserved = self.core.assignments;
        self.stats.assignment_work_reserved = self.core.work;
        self.stats.resets = self.core.epoch;
        if result.is_err() {
            self.detector = None;
            self.stats.failures += 1;
            self.stats.ended = true;
        }
        result
    }
    fn advance(&mut self, deployment: &ReferenceDeployment, cx: &ReplayCx,
        scalar: &ScalarExecCx) -> Result<RtpTrackingStep>
    {
        checkpoint(cx, scalar, "rtp_track:step")?;
        if deployment.current_anchor() != &self.basis { return Err(RtpTrackingError::StaleBasis); }
        let detector = self.detector.as_mut().ok_or(RtpTrackingError::Encoding)?;
        let result = detector.step(deployment, cx, scalar);
        self.stats.detection = detector.stats();
        match result.map_err(RtpTrackingError::Detection)? {
            RtpDetectionStep::Progress { event, effect } => {
                if matches!(&effect, RtpDecodeEffect::Refused { .. }
                    | RtpDecodeEffect::WaitingForIdr { .. } | RtpDecodeEffect::Fenced)
                { self.core.gap = true; }
                Ok(RtpTrackingStep::Progress { event, effect })
            }
            RtpDetectionStep::Ended(_) => {
                self.detector = None;
                self.stats.ended = true;
                Ok(RtpTrackingStep::Ended(self.stats))
            }
            RtpDetectionStep::Frame(detected) => {
                let all = detected.detections().detections();
                let indices: Vec<_> = all.iter().enumerate()
                    .filter_map(|(i, d)| (d.class_index() == self.class_index).then_some(i)).collect();
                if indices.len() > self.core.limits.step.max_detections { return Err(RtpTrackingError::Limit); }
                let selected: Vec<_> = indices.iter().map(|&i| {
                    let [x1, y1, x2, y2] = all[i].bounds();
                    let unit = f64::from(BOX_SUBPIXELS);
                    Detection { box_x: f64::from(x1) / unit, box_y: f64::from(y1) / unit,
                        box_w: (f64::from(x2) - f64::from(x1)) / unit,
                        box_h: (f64::from(y2) - f64::from(y1)) / unit }
                }).collect();
                let source = detected.source();
                let order = FrameOrder { index: source.output_index, decoder_epoch: source.decoder_epoch,
                    dimensions: source.dimensions, policy: source.policy };
                let (assigned, reset) = self.core.advance(order, &selected)?;
                let mut observations = Vec::with_capacity(assigned.assignments.len());
                // Track output may be swap-removed; sort once and merge by stable identity.
                let mut tracks: Vec<_> = assigned.output.tracks.iter().collect();
                tracks.sort_unstable_by_key(|track| track.id);
                let mut position = 0;
                for assignment in &assigned.assignments {
                    while position < tracks.len() && tracks[position].id < assignment.track_id { position += 1; }
                    let track = tracks.get(position).filter(|t| t.id == assignment.track_id)
                        .ok_or(RtpTrackingError::Encoding)?;
                    let detection_index = *indices.get(assignment.detection_index).ok_or(RtpTrackingError::Encoding)?;
                    let mut e = CanonicalEncoder::new();
                    e.text("fss.rtp_track_identity.v1");
                    e.digest(self.recipe);
                    e.digest(source.root);
                    e.u64(self.core.epoch);
                    e.u64(track.id);
                    observations.push(RtpTrackObservation { identity: digest(e)?, local_id: track.id,
                        detection_index, status: track.status, hits: track.hits });
                }
                let mut e = CanonicalEncoder::new();
                e.text("fss.rtp_tracked_frame.v1");
                e.digest(self.recipe);
                e.digest(detected.digest());
                e.bool(self.previous.is_some());
                if let Some(previous) = self.previous { e.digest(previous); }
                e.u64(self.core.epoch);
                e.u8(match reset { None => 0, Some(RtpTrackReset::Baseline) => 1,
                    Some(RtpTrackReset::SourceGap) => 2, Some(RtpTrackReset::DisplayGap) => 3,
                    Some(RtpTrackReset::ProjectionChanged) => 4 });
                e.u64(assigned.output.tracks.len() as u64);
                e.u64(assigned.output.deleted_tracks as u64);
                e.u64(self.core.work);
                e.u64(self.core.assignments);
                e.u64(observations.len() as u64);
                for o in &observations {
                    e.digest(o.identity);
                    e.u64(o.local_id);
                    e.u64(o.detection_index as u64);
                    e.u8(match o.status { TrackStatus::Tentative => 0, TrackStatus::Confirmed => 1,
                        TrackStatus::Lost => return Err(RtpTrackingError::Encoding) });
                    e.u32(o.hits);
                }
                let digest = digest(e)?;
                checkpoint(cx, scalar, "rtp_track:deliver")?;
                if deployment.current_anchor() != &self.basis { return Err(RtpTrackingError::StaleBasis); }
                let frame = RtpTrackedFrame { detected, observations, recipe: self.recipe, digest,
                    predecessor: self.previous, epoch: self.core.epoch, reset,
                    active_tracks: assigned.output.tracks.len(), deleted_tracks: assigned.output.deleted_tracks };
                self.previous = Some(digest);
                self.stats.frames += 1;
                Ok(RtpTrackingStep::Frame(frame))
            }
        }
    }
}
fn digest(e: CanonicalEncoder) -> Result<ContentDigest> {
    Ok(ContentDigest::sha256(&e.finish_checked().map_err(|_| RtpTrackingError::Encoding)?))
}
fn checkpoint(cx: &ReplayCx, scalar: &ScalarExecCx, stage: &'static str) -> Result<()> {
    if cx.checkpoint(stage).is_err() || scalar.checkpoint(stage).is_err() {
        cx.drain_and_finalize();
        scalar.request_cancellation();
        scalar.drain_and_finalize();
        return Err(RtpTrackingError::Cancelled);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    type TestResult = std::result::Result<(), Box<dyn std::error::Error>>;
    fn config() -> TrackerConfig {
        TrackerConfig { min_hits: 2, max_misses: 2, iou_threshold: 0.1,
            process_noise: 1.0, measurement_noise: 1.0 }
    }
    fn order(index: usize) -> FrameOrder {
        FrameOrder { index, decoder_epoch: 0, dimensions: [640, 480], policy: None }
    }
    fn detection(x: f64) -> Detection {
        Detection { box_x: x, box_y: 0.0, box_w: 20.0, box_h: 20.0 }
    }
    #[test]
    fn assignment_and_confirmation_come_from_the_existing_solver() -> TestResult {
        let mut core = TrackCore::new(config(), RtpTrackingLimits::default())?;
        let (first, reset) = core.advance(order(0), &[detection(100.0), detection(0.0)])?;
        assert_eq!(reset, Some(RtpTrackReset::Baseline));
        assert_eq!(first.observed_detection(1), Some(1));
        let (second, reset) = core.advance(order(1), &[detection(0.0), detection(100.0)])?;
        assert_eq!(reset, None);
        assert_eq!(second.observed_detection(1), Some(0));
        assert!(second.output.tracks.iter().all(|t| t.status == TrackStatus::Confirmed));
        Ok(())
    }
    #[test]
    fn lost_predictions_are_not_observations() -> TestResult {
        let mut cfg = config(); cfg.min_hits = 1;
        let mut core = TrackCore::new(cfg, RtpTrackingLimits::default())?;
        core.advance(order(0), &[detection(0.0)])?;
        let (lost, _) = core.advance(order(1), &[])?;
        assert_eq!(lost.output.tracks.len(), 1);
        assert_eq!(lost.output.tracks[0].status, TrackStatus::Lost);
        assert!(lost.assignments.is_empty());
        Ok(())
    }
    #[test]
    fn recovery_retires_old_identity_and_does_not_refill_lifetime_admission() -> TestResult {
        let limits = RtpTrackingLimits { max_assignments: 2, ..Default::default() };
        let mut core = TrackCore::new(config(), limits)?;
        core.advance(order(0), &[detection(0.0)])?;
        core.gap = true;
        let mut next = order(1); next.decoder_epoch = 1;
        let (recovered, reset) = core.advance(next, &[detection(0.0)])?;
        assert_eq!(reset, Some(RtpTrackReset::SourceGap));
        assert_eq!(core.epoch, 1);
        assert_eq!(recovered.output.tracks[0].hits, 1);
        assert_eq!(recovered.output.tracks[0].status, TrackStatus::Tentative);
        next.index = 2; next.decoder_epoch = 2;
        assert!(matches!(core.advance(next, &[detection(0.0)]), Err(RtpTrackingError::Limit)));
        assert_eq!(core.epoch, 1);
        assert_eq!(core.assignments, 2);
        Ok(())
    }
    #[test]
    fn display_and_projection_breaks_are_explicit() -> TestResult {
        let mut core = TrackCore::new(config(), RtpTrackingLimits::default())?;
        core.advance(order(0), &[])?;
        assert_eq!(core.advance(order(2), &[])?.1, Some(RtpTrackReset::DisplayGap));
        let mut changed = order(3); changed.dimensions = [320, 240];
        assert_eq!(core.advance(changed, &[])?.1, Some(RtpTrackReset::ProjectionChanged));
        changed.index = 4; changed.policy = Some(ContentDigest::sha256(b"mask"));
        assert_eq!(core.advance(changed, &[])?.1, Some(RtpTrackReset::ProjectionChanged));
        assert_eq!(core.epoch, 3);
        Ok(())
    }
    #[test]
    fn reversed_source_order_is_not_an_implicit_new_session() -> TestResult {
        let mut core = TrackCore::new(config(), RtpTrackingLimits::default())?;
        let mut start = order(1); start.decoder_epoch = 2;
        core.advance(start, &[detection(0.0)])?;
        assert!(matches!(core.advance(start, &[]), Err(RtpTrackingError::SourceOrder)));
        assert!(matches!(core.advance(order(2), &[]), Err(RtpTrackingError::SourceOrder)));
        assert_eq!(core.frames, 1);
        assert_eq!(core.assignments, 1);
        Ok(())
    }
    #[test]
    fn cumulative_work_is_not_a_per_frame_allowance() -> TestResult {
        let limits = RtpTrackingLimits { max_assignment_work: 2, ..Default::default() };
        let mut core = TrackCore::new(config(), limits)?;
        core.advance(order(0), &[detection(0.0)])?;
        core.advance(order(1), &[detection(0.0)])?;
        assert_eq!(core.work, 2);
        assert!(matches!(core.advance(order(2), &[detection(0.0)]), Err(RtpTrackingError::Limit)));
        assert_eq!(core.frames, 2);
        core.gap = true;
        core.advance(order(2), &[detection(0.0)])?;
        assert_eq!(core.work, 2);
        assert!(matches!(core.advance(order(3), &[detection(0.0)]), Err(RtpTrackingError::Limit)));
        Ok(())
    }
    #[test]
    fn empty_frames_still_consume_lifetime_frame_budget() -> TestResult {
        let limits = RtpTrackingLimits { max_frames: 1, ..Default::default() };
        let mut core = TrackCore::new(config(), limits)?;
        core.advance(order(0), &[])?; core.gap = true;
        assert!(matches!(core.advance(order(1), &[]), Err(RtpTrackingError::Limit)));
        Ok(())
    }
    #[test]
    fn invalid_geometry_and_capacity_never_commit_partial_tracks() -> TestResult {
        let limits = RtpTrackingLimits { step: TrackerLimits { max_tracks: 1,
            ..Default::default() }, ..Default::default() };
        let mut core = TrackCore::new(config(), limits)?;
        assert!(matches!(core.advance(order(0), &[detection(0.0), detection(100.0)]),
            Err(RtpTrackingError::Tracker(TrackerStepError::Limit))));
        assert_eq!(core.frames, 0);
        assert_eq!(core.active, 0);
        assert_eq!(core.assignments, 2);
        assert!(matches!(core.advance(order(0), &[detection(f64::NAN)]),
            Err(RtpTrackingError::Tracker(TrackerStepError::Detection))));
        assert_eq!(core.frames, 0);
        Ok(())
    }
    #[test]
    fn invalid_limits_are_refused_before_creating_a_source_owner() {
        for limits in [RtpTrackingLimits { max_frames: 0, ..Default::default() },
            RtpTrackingLimits { step: TrackerLimits { max_tracks: MAX_CHECKED_TRACKS + 1,
                ..Default::default() }, ..Default::default() }] {
            assert!(matches!(TrackCore::new(config(), limits), Err(RtpTrackingError::InvalidRequest)));
        }
    }
}
