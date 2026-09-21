#![forbid(unsafe_code)]
//! Always-on luma health and acknowledgement-driven semantic-analysis admission.
//!
//! A quiet frame is not observed absence. Health findings are suspected failure modes,
//! not a diagnosis of tampering. Source custody and capture-clock admission remain external.
//! No model, effect, background update, thread, device or wall clock is owned here.

use fss_core::{CanonicalEncoder, ContentDigest};
use fss_geometry::{GeometryError, WorkBudget};
use crate::foreground::{ForegroundError, ForegroundFrame, ForegroundReport, ForegroundSource,
    MAX_FOREGROUND_PIXELS};

/// All thresholds are explicit deployment policy, not calibrated detection claims.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ScreeningPolicy {
    /// Minimum number of permitted samples before image health is assessable.
    pub minimum_visible_pixels: usize,
    /// Dark and saturated thresholds, inclusive, with dark strictly below bright.
    pub dark_luma: u8,
    /// Inclusive saturated-luma threshold.
    pub bright_luma: u8,
    /// Fraction in either extreme needed to flag exposure loss, in 1..=1000.
    pub extreme_per_mille: u16,
    /// Maximum permitted-image luma range classified as low texture, in 0..=254.
    pub flat_range: u8,
    /// Minimum identical consecutive visible images for a freeze suspicion, at least two.
    pub repeat_frames: u32,
    /// Minimum receive-clock duration of that identical-image run, nonzero.
    pub repeat_duration_ns: u64,
    /// Maximum allowed silence between complete inputs, nonzero.
    pub stall_after_ns: u64,
    /// Maximum admitted capture-interval width before temporal evidence is degraded.
    pub maximum_capture_uncertainty_ns: u64,
    /// Consecutive clean frames required to leave recovery, at least one.
    pub recovery_frames: u32,
    /// Minimum interval between completed ordinary foreground analyses; may be zero.
    pub minimum_analysis_interval_ns: u64,
    /// Hard periodic analysis interval even when the foreground stage sees nothing.
    pub sentinel_interval_ns: u64,
    /// Continue ordinary analysis this long after the last changed pixel.
    pub activity_hold_ns: u64,
}
impl ScreeningPolicy {
    /// Validate policy before any frame is accepted.
    pub fn validate(self) -> Result<(), ScreeningError> {
        if self.minimum_visible_pixels == 0 || self.minimum_visible_pixels > MAX_FOREGROUND_PIXELS
            || self.dark_luma >= self.bright_luma || self.flat_range == 255
            || !(1..=1000).contains(&self.extreme_per_mille) || self.repeat_frames < 2
            || self.repeat_duration_ns == 0 || self.stall_after_ns == 0
            || self.recovery_frames == 0 || self.sentinel_interval_ns == 0
            || self.minimum_analysis_interval_ns > self.sentinel_interval_ns {
            return Err(ScreeningError::InvalidPolicy);
        }
        Ok(())
    }
    /// Local reference-policy identity, not a registered durable format or activation grant.
    pub fn digest(self) -> [u8; 32] {
        let mut e = CanonicalEncoder::new();
        e.text("fss.screening_policy.reference.v1");
        for value in [self.minimum_visible_pixels as u64, u64::from(self.dark_luma),
            u64::from(self.bright_luma), u64::from(self.extreme_per_mille),
            u64::from(self.flat_range), u64::from(self.repeat_frames), self.repeat_duration_ns,
            self.stall_after_ns, self.maximum_capture_uncertainty_ns, u64::from(self.recovery_frames),
            self.minimum_analysis_interval_ns, self.sentinel_interval_ns, self.activity_hold_ns] {
            e.u64(value);
        }
        ContentDigest::sha256(&e.finish()).bytes()
    }
}

/// Stable diagnostic bits. None of these establishes physical cause or scene absence.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum HealthFlag {
    /// Too few permitted pixels for this policy; fully masked is included.
    InsufficientVisible = 0,
    /// Most permitted pixels are dark.
    Dark = 1,
    /// Most permitted pixels are saturated.
    Saturated = 2,
    /// The permitted image has very little luma range; obstruction/defocus is unresolved.
    LowTexture = 3,
    /// Exact repeated permitted pixels persisted across advancing input records.
    SuspectedFreeze = 4,
    /// Input sequence numbers demonstrate an omitted interval.
    SequenceGap = 5,
    /// Complete frames were absent for at least the configured watchdog interval.
    ReceiveGap = 6,
    /// The previous exposure identity was reused; this is not new scene evidence.
    ReusedExposure = 7,
    /// Capture intervals overlap or fail to advance, so temporal continuity is uncertain.
    CaptureUncertain = 8,
    /// Capture uncertainty exceeds the declared operating envelope.
    WideCaptureInterval = 9,
    /// The visible mask changed; repeat history is reset and new coverage is not assumed.
    MaskChanged = 10,
    /// A foreground result was unavailable; no negative inference is allowed.
    ForegroundUnavailable = 11,
    /// Some permitted pixels have no admitted background comparison.
    BackgroundIncomplete = 12,
}
/// Bounded, deterministic diagnostic set.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct HealthFlags(u32);
impl HealthFlags {
    /// Whether a particular diagnostic is present.
    pub fn contains(self, flag: HealthFlag) -> bool { self.0 & (1 << flag as u8) != 0 }
    /// Exact stable diagnostic bits for local reports.
    pub fn bits(self) -> u32 { self.0 }
    fn insert(&mut self, flag: HealthFlag) { self.0 |= 1 << flag as u8; }
}
/// Conservative health state; even NoFaultObserved is not a coverage witness.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum ScreeningHealth {
    /// Insufficient permitted samples to assess the image.
    NotObservable = 0,
    /// One or more image, time, source or candidate-stage concerns remain.
    Degraded = 1,
    /// Clean observations have not yet met the recovery window.
    Recovering = 2,
    /// This narrow screen currently observes no configured fault.
    NoFaultObserved = 3,
}
/// Reasons to run downstream semantic analysis. These do not authorize an external effect.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum AnalysisReason {
    /// No downstream result has completed in this monitor generation.
    Initial = 0,
    /// The hard sentinel interval elapsed since a completed analysis.
    Sentinel = 1,
    /// Actual changed pixels exist, including size-filtered components.
    Foreground = 2,
    /// A recent changed-pixel interval keeps analysis active.
    ActivityHold = 3,
    /// Health state or diagnostics changed, including recovery.
    HealthChanged = 4,
    /// The owner requests analysis, for example to continue an active track.
    OwnerRequested = 5,
}
/// Bounded reason set; an empty set means an explicit skip, never a negative finding.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct AnalysisReasons(u32);
impl AnalysisReasons {
    /// Whether this reason contributed to admission.
    pub fn contains(self, reason: AnalysisReason) -> bool { self.0 & (1 << reason as u8) != 0 }
    /// Exact local reason bits.
    pub fn bits(self) -> u32 { self.0 }
    fn insert(&mut self, reason: AnalysisReason) { self.0 |= 1 << reason as u8; }
}
/// Owner-supplied receive ordering; frame sequence is never converted to capture time.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ScreeningStamp {
    /// Nonzero stream generation fixed for the lifetime of the monitor.
    pub stream_generation: u64,
    /// Strictly increasing original frame sequence, starting at any positive value.
    pub sequence: u64,
    /// Nondecreasing receive time on one owner-admitted monotonic clock.
    pub received_at_ns: u64,
    /// Explicit local analysis floor, e.g. an active track that must not be sampled out.
    pub owner_requests_analysis: bool,
}
/// Failure never returns a partial screen or advances temporal/analysis state.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ScreeningError {
    /// Invalid explicit deployment thresholds.
    InvalidPolicy,
    /// Source mode, stream generation or supplied foreground report does not match.
    BasisMismatch,
    /// Sequence/receive time regressed or a sequence was reused.
    OutOfOrder,
    /// Completion does not name the currently pending analysis (or its exact last retry).
    StaleCompletion,
    /// Pixel, source or permission validation failed.
    Frame(ForegroundError),
    /// Owner cancellation or deterministic work bound interrupted evaluation.
    Work(GeometryError),
    /// Bounded allocation failed.
    Allocation,
}
impl From<ForegroundError> for ScreeningError { fn from(e: ForegroundError) -> Self { Self::Frame(e) } }
impl From<GeometryError> for ScreeningError { fn from(e: GeometryError) -> Self { Self::Work(e) } }
impl std::fmt::Display for ScreeningError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::InvalidPolicy => "invalid screening policy", Self::BasisMismatch => "screening basis mismatch",
            Self::OutOfOrder => "screening clock or sequence did not advance",
            Self::StaleCompletion => "screening analysis completion is stale",
            Self::Frame(_) => "invalid screening frame", Self::Work(_) => "screening work interrupted",
            Self::Allocation => "screening allocation failed",
        })
    }
}
impl std::error::Error for ScreeningError {}

/// Immutable derived screen. Source identity is not device authentication or retained custody.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ScreeningReport {
    source: ForegroundSource,
    stamp: ScreeningStamp,
    policy: [u8; 32],
    foreground: Option<[u8; 32]>,
    mask: [u8; 32],
    previous: Option<[u8; 32]>,
    visible: usize,
    dark: usize,
    saturated: usize,
    luma_range: Option<[u8; 2]>,
    identical_run: u32,
    repeat_since_ns: u64,
    clean_run: u32,
    last_activity_ns: Option<u64>,
    last_completed: Option<(u64, [u8; 32], [u8; 32])>,
    flags: HealthFlags,
    health: ScreeningHealth,
    reasons: AnalysisReasons,
    digest: [u8; 32],
}
impl ScreeningReport {
    /// Exact local derivation root, also the acknowledgement token when analysis is due.
    pub fn digest(&self) -> [u8; 32] { self.digest }
    /// Original evidence and capture interval.
    pub fn source(&self) -> ForegroundSource { self.source }
    /// Original stream generation, sequence and receive clock.
    pub fn stamp(&self) -> ScreeningStamp { self.stamp }
    /// Explicit image/source/time concerns.
    pub fn flags(&self) -> HealthFlags { self.flags }
    /// Conservative health state, not physical coverage or a negative observation.
    pub fn health(&self) -> ScreeningHealth { self.health }
    /// Reasons for downstream semantic-analysis admission.
    pub fn reasons(&self) -> AnalysisReasons { self.reasons }
    /// Whether downstream analysis is recommended and acknowledgement remains required.
    pub fn analysis_due(&self) -> bool { self.reasons.0 != 0 }
    /// Number of permitted samples actually assessed.
    pub fn visible_pixels(&self) -> usize { self.visible }
    /// Permitted samples at or below the configured dark threshold.
    pub fn dark_pixels(&self) -> usize { self.dark }
    /// Permitted samples at or above the configured bright threshold.
    pub fn saturated_pixels(&self) -> usize { self.saturated }
    /// Minimum/maximum over permitted samples only; None for a fully denied image.
    pub fn luma_range(&self) -> Option<[u8; 2]> { self.luma_range }
    /// Length of the identical-image run, saturated at u32::MAX without wrapping.
    pub fn identical_run(&self) -> u32 { self.identical_run }
    /// Optional exact foreground report; missing never means no foreground.
    pub fn foreground_digest(&self) -> Option<[u8; 32]> { self.foreground }
    /// Last acknowledged analysis: source receive time, screen root and downstream result root.
    /// The owning executor, not this screen, must vouch for result-root custody and provenance.
    pub fn last_completed_analysis(&self) -> Option<(u64, [u8; 32], [u8; 32])> { self.last_completed }
    fn computed_digest(&self) -> [u8; 32] {
        let mut e = CanonicalEncoder::new();
        e.text("fss.screening_report.reference.v1");
        for id in [self.source.image.exposure, self.source.image.pixels, self.source.image.image_domain,
            self.source.calibration, self.mask, self.policy] { e.digest(ContentDigest::sha256(&id)); }
        for id in [self.foreground, self.previous] {
            e.bool(id.is_some()); if let Some(id) = id { e.digest(ContentDigest::sha256(&id)); }
        }
        for n in [self.source.camera, self.source.clock, self.source.capture[0], self.source.capture[1],
            u64::from(self.source.image.dimensions[0]), u64::from(self.source.image.dimensions[1]),
            self.stamp.stream_generation, self.stamp.sequence, self.stamp.received_at_ns,
            self.visible as u64, self.dark as u64, self.saturated as u64, u64::from(self.identical_run),
            self.repeat_since_ns, u64::from(self.clean_run), u64::from(self.flags.0), self.health as u64, u64::from(self.reasons.0)] { e.u64(n); }
        e.bool(self.last_activity_ns.is_some());
        if let Some(t) = self.last_activity_ns { e.u64(t); }
        e.bool(self.last_completed.is_some());
        if let Some((t, screen, result)) = self.last_completed {
            e.u64(t); e.digest(ContentDigest::sha256(&screen)); e.digest(ContentDigest::sha256(&result));
        }
        e.bool(self.stamp.owner_requests_analysis);
        e.bool(self.luma_range.is_some());
        if let Some([lo, hi]) = self.luma_range { e.u8(lo); e.u8(hi); }
        ContentDigest::sha256(&e.finish()).bytes()
    }
}

/// Watchdog result even when no frame arrives. It proves only local input silence.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StallObservation {
    /// Fixed monitored stream generation.
    pub stream_generation: u64,
    /// Exact policy used for the silence threshold.
    pub policy_digest: [u8; 32],
    /// Last complete frame report, absent before the first frame.
    pub last_report: Option<[u8; 32]>,
    /// Last complete-frame receive time, or monitor start time before the first frame.
    pub since_ns: u64,
    /// Owner-supplied monotonic check time.
    pub checked_at_ns: u64,
    /// Threshold-inclusive silence condition, not proof that the physical camera failed.
    pub stalled: bool,
}

/// One stream's bounded health state and outstanding downstream-analysis recommendation.
///
/// At most one prior masked luma plane is retained. A generation/mode change requires a new
/// monitor; it cannot quietly carry health or sentinel credit across a reconnect. This is an
/// in-process reference, not durable service ownership. Restart safely requires initial analysis.
pub struct ScreeningMonitor {
    policy: ScreeningPolicy,
    generation: u64,
    started_at: u64,
    clock: u64,
    last: Option<ScreeningReport>,
    prior_visible: Vec<u8>,
    repeat_since: u64,
    clean_run: u32,
    last_activity: Option<u64>,
    last_completed: Option<(u64, [u8; 32], [u8; 32])>,
    pending: Option<(u64, [u8; 32])>,
}
impl std::fmt::Debug for ScreeningMonitor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ScreeningMonitor").field("generation", &self.generation)
            .field("has_prior_frame", &self.last.is_some()).finish_non_exhaustive()
    }
}
impl ScreeningMonitor {
    /// Start one explicitly identified generation on an admitted receive clock.
    pub fn new(policy: ScreeningPolicy, stream_generation: u64, started_at_ns: u64)
        -> Result<Self, ScreeningError> {
        policy.validate()?;
        if stream_generation == 0 { return Err(ScreeningError::BasisMismatch); }
        Ok(Self { policy, generation: stream_generation, started_at: started_at_ns,
            clock: started_at_ns, last: None, prior_visible: Vec::new(), repeat_since: started_at_ns,
            clean_run: 0, last_activity: None, last_completed: None, pending: None })
    }
    /// Last successful screen, never overwritten by a cancelled/failed evaluation.
    pub fn last_report(&self) -> Option<&ScreeningReport> { self.last.as_ref() }
    /// Next receive watchdog deadline; None only if the timestamp cannot be represented.
    pub fn watchdog_deadline_ns(&self) -> Option<u64> {
        self.last.map_or(self.started_at, |r| r.stamp.received_at_ns).checked_add(self.policy.stall_after_ns)
    }
    /// Observe local silence without inventing pixels, capture time, absence or camera liveness.
    pub fn poll(&mut self, now_ns: u64) -> Result<StallObservation, ScreeningError> {
        if now_ns < self.clock { return Err(ScreeningError::OutOfOrder); }
        let since_ns = self.last.map_or(self.started_at, |r| r.stamp.received_at_ns);
        let result = StallObservation { stream_generation: self.generation,
            policy_digest: self.policy.digest(), last_report: self.last.map(|r| r.digest),
            since_ns, checked_at_ns: now_ns, stalled: now_ns - since_ns >= self.policy.stall_after_ns };
        self.clock = now_ns;
        Ok(result)
    }
    /// Assess complete luma and an optional exact foreground result, then atomically advance.
    /// Denied pixel intensities do not enter statistics or repeat comparison. Source hashing
    /// still covers the supplied complete bytes, as it does in the existing foreground API.
    #[allow(clippy::too_many_arguments)]
    pub fn observe(&mut self, source: ForegroundSource, pixels: &[u8], allowed: &[u8],
        foreground: Option<&ForegroundReport>, stamp: ScreeningStamp, budget: &mut WorkBudget<'_>)
        -> Result<ScreeningReport, ScreeningError> {
        budget.charge(0)?;
        if stamp.stream_generation != self.generation || stamp.sequence == 0 {
            return Err(ScreeningError::BasisMismatch);
        }
        if stamp.received_at_ns < self.clock || self.last.is_some_and(|r| stamp.sequence <= r.stamp.sequence) {
            return Err(ScreeningError::OutOfOrder);
        }
        let frame = ForegroundFrame::new(source, pixels, allowed, budget)?;
        let mask = frame.mask_digest();
        if let Some(prior) = self.last
            && (prior.source.camera != source.camera || prior.source.clock != source.clock
                || prior.source.calibration != source.calibration
                || prior.source.image.image_domain != source.image.image_domain
                || prior.source.image.dimensions != source.image.dimensions) {
            return Err(ScreeningError::BasisMismatch);
        }
        if foreground.is_some_and(|r| r.source() != source || r.mask_digest() != mask) {
            return Err(ScreeningError::BasisMismatch);
        }
        budget.charge(pixels.len() as u64 * 2 + 1024)?;
        let mut visible_plane = Vec::new();
        visible_plane.try_reserve_exact(pixels.len()).map_err(|_| ScreeningError::Allocation)?;
        let mut visible = 0_usize; let mut dark = 0_usize; let mut saturated = 0_usize;
        let mut lo = 255_u8; let mut hi = 0_u8;
        for (i, permission) in allowed.iter().enumerate() {
            if i % 1024 == 0 { budget.charge(1024)?; }
            if *permission == 0 { visible_plane.push(0); continue; }
            let v = pixels[i]; visible_plane.push(v); visible += 1;
            dark += usize::from(v <= self.policy.dark_luma);
            saturated += usize::from(v >= self.policy.bright_luma);
            lo = lo.min(v); hi = hi.max(v);
        }
        let mut flags = HealthFlags::default();
        if visible < self.policy.minimum_visible_pixels { flags.insert(HealthFlag::InsufficientVisible); }
        if visible > 0 {
            if dark as u64 * 1000 >= visible as u64 * u64::from(self.policy.extreme_per_mille) {
                flags.insert(HealthFlag::Dark);
            }
            if saturated as u64 * 1000 >= visible as u64 * u64::from(self.policy.extreme_per_mille) {
                flags.insert(HealthFlag::Saturated);
            }
            if hi - lo <= self.policy.flat_range { flags.insert(HealthFlag::LowTexture); }
        }
        if source.capture[1] - source.capture[0] > self.policy.maximum_capture_uncertainty_ns {
            flags.insert(HealthFlag::WideCaptureInterval);
        }
        let mut repeat_since = stamp.received_at_ns;
        let mut identical_run = u32::from(visible > 0);
        if let Some(prior) = self.last {
            let sequence_gap = stamp.sequence - prior.stamp.sequence != 1;
            let receive_gap = stamp.received_at_ns - prior.stamp.received_at_ns >= self.policy.stall_after_ns;
            if sequence_gap { flags.insert(HealthFlag::SequenceGap); }
            if receive_gap { flags.insert(HealthFlag::ReceiveGap); }
            if source.image.exposure == prior.source.image.exposure { flags.insert(HealthFlag::ReusedExposure); }
            if source.capture[0] <= prior.source.capture[1] { flags.insert(HealthFlag::CaptureUncertain); }
            if mask != prior.mask { flags.insert(HealthFlag::MaskChanged); }
            if visible > 0 && !sequence_gap && !receive_gap && mask == prior.mask
                && self.prior_visible == visible_plane {
                identical_run = prior.identical_run.saturating_add(1);
                repeat_since = self.repeat_since;
            }
        } else if stamp.received_at_ns - self.started_at >= self.policy.stall_after_ns {
            flags.insert(HealthFlag::ReceiveGap);
        }
        if visible >= self.policy.minimum_visible_pixels && identical_run >= self.policy.repeat_frames
            && stamp.received_at_ns - repeat_since >= self.policy.repeat_duration_ns {
            flags.insert(HealthFlag::SuspectedFreeze);
        }
        match foreground {
            None => flags.insert(HealthFlag::ForegroundUnavailable),
            Some(r) if r.comparable_pixels() < visible => flags.insert(HealthFlag::BackgroundIncomplete),
            Some(_) => {},
        }
        let clean_run = if flags.0 == 0 { self.clean_run.saturating_add(1) } else { 0 };
        let health = if flags.contains(HealthFlag::InsufficientVisible) { ScreeningHealth::NotObservable }
            else if flags.0 != 0 { ScreeningHealth::Degraded }
            else if clean_run < self.policy.recovery_frames { ScreeningHealth::Recovering }
            else { ScreeningHealth::NoFaultObserved };
        let changed = foreground.is_some_and(|r| r.changed_pixels() > 0);
        let activity = if changed { Some(stamp.received_at_ns) } else { self.last_activity };
        let mut reasons = AnalysisReasons::default();
        let elapsed = self.last_completed.map(|(t, _, _)| stamp.received_at_ns - t);
        if elapsed.is_none() { reasons.insert(AnalysisReason::Initial); }
        if elapsed.is_some_and(|n| n >= self.policy.sentinel_interval_ns) { reasons.insert(AnalysisReason::Sentinel); }
        if self.last.is_none_or(|r| r.flags != flags || r.health != health) { reasons.insert(AnalysisReason::HealthChanged); }
        if stamp.owner_requests_analysis { reasons.insert(AnalysisReason::OwnerRequested); }
        if elapsed.is_none_or(|n| n >= self.policy.minimum_analysis_interval_ns) {
            if changed { reasons.insert(AnalysisReason::Foreground); }
            else if activity.is_some_and(|t| stamp.received_at_ns - t <= self.policy.activity_hold_ns) {
                reasons.insert(AnalysisReason::ActivityHold);
            }
        }
        let mut report = ScreeningReport { source, stamp, policy: self.policy.digest(),
            foreground: foreground.map(ForegroundReport::digest), mask,
            previous: self.last.map(|r| r.digest), visible, dark, saturated,
            luma_range: (visible > 0).then_some([lo, hi]), identical_run, repeat_since_ns: repeat_since,
            clean_run, last_activity_ns: activity, last_completed: self.last_completed, flags, health, reasons,
            digest: [0; 32] };
        report.digest = report.computed_digest();
        budget.charge(0)?;
        // All fallible work is finished. Selecting a frame never gives completed-analysis credit.
        self.clock = stamp.received_at_ns; self.repeat_since = repeat_since;
        self.clean_run = clean_run; self.last_activity = activity; self.prior_visible = visible_plane;
        self.pending = report.analysis_due().then_some((stamp.received_at_ns, report.digest));
        self.last = Some(report);
        Ok(report)
    }
    /// Acknowledge successful downstream analysis of the current admitted report.
    /// Exact last-completion retries are idempotent. A stale/forged token does not move the
    /// sentinel clock. Cancellation, unavailable models and failed analyses must not call this.
    /// `result_root` identifies the successful source-bound result retained by the owning
    /// executor. A nonzero hash is required but is not itself proof that analysis occurred.
    pub fn acknowledge_analysis(&mut self, report_digest: [u8; 32], result_root: [u8; 32])
        -> Result<(), ScreeningError> {
        if result_root == [0; 32] { return Err(ScreeningError::StaleCompletion); }
        if self.last_completed.is_some_and(|(_, id, result)| id == report_digest && result == result_root) {
            return Ok(());
        }
        let pending = self.pending.filter(|(_, id)| *id == report_digest)
            .ok_or(ScreeningError::StaleCompletion)?;
        self.last_completed = Some((pending.0, pending.1, result_root)); self.pending = None;
        Ok(())
    }
}


/// Health-gated foreground/JPEG trajectory continuity with source-linked receipts.
pub mod tracking;
