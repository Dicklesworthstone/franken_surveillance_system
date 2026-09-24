#![forbid(unsafe_code)]
//! Model-free single-camera candidates from a retained recording.
//!
//! One composition, no trained model: retained decode (JPEG/MJPEG through the canonical JPEG
//! codec, or H.264 through [`super::recorded_decode::h264`]) → [`super::foreground`] running
//! background model → [`super::tracker`] constant-velocity Kalman tracker → [`super::eventgen`]
//! zone gate. Each confirmed track entering an owner-drawn zone yields one candidate.
//!
//! Analysis is read-only and deterministic: equal retained source and [`WatchPlan`] give
//! byte-identical reports, candidate identities and proposal digests. Publication follows the
//! existing recorded-event authority model: a candidate becomes an event only when the operator
//! presents its exact proposal digest. It then retains a complete provenance graph root-last and
//! calls the deployment's guarded event publisher with a `Hold` decision. The event is
//! `Unclassified` and `Indeterminate`, abstains, carries non-supporting derived evidence from one
//! failure domain (never corroborated), and authorizes no alert or other effect. An already
//! published candidate is reported, never republished.
//!
//! Synthetic scenes prove the wiring, not detection quality: foreground thresholds and zones are
//! uncalibrated operator choices, and a missing candidate never certifies absence.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use fss_codec_mjpeg::{DecodeBudget, decode_luma};
use fss_core::abstraction::runtime_authority::RuntimeGrant;
use fss_core::event::EventDecodeError;
use fss_core::{
    CanonicalEncoder, CaptureInterval, ContentDigest, ContractError, DecisionPath, EventEvidence,
    EventHypothesis, EventId, EventKind, EventState, EvidenceClass, EvidenceEdgeRelation, ObjectId,
    ProbabilityInterval, SensorCapsule,
};
use fss_object::{ObjectError, ObjectManifest, SpoolError};
use fss_publication::{LocalPublicationError, SlotName};

use super::eventgen::{
    ZoneEventConfig, ZoneEventError, ZoneEventGenerator, ZoneObservation, ZoneSpec,
};
use super::foreground::{ForegroundConfig, ForegroundDetector, ForegroundError};
use super::recorded_decode::h264::{DecoderLimits, RecordedH264Range, RecordedH264Request};
use super::recorded_decode::{
    ComponentInterpretation, DecodeLimits, RecordedDecodeError, source_capsule, validate_limits,
};
use super::tracker::{
    Detection, MultiObjectTracker, TrackStatus, TrackerConfig, TrackerError, TrackerLimits,
    TrackerStepError,
};
use super::{FileIngestError, RetainedFileImport, RetainedReadLimits};
use crate::{
    ReferenceDeployment, ReferenceError, ReferencePolicyAction, ReferencePolicyDecision, ReplayCx,
};

/// Maximum decoded frames in one watch run.
pub const MAX_WATCH_FRAMES: usize = 128;
/// Maximum owner-drawn zones.
pub const MAX_WATCH_ZONES: usize = 16;
/// Maximum candidates in one report; more is a typed refusal, never a silent drop.
pub const MAX_WATCH_CANDIDATES: usize = 32;
/// Boundary after provenance retention, before event authority.
pub const STAGE_RECORDED_WATCH_COMMIT: &str = "recorded_watch:commit";

const POLICY: &[u8] = b"fss.recorded_watch_policy.v1:model-free:foreground-running-variance:\
kalman-global-iou:zone-entry:uncalibrated:unclassified:indeterminate:hold:single-sensor";
const PLAN_DOMAIN: &str = "fss.recorded_watch_plan.v1";
const ANALYSIS_DOMAIN: &str = "fss.recorded_watch_analysis.v1";
const OBSERVATION_DOMAIN: &str = "fss.recorded_watch_observation.v1";
const CANDIDATE_DOMAIN: &str = "fss.recorded_watch_candidate.v1";
const PROVENANCE_DOMAIN: &str = "fss.recorded_watch_provenance.v1";
const PROPOSAL_DOMAIN: &str = "fss.recorded_watch_proposal.v1";
// Kalman noise is fixed policy (bound into the plan digest through POLICY), not a tuning knob.
const PROCESS_NOISE: f64 = 1.0;
const MEASUREMENT_NOISE: f64 = 1.0;
const UNCERTAINTY: &str = "Model-free foreground track entering an operator-drawn image zone; \
uncalibrated thresholds, one sensor, never corroborated; capture bounds are evidence windows.";
const ABSTENTION: &str = "Retain and investigate. No presence, identity, intent, absence, \
corroboration or alert decision is authorized by a model-free single-camera candidate.";

/// Typed refusal of planning, analysis, or publication.
#[derive(Debug)]
pub enum WatchError {
    /// The plan is outside its bounds or contains an invalid zone/threshold.
    InvalidPlan(&'static str),
    /// A retained source gap lies inside the requested range.
    SourceGap {
        /// First segment whose predecessor bytes are missing.
        segment: usize,
    },
    /// Frame dimensions changed inside the range.
    DimensionChange {
        /// First segment with different dimensions.
        segment: usize,
    },
    /// A hard frame, candidate, detection or track bound was reached.
    Limit,
    /// An approval digest matches no candidate proposal in this exact analysis.
    StaleApproval(ContentDigest),
    /// An event with this candidate identity exists with different content.
    Conflict,
    /// Retained source or decode refusal.
    Decode(Box<RecordedDecodeError>),
    /// Foreground detector refusal.
    Foreground(ForegroundError),
    /// Tracker configuration refusal.
    TrackerConfig(TrackerError),
    /// Tracker step refusal.
    Tracker(TrackerStepError),
    /// Zone event generator refusal.
    Zone(ZoneEventError),
    /// Shared canonical validation failed.
    Contract(ContractError),
    /// Event schema refusal.
    Event(Box<EventDecodeError>),
    /// Guarded deployment publication failed.
    Reference(Box<ReferenceError>),
    /// Object graph construction failed.
    Object(ObjectError),
    /// Root-last publication failed.
    Publication(Box<LocalPublicationError>),
    /// Retained custody could not be read or verified.
    Spool(SpoolError),
}

impl WatchError {
    /// Registered stable identity (registries/ERRORS.md) of this refusal.
    #[must_use]
    pub fn stable_id(&self) -> &'static str {
        match self {
            Self::InvalidPlan(_) => "ERR-WATCH-PLAN-INVALID-001",
            Self::SourceGap { .. } => "ERR-WATCH-SOURCE-GAP-001",
            Self::Limit | Self::Tracker(TrackerStepError::Limit) => "ERR-WATCH-LIMIT-001",
            Self::StaleApproval(_) => "ERR-WATCH-APPROVAL-STALE-001",
            Self::Conflict => "ERR-IDEMPOTENCY-CONFLICT-001",
            Self::Decode(error) => error.stable_id(),
            _ => "ERR-WATCH-001",
        }
    }
}

impl fmt::Display for WatchError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidPlan(why) => write!(f, "invalid watch plan: {why}"),
            Self::SourceGap { segment } => {
                write!(
                    f,
                    "watch range crosses a source gap before segment {segment}"
                )
            }
            Self::DimensionChange { segment } => {
                write!(f, "frame dimensions change at segment {segment}")
            }
            Self::Limit => f.write_str("watch bound exceeded"),
            Self::StaleApproval(digest) => {
                write!(
                    f,
                    "approval {digest} matches no proposal of this exact analysis"
                )
            }
            Self::Conflict => {
                f.write_str("a different event already holds this candidate identity")
            }
            Self::Decode(e) => write!(f, "watch decode: {e}"),
            Self::Foreground(e) => write!(f, "watch foreground: {e}"),
            Self::TrackerConfig(e) => write!(f, "watch tracker: {e}"),
            Self::Tracker(e) => write!(f, "watch tracker: {e}"),
            Self::Zone(e) => write!(f, "watch zone gate: {e}"),
            Self::Contract(e) => write!(f, "watch contract: {e}"),
            Self::Event(e) => write!(f, "watch event: {e}"),
            Self::Reference(e) => write!(f, "watch deployment: {e}"),
            Self::Object(e) => write!(f, "watch manifest: {e}"),
            Self::Publication(e) => write!(f, "watch publication: {e}"),
            Self::Spool(e) => write!(f, "watch custody: {e}"),
        }
    }
}
impl std::error::Error for WatchError {}

macro_rules! conversion {
    ($source:ty, $variant:ident) => {
        impl From<$source> for WatchError {
            fn from(error: $source) -> Self {
                Self::$variant(error.into())
            }
        }
    };
}
conversion!(RecordedDecodeError, Decode);
conversion!(ForegroundError, Foreground);
conversion!(TrackerError, TrackerConfig);
conversion!(TrackerStepError, Tracker);
conversion!(ZoneEventError, Zone);
conversion!(ContractError, Contract);
conversion!(EventDecodeError, Event);
conversion!(ReferenceError, Reference);
conversion!(ObjectError, Object);
conversion!(LocalPublicationError, Publication);
conversion!(SpoolError, Spool);
impl From<FileIngestError> for WatchError {
    fn from(error: FileIngestError) -> Self {
        Self::Decode(Box::new(error.into()))
    }
}
type Result<T> = std::result::Result<T, WatchError>;

fn checkpoint(cx: &ReplayCx, stage: &'static str) -> Result<()> {
    cx.checkpoint(stage)
        .map_err(|_| RecordedDecodeError::Cancelled.into())
}
fn hex(digest: ContentDigest) -> String {
    digest.bytes().iter().map(|b| format!("{b:02x}")).collect()
}

/// An operator-drawn axis-aligned image zone in decoded pixel coordinates.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WatchZone {
    /// Stable zone identifier: 1..=64 ASCII alphanumerics, `-` or `_`.
    pub zone_id: String,
    /// Left edge.
    pub x: u32,
    /// Top edge.
    pub y: u32,
    /// Positive width.
    pub width: u32,
    /// Positive height.
    pub height: u32,
}

/// Foreground (running mean/variance background) thresholds; see [`ForegroundConfig`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WatchDetectorConfig {
    /// Minimum absolute luma deviation before the variance term.
    pub base_threshold: u16,
    /// Multiplier on the per-pixel standard deviation.
    pub threshold_sigma: u16,
    /// Background learning-rate numerator.
    pub learning_rate_num: u16,
    /// Background learning-rate denominator.
    pub learning_rate_den: u16,
    /// Minimum connected foreground pixels for a detection box.
    pub minimum_region_pixels: usize,
}
impl Default for WatchDetectorConfig {
    fn default() -> Self {
        Self {
            base_threshold: 25,
            threshold_sigma: 3,
            learning_rate_num: 1,
            learning_rate_den: 32,
            minimum_region_pixels: 16,
        }
    }
}

/// Kalman/IoU tracker lifecycle policy; see [`TrackerConfig`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WatchTrackerConfig {
    /// Consecutive hits before a track is confirmed.
    pub confirmation_hits: u32,
    /// Consecutive misses before a track is deleted.
    pub maximum_missed_frames: u32,
    /// Minimum predicted-box IoU for association, in parts per million.
    pub minimum_iou_ppm: u32,
}
impl Default for WatchTrackerConfig {
    fn default() -> Self {
        Self {
            confirmation_hits: 3,
            maximum_missed_frames: 2,
            minimum_iou_ppm: 100_000,
        }
    }
}

/// Complete analysis identity. Resource ceilings are separate ([`WatchLimits`]): they can refuse
/// work but never change a successful result.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WatchPlan {
    /// Exact completed import.
    pub import_identity: ContentDigest,
    /// Explicit component interpretation (H.264 requires `YCbCr`).
    pub interpretation: ComponentInterpretation,
    /// First decoded segment; for H.264 it must be an IDR access unit.
    pub first_segment: usize,
    /// Contiguous segments, 1..=[`MAX_WATCH_FRAMES`].
    pub segment_count: usize,
    /// Owner-drawn zones in evaluation order, 1..=[`MAX_WATCH_ZONES`].
    pub zones: Vec<WatchZone>,
    /// Foreground thresholds.
    pub detector: WatchDetectorConfig,
    /// Tracker lifecycle policy.
    pub tracker: WatchTrackerConfig,
}

impl WatchPlan {
    /// Validates bounds, zone identifiers and thresholds before any source is read.
    pub fn validate(&self) -> Result<()> {
        if self.segment_count == 0 || self.segment_count > MAX_WATCH_FRAMES {
            return Err(WatchError::InvalidPlan("segment count must be 1..128"));
        }
        if self.first_segment.checked_add(self.segment_count).is_none() {
            return Err(WatchError::InvalidPlan("segment range overflows"));
        }
        if self.zones.is_empty() || self.zones.len() > MAX_WATCH_ZONES {
            return Err(WatchError::InvalidPlan(
                "one through sixteen zones are required",
            ));
        }
        let mut seen = BTreeSet::new();
        for zone in &self.zones {
            let id = zone.zone_id.as_bytes();
            if id.is_empty()
                || id.len() > 64
                || !id
                    .iter()
                    .all(|b| b.is_ascii_alphanumeric() || *b == b'-' || *b == b'_')
            {
                return Err(WatchError::InvalidPlan(
                    "zone id must be 1..64 of [A-Za-z0-9_-]",
                ));
            }
            if !seen.insert(zone.zone_id.as_str()) {
                return Err(WatchError::InvalidPlan("duplicate zone id"));
            }
            if zone.width == 0
                || zone.height == 0
                || zone.x.checked_add(zone.width).is_none()
                || zone.y.checked_add(zone.height).is_none()
            {
                return Err(WatchError::InvalidPlan(
                    "zone must have positive finite extent",
                ));
            }
        }
        if self.tracker.minimum_iou_ppm > 1_000_000 {
            return Err(WatchError::InvalidPlan(
                "minimum IoU must be at most 1000000 ppm",
            ));
        }
        self.tracker_config().validate()?;
        // Dimensions are only known after decode; validate thresholds on a placeholder size.
        self.foreground_config([1, 1]).validate()?;
        Ok(())
    }

    fn foreground_config(&self, dimensions: [u32; 2]) -> ForegroundConfig {
        ForegroundConfig {
            base_threshold: self.detector.base_threshold,
            threshold_sigma: self.detector.threshold_sigma,
            learning_rate_num: self.detector.learning_rate_num,
            learning_rate_den: self.detector.learning_rate_den,
            minimum_region_pixels: self.detector.minimum_region_pixels,
            dimensions,
        }
    }

    fn tracker_config(&self) -> TrackerConfig {
        TrackerConfig {
            min_hits: self.tracker.confirmation_hits,
            max_misses: self.tracker.maximum_missed_frames,
            iou_threshold: f64::from(self.tracker.minimum_iou_ppm) / 1_000_000.0,
            process_noise: PROCESS_NOISE,
            measurement_noise: MEASUREMENT_NOISE,
        }
    }

    /// Canonical plan identity, including the fixed pipeline policy.
    #[must_use]
    pub fn digest(&self) -> ContentDigest {
        let mut e = CanonicalEncoder::new();
        e.text(PLAN_DOMAIN);
        e.digest(ContentDigest::sha256(POLICY));
        e.digest(self.import_identity);
        e.u8(match self.interpretation {
            ComponentInterpretation::Grayscale => 0,
            ComponentInterpretation::YCbCr => 1,
        });
        e.u64(self.first_segment as u64);
        e.u64(self.segment_count as u64);
        e.u64(self.zones.len() as u64);
        for zone in &self.zones {
            e.text(&zone.zone_id);
            for value in [zone.x, zone.y, zone.width, zone.height] {
                e.u32(value);
            }
        }
        for value in [
            self.detector.base_threshold,
            self.detector.threshold_sigma,
            self.detector.learning_rate_num,
            self.detector.learning_rate_den,
        ] {
            e.u32(u32::from(value));
        }
        e.u64(self.detector.minimum_region_pixels as u64);
        e.u32(self.tracker.confirmation_hits);
        e.u32(self.tracker.maximum_missed_frames);
        e.u32(self.tracker.minimum_iou_ppm);
        ContentDigest::sha256(&e.finish())
    }
}

/// Resource ceilings; they refuse work but never alter a successful analysis.
#[derive(Clone, Copy, Debug)]
pub struct WatchLimits {
    /// Custody-read ceilings for every retained segment.
    pub read_limits: RetainedReadLimits,
    /// JPEG codec ceilings.
    pub jpeg_limits: DecodeLimits,
    /// JPEG codec work units across the whole run.
    pub jpeg_work_units: u64,
    /// H.264 codec ceilings (`max_pictures` is narrowed to the range).
    pub h264_limits: DecoderLimits,
}
impl Default for WatchLimits {
    fn default() -> Self {
        Self {
            read_limits: RetainedReadLimits::default(),
            jpeg_limits: DecodeLimits::default(),
            jpeg_work_units: 100_000_000,
            h264_limits: DecoderLimits::default(),
        }
    }
}

/// One decoded frame's retained identities; pixels are not kept after analysis.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WatchFrame {
    /// Zero-based retained segment.
    pub segment: usize,
    /// Retained source-capsule payload digest.
    pub capsule_digest: ContentDigest,
    /// Conservative capture interval of the source capsule.
    pub capture: CaptureInterval,
    /// SHA-256 of the decoded luma plane.
    pub luma_digest: ContentDigest,
    /// Foreground boxes `(x, y, width, height)` in pixels, in detector order.
    pub boxes: Vec<[u32; 4]>,
}

/// One frame in which a candidate's track was actually matched (not a coasting prediction).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WatchObservation {
    /// Zero-based retained segment.
    pub segment: usize,
    /// Retained source-capsule payload digest.
    pub capsule_digest: ContentDigest,
    /// SHA-256 of the decoded luma plane.
    pub luma_digest: ContentDigest,
    /// Filtered track box `(center x, center y, width, height)`, rounded to pixels.
    pub track_box: [i64; 4],
    /// Digest of the canonical observation record retained as event evidence.
    pub record_digest: ContentDigest,
    record: Vec<u8>,
    capture: CaptureInterval,
}

/// Publication state of one candidate in this deployment.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WatchStatus {
    /// Proposal prepared; no event authority exists yet.
    Prepared,
    /// This exact event revision is already authoritative; it is never republished.
    AlreadyPublished,
    /// Published by this call.
    Published,
}
impl WatchStatus {
    /// Stable spelling.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Prepared => "prepared",
            Self::AlreadyPublished => "already_published",
            Self::Published => "published",
        }
    }
}

#[derive(Clone, Debug)]
struct Provenance {
    slot: SlotName,
    manifest: ObjectManifest,
    objects: BTreeMap<ContentDigest, Vec<u8>>,
    event: EventHypothesis,
}

/// A confirmed track entering a zone, with its complete prepared event proposal.
#[derive(Clone, Debug)]
pub struct WatchCandidate {
    /// Zone entered.
    pub zone_id: String,
    /// Tracker-local identifier; not a physical identity.
    pub track_id: u64,
    /// Segment at which the confirmed track centre was first inside the zone.
    pub entry_segment: usize,
    /// Frames in which the track was matched, in order.
    pub observations: Vec<WatchObservation>,
    identity: ContentDigest,
    proof: Provenance,
    proposal: ContentDigest,
    status: WatchStatus,
}
impl WatchCandidate {
    /// Deterministic candidate identity (import, plan, zone, track, entry frame).
    #[must_use]
    pub fn identity(&self) -> ContentDigest {
        self.identity
    }
    /// Exact approval identity: event revision digest plus provenance root.
    #[must_use]
    pub fn proposal_digest(&self) -> ContentDigest {
        self.proposal
    }
    /// Event that publication would record.
    #[must_use]
    pub fn event(&self) -> &EventHypothesis {
        &self.proof.event
    }
    /// Provenance graph root retained before event authority.
    #[must_use]
    pub fn provenance_root(&self) -> ContentDigest {
        self.proof.manifest.root()
    }
    /// Current publication state.
    #[must_use]
    pub fn status(&self) -> WatchStatus {
        self.status
    }
    /// First and last matched segments of the track.
    #[must_use]
    pub fn frame_range(&self) -> [usize; 2] {
        let first = self
            .observations
            .first()
            .map_or(self.entry_segment, |o| o.segment);
        let last = self
            .observations
            .last()
            .map_or(self.entry_segment, |o| o.segment);
        [first, last]
    }
}

/// Complete deterministic analysis of one plan against retained source.
#[derive(Clone, Debug)]
pub struct WatchReport {
    plan: WatchPlan,
    plan_digest: ContentDigest,
    import_root: ContentDigest,
    media_format: String,
    dimensions: [u32; 2],
    frames: Vec<WatchFrame>,
    confirmed_tracks: usize,
    candidates: Vec<WatchCandidate>,
    analysis: Vec<u8>,
    decode_work_units: u64,
}

enum FrameSource {
    Jpeg {
        retained: Box<RetainedFileImport>,
        next: usize,
        end: usize,
    },
    H264(Box<RecordedH264Range>),
}

struct DecodedFrame {
    segment: usize,
    capsule: SensorCapsule,
    capsule_digest: ContentDigest,
    dimensions: [u32; 2],
    pixels: Vec<u8>,
}

#[derive(Default)]
struct TrackHistory {
    observations: Vec<(usize, [i64; 4])>,
}

fn rounded(value: f64) -> i64 {
    // Finite by tracker admission (try_step refuses non-finite state); bounded by image size.
    value.round() as i64
}

impl WatchReport {
    /// Decode, detect, track and gate the plan's range. Reads retained custody only; writes no
    /// objects, ledger batches or events. Candidate publication state is read from the ledger.
    pub fn analyze(
        deployment: &ReferenceDeployment,
        plan: &WatchPlan,
        limits: &WatchLimits,
        cx: &ReplayCx,
    ) -> Result<Self> {
        checkpoint(cx, "recorded_watch:analyze")?;
        plan.validate()?;
        validate_limits(limits.jpeg_limits)?;
        let retained =
            RetainedFileImport::open(deployment, plan.import_identity, limits.read_limits, cx)?;
        let spans = &retained.manifest().segment_spans;
        let end = plan.first_segment + plan.segment_count;
        if end > spans.len() {
            return Err(RecordedDecodeError::Unavailable.into());
        }
        if let Some(span) = spans[plan.first_segment + 1..end]
            .iter()
            .find(|s| s.gap_before)
        {
            return Err(WatchError::SourceGap {
                segment: span.segment_index,
            });
        }
        let media_format = retained.manifest().format.clone();
        let import_root = retained.import_root();
        let mut source = match media_format.as_str() {
            "mjpeg" => FrameSource::Jpeg {
                retained: Box::new(retained),
                next: plan.first_segment,
                end,
            },
            "annexb" => FrameSource::H264(Box::new(RecordedH264Range::open(
                deployment,
                RecordedH264Request {
                    import_identity: plan.import_identity,
                    first_segment: plan.first_segment,
                    segment_count: plan.segment_count,
                    interpretation: plan.interpretation,
                    read_limits: limits.read_limits,
                    decoder_limits: limits.h264_limits,
                },
                cx,
            )?)),
            _ => return Err(RecordedDecodeError::UnsupportedMedia.into()),
        };
        let plan_digest = plan.digest();
        let source_generation = format!("import:{}", hex(plan.import_identity));
        let mut budget = DecodeBudget::new(limits.jpeg_work_units);
        let mut generator = ZoneEventGenerator::new(ZoneEventConfig {
            policy_generation: ContentDigest::sha256(POLICY),
            // One candidate per (zone, track) per run: the cooldown never elapses.
            dedup_cooldown_ns: i64::MAX,
            min_probability: 0.0,
            max_dedup_entries: super::eventgen::MAX_EVENT_TRACKS,
        })?;
        for zone in &plan.zones {
            generator.register_zone(ZoneSpec {
                zone_id: zone.zone_id.clone(),
                bounds: (
                    f64::from(zone.x),
                    f64::from(zone.y),
                    f64::from(zone.width),
                    f64::from(zone.height),
                ),
                kind: EventKind::Unclassified,
            })?;
        }
        let mut background: Option<ForegroundDetector> = None;
        let mut dimensions = [0, 0];
        let mut tracker = MultiObjectTracker::new(plan.tracker_config())?;
        let mut frames = Vec::with_capacity(plan.segment_count);
        let mut histories: BTreeMap<u64, TrackHistory> = BTreeMap::new();
        let mut confirmed = BTreeSet::new();
        let mut entries: Vec<(String, u64, usize)> = Vec::new();
        let mut sensor = None;
        while let Some(frame) = source.next(deployment, plan, limits, &mut budget, cx)? {
            checkpoint(cx, "recorded_watch:frame")?;
            if background.is_none() {
                dimensions = frame.dimensions;
                background = Some(ForegroundDetector::new(plan.foreground_config(dimensions))?);
            } else if frame.dimensions != dimensions {
                return Err(WatchError::DimensionChange {
                    segment: frame.segment,
                });
            }
            let detector = background.as_mut().ok_or(WatchError::Limit)?;
            let foreground = detector.observe(&frame.pixels, dimensions[0], dimensions[1])?;
            let luma_digest = ContentDigest::sha256(&frame.pixels);
            let detections: Vec<Detection> = foreground
                .boxes
                .iter()
                .map(|b| Detection {
                    box_x: f64::from(b.x),
                    box_y: f64::from(b.y),
                    box_w: f64::from(b.width),
                    box_h: f64::from(b.height),
                })
                .collect();
            let output = tracker.try_step(&detections, TrackerLimits::default())?;
            if sensor.is_none() {
                sensor = Some(frame.capsule.sensor_id.clone());
            }
            let failure_domain = format!(
                "recorded-sensor:{}",
                hex(ContentDigest::sha256(
                    frame.capsule.sensor_id.as_str().as_bytes()
                ))
            );
            for target in &output.tracks {
                if target.misses != 0 {
                    continue;
                }
                let history = histories.entry(target.id).or_default();
                history.observations.push((
                    frame.segment,
                    [
                        rounded(target.cx),
                        rounded(target.cy),
                        rounded(target.box_w),
                        rounded(target.box_h),
                    ],
                ));
                if target.status != TrackStatus::Confirmed {
                    continue;
                }
                confirmed.insert(target.id);
                for zone in &plan.zones {
                    let emitted = generator.observe_interval(
                        RuntimeGrant::ObserveEvent,
                        ZoneObservation {
                            source_generation: &source_generation,
                            target,
                            zone_id: &zone.zone_id,
                            failure_domain: &failure_domain,
                            capture: frame.capsule.capture,
                            frame_digest: luma_digest,
                            upper_probability: 1.0,
                        },
                    )?;
                    if emitted.is_some() {
                        if entries.len() == MAX_WATCH_CANDIDATES {
                            return Err(WatchError::Limit);
                        }
                        entries.push((zone.zone_id.clone(), target.id, frame.segment));
                    }
                }
            }
            frames.push(WatchFrame {
                segment: frame.segment,
                capsule_digest: frame.capsule_digest,
                capture: frame.capsule.capture,
                luma_digest,
                boxes: foreground
                    .boxes
                    .iter()
                    .map(|b| [b.x, b.y, b.width, b.height])
                    .collect(),
            });
        }
        let decode_work_units = budget.used();
        let by_segment: BTreeMap<usize, &WatchFrame> =
            frames.iter().map(|f| (f.segment, f)).collect();
        let mut candidates = Vec::with_capacity(entries.len());
        for (zone_id, track_id, entry_segment) in entries {
            let mut observations = Vec::new();
            for (segment, track_box) in histories
                .get(&track_id)
                .map(|h| h.observations.as_slice())
                .unwrap_or_default()
            {
                let frame = by_segment.get(segment).ok_or(WatchError::Limit)?;
                let mut e = CanonicalEncoder::new();
                e.text(OBSERVATION_DOMAIN);
                e.digest(plan.import_identity);
                e.digest(plan_digest);
                e.u64(*segment as u64);
                e.digest(frame.capsule_digest);
                e.digest(frame.luma_digest);
                e.u64(track_id);
                for value in track_box {
                    e.i128(i128::from(*value));
                }
                let record = e.finish();
                observations.push(WatchObservation {
                    segment: *segment,
                    capsule_digest: frame.capsule_digest,
                    luma_digest: frame.luma_digest,
                    track_box: *track_box,
                    record_digest: ContentDigest::sha256(&record),
                    record,
                    capture: frame.capture,
                });
            }
            let mut e = CanonicalEncoder::new();
            e.text(CANDIDATE_DOMAIN);
            e.digest(plan.import_identity);
            e.digest(plan_digest);
            e.text(&zone_id);
            e.u64(track_id);
            e.u64(entry_segment as u64);
            let identity = ContentDigest::sha256(&e.finish());
            candidates.push(PendingCandidate {
                zone_id,
                track_id,
                entry_segment,
                observations,
                identity,
            });
        }
        let analysis = analysis_bytes(plan_digest, import_root, &frames, &candidates);
        let sensor = sensor.ok_or(WatchError::Limit)?;
        let mut prepared = Vec::with_capacity(candidates.len());
        for pending in candidates {
            checkpoint(cx, "recorded_watch:prepare")?;
            let proof = provenance(&pending, &analysis, import_root, sensor.as_str())?;
            let PendingCandidate {
                zone_id,
                track_id,
                entry_segment,
                observations,
                identity,
            } = pending;
            let mut e = CanonicalEncoder::new();
            e.text(PROPOSAL_DOMAIN);
            e.digest(proof.event.revision_digest());
            e.digest(proof.manifest.root());
            let proposal = ContentDigest::sha256(&e.finish());
            let status = current_status(deployment, &proof.event)?;
            prepared.push(WatchCandidate {
                zone_id,
                track_id,
                entry_segment,
                observations,
                identity,
                proof,
                proposal,
                status,
            });
        }
        Ok(Self {
            plan: plan.clone(),
            plan_digest,
            import_root,
            media_format,
            dimensions,
            frames,
            confirmed_tracks: confirmed.len(),
            candidates: prepared,
            analysis,
            decode_work_units,
        })
    }

    /// Plan identity.
    #[must_use]
    pub fn plan_digest(&self) -> ContentDigest {
        self.plan_digest
    }
    /// Digest of the canonical analysis record retained with every published candidate.
    #[must_use]
    pub fn analysis_digest(&self) -> ContentDigest {
        ContentDigest::sha256(&self.analysis)
    }
    /// Decoded frames in order.
    #[must_use]
    pub fn frames(&self) -> &[WatchFrame] {
        &self.frames
    }
    /// Candidates in deterministic (frame, track, zone) order.
    #[must_use]
    pub fn candidates(&self) -> &[WatchCandidate] {
        &self.candidates
    }
    /// Retained media format (`mjpeg` or `annexb`).
    #[must_use]
    pub fn media_format(&self) -> &str {
        &self.media_format
    }

    /// Publishes exactly the approved proposals. Every approval must name a proposal of this
    /// analysis, checked before any write. Already-published candidates are left untouched.
    /// A failure after provenance retention leaves the root; a rerun resumes to the event.
    pub fn publish(
        &mut self,
        deployment: &mut ReferenceDeployment,
        approvals: &BTreeSet<ContentDigest>,
        cx: &ReplayCx,
    ) -> Result<usize> {
        checkpoint(cx, "recorded_watch:revalidate")?;
        for approval in approvals {
            if !self.candidates.iter().any(|c| c.proposal == *approval) {
                return Err(WatchError::StaleApproval(*approval));
            }
        }
        let mut published = 0;
        for candidate in &mut self.candidates {
            if !approvals.contains(&candidate.proposal) {
                continue;
            }
            // Re-read authority immediately before writing: never overwrite, never duplicate.
            candidate.status = current_status(deployment, &candidate.proof.event)?;
            if candidate.status == WatchStatus::AlreadyPublished {
                continue;
            }
            let proof = &candidate.proof;
            let existing = deployment
                .publisher()
                .root(&proof.slot)
                .map(|root| root.root);
            if existing.is_some_and(|root| root != proof.manifest.root()) {
                return Err(WatchError::Conflict);
            }
            for bytes in proof.objects.values() {
                checkpoint(cx, "recorded_watch:stage")?;
                let digest = deployment.publisher_mut().stage_object(bytes)?;
                deployment.publisher_mut().verify_object(digest)?;
            }
            for digest in proof.manifest.children() {
                checkpoint(cx, "recorded_watch:closure")?;
                deployment.publisher_mut().verify_object(*digest)?;
            }
            if existing.is_none() {
                deployment
                    .publisher_mut()
                    .stage_manifest(&proof.slot, &proof.manifest)?;
            }
            deployment.publish_and_commit(
                &proof.slot,
                &proof.manifest,
                proof.event.interval,
                cx,
            )?;
            checkpoint(cx, STAGE_RECORDED_WATCH_COMMIT)?;
            deployment.publish_event(
                &ReferencePolicyDecision {
                    event: proof.event.clone(),
                    action: ReferencePolicyAction::Hold,
                },
                cx,
            )?;
            cx.checkpoint_post_commit("recorded_watch:published");
            candidate.status = WatchStatus::Published;
            published += 1;
        }
        Ok(published)
    }

    /// Bounded deterministic JSON rendering. `approve_hint` (for example the exact rerun command
    /// prefix) is echoed for prepared candidates; it grants nothing.
    #[must_use]
    pub fn to_json(&self, authority_sequence: u64, approve_hint: Option<&str>) -> String {
        let zones: Vec<String> = self
            .plan
            .zones
            .iter()
            .map(|z| {
                format!(
                    "{{\"zone_id\":\"{}\",\"x\":{},\"y\":{},\"width\":{},\"height\":{}}}",
                    z.zone_id, z.x, z.y, z.width, z.height
                )
            })
            .collect();
        let candidates: Vec<String> = self
            .candidates
            .iter()
            .map(|c| {
                let evidence: Vec<String> = c
                    .observations
                    .iter()
                    .map(|o| {
                        format!(
                            "{{\"segment\":{},\"capsule_digest\":\"{}\",\"luma_digest\":\"{}\",\"observation_digest\":\"{}\",\"track_box_cxcywh\":[{},{},{},{}]}}",
                            o.segment,
                            o.capsule_digest,
                            o.luma_digest,
                            o.record_digest,
                            o.track_box[0],
                            o.track_box[1],
                            o.track_box[2],
                            o.track_box[3]
                        )
                    })
                    .collect();
                let [first, last] = c.frame_range();
                let command = match (c.status, approve_hint) {
                    (WatchStatus::Prepared, Some(hint)) => {
                        json_string(&format!("{hint} --approve {}", c.proposal))
                    }
                    _ => "null".to_owned(),
                };
                format!(
                    "{{\"candidate_id\":\"{}\",\"zone_id\":\"{}\",\"track_id\":{},\"entry_segment\":{},\"frame_range\":[{first},{last}],\"event_id\":\"{}\",\"event_kind\":\"{}\",\"event_state\":\"{}\",\"proposal_digest\":\"{}\",\"provenance_root\":\"{}\",\"status\":\"{}\",\"publish_command\":{command},\"evidence\":[{}]}}",
                    c.identity,
                    c.zone_id,
                    c.track_id,
                    c.entry_segment,
                    c.proof.event.event_id,
                    c.proof.event.kind.as_str(),
                    c.proof.event.state.as_str(),
                    c.proposal,
                    c.proof.manifest.root(),
                    c.status.as_str(),
                    evidence.join(",")
                )
            })
            .collect();
        let count = |status| {
            self.candidates
                .iter()
                .filter(|c| c.status == status)
                .count()
        };
        let boxes: usize = self.frames.iter().map(|f| f.boxes.len()).sum();
        format!(
            concat!(
                "{{\"format\":\"fss.recorded_watch_report.v1\",\"import_identity\":\"{}\",",
                "\"import_root\":\"{}\",\"media_format\":\"{}\",\"plan_digest\":\"{}\",",
                "\"analysis_digest\":\"{}\",\"policy_digest\":\"{}\",\"first_segment\":{},",
                "\"segment_count\":{},\"frames_decoded\":{},\"width\":{},\"height\":{},",
                "\"zones\":[{}],\"foreground_boxes\":{},\"confirmed_tracks\":{},",
                "\"jpeg_decode_work_units\":{},\"candidate_count\":{},\"candidates\":[{}],",
                "\"prepared_count\":{},\"published_count\":{},\"already_published_count\":{},",
                "\"authority_sequence\":{},\"event_kind\":\"unclassified\",",
                "\"event_state\":\"indeterminate\",\"calibrated\":false,\"corroborated\":false,",
                "\"alert_authorized\":false,\"effects_authorized\":false,",
                "\"absence_certifiable\":false,\"detection_quality_claim\":false}}"
            ),
            self.plan.import_identity,
            self.import_root,
            self.media_format,
            self.plan_digest,
            self.analysis_digest(),
            ContentDigest::sha256(POLICY),
            self.plan.first_segment,
            self.plan.segment_count,
            self.frames.len(),
            self.dimensions[0],
            self.dimensions[1],
            zones.join(","),
            boxes,
            self.confirmed_tracks,
            self.decode_work_units,
            self.candidates.len(),
            candidates.join(","),
            count(WatchStatus::Prepared),
            count(WatchStatus::Published),
            count(WatchStatus::AlreadyPublished),
            authority_sequence,
        )
    }
}

fn json_string(value: &str) -> String {
    let mut out = String::with_capacity(value.len() + 2);
    out.push('"');
    for ch in value.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            c if u32::from(c) < 0x20 => out.push_str(&format!("\\u{:04x}", u32::from(c))),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

impl FrameSource {
    fn next(
        &mut self,
        deployment: &ReferenceDeployment,
        plan: &WatchPlan,
        limits: &WatchLimits,
        budget: &mut DecodeBudget<'_>,
        cx: &ReplayCx,
    ) -> Result<Option<DecodedFrame>> {
        match self {
            Self::Jpeg {
                retained,
                next,
                end,
            } => {
                if *next >= *end {
                    return Ok(None);
                }
                let segment = *next;
                let span = &retained.manifest().segment_spans[segment];
                if span.len > limits.jpeg_limits.maximum_bytes as u64 {
                    return Err(RecordedDecodeError::Limit.into());
                }
                let (capsule, capsule_digest) = source_capsule(deployment, retained, segment)?;
                let bytes = retained.read_segment(deployment, segment, limits.read_limits, cx)?;
                let image = decode_luma(
                    &bytes,
                    capsule.source_digest.bytes(),
                    plan.interpretation,
                    limits.jpeg_limits,
                    budget,
                )
                .map_err(RecordedDecodeError::from)?;
                *next += 1;
                Ok(Some(DecodedFrame {
                    segment,
                    capsule,
                    capsule_digest,
                    dimensions: image.dimensions(),
                    pixels: image.pixels().to_vec(),
                }))
            }
            Self::H264(range) => {
                let Some(frame) = range.next_frame(deployment, cx)? else {
                    return Ok(None);
                };
                let receipt = frame.receipt();
                Ok(Some(DecodedFrame {
                    segment: usize::try_from(receipt.segment_index())
                        .map_err(|_| WatchError::Limit)?,
                    capsule: receipt.capsule().clone(),
                    capsule_digest: receipt.capsule_digest(),
                    dimensions: receipt.dimensions(),
                    pixels: frame.pixels().to_vec(),
                }))
            }
        }
    }
}

struct PendingCandidate {
    zone_id: String,
    track_id: u64,
    entry_segment: usize,
    observations: Vec<WatchObservation>,
    identity: ContentDigest,
}

fn analysis_bytes(
    plan_digest: ContentDigest,
    import_root: ContentDigest,
    frames: &[WatchFrame],
    candidates: &[PendingCandidate],
) -> Vec<u8> {
    let mut e = CanonicalEncoder::new();
    e.text(ANALYSIS_DOMAIN);
    e.digest(plan_digest);
    e.digest(import_root);
    e.u64(frames.len() as u64);
    for frame in frames {
        e.u64(frame.segment as u64);
        e.digest(frame.capsule_digest);
        e.digest(frame.luma_digest);
        e.u64(frame.boxes.len() as u64);
        for b in &frame.boxes {
            for value in b {
                e.u32(*value);
            }
        }
    }
    e.u64(candidates.len() as u64);
    for candidate in candidates {
        e.digest(candidate.identity);
        e.text(&candidate.zone_id);
        e.u64(candidate.track_id);
        e.u64(candidate.entry_segment as u64);
        e.u64(candidate.observations.len() as u64);
        for observation in &candidate.observations {
            e.digest(observation.record_digest);
        }
    }
    e.finish()
}

fn insert(objects: &mut BTreeMap<ContentDigest, Vec<u8>>, bytes: Vec<u8>) -> ContentDigest {
    let digest = ContentDigest::sha256(&bytes);
    objects.insert(digest, bytes);
    digest
}

fn provenance(
    candidate: &PendingCandidate,
    analysis: &[u8],
    import_root: ContentDigest,
    sensor: &str,
) -> Result<Provenance> {
    let observations = &candidate.observations;
    let analysis_digest = ContentDigest::sha256(analysis);
    let identity = candidate.identity;
    if observations.is_empty() {
        return Err(WatchError::Limit);
    }
    let mut objects = BTreeMap::new();
    insert(&mut objects, analysis.to_vec());
    let policy = insert(&mut objects, POLICY.to_vec());
    let sensor_digest = insert(&mut objects, sensor.as_bytes().to_vec());
    let failure_domain = format!("recorded-sensor:{}", hex(sensor_digest));
    let mut children = BTreeSet::from([import_root]);
    let mut evidence = Vec::with_capacity(observations.len());
    let mut interval: Option<CaptureInterval> = None;
    for observation in observations {
        let digest = insert(&mut objects, observation.record.clone());
        children.insert(observation.capsule_digest);
        let window = observation.capture;
        interval = Some(match interval {
            Some(old) => CaptureInterval::new(
                old.earliest.min(window.earliest),
                old.latest.max(window.latest),
            )?,
            None => window,
        });
        evidence.push(EventEvidence {
            digest,
            class: EvidenceClass::Derived,
            failure_domain: failure_domain.clone(),
            supports: false,
            relation: EvidenceEdgeRelation::DerivedFrom,
            capsule_digest: Some(observation.capsule_digest),
            identity_digest: Some(sensor_digest),
        });
    }
    let interval = interval.ok_or(WatchError::Limit)?;
    let mut e = CanonicalEncoder::new();
    e.bytes(b"FSSWTCH1");
    e.u32(1);
    e.text(PROVENANCE_DOMAIN);
    e.digest(policy);
    e.digest(identity);
    e.digest(analysis_digest);
    let metadata = insert(&mut objects, e.finish());
    children.extend(objects.keys().copied());
    children.remove(&metadata);
    let slot = SlotName::parse(&format!("rw-{}", hex(identity)))
        .map_err(|_| WatchError::InvalidPlan("candidate slot name"))?;
    let manifest = ObjectManifest::new(slot.as_str(), children, Some(metadata))?;
    evidence.sort_by_key(|e| e.digest);
    let event = EventHypothesis {
        schema: EventHypothesis::SCHEMA.to_owned(),
        event_id: EventId::parse(format!("event:watch:{}", hex(identity)))?,
        revision: 1,
        supersedes: None,
        state: EventState::Indeterminate,
        kind: EventKind::Unclassified,
        interval,
        uncertainty_reason: Some(UNCERTAINTY.to_owned()),
        zone_ids: vec![candidate.zone_id.clone()],
        track_ids: vec![format!("track:{}", candidate.track_id)],
        probability: ProbabilityInterval::new(0.0, 1.0)?,
        evidence,
        model_receipts: Vec::new(),
        decision_path: DecisionPath {
            policy_generation: policy,
            fingerprint: manifest.root(),
            abstained: true,
            abstention_reason: Some(ABSTENTION.to_owned()),
        },
    };
    event.validate()?;
    Ok(Provenance {
        slot,
        manifest,
        objects,
        event,
    })
}

fn current_status(
    deployment: &ReferenceDeployment,
    event: &EventHypothesis,
) -> Result<WatchStatus> {
    let object = ObjectId::parse(format!("object:event:{}", event.event_id.as_str()))?;
    let Some(current) = deployment.ledger().current().objects.get(&object) else {
        return Ok(WatchStatus::Prepared);
    };
    let revision = event.revision_digest();
    let exact = deployment.ledger().batches().iter().any(|batch| {
        batch.deltas.iter().any(|delta| {
            delta.object_id == object
                && delta.family == "event_revision"
                && delta.new_generation == current.generation
                && delta.payload_digest == current.payload_digest
                && delta.witness_digest == Some(revision)
        })
    });
    if exact {
        Ok(WatchStatus::AlreadyPublished)
    } else {
        Err(WatchError::Conflict)
    }
}

#[cfg(test)]
mod tests;
