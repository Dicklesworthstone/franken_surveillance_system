#![forbid(unsafe_code)]
//! Model-free single-camera candidates from a retained recording.
//!
//! One composition, no trained model: retained decode (JPEG/MJPEG through the canonical JPEG
//! codec, H.264 through [`super::recorded_decode::h264`], or H.265 through
//! [`super::recorded_decode::h265`]) → [`super::foreground`] running
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
//! uncalibrated operator choices, and a missing candidate never certifies absence by itself.
//!
//! Optionally ([`WatchReport::analyze_with_detector`]) a verified detector package runs as a
//! cascade stage ([`super::detector_cascade`]) on the frames this cheap gate selected (each
//! candidate track's zone-entry, confirmation and following frames, within an explicit inference
//! budget). Its class evidence (label, uncalibrated score, package digest and generation, frame
//! and capsule digests) is retained with the candidate as supporting cognition evidence in the
//! sensor's own failure domain: the candidate stays `Unclassified`, `Indeterminate` and
//! single-sensor, and the cascade identity is bound into the candidate identity, analysis and
//! coverage pipeline generation. Without a detector every byte is unchanged.
//!
//! Every analysis also proposes a [`CoverageRecord`] (see [`super::recorded_coverage`]): one
//! `CoverageWitness` per (sensor, zone, maximal contiguous interval) the pipeline could actually
//! see, and every other frame as an explicit uncovered interval. Like a candidate, the record
//! becomes authority only through [`WatchReport::retain_coverage`] with its exact approval digest.
//!
//! With [`WatchOptions::tolerate_decode_refusals`] (opt-in; the default is unchanged) a typed
//! decode refusal or source gap inside the range no longer refuses the analysis: the refused
//! segments become `decode_refused` coverage intervals with their error id, H.264/H.265 resume at
//! the next IDR/IRAP ([`super::tolerant_decode`]), and the tracker restarts after every gap with
//! fresh track identities, so no track is bridged across it. A run without any refusal or gap
//! is byte-identical to the default analysis. A detector cascade receives those exact refusals
//! and restarts, decodes each selected epoch independently, and retains one inference allowance
//! for the whole analysis. Neither class evidence nor coverage bridges a recovery boundary.
//!
//! The sensor's current retained privacy mask ([`super::privacy_mask`]) is applied to every
//! decoded plane before foreground detection, tracking, the zone gate or the cascade sees it. A
//! policy is folded into the plan identity (so candidates, analyses and coverage of different
//! mask generations never share an identity), bound into every coverage pipeline generation,
//! named on every candidate and retained as a `required_by` evidence edge of its event; zones
//! with any masked pixel carry no witness (`privacy_masked`). Without a policy every report byte
//! is unchanged; the binding is then the explicit no-policy marker ([`WatchReport::privacy_mask`]).

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

use super::detector_cascade::{
    CascadeError, CascadeOutcome, CascadeSource, CascadeTrack, ClassEvidence, DetectorCascade,
    RecoveredCascadeSource, cascade_outcome_json, cascade_policy_json, class_evidence_json,
    select_frames,
};
use super::eventgen::{
    ZoneEventConfig, ZoneEventError, ZoneEventGenerator, ZoneObservation, ZoneSpec,
};
use super::foreground::{ForegroundConfig, ForegroundDetector, ForegroundError};
use super::privacy_mask::coverage::mask_coverage_zones;
use super::privacy_mask::{MaskBinding, current_mask, lineage_digest};
use super::recorded_coverage::{
    CoverageEntry, CoverageError, CoverageExtras, CoverageFrame, CoverageInput, CoverageRecord,
    CoverageSource, CoverageStatus, CoverageZoneInput, approval_digest, build_coverage_with,
    check_approval, coverage_status, pipeline_generation, retain_coverage,
};
use super::recorded_decode::h264::{DecoderLimits, RecordedH264Range, RecordedH264Request};
use super::recorded_decode::h265::{
    DecoderLimits as H265DecoderLimits, RecordedH265Range, RecordedH265Request,
};
use super::recorded_decode::{
    ComponentInterpretation, DecodeLimits, RecordedDecodeError, source_capsule, validate_limits,
};
use super::tolerant_decode::{
    DecodeRefusal, TolerantFrame, TolerantItem, TolerantRequest, TolerantSource,
};
use super::tracker::{
    Detection, MultiObjectTracker, TrackStatus, TrackedTarget, TrackerConfig, TrackerError,
    TrackerLimits, TrackerStepError,
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
    /// Coverage retention refusal (stale approval or storage).
    Coverage(CoverageError),
    /// Detector cascade stage refusal (configuration, decode or cancellation).
    Cascade(CascadeError),
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
            Self::Coverage(error) => error.stable_id(),
            Self::Cascade(error) => error.stable_id(),
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
            Self::Coverage(e) => write!(f, "watch coverage: {e}"),
            Self::Cascade(e) => write!(f, "watch detector cascade: {e}"),
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
conversion!(CoverageError, Coverage);
conversion!(CascadeError, Cascade);
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

/// Analysis options. The default is the strict analysis every existing caller gets.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct WatchOptions {
    /// Turn typed mid-recording decode refusals and source gaps into `decode_refused` coverage
    /// intervals (H.264/H.265 resume at the next IDR/IRAP) and restart tracking after each gap,
    /// instead of refusing the whole analysis. H.264/H.265 ranges must still open at an IDR/IRAP.
    pub tolerate_decode_refusals: bool,
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
    /// H.265 codec ceilings (`max_pictures` is narrowed to the range).
    pub h265_limits: H265DecoderLimits,
}
impl Default for WatchLimits {
    fn default() -> Self {
        Self {
            read_limits: RetainedReadLimits::default(),
            jpeg_limits: DecodeLimits::default(),
            jpeg_work_units: 100_000_000,
            h264_limits: DecoderLimits::default(),
            h265_limits: H265DecoderLimits::default(),
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
    /// Detector-cascade class evidence (empty without a detector), in selection order.
    pub class_evidence: Vec<ClassEvidence>,
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
    coverage: CoverageRecord,
    coverage_status: CoverageStatus,
    cascade: Option<WatchCascade>,
    decode_refusals: Vec<DecodeRefusal>,
    tracking_restarts: Vec<usize>,
    privacy: MaskBinding,
}

/// Detector-cascade record of one analysis.
#[derive(Clone, Debug)]
struct WatchCascade {
    digest: ContentDigest,
    policy_json: String,
    outcome: CascadeOutcome,
}

/// Decoder label of a retained media format, bound into coverage pipeline generations.
#[must_use]
pub fn media_decoder_label(media_format: &str) -> &'static str {
    match media_format {
        "mjpeg" => "mjpeg:fss-codec-mjpeg:luma",
        "annexb" => "annexb:fss-codec-h264:idr-led-range:luma",
        _ => "hevc:fss-codec-h265:irap-led-range:rasl-skipped:luma",
    }
}

/// Detector and tracker parameters bound into a coverage pipeline generation, in fixed order.
#[must_use]
pub fn pipeline_parameters(
    interpretation: ComponentInterpretation,
    detector: &WatchDetectorConfig,
    tracker: &WatchTrackerConfig,
) -> Vec<u64> {
    vec![
        match interpretation {
            ComponentInterpretation::Grayscale => 0,
            ComponentInterpretation::YCbCr => 1,
        },
        u64::from(detector.base_threshold),
        u64::from(detector.threshold_sigma),
        u64::from(detector.learning_rate_num),
        u64::from(detector.learning_rate_den),
        detector.minimum_region_pixels as u64,
        u64::from(tracker.confirmation_hits),
        u64::from(tracker.maximum_missed_frames),
        u64::from(tracker.minimum_iou_ppm),
        PROCESS_NOISE.to_bits(),
        MEASUREMENT_NOISE.to_bits(),
    ]
}

enum FrameSource {
    Jpeg {
        retained: Box<RetainedFileImport>,
        next: usize,
        end: usize,
        mask: Box<MaskBinding>,
    },
    H264(Box<RecordedH264Range>),
    H265(Box<RecordedH265Range>),
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
        Self::analyze_with_detector(deployment, plan, limits, None, cx)
    }

    /// [`Self::analyze`] plus an optional detector cascade over the frames the cheap stage
    /// selected. `None` is byte-for-byte [`Self::analyze`].
    pub fn analyze_with_detector(
        deployment: &ReferenceDeployment,
        plan: &WatchPlan,
        limits: &WatchLimits,
        detector: Option<&mut DetectorCascade<'_>>,
        cx: &ReplayCx,
    ) -> Result<Self> {
        Self::analyze_with_options(
            deployment,
            plan,
            limits,
            detector,
            WatchOptions::default(),
            cx,
        )
    }

    /// [`Self::analyze_with_detector`] under explicit [`WatchOptions`]. The default options are
    /// byte-for-byte [`Self::analyze_with_detector`]; a tolerant run that meets no refusal or gap
    /// is byte-identical to it too.
    pub fn analyze_with_options(
        deployment: &ReferenceDeployment,
        plan: &WatchPlan,
        limits: &WatchLimits,
        detector: Option<&mut DetectorCascade<'_>>,
        options: WatchOptions,
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
            .filter(|_| !options.tolerate_decode_refusals)
        {
            return Err(WatchError::SourceGap {
                segment: span.segment_index,
            });
        }
        let media_format = retained.manifest().format.clone();
        let import_root = retained.import_root();
        let capture_time_label = retained.manifest().capture_time_label.clone();
        let segment_gaps: Vec<bool> = spans.iter().map(|s| s.gap_before).collect();
        let basis = deployment.current_anchor().clone();
        // The sensor's current privacy mask, resolved once; every decode path applies it.
        let (first_capsule, _) = source_capsule(deployment, &retained, plan.first_segment)?;
        let privacy = current_mask(deployment, &first_capsule.sensor_id)
            .map_err(RecordedDecodeError::from)?;
        let mut tolerant = if options.tolerate_decode_refusals {
            Some(Box::new(TolerantSource::open(
                deployment,
                TolerantRequest {
                    import_identity: plan.import_identity,
                    interpretation: plan.interpretation,
                    first_segment: plan.first_segment,
                    end,
                    read_limits: limits.read_limits,
                    jpeg_limits: limits.jpeg_limits,
                    h264_limits: limits.h264_limits,
                    h265_limits: limits.h265_limits,
                },
                cx,
            )?))
        } else {
            None
        };
        let mut source = match media_format.as_str() {
            _ if tolerant.is_some() => None,
            "mjpeg" => Some(FrameSource::Jpeg {
                retained: Box::new(retained),
                next: plan.first_segment,
                end,
                mask: Box::new(privacy.clone()),
            }),
            "annexb" => Some(FrameSource::H264(Box::new(RecordedH264Range::open(
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
            )?))),
            "hevc" => Some(FrameSource::H265(Box::new(RecordedH265Range::open(
                deployment,
                RecordedH265Request {
                    import_identity: plan.import_identity,
                    first_segment: plan.first_segment,
                    segment_count: plan.segment_count,
                    interpretation: plan.interpretation,
                    read_limits: limits.read_limits,
                    decoder_limits: limits.h265_limits,
                },
                cx,
            )?))),
            _ => return Err(RecordedDecodeError::UnsupportedMedia.into()),
        };
        let plan_digest = masked_plan_digest(plan.digest(), &privacy);
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
        let mut confirmed_at: BTreeMap<u64, usize> = BTreeMap::new();
        let mut entries: Vec<(String, u64, usize)> = Vec::new();
        let mut sensor = None;
        // Tolerant decode only: refused runs, tracking restarts, and the offset that keeps track
        // identities of a restarted tracker distinct from every earlier one.
        let mut decode_refusals: Vec<DecodeRefusal> = Vec::new();
        let mut restarts: Vec<usize> = Vec::new();
        let mut restart_pending = false;
        let mut track_base = 0_u64;
        let mut last_track = 0_u64;
        loop {
            let frame = match (tolerant.as_mut(), source.as_mut()) {
                (Some(tolerant), _) => match tolerant.next(deployment, &mut budget, cx)? {
                    None => break,
                    Some(TolerantItem::Break(refusal)) => {
                        restart_pending = true;
                        if let Some(refusal) = refusal {
                            match decode_refusals.last_mut() {
                                Some(last)
                                    if last.last_segment + 1 == refusal.first_segment
                                        && last.error_id == refusal.error_id =>
                                {
                                    last.last_segment = refusal.last_segment;
                                }
                                _ => decode_refusals.push(refusal),
                            }
                        }
                        continue;
                    }
                    Some(TolerantItem::Frame(frame)) => {
                        let TolerantFrame {
                            segment,
                            capsule,
                            capsule_digest,
                            dimensions,
                            pixels,
                        } = *frame;
                        DecodedFrame {
                            segment,
                            capsule,
                            capsule_digest,
                            dimensions,
                            pixels,
                        }
                    }
                },
                (None, Some(source)) => {
                    match source.next(deployment, plan, limits, &mut budget, cx)? {
                        Some(frame) => frame,
                        None => break,
                    }
                }
                (None, None) => return Err(RecordedDecodeError::UnsupportedMedia.into()),
            };
            checkpoint(cx, "recorded_watch:frame")?;
            if restart_pending && !frames.is_empty() {
                // No track is bridged across a decode gap: a fresh tracker, fresh identities.
                tracker = MultiObjectTracker::new(plan.tracker_config())?;
                track_base = last_track;
                restarts.push(frame.segment);
            }
            restart_pending = false;
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
            let tracks: Vec<TrackedTarget> = output
                .tracks
                .iter()
                .map(|target| {
                    let mut target = target.clone();
                    target.id += track_base;
                    last_track = last_track.max(target.id);
                    target
                })
                .collect();
            if sensor.is_none() {
                sensor = Some(frame.capsule.sensor_id.clone());
            }
            if frame.capsule.sensor_id != first_capsule.sensor_id {
                return Err(RecordedDecodeError::InvalidReceipt.into());
            }
            let failure_domain = format!(
                "recorded-sensor:{}",
                hex(ContentDigest::sha256(
                    frame.capsule.sensor_id.as_str().as_bytes()
                ))
            );
            for target in &tracks {
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
                confirmed_at.entry(target.id).or_insert(frame.segment);
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
        let cascade = match detector {
            None => None,
            Some(detector) => {
                let tracks: Vec<CascadeTrack> = entries
                    .iter()
                    .map(|(_, track_id, entry_segment)| {
                        let observations = histories
                            .get(track_id)
                            .map(|h| h.observations.as_slice())
                            .unwrap_or_default();
                        CascadeTrack {
                            track_id: *track_id,
                            selections: select_frames(
                                *entry_segment,
                                confirmed_at
                                    .get(track_id)
                                    .copied()
                                    .unwrap_or(*entry_segment),
                                observations,
                                detector.config().frames_per_track,
                            ),
                        }
                    })
                    .collect();
                let decoded: Vec<usize> = frames.iter().map(|f| f.segment).collect();
                let mut allowance = detector.budget();
                let outcome = detector.run_recovered(
                    deployment,
                    RecoveredCascadeSource {
                        source: CascadeSource {
                            import_identity: plan.import_identity,
                            import_root,
                            interpretation: plan.interpretation,
                            media_format: &media_format,
                            first_segment: plan.first_segment,
                            decoded_segments: &decoded,
                        },
                        decode_refusals: &decode_refusals,
                        tracking_restarts: &restarts,
                    },
                    &tracks,
                    &mut allowance,
                    limits,
                    cx,
                )?;
                Some(WatchCascade {
                    digest: detector.digest(),
                    policy_json: cascade_policy_json(detector),
                    outcome,
                })
            }
        };
        let by_segment: BTreeMap<usize, &WatchFrame> =
            frames.iter().map(|f| (f.segment, f)).collect();
        let mut candidates = Vec::with_capacity(entries.len());
        for (position, (zone_id, track_id, entry_segment)) in entries.into_iter().enumerate() {
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
            let class_evidence = match &cascade {
                Some(cascade) => {
                    // A cascade analysis is a distinct candidate: its evidence differs.
                    e.digest(cascade.digest);
                    cascade
                        .outcome
                        .evidence
                        .get(position)
                        .cloned()
                        .ok_or(WatchError::Limit)?
                }
                None => Vec::new(),
            };
            let identity = ContentDigest::sha256(&e.finish());
            candidates.push(PendingCandidate {
                zone_id,
                track_id,
                entry_segment,
                observations,
                class_evidence,
                identity,
            });
        }
        let analysis = analysis_bytes(
            plan_digest,
            import_root,
            &frames,
            &candidates,
            cascade
                .as_ref()
                .map(|c| (c.digest, c.outcome.digest(c.digest))),
            &decode_refusals,
            &restarts,
        );
        let sensor = sensor.ok_or(WatchError::Limit)?;
        let coverage = watch_coverage(&WatchCoverageContext {
            plan,
            import_root,
            sensor: sensor.as_str(),
            analysis_digest: ContentDigest::sha256(&analysis),
            basis,
            capture_time_label: &capture_time_label,
            segment_gaps: &segment_gaps,
            media_format: &media_format,
            dimensions,
            frames: &frames,
            candidates: &candidates,
            cascade: cascade.as_ref().map(|c| c.digest),
            refusals: &decode_refusals,
            restarts: &restarts,
            privacy: &privacy,
        })?;
        let coverage_status = coverage_status(deployment, &[&coverage])?;
        let mut prepared = Vec::with_capacity(candidates.len());
        for pending in candidates {
            checkpoint(cx, "recorded_watch:prepare")?;
            let proof = provenance(&pending, &analysis, import_root, sensor.as_str(), &privacy)?;
            let PendingCandidate {
                zone_id,
                track_id,
                entry_segment,
                observations,
                class_evidence,
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
                class_evidence,
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
            coverage,
            coverage_status,
            cascade,
            decode_refusals,
            tracking_restarts: restarts,
            privacy,
        })
    }

    /// Refused segment runs of a tolerant analysis (always empty otherwise), in segment order.
    #[must_use]
    pub fn decode_refusals(&self) -> &[DecodeRefusal] {
        &self.decode_refusals
    }

    /// First decoded segment after each tracking restart, in segment order. These are the
    /// exact boundaries used by coverage and bound into the analysis identity; they cannot be
    /// reconstructed from missing frames alone (a decoder may restart without losing a frame).
    /// Always empty for strict analyses, and for tolerant analyses with no discontinuity.
    #[must_use]
    pub fn tracking_restarts(&self) -> &[usize] {
        &self.tracking_restarts
    }

    /// Privacy mask binding applied to every decoded frame of this analysis.
    #[must_use]
    pub fn privacy_mask(&self) -> &MaskBinding {
        &self.privacy
    }

    /// Detector-cascade outcome of this analysis, if a detector was supplied.
    #[must_use]
    pub fn detector_cascade(&self) -> Option<&CascadeOutcome> {
        self.cascade.as_ref().map(|c| &c.outcome)
    }

    /// Cascade identity bound into this analysis, if a detector was supplied.
    #[must_use]
    pub fn cascade_digest(&self) -> Option<ContentDigest> {
        self.cascade.as_ref().map(|c| c.digest)
    }

    /// Proposed (or retained) coverage of this analysis.
    #[must_use]
    pub fn coverage(&self) -> &CoverageRecord {
        &self.coverage
    }

    /// Retention state of [`Self::coverage`].
    #[must_use]
    pub fn coverage_status(&self) -> CoverageStatus {
        self.coverage_status
    }

    /// Exact approval digest that retains [`Self::coverage`].
    #[must_use]
    pub fn coverage_approval(&self) -> ContentDigest {
        approval_digest(&[&self.coverage])
    }

    /// Decoded frame size.
    #[must_use]
    pub fn dimensions(&self) -> [u32; 2] {
        self.dimensions
    }

    /// Fails closed, before any write, when `approval` is neither this analysis's coverage
    /// proposal nor the approval of its already retained coverage.
    pub fn check_coverage_approval(
        &self,
        deployment: &ReferenceDeployment,
        approval: ContentDigest,
    ) -> Result<()> {
        check_approval(deployment, &[&self.coverage], approval)?;
        Ok(())
    }

    /// Retains this analysis's coverage record with its exact approval digest (or reports it as
    /// already retained). Coverage is authority-plane evidence: nothing is written without the
    /// approval, and an already retained analysis is never rewritten.
    pub fn retain_coverage(
        &mut self,
        deployment: &mut ReferenceDeployment,
        approval: ContentDigest,
        cx: &ReplayCx,
    ) -> Result<CoverageStatus> {
        checkpoint(cx, "recorded_watch:coverage")?;
        let status = retain_coverage(deployment, &[&self.coverage], approval, cx)?;
        self.coverage_status = status;
        Ok(status)
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
    /// Retained media format (`mjpeg`, `annexb` or `hevc`).
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
        self.to_json_with_coverage(authority_sequence, approve_hint, None)
    }

    /// [`Self::to_json`] with an optional pre-rendered `coverage` JSON value appended as the
    /// report's last member.
    #[must_use]
    pub fn to_json_with_coverage(
        &self,
        authority_sequence: u64,
        approve_hint: Option<&str>,
        coverage_json: Option<&str>,
    ) -> String {
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
                let class_evidence = match self.cascade {
                    Some(_) => format!(",\"class_evidence\":{}", class_evidence_json(&c.class_evidence)),
                    None => String::new(),
                };
                let privacy = match self.privacy.policy_digest() {
                    Some(digest) => format!(
                        ",\"privacy_transform\":{{\"applied_redaction_transform\":\"{}\",\"policy_digest\":\"{digest}\"}}",
                        self.privacy.applied_transform().unwrap_or_default()
                    ),
                    None => String::new(),
                };
                format!(
                    "{{\"candidate_id\":\"{}\",\"zone_id\":\"{}\",\"track_id\":{},\"entry_segment\":{},\"frame_range\":[{first},{last}],\"event_id\":\"{}\",\"event_kind\":\"{}\",\"event_state\":\"{}\",\"proposal_digest\":\"{}\",\"provenance_root\":\"{}\",\"status\":\"{}\",\"publish_command\":{command},\"evidence\":[{}]{class_evidence}{privacy}}}",
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
                "\"absence_certifiable\":false,\"detection_quality_claim\":false{}{}{}{}}}"
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
            decode_refusals_json(&self.decode_refusals),
            // Without a retained policy the report is byte-identical to the pre-mask tree
            // (pinned by `watch_report_golden`) and the binding is the explicit no-policy marker
            // (`privacy_mask()`). With a policy the applied transform is named here.
            self.privacy.policy().map_or_else(String::new, |_| format!(
                ",\"privacy_mask\":{}",
                self.privacy.to_json()
            )),
            self.cascade.as_ref().map_or_else(String::new, |c| format!(
                ",\"detector_cascade\":{{{},{}}}",
                c.policy_json,
                cascade_outcome_json(&c.outcome)
            )),
            coverage_json.map_or_else(String::new, |json| format!(",\"coverage\":{json}")),
        )
    }
}

/// `,"decode_refusals":[...]` for a tolerant analysis that refused segments; empty otherwise, so
/// every other report keeps its exact bytes.
pub(crate) fn decode_refusals_json(refusals: &[DecodeRefusal]) -> String {
    if refusals.is_empty() {
        return String::new();
    }
    let items: Vec<String> = refusals
        .iter()
        .map(|refusal| {
            format!(
                "{{\"first_segment\":{},\"last_segment\":{},\"error_id\":{},\"coverage\":\"decode_refused\"}}",
                refusal.first_segment,
                refusal.last_segment,
                json_string(&refusal.error_id)
            )
        })
        .collect();
    format!(",\"decode_refusals\":[{}]", items.join(","))
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
                mask,
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
                // Masked before the foreground model, tracker or zone gate sees any pixel.
                let mut pixels = image.pixels().to_vec();
                mask.apply_luma(&mut pixels, image.dimensions())
                    .map_err(RecordedDecodeError::from)?;
                *next += 1;
                Ok(Some(DecodedFrame {
                    segment,
                    capsule,
                    capsule_digest,
                    dimensions: image.dimensions(),
                    pixels,
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
            // RASL pictures skipped after a leading CRA/BLA yield no frame (and no observation).
            Self::H265(range) => {
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

struct WatchCoverageContext<'a> {
    plan: &'a WatchPlan,
    import_root: ContentDigest,
    sensor: &'a str,
    analysis_digest: ContentDigest,
    basis: fss_core::LedgerAnchor,
    capture_time_label: &'a str,
    segment_gaps: &'a [bool],
    media_format: &'a str,
    dimensions: [u32; 2],
    frames: &'a [WatchFrame],
    candidates: &'a [PendingCandidate],
    cascade: Option<ContentDigest>,
    refusals: &'a [DecodeRefusal],
    restarts: &'a [usize],
    privacy: &'a MaskBinding,
}

/// The plan identity of an analysis under `privacy`: unchanged without a policy, otherwise
/// folded with the mask binding, so no identity is shared across mask generations.
#[must_use]
pub fn masked_plan_digest(plan: ContentDigest, privacy: &MaskBinding) -> ContentDigest {
    match privacy {
        MaskBinding::NoPolicy => plan,
        MaskBinding::Policy(_) => lineage_digest("watch_plan", plan, privacy.digest()),
    }
}

/// Appends a detector-cascade identity (package, generation, policy) to coverage parameters.
pub fn bind_cascade_parameters(parameters: &mut Vec<u64>, cascade: Option<ContentDigest>) {
    if let Some(digest) = cascade {
        let bytes = digest.bytes();
        parameters.extend(bytes.chunks(8).map(|chunk| {
            chunk
                .iter()
                .fold(0_u64, |value, byte| (value << 8) | u64::from(*byte))
        }));
    }
}

fn watch_coverage(context: &WatchCoverageContext<'_>) -> Result<CoverageRecord> {
    let plan = context.plan;
    let mut parameters = pipeline_parameters(plan.interpretation, &plan.detector, &plan.tracker);
    bind_cascade_parameters(&mut parameters, context.cascade);
    // A mask generation is part of the pipeline generation: witnesses never cross it.
    bind_cascade_parameters(
        &mut parameters,
        context.privacy.policy().map(|_| context.privacy.digest()),
    );
    let frames: Vec<CoverageFrame> = context
        .frames
        .iter()
        .map(|frame| CoverageFrame {
            segment: frame.segment,
            capture: frame.capture,
        })
        .collect();
    let mut zones = Vec::with_capacity(plan.zones.len());
    for zone in &plan.zones {
        let geometry = format!("{},{},{},{}", zone.x, zone.y, zone.width, zone.height);
        let inside_frame = u64::from(zone.x) + u64::from(zone.width)
            <= u64::from(context.dimensions[0])
            && u64::from(zone.y) + u64::from(zone.height) <= u64::from(context.dimensions[1]);
        let entries = context
            .candidates
            .iter()
            .filter(|candidate| candidate.zone_id == zone.zone_id)
            .map(|candidate| CoverageEntry {
                segment: candidate.entry_segment,
                candidate: candidate.identity,
                event_id: Some(format!("event:watch:{}", hex(candidate.identity))),
            })
            .collect();
        zones.push(CoverageZoneInput {
            zone_id: zone.zone_id.clone(),
            pipeline_generation: pipeline_generation(
                CoverageSource::Watch,
                ContentDigest::sha256(POLICY),
                media_decoder_label(context.media_format),
                &parameters,
                &zone.zone_id,
                &geometry,
            ),
            geometry,
            inside_frame,
            entries,
        });
    }
    let masked: BTreeSet<String> = match context.privacy.policy() {
        None => BTreeSet::new(),
        Some(policy) => plan
            .zones
            .iter()
            .filter(|zone| {
                policy
                    .zone_masking([zone.x, zone.y, zone.width, zone.height])
                    .any()
            })
            .map(|zone| zone.zone_id.clone())
            .collect(),
    };
    let extras = CoverageExtras {
        visibility: Vec::new(),
        refusals: context.refusals.to_vec(),
        restarts: context.restarts.to_vec(),
        pose_provenance: None,
    };
    let mut record = build_coverage_with(
        &CoverageInput {
            source: CoverageSource::Watch,
            import_identity: plan.import_identity,
            import_root: context.import_root,
            sensor_id: context.sensor,
            analysis_digest: context.analysis_digest,
            basis: context.basis.clone(),
            capture_time_label: context.capture_time_label,
            segment_gaps: context.segment_gaps,
            first_segment: plan.first_segment,
            last_segment: plan.first_segment + plan.segment_count - 1,
            frames: &frames,
            confirmation_hits: plan.tracker.confirmation_hits,
            zones,
        },
        &extras,
    )?;
    mask_coverage_zones(&mut record, &masked)?;
    Ok(record)
}

struct PendingCandidate {
    zone_id: String,
    track_id: u64,
    entry_segment: usize,
    observations: Vec<WatchObservation>,
    class_evidence: Vec<ClassEvidence>,
    identity: ContentDigest,
}

fn analysis_bytes(
    plan_digest: ContentDigest,
    import_root: ContentDigest,
    frames: &[WatchFrame],
    candidates: &[PendingCandidate],
    cascade: Option<(ContentDigest, ContentDigest)>,
    refusals: &[DecodeRefusal],
    restarts: &[usize],
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
    if let Some((cascade, outcome)) = cascade {
        e.text("detector_cascade");
        e.digest(cascade);
        e.digest(outcome);
    }
    // Tolerant analyses only: the refused runs and tracking restarts are part of the analysis.
    if !refusals.is_empty() || !restarts.is_empty() {
        e.text("decode_refusals");
        e.u64(refusals.len() as u64);
        for refusal in refusals {
            e.u64(refusal.first_segment as u64);
            e.u64(refusal.last_segment as u64);
            e.text(&refusal.error_id);
        }
        e.u64(restarts.len() as u64);
        for segment in restarts {
            e.u64(*segment as u64);
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
    privacy: &MaskBinding,
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
    for item in &candidate.class_evidence {
        let digest = insert(&mut objects, item.record.clone());
        let capsule = observations
            .iter()
            .find(|o| o.segment == item.segment)
            .map(|o| o.capsule_digest)
            .ok_or(WatchError::Limit)?;
        // Same sensor, same failure domain: detector evidence can never corroborate.
        let supports = item.supports();
        evidence.push(EventEvidence {
            digest,
            class: EvidenceClass::Derived,
            failure_domain: failure_domain.clone(),
            supports,
            relation: if supports {
                EvidenceEdgeRelation::Supports
            } else {
                EvidenceEdgeRelation::DerivedFrom
            },
            capsule_digest: Some(capsule),
            identity_digest: Some(sensor_digest),
        });
    }
    if let Some(policy) = privacy.policy() {
        // The applied privacy transform is a typed dependency of the event: the exact retained
        // policy the pixels were masked with, never support for the event itself.
        let digest = insert(&mut objects, policy.to_bytes());
        evidence.push(EventEvidence {
            digest,
            class: EvidenceClass::Assertion,
            failure_domain: failure_domain.clone(),
            supports: false,
            relation: EvidenceEdgeRelation::RequiredBy,
            capsule_digest: None,
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
