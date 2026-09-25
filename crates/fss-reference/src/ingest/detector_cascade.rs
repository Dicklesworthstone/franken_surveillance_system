#![forbid(unsafe_code)]
//! Detection cascade: the cheap foreground + Kalman gate selects frames, a verified detector
//! package runs only there.
//!
//! The model-free watch pipeline ([`super::recorded_watch`]) decodes every frame, finds
//! foreground, tracks it and gates zone entries. Running the trained detector (for example the
//! admitted YOLOX-Nano package, about 3 s per 416x416 inference on the scalar executor) on every
//! frame would dominate the cost, so this stage runs it only on frames the cheap stage selected:
//! for each confirmed track that produced a candidate, its zone-entry frame, then its
//! confirmation frame, then its following matched frames, up to `frames_per_track` frames. The
//! unique selected frames are admitted in deterministic order against an explicit
//! `max_inferences` budget; frames past the budget are recorded as typed budget exhaustion, never
//! dropped. The full decoded frame is letterboxed exactly as the package spec declares (the same
//! path as `fss-infer package-detect`), and each detection is associated with the track's filtered
//! box by integer IoU on the 1/256-pixel source grid.
//!
//! The result is supporting cognition evidence only. Scores are uncalibrated model outputs. The
//! evidence shares the sensor's failure domain, so it can never corroborate a single-sensor
//! candidate, and it never changes an event's kind (candidates stay `Unclassified`), state or
//! alert affordance. A frame without an associated detection is not evidence of absence.
//!
//! [`DetectorCascade::run_recovered`] accepts the watch stage's exact refused intervals and
//! tracking restarts. Selected frames are decoded in separate native IDR/IRAP-led epochs; the
//! inference allowance and detection-work budget do not restart with the decoder. Refused or
//! missing frames cannot be selected, and no track's class evidence can bridge an epoch.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::fmt::Write as _;

use fss_codec_mjpeg::DecodeBudget;
use fss_codec_mjpeg::color::{MAX_RGB_BYTES, RgbDecodeLimits, decode_rgb, rgb_decoder_identity};
use fss_core::{CanonicalEncoder, ContentDigest};

use super::RetainedFileImport;
use super::package_detect::{
    DecodedFrame, FrameRun, PackageDetectError, PackageDetectFrame, PackageDetectLimits,
    VideoPicture,
};
use super::privacy_mask::current_mask;
use super::recorded_decode::h264::{RecordedH264Range, RecordedH264Request};
use super::recorded_decode::h265::{RecordedH265Range, RecordedH265Request};
use super::recorded_decode::video_rgb::video_rgb_transform_identity;
use super::recorded_decode::{ComponentInterpretation, RecordedDecodeError, source_capsule};
use super::recorded_watch::WatchLimits;
use super::rgb_detections::{RgbDetectionBudget, RgbDetectionContract};
use super::rgb_package::RgbDetectorPackage;
use crate::{ReferenceDeployment, ReplayCx, ScalarExecCx};

/// Largest explicit inference budget of one analysis.
pub const MAX_CASCADE_INFERENCES: usize = 64;
/// Largest number of selected frames per candidate track.
pub const MAX_CASCADE_FRAMES_PER_TRACK: usize = 8;
/// Stable identity of a selected frame skipped because the inference budget was exhausted.
pub const CASCADE_BUDGET_EXHAUSTED: &str = "ERR-DETECTOR-CASCADE-BUDGET-001";
/// Stable identity of a per-frame detector refusal recorded by the cascade.
pub const CASCADE_FRAME_REFUSED: &str = "ERR-PACKAGE-DETECT-001";

const CASCADE_DOMAIN: &str = "fss.detector_cascade.v1";
const EVIDENCE_DOMAIN: &str = "fss.detector_class_evidence.v1";
const POLICY: &[u8] = b"fss.detector_cascade_policy.v1:cheap-foreground-kalman-zone-gate-first:\
zone-entry-then-confirmation-then-following-frames:explicit-inference-budget:full-frame-letterbox:\
integer-iou-association:uncalibrated-scores:supporting-cognition-only:kind-state-alert-unchanged:\
sensor-failure-domain";

/// Typed refusal of the cascade stage itself (per-frame outcomes are not refusals).
#[derive(Debug)]
pub enum CascadeError {
    /// The cascade configuration is outside its bounds.
    InvalidConfig(&'static str),
    /// Retained decode of a selected frame was refused.
    Decode(Box<RecordedDecodeError>),
    /// Owner cancellation before the stage completed.
    Cancelled,
}
impl CascadeError {
    /// Registered stable identity (registries/ERRORS.md).
    #[must_use]
    pub fn stable_id(&self) -> &'static str {
        match self {
            Self::InvalidConfig(_) => "ERR-DETECTOR-CASCADE-PLAN-001",
            Self::Decode(error) => error.stable_id(),
            Self::Cancelled => "ERR-PACKAGE-DETECT-CANCELLED-001",
        }
    }
}
impl fmt::Display for CascadeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidConfig(why) => write!(f, "invalid detector cascade: {why}"),
            Self::Decode(e) => write!(f, "detector cascade decode: {e}"),
            Self::Cancelled => f.write_str("detector cascade cancelled"),
        }
    }
}
impl std::error::Error for CascadeError {}
impl From<RecordedDecodeError> for CascadeError {
    fn from(error: RecordedDecodeError) -> Self {
        match error {
            RecordedDecodeError::Cancelled => Self::Cancelled,
            other => Self::Decode(Box::new(other)),
        }
    }
}
impl From<super::FileIngestError> for CascadeError {
    fn from(error: super::FileIngestError) -> Self {
        Self::from(RecordedDecodeError::from(error))
    }
}

/// Explicit cascade policy. Every field is bound into the cascade identity.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CascadeConfig {
    /// Selected frames per candidate track, 1..=[`MAX_CASCADE_FRAMES_PER_TRACK`].
    pub frames_per_track: usize,
    /// Unique inferences one analysis may run, 1..=[`MAX_CASCADE_INFERENCES`].
    pub max_inferences: usize,
    /// Minimum detection/track IoU for association, parts per million (0..=1000000).
    pub minimum_association_iou_ppm: u32,
    /// `None` keeps the package threshold; `Some` is an explicit operator override.
    pub minimum_score_ppm: Option<u32>,
}
impl Default for CascadeConfig {
    fn default() -> Self {
        Self {
            frames_per_track: 1,
            max_inferences: 8,
            minimum_association_iou_ppm: 300_000,
            minimum_score_ppm: None,
        }
    }
}
impl CascadeConfig {
    /// Validates the bounds before any package work.
    pub fn validate(&self) -> Result<(), CascadeError> {
        if self.frames_per_track == 0 || self.frames_per_track > MAX_CASCADE_FRAMES_PER_TRACK {
            return Err(CascadeError::InvalidConfig("frames per track must be 1..8"));
        }
        if self.max_inferences == 0 || self.max_inferences > MAX_CASCADE_INFERENCES {
            return Err(CascadeError::InvalidConfig("max inferences must be 1..64"));
        }
        if self.minimum_association_iou_ppm > 1_000_000 {
            return Err(CascadeError::InvalidConfig(
                "association IoU must be at most 1000000 ppm",
            ));
        }
        if self.minimum_score_ppm.is_some_and(|ppm| ppm > 1_000_000) {
            return Err(CascadeError::InvalidConfig(
                "minimum score must be at most 1000000 ppm",
            ));
        }
        Ok(())
    }
}

/// Why a frame was selected for one track.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SelectionReason {
    /// The frame at which the confirmed track entered the zone.
    ZoneEntry,
    /// The frame at which the track was first confirmed.
    Confirmation,
    /// A later matched frame of the confirmed track.
    FollowingMatch,
}
impl SelectionReason {
    /// Stable spelling.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ZoneEntry => "zone_entry",
            Self::Confirmation => "confirmation",
            Self::FollowingMatch => "following_match",
        }
    }
    fn tag(self) -> u8 {
        match self {
            Self::ZoneEntry => 0,
            Self::Confirmation => 1,
            Self::FollowingMatch => 2,
        }
    }
}

/// One frame selected for one track, with the track's filtered box `(cx, cy, w, h)` there.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CascadeSelection {
    /// Retained segment.
    pub segment: usize,
    /// Why the cheap stage selected it.
    pub reason: SelectionReason,
    /// Filtered track box in pixels, rounded.
    pub track_box: [i64; 4],
}

/// Deterministic selection: entry frame, confirmation frame, then following matched frames.
/// `observations` are the track's matched `(segment, box)` pairs in segment order.
#[must_use]
pub fn select_frames(
    entry: usize,
    confirmation: usize,
    observations: &[(usize, [i64; 4])],
    frames_per_track: usize,
) -> Vec<CascadeSelection> {
    let at = |segment: usize| {
        observations
            .iter()
            .find(|(s, _)| *s == segment)
            .map(|(_, b)| *b)
    };
    let mut selections = Vec::new();
    let push = |segment: usize, reason: SelectionReason, selections: &mut Vec<_>| {
        if selections.len() < frames_per_track
            && !selections
                .iter()
                .any(|s: &CascadeSelection| s.segment == segment)
            && let Some(track_box) = at(segment)
        {
            selections.push(CascadeSelection {
                segment,
                reason,
                track_box,
            });
        }
    };
    push(entry, SelectionReason::ZoneEntry, &mut selections);
    push(confirmation, SelectionReason::Confirmation, &mut selections);
    for (segment, _) in observations.iter().filter(|(s, _)| *s > confirmation) {
        push(*segment, SelectionReason::FollowingMatch, &mut selections);
    }
    selections
}

/// One detection of an inferred frame (uncalibrated).
#[derive(Clone, Debug, PartialEq)]
pub struct CascadeDetection {
    /// Head row.
    pub row: usize,
    /// Index in the package label vocabulary.
    pub class_index: usize,
    /// Label text.
    pub label: String,
    /// Combined F32 score; uncalibrated.
    pub score: f32,
    /// Source-grid XYXY in 1/256 pixels.
    pub bounds: [u32; 4],
}

/// Identities of one completed inference, without its tensors.
#[derive(Clone, Debug, PartialEq)]
pub struct InferredFrame {
    /// `jpeg_rgb` or `ycbcr420_bt601_limited_rgb`.
    pub color: &'static str,
    /// SHA-256 of the packed RGB input before privacy projection and letterbox.
    pub rgb_digest: ContentDigest,
    /// Inference identity (model, source binding, preprocessing).
    pub inference_identity: ContentDigest,
    /// Model-input tensor digest.
    pub input_digest: ContentDigest,
    /// Output tensor digest.
    pub output_digest: ContentDigest,
    /// Head projection report digest.
    pub detection_report_digest: ContentDigest,
    /// Executed multiply-accumulates.
    pub executed_macs: u64,
    /// NMS survivors in report order.
    pub detections: Vec<CascadeDetection>,
}

/// Outcome of one selected unique frame.
#[derive(Clone, Debug, PartialEq)]
pub enum FrameStatus {
    /// The detector ran on this frame.
    Inferred(Box<InferredFrame>),
    /// Selected but not run: the explicit inference budget was exhausted.
    BudgetExhausted,
    /// The detector refused this frame (decode, preprocessing, execution or head bounds).
    Refused(&'static str),
}

/// One selected unique frame of one recording.
#[derive(Clone, Debug, PartialEq)]
pub struct CascadeFrame {
    /// Retained segment.
    pub segment: usize,
    /// Outcome.
    pub status: FrameStatus,
}

/// How one selection fared.
#[derive(Clone, Debug, PartialEq)]
pub enum EvidenceOutcome {
    /// A detection overlaps the track box at or above the association threshold.
    Associated {
        /// The associated detection.
        detection: CascadeDetection,
        /// Integer IoU with the track box, parts per million.
        iou_ppm: u32,
    },
    /// The detector ran; no detection reached the association threshold.
    NoAssociation {
        /// Survivors in the frame.
        detections: usize,
    },
    /// Budget exhausted before this frame.
    BudgetExhausted,
    /// The detector refused this frame.
    Refused(&'static str),
}
impl EvidenceOutcome {
    /// Stable spelling.
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Associated { .. } => "associated",
            Self::NoAssociation { .. } => "no_association",
            Self::BudgetExhausted => "budget_exhausted",
            Self::Refused(_) => "detector_refused",
        }
    }
}

/// Class evidence of one track at one selected frame, with its canonical retained record.
#[derive(Clone, Debug, PartialEq)]
pub struct ClassEvidence {
    /// Retained segment.
    pub segment: usize,
    /// Why the frame was selected.
    pub reason: SelectionReason,
    /// Association outcome.
    pub outcome: EvidenceOutcome,
    /// Digest of [`Self::record`].
    pub digest: ContentDigest,
    /// Canonical record retained with the candidate's provenance.
    pub record: Vec<u8>,
}
impl ClassEvidence {
    /// Whether this record is a supporting edge (an associated detection).
    #[must_use]
    pub fn supports(&self) -> bool {
        matches!(self.outcome, EvidenceOutcome::Associated { .. })
    }
}

/// One track presented to the cascade.
#[derive(Clone, Debug)]
pub struct CascadeTrack {
    /// Tracker-local identifier.
    pub track_id: u64,
    /// Selected frames in priority order.
    pub selections: Vec<CascadeSelection>,
}

/// One recording presented to the cascade.
#[derive(Clone, Copy, Debug)]
pub struct CascadeSource<'a> {
    /// Exact completed import.
    pub import_identity: ContentDigest,
    /// Import root.
    pub import_root: ContentDigest,
    /// Component interpretation of the analysis.
    pub interpretation: ComponentInterpretation,
    /// `mjpeg`, `annexb` or `hevc`.
    pub media_format: &'a str,
    /// First segment of the analysed range (an IDR/IRAP for video).
    pub first_segment: usize,
    /// Every decoded segment of the analysis, in order.
    pub decoded_segments: &'a [usize],
}

/// Per-analysis inference allowance shared by every recording of that analysis.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CascadeBudget {
    remaining: usize,
}
impl CascadeBudget {
    /// Remaining unique inferences.
    #[must_use]
    pub fn remaining(&self) -> usize {
        self.remaining
    }
}

/// Complete cascade outcome for one recording.
#[derive(Clone, Debug, PartialEq)]
pub struct CascadeOutcome {
    /// Import the outcome belongs to.
    pub import_identity: ContentDigest,
    /// Unique selected frames in admission order.
    pub frames: Vec<CascadeFrame>,
    /// Class evidence per input track, aligned with the input order.
    pub evidence: Vec<Vec<ClassEvidence>>,
    /// Decoded frames the cheap stage never selected.
    pub cascade_skipped: Vec<usize>,
}
impl CascadeOutcome {
    /// Frames the detector actually ran on.
    #[must_use]
    pub fn inferred_segments(&self) -> Vec<usize> {
        self.segments(|s| matches!(s, FrameStatus::Inferred(_)))
    }
    /// Selected frames skipped by budget exhaustion.
    #[must_use]
    pub fn budget_skipped_segments(&self) -> Vec<usize> {
        self.segments(|s| matches!(s, FrameStatus::BudgetExhausted))
    }
    /// Selected frames the detector refused.
    #[must_use]
    pub fn refused_segments(&self) -> Vec<usize> {
        self.segments(|s| matches!(s, FrameStatus::Refused(_)))
    }
    fn segments(&self, keep: impl Fn(&FrameStatus) -> bool) -> Vec<usize> {
        self.frames
            .iter()
            .filter(|f| keep(&f.status))
            .map(|f| f.segment)
            .collect()
    }
    /// Canonical digest of the outcome, bound into analysis records.
    #[must_use]
    pub fn digest(&self, cascade: ContentDigest) -> ContentDigest {
        let mut e = CanonicalEncoder::new();
        e.text(CASCADE_DOMAIN);
        e.text("outcome");
        e.digest(cascade);
        e.digest(self.import_identity);
        e.u64(self.frames.len() as u64);
        for frame in &self.frames {
            e.u64(frame.segment as u64);
            match &frame.status {
                FrameStatus::Inferred(inferred) => {
                    e.u8(0);
                    e.digest(inferred.rgb_digest);
                    e.digest(inferred.inference_identity);
                    e.digest(inferred.output_digest);
                    e.digest(inferred.detection_report_digest);
                }
                FrameStatus::BudgetExhausted => e.u8(1),
                FrameStatus::Refused(id) => {
                    e.u8(2);
                    e.text(id);
                }
            }
        }
        e.u64(self.evidence.len() as u64);
        for track in &self.evidence {
            e.u64(track.len() as u64);
            for evidence in track {
                e.digest(evidence.digest);
            }
        }
        e.u64(self.cascade_skipped.len() as u64);
        for segment in &self.cascade_skipped {
            e.u64(*segment as u64);
        }
        ContentDigest::sha256(&e.finish())
    }
}

/// A recording plus the exact recovery diagnostics emitted by the cheap watch stage.
/// The ordinary [`CascadeSource`] API remains strict. Refusals are never selected for
/// inference, and a track's selections may not cross a tracking restart.
#[derive(Clone, Copy, Debug)]
pub struct RecoveredCascadeSource<'a> {
    /// The retained recording and its complete decoded-segment set.
    pub source: CascadeSource<'a>,
    /// Refused retained segment intervals, in increasing, nonoverlapping order.
    pub decode_refusals: &'a [super::tolerant_decode::DecodeRefusal],
    /// First decoded segments of restarted tracking epochs, in increasing order.
    pub tracking_restarts: &'a [usize],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct CascadeEpoch {
    first: usize,
    last: usize,
}

struct CascadeReadPlan<'a> {
    source: CascadeSource<'a>,
    epochs: Vec<CascadeEpoch>,
    recovered: bool,
}

impl<'a> CascadeReadPlan<'a> {
    fn build(input: RecoveredCascadeSource<'a>, tracks: &[CascadeTrack]) -> Result<Self, CascadeError> {
        let RecoveredCascadeSource { source, decode_refusals, tracking_restarts } = input;
        let limit = super::recorded_watch::MAX_WATCH_FRAMES;
        if source.decoded_segments.len() > limit || tracks.len() > limit
            || decode_refusals.len() > limit || tracking_restarts.len() > limit
        {
            return Err(CascadeError::InvalidConfig("recovery input exceeds watch bounds"));
        }
        let decoded: BTreeSet<usize> = source.decoded_segments.iter().copied().collect();
        if decoded.len() != source.decoded_segments.len() {
            return Err(CascadeError::InvalidConfig("duplicate decoded segment"));
        }
        // Decoder display order need not be segment order (B pictures). Validate the set,
        // but retain the original order in CascadeOutcome.cascade_skipped.
        let within = |segment: usize| segment.checked_sub(source.first_segment).is_some_and(|n| n < limit);
        if decoded.iter().any(|s| !within(*s))
            || decode_refusals.iter().any(|r| r.first_segment > r.last_segment
                || !within(r.first_segment) || !within(r.last_segment) || r.error_id.is_empty())
            || decode_refusals.windows(2).any(|w| w[0].last_segment >= w[1].first_segment)
            || tracking_restarts.windows(2).any(|w| w[0] >= w[1])
            || tracking_restarts.iter().any(|s| !decoded.contains(s))
        {
            return Err(CascadeError::InvalidConfig("invalid recovery diagnostics"));
        }
        if decode_refusals.iter().any(|r| decoded.range(r.first_segment..=r.last_segment).next().is_some()) {
            return Err(CascadeError::InvalidConfig("refused segment also marked decoded"));
        }
        let recovered = !decode_refusals.is_empty() || !tracking_restarts.is_empty();
        let mut epochs = Vec::new();
        if let Some(&first_decoded) = decoded.first() {
            let first = if decode_refusals.iter().any(|r| r.first_segment <= source.first_segment
                && source.first_segment <= r.last_segment)
            {
                // The native video reader must still verify that this is an IDR/IRAP.
                first_decoded
            } else {
                source.first_segment
            };
            let mut starts = vec![first];
            for &restart in tracking_restarts {
                if restart < first {
                    return Err(CascadeError::InvalidConfig("restart precedes recovered range"));
                }
                if restart != first { starts.push(restart); }
            }
            for (index, &start) in starts.iter().enumerate() {
                let last = match starts.get(index + 1) {
                    Some(next) => decoded.range(start..*next).next_back().copied(),
                    None => decoded.range(start..).next_back().copied(),
                }.ok_or(CascadeError::InvalidConfig("empty recovery epoch"))?;
                if decode_refusals.iter().any(|r| r.first_segment <= last && r.last_segment >= start) {
                    return Err(CascadeError::InvalidConfig("refusal lacks a tracking restart"));
                }
                epochs.push(CascadeEpoch { first: start, last });
            }
        }
        for track in tracks {
            if track.selections.len() > MAX_CASCADE_FRAMES_PER_TRACK {
                return Err(CascadeError::InvalidConfig("selection exceeds hard frame bound"));
            }
            let mut selected_epoch = None;
            for selection in &track.selections {
                if !decoded.contains(&selection.segment) {
                    return Err(CascadeError::InvalidConfig("selected segment was not decoded"));
                }
                let epoch = epochs.iter().position(|e| e.first <= selection.segment && selection.segment <= e.last)
                    .ok_or(CascadeError::InvalidConfig("selected segment outside recovery epochs"))?;
                if selected_epoch.is_some_and(|previous| previous != epoch) {
                    return Err(CascadeError::InvalidConfig("track selection crosses a recovery boundary"));
                }
                selected_epoch = Some(epoch);
            }
        }
        Ok(Self { source, epochs, recovered })
    }

    /// Decode each requested epoch only through its last selected segment. Holes and
    /// restart boundaries are never bridged to reach another selected frame.
    fn ranges(&self, wanted: &BTreeSet<usize>) -> Result<Vec<(usize, usize)>, CascadeError> {
        let mut ranges = Vec::new();
        for epoch in &self.epochs {
            if let Some(&last) = wanted.range(epoch.first..=epoch.last).next_back() {
                let count = last.checked_sub(epoch.first).and_then(|n| n.checked_add(1))
                    .ok_or(CascadeError::InvalidConfig("recovery segment count overflow"))?;
                ranges.push((epoch.first, count));
            }
        }
        Ok(ranges)
    }
}

/// One admission pass for the whole recording. A caller's allowance also spans cameras;
/// decoder restarts never create another allowance or change track-priority ordering.
fn admit_selected_frames(
    tracks: &[CascadeTrack], frames_per_track: usize, budget: &mut CascadeBudget,
) -> Result<(Vec<usize>, BTreeSet<usize>), CascadeError> {
    let mut order = Vec::new();
    for track in tracks {
        if track.selections.len() > frames_per_track {
            return Err(CascadeError::InvalidConfig("selection exceeds frames per track"));
        }
        for selection in &track.selections {
            if !order.contains(&selection.segment) { order.push(selection.segment); }
        }
    }
    let admitted: BTreeSet<usize> = order.iter().take(budget.remaining).copied().collect();
    budget.remaining -= admitted.len();
    Ok((order, admitted))
}

/// A loaded, verified detector package with its cascade policy and an inference cache.
///
/// The cache holds completed per-frame outcomes of this exact package, threshold and import,
/// so a re-analysis in the same process (for example the coverage re-proposal after
/// publication) reuses them instead of re-running identical deterministic inference; budget
/// accounting and every reported outcome are unchanged by the cache. Recovered runs deliberately
/// bypass and clear this cache because their independent decoder ranges must be revalidated.
pub struct DetectorCascade<'a> {
    package: &'a RgbDetectorPackage,
    contract: Option<RgbDetectionContract>,
    config: CascadeConfig,
    limits: PackageDetectLimits,
    scalar: &'a ScalarExecCx,
    cache: BTreeMap<(ContentDigest, usize), FrameStatus>,
    executed: usize,
    digest: ContentDigest,
}
impl fmt::Debug for DetectorCascade<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DetectorCascade")
            .field("digest", &self.digest)
            .field("config", &self.config)
            .field("executed", &self.executed)
            .finish_non_exhaustive()
    }
}

impl<'a> DetectorCascade<'a> {
    /// Binds a verified package (see [`RgbDetectorPackage::load`]) to a validated policy.
    pub fn new(
        package: &'a RgbDetectorPackage,
        config: CascadeConfig,
        limits: PackageDetectLimits,
        scalar: &'a ScalarExecCx,
    ) -> Result<Self, CascadeError> {
        config.validate()?;
        let contract = match config.minimum_score_ppm {
            None => None,
            Some(ppm) => Some(
                package
                    .contract_with_threshold(ppm)
                    .map_err(|_| CascadeError::InvalidConfig("threshold refused by package"))?,
            ),
        };
        let contract_digest = contract
            .as_ref()
            .unwrap_or_else(|| package.contract())
            .digest();
        let mut e = CanonicalEncoder::new();
        e.text(CASCADE_DOMAIN);
        e.digest(ContentDigest::sha256(POLICY));
        e.digest(package.archive_digest());
        e.digest(package.manifest_digest());
        e.text(package.manifest().model_id().as_str());
        e.text(package.manifest().generation().as_str());
        e.digest(package.model().digest());
        e.digest(package.graph_digest());
        e.digest(contract_digest);
        e.u64(config.frames_per_track as u64);
        e.u64(config.max_inferences as u64);
        e.u32(config.minimum_association_iou_ppm);
        e.digest(video_rgb_transform_identity());
        e.bytes(&rgb_decoder_identity());
        let digest = ContentDigest::sha256(&e.finish());
        Ok(Self {
            package,
            contract,
            config,
            limits,
            scalar,
            cache: BTreeMap::new(),
            executed: 0,
            digest,
        })
    }
    /// Cascade identity: policy, package archive/manifest/model/graph/contract, model id and
    /// generation, selection, budget and association policy, colour transforms.
    #[must_use]
    pub fn digest(&self) -> ContentDigest {
        self.digest
    }
    /// Fixed cascade policy digest.
    #[must_use]
    pub fn policy_digest() -> ContentDigest {
        ContentDigest::sha256(POLICY)
    }
    /// Configured policy.
    #[must_use]
    pub fn config(&self) -> CascadeConfig {
        self.config
    }
    /// Verified package.
    #[must_use]
    pub fn package(&self) -> &RgbDetectorPackage {
        self.package
    }
    /// Contract actually applied (package threshold or explicit override).
    #[must_use]
    pub fn contract(&self) -> &RgbDetectionContract {
        self.contract
            .as_ref()
            .unwrap_or_else(|| self.package.contract())
    }
    /// Model executions actually performed by this instance (cache hits excluded).
    #[must_use]
    pub fn executed_inferences(&self) -> usize {
        self.executed
    }
    /// A fresh per-analysis allowance of `max_inferences`.
    #[must_use]
    pub fn budget(&self) -> CascadeBudget {
        CascadeBudget {
            remaining: self.config.max_inferences,
        }
    }

    /// Runs the detector on the selected frames of one recording within `budget`.
    pub fn run(
        &mut self,
        deployment: &ReferenceDeployment,
        source: CascadeSource<'_>,
        tracks: &[CascadeTrack],
        budget: &mut CascadeBudget,
        limits: &WatchLimits,
        cx: &ReplayCx,
    ) -> Result<CascadeOutcome, CascadeError> {
        self.run_recovered(
            deployment,
            RecoveredCascadeSource {
                source,
                decode_refusals: &[],
                tracking_restarts: &[],
            },
            tracks,
            budget,
            limits,
            cx,
        )
    }

    /// Runs selected frames across explicitly recovered watch epochs. Admission occurs once
    /// against the caller's allowance, and one detection-work budget spans all video epochs.
    /// Each native video reader independently requires an IDR/IRAP and validates custody,
    /// continuity and privacy. Recovery diagnostics never authorize a track to bridge a gap.
    /// Clean inputs retain the ordinary run's records and cache behavior. Recovered runs do
    /// not reuse or retain cached frames: their decoder range and privacy basis are re-read.
    pub fn run_recovered(
        &mut self,
        deployment: &ReferenceDeployment,
        source: RecoveredCascadeSource<'_>,
        tracks: &[CascadeTrack],
        budget: &mut CascadeBudget,
        limits: &WatchLimits,
        cx: &ReplayCx,
    ) -> Result<CascadeOutcome, CascadeError> {
        cx.checkpoint("detector_cascade:select")
            .map_err(|_| CascadeError::Cancelled)?;
        let plan = CascadeReadPlan::build(source, tracks)?;
        if plan.recovered {
            self.cache.clear();
        }
        let result = self.run_planned(deployment, &plan, tracks, budget, limits, cx);
        // Also clear on cancellation/refusal, so a later run cannot inherit a partially
        // processed recovery basis. No cached result can cross between strict and recovery.
        if plan.recovered {
            self.cache.clear();
        }
        result
    }

    fn run_planned(
        &mut self,
        deployment: &ReferenceDeployment,
        plan: &CascadeReadPlan<'_>,
        tracks: &[CascadeTrack],
        budget: &mut CascadeBudget,
        limits: &WatchLimits,
        cx: &ReplayCx,
    ) -> Result<CascadeOutcome, CascadeError> {
        let source = plan.source;
        let (order, admitted) =
            admit_selected_frames(tracks, self.config.frames_per_track, budget)?;
        let missing: BTreeSet<usize> = admitted
            .iter()
            .copied()
            .filter(|s| !self.cache.contains_key(&(source.import_identity, *s)))
            .collect();
        if !missing.is_empty() {
            self.infer(deployment, plan, &missing, limits, cx)?;
        }
        let mut frames = Vec::with_capacity(order.len());
        for segment in &order {
            let status = if admitted.contains(segment) {
                self.cache
                    .get(&(source.import_identity, *segment))
                    .cloned()
                    .ok_or(CascadeError::InvalidConfig(
                        "selected frame was not decoded",
                    ))?
            } else {
                FrameStatus::BudgetExhausted
            };
            frames.push(CascadeFrame {
                segment: *segment,
                status,
            });
        }
        let minimum = self.config.minimum_association_iou_ppm;
        let mut evidence = Vec::with_capacity(tracks.len());
        for track in tracks {
            let mut records = Vec::with_capacity(track.selections.len());
            for selection in &track.selections {
                let status = frames
                    .iter()
                    .find(|f| f.segment == selection.segment)
                    .map(|f| &f.status)
                    .ok_or(CascadeError::InvalidConfig("selection without frame"))?;
                let outcome = match status {
                    FrameStatus::Inferred(inferred) => associate(inferred, selection, minimum),
                    FrameStatus::BudgetExhausted => EvidenceOutcome::BudgetExhausted,
                    FrameStatus::Refused(id) => EvidenceOutcome::Refused(id),
                };
                let record = self.record(&source, track.track_id, selection, status, &outcome);
                records.push(ClassEvidence {
                    segment: selection.segment,
                    reason: selection.reason,
                    outcome,
                    digest: ContentDigest::sha256(&record),
                    record,
                });
            }
            evidence.push(records);
        }
        let selected: BTreeSet<usize> = order.iter().copied().collect();
        Ok(CascadeOutcome {
            import_identity: source.import_identity,
            frames,
            evidence,
            cascade_skipped: source
                .decoded_segments
                .iter()
                .copied()
                .filter(|s| !selected.contains(s))
                .collect(),
        })
    }

    fn record(
        &self,
        source: &CascadeSource<'_>,
        track_id: u64,
        selection: &CascadeSelection,
        status: &FrameStatus,
        outcome: &EvidenceOutcome,
    ) -> Vec<u8> {
        let mut e = CanonicalEncoder::new();
        e.text(EVIDENCE_DOMAIN);
        e.digest(self.digest);
        e.digest(self.package.archive_digest());
        e.text(self.package.manifest().generation().as_str());
        e.digest(source.import_identity);
        e.u64(track_id);
        e.u64(selection.segment as u64);
        e.u8(selection.reason.tag());
        for value in selection.track_box {
            e.i128(i128::from(value));
        }
        match status {
            FrameStatus::Inferred(inferred) => {
                e.u8(0);
                e.digest(inferred.rgb_digest);
                e.digest(inferred.inference_identity);
                e.digest(inferred.input_digest);
                e.digest(inferred.output_digest);
                e.digest(inferred.detection_report_digest);
            }
            FrameStatus::BudgetExhausted => e.u8(1),
            FrameStatus::Refused(id) => {
                e.u8(2);
                e.text(id);
            }
        }
        match outcome {
            EvidenceOutcome::Associated { detection, iou_ppm } => {
                e.u8(0);
                e.u64(detection.row as u64);
                e.u64(detection.class_index as u64);
                e.text(&detection.label);
                e.u32(detection.score.to_bits());
                for value in detection.bounds {
                    e.u32(value);
                }
                e.u32(*iou_ppm);
            }
            EvidenceOutcome::NoAssociation { detections } => {
                e.u8(1);
                e.u64(*detections as u64);
            }
            EvidenceOutcome::BudgetExhausted => e.u8(2),
            EvidenceOutcome::Refused(id) => {
                e.u8(3);
                e.text(id);
            }
        }
        e.text("uncalibrated");
        e.finish()
    }

    fn infer(
        &mut self,
        deployment: &ReferenceDeployment,
        plan: &CascadeReadPlan<'_>,
        wanted: &BTreeSet<usize>,
        limits: &WatchLimits,
        cx: &ReplayCx,
    ) -> Result<(), CascadeError> {
        let source = plan.source;
        let ranges = plan.ranges(wanted)?;
        let package = self.package;
        let contract = self.contract.as_ref().unwrap_or_else(|| package.contract());
        let mut run = FrameRun {
            package,
            contract,
            run: self.limits.run,
            import_root: source.import_root,
            budget: RgbDetectionBudget::new(
                self.limits.detection_work_units,
                self.limits.detection_scratch_bytes,
            ),
            scalar: self.scalar,
            cx,
        };
        let labels = &contract.spec().labels;
        let mut results: Vec<(usize, FrameStatus)> = Vec::with_capacity(wanted.len());
        match source.media_format {
            "mjpeg" => {
                let retained = RetainedFileImport::open(
                    deployment,
                    source.import_identity,
                    limits.read_limits,
                    cx,
                )?;
                let mut budget = DecodeBudget::new(limits.jpeg_work_units);
                let (first_capsule, _) =
                    source_capsule(deployment, &retained, source.first_segment)?;
                let privacy_sensor = &first_capsule.sensor_id;
                let privacy =
                    current_mask(deployment, privacy_sensor).map_err(RecordedDecodeError::from)?;
                let rgb_limits = RgbDecodeLimits {
                    frame: limits.jpeg_limits,
                    maximum_output_bytes: MAX_RGB_BYTES,
                };
                for &segment in wanted {
                    cx.checkpoint("detector_cascade:decode")
                        .map_err(|_| CascadeError::Cancelled)?;
                    let (capsule, capsule_digest) = source_capsule(deployment, &retained, segment)?;
                    let bytes =
                        retained.read_segment(deployment, segment, limits.read_limits, cx)?;
                    let decoded = match decode_rgb(
                        &bytes,
                        capsule.source_digest.bytes(),
                        source.interpretation,
                        rgb_limits,
                        &mut budget,
                    ) {
                        Ok(image) => image,
                        Err(_) => {
                            results.push((segment, FrameStatus::Refused(CASCADE_FRAME_REFUSED)));
                            continue;
                        }
                    };
                    if capsule.sensor_id != *privacy_sensor {
                        results.push((segment, FrameStatus::Refused(CASCADE_FRAME_REFUSED)));
                        continue;
                    }
                    // The sensor's privacy mask is applied before the detector sees the frame.
                    results.push(
                        match DecodedFrame::jpeg(
                            segment,
                            capsule,
                            capsule_digest,
                            decoded,
                            privacy.clone(),
                        ) {
                            Ok(frame) => infer_one(&mut run, frame, labels)?,
                            Err(_) => (segment, FrameStatus::Refused(CASCADE_FRAME_REFUSED)),
                        },
                    );
                }
            }
            "annexb" => {
                for &(first_segment, count) in &ranges {
                    let mut range = RecordedH264Range::open(
                        deployment,
                        RecordedH264Request {
                            import_identity: source.import_identity,
                            first_segment,
                            segment_count: count,
                            interpretation: source.interpretation,
                            read_limits: limits.read_limits,
                            decoder_limits: limits.h264_limits,
                        },
                        cx,
                    )?;
                    while let Some(frame) = range.next_frame(deployment, cx)? {
                        let r = frame.receipt();
                        let segment = usize::try_from(r.segment_index())
                            .map_err(|_| CascadeError::InvalidConfig("segment index"))?;
                        if !wanted.contains(&segment) {
                            continue;
                        }
                        let picture = VideoPicture {
                            segment: r.segment_index(),
                            capsule: r.capsule(),
                            capsule_digest: r.capsule_digest(),
                            dimensions: r.dimensions(),
                            codec_receipt: r.digest(),
                            i420: r.i420_sha256(),
                            rgb: frame.to_rgb(),
                            mask: frame.mask().clone(),
                        };
                        results.push(match DecodedFrame::video(picture) {
                            Ok(decoded) => infer_one(&mut run, decoded, labels)?,
                            Err(_) => (segment, FrameStatus::Refused(CASCADE_FRAME_REFUSED)),
                        });
                    }
                }
            }
            "hevc" => {
                for &(first_segment, count) in &ranges {
                    let mut range = RecordedH265Range::open(
                        deployment,
                        RecordedH265Request {
                            import_identity: source.import_identity,
                            first_segment,
                            segment_count: count,
                            interpretation: source.interpretation,
                            read_limits: limits.read_limits,
                            decoder_limits: limits.h265_limits,
                        },
                        cx,
                    )?;
                    while let Some(frame) = range.next_frame(deployment, cx)? {
                        let r = frame.receipt();
                        let segment = usize::try_from(r.segment_index())
                            .map_err(|_| CascadeError::InvalidConfig("segment index"))?;
                        if !wanted.contains(&segment) {
                            continue;
                        }
                        let picture = VideoPicture {
                            segment: r.segment_index(),
                            capsule: r.capsule(),
                            capsule_digest: r.capsule_digest(),
                            dimensions: r.dimensions(),
                            codec_receipt: r.digest(),
                            i420: r.i420_sha256(),
                            rgb: frame.to_rgb(),
                            mask: frame.mask().clone(),
                        };
                        results.push(match DecodedFrame::video(picture) {
                            Ok(decoded) => infer_one(&mut run, decoded, labels)?,
                            Err(_) => (segment, FrameStatus::Refused(CASCADE_FRAME_REFUSED)),
                        });
                    }
                }
            }
            _ => return Err(RecordedDecodeError::UnsupportedMedia.into()),
        }
        for (segment, status) in results {
            if matches!(status, FrameStatus::Inferred(_)) {
                self.executed += 1;
            }
            self.cache.insert((source.import_identity, segment), status);
        }
        for segment in wanted {
            if !self.cache.contains_key(&(source.import_identity, *segment)) {
                return Err(CascadeError::InvalidConfig(
                    "a selected frame was not produced by retained decode",
                ));
            }
        }
        Ok(())
    }
}

fn infer_one(
    run: &mut FrameRun<'_>,
    decoded: DecodedFrame,
    labels: &[String],
) -> Result<(usize, FrameStatus), CascadeError> {
    let segment = decoded.segment;
    let rgb_digest = decoded.rgb_digest();
    let status = match run.infer(decoded) {
        Ok(frame) => FrameStatus::Inferred(Box::new(summarize(&frame, rgb_digest, labels))),
        Err(PackageDetectError::Cancelled) => return Err(CascadeError::Cancelled),
        Err(_) => FrameStatus::Refused(CASCADE_FRAME_REFUSED),
    };
    Ok((segment, status))
}

fn summarize(
    frame: &PackageDetectFrame,
    rgb_digest: ContentDigest,
    labels: &[String],
) -> InferredFrame {
    InferredFrame {
        color: frame.color,
        rgb_digest,
        inference_identity: frame.inference.identity(),
        input_digest: frame.inference.input_digest(),
        output_digest: frame.inference.output_digest(),
        detection_report_digest: frame.detections.digest(),
        executed_macs: frame.inference.executed_macs(),
        detections: frame
            .detections
            .detections()
            .iter()
            .map(|d| CascadeDetection {
                row: d.row(),
                class_index: d.class_index(),
                label: labels.get(d.class_index()).cloned().unwrap_or_default(),
                score: d.score(),
                bounds: d.bounds(),
            })
            .collect(),
    }
}

/// Integer IoU (parts per million) of a detection box and a track box, both on the 1/256-pixel
/// source grid. The track box `(cx, cy, w, h)` in pixels maps to `((2cx - w) * 128, ...)`.
#[must_use]
pub fn iou_ppm(bounds: [u32; 4], track_box: [i64; 4]) -> u32 {
    let [cx, cy, w, h] = track_box.map(i128::from);
    let track = [
        (2 * cx - w) * 128,
        (2 * cy - h) * 128,
        (2 * cx + w) * 128,
        (2 * cy + h) * 128,
    ];
    let detection = bounds.map(i128::from);
    let area = |b: [i128; 4]| (b[2] - b[0]).max(0) * (b[3] - b[1]).max(0);
    let inter = [
        detection[0].max(track[0]),
        detection[1].max(track[1]),
        detection[2].min(track[2]),
        detection[3].min(track[3]),
    ];
    let intersection = area(inter);
    let union = area(detection) + area(track) - intersection;
    if union <= 0 || intersection <= 0 {
        return 0;
    }
    u32::try_from(intersection * 1_000_000 / union).unwrap_or(1_000_000)
}

/// Best detection by IoU, then score, then lower row; below `minimum` is no association.
fn associate(
    inferred: &InferredFrame,
    selection: &CascadeSelection,
    minimum: u32,
) -> EvidenceOutcome {
    let mut best: Option<(&CascadeDetection, u32)> = None;
    for detection in &inferred.detections {
        let iou = iou_ppm(detection.bounds, selection.track_box);
        if iou < minimum || iou == 0 {
            continue;
        }
        let better = match best {
            None => true,
            Some((current, current_iou)) => {
                iou > current_iou
                    || (iou == current_iou
                        && (detection.score.total_cmp(&current.score).is_gt()
                            || (detection.score.to_bits() == current.score.to_bits()
                                && detection.row < current.row)))
            }
        };
        if better {
            best = Some((detection, iou));
        }
    }
    match best {
        Some((detection, iou_ppm)) => EvidenceOutcome::Associated {
            detection: detection.clone(),
            iou_ppm,
        },
        None => EvidenceOutcome::NoAssociation {
            detections: inferred.detections.len(),
        },
    }
}

fn json_string(value: &str) -> String {
    let mut out = String::with_capacity(value.len() + 2);
    out.push('"');
    for ch in value.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            c if u32::from(c) < 0x20 => {
                let _ = write!(out, "\\u{:04x}", u32::from(c));
            }
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

fn segments_json(segments: &[usize]) -> String {
    let items: Vec<String> = segments.iter().map(usize::to_string).collect();
    format!("[{}]", items.join(","))
}

fn detection_json(d: &CascadeDetection) -> String {
    format!(
        "{{\"row\":{},\"class_index\":{},\"label\":{},\"score\":{},\"bounds_subpixel\":[{},{},{},{}]}}",
        d.row,
        d.class_index,
        json_string(&d.label),
        d.score,
        d.bounds[0],
        d.bounds[1],
        d.bounds[2],
        d.bounds[3]
    )
}

/// JSON members describing the cascade policy and package (no surrounding braces).
#[must_use]
pub fn cascade_policy_json(cascade: &DetectorCascade<'_>) -> String {
    let package = cascade.package();
    let config = cascade.config();
    let contract = cascade.contract();
    format!(
        concat!(
            "\"cascade_digest\":\"{}\",\"policy_digest\":\"{}\",\"package_digest\":\"{}\",",
            "\"manifest_digest\":\"{}\",\"model_id\":{},\"generation\":{},\"model_digest\":\"{}\",",
            "\"contract_digest\":\"{}\",\"minimum_score_ppm\":{},\"frames_per_track\":{},",
            "\"max_inferences\":{},\"minimum_association_iou_ppm\":{},",
            "\"frame_selection\":\"zone_entry_then_confirmation_then_following_matches\",",
            "\"input\":\"full_frame_letterboxed_per_package_spec\",",
            "\"video_color_transform\":\"{}\",\"scores\":\"uncalibrated\",",
            "\"event_kind_policy\":\"unchanged_unclassified\",",
            "\"corroboration_effect\":\"none_same_sensor_failure_domain\",",
            "\"alert_effect\":\"none\",\"quality_claim\":\"none\""
        ),
        cascade.digest(),
        DetectorCascade::policy_digest(),
        package.archive_digest(),
        package.manifest_digest(),
        json_string(package.manifest().model_id().as_str()),
        json_string(package.manifest().generation().as_str()),
        package.model().digest(),
        contract.digest(),
        contract.spec().minimum_score_ppm,
        config.frames_per_track,
        config.max_inferences,
        config.minimum_association_iou_ppm,
        super::recorded_decode::video_rgb::VIDEO_RGB_TRANSFORM,
    )
}

/// JSON members describing one recording's cascade outcome (no surrounding braces).
#[must_use]
pub fn cascade_outcome_json(outcome: &CascadeOutcome) -> String {
    let frames: Vec<String> = outcome
        .frames
        .iter()
        .map(|frame| match &frame.status {
            FrameStatus::Inferred(inferred) => {
                let detections: Vec<String> =
                    inferred.detections.iter().map(detection_json).collect();
                format!(
                    concat!(
                        "{{\"segment\":{},\"status\":\"inferred\",\"color\":\"{}\",",
                        "\"rgb_digest\":\"{}\",\"inference_identity\":\"{}\",",
                        "\"input_digest\":\"{}\",\"output_digest\":\"{}\",",
                        "\"detection_report_digest\":\"{}\",\"executed_macs\":{},",
                        "\"detections\":[{}]}}"
                    ),
                    frame.segment,
                    inferred.color,
                    inferred.rgb_digest,
                    inferred.inference_identity,
                    inferred.input_digest,
                    inferred.output_digest,
                    inferred.detection_report_digest,
                    inferred.executed_macs,
                    detections.join(",")
                )
            }
            FrameStatus::BudgetExhausted => format!(
                "{{\"segment\":{},\"status\":\"budget_exhausted\",\"refusal_id\":\"{CASCADE_BUDGET_EXHAUSTED}\"}}",
                frame.segment
            ),
            FrameStatus::Refused(id) => format!(
                "{{\"segment\":{},\"status\":\"detector_refused\",\"refusal_id\":\"{id}\"}}",
                frame.segment
            ),
        })
        .collect();
    let budget = outcome.budget_skipped_segments();
    format!(
        concat!(
            "\"selected_segments\":{},\"inferred_segments\":{},\"budget_skipped_segments\":{},",
            "\"refused_segments\":{},\"cascade_skipped_segments\":{},\"inference_count\":{},",
            "\"budget_exhausted\":{},\"frames\":[{}]"
        ),
        segments_json(&outcome.frames.iter().map(|f| f.segment).collect::<Vec<_>>()),
        segments_json(&outcome.inferred_segments()),
        segments_json(&budget),
        segments_json(&outcome.refused_segments()),
        segments_json(&outcome.cascade_skipped),
        outcome.inferred_segments().len(),
        !budget.is_empty(),
        frames.join(",")
    )
}

/// JSON array of one track's class evidence.
#[must_use]
pub fn class_evidence_json(evidence: &[ClassEvidence]) -> String {
    let items: Vec<String> = evidence
        .iter()
        .map(|item| {
            let detail = match &item.outcome {
                EvidenceOutcome::Associated { detection, iou_ppm } => format!(
                    concat!(
                        ",\"label\":{},\"class_index\":{},\"score\":{},\"score_calibrated\":false,",
                        "\"iou_ppm\":{},\"bounds_subpixel\":[{},{},{},{}]"
                    ),
                    json_string(&detection.label),
                    detection.class_index,
                    detection.score,
                    iou_ppm,
                    detection.bounds[0],
                    detection.bounds[1],
                    detection.bounds[2],
                    detection.bounds[3]
                ),
                EvidenceOutcome::NoAssociation { detections } => {
                    format!(",\"frame_detections\":{detections}")
                }
                EvidenceOutcome::BudgetExhausted => {
                    format!(",\"refusal_id\":\"{CASCADE_BUDGET_EXHAUSTED}\"")
                }
                EvidenceOutcome::Refused(id) => format!(",\"refusal_id\":\"{id}\""),
            };
            format!(
                "{{\"segment\":{},\"selection\":\"{}\",\"outcome\":\"{}\"{detail},\"supports\":{},\"evidence_digest\":\"{}\"}}",
                item.segment,
                item.reason.as_str(),
                item.outcome.as_str(),
                item.supports(),
                item.digest
            )
        })
        .collect();
    format!("[{}]", items.join(","))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn selection_orders_entry_confirmation_then_following_and_respects_k() {
        let observations: Vec<(usize, [i64; 4])> =
            (2..10).map(|s| (s, [s as i64, 0, 4, 4])).collect();
        let one = select_frames(7, 4, &observations, 1);
        assert_eq!(one.len(), 1);
        assert_eq!(
            (one[0].segment, one[0].reason),
            (7, SelectionReason::ZoneEntry)
        );
        let three = select_frames(7, 4, &observations, 3);
        let picked: Vec<_> = three.iter().map(|s| (s.segment, s.reason)).collect();
        assert_eq!(
            picked,
            [
                (7, SelectionReason::ZoneEntry),
                (4, SelectionReason::Confirmation),
                (5, SelectionReason::FollowingMatch)
            ]
        );
        // Entry equal to confirmation is selected once; unmatched segments are never selected.
        let same = select_frames(4, 4, &observations, 8);
        assert_eq!(same.len(), 6);
        assert_eq!(same[0].segment, 4);
        assert!(select_frames(20, 20, &observations, 2).is_empty());
    }

    #[test]
    fn integer_iou_matches_hand_computation() {
        // Track box centred (10, 10), 8x8 -> pixels [6, 14) -> subpixels [1536, 3584).
        let track = [10, 10, 8, 8];
        assert_eq!(iou_ppm([1536, 1536, 3584, 3584], track), 1_000_000);
        // Detection shifted right by 4 px: intersection 4x8, union 12x8 -> 1/3.
        assert_eq!(iou_ppm([2560, 1536, 4608, 3584], track), 333_333);
        assert_eq!(iou_ppm([0, 0, 256, 256], track), 0);
    }

    #[test]
    fn invalid_cascade_bounds_are_typed() {
        for config in [
            CascadeConfig {
                frames_per_track: 0,
                ..CascadeConfig::default()
            },
            CascadeConfig {
                frames_per_track: 9,
                ..CascadeConfig::default()
            },
            CascadeConfig {
                max_inferences: 0,
                ..CascadeConfig::default()
            },
            CascadeConfig {
                max_inferences: 65,
                ..CascadeConfig::default()
            },
            CascadeConfig {
                minimum_association_iou_ppm: 1_000_001,
                ..CascadeConfig::default()
            },
            CascadeConfig {
                minimum_score_ppm: Some(1_000_001),
                ..CascadeConfig::default()
            },
        ] {
            let refused = config.validate();
            assert!(
                matches!(refused, Err(ref e) if e.stable_id() == "ERR-DETECTOR-CASCADE-PLAN-001"),
                "{config:?}"
            );
        }
        assert!(CascadeConfig::default().validate().is_ok());
    }

    #[test]
    fn association_prefers_iou_then_score_and_never_below_threshold() {
        let detection = |row, class_index: usize, score: f32, bounds| CascadeDetection {
            row,
            class_index,
            label: format!("c{class_index}"),
            score,
            bounds,
        };
        let inferred = InferredFrame {
            color: "jpeg_rgb",
            rgb_digest: ContentDigest::sha256(b"rgb"),
            inference_identity: ContentDigest::sha256(b"i"),
            input_digest: ContentDigest::sha256(b"in"),
            output_digest: ContentDigest::sha256(b"out"),
            detection_report_digest: ContentDigest::sha256(b"r"),
            executed_macs: 0,
            detections: vec![
                detection(1, 5, 0.9, [2560, 1536, 4608, 3584]),
                detection(2, 0, 0.4, [1536, 1536, 3584, 3584]),
                detection(3, 0, 0.8, [1536, 1536, 3584, 3584]),
            ],
        };
        let selection = CascadeSelection {
            segment: 3,
            reason: SelectionReason::ZoneEntry,
            track_box: [10, 10, 8, 8],
        };
        let chosen = associate(&inferred, &selection, 300_000);
        assert!(
            matches!(
                &chosen,
                EvidenceOutcome::Associated { detection, iou_ppm: 1_000_000 } if detection.row == 3
            ),
            "{chosen:?}"
        );
        let far = CascadeSelection {
            track_box: [100, 100, 8, 8],
            ..selection
        };
        assert_eq!(
            associate(&inferred, &far, 300_000),
            EvidenceOutcome::NoAssociation { detections: 3 }
        );
    }

    fn recovery_source<'a>(
        decoded: &'a [usize],
        refusals: &'a [super::super::tolerant_decode::DecodeRefusal],
        restarts: &'a [usize],
    ) -> RecoveredCascadeSource<'a> {
        RecoveredCascadeSource {
            source: CascadeSource {
                import_identity: ContentDigest::sha256(b"recovery-import"),
                import_root: ContentDigest::sha256(b"recovery-root"),
                interpretation: ComponentInterpretation::Grayscale,
                media_format: "annexb",
                first_segment: 0,
                decoded_segments: decoded,
            },
            decode_refusals: refusals,
            tracking_restarts: restarts,
        }
    }

    fn refusal(first: usize, last: usize) -> super::super::tolerant_decode::DecodeRefusal {
        super::super::tolerant_decode::DecodeRefusal {
            first_segment: first,
            last_segment: last,
            error_id: "ERR-DECODE-MALFORMED-001".to_owned(),
        }
    }

    fn selected(track_id: u64, segments: &[usize]) -> CascadeTrack {
        CascadeTrack {
            track_id,
            selections: segments.iter().map(|&segment| CascadeSelection {
                segment,
                reason: SelectionReason::ZoneEntry,
                track_box: [10, 10, 8, 8],
            }).collect(),
        }
    }

    #[test]
    fn clean_plan_preserves_one_range_and_decoder_display_order() -> Result<(), CascadeError> {
        let decoded = [0, 3, 1, 2, 6, 4, 5];
        let plan = CascadeReadPlan::build(recovery_source(&decoded, &[], &[]), &[])?;
        assert!(!plan.recovered);
        assert_eq!(plan.source.decoded_segments, decoded);
        assert_eq!(plan.ranges(&[2, 5].into())?, vec![(0, 6)]);
        Ok(())
    }

    #[test]
    fn recovered_video_reads_separate_ranges_without_refused_tails() -> Result<(), CascadeError> {
        let decoded = [0, 1, 2, 5, 6, 7, 10, 11];
        let refusals = [refusal(3, 4), refusal(8, 9)];
        let tracks = [selected(1, &[2]), selected(2, &[7, 5]), selected(3, &[11])];
        let plan = CascadeReadPlan::build(recovery_source(&decoded, &refusals, &[5, 10]), &tracks)?;
        assert!(plan.recovered);
        assert_eq!(plan.ranges(&[2, 5, 11].into())?, vec![(0, 3), (5, 1), (10, 2)]);
        // No work is spent decoding an epoch with no admitted selections.
        assert_eq!(plan.ranges(&[11].into())?, vec![(10, 2)]);
        Ok(())
    }

    #[test]
    fn leading_and_trailing_refusals_do_not_extend_native_ranges() -> Result<(), CascadeError> {
        let refusals = [refusal(0, 3), refusal(7, 9)];
        let plan = CascadeReadPlan::build(recovery_source(&[4, 5, 6], &refusals, &[]), &[])?;
        assert_eq!(plan.ranges(&[5].into())?, vec![(4, 2)]);
        Ok(())
    }

    #[test]
    fn restart_without_a_missing_frame_is_still_a_decode_boundary() -> Result<(), CascadeError> {
        let plan = CascadeReadPlan::build(recovery_source(&[0, 1, 2, 3, 4], &[], &[3]), &[])?;
        assert_eq!(plan.ranges(&[2, 4].into())?, vec![(0, 3), (3, 2)]);
        Ok(())
    }

    #[test]
    fn recovery_never_guesses_a_restart_across_a_refusal() {
        let refusals = [refusal(2, 3)];
        assert!(matches!(
            CascadeReadPlan::build(recovery_source(&[0, 1, 4, 5], &refusals, &[]), &[]),
            Err(CascadeError::InvalidConfig("refusal lacks a tracking restart"))
        ));
    }

    #[test]
    fn track_selections_cannot_bridge_restarts() {
        let tracks = [selected(1, &[1, 3])];
        assert!(matches!(
            CascadeReadPlan::build(recovery_source(&[0, 1, 2, 3], &[], &[2]), &tracks),
            Err(CascadeError::InvalidConfig("track selection crosses a recovery boundary"))
        ));
    }

    #[test]
    fn selections_must_belong_to_actual_decoded_frames() {
        let tracks = [selected(1, &[2])];
        let refusals = [refusal(2, 2)];
        assert!(matches!(
            CascadeReadPlan::build(recovery_source(&[0, 1, 3, 4], &refusals, &[3]), &tracks),
            Err(CascadeError::InvalidConfig("selected segment was not decoded"))
        ));
    }

    #[test]
    fn recovery_rejects_contradictory_duplicate_and_noncanonical_diagnostics() {
        let decoded = [0, 1, 4, 5];
        for (refusals, restarts) in [
            (vec![refusal(2, 3)], vec![4, 4]),
            (vec![refusal(2, 3)], vec![5, 4]),
            (vec![refusal(2, 3)], vec![3]),
            (vec![refusal(3, 2)], vec![4]),
            (vec![refusal(2, 3), refusal(3, 3)], vec![4]),
            (vec![refusal(0, 0)], vec![4]),
        ] {
            assert!(matches!(
                CascadeReadPlan::build(recovery_source(&decoded, &refusals, &restarts), &[]),
                Err(CascadeError::InvalidConfig(_))
            ));
        }
        assert!(matches!(
            CascadeReadPlan::build(recovery_source(&[0, 1, 1], &[], &[]), &[]),
            Err(CascadeError::InvalidConfig("duplicate decoded segment"))
        ));
    }

    #[test]
    fn recovery_planning_is_bounded_and_uses_checked_segment_arithmetic() -> Result<(), CascadeError> {
        let decoded = [usize::MAX];
        let mut source = recovery_source(&decoded, &[], &[]);
        source.source.first_segment = usize::MAX;
        let plan = CascadeReadPlan::build(source, &[])?;
        assert_eq!(plan.ranges(&[usize::MAX].into())?, vec![(usize::MAX, 1)]);
        assert!(matches!(
            CascadeReadPlan::build(recovery_source(&[0, 128], &[], &[]), &[]),
            Err(CascadeError::InvalidConfig("invalid recovery diagnostics"))
        ));
        Ok(())
    }

    #[test]
    fn inference_admission_preserves_priority_deduplication_and_cross_camera_budget() -> Result<(), CascadeError> {
        let tracks = [selected(1, &[7, 4, 5]), selected(2, &[4, 11])];
        let mut budget = CascadeBudget { remaining: 3 };
        let (order, admitted) = admit_selected_frames(&tracks, 3, &mut budget)?;
        assert_eq!(order, vec![7, 4, 5, 11]);
        assert_eq!(admitted, [4, 5, 7].into());
        assert_eq!(budget.remaining(), 0);
        let (second_order, second_admitted) = admit_selected_frames(&[selected(1, &[1, 8])], 3, &mut budget)?;
        assert_eq!(second_order, vec![1, 8]);
        assert!(second_admitted.is_empty());
        assert_eq!(budget.remaining(), 0);
        Ok(())
    }

    #[test]
    fn invalid_selection_does_not_consume_an_allowance() {
        let mut budget = CascadeBudget { remaining: 3 };
        let result = admit_selected_frames(&[selected(1, &[1]), selected(2, &[4, 5])], 1, &mut budget);
        assert!(matches!(result, Err(CascadeError::InvalidConfig(_))));
        assert_eq!(budget.remaining(), 3);
    }

    #[test]
    fn all_small_loss_patterns_keep_every_selected_decode_inside_its_epoch() -> Result<(), CascadeError> {
        for mask in 1u16..256 {
            let decoded: Vec<usize> = (0..8).filter(|s| mask & (1 << s) != 0).collect();
            let mut refusals = Vec::new();
            let mut restarts = Vec::new();
            let mut segment = 0;
            while segment < 8 {
                if decoded.contains(&segment) {
                    if segment > 0 && !decoded.contains(&(segment - 1)) && segment != decoded[0] {
                        restarts.push(segment);
                    }
                    segment += 1;
                } else {
                    let first = segment;
                    while segment < 8 && !decoded.contains(&segment) { segment += 1; }
                    refusals.push(refusal(first, segment - 1));
                }
            }
            let plan = CascadeReadPlan::build(recovery_source(&decoded, &refusals, &restarts), &[])?;
            for subset in 0u16..256 {
                if subset & !mask != 0 { continue; }
                let wanted: BTreeSet<usize> = (0..8).filter(|s| subset & (1 << s) != 0).collect();
                let ranges = plan.ranges(&wanted)?;
                let mut covered = BTreeSet::new();
                for (first, count) in ranges {
                    assert!(wanted.contains(&(first + count - 1)));
                    for index in first..first + count {
                        assert!(decoded.contains(&index), "mask={mask} subset={subset} index={index}");
                        assert!(covered.insert(index));
                    }
                    assert!(!restarts.iter().any(|s| *s > first && *s < first + count));
                }
                assert!(wanted.is_subset(&covered));
            }
        }
        Ok(())
    }
}
