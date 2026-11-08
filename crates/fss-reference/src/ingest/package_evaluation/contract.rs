#![forbid(unsafe_code)]
//! Pure, bounded projection of actual package-track data into event-evaluation inputs.
//!
//! Public records describe inputs; they do not authenticate source custody. The enclosing
//! native owner reconstructs these inputs from retained authority and revalidates them before
//! releasing a result. This module never executes a model or manufactures coverage evidence.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use fss_core::{
    CanonicalEncode, CanonicalEncoder, CaptureInterval, ClockBasis, ContentDigest, DigestAlgorithm,
    LedgerAnchor, SensorId, StreamId,
};

use crate::evaluation::{
    CandidateSet, EvaluationIdentity, EvaluationPolicy, EventCandidate, LabelSet,
};
use crate::ingest::package_event::types::{
    PackageDetectionRecord, PackageObservation, PackageTrack, PackageTrackingBoundary,
    PackageTrackingConfig, RecordFrame, sample_confirmed,
};

/// Maximum complete source frames admitted by this one-clip consumer.
pub const MAX_PACKAGE_EVALUATION_FRAMES: usize = 64;
/// Maximum tracks; every native track must fit, including tentative and excluded tracks.
pub const MAX_PACKAGE_EVALUATION_TRACKS: usize = 128;
/// Maximum truth events in the one selected clip.
pub const MAX_PACKAGE_EVALUATION_TRUTHS: usize = 128;
/// Maximum explicitly declared not-observable intervals.
pub const MAX_PACKAGE_EVALUATION_GAPS: usize = 128;
/// Maximum candidate/truth cells reserved before native matching.
pub const MAX_PACKAGE_EVALUATION_MATCHING_CELLS: usize = 16_384;
/// Maximum canonical projection bytes, excluding the separately bound evaluation report.
pub const MAX_PACKAGE_EVALUATION_PROJECTION_BYTES: usize = 1024 * 1024;
/// Maximum metadata-only native JSON output bytes.
pub const MAX_PACKAGE_EVALUATION_OUTPUT_BYTES: usize = 1024 * 1024;
/// One nonrenewing original-source allowance shared across read and final revalidation.
pub const MAX_PACKAGE_EVALUATION_SOURCE_BYTES: u64 = 4 * 1024 * 1024 * 1024;
/// Canonical identity of the exact source-to-candidate projection.
pub const PACKAGE_EVALUATION_PROJECTION_DOMAIN: &str = "fss.package_evaluation_projection.v1";
/// Complete fixed extraction policy, including temporal and score semantics.
pub const PACKAGE_EVALUATION_POLICY_DOMAIN: &str = "fss.package_evaluation_policy.v1";
/// Candidate identities bind native provenance and the explicit clip mapping.
pub const PACKAGE_EVALUATION_CANDIDATE_DOMAIN: &str = "fss.package_evaluation_candidate.v1";
/// Exact model/head/label comparison space used by this evaluation.
pub const PACKAGE_EVALUATION_MODEL_DOMAIN: &str = "fss.package_evaluation_model.v1";
/// Fixed pipeline and tracker generation, independent of the evaluated input clip.
pub const PACKAGE_EVALUATION_PIPELINE_DOMAIN: &str = "fss.package_evaluation_pipeline.v1";

const MAX_TEXT: usize = 512;
const MAX_LABELS: usize = 256;
const MAX_FRAME_DETECTIONS: usize = 256;
const POLICY: &str = "one-clip:one-native-label:no-zone:no-class-upgrade:all-native-tracks:\
first-confirmed-assigned-row:no-hindsight:no-later-replacement:floor-f32-score-to-ppm:\
fixed-retained-threshold-and-nms:operator-assumed-singleton-time:strict-display-time-order:\
sample-hull-subwindow:no-guessed-cadence-or-tail:no-source-or-sequence-gap:\
declared-label-gaps-only:no-coverage-or-activation-authority";

/// Fixed interpretation limits, also bound by the versioned projection policy.
pub const PACKAGE_EVALUATION_LIMITATIONS: &[&str] = &[
    "Detector scores are uncalibrated; the curve conditions on the retained detector threshold and NMS policy.",
    "Capture times remain operator assumptions. The declared label gaps are not independently certified coverage.",
    "The clip window lies inside the analysed sample hull; no frame cadence or trailing duration is inferred.",
    "Only the selected native class is evaluated. This is no identity, intrusion, alert, activation or held-out quality qualification.",
];

/// Complete caller-declared scope; no caller-supplied candidate rows are accepted.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PackageEvaluationRequest {
    /// Exact already-retained native package-detection report.
    pub report_digest: ContentDigest,
    /// Exact native vocabulary label, also the evaluation class.
    pub label: String,
    /// Exact tracker recipe reconstructed by the package owner.
    pub tracking: PackageTrackingConfig,
    /// Identifier of the single labeled clip.
    pub clip_id: String,
    /// Clip-relative zero on the explicitly pinned source clock.
    pub clip_origin_ns: i128,
    /// Exact source stream-generation identity.
    pub stream_id: String,
    /// Original clock basis; no conversion or synchronization is inferred.
    pub clock_basis: ClockBasis,
}

impl PackageEvaluationRequest {
    /// Refuse unsupported scope before opening retained custody.
    pub fn validate(&self) -> Result<()> {
        if !sha(self.report_digest)
            || !identifier(&self.label, 128)
            || !identifier(&self.clip_id, 128)
            || self.stream_id.len() > MAX_TEXT
            || StreamId::parse(self.stream_id.as_str()).is_err()
            || !(1..=MAX_PACKAGE_EVALUATION_FRAMES as u32)
                .contains(&self.tracking.confirmation_hits)
            || !(1..=MAX_PACKAGE_EVALUATION_FRAMES as u32)
                .contains(&self.tracking.maximum_missed_frames)
            || self.tracking.minimum_iou_ppm > 1_000_000
        {
            return Err(PackageEvaluationError::Invalid(
                "request scope or tracking policy",
            ));
        }
        Ok(())
    }
}

/// Source facts copied from one exact authenticated capsule by the native owner.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PackageEvaluationFrameBinding {
    /// Source segment coordinate, not a timestamp or display-order index.
    pub segment: u64,
    /// Exact canonical capsule payload digest.
    pub capsule_digest: ContentDigest,
    /// Original encoded media bytes named by the capsule.
    pub source_digest: ContentDigest,
    /// Authenticated source sensor.
    pub sensor_id: String,
    /// Authenticated source stream generation.
    pub stream_id: String,
    /// Authenticated source sequence number.
    pub sequence: u64,
    /// Original source clock basis.
    pub clock_basis: ClockBasis,
    /// Full source capture interval; this policy requires a singleton.
    pub capture: CaptureInterval,
    /// Whether this capsule declares a preceding source gap.
    pub gap_before: bool,
}

/// Full retained-source and current-authority binding supplied by the native owner.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PackageEvaluationSourceBinding {
    /// Actual local deployment lineage, checked against current and retained anchors.
    pub site_lineage: String,
    /// Actual native read principal; a caller label never substitutes for this authority.
    pub principal: String,
    /// Exact source-rebuilt package-analysis digest.
    pub analysis_digest: ContentDigest,
    /// Exact retained package-detection record payload.
    pub record_digest: ContentDigest,
    /// Exact package-detection retained root.
    pub retained_root: ContentDigest,
    /// Package-detection retention authority.
    pub retained_anchor: LedgerAnchor,
    /// Current authority used to check custody and privacy.
    pub authority_anchor: LedgerAnchor,
    /// Exact original-import manifest digest.
    pub import_manifest_digest: ContentDigest,
    /// Current authenticated privacy binding, including an explicit no-policy marker.
    pub privacy_binding: ContentDigest,
    /// Current retained mask policy, or its explicit absence.
    pub privacy_policy: Option<ContentDigest>,
    /// Original import's timing label; only operator_assumption is admitted here.
    pub capture_time_label: String,
    /// Whether the import omitted any non-container-structure source bytes.
    pub non_container_omissions: bool,
    /// First source gap after segment zero anywhere in the import, including before this range.
    pub first_source_gap: Option<u64>,
    /// Every analysed frame's authenticated source facts.
    pub frames: Vec<PackageEvaluationFrameBinding>,
    /// Exact source-rebuilt tracking epoch boundaries.
    pub boundaries: Vec<PackageTrackingBoundary>,
}

/// The actual assigned observation at which a native track first became confirmed.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PackageEvaluationConfirmation {
    /// Zero-based observation index in native display order.
    pub observation_index: usize,
    /// Native source segment.
    pub segment: u64,
    /// Source capsule payload.
    pub capsule_digest: ContentDigest,
    /// Original encoded media bytes.
    pub source_digest: ContentDigest,
    /// Native model invocation identity.
    pub inference_identity: ContentDigest,
    /// Actual output tensor digest.
    pub output_digest: ContentDigest,
    /// Actual native detector-head report.
    pub detection_report_digest: ContentDigest,
    /// Assigned native detector row.
    pub detection_row: u64,
    /// Exact selected vocabulary index.
    pub class_index: u64,
    /// Original uncalibrated binary32 score bits.
    pub score_bits: u32,
    /// Fixed floor(score * 1_000_000), never a calibrated probability.
    pub score_ppm: u32,
    /// Singleton capture instant on the original pinned clock.
    pub capture_ns: i128,
}

/// Exhaustive fate of one native track in this explicit clip window.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PackageEvaluationTrackDisposition {
    /// First native confirmation emitted one candidate inside the clip.
    Candidate,
    /// No actual observation reached native confirmation.
    Unconfirmed,
    /// First confirmation preceded this clip; later samples do not replace it.
    BeforeClip,
    /// First confirmation was at or after the exclusive clip end.
    AfterClip,
}

impl PackageEvaluationTrackDisposition {
    /// Stable report token.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Candidate => "candidate",
            Self::Unconfirmed => "unconfirmed",
            Self::BeforeClip => "first_confirmation_before_clip",
            Self::AfterClip => "first_confirmation_after_clip",
        }
    }
}

/// Complete track accounting, including tentative and temporally excluded tracks.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PackageEvaluationTrackProvenance {
    /// Native analysis-local track identity, not a physical identity.
    pub track: ContentDigest,
    /// Native tracker number, never recycled across an epoch boundary.
    pub track_id: u64,
    /// Number of actual assigned observations.
    pub observations: usize,
    /// Exhaustive projection outcome.
    pub disposition: PackageEvaluationTrackDisposition,
    /// Exact first confirmation, even when outside the clip.
    pub first_confirmation: Option<PackageEvaluationConfirmation>,
    /// The emitted candidate, present exactly for Candidate disposition.
    pub candidate: Option<EventCandidate>,
}

/// Typed complete provenance of the pure projection; the native owner authenticates its source.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PackageEvaluationProvenance {
    /// Explicit clip mapping and native tracking request.
    pub request: PackageEvaluationRequest,
    /// Exact retained source and current authority facts.
    pub source: PackageEvaluationSourceBinding,
    /// Package archive identity.
    pub package_digest: ContentDigest,
    /// Package manifest identity.
    pub manifest_digest: ContentDigest,
    /// Built model identity.
    pub model_digest: ContentDigest,
    /// Graph artifact identity.
    pub graph_digest: ContentDigest,
    /// Applied detector-head identity, including its threshold/NMS contract.
    pub contract_digest: ContentDigest,
    /// Actual immutable native model identifier.
    pub model_id: String,
    /// Actual immutable native model generation.
    pub model_generation: String,
    /// Selected vocabulary index.
    pub class_index: u64,
    /// Original import identity.
    pub import_identity: ContentDigest,
    /// Original import root.
    pub import_root: ContentDigest,
    /// Original media format.
    pub media_format: String,
    /// Exact first source segment analysed.
    pub first_segment: u64,
    /// Complete number of source segments analysed.
    pub segment_count: u64,
    /// Retained detector floor; no detections below it are reconstructed.
    pub minimum_score_ppm: u32,
    /// Caller-declared clip duration, fenced inside the analysed sample hull.
    pub clip_duration_ns: u64,
    /// Inclusive first and last authenticated sample instants in native display order.
    pub analysed_sample_hull: [i128; 2],
    /// All native tracks, canonically ordered by tracker number.
    pub tracks: Vec<PackageEvaluationTrackProvenance>,
}

/// Deterministic candidates and metadata; only the enclosing retained owner seals custody.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PackageEvaluationProjection {
    /// Actual model/pipeline/policy identities supplied to the scoring engine.
    pub identity: EvaluationIdentity,
    /// One event candidate per eligible native first confirmation.
    pub candidates: CandidateSet,
    /// Complete source and track accounting.
    pub provenance: PackageEvaluationProvenance,
    /// SHA-256 of the canonical provenance and candidate bytes.
    pub digest: ContentDigest,
    bytes: Vec<u8>,
}

impl PackageEvaluationProjection {
    /// Exact canonical bytes bound by digest; no media payload is included.
    pub fn encoded(&self) -> &[u8] {
        &self.bytes
    }
}

/// Typed complete refusal of the pure scope or projection; no partial candidate set escapes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PackageEvaluationError {
    /// Unsupported or malformed operator declaration.
    Invalid(&'static str),
    /// Source, record or assignment fields disagree.
    Mismatch(&'static str),
    /// Collection or canonical output bounds exceeded.
    Limit,
    /// Checked clip-time arithmetic cannot be represented.
    TimeOverflow,
    /// Cooperative cancellation observed before result publication.
    Cancelled,
}

impl fmt::Display for PackageEvaluationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Invalid(why) => write!(f, "package evaluation scope invalid: {why}"),
            Self::Mismatch(why) => write!(f, "package evaluation source mismatch: {why}"),
            Self::Limit => f.write_str("package evaluation bound exceeded"),
            Self::TimeOverflow => f.write_str("package evaluation clip time overflow"),
            Self::Cancelled => f.write_str("package evaluation cancelled"),
        }
    }
}
impl std::error::Error for PackageEvaluationError {}
impl PackageEvaluationError {
    /// Stable metadata-only report refusal code.
    pub const fn code(self) -> &'static str {
        match self {
            Self::Invalid(_) => "evaluation.retained.invalid",
            Self::Mismatch(_) => "evaluation.retained.mismatch",
            Self::Limit => "evaluation.retained.limit",
            Self::TimeOverflow => "evaluation.retained.time_overflow",
            Self::Cancelled => "evaluation.cancelled",
        }
    }
}
type Result<T> = std::result::Result<T, PackageEvaluationError>;

fn identifier(value: &str, maximum: usize) -> bool {
    !value.is_empty()
        && value.len() <= maximum
        && value.bytes().all(|byte| (0x21..=0x7e).contains(&byte))
}
fn sha(digest: ContentDigest) -> bool {
    digest.algorithm() == DigestAlgorithm::Sha256
}
fn checkpoint(cancelled: &dyn Fn() -> bool) -> Result<()> {
    if cancelled() {
        Err(PackageEvaluationError::Cancelled)
    } else {
        Ok(())
    }
}

/// Fixed deterministic projection from complete native track data.
///
/// No truth interval influences the selected observation, score, identity or confirmation.
/// The single declared clip fences time; label gaps are passed unchanged to the evaluator.
pub fn project_package_candidates(
    request: &PackageEvaluationRequest,
    source: &PackageEvaluationSourceBinding,
    record: &PackageDetectionRecord,
    tracks: &[PackageTrack],
    labels: &LabelSet,
    policy: &EvaluationPolicy,
    cancelled: &dyn Fn() -> bool,
) -> Result<PackageEvaluationProjection> {
    checkpoint(cancelled)?;
    request.validate()?;
    let duration = validate_labels(request, labels, policy)?;
    if !(2..=MAX_PACKAGE_EVALUATION_FRAMES).contains(&record.frames.len())
        || record.segment_count != record.frames.len() as u64
        || source.frames.len() != record.frames.len()
        || tracks.len() > MAX_PACKAGE_EVALUATION_TRACKS
        || source.boundaries.len() >= MAX_PACKAGE_EVALUATION_FRAMES
        || record.labels.is_empty()
        || record.labels.len() > MAX_LABELS
    {
        return Err(PackageEvaluationError::Limit);
    }
    let end_segment = record
        .first_segment
        .checked_add(record.segment_count)
        .ok_or(PackageEvaluationError::Limit)?;
    if record.report_digest != request.report_digest
        || record.minimum_score_ppm > 1_000_000
        || !identifier(&record.model_id, MAX_TEXT)
        || !identifier(&record.generation, MAX_TEXT)
        || !identifier(&record.media_format, MAX_TEXT)
        || record
            .labels
            .iter()
            .any(|label| label.is_empty() || label.len() > MAX_TEXT)
        || record.labels.iter().collect::<BTreeSet<_>>().len() != record.labels.len()
        || [
            record.report_digest,
            record.package_digest,
            record.manifest_digest,
            record.model_digest,
            record.graph_digest,
            record.contract_digest,
            record.import_identity,
            record.import_root,
            source.analysis_digest,
            source.record_digest,
            source.retained_root,
            source.import_manifest_digest,
            source.privacy_binding,
            source.retained_anchor.state_root,
            source.authority_anchor.state_root,
        ]
        .into_iter()
        .any(|digest| !sha(digest))
        || source.privacy_policy.is_some_and(|digest| !sha(digest))
        || source.retained_anchor.site_lineage != source.authority_anchor.site_lineage
        || source.site_lineage != source.authority_anchor.site_lineage
        || source.retained_anchor.ledger_epoch != source.authority_anchor.ledger_epoch
        || source.retained_anchor.commit_sequence > source.authority_anchor.commit_sequence
        || !identifier(&source.retained_anchor.site_lineage, MAX_TEXT)
        || !identifier(&source.principal, MAX_TEXT)
    {
        return Err(PackageEvaluationError::Mismatch(
            "record, generation or authority pins",
        ));
    }
    let class_index = record
        .labels
        .iter()
        .position(|label| label == &request.label)
        .ok_or(PackageEvaluationError::Mismatch("selected native label"))?
        as u64;
    if source.capture_time_label != "operator_assumption"
        || source.non_container_omissions
        || source.first_source_gap.is_some_and(|gap| gap < end_segment)
    {
        return Err(PackageEvaluationError::Invalid(
            "unknown or discontinuous source time",
        ));
    }
    if source
        .boundaries
        .windows(2)
        .any(|pair| pair[0].before_segment >= pair[1].before_segment)
        || source.boundaries.iter().any(|boundary| {
            boundary.before_segment <= record.first_segment
                || boundary.before_segment >= end_segment
                || boundary.source_gap
                || boundary.sequence_gap
                || !boundary.dimensions_changed
        })
    {
        return Err(PackageEvaluationError::Invalid(
            "source continuity boundaries",
        ));
    }
    let source_frames = validate_frames(request, source, record, end_segment, cancelled)?;
    let first = record.frames[0].capture.earliest.0;
    let last = record.frames[record.frames.len() - 1].capture.latest.0;
    let hull_end = last
        .checked_add(1)
        .ok_or(PackageEvaluationError::TimeOverflow)?;
    let clip_end = request
        .clip_origin_ns
        .checked_add(i128::from(duration))
        .ok_or(PackageEvaluationError::TimeOverflow)?;
    if request.clip_origin_ns < first || clip_end > hull_end {
        return Err(PackageEvaluationError::Invalid(
            "clip lies outside analysed sample hull",
        ));
    }

    let mut sorted: Vec<_> = tracks.iter().collect();
    sorted.sort_unstable_by_key(|track| track.track_id);
    let frames: BTreeMap<_, _> = record
        .frames
        .iter()
        .enumerate()
        .map(|(index, frame)| (frame.segment, (index, frame)))
        .collect();
    let mut ids = BTreeSet::new();
    let mut identities = BTreeSet::new();
    let mut assignments = BTreeSet::new();
    let mut provenance = Vec::with_capacity(tracks.len());
    let mut candidates = Vec::new();
    for track in sorted {
        checkpoint(cancelled)?;
        if track.track_id == 0
            || !ids.insert(track.track_id)
            || !sha(track.identity)
            || !identities.insert(track.identity)
            || track.observations.is_empty()
            || track.observations.len() > record.frames.len()
            || track.confirmed != sample_confirmed(request.tracking, track.observations.len() - 1)
        {
            return Err(PackageEvaluationError::Mismatch(
                "native track shape or confirmation",
            ));
        }
        let mut previous_index = None;
        let mut epoch = None;
        let mut first_confirmation = None;
        for (index, observation) in track.observations.iter().enumerate() {
            checkpoint(cancelled)?;
            let &(frame_index, frame) =
                frames
                    .get(&observation.segment)
                    .ok_or(PackageEvaluationError::Mismatch(
                        "observation source segment",
                    ))?;
            if previous_index.is_some_and(|previous| previous >= frame_index) {
                return Err(PackageEvaluationError::Mismatch(
                    "native observation display order",
                ));
            }
            if let Some(previous) = previous_index {
                let distance = frame_index - previous;
                let was_confirmed = sample_confirmed(request.tracking, index - 1);
                if (!was_confirmed && distance != 1)
                    || (was_confirmed
                        && distance > request.tracking.maximum_missed_frames as usize + 1)
                {
                    return Err(PackageEvaluationError::Mismatch(
                        "track survived a native retirement boundary",
                    ));
                }
            }
            previous_index = Some(frame_index);
            let frame_epoch = source
                .boundaries
                .partition_point(|boundary| boundary.before_segment <= observation.segment);
            if epoch.is_some_and(|previous| previous != frame_epoch) {
                return Err(PackageEvaluationError::Mismatch(
                    "track crosses a source epoch",
                ));
            }
            epoch = Some(frame_epoch);
            let (row, bits) = validate_assignment(observation, frame, class_index)?;
            if !assignments.insert((observation.segment, row, class_index)) {
                return Err(PackageEvaluationError::Mismatch(
                    "source row assigned to multiple tracks",
                ));
            }
            if first_confirmation.is_none() && sample_confirmed(request.tracking, index) {
                let bound = source_frames.get(&observation.segment).ok_or(
                    PackageEvaluationError::Mismatch("confirmation source capsule"),
                )?;
                first_confirmation = Some(PackageEvaluationConfirmation {
                    observation_index: index,
                    segment: observation.segment,
                    capsule_digest: observation.capsule_digest,
                    source_digest: bound.source_digest,
                    inference_identity: frame.inference_identity,
                    output_digest: frame.output_digest,
                    detection_report_digest: frame.detection_report_digest,
                    detection_row: row,
                    class_index,
                    score_bits: bits,
                    score_ppm: score_ppm(bits)?,
                    capture_ns: frame.capture.earliest.0,
                });
            }
        }
        let (disposition, candidate) = match &first_confirmation {
            None => (PackageEvaluationTrackDisposition::Unconfirmed, None),
            Some(sample) if sample.capture_ns < request.clip_origin_ns => {
                (PackageEvaluationTrackDisposition::BeforeClip, None)
            }
            Some(sample) if sample.capture_ns >= clip_end => {
                (PackageEvaluationTrackDisposition::AfterClip, None)
            }
            Some(sample) => {
                let detect_ns = sample
                    .capture_ns
                    .checked_sub(request.clip_origin_ns)
                    .and_then(|value| u64::try_from(value).ok())
                    .ok_or(PackageEvaluationError::TimeOverflow)?;
                let candidate = EventCandidate {
                    candidate_id: candidate_id(
                        request,
                        source.analysis_digest,
                        track.identity,
                        sample,
                    ),
                    clip_id: request.clip_id.clone(),
                    class: request.label.clone(),
                    zone: None,
                    detect_ns,
                    score_ppm: sample.score_ppm,
                };
                candidates.push(candidate.clone());
                (
                    PackageEvaluationTrackDisposition::Candidate,
                    Some(candidate),
                )
            }
        };
        provenance.push(PackageEvaluationTrackProvenance {
            track: track.identity,
            track_id: track.track_id,
            observations: track.observations.len(),
            disposition,
            first_confirmation,
            candidate,
        });
    }
    if candidates
        .len()
        .checked_mul(labels.events.len())
        .is_none_or(|cells| cells > MAX_PACKAGE_EVALUATION_MATCHING_CELLS)
    {
        return Err(PackageEvaluationError::Limit);
    }
    candidates.sort_unstable_by(|left, right| left.candidate_id.cmp(&right.candidate_id));
    let identity = identities_for(request, record, class_index, policy);
    let mut canonical_source = source.clone();
    canonical_source
        .frames
        .sort_unstable_by_key(|frame| frame.segment);
    let provenance = PackageEvaluationProvenance {
        request: request.clone(),
        source: canonical_source,
        package_digest: record.package_digest,
        manifest_digest: record.manifest_digest,
        model_digest: record.model_digest,
        graph_digest: record.graph_digest,
        contract_digest: record.contract_digest,
        model_id: record.model_id.clone(),
        model_generation: record.generation.clone(),
        class_index,
        import_identity: record.import_identity,
        import_root: record.import_root,
        media_format: record.media_format.clone(),
        first_segment: record.first_segment,
        segment_count: record.segment_count,
        minimum_score_ppm: record.minimum_score_ppm,
        clip_duration_ns: duration,
        analysed_sample_hull: [first, last],
        tracks: provenance,
    };
    checkpoint(cancelled)?;
    let bytes = encode_projection(&identity, &provenance);
    if bytes.len() > MAX_PACKAGE_EVALUATION_PROJECTION_BYTES {
        return Err(PackageEvaluationError::Limit);
    }
    let digest = ContentDigest::sha256(&bytes);
    checkpoint(cancelled)?;
    Ok(PackageEvaluationProjection {
        identity,
        candidates: CandidateSet { candidates },
        provenance,
        digest,
        bytes,
    })
}

/// Validate the bounded label/policy scope before native custody work.
pub fn validate_package_evaluation_scope(
    request: &PackageEvaluationRequest,
    labels: &LabelSet,
    policy: &EvaluationPolicy,
) -> Result<()> {
    request.validate()?;
    validate_labels(request, labels, policy).map(|_| ())
}

/// Compatibility name for the complete pre-I/O request, labels and policy admission.
pub fn validate_package_evaluation_inputs(
    request: &PackageEvaluationRequest,
    labels: &LabelSet,
    policy: &EvaluationPolicy,
) -> Result<()> {
    validate_package_evaluation_scope(request, labels, policy)
}

fn validate_labels(
    request: &PackageEvaluationRequest,
    labels: &LabelSet,
    policy: &EvaluationPolicy,
) -> Result<u64> {
    if labels.clips.len() != 1 || labels.events.len() > MAX_PACKAGE_EVALUATION_TRUTHS {
        return Err(PackageEvaluationError::Limit);
    }
    let clip = &labels.clips[0];
    if clip.clip_id != request.clip_id
        || clip.duration_ns == 0
        || policy.false_alert_budget.per_observed_ns == 0
    {
        return Err(PackageEvaluationError::Invalid(
            "one exact labeled clip and finite budget required",
        ));
    }
    if clip.not_observable.len() > MAX_PACKAGE_EVALUATION_GAPS {
        return Err(PackageEvaluationError::Limit);
    }
    let valid_interval = |span: crate::evaluation::ClosedIntervalNs| {
        span.start_ns <= span.end_ns && span.end_ns < clip.duration_ns
    };
    if clip
        .not_observable
        .iter()
        .any(|gap| !valid_interval(gap.interval))
    {
        return Err(PackageEvaluationError::Invalid("declared label gap"));
    }
    let mut events = BTreeSet::new();
    for event in &labels.events {
        if event.clip_id != request.clip_id
            || event.class != request.label
            || event.zone.is_some()
            || !identifier(&event.event_id, 128)
            || !events.insert(event.event_id.as_str())
            || !valid_interval(event.interval)
        {
            return Err(PackageEvaluationError::Invalid(
                "truth must describe the selected unlocalized native class",
            ));
        }
    }
    Ok(clip.duration_ns)
}

fn validate_frames<'a>(
    request: &PackageEvaluationRequest,
    source: &'a PackageEvaluationSourceBinding,
    record: &PackageDetectionRecord,
    end_segment: u64,
    cancelled: &dyn Fn() -> bool,
) -> Result<BTreeMap<u64, &'a PackageEvaluationFrameBinding>> {
    let mut sources = BTreeMap::new();
    for frame in &source.frames {
        checkpoint(cancelled)?;
        if !sha(frame.capsule_digest)
            || !sha(frame.source_digest)
            || frame.stream_id != request.stream_id
            || frame.clock_basis != request.clock_basis
            || frame.gap_before
            || frame.sensor_id.len() > MAX_TEXT
            || SensorId::parse(frame.sensor_id.as_str()).is_err()
            || sources.insert(frame.segment, frame).is_some()
        {
            return Err(PackageEvaluationError::Mismatch(
                "source capsule, stream, clock or gap",
            ));
        }
    }
    let mut previous_sequence = None;
    for frame in sources.values() {
        if previous_sequence
            .is_some_and(|previous: u64| previous.checked_add(1) != Some(frame.sequence))
        {
            return Err(PackageEvaluationError::Invalid("source sequence gap"));
        }
        previous_sequence = Some(frame.sequence);
    }
    let mut segments = BTreeSet::new();
    let mut capsules = BTreeSet::new();
    let mut previous_time = None;
    let mut previous_epoch = None;
    let sensor = &record.frames[0].sensor_id;
    for frame in &record.frames {
        checkpoint(cancelled)?;
        let bound = sources
            .get(&frame.segment)
            .ok_or(PackageEvaluationError::Mismatch("missing source frame"))?;
        if frame.segment < record.first_segment
            || frame.segment >= end_segment
            || !segments.insert(frame.segment)
            || !capsules.insert(frame.capsule_digest)
            || frame.sensor_id != *sensor
            || frame.sensor_id != bound.sensor_id
            || frame.capsule_digest != bound.capsule_digest
            || frame.capture != bound.capture
            || frame.capture.earliest != frame.capture.latest
            || previous_time.is_some_and(|previous| previous >= frame.capture.earliest.0)
            || [
                frame.inference_identity,
                frame.output_digest,
                frame.detection_report_digest,
            ]
            .into_iter()
            .any(|digest| !sha(digest))
        {
            return Err(PackageEvaluationError::Mismatch(
                "frame identity or known singleton display time",
            ));
        }
        previous_time = Some(frame.capture.earliest.0);
        let epoch = source
            .boundaries
            .partition_point(|boundary| boundary.before_segment <= frame.segment);
        if previous_epoch.is_some_and(|previous| previous > epoch) {
            return Err(PackageEvaluationError::Mismatch(
                "display order crosses a source discontinuity",
            ));
        }
        previous_epoch = Some(epoch);
        if frame.detections.len() > MAX_FRAME_DETECTIONS {
            return Err(PackageEvaluationError::Limit);
        }
        let right = frame.dimensions[0]
            .checked_mul(256)
            .filter(|value| *value > 0)
            .ok_or(PackageEvaluationError::Mismatch("frame dimensions"))?;
        let bottom = frame.dimensions[1]
            .checked_mul(256)
            .filter(|value| *value > 0)
            .ok_or(PackageEvaluationError::Mismatch("frame dimensions"))?;
        let mut rows = BTreeSet::new();
        for detection in &frame.detections {
            checkpoint(cancelled)?;
            let [x0, y0, x1, y1] = detection.bounds;
            if detection.class_index >= record.labels.len() as u64
                || !rows.insert((detection.row, detection.class_index))
                || x0 >= x1
                || y0 >= y1
                || x1 > right
                || y1 > bottom
                || score_ppm(detection.score_bits).is_err()
            {
                return Err(PackageEvaluationError::Mismatch("native detection row"));
            }
        }
    }
    let ordered: BTreeMap<_, _> = record
        .frames
        .iter()
        .map(|frame| (frame.segment, frame))
        .collect();
    let mut prior_dimensions = None;
    let mut expected_boundaries = Vec::new();
    for frame in ordered.values() {
        if prior_dimensions.is_some_and(|previous| previous != frame.dimensions) {
            expected_boundaries.push(PackageTrackingBoundary {
                before_segment: frame.segment,
                source_gap: false,
                sequence_gap: false,
                dimensions_changed: true,
            });
        }
        prior_dimensions = Some(frame.dimensions);
    }
    if expected_boundaries != source.boundaries {
        return Err(PackageEvaluationError::Mismatch(
            "declared boundaries disagree with source dimensions",
        ));
    }
    Ok(sources)
}

fn validate_assignment(
    observation: &PackageObservation,
    frame: &RecordFrame,
    class: u64,
) -> Result<(u64, u32)> {
    let (row, bits, bounds, iou) =
        observation
            .detection
            .ok_or(PackageEvaluationError::Mismatch(
                "observation has no actual assigned row",
            ))?;
    if observation.capsule_digest != frame.capsule_digest
        || iou > 1_000_000
        || !frame.detections.iter().any(|d| {
            d.row == row && d.class_index == class && d.score_bits == bits && d.bounds == bounds
        })
    {
        return Err(PackageEvaluationError::Mismatch(
            "assigned row, class, score or capsule changed",
        ));
    }
    Ok((row, bits))
}

fn score_ppm(bits: u32) -> Result<u32> {
    let score = f32::from_bits(bits);
    if !score.is_finite() || !(0.0..=1.0).contains(&score) {
        return Err(PackageEvaluationError::Mismatch(
            "nonfinite or out-of-range score",
        ));
    }
    // A binary32 mantissa times this 20-bit integer is exact in binary64.
    // Nonnegative truncation therefore implements the fixed floor without score promotion.
    Ok((f64::from(score) * 1_000_000.0) as u32)
}

fn encode_tracking(e: &mut CanonicalEncoder, config: PackageTrackingConfig) {
    e.u32(config.confirmation_hits);
    e.u32(config.maximum_missed_frames);
    e.u32(config.minimum_iou_ppm);
}
fn encode_request(e: &mut CanonicalEncoder, request: &PackageEvaluationRequest) {
    e.digest(request.report_digest);
    e.text(&request.label);
    encode_tracking(e, request.tracking);
    e.text(&request.clip_id);
    e.i128(request.clip_origin_ns);
    e.text(&request.stream_id);
    e.text(request.clock_basis.as_str());
}
fn identities_for(
    request: &PackageEvaluationRequest,
    record: &PackageDetectionRecord,
    class: u64,
    policy: &EvaluationPolicy,
) -> EvaluationIdentity {
    let mut model = CanonicalEncoder::new();
    model.text(PACKAGE_EVALUATION_MODEL_DOMAIN);
    for digest in [
        record.package_digest,
        record.manifest_digest,
        record.model_digest,
        record.graph_digest,
        record.contract_digest,
    ] {
        model.digest(digest);
    }
    model.text(&record.model_id);
    model.text(&record.generation);
    model.text(&request.label);
    model.u64(class);
    let mut pipeline = CanonicalEncoder::new();
    pipeline.text(PACKAGE_EVALUATION_PIPELINE_DOMAIN);
    pipeline.text(POLICY);
    pipeline.digest(ContentDigest::sha256(include_bytes!("contract.rs")));
    pipeline.digest(ContentDigest::sha256(include_bytes!(
        "../package_event/types.rs"
    )));
    pipeline.digest(ContentDigest::sha256(include_bytes!(
        "../package_event/tracking.rs"
    )));
    for source in [
        include_bytes!("../package_event.rs").as_slice(),
        include_bytes!("../tracker.rs").as_slice(),
        include_bytes!("../tracker/assignment.rs").as_slice(),
        include_bytes!("../tracker/checked.rs").as_slice(),
        include_bytes!("../tracker/observation.rs").as_slice(),
    ] {
        pipeline.digest(ContentDigest::sha256(source));
    }
    encode_tracking(&mut pipeline, request.tracking);
    pipeline.u32(record.minimum_score_ppm);
    let mut evaluation = CanonicalEncoder::new();
    evaluation.text(PACKAGE_EVALUATION_POLICY_DOMAIN);
    evaluation.text(POLICY);
    evaluation.digest(ContentDigest::sha256(include_bytes!("../../evaluation.rs")));
    evaluation.u64(policy.early_tolerance_ns);
    evaluation.u64(policy.late_tolerance_ns);
    evaluation.u64(policy.false_alert_budget.max_false_alerts);
    evaluation.u64(policy.false_alert_budget.per_observed_ns);
    EvaluationIdentity {
        pipeline_generation: ContentDigest::sha256(&pipeline.finish()).to_text(),
        model_generation: ContentDigest::sha256(&model.finish()).to_text(),
        policy_generation: ContentDigest::sha256(&evaluation.finish()).to_text(),
    }
}
fn candidate_id(
    request: &PackageEvaluationRequest,
    analysis: ContentDigest,
    track: ContentDigest,
    sample: &PackageEvaluationConfirmation,
) -> String {
    let mut e = CanonicalEncoder::new();
    e.text(PACKAGE_EVALUATION_CANDIDATE_DOMAIN);
    encode_request(&mut e, request);
    e.digest(analysis);
    e.digest(track);
    e.u64(sample.observation_index as u64);
    e.u64(sample.segment);
    e.digest(sample.capsule_digest);
    e.u64(sample.detection_row);
    e.u32(sample.score_bits);
    ContentDigest::sha256(&e.finish()).to_text()
}
fn encode_projection(identity: &EvaluationIdentity, p: &PackageEvaluationProvenance) -> Vec<u8> {
    let mut e = CanonicalEncoder::new();
    e.text(PACKAGE_EVALUATION_PROJECTION_DOMAIN);
    e.text(POLICY);
    e.text(&identity.pipeline_generation);
    e.text(&identity.model_generation);
    e.text(&identity.policy_generation);
    encode_request(&mut e, &p.request);
    let s = &p.source;
    e.text(&s.site_lineage);
    e.text(&s.principal);
    for digest in [
        s.analysis_digest,
        s.record_digest,
        s.retained_root,
        s.import_manifest_digest,
        s.privacy_binding,
    ] {
        e.digest(digest);
    }
    s.retained_anchor.encode_canonical(&mut e);
    s.authority_anchor.encode_canonical(&mut e);
    e.bool(s.privacy_policy.is_some());
    if let Some(digest) = s.privacy_policy {
        e.digest(digest);
    }
    e.text(&s.capture_time_label);
    e.bool(s.non_container_omissions);
    e.bool(s.first_source_gap.is_some());
    if let Some(segment) = s.first_source_gap {
        e.u64(segment);
    }
    e.u64(s.frames.len() as u64);
    for frame in &s.frames {
        e.u64(frame.segment);
        e.digest(frame.capsule_digest);
        e.digest(frame.source_digest);
        e.text(&frame.sensor_id);
        e.text(&frame.stream_id);
        e.u64(frame.sequence);
        e.text(frame.clock_basis.as_str());
        e.i128(frame.capture.earliest.0);
        e.i128(frame.capture.latest.0);
        e.bool(frame.gap_before);
    }
    e.u64(s.boundaries.len() as u64);
    for b in &s.boundaries {
        e.u64(b.before_segment);
        e.bool(b.source_gap);
        e.bool(b.sequence_gap);
        e.bool(b.dimensions_changed);
    }
    for digest in [
        p.package_digest,
        p.manifest_digest,
        p.model_digest,
        p.graph_digest,
        p.contract_digest,
        p.import_identity,
        p.import_root,
    ] {
        e.digest(digest);
    }
    e.text(&p.model_id);
    e.text(&p.model_generation);
    e.u64(p.class_index);
    e.text(&p.media_format);
    e.u64(p.first_segment);
    e.u64(p.segment_count);
    e.u32(p.minimum_score_ppm);
    e.u64(p.clip_duration_ns);
    e.i128(p.analysed_sample_hull[0]);
    e.i128(p.analysed_sample_hull[1]);
    e.u64(p.tracks.len() as u64);
    for track in &p.tracks {
        e.digest(track.track);
        e.u64(track.track_id);
        e.u64(track.observations as u64);
        e.text(track.disposition.as_str());
        e.bool(track.first_confirmation.is_some());
        if let Some(c) = &track.first_confirmation {
            e.u64(c.observation_index as u64);
            e.u64(c.segment);
            for digest in [
                c.capsule_digest,
                c.source_digest,
                c.inference_identity,
                c.output_digest,
                c.detection_report_digest,
            ] {
                e.digest(digest);
            }
            e.u64(c.detection_row);
            e.u64(c.class_index);
            e.u32(c.score_bits);
            e.u32(c.score_ppm);
            e.i128(c.capture_ns);
        }
        e.bool(track.candidate.is_some());
        if let Some(c) = &track.candidate {
            e.text(&c.candidate_id);
            e.text(&c.clip_id);
            e.text(&c.class);
            e.u64(c.detect_ns);
            e.u32(c.score_ppm);
        }
    }
    e.finish()
}
