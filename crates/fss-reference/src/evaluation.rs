#![forbid(unsafe_code)]
//! Deterministic event-level evaluation harness (fss-zta8j).
//!
//! FSS states its quality objective at the event level: area under the precision/recall curve,
//! recall at a declared false-alert budget, time-to-detect, and explicit `not_observable`
//! accounting, never per-frame accuracy. This module scores any pipeline's event candidates
//! against ground-truth labels and emits a canonical, digest-bound [`EvaluationReport`].
//!
//! # What this module does NOT prove
//!
//! The harness is a scoring function. Validating it on synthetic labels proves only that the
//! arithmetic below is implemented as specified; it proves nothing about the detection quality of
//! any pipeline or model. A report is a derived cognition artifact: it never grants effect
//! authority, never activates a threshold, and its numbers are only as good as the labels and the
//! declared coverage (`not_observable` intervals) supplied by the caller.
//!
//! # Time model
//!
//! Every clip covers the half-open span `[0, duration_ns)` in clip-relative nanoseconds. Truth
//! events and `not_observable` intervals are *closed* intervals `[start_ns, end_ns]` with
//! `start_ns <= end_ns < duration_ns`; a closed interval covers `end_ns - start_ns + 1`
//! nanoseconds. Candidate detection instants satisfy `detect_ns < duration_ns`.
//!
//! # Coverage (`not_observable`)
//!
//! Per clip, `not_observable` intervals are merged (overlapping or integer-adjacent intervals
//! coalesce). Then:
//!
//! * a truth event lying wholly inside one merged interval is *not observable*: it is never a
//!   positive, never a false negative, and is reported in its own count;
//! * a candidate whose `detect_ns` lies inside a merged interval is removed before matching and
//!   reported as `inside_not_observable`; it is never a false positive;
//! * a scored candidate that can only match a not-observable truth event is *neutral*
//!   (`matched_not_observable_truth`): neither a true nor a false positive. Without this rule a
//!   detection a few nanoseconds after a coverage gap (within the late tolerance) would be
//!   penalised as a false alert for an event the labels declare unobservable.
//! * the observed duration is the sum of clip durations minus the merged `not_observable` length.
//!
//! # Matching rule
//!
//! A scored candidate `c` is *eligible* for truth event `e` iff all of the following hold:
//!
//! * `c.clip_id == e.clip_id` and `c.class == e.class`;
//! * zones are compatible: either side is unspecified (`None`), or both are equal;
//! * `e.start_ns.saturating_sub(early_tolerance_ns) <= c.detect_ns <=
//!   e.end_ns.saturating_add(late_tolerance_ns)`.
//!
//! Matching is one-to-one and greedy: scored candidates are visited in descending `score_ppm`,
//! ties broken by ascending `candidate_id` (byte order). Each candidate takes the first
//! still-unmatched eligible *observable* truth event in `(start_ns, event_id)` order; if none
//! exists it takes the first unmatched eligible not-observable truth event (neutral); otherwise it
//! is a false positive. Every truth event is matched at most once, so a second candidate for an
//! already matched event is a false positive. Because a candidate's fate depends only on
//! candidates visited before it, the matching restricted to scores `>= t` is exactly the prefix
//! of this single pass, which makes the precision/recall curve consistent at every threshold.
//!
//! # Precision/recall curve and AUPRC
//!
//! Let `P` be the number of observable truth events. The curve has one point per distinct
//! `score_ppm` among candidates that ended as true or false positives, in descending order. At
//! threshold `t_k`, `TP_k` / `FP_k` count those candidates with `score_ppm >= t_k`;
//! `precision_k = TP_k / (TP_k + FP_k)` and `recall_k = TP_k / P`.
//!
//! AUPRC uses step-wise (right-continuous, non-interpolated "average precision") integration:
//!
//! ```text
//! AUPRC = sum_k (recall_k - recall_{k-1}) * precision_k
//!       = (1 / P) * sum_k (TP_k - TP_{k-1}) * TP_k / (TP_k + FP_k),     TP_0 = 0
//! ```
//!
//! It is reported in integer parts per million: every term is computed exactly in `u128` as
//! `floor((TP_k - TP_{k-1}) * TP_k * 10^18 / (P * (TP_k + FP_k)))`, the terms are summed, and the
//! sum is rounded half-up to ppm (`(sum + 5 * 10^11) / 10^12`). The accumulated floor error is at
//! most `points * 10^-18`, far below one ppm. If `P == 0` the AUPRC is
//! [`UndefinedReason::NoObservableTruthEvents`]; with `P > 0` and no scored candidates the sum is
//! empty and the AUPRC is defined as `0`.
//!
//! # Recall at the false-alert budget
//!
//! A curve point is within budget iff `FP_k * per_observed_ns <= max_false_alerts *
//! observed_ns` (exact integer comparison, so a rate exactly equal to the budget is within it).
//! False positives never decrease as the threshold falls, so the within-budget points form a
//! prefix of the curve; the operating point is the *lowest* threshold of that prefix (the most
//! permissive threshold still inside the budget, i.e. the maximum recall the budget allows).
//!
//! # Time to detect
//!
//! For each matched observable truth event, `ttd_ns = detect_ns.saturating_sub(start_ns)`
//! (clamped at zero for early detections). Summaries report min, lower median (element at index
//! `(n - 1) / 2` of the ascending list) and max.
//!
//! # Determinism
//!
//! All inputs are validated and canonically ordered by stable identifiers before scoring, all
//! arithmetic is integer, and the report digest is a SHA-256 over the canonical encoding under
//! [`EVALUATION_REPORT_DOMAIN`]. Permuting the input order yields a byte-identical report.

use std::collections::BTreeMap;
use std::fmt;

use fss_core::{CanonicalEncoder, ContentDigest};

#[cfg(test)]
mod tests;

/// Canonical digest domain for evaluation reports; sub-tags `/labels`, `/candidates` and
/// `/report` separate the three digests bound by a report.
pub const EVALUATION_REPORT_DOMAIN: &str = "fss.evaluation_report.v1";
/// Maximum number of labeled clips in one evaluation.
pub const MAX_EVALUATION_CLIPS: usize = 4_096;
/// Maximum number of truth events in one evaluation.
pub const MAX_EVALUATION_TRUTH_EVENTS: usize = 16_384;
/// Maximum number of event candidates in one evaluation.
pub const MAX_EVALUATION_CANDIDATES: usize = 65_536;
/// Maximum number of `not_observable` intervals across all clips.
pub const MAX_EVALUATION_NOT_OBSERVABLE_INTERVALS: usize = 16_384;
/// Maximum byte length of a clip, event, candidate, class, or zone identifier.
pub const MAX_EVALUATION_ID_BYTES: usize = 128;
/// Maximum byte length of an identity field (pipeline/model/policy generation).
pub const MAX_EVALUATION_IDENTITY_BYTES: usize = 256;
/// Maximum candidate score (1.0 expressed in parts per million).
pub const MAX_SCORE_PPM: u32 = 1_000_000;
/// Nanoseconds in one hour.
pub const NANOS_PER_HOUR: u64 = 3_600_000_000_000;
/// Nanoseconds in one day.
pub const NANOS_PER_DAY: u64 = 86_400_000_000_000;

const ATTO_PER_UNIT: u128 = 1_000_000_000_000_000_000;
const ATTO_PER_PPM: u128 = 1_000_000_000_000;

/// A closed interval `[start_ns, end_ns]` in clip-relative nanoseconds.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ClosedIntervalNs {
    /// Inclusive start.
    pub start_ns: u64,
    /// Inclusive end.
    pub end_ns: u64,
}

impl ClosedIntervalNs {
    /// Constructs an interval without validation; [`evaluate`] validates `start_ns <= end_ns`.
    #[must_use]
    pub const fn new(start_ns: u64, end_ns: u64) -> Self {
        Self { start_ns, end_ns }
    }

    /// Returns true if `at_ns` lies inside the closed interval.
    #[must_use]
    pub const fn contains(&self, at_ns: u64) -> bool {
        self.start_ns <= at_ns && at_ns <= self.end_ns
    }

    /// Returns true if `other` lies wholly inside this closed interval.
    #[must_use]
    pub const fn contains_interval(&self, other: &Self) -> bool {
        self.start_ns <= other.start_ns && other.end_ns <= self.end_ns
    }

    /// Covered nanoseconds, `end_ns - start_ns + 1` (zero for an invalid interval).
    #[must_use]
    pub const fn covered_ns(&self) -> u128 {
        if self.end_ns < self.start_ns {
            0
        } else {
            (self.end_ns - self.start_ns) as u128 + 1
        }
    }
}

/// Why a span of a clip is not observable.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum NotObservableReason {
    /// The sensor was down or not delivering.
    SensorDown,
    /// The scene was occluded.
    Occluded,
    /// The sensor was not calibrated for the labeled semantics.
    Uncalibrated,
    /// Any other declared coverage gap.
    Other,
}

impl NotObservableReason {
    /// Stable lower-case token.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::SensorDown => "sensor_down",
            Self::Occluded => "occluded",
            Self::Uncalibrated => "uncalibrated",
            Self::Other => "other",
        }
    }

    /// Parses the stable token produced by [`Self::as_str`].
    #[must_use]
    pub fn parse(token: &str) -> Option<Self> {
        match token {
            "sensor_down" => Some(Self::SensorDown),
            "occluded" => Some(Self::Occluded),
            "uncalibrated" => Some(Self::Uncalibrated),
            "other" => Some(Self::Other),
            _ => None,
        }
    }

    const fn tag(self) -> u8 {
        match self {
            Self::SensorDown => 1,
            Self::Occluded => 2,
            Self::Uncalibrated => 3,
            Self::Other => 4,
        }
    }
}

/// A declared coverage gap inside one clip.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NotObservableInterval {
    /// Closed span that was not observable.
    pub interval: ClosedIntervalNs,
    /// Declared reason.
    pub reason: NotObservableReason,
}

/// One labeled clip (or sensor stream segment) and its coverage gaps.
///
/// The clip duration lives with the labels, not the policy: it is a property of the labeled
/// corpus, which keeps one [`EvaluationPolicy`] reusable across corpora.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LabeledClip {
    /// Stable clip/sensor identifier.
    pub clip_id: String,
    /// Total clip duration; the clip covers `[0, duration_ns)`.
    pub duration_ns: u64,
    /// Declared coverage gaps.
    pub not_observable: Vec<NotObservableInterval>,
}

/// One ground-truth event.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TruthEvent {
    /// Stable event identifier, unique across the label set.
    pub event_id: String,
    /// Owning clip.
    pub clip_id: String,
    /// Event class.
    pub class: String,
    /// Optional zone; `None` means the label does not constrain the zone.
    pub zone: Option<String>,
    /// Closed event span.
    pub interval: ClosedIntervalNs,
}

/// Ground-truth labels for an evaluation.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct LabelSet {
    /// Labeled clips with durations and coverage gaps.
    pub clips: Vec<LabeledClip>,
    /// Truth events.
    pub events: Vec<TruthEvent>,
}

/// One pipeline event candidate.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EventCandidate {
    /// Stable candidate identifier, unique across the candidate set.
    pub candidate_id: String,
    /// Clip the candidate was emitted for.
    pub clip_id: String,
    /// Candidate class.
    pub class: String,
    /// Optional zone; `None` means the candidate does not assert a zone.
    pub zone: Option<String>,
    /// Detection instant (clip-relative).
    pub detect_ns: u64,
    /// Score in parts per million, `0..=1_000_000`.
    pub score_ppm: u32,
}

/// Pipeline candidates for an evaluation.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct CandidateSet {
    /// Event candidates.
    pub candidates: Vec<EventCandidate>,
}

/// Declared false-alert budget: at most `max_false_alerts` per `per_observed_ns` of observed time.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct FalseAlertBudget {
    /// Allowed false alerts per window.
    pub max_false_alerts: u64,
    /// Window length in observed nanoseconds; must be non-zero.
    pub per_observed_ns: u64,
}

impl FalseAlertBudget {
    /// Budget of `max_false_alerts` per observed day.
    #[must_use]
    pub const fn per_day(max_false_alerts: u64) -> Self {
        Self {
            max_false_alerts,
            per_observed_ns: NANOS_PER_DAY,
        }
    }

    /// Budget of `max_false_alerts` per observed hour.
    #[must_use]
    pub const fn per_hour(max_false_alerts: u64) -> Self {
        Self {
            max_false_alerts,
            per_observed_ns: NANOS_PER_HOUR,
        }
    }

    /// Exact test `false_alerts / observed_ns <= max_false_alerts / per_observed_ns`.
    #[must_use]
    pub fn admits(&self, false_alerts: u64, observed_ns: u128) -> bool {
        let lhs = u128::from(false_alerts) * u128::from(self.per_observed_ns);
        u128::from(self.max_false_alerts)
            .checked_mul(observed_ns)
            .is_none_or(|rhs| lhs <= rhs)
    }
}

/// Scoring policy.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct EvaluationPolicy {
    /// How far before a truth event's start a detection still matches.
    pub early_tolerance_ns: u64,
    /// How far after a truth event's end a detection still matches.
    pub late_tolerance_ns: u64,
    /// Declared false-alert budget.
    pub false_alert_budget: FalseAlertBudget,
}

/// Caller-supplied identity bound into the report digest.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct EvaluationIdentity {
    /// Pipeline generation (string or digest) that produced the candidates.
    pub pipeline_generation: String,
    /// Model generation (string or digest) behind the candidates.
    pub model_generation: String,
    /// Evaluation policy generation (string or digest).
    pub policy_generation: String,
}

/// Which bound was exceeded.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EvaluationLimit {
    /// [`MAX_EVALUATION_CLIPS`].
    Clips,
    /// [`MAX_EVALUATION_TRUTH_EVENTS`].
    TruthEvents,
    /// [`MAX_EVALUATION_CANDIDATES`].
    Candidates,
    /// [`MAX_EVALUATION_NOT_OBSERVABLE_INTERVALS`].
    NotObservableIntervals,
}

/// Why an identifier or identity string was refused.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TextViolation {
    /// Empty string.
    Empty,
    /// Longer than the field bound.
    TooLong,
    /// Contains a byte outside printable ASCII without spaces (`0x21..=0x7e`).
    InvalidCharacter,
}

/// Typed refusal from [`evaluate`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum EvaluationError {
    /// An input exceeded its explicit bound.
    LimitExceeded {
        /// Bound that was exceeded.
        limit: EvaluationLimit,
        /// Maximum admitted count.
        max: usize,
        /// Supplied count.
        actual: usize,
    },
    /// An identifier or identity string is malformed.
    InvalidText {
        /// Field name.
        field: &'static str,
        /// Violation.
        violation: TextViolation,
    },
    /// An identifier appears twice.
    DuplicateId {
        /// Field name.
        field: &'static str,
        /// Duplicated identifier.
        id: String,
    },
    /// A truth event or candidate names a clip absent from the label set.
    UnknownClip {
        /// Owning record identifier.
        owner_id: String,
        /// Unknown clip.
        clip_id: String,
    },
    /// A clip declares zero duration.
    ZeroClipDuration {
        /// Clip identifier.
        clip_id: String,
    },
    /// An interval has `start_ns > end_ns`.
    InvalidInterval {
        /// Owning record identifier (event id or clip id).
        owner_id: String,
        /// Supplied start.
        start_ns: u64,
        /// Supplied end.
        end_ns: u64,
    },
    /// A time lies at or beyond the clip duration.
    OutsideClip {
        /// Owning record identifier.
        owner_id: String,
        /// Offending time.
        at_ns: u64,
        /// Clip duration.
        duration_ns: u64,
    },
    /// A score exceeds [`MAX_SCORE_PPM`].
    ScoreOutOfRange {
        /// Candidate identifier.
        candidate_id: String,
        /// Supplied score.
        score_ppm: u32,
    },
    /// The false-alert budget window is zero.
    InvalidBudget,
    /// Canonical encoding failed.
    Encoding,
}

impl EvaluationError {
    /// Stable machine error identity.
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::LimitExceeded { .. } => "evaluation.limit_exceeded",
            Self::InvalidText { .. } => "evaluation.invalid_text",
            Self::DuplicateId { .. } => "evaluation.duplicate_id",
            Self::UnknownClip { .. } => "evaluation.unknown_clip",
            Self::ZeroClipDuration { .. } => "evaluation.zero_clip_duration",
            Self::InvalidInterval { .. } => "evaluation.invalid_interval",
            Self::OutsideClip { .. } => "evaluation.outside_clip",
            Self::ScoreOutOfRange { .. } => "evaluation.score_out_of_range",
            Self::InvalidBudget => "evaluation.invalid_budget",
            Self::Encoding => "evaluation.encoding",
        }
    }
}

impl fmt::Display for EvaluationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::LimitExceeded { limit, max, actual } => {
                write!(formatter, "{limit:?} limit exceeded: {actual} > {max}")
            }
            Self::InvalidText { field, violation } => {
                write!(formatter, "invalid {field}: {violation:?}")
            }
            Self::DuplicateId { field, id } => write!(formatter, "duplicate {field} `{id}`"),
            Self::UnknownClip { owner_id, clip_id } => {
                write!(formatter, "`{owner_id}` names unknown clip `{clip_id}`")
            }
            Self::ZeroClipDuration { clip_id } => {
                write!(formatter, "clip `{clip_id}` declares zero duration")
            }
            Self::InvalidInterval {
                owner_id,
                start_ns,
                end_ns,
            } => write!(
                formatter,
                "`{owner_id}` interval start {start_ns} exceeds end {end_ns}"
            ),
            Self::OutsideClip {
                owner_id,
                at_ns,
                duration_ns,
            } => write!(
                formatter,
                "`{owner_id}` time {at_ns} is outside clip duration {duration_ns}"
            ),
            Self::ScoreOutOfRange {
                candidate_id,
                score_ppm,
            } => write!(
                formatter,
                "candidate `{candidate_id}` score {score_ppm} exceeds {MAX_SCORE_PPM} ppm"
            ),
            Self::InvalidBudget => {
                formatter.write_str("false-alert budget window must be non-zero")
            }
            Self::Encoding => formatter.write_str("canonical encoding failed"),
        }
    }
}

impl std::error::Error for EvaluationError {}

/// Why a metric has no value. Never flattened into zero or NaN.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum UndefinedReason {
    /// There are no observable truth events, so recall and AUPRC are undefined.
    NoObservableTruthEvents,
    /// No candidate was scored as a true or false positive, so precision is undefined.
    NoScoredCandidates,
    /// The observed duration is zero, so a false-alert rate is undefined.
    NoObservedTime,
}

impl UndefinedReason {
    const fn tag(self) -> u8 {
        match self {
            Self::NoObservableTruthEvents => 1,
            Self::NoScoredCandidates => 2,
            Self::NoObservedTime => 3,
        }
    }
}

/// An exact ratio or an explicit undefined state.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum Ratio {
    /// `numerator / denominator` with `denominator > 0`.
    Defined {
        /// Numerator.
        numerator: u64,
        /// Denominator (non-zero).
        denominator: u64,
    },
    /// No value.
    Undefined(UndefinedReason),
}

impl Ratio {
    fn of(numerator: u64, denominator: u64, reason: UndefinedReason) -> Self {
        if denominator == 0 {
            Self::Undefined(reason)
        } else {
            Self::Defined {
                numerator,
                denominator,
            }
        }
    }

    /// Floor of the ratio in parts per million, or `None` when undefined.
    #[must_use]
    pub fn ppm_floor(&self) -> Option<u64> {
        match *self {
            Self::Defined {
                numerator,
                denominator,
            } => {
                let scaled = u128::from(numerator) * 1_000_000 / u128::from(denominator);
                Some(u64::try_from(scaled).unwrap_or(u64::MAX))
            }
            Self::Undefined(_) => None,
        }
    }

    fn encode(&self, encoder: &mut CanonicalEncoder) {
        match *self {
            Self::Defined {
                numerator,
                denominator,
            } => {
                encoder.tag(1);
                encoder.u64(numerator);
                encoder.u64(denominator);
            }
            Self::Undefined(reason) => {
                encoder.tag(0);
                encoder.tag(reason.tag());
            }
        }
    }
}

/// A metric in integer parts per million or an explicit undefined state.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum PpmMetric {
    /// Value in parts per million, `0..=1_000_000`.
    Defined(u32),
    /// No value.
    Undefined(UndefinedReason),
}

/// One precision/recall curve point.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct PrPoint {
    /// Candidates with `score_ppm >= threshold_ppm` are alerts.
    pub threshold_ppm: u32,
    /// True positives at this threshold.
    pub true_positives: u64,
    /// False positives at this threshold.
    pub false_positives: u64,
    /// `TP / (TP + FP)`.
    pub precision: Ratio,
    /// `TP / P`.
    pub recall: Ratio,
    /// Whether the false-alert rate at this threshold is within the declared budget.
    pub within_false_alert_budget: bool,
}

/// Min / lower-median / max summary of time-to-detect values.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct TimeToDetectSummary {
    /// Number of matched observable events summarised.
    pub count: u64,
    /// Minimum.
    pub min_ns: u64,
    /// Lower median (index `(count - 1) / 2` of the sorted values).
    pub median_ns: u64,
    /// Maximum.
    pub max_ns: u64,
}

impl TimeToDetectSummary {
    fn from_values(mut values: Vec<u64>) -> Option<Self> {
        values.sort_unstable();
        let min_ns = *values.first()?;
        let max_ns = *values.last()?;
        let median_ns = *values.get((values.len() - 1) / 2)?;
        Some(Self {
            count: values.len() as u64,
            min_ns,
            median_ns,
            max_ns,
        })
    }
}

/// Operating point selected by the false-alert budget.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum OperatingPoint {
    /// Lowest threshold whose false-alert rate is within budget.
    WithinBudget {
        /// The selected curve point.
        point: PrPoint,
        /// Time-to-detect over events matched at this threshold (`None` if no true positives).
        time_to_detect: Option<TimeToDetectSummary>,
    },
    /// Even the highest threshold exceeds the budget.
    NoThresholdWithinBudget {
        /// False positives at the highest threshold.
        false_positives_at_highest_threshold: u64,
    },
    /// No candidate was scored, so there is no threshold to select.
    NoScoredCandidates,
    /// Observed duration is zero, so no false-alert rate exists.
    NoObservedTime,
}

impl OperatingPoint {
    /// Recall at the operating point; undefined variants carry their reason.
    #[must_use]
    pub fn recall(&self) -> Ratio {
        match self {
            Self::WithinBudget { point, .. } => point.recall,
            Self::NoThresholdWithinBudget { .. } | Self::NoScoredCandidates => {
                Ratio::Undefined(UndefinedReason::NoScoredCandidates)
            }
            Self::NoObservedTime => Ratio::Undefined(UndefinedReason::NoObservedTime),
        }
    }
}

/// Final disposition of one truth event under the full matching.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub enum TruthDisposition {
    /// Observable event matched by a candidate.
    Detected {
        /// Matching candidate.
        candidate_id: String,
        /// Matching candidate score.
        score_ppm: u32,
        /// `detect_ns - start_ns`, clamped at zero.
        time_to_detect_ns: u64,
    },
    /// Observable event with no matching candidate (false negative).
    Missed,
    /// Event wholly inside a `not_observable` interval; never a false negative.
    NotObservable {
        /// Neutral candidate that matched it, if any.
        matched_candidate_id: Option<String>,
    },
}

/// Outcome for one truth event.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct TruthOutcome {
    /// Truth event identifier.
    pub event_id: String,
    /// Disposition.
    pub disposition: TruthDisposition,
}

/// Final disposition of one candidate under the full matching.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub enum CandidateDisposition {
    /// Matched an observable truth event.
    TruePositive {
        /// Matched truth event.
        event_id: String,
    },
    /// Scored, matched nothing.
    FalsePositive,
    /// Scored, but could only match a not-observable truth event; neutral.
    MatchedNotObservableTruth {
        /// Matched not-observable truth event.
        event_id: String,
    },
    /// Detection instant inside a `not_observable` interval; not scored.
    InsideNotObservable,
}

/// Outcome for one candidate.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct CandidateOutcome {
    /// Candidate identifier.
    pub candidate_id: String,
    /// Disposition.
    pub disposition: CandidateDisposition,
}

/// Counts under the full matching (lowest threshold: every scored candidate is an alert).
#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
pub struct EvaluationCounts {
    /// All truth events.
    pub truth_events: u64,
    /// Observable truth events (`P`).
    pub observable_truth_events: u64,
    /// Truth events wholly inside `not_observable`; never false negatives.
    pub not_observable_truth_events: u64,
    /// All candidates.
    pub candidates: u64,
    /// Candidates whose detection instant is inside `not_observable`; never false positives.
    pub candidates_inside_not_observable: u64,
    /// Scored candidates that matched only a not-observable truth event; neutral.
    pub candidates_matched_not_observable_truth: u64,
    /// True positives.
    pub true_positives: u64,
    /// False positives.
    pub false_positives: u64,
    /// False negatives (observable, unmatched).
    pub false_negatives: u64,
}

/// Durations summed over all clips.
#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
pub struct ObservedDurations {
    /// Sum of clip durations.
    pub total_ns: u128,
    /// Merged `not_observable` coverage.
    pub not_observable_ns: u128,
    /// `total_ns - not_observable_ns`.
    pub observed_ns: u128,
}

/// Deterministic, digest-bound event-level evaluation report.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EvaluationReport {
    /// Caller-supplied generations.
    pub identity: EvaluationIdentity,
    /// Policy applied.
    pub policy: EvaluationPolicy,
    /// Digest of the canonical label set (`/labels`).
    pub label_set_digest: ContentDigest,
    /// Digest of the canonical candidate set (`/candidates`).
    pub candidate_set_digest: ContentDigest,
    /// Counts under the full matching.
    pub counts: EvaluationCounts,
    /// Observed / not-observable durations.
    pub durations: ObservedDurations,
    /// Precision/recall curve, thresholds strictly descending.
    pub pr_curve: Vec<PrPoint>,
    /// Step-wise AUPRC in ppm.
    pub auprc: PpmMetric,
    /// Recall at the false-alert budget.
    pub operating_point: OperatingPoint,
    /// Precision under the full matching.
    pub precision: Ratio,
    /// Recall under the full matching.
    pub recall: Ratio,
    /// Time-to-detect over all matched observable events.
    pub time_to_detect: Option<TimeToDetectSummary>,
    /// Per-truth-event outcomes, ascending `event_id`.
    pub truth_outcomes: Vec<TruthOutcome>,
    /// Per-candidate outcomes, ascending `candidate_id`.
    pub candidate_outcomes: Vec<CandidateOutcome>,
    /// SHA-256 over the canonical encoding of every field above (`/report`).
    pub digest: ContentDigest,
}

fn check_text(field: &'static str, value: &str, max: usize) -> Result<(), EvaluationError> {
    let violation = if value.is_empty() {
        Some(TextViolation::Empty)
    } else if value.len() > max {
        Some(TextViolation::TooLong)
    } else if !value.bytes().all(|byte| (0x21..=0x7e).contains(&byte)) {
        Some(TextViolation::InvalidCharacter)
    } else {
        None
    };
    match violation {
        Some(violation) => Err(EvaluationError::InvalidText { field, violation }),
        None => Ok(()),
    }
}

fn check_id(field: &'static str, value: &str) -> Result<(), EvaluationError> {
    check_text(field, value, MAX_EVALUATION_ID_BYTES)
}

fn check_limit(limit: EvaluationLimit, max: usize, actual: usize) -> Result<(), EvaluationError> {
    if actual > max {
        Err(EvaluationError::LimitExceeded { limit, max, actual })
    } else {
        Ok(())
    }
}

fn check_interval(owner_id: &str, interval: ClosedIntervalNs) -> Result<(), EvaluationError> {
    if interval.start_ns > interval.end_ns {
        return Err(EvaluationError::InvalidInterval {
            owner_id: owner_id.to_owned(),
            start_ns: interval.start_ns,
            end_ns: interval.end_ns,
        });
    }
    Ok(())
}

fn check_inside_clip(owner_id: &str, at_ns: u64, duration_ns: u64) -> Result<(), EvaluationError> {
    if at_ns >= duration_ns {
        return Err(EvaluationError::OutsideClip {
            owner_id: owner_id.to_owned(),
            at_ns,
            duration_ns,
        });
    }
    Ok(())
}

/// Merges overlapping or integer-adjacent closed intervals.
fn merge_intervals(mut intervals: Vec<ClosedIntervalNs>) -> Vec<ClosedIntervalNs> {
    intervals.sort_unstable();
    let mut merged: Vec<ClosedIntervalNs> = Vec::with_capacity(intervals.len());
    for interval in intervals {
        match merged.last_mut() {
            Some(last) if interval.start_ns <= last.end_ns.saturating_add(1) => {
                last.end_ns = last.end_ns.max(interval.end_ns);
            }
            _ => merged.push(interval),
        }
    }
    merged
}

fn zones_compatible(truth: Option<&str>, candidate: Option<&str>) -> bool {
    match (truth, candidate) {
        (Some(truth), Some(candidate)) => truth == candidate,
        _ => true,
    }
}

fn encode_option_text(encoder: &mut CanonicalEncoder, value: Option<&str>) {
    match value {
        Some(text) => {
            encoder.tag(1);
            encoder.text(text);
        }
        None => encoder.tag(0),
    }
}

fn encode_u128(encoder: &mut CanonicalEncoder, value: u128) {
    encoder.u64((value >> 64) as u64);
    encoder.u64(value as u64);
}

fn domain_encoder(part: &str) -> CanonicalEncoder {
    let mut encoder = CanonicalEncoder::new();
    encoder.text("fss.canonical.v1");
    encoder.text(EVALUATION_REPORT_DOMAIN);
    encoder.text(part);
    encoder
}

fn finish_digest(encoder: CanonicalEncoder) -> Result<ContentDigest, EvaluationError> {
    encoder
        .finish_checked()
        .map(|bytes| ContentDigest::sha256(&bytes))
        .map_err(|_| EvaluationError::Encoding)
}

/// Canonical digest of a label set (clips and events sorted by id, gaps sorted as supplied).
fn label_set_digest(
    clips: &[&LabeledClip],
    events: &[&TruthEvent],
) -> Result<ContentDigest, EvaluationError> {
    let mut encoder = domain_encoder("labels");
    encoder.u64(clips.len() as u64);
    for clip in clips {
        encoder.text(&clip.clip_id);
        encoder.u64(clip.duration_ns);
        let mut gaps: Vec<(ClosedIntervalNs, NotObservableReason)> = clip
            .not_observable
            .iter()
            .map(|gap| (gap.interval, gap.reason))
            .collect();
        gaps.sort_unstable();
        encoder.u64(gaps.len() as u64);
        for (interval, reason) in gaps {
            encoder.u64(interval.start_ns);
            encoder.u64(interval.end_ns);
            encoder.tag(reason.tag());
        }
    }
    encoder.u64(events.len() as u64);
    for event in events {
        encoder.text(&event.event_id);
        encoder.text(&event.clip_id);
        encoder.text(&event.class);
        encode_option_text(&mut encoder, event.zone.as_deref());
        encoder.u64(event.interval.start_ns);
        encoder.u64(event.interval.end_ns);
    }
    finish_digest(encoder)
}

fn candidate_set_digest(candidates: &[&EventCandidate]) -> Result<ContentDigest, EvaluationError> {
    let mut encoder = domain_encoder("candidates");
    encoder.u64(candidates.len() as u64);
    for candidate in candidates {
        encoder.text(&candidate.candidate_id);
        encoder.text(&candidate.clip_id);
        encoder.text(&candidate.class);
        encode_option_text(&mut encoder, candidate.zone.as_deref());
        encoder.u64(candidate.detect_ns);
        encoder.u32(candidate.score_ppm);
    }
    finish_digest(encoder)
}

struct ClipState {
    duration_ns: u64,
    gaps: Vec<ClosedIntervalNs>,
}

impl ClipState {
    fn gap_contains(&self, at_ns: u64) -> bool {
        self.gaps.iter().any(|gap| gap.contains(at_ns))
    }

    fn gap_contains_interval(&self, interval: &ClosedIntervalNs) -> bool {
        self.gaps.iter().any(|gap| gap.contains_interval(interval))
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum MatchKind {
    TruePositive(usize),
    Neutral(usize),
    FalsePositive,
}

/// Scores `candidates` against `labels` under `policy` and returns a canonical report.
///
/// See the module documentation for the exact matching rule, AUPRC formula, budget rule, and
/// `not_observable` accounting.
pub fn evaluate(
    identity: &EvaluationIdentity,
    policy: &EvaluationPolicy,
    labels: &LabelSet,
    candidates: &CandidateSet,
) -> Result<EvaluationReport, EvaluationError> {
    // ---- bounds and identity ------------------------------------------------------------
    check_limit(
        EvaluationLimit::Clips,
        MAX_EVALUATION_CLIPS,
        labels.clips.len(),
    )?;
    check_limit(
        EvaluationLimit::TruthEvents,
        MAX_EVALUATION_TRUTH_EVENTS,
        labels.events.len(),
    )?;
    check_limit(
        EvaluationLimit::Candidates,
        MAX_EVALUATION_CANDIDATES,
        candidates.candidates.len(),
    )?;
    let gap_total = labels.clips.iter().fold(0_usize, |total, clip| {
        total.saturating_add(clip.not_observable.len())
    });
    check_limit(
        EvaluationLimit::NotObservableIntervals,
        MAX_EVALUATION_NOT_OBSERVABLE_INTERVALS,
        gap_total,
    )?;
    for (field, value) in [
        ("pipeline_generation", &identity.pipeline_generation),
        ("model_generation", &identity.model_generation),
        ("policy_generation", &identity.policy_generation),
    ] {
        check_text(field, value, MAX_EVALUATION_IDENTITY_BYTES)?;
    }
    if policy.false_alert_budget.per_observed_ns == 0 {
        return Err(EvaluationError::InvalidBudget);
    }

    // ---- clips ----------------------------------------------------------------------------
    let mut clips: BTreeMap<&str, ClipState> = BTreeMap::new();
    let mut sorted_clips: Vec<&LabeledClip> = labels.clips.iter().collect();
    sorted_clips.sort_unstable_by(|a, b| a.clip_id.cmp(&b.clip_id));
    let mut durations = ObservedDurations::default();
    for clip in &sorted_clips {
        check_id("clip_id", &clip.clip_id)?;
        if clip.duration_ns == 0 {
            return Err(EvaluationError::ZeroClipDuration {
                clip_id: clip.clip_id.clone(),
            });
        }
        let mut gaps = Vec::with_capacity(clip.not_observable.len());
        for gap in &clip.not_observable {
            check_interval(&clip.clip_id, gap.interval)?;
            check_inside_clip(&clip.clip_id, gap.interval.end_ns, clip.duration_ns)?;
            gaps.push(gap.interval);
        }
        let gaps = merge_intervals(gaps);
        let gap_ns: u128 = gaps.iter().map(ClosedIntervalNs::covered_ns).sum();
        durations.total_ns += u128::from(clip.duration_ns);
        durations.not_observable_ns += gap_ns;
        if clips
            .insert(
                clip.clip_id.as_str(),
                ClipState {
                    duration_ns: clip.duration_ns,
                    gaps,
                },
            )
            .is_some()
        {
            return Err(EvaluationError::DuplicateId {
                field: "clip_id",
                id: clip.clip_id.clone(),
            });
        }
    }
    durations.observed_ns = durations.total_ns - durations.not_observable_ns;

    // ---- truth events -------------------------------------------------------------------
    let mut events: Vec<&TruthEvent> = labels.events.iter().collect();
    events.sort_unstable_by(|a, b| a.event_id.cmp(&b.event_id));
    let mut event_not_observable = Vec::with_capacity(events.len());
    let mut previous_event: Option<&str> = None;
    for event in &events {
        check_id("event_id", &event.event_id)?;
        if previous_event == Some(event.event_id.as_str()) {
            return Err(EvaluationError::DuplicateId {
                field: "event_id",
                id: event.event_id.clone(),
            });
        }
        previous_event = Some(event.event_id.as_str());
        check_id("event_clip_id", &event.clip_id)?;
        check_id("event_class", &event.class)?;
        if let Some(zone) = &event.zone {
            check_id("event_zone", zone)?;
        }
        check_interval(&event.event_id, event.interval)?;
        let clip =
            clips
                .get(event.clip_id.as_str())
                .ok_or_else(|| EvaluationError::UnknownClip {
                    owner_id: event.event_id.clone(),
                    clip_id: event.clip_id.clone(),
                })?;
        check_inside_clip(&event.event_id, event.interval.end_ns, clip.duration_ns)?;
        event_not_observable.push(clip.gap_contains_interval(&event.interval));
    }

    // ---- candidates ---------------------------------------------------------------------
    let mut by_id: Vec<&EventCandidate> = candidates.candidates.iter().collect();
    by_id.sort_unstable_by(|a, b| a.candidate_id.cmp(&b.candidate_id));
    let mut candidate_inside_gap = Vec::with_capacity(by_id.len());
    let mut previous_candidate: Option<&str> = None;
    for candidate in &by_id {
        check_id("candidate_id", &candidate.candidate_id)?;
        if previous_candidate == Some(candidate.candidate_id.as_str()) {
            return Err(EvaluationError::DuplicateId {
                field: "candidate_id",
                id: candidate.candidate_id.clone(),
            });
        }
        previous_candidate = Some(candidate.candidate_id.as_str());
        check_id("candidate_clip_id", &candidate.clip_id)?;
        check_id("candidate_class", &candidate.class)?;
        if let Some(zone) = &candidate.zone {
            check_id("candidate_zone", zone)?;
        }
        if candidate.score_ppm > MAX_SCORE_PPM {
            return Err(EvaluationError::ScoreOutOfRange {
                candidate_id: candidate.candidate_id.clone(),
                score_ppm: candidate.score_ppm,
            });
        }
        let clip =
            clips
                .get(candidate.clip_id.as_str())
                .ok_or_else(|| EvaluationError::UnknownClip {
                    owner_id: candidate.candidate_id.clone(),
                    clip_id: candidate.clip_id.clone(),
                })?;
        check_inside_clip(
            &candidate.candidate_id,
            candidate.detect_ns,
            clip.duration_ns,
        )?;
        candidate_inside_gap.push(clip.gap_contains(candidate.detect_ns));
    }

    // ---- matching -------------------------------------------------------------------------
    // (clip, class) -> truth indices ordered by (start_ns, event_id).
    let mut truth_index: BTreeMap<(&str, &str), Vec<usize>> = BTreeMap::new();
    for (index, event) in events.iter().enumerate() {
        truth_index
            .entry((event.clip_id.as_str(), event.class.as_str()))
            .or_default()
            .push(index);
    }
    for indices in truth_index.values_mut() {
        indices.sort_unstable_by(|&a, &b| {
            (events[a].interval.start_ns, &events[a].event_id)
                .cmp(&(events[b].interval.start_ns, &events[b].event_id))
        });
    }

    let mut scoring_order: Vec<usize> = (0..by_id.len())
        .filter(|&index| !candidate_inside_gap[index])
        .collect();
    scoring_order.sort_unstable_by(|&a, &b| {
        by_id[b]
            .score_ppm
            .cmp(&by_id[a].score_ppm)
            .then_with(|| by_id[a].candidate_id.cmp(&by_id[b].candidate_id))
    });

    let positives = event_not_observable.iter().filter(|flag| !**flag).count() as u64;
    let mut truth_match: Vec<Option<usize>> = vec![None; events.len()];
    let mut candidate_match: Vec<Option<MatchKind>> = vec![None; by_id.len()];
    let mut pr_curve: Vec<PrPoint> = Vec::new();
    let mut true_positives = 0_u64;
    let mut false_positives = 0_u64;
    let mut position = 0;
    while position < scoring_order.len() {
        let score = by_id[scoring_order[position]].score_ppm;
        let mut group_scored = false;
        while position < scoring_order.len() && by_id[scoring_order[position]].score_ppm == score {
            let candidate_index = scoring_order[position];
            let candidate = by_id[candidate_index];
            let mut observable_choice = None;
            let mut neutral_choice = None;
            if let Some(indices) =
                truth_index.get(&(candidate.clip_id.as_str(), candidate.class.as_str()))
            {
                for &truth in indices {
                    let event = events[truth];
                    let eligible = truth_match[truth].is_none()
                        && zones_compatible(event.zone.as_deref(), candidate.zone.as_deref())
                        && event
                            .interval
                            .start_ns
                            .saturating_sub(policy.early_tolerance_ns)
                            <= candidate.detect_ns
                        && candidate.detect_ns
                            <= event
                                .interval
                                .end_ns
                                .saturating_add(policy.late_tolerance_ns);
                    if !eligible {
                        continue;
                    }
                    if event_not_observable[truth] {
                        if neutral_choice.is_none() {
                            neutral_choice = Some(truth);
                        }
                    } else {
                        observable_choice = Some(truth);
                        break;
                    }
                }
            }
            let kind = match (observable_choice, neutral_choice) {
                (Some(truth), _) => {
                    truth_match[truth] = Some(candidate_index);
                    true_positives += 1;
                    group_scored = true;
                    MatchKind::TruePositive(truth)
                }
                (None, Some(truth)) => {
                    truth_match[truth] = Some(candidate_index);
                    MatchKind::Neutral(truth)
                }
                (None, None) => {
                    false_positives += 1;
                    group_scored = true;
                    MatchKind::FalsePositive
                }
            };
            candidate_match[candidate_index] = Some(kind);
            position += 1;
        }
        if group_scored {
            pr_curve.push(PrPoint {
                threshold_ppm: score,
                true_positives,
                false_positives,
                precision: Ratio::of(
                    true_positives,
                    true_positives + false_positives,
                    UndefinedReason::NoScoredCandidates,
                ),
                recall: Ratio::of(
                    true_positives,
                    positives,
                    UndefinedReason::NoObservableTruthEvents,
                ),
                within_false_alert_budget: policy
                    .false_alert_budget
                    .admits(false_positives, durations.observed_ns),
            });
        }
    }

    // ---- AUPRC ------------------------------------------------------------------------------
    let auprc = if positives == 0 {
        PpmMetric::Undefined(UndefinedReason::NoObservableTruthEvents)
    } else {
        let mut sum_atto: u128 = 0;
        let mut previous_tp = 0_u64;
        for point in &pr_curve {
            let delta = u128::from(point.true_positives - previous_tp);
            let alerts = u128::from(point.true_positives + point.false_positives);
            sum_atto += delta * u128::from(point.true_positives) * ATTO_PER_UNIT
                / (u128::from(positives) * alerts);
            previous_tp = point.true_positives;
        }
        let ppm = ((sum_atto + ATTO_PER_PPM / 2) / ATTO_PER_PPM).min(u128::from(MAX_SCORE_PPM));
        PpmMetric::Defined(u32::try_from(ppm).unwrap_or(MAX_SCORE_PPM))
    };

    // ---- outcomes -------------------------------------------------------------------------
    let mut counts = EvaluationCounts {
        truth_events: events.len() as u64,
        observable_truth_events: positives,
        not_observable_truth_events: events.len() as u64 - positives,
        candidates: by_id.len() as u64,
        true_positives,
        false_positives,
        ..EvaluationCounts::default()
    };
    let mut truth_outcomes = Vec::with_capacity(events.len());
    let mut all_ttd = Vec::new();
    for (index, event) in events.iter().enumerate() {
        let disposition = match (event_not_observable[index], truth_match[index]) {
            (true, matched) => TruthDisposition::NotObservable {
                matched_candidate_id: matched.map(|c| by_id[c].candidate_id.clone()),
            },
            (false, Some(candidate_index)) => {
                let candidate = by_id[candidate_index];
                let ttd = candidate.detect_ns.saturating_sub(event.interval.start_ns);
                all_ttd.push(ttd);
                TruthDisposition::Detected {
                    candidate_id: candidate.candidate_id.clone(),
                    score_ppm: candidate.score_ppm,
                    time_to_detect_ns: ttd,
                }
            }
            (false, None) => {
                counts.false_negatives += 1;
                TruthDisposition::Missed
            }
        };
        truth_outcomes.push(TruthOutcome {
            event_id: event.event_id.clone(),
            disposition,
        });
    }
    let mut candidate_outcomes = Vec::with_capacity(by_id.len());
    for (index, candidate) in by_id.iter().enumerate() {
        let disposition = match candidate_match[index] {
            None => {
                counts.candidates_inside_not_observable += 1;
                CandidateDisposition::InsideNotObservable
            }
            Some(MatchKind::TruePositive(truth)) => CandidateDisposition::TruePositive {
                event_id: events[truth].event_id.clone(),
            },
            Some(MatchKind::Neutral(truth)) => {
                counts.candidates_matched_not_observable_truth += 1;
                CandidateDisposition::MatchedNotObservableTruth {
                    event_id: events[truth].event_id.clone(),
                }
            }
            Some(MatchKind::FalsePositive) => CandidateDisposition::FalsePositive,
        };
        candidate_outcomes.push(CandidateOutcome {
            candidate_id: candidate.candidate_id.clone(),
            disposition,
        });
    }

    // ---- operating point ---------------------------------------------------------------
    let operating_point = if durations.observed_ns == 0 {
        OperatingPoint::NoObservedTime
    } else {
        match (
            pr_curve.first(),
            pr_curve.iter().rev().find(|p| p.within_false_alert_budget),
        ) {
            (None, _) => OperatingPoint::NoScoredCandidates,
            (Some(first), None) => OperatingPoint::NoThresholdWithinBudget {
                false_positives_at_highest_threshold: first.false_positives,
            },
            (Some(_), Some(point)) => {
                let values = truth_outcomes
                    .iter()
                    .filter_map(|outcome| match outcome.disposition {
                        TruthDisposition::Detected {
                            score_ppm,
                            time_to_detect_ns,
                            ..
                        } if score_ppm >= point.threshold_ppm => Some(time_to_detect_ns),
                        TruthDisposition::Detected { .. }
                        | TruthDisposition::Missed
                        | TruthDisposition::NotObservable { .. } => None,
                    })
                    .collect();
                OperatingPoint::WithinBudget {
                    point: *point,
                    time_to_detect: TimeToDetectSummary::from_values(values),
                }
            }
        }
    };

    let precision = Ratio::of(
        true_positives,
        true_positives + false_positives,
        UndefinedReason::NoScoredCandidates,
    );
    let recall = Ratio::of(
        true_positives,
        positives,
        UndefinedReason::NoObservableTruthEvents,
    );

    let label_set_digest = label_set_digest(&sorted_clips, &events)?;
    let candidate_set_digest = candidate_set_digest(&by_id)?;
    let mut report = EvaluationReport {
        identity: identity.clone(),
        policy: *policy,
        label_set_digest,
        candidate_set_digest,
        counts,
        durations,
        pr_curve,
        auprc,
        operating_point,
        precision,
        recall,
        time_to_detect: TimeToDetectSummary::from_values(all_ttd),
        truth_outcomes,
        candidate_outcomes,
        digest: label_set_digest,
    };
    report.digest = report.compute_digest()?;
    Ok(report)
}

fn encode_ttd(encoder: &mut CanonicalEncoder, summary: Option<&TimeToDetectSummary>) {
    match summary {
        Some(summary) => {
            encoder.tag(1);
            encoder.u64(summary.count);
            encoder.u64(summary.min_ns);
            encoder.u64(summary.median_ns);
            encoder.u64(summary.max_ns);
        }
        None => encoder.tag(0),
    }
}

fn encode_point(encoder: &mut CanonicalEncoder, point: &PrPoint) {
    encoder.u32(point.threshold_ppm);
    encoder.u64(point.true_positives);
    encoder.u64(point.false_positives);
    point.precision.encode(encoder);
    point.recall.encode(encoder);
    encoder.bool(point.within_false_alert_budget);
}

impl EvaluationReport {
    /// Recomputes the canonical report digest over every field except `digest` itself.
    pub fn compute_digest(&self) -> Result<ContentDigest, EvaluationError> {
        let mut encoder = domain_encoder("report");
        encoder.text(&self.identity.pipeline_generation);
        encoder.text(&self.identity.model_generation);
        encoder.text(&self.identity.policy_generation);
        encoder.u64(self.policy.early_tolerance_ns);
        encoder.u64(self.policy.late_tolerance_ns);
        encoder.u64(self.policy.false_alert_budget.max_false_alerts);
        encoder.u64(self.policy.false_alert_budget.per_observed_ns);
        encoder.digest(self.label_set_digest);
        encoder.digest(self.candidate_set_digest);
        let counts = &self.counts;
        for value in [
            counts.truth_events,
            counts.observable_truth_events,
            counts.not_observable_truth_events,
            counts.candidates,
            counts.candidates_inside_not_observable,
            counts.candidates_matched_not_observable_truth,
            counts.true_positives,
            counts.false_positives,
            counts.false_negatives,
        ] {
            encoder.u64(value);
        }
        encode_u128(&mut encoder, self.durations.total_ns);
        encode_u128(&mut encoder, self.durations.not_observable_ns);
        encode_u128(&mut encoder, self.durations.observed_ns);
        encoder.u64(self.pr_curve.len() as u64);
        for point in &self.pr_curve {
            encode_point(&mut encoder, point);
        }
        match self.auprc {
            PpmMetric::Defined(ppm) => {
                encoder.tag(1);
                encoder.u32(ppm);
            }
            PpmMetric::Undefined(reason) => {
                encoder.tag(0);
                encoder.tag(reason.tag());
            }
        }
        match &self.operating_point {
            OperatingPoint::WithinBudget {
                point,
                time_to_detect,
            } => {
                encoder.tag(1);
                encode_point(&mut encoder, point);
                encode_ttd(&mut encoder, time_to_detect.as_ref());
            }
            OperatingPoint::NoThresholdWithinBudget {
                false_positives_at_highest_threshold,
            } => {
                encoder.tag(2);
                encoder.u64(*false_positives_at_highest_threshold);
            }
            OperatingPoint::NoScoredCandidates => encoder.tag(3),
            OperatingPoint::NoObservedTime => encoder.tag(4),
        }
        self.precision.encode(&mut encoder);
        self.recall.encode(&mut encoder);
        encode_ttd(&mut encoder, self.time_to_detect.as_ref());
        encoder.u64(self.truth_outcomes.len() as u64);
        for outcome in &self.truth_outcomes {
            encoder.text(&outcome.event_id);
            match &outcome.disposition {
                TruthDisposition::Detected {
                    candidate_id,
                    score_ppm,
                    time_to_detect_ns,
                } => {
                    encoder.tag(1);
                    encoder.text(candidate_id);
                    encoder.u32(*score_ppm);
                    encoder.u64(*time_to_detect_ns);
                }
                TruthDisposition::Missed => encoder.tag(2),
                TruthDisposition::NotObservable {
                    matched_candidate_id,
                } => {
                    encoder.tag(3);
                    encode_option_text(&mut encoder, matched_candidate_id.as_deref());
                }
            }
        }
        encoder.u64(self.candidate_outcomes.len() as u64);
        for outcome in &self.candidate_outcomes {
            encoder.text(&outcome.candidate_id);
            match &outcome.disposition {
                CandidateDisposition::TruePositive { event_id } => {
                    encoder.tag(1);
                    encoder.text(event_id);
                }
                CandidateDisposition::FalsePositive => encoder.tag(2),
                CandidateDisposition::MatchedNotObservableTruth { event_id } => {
                    encoder.tag(3);
                    encoder.text(event_id);
                }
                CandidateDisposition::InsideNotObservable => encoder.tag(4),
            }
        }
        finish_digest(encoder)
    }

    /// Returns true if `digest` matches a recomputation over the report fields.
    #[must_use]
    pub fn verify_digest(&self) -> bool {
        self.compute_digest()
            .is_ok_and(|digest| digest == self.digest)
    }
}
