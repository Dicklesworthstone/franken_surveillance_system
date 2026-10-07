//! Fusion inputs, outputs, validation and canonical encodings.

use std::collections::BTreeSet;
use std::fmt;

use fss_core::{CanonicalEncoder, ContentDigest};

/// Largest admitted magnitude of one log-likelihood-ratio bound, in millibans (100 bans): sums
/// of at most [`MAX_EVIDENCE`] + 1 such bounds stay far inside `i64`.
pub const MAX_ABS_LLR: i64 = 100_000;
/// Maximum observations of one query.
pub const MAX_EVIDENCE: usize = 256;
/// Maximum corroboration opportunities of one query.
pub const MAX_OPPORTUNITIES: usize = 64;
/// Maximum probes of one query.
pub const MAX_PROBES: usize = 64;
/// Maximum failure domains of one observation, opportunity or probe.
pub const MAX_DOMAINS_PER_ITEM: usize = 16;
/// Maximum byte length of one identity, reason or generation text.
pub const MAX_TEXT: usize = 256;

/// A typed fusion refusal.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum FusionError {
    /// A query field is outside its contract (named).
    InvalidInput(String),
    /// The policy is inconsistent (thresholds out of order, zero independence requirement).
    InvalidPolicy(String),
    /// An exact integer sum left its domain.
    Overflow(&'static str),
}

impl FusionError {
    /// Registered stable error identity (`registries/ERRORS.md`).
    #[must_use]
    pub const fn stable_id(&self) -> &'static str {
        match self {
            Self::InvalidInput(_) => "ERR-FUSION-INPUT-INVALID-001",
            Self::InvalidPolicy(_) => "ERR-FUSION-POLICY-INVALID-001",
            Self::Overflow(_) => "ERR-FUSION-NUMERIC-OVERFLOW-001",
        }
    }
}

impl fmt::Display for FusionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidInput(what) => write!(formatter, "invalid fusion input: {what}"),
            Self::InvalidPolicy(what) => write!(formatter, "invalid fusion policy: {what}"),
            Self::Overflow(what) => write!(formatter, "{what} overflowed its exact domain"),
        }
    }
}

impl std::error::Error for FusionError {}

pub(crate) fn valid_text(text: &str) -> bool {
    !text.is_empty() && text.len() <= MAX_TEXT && !text.chars().any(char::is_control)
}

fn require_text(text: &str, what: &str) -> Result<(), FusionError> {
    if valid_text(text) {
        Ok(())
    } else {
        Err(FusionError::InvalidInput(format!("{what} {text:?}")))
    }
}

/// A closed interval of log-odds (or log-likelihood ratios) in millibans.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct LlrInterval {
    lo: i64,
    hi: i64,
}

impl LlrInterval {
    /// `[lo, hi]` in millibans.
    ///
    /// # Errors
    ///
    /// [`FusionError::InvalidInput`] when `lo > hi` or a bound exceeds [`MAX_ABS_LLR`].
    pub fn new(lo: i64, hi: i64) -> Result<Self, FusionError> {
        if lo > hi || lo.abs() > MAX_ABS_LLR || hi.abs() > MAX_ABS_LLR {
            return Err(FusionError::InvalidInput(format!(
                "log-likelihood interval [{lo}, {hi}] (lo <= hi, |bound| <= {MAX_ABS_LLR})"
            )));
        }
        Ok(Self { lo, hi })
    }

    /// The point interval `[value, value]`.
    ///
    /// # Errors
    ///
    /// As [`Self::new`].
    pub fn point(value: i64) -> Result<Self, FusionError> {
        Self::new(value, value)
    }

    /// An interval of derived sums (bounds already checked by the caller's arithmetic).
    pub(crate) const fn unchecked(lo: i64, hi: i64) -> Self {
        Self { lo, hi }
    }

    /// Lower bound.
    #[must_use]
    pub const fn lo(self) -> i64 {
        self.lo
    }

    /// Upper bound.
    #[must_use]
    pub const fn hi(self) -> i64 {
        self.hi
    }

    /// The smallest interval containing both.
    #[must_use]
    pub fn hull(self, other: Self) -> Self {
        Self {
            lo: self.lo.min(other.lo),
            hi: self.hi.max(other.hi),
        }
    }

    pub(crate) fn encode(self, encoder: &mut CanonicalEncoder) {
        encoder.i128(i128::from(self.lo));
        encoder.i128(i128::from(self.hi));
    }
}

/// How an observation's likelihood is known.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Calibration {
    /// A calibration generation bounds its log-likelihood ratio for this hypothesis.
    Calibrated {
        /// Calibration certificate or generation identity.
        generation: String,
        /// Log-likelihood ratio interval (positive supports the hypothesis).
        llr: LlrInterval,
    },
    /// No admitted calibration: the score has no numeric authority and is never fused.
    Uncalibrated {
        /// Why (for example `no calibration for this mode`).
        reason: String,
    },
}

/// Whether the observation can be used at all.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Observability {
    /// Observed under the declared calibration.
    Observed,
    /// The sensor could not observe (gap, dark, occluded, out of frame): not absence.
    NotObservable {
        /// Why.
        reason: String,
    },
    /// Withheld by a privacy transform.
    Redacted,
    /// Superseded by newer evidence or outside its validity.
    Stale,
}

/// One observation offered to fusion.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EvidenceItem {
    /// Stable identity (for example the model result digest).
    pub id: String,
    /// Producing sensor.
    pub sensor: String,
    /// Every declared failure domain (at least the sensor's).
    pub failure_domains: BTreeSet<String>,
    /// Likelihood knowledge.
    pub calibration: Calibration,
    /// Usability.
    pub observability: Observability,
}

/// Coverage of the hypothesis's zone and interval.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Coverage {
    /// Every relevant cell certified observed for the whole interval.
    Complete,
    /// Observed with degraded quality or partial cells.
    Degraded {
        /// Why.
        reason: String,
    },
    /// Some relevant cell or time was not observable.
    Gap {
        /// Why.
        reason: String,
    },
}

/// A predicted observation by another sensor (for example an `ALG-TREACH-001` arrival window).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Opportunity {
    /// Stable identity.
    pub id: String,
    /// The sensor expected to observe.
    pub sensor: String,
    /// Its declared failure domains.
    pub failure_domains: BTreeSet<String>,
    /// Earliest expected observation (evidence clock, ns).
    pub window_start: u64,
    /// Latest expected observation (evidence clock, ns): the wait deadline.
    pub window_end: u64,
    /// Calibrated log-likelihood ratio if it observes the entity.
    pub positive: LlrInterval,
    /// Calibrated log-likelihood ratio if it observes and finds nothing.
    pub negative: LlrInterval,
}

/// An observation the system can request (verifier model, crop, PTZ pose, higher frame rate).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Probe {
    /// Stable identity.
    pub id: String,
    /// Kind label.
    pub kind: String,
    /// Its declared failure domains.
    pub failure_domains: BTreeSet<String>,
    /// Full cost in loss units (compute, privacy exposure, energy, operator attention).
    pub cost: u64,
    /// Latency until its answer (ns).
    pub latency_ns: u64,
    /// Calibrated log-likelihood ratio of a positive answer.
    pub positive: LlrInterval,
    /// Calibrated log-likelihood ratio of a negative answer.
    pub negative: LlrInterval,
}

/// Consequence profile of the hypothesis — distinct from its probability.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Severity {
    /// Expected harm of a missed true threat (loss units).
    pub expected_harm: u64,
    /// Cost of one false alert (loss units).
    pub false_alert_cost: u64,
    /// Loss per second of delaying the decision while a true threat continues.
    pub delay_cost_per_second: u64,
    /// The harm can be undone (affects nothing automatically; recorded for the operator).
    pub reversible: bool,
}

/// A versioned calibrated decision policy (layer 3; never adapted online).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FusionPolicy {
    /// Policy generation identity.
    pub generation: String,
    /// Robust posterior log-odds at or above which an alert is warranted (millibans).
    pub alert_threshold: i64,
    /// Posterior upper bound below which the hypothesis is retained silently.
    pub retain_threshold: i64,
    /// Posterior upper bound at or below which the hypothesis may be rejected (only with
    /// complete coverage).
    pub reject_threshold: i64,
    /// Independent supporting clusters an alert needs (corroboration).
    pub min_independent_support: u32,
    /// Registered urgent exception: a single-domain alert, labeled unconfirmed, when the
    /// robust posterior reaches this threshold.
    pub urgent_single_domain_threshold: Option<i64>,
    /// Longest admissible wait for corroboration (ns).
    pub max_wait_ns: u64,
    /// Alert-threshold increase per doubling of looks (millibans; 3010 is Bonferroni).
    pub look_penalty_per_doubling: i64,
    /// An operator can be asked to confirm.
    pub operator_confirmation_available: bool,
}

impl FusionPolicy {
    pub(crate) fn validate(&self) -> Result<(), FusionError> {
        if !valid_text(&self.generation) {
            return Err(FusionError::InvalidPolicy("generation".to_owned()));
        }
        let bounded = |value: i64| value.abs() <= 1_000 * MAX_ABS_LLR;
        if !(self.reject_threshold < self.retain_threshold
            && self.retain_threshold <= self.alert_threshold)
            || !bounded(self.reject_threshold)
            || !bounded(self.alert_threshold)
        {
            return Err(FusionError::InvalidPolicy(
                "thresholds must satisfy reject < retain <= alert within bounds".to_owned(),
            ));
        }
        if self.min_independent_support == 0 {
            return Err(FusionError::InvalidPolicy(
                "min_independent_support must be at least 1".to_owned(),
            ));
        }
        if let Some(urgent) = self.urgent_single_domain_threshold
            && (urgent < self.retain_threshold || !bounded(urgent))
        {
            return Err(FusionError::InvalidPolicy(
                "the urgent single-domain threshold must not be below retain".to_owned(),
            ));
        }
        if !(0..=MAX_ABS_LLR).contains(&self.look_penalty_per_doubling) {
            return Err(FusionError::InvalidPolicy("look penalty".to_owned()));
        }
        Ok(())
    }

    pub(crate) fn encode(&self, encoder: &mut CanonicalEncoder) {
        encoder.text(&self.generation);
        encoder.i128(i128::from(self.alert_threshold));
        encoder.i128(i128::from(self.retain_threshold));
        encoder.i128(i128::from(self.reject_threshold));
        encoder.u32(self.min_independent_support);
        match self.urgent_single_domain_threshold {
            None => encoder.tag(0),
            Some(value) => {
                encoder.tag(1);
                encoder.i128(i128::from(value));
            }
        }
        encoder.u64(self.max_wait_ns);
        encoder.i128(i128::from(self.look_penalty_per_doubling));
        encoder.bool(self.operator_confirmation_available);
    }
}

/// One complete fusion question.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FusionQuery {
    /// Hypothesis identity (event id).
    pub hypothesis: String,
    /// Event kind label.
    pub kind: String,
    /// Prior log-odds interval (base rate of this kind in this zone and mode).
    pub prior: LlrInterval,
    /// Observations.
    pub evidence: Vec<EvidenceItem>,
    /// Coverage of the hypothesis's zone and interval.
    pub coverage: Coverage,
    /// Predicted corroborating observations.
    pub opportunities: Vec<Opportunity>,
    /// Requestable observations.
    pub probes: Vec<Probe>,
    /// Consequence profile.
    pub severity: Severity,
    /// The decision policy.
    pub policy: FusionPolicy,
    /// How many times this hypothesis has been evaluated, including this time (>= 1).
    pub looks: u32,
    /// Evidence-clock time of this evaluation (ns).
    pub now_ns: u64,
}

fn validate_domains(domains: &BTreeSet<String>, what: &str) -> Result<(), FusionError> {
    if domains.is_empty() || domains.len() > MAX_DOMAINS_PER_ITEM {
        return Err(FusionError::InvalidInput(format!(
            "{what} must declare 1..={MAX_DOMAINS_PER_ITEM} failure domains"
        )));
    }
    for domain in domains {
        require_text(domain, "failure domain")?;
    }
    Ok(())
}

impl FusionQuery {
    pub(crate) fn validate(&self) -> Result<(), FusionError> {
        require_text(&self.hypothesis, "hypothesis")?;
        require_text(&self.kind, "kind")?;
        self.policy.validate()?;
        if self.looks == 0 {
            return Err(FusionError::InvalidInput(
                "looks must be at least 1".to_owned(),
            ));
        }
        if self.evidence.len() > MAX_EVIDENCE
            || self.opportunities.len() > MAX_OPPORTUNITIES
            || self.probes.len() > MAX_PROBES
        {
            return Err(FusionError::InvalidInput("too many items".to_owned()));
        }
        let mut ids = BTreeSet::new();
        for item in &self.evidence {
            require_text(&item.id, "evidence id")?;
            require_text(&item.sensor, "sensor")?;
            validate_domains(&item.failure_domains, &item.id)?;
            if !ids.insert(item.id.as_str()) {
                return Err(FusionError::InvalidInput(format!(
                    "duplicate evidence {}",
                    item.id
                )));
            }
            match &item.calibration {
                Calibration::Calibrated { generation, .. } => {
                    require_text(generation, "calibration")?
                }
                Calibration::Uncalibrated { reason } => require_text(reason, "reason")?,
            }
            if let Observability::NotObservable { reason } = &item.observability {
                require_text(reason, "reason")?;
            }
        }
        let mut other = BTreeSet::new();
        for opportunity in &self.opportunities {
            require_text(&opportunity.id, "opportunity id")?;
            require_text(&opportunity.sensor, "sensor")?;
            validate_domains(&opportunity.failure_domains, &opportunity.id)?;
            if opportunity.window_start > opportunity.window_end {
                return Err(FusionError::InvalidInput(format!(
                    "opportunity {} window is inverted",
                    opportunity.id
                )));
            }
            if !other.insert(opportunity.id.as_str()) {
                return Err(FusionError::InvalidInput(format!(
                    "duplicate opportunity {}",
                    opportunity.id
                )));
            }
        }
        for probe in &self.probes {
            require_text(&probe.id, "probe id")?;
            require_text(&probe.kind, "probe kind")?;
            validate_domains(&probe.failure_domains, &probe.id)?;
            if !other.insert(probe.id.as_str()) {
                return Err(FusionError::InvalidInput(format!(
                    "duplicate probe {}",
                    probe.id
                )));
            }
        }
        match &self.coverage {
            Coverage::Complete => {}
            Coverage::Degraded { reason } | Coverage::Gap { reason } => {
                require_text(reason, "reason")?
            }
        }
        Ok(())
    }

    /// Canonical digest of the whole query (evidence, opportunities and probes in identity
    /// order, so caller order never changes it).
    #[must_use]
    pub fn digest(&self) -> ContentDigest {
        let mut encoder = CanonicalEncoder::new();
        encoder.text(crate::FUSION_QUERY_DOMAIN);
        encoder.text(crate::IMPLEMENTATION_ID);
        encoder.text(&self.hypothesis);
        encoder.text(&self.kind);
        self.prior.encode(&mut encoder);
        let mut evidence: Vec<&EvidenceItem> = self.evidence.iter().collect();
        evidence.sort_by(|a, b| a.id.cmp(&b.id));
        encoder.u64(evidence.len() as u64);
        for item in evidence {
            encoder.text(&item.id);
            encoder.text(&item.sensor);
            encode_set(&mut encoder, &item.failure_domains);
            match &item.calibration {
                Calibration::Calibrated { generation, llr } => {
                    encoder.tag(0);
                    encoder.text(generation);
                    llr.encode(&mut encoder);
                }
                Calibration::Uncalibrated { reason } => {
                    encoder.tag(1);
                    encoder.text(reason);
                }
            }
            match &item.observability {
                Observability::Observed => encoder.tag(0),
                Observability::NotObservable { reason } => {
                    encoder.tag(1);
                    encoder.text(reason);
                }
                Observability::Redacted => encoder.tag(2),
                Observability::Stale => encoder.tag(3),
            }
        }
        match &self.coverage {
            Coverage::Complete => encoder.tag(0),
            Coverage::Degraded { reason } => {
                encoder.tag(1);
                encoder.text(reason);
            }
            Coverage::Gap { reason } => {
                encoder.tag(2);
                encoder.text(reason);
            }
        }
        let mut opportunities: Vec<&Opportunity> = self.opportunities.iter().collect();
        opportunities.sort_by(|a, b| a.id.cmp(&b.id));
        encoder.u64(opportunities.len() as u64);
        for opportunity in opportunities {
            encoder.text(&opportunity.id);
            encoder.text(&opportunity.sensor);
            encode_set(&mut encoder, &opportunity.failure_domains);
            encoder.u64(opportunity.window_start);
            encoder.u64(opportunity.window_end);
            opportunity.positive.encode(&mut encoder);
            opportunity.negative.encode(&mut encoder);
        }
        let mut probes: Vec<&Probe> = self.probes.iter().collect();
        probes.sort_by(|a, b| a.id.cmp(&b.id));
        encoder.u64(probes.len() as u64);
        for probe in probes {
            encoder.text(&probe.id);
            encoder.text(&probe.kind);
            encode_set(&mut encoder, &probe.failure_domains);
            encoder.u64(probe.cost);
            encoder.u64(probe.latency_ns);
            probe.positive.encode(&mut encoder);
            probe.negative.encode(&mut encoder);
        }
        encoder.u64(self.severity.expected_harm);
        encoder.u64(self.severity.false_alert_cost);
        encoder.u64(self.severity.delay_cost_per_second);
        encoder.bool(self.severity.reversible);
        self.policy.encode(&mut encoder);
        encoder.u32(self.looks);
        encoder.u64(self.now_ns);
        ContentDigest::sha256(&encoder.finish())
    }
}

pub(crate) fn encode_set(encoder: &mut CanonicalEncoder, values: &BTreeSet<String>) {
    encoder.u64(values.len() as u64);
    for value in values {
        encoder.text(value);
    }
}

/// Direction of one dependency cluster's likelihood interval.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum ClusterDirection {
    /// Every admissible likelihood supports the hypothesis (`lo > 0`).
    Supports,
    /// Every admissible likelihood contradicts it (`hi < 0`).
    Contradicts,
    /// Members disagree (`lo < 0 < hi`): the cluster is internally conflicted.
    Conflicted,
    /// No information either way.
    Neutral,
}

impl ClusterDirection {
    /// Stable spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Supports => "supports",
            Self::Contradicts => "contradicts",
            Self::Conflicted => "conflicted",
            Self::Neutral => "neutral",
        }
    }
}

/// One dependency cluster: observations joined by any shared failure domain.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Cluster {
    /// Position in identity order of the clusters' smallest members.
    pub label: u32,
    /// Member observation identities, ascending.
    pub members: Vec<String>,
    /// Union of the members' failure domains.
    pub failure_domains: BTreeSet<String>,
    /// Hull of the members' likelihood intervals (counted once).
    pub llr: LlrInterval,
    /// Direction.
    pub direction: ClusterDirection,
}

/// The decision.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Decision {
    /// Robustly above the (look-corrected) alert threshold with enough independent support and
    /// complete coverage.
    Alert,
    /// As [`Self::Alert`] but coverage is degraded or gapped: alert with that uncertainty.
    AlertDegradedCoverage,
    /// Registered urgent exception: alert from too few independent domains, labeled
    /// single-domain and unconfirmed.
    AlertSingleDomainUnconfirmed,
    /// Wait for one predicted independent observation until its deadline.
    WaitForCorroboration {
        /// Opportunity identity.
        opportunity: String,
        /// Evidence-clock deadline (ns); never later than `now + max_wait`.
        deadline_ns: u64,
        /// Upper bound of the wait's value: robust decision loss now minus delay loss.
        value_bound: u64,
    },
    /// Request one decision-relevant observation.
    RequestObservation {
        /// Probe identity.
        probe: String,
        /// Upper bound of its value: robust decision loss now minus cost and delay loss.
        value_bound: u64,
    },
    /// Ask the operator to confirm.
    RequestOperatorConfirmation,
    /// Low risk: retain the evidence without notifying.
    RetainSilently,
    /// Robustly below the reject threshold with complete coverage; evidence retained.
    Reject,
    /// Undecided and no admissible action resolves it: keep the hypothesis open.
    HoldIndeterminate,
}

impl Decision {
    /// Stable spelling.
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Alert => "alert",
            Self::AlertDegradedCoverage => "alert_degraded_coverage",
            Self::AlertSingleDomainUnconfirmed => "alert_single_domain_unconfirmed",
            Self::WaitForCorroboration { .. } => "wait_for_corroboration",
            Self::RequestObservation { .. } => "request_observation",
            Self::RequestOperatorConfirmation => "request_operator_confirmation",
            Self::RetainSilently => "retain_silently",
            Self::Reject => "reject",
            Self::HoldIndeterminate => "hold_indeterminate",
        }
    }

    pub(crate) fn encode(&self, encoder: &mut CanonicalEncoder) {
        encoder.text(self.as_str());
        match self {
            Self::WaitForCorroboration {
                opportunity,
                deadline_ns,
                value_bound,
            } => {
                encoder.text(opportunity);
                encoder.u64(*deadline_ns);
                encoder.u64(*value_bound);
            }
            Self::RequestObservation { probe, value_bound } => {
                encoder.text(probe);
                encoder.u64(*value_bound);
            }
            _ => {}
        }
    }
}

/// Why the decision is what it is (every applicable reason, in this order).
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum Reason {
    /// The robust lower bound reaches the look-corrected alert threshold.
    AboveAlertThreshold,
    /// Fewer independent supporting clusters than the policy requires.
    InsufficientIndependentSupport,
    /// Coverage is degraded or gapped.
    CoverageNotComplete,
    /// The upper bound is at or below the reject threshold.
    BelowRejectThreshold,
    /// A low posterior cannot certify absence: coverage incomplete or observations missing.
    AbsenceNotCertified,
    /// The upper bound is below the retain threshold.
    BelowRetainThreshold,
    /// The interval straddles the decision thresholds.
    Undecided,
    /// Clusters disagree.
    ConflictingEvidence,
    /// Some observations were not observable, redacted or stale.
    MissingObservations,
    /// Some scores were uncalibrated and not fused.
    UncalibratedEvidenceIgnored,
    /// Repeated looks raised the alert threshold.
    OptionalStoppingCorrection,
    /// No wait, probe or confirmation is admissible.
    NoDecisionRelevantObservation,
}

impl Reason {
    /// Stable spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::AboveAlertThreshold => "above_alert_threshold",
            Self::InsufficientIndependentSupport => "insufficient_independent_support",
            Self::CoverageNotComplete => "coverage_not_complete",
            Self::BelowRejectThreshold => "below_reject_threshold",
            Self::AbsenceNotCertified => "absence_not_certified",
            Self::BelowRetainThreshold => "below_retain_threshold",
            Self::Undecided => "undecided",
            Self::ConflictingEvidence => "conflicting_evidence",
            Self::MissingObservations => "missing_observations",
            Self::UncalibratedEvidenceIgnored => "uncalibrated_evidence_ignored",
            Self::OptionalStoppingCorrection => "optional_stopping_correction",
            Self::NoDecisionRelevantObservation => "no_decision_relevant_observation",
        }
    }
}

/// The decision with one dependency cluster removed.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Counterfactual {
    /// Removed cluster label.
    pub removed_cluster: u32,
    /// Posterior without it.
    pub posterior: LlrInterval,
    /// Decision without it.
    pub decision: Decision,
}

/// The complete, digest-bound answer.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FusionOutcome {
    /// Digest of the query.
    pub query_digest: ContentDigest,
    /// Policy generation.
    pub policy_generation: String,
    /// Dependency clusters of the calibrated observed evidence.
    pub clusters: Vec<Cluster>,
    /// `(observation, reason)` of everything not fused because it was not observed.
    pub excluded: Vec<(String, String)>,
    /// Observed but uncalibrated observations (never fused).
    pub uncalibrated: Vec<String>,
    /// Posterior log-odds interval (millibans).
    pub posterior: LlrInterval,
    /// Outward-rounded posterior probability bounds (parts per million).
    pub probability_ppm: (u32, u32),
    /// Robustly supporting clusters.
    pub supporting_clusters: u32,
    /// Robustly contradicting clusters.
    pub contradicting_clusters: u32,
    /// Knowledge state of the hypothesis (`estimated`, `conflicted`, `unknown`,
    /// `not_observable`).
    pub knowledge_state: &'static str,
    /// Alert threshold after the optional-stopping correction.
    pub sequential_alert_threshold: i64,
    /// The decision.
    pub decision: Decision,
    /// Every applicable reason, in [`Reason`] order.
    pub reasons: Vec<Reason>,
    /// Additional robust independent support (millibans) that would reach the alert threshold,
    /// when below it.
    pub support_to_alert: Option<i64>,
    /// Reduction of the upper bound (millibans) that would fall below the retain threshold,
    /// when at or above it.
    pub reduction_to_retain: Option<i64>,
    /// Decision with each cluster removed, in label order.
    pub counterfactuals: Vec<Counterfactual>,
    /// Digest of the query digest and every field above.
    pub decision_digest: ContentDigest,
}

impl FusionOutcome {
    pub(crate) fn seal(mut self) -> Self {
        let mut encoder = CanonicalEncoder::new();
        encoder.text(crate::FUSION_DECISION_DOMAIN);
        encoder.text(&self.query_digest.to_text());
        encoder.text(&self.policy_generation);
        encoder.u64(self.clusters.len() as u64);
        for cluster in &self.clusters {
            encoder.u32(cluster.label);
            encoder.u64(cluster.members.len() as u64);
            for member in &cluster.members {
                encoder.text(member);
            }
            encode_set(&mut encoder, &cluster.failure_domains);
            cluster.llr.encode(&mut encoder);
            encoder.text(cluster.direction.as_str());
        }
        encoder.u64(self.excluded.len() as u64);
        for (id, reason) in &self.excluded {
            encoder.text(id);
            encoder.text(reason);
        }
        encoder.u64(self.uncalibrated.len() as u64);
        for id in &self.uncalibrated {
            encoder.text(id);
        }
        self.posterior.encode(&mut encoder);
        encoder.u32(self.probability_ppm.0);
        encoder.u32(self.probability_ppm.1);
        encoder.u32(self.supporting_clusters);
        encoder.u32(self.contradicting_clusters);
        encoder.text(self.knowledge_state);
        encoder.i128(i128::from(self.sequential_alert_threshold));
        self.decision.encode(&mut encoder);
        encoder.u64(self.reasons.len() as u64);
        for reason in &self.reasons {
            encoder.text(reason.as_str());
        }
        for margin in [self.support_to_alert, self.reduction_to_retain] {
            match margin {
                None => encoder.tag(0),
                Some(value) => {
                    encoder.tag(1);
                    encoder.i128(i128::from(value));
                }
            }
        }
        encoder.u64(self.counterfactuals.len() as u64);
        for counterfactual in &self.counterfactuals {
            encoder.u32(counterfactual.removed_cluster);
            counterfactual.posterior.encode(&mut encoder);
            counterfactual.decision.encode(&mut encoder);
        }
        self.decision_digest = ContentDigest::sha256(&encoder.finish());
        self
    }
}
