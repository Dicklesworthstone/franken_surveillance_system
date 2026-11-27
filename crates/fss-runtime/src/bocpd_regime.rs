#![forbid(unsafe_code)]
//! Bounded deterministic scalar Bayesian Online Change-Point Detection (BOCPD) regime monitor
//! (`DOC-049`, bead `fss-x4a.5.49`, import reference `IMP-FSQL-BOCPD-001`).
//!
//! Identifies operational workload or sensor regimes strictly as **advisory derived cognition**:
//! - Fixed registered Normal-Inverse-Gamma conjugate priors and constant geometric hazard.
//! - Bounded run-length distribution (`4..=MAX_BOCPD_RUN_LENGTH`) with exact tail mass conservation
//!   and deterministic log-space arithmetic (rejects NaN/Inf inputs fail-closed).
//! - Separates non-regime operational causes (`ClockGap`, `SensorReconnect`, `ConfigChange`) into
//!   explicit bounded resets rather than false change-point alarms.
//! - Enforces that privacy transformations precede monitoring (`privacy_minimized == true`).
//! - Emits [`RegimeHypothesis`] with `is_event_evidence == false` (never intrusion/tamper truth).
//! - Clamps [`AdvisoryProposal`] strictly to advisory tuning knobs (`inspection_depth`,
//!   `batch_size`, `candidate_count`, `path_allocation_bps`) — structurally incapable of weakening
//!   authority, freshness, coverage, integrity, privacy, retention, or verification.
//! - Enforces hysteresis, cooldown, mandatory shadow evaluation, prior complete generation
//!   preservation, root-last activation, and rollback into negative evidence on harmful proposals.

use core::f64::consts::PI;
use core::fmt;

use fss_core::{
    CanonicalDecode, CanonicalDecoder, CanonicalEncode, CanonicalEncoder, ContentDigest,
    ContractError, Generation, TimestampNs,
};

/// Registered digest domain for canonical BOCPD advisory activation/rollback receipts
/// (`SCHEMA-DOMAIN-RUNTIME-BOCPD-ADVISORY-001`).
pub const BOCPD_ADVISORY_RECEIPT_DOMAIN: &str = "fss.runtime.bocpd_advisory_receipt.v1";

/// Canonical binary format version for [`BocpdAdvisoryReceipt`].
pub const BOCPD_ADVISORY_FORMAT_VERSION: u32 = 1;

/// Hard upper bound on tracked run-length states (prevents unbounded state growth).
pub const MAX_BOCPD_RUN_LENGTH: usize = 256;

/// Hard lower bound on tracked run-length states.
pub const MIN_BOCPD_RUN_LENGTH: usize = 4;

/// Maximum UTF-8 bytes in monitor/explanation/reason labels.
pub const MAX_BOCPD_LABEL_BYTES: usize = 128;

/// Maximum retained negative-evidence rollback entries per monitor instance.
pub const MAX_NEGATIVE_EVIDENCE_RECORDS: usize = 64;

/// Fixed Normal-Inverse-Gamma conjugate prior parameters for scalar BOCPD.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct BocpdPrior {
    /// Prior mean `mu_0`.
    pub mu0: f64,
    /// Prior mean precision weight `kappa_0 > 0`.
    pub kappa0: f64,
    /// Prior shape parameter `alpha_0 > 0`.
    pub alpha0: f64,
    /// Prior scale parameter `beta_0 > 0`.
    pub beta0: f64,
}

impl Default for BocpdPrior {
    fn default() -> Self {
        Self {
            mu0: 0.0,
            kappa0: 1.0,
            alpha0: 1.0,
            beta0: 1.0,
        }
    }
}

impl BocpdPrior {
    /// Validates finiteness and strict positivity of prior parameters.
    pub fn validate(self) -> Result<(), BocpdError> {
        if !self.mu0.is_finite()
            || !self.kappa0.is_finite()
            || !self.alpha0.is_finite()
            || !self.beta0.is_finite()
            || self.kappa0 <= 0.0
            || self.alpha0 <= 0.0
            || self.beta0 <= 0.0
        {
            return Err(BocpdError::InvalidConfiguration("invalid_nig_prior"));
        }
        Ok(())
    }
}

/// Hard safety clamp envelope constraining every advisory tuning proposal (`DOC-049`).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AdvisoryClampBounds {
    /// Allowed inclusive range for inspection depth (`1..=max`).
    pub min_inspection_depth: u16,
    /// Maximum inspection depth.
    pub max_inspection_depth: u16,
    /// Allowed inclusive range for inference/processing batch size.
    pub min_batch_size: u16,
    /// Maximum batch size.
    pub max_batch_size: u16,
    /// Allowed inclusive range for candidate count.
    pub min_candidate_count: u16,
    /// Maximum candidate count.
    pub max_candidate_count: u16,
    /// Allowed inclusive range for advisory path allocation share in basis points (`0..=10_000`).
    pub min_path_allocation_bps: u16,
    /// Maximum path allocation share in basis points (`<= 10_000`).
    pub max_path_allocation_bps: u16,
}

impl Default for AdvisoryClampBounds {
    fn default() -> Self {
        Self {
            min_inspection_depth: 1,
            max_inspection_depth: 8,
            min_batch_size: 1,
            max_batch_size: 32,
            min_candidate_count: 1,
            max_candidate_count: 64,
            min_path_allocation_bps: 1_000,
            max_path_allocation_bps: 9_000,
        }
    }
}

impl AdvisoryClampBounds {
    /// Validates monotonic, non-zero clamp bounds.
    pub fn validate(self) -> Result<(), BocpdError> {
        if self.min_inspection_depth == 0
            || self.min_inspection_depth > self.max_inspection_depth
            || self.min_batch_size == 0
            || self.min_batch_size > self.max_batch_size
            || self.min_candidate_count == 0
            || self.min_candidate_count > self.max_candidate_count
            || self.min_path_allocation_bps > self.max_path_allocation_bps
            || self.max_path_allocation_bps > 10_000
        {
            return Err(BocpdError::InvalidConfiguration("invalid_clamp_bounds"));
        }
        Ok(())
    }

    /// Returns `true` iff every field in `params` sits within hard bounds and weakens no invariants.
    #[must_use]
    pub const fn admits(self, params: AdvisoryParameters) -> bool {
        !params.weakens_invariants
            && params.inspection_depth >= self.min_inspection_depth
            && params.inspection_depth <= self.max_inspection_depth
            && params.batch_size >= self.min_batch_size
            && params.batch_size <= self.max_batch_size
            && params.candidate_count >= self.min_candidate_count
            && params.candidate_count <= self.max_candidate_count
            && params.path_allocation_bps >= self.min_path_allocation_bps
            && params.path_allocation_bps <= self.max_path_allocation_bps
    }
}

/// Complete immutable set of advisory tuning parameters controlled by a policy generation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AdvisoryParameters {
    /// Pipeline inspection depth knob.
    pub inspection_depth: u16,
    /// Processing batch size knob.
    pub batch_size: u16,
    /// Candidate fanout count knob.
    pub candidate_count: u16,
    /// Preferred path allocation share in basis points (`0..=10_000`).
    pub path_allocation_bps: u16,
    /// MUST remain `false`: advisory adaptation may never weaken authority, freshness, coverage,
    /// integrity, privacy, retention, or verification invariants.
    pub weakens_invariants: bool,
}

impl Default for AdvisoryParameters {
    fn default() -> Self {
        Self {
            inspection_depth: 2,
            batch_size: 4,
            candidate_count: 8,
            path_allocation_bps: 5_000,
            weakens_invariants: false,
        }
    }
}

impl CanonicalEncode for AdvisoryParameters {
    fn encode_canonical(&self, encoder: &mut CanonicalEncoder) {
        encoder.u32(u32::from(self.inspection_depth));
        encoder.u32(u32::from(self.batch_size));
        encoder.u32(u32::from(self.candidate_count));
        encoder.u32(u32::from(self.path_allocation_bps));
        encoder.u8(u8::from(self.weakens_invariants));
    }
}

impl CanonicalDecode for AdvisoryParameters {
    fn decode_canonical(decoder: &mut CanonicalDecoder<'_>) -> Result<Self, ContractError> {
        let inspection_depth =
            u16::try_from(decoder.u32()?).map_err(|_| ContractError::InvalidIdentifier)?;
        let batch_size =
            u16::try_from(decoder.u32()?).map_err(|_| ContractError::InvalidIdentifier)?;
        let candidate_count =
            u16::try_from(decoder.u32()?).map_err(|_| ContractError::InvalidIdentifier)?;
        let path_allocation_bps =
            u16::try_from(decoder.u32()?).map_err(|_| ContractError::InvalidIdentifier)?;
        let weakens_invariants = match decoder.u8()? {
            0 => false,
            1 => true,
            _ => return Err(ContractError::InvalidIdentifier),
        };
        if inspection_depth == 0
            || batch_size == 0
            || candidate_count == 0
            || path_allocation_bps > 10_000
            || weakens_invariants
        {
            return Err(ContractError::InvalidIdentifier);
        }
        Ok(Self {
            inspection_depth,
            batch_size,
            candidate_count,
            path_allocation_bps,
            weakens_invariants,
        })
    }
}

/// Registered configuration for one bounded scalar BOCPD regime monitor.
#[derive(Clone, Debug, PartialEq)]
pub struct BocpdConfig {
    /// Clean stable monitor identifier.
    pub monitor_id: String,
    /// Pinned baseline advisory policy generation (`>= 1`).
    pub initial_generation: Generation,
    /// Fixed registered NIG conjugate prior.
    pub prior: BocpdPrior,
    /// Constant change-point hazard in parts per million (`1..=500_000`).
    pub hazard_ppm: u32,
    /// Bounded run-length truncation (`4..=MAX_BOCPD_RUN_LENGTH`).
    pub max_run_length: usize,
    /// Short-run window (`0..=short_run_window`) summed for regime-shift posterior probability.
    pub short_run_window: usize,
    /// Posterior shift threshold in basis points (`1..=10_000`) to count as a regime trigger.
    pub trigger_threshold_bps: u16,
    /// Minimum consecutive triggered observations before proposing adaptation (hysteresis).
    pub hysteresis_min_steps: u16,
    /// Minimum cooldown duration between advisory policy activations/rollbacks in nanoseconds.
    pub cooldown_ns: i128,
    /// Expiration horizon added to observation timestamps for each emitted [`RegimeHypothesis`].
    pub hypothesis_ttl_ns: i128,
    /// Minimum observation coverage (`0..=10_000` bps) required to update statistics.
    pub min_coverage_bps: u16,
    /// Hard safety clamp bounds for advisory proposals.
    pub clamp_bounds: AdvisoryClampBounds,
    /// Safe baseline advisory parameters for `initial_generation`.
    pub baseline_params: AdvisoryParameters,
}

impl BocpdConfig {
    /// Validates all configuration bounds fail-closed.
    pub fn validate(&self) -> Result<(), BocpdError> {
        if !is_clean_label(&self.monitor_id)
            || self.initial_generation.0 == 0
            || !(1..=500_000).contains(&self.hazard_ppm)
            || !(MIN_BOCPD_RUN_LENGTH..=MAX_BOCPD_RUN_LENGTH).contains(&self.max_run_length)
            || self.short_run_window >= self.max_run_length
            || self.short_run_window < usize::from(self.hysteresis_min_steps)
            || !(1..=10_000).contains(&self.trigger_threshold_bps)
            || self.hysteresis_min_steps == 0
            || self.cooldown_ns < 0
            || self.hypothesis_ttl_ns <= 0
            || self.min_coverage_bps > 10_000
        {
            return Err(BocpdError::InvalidConfiguration("invalid_bocpd_config"));
        }
        self.prior.validate()?;
        self.clamp_bounds.validate()?;
        if !self.clamp_bounds.admits(self.baseline_params) {
            return Err(BocpdError::InvalidConfiguration(
                "baseline_outside_clamp_bounds",
            ));
        }
        Ok(())
    }
}

/// Distinguishes nominal observations from separate operational non-regime causes (`DOC-049`).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ObservationCause {
    /// Normal operational/sensor summary tick.
    Nominal,
    /// Clock discontinuity / skew gap (must reset cleanly, never trigger false change-point).
    ClockGap,
    /// Sensor disconnect/reconnect boundary (must reset cleanly).
    SensorReconnect,
    /// Explicit operator/config generation change (must reset cleanly).
    ConfigChange,
}

impl ObservationCause {
    /// Stable canonical machine spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Nominal => "nominal",
            Self::ClockGap => "clock_gap",
            Self::SensorReconnect => "sensor_reconnect",
            Self::ConfigChange => "config_change",
        }
    }
}

/// Typed operational/sensor summary fed into [`BocpdRegimeMonitor`].
#[derive(Clone, Debug, PartialEq)]
pub struct RegimeObservation {
    /// Monotonic observation timestamp in nanoseconds.
    pub timestamp_ns: TimestampNs,
    /// Finite scalar metric value (e.g., privacy-safe queue depth, frame inter-arrival jitter).
    pub value: f64,
    /// Observation coverage in basis points (`0..=10_000`).
    pub coverage_bps: u16,
    /// Content digest of the upstream summary provenance record.
    pub source_digest: ContentDigest,
    /// MUST be `true`: privacy transformations precede monitoring (`DOC-049`).
    pub privacy_minimized: bool,
    /// Operational cause marker separating clock/reconnect/config boundaries from regime shifts.
    pub cause: ObservationCause,
}

/// Derived regime hypothesis emitted by [`BocpdRegimeMonitor`] (never event evidence!).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RegimeHypothesis {
    /// Pinned active advisory generation at observation time.
    pub policy_generation: Generation,
    /// Posterior probability mass in `0..=short_run_window` scaled to basis points (`0..=10_000`).
    pub change_point_prob_bps: u16,
    /// Maximum a posteriori run length (`0..=max_run_length`).
    pub map_run_length: u32,
    /// Uncertainty proxy: Shannon entropy of run-length posterior in milli-nats.
    pub run_length_entropy_milli_nats: u32,
    /// Consecutive triggered ticks satisfying `change_point_prob_bps >= trigger_threshold_bps`.
    pub consecutive_triggers: u16,
    /// Whether minimum coverage held for this observation.
    pub sufficient_coverage: bool,
    /// Whether an explicit non-regime operational reset occurred (`ClockGap`/`Reconnect`/`Config`).
    pub reset_by_operational_cause: bool,
    /// Evidence window start timestamp.
    pub evidence_window_start_ns: TimestampNs,
    /// Evidence window end timestamp.
    pub evidence_window_end_ns: TimestampNs,
    /// Hard expiration timestamp after which this hypothesis may not drive proposals.
    pub expires_at_ns: TimestampNs,
    /// Stable short machine explanation.
    pub explanation: String,
    /// Always `false`: a change point is advisory cognition only, never intrusion/tamper truth.
    pub is_event_evidence: bool,
    /// Canonical SHA-256 commitment over this hypothesis.
    pub hypothesis_digest: ContentDigest,
}

impl RegimeHypothesis {
    fn compute_digest(&self) -> ContentDigest {
        let mut enc = CanonicalEncoder::new();
        enc.text("fss.runtime.bocpd_regime_hypothesis.v1");
        enc.u64(self.policy_generation.0);
        enc.u32(u32::from(self.change_point_prob_bps));
        enc.u32(self.map_run_length);
        enc.u32(self.run_length_entropy_milli_nats);
        enc.u32(u32::from(self.consecutive_triggers));
        enc.u8(u8::from(self.sufficient_coverage));
        enc.u8(u8::from(self.reset_by_operational_cause));
        enc.i128(self.evidence_window_start_ns.0);
        enc.i128(self.evidence_window_end_ns.0);
        enc.i128(self.expires_at_ns.0);
        enc.text(&self.explanation);
        enc.u8(u8::from(self.is_event_evidence));
        ContentDigest::sha256(&enc.finish())
    }
}

/// Staged advisory tuning proposal awaiting mandatory shadow evaluation before root-last activation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StagedAdvisoryProposal {
    /// Digest of the motivating [`RegimeHypothesis`].
    pub hypothesis_digest: ContentDigest,
    /// Prior active generation preserved untouched during shadow evaluation.
    pub prior_generation: Generation,
    /// Target candidate generation to activate if shadow evaluation passes.
    pub candidate_generation: Generation,
    /// Proposed clamped advisory parameters.
    pub proposed_params: AdvisoryParameters,
    /// Timestamp when proposal was staged.
    pub staged_at_ns: TimestampNs,
    /// Hard expiration timestamp inherited from the hypothesis.
    pub expires_at_ns: TimestampNs,
    /// Canonical digest of this staged proposal.
    pub proposal_digest: ContentDigest,
}

impl StagedAdvisoryProposal {
    fn compute_digest(&self) -> ContentDigest {
        let mut enc = CanonicalEncoder::new();
        enc.text("fss.runtime.bocpd_staged_proposal.v1");
        enc.digest(self.hypothesis_digest);
        enc.u64(self.prior_generation.0);
        enc.u64(self.candidate_generation.0);
        self.proposed_params.encode_canonical(&mut enc);
        enc.i128(self.staged_at_ns.0);
        enc.i128(self.expires_at_ns.0);
        ContentDigest::sha256(&enc.finish())
    }
}

/// Result of mandatory shadow evaluation before activating an advisory policy generation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ShadowEvalOutcome {
    /// Shadow evaluation passed within resource and quality bounds.
    Passed {
        /// Digest of the shadow evaluation telemetry bundle.
        shadow_evidence_digest: ContentDigest,
    },
    /// Shadow evaluation detected harm/regression; proposal must roll back into negative evidence.
    Harmful {
        /// Digest of the shadow evaluation telemetry bundle.
        shadow_evidence_digest: ContentDigest,
        /// Short machine-readable regression reason.
        reason: String,
    },
}

/// Recorded negative evidence emitted whenever a harmful advisory proposal is rolled back.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NegativeRegimeEvidence {
    /// Digest of the rejected proposal.
    pub proposal_digest: ContentDigest,
    /// Digest of the motivating hypothesis.
    pub hypothesis_digest: ContentDigest,
    /// Digest of the shadow evidence that proved regression.
    pub shadow_evidence_digest: ContentDigest,
    /// Short machine-readable harm reason.
    pub reason: String,
    /// Timestamp when rollback completed.
    pub recorded_at_ns: TimestampNs,
}

/// Non-collapsed outcome recorded in [`BocpdAdvisoryReceipt`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BocpdAdvisoryDisposition {
    /// Shadow evaluation passed; candidate generation root-last activated with prior preserved.
    ActivatedRootLast,
    /// Shadow evaluation failed; staged candidate discarded and logged as negative evidence.
    RolledBackNegativeEvidence,
}

impl CanonicalEncode for BocpdAdvisoryDisposition {
    fn encode_canonical(&self, encoder: &mut CanonicalEncoder) {
        encoder.u8(match self {
            Self::ActivatedRootLast => 1,
            Self::RolledBackNegativeEvidence => 2,
        });
    }
}

impl CanonicalDecode for BocpdAdvisoryDisposition {
    fn decode_canonical(decoder: &mut CanonicalDecoder<'_>) -> Result<Self, ContractError> {
        match decoder.u8()? {
            1 => Ok(Self::ActivatedRootLast),
            2 => Ok(Self::RolledBackNegativeEvidence),
            _ => Err(ContractError::InvalidIdentifier),
        }
    }
}

/// Canonical, tamper-evident receipt sealing an advisory policy activation or rollback (`DOC-049`).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BocpdAdvisoryReceipt {
    /// Format version (`BOCPD_ADVISORY_FORMAT_VERSION`).
    pub format_version: u32,
    /// Monitor identifier.
    pub monitor_id: String,
    /// Preserved prior complete generation.
    pub prior_generation: Generation,
    /// Active generation after this transition (`== prior_generation` on rollback, `> prior` on activation).
    pub active_generation: Generation,
    /// Active advisory parameters after this transition.
    pub active_params: AdvisoryParameters,
    /// Hypothesis digest motivating this transition.
    pub hypothesis_digest: ContentDigest,
    /// Proposal digest evaluated in shadow mode.
    pub proposal_digest: ContentDigest,
    /// Shadow evaluation evidence digest.
    pub shadow_evidence_digest: ContentDigest,
    /// Final non-collapsed disposition.
    pub disposition: BocpdAdvisoryDisposition,
    /// Timestamp when decision finalized.
    pub finalized_at_ns: TimestampNs,
    /// Always `false`: BOCPD receipts are advisory cognition only, never event or effect authority.
    pub grants_effect_authority: bool,
    /// Domain-separated SHA-256 digest over all fields above.
    pub receipt_digest: ContentDigest,
}

impl BocpdAdvisoryReceipt {
    /// Recomputes the exact domain-separated SHA-256 digest over all canonical fields.
    #[must_use]
    pub fn computed_digest(&self) -> ContentDigest {
        let mut enc = CanonicalEncoder::new();
        enc.text(BOCPD_ADVISORY_RECEIPT_DOMAIN);
        enc.u32(self.format_version);
        enc.text(&self.monitor_id);
        enc.u64(self.prior_generation.0);
        enc.u64(self.active_generation.0);
        self.active_params.encode_canonical(&mut enc);
        enc.digest(self.hypothesis_digest);
        enc.digest(self.proposal_digest);
        enc.digest(self.shadow_evidence_digest);
        self.disposition.encode_canonical(&mut enc);
        enc.i128(self.finalized_at_ns.0);
        enc.u8(u8::from(self.grants_effect_authority));
        ContentDigest::sha256(&enc.finish())
    }

    /// Returns `true` iff `receipt_digest` matches [`Self::computed_digest`].
    #[must_use]
    pub fn verify_digest(&self) -> bool {
        self.receipt_digest == self.computed_digest()
    }
}

impl CanonicalEncode for BocpdAdvisoryReceipt {
    fn encode_canonical(&self, encoder: &mut CanonicalEncoder) {
        encoder.u32(self.format_version);
        encoder.text(&self.monitor_id);
        encoder.u64(self.prior_generation.0);
        encoder.u64(self.active_generation.0);
        self.active_params.encode_canonical(encoder);
        encoder.digest(self.hypothesis_digest);
        encoder.digest(self.proposal_digest);
        encoder.digest(self.shadow_evidence_digest);
        self.disposition.encode_canonical(encoder);
        encoder.i128(self.finalized_at_ns.0);
        encoder.u8(u8::from(self.grants_effect_authority));
        encoder.digest(self.receipt_digest);
    }
}

impl CanonicalDecode for BocpdAdvisoryReceipt {
    fn decode_canonical(decoder: &mut CanonicalDecoder<'_>) -> Result<Self, ContractError> {
        let format_version = decoder.u32()?;
        if format_version != BOCPD_ADVISORY_FORMAT_VERSION {
            return Err(ContractError::InvalidIdentifier);
        }
        let monitor_id = decoder.text()?.to_owned();
        let prior_generation = Generation(decoder.u64()?);
        let active_generation = Generation(decoder.u64()?);
        let active_params = AdvisoryParameters::decode_canonical(decoder)?;
        let hypothesis_digest = decoder.digest()?;
        let proposal_digest = decoder.digest()?;
        let shadow_evidence_digest = decoder.digest()?;
        let disposition = BocpdAdvisoryDisposition::decode_canonical(decoder)?;
        let finalized_at_ns = TimestampNs(decoder.i128()?);
        let grants_effect_authority = match decoder.u8()? {
            0 => false,
            1 => true,
            _ => return Err(ContractError::InvalidIdentifier),
        };
        let receipt_digest = decoder.digest()?;

        let gen_valid = match disposition {
            BocpdAdvisoryDisposition::ActivatedRootLast => active_generation.0 > prior_generation.0,
            BocpdAdvisoryDisposition::RolledBackNegativeEvidence => {
                active_generation == prior_generation
            }
        };
        if !is_clean_label(&monitor_id)
            || prior_generation.0 == 0
            || active_generation.0 == 0
            || grants_effect_authority
            || !gen_valid
        {
            return Err(ContractError::InvalidIdentifier);
        }

        let receipt = Self {
            format_version,
            monitor_id,
            prior_generation,
            active_generation,
            active_params,
            hypothesis_digest,
            proposal_digest,
            shadow_evidence_digest,
            disposition,
            finalized_at_ns,
            grants_effect_authority,
            receipt_digest,
        };
        if !receipt.verify_digest() {
            return Err(ContractError::InvalidIdentifier);
        }
        Ok(receipt)
    }
}

/// Typed fail-closed error returned by [`BocpdRegimeMonitor`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum BocpdError {
    /// Invalid configuration, prior, or clamp bounds.
    InvalidConfiguration(&'static str),
    /// Non-finite (`NaN`/`Inf`), non-monotonic, or out-of-range observation.
    InvalidObservation(&'static str),
    /// Privacy minimization did not precede monitoring (`DOC-049`).
    PrivacyTransformRequired,
    /// Proposal tried to exceed hard clamp bounds or weaken system invariants.
    ClampViolation(&'static str),
    /// Hysteresis requirement not yet met.
    HysteresisNotMet,
    /// Cooldown window still active.
    CooldownActive,
    /// Motivating hypothesis expired or lacked required coverage.
    StaleOrUncoveredHypothesis,
    /// No staged proposal exists to finalize, or one is already pending.
    InvalidProposalState(&'static str),
    /// Cooperative cancellation observed before completing step.
    Cancelled,
}

impl fmt::Display for BocpdError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidConfiguration(why) => write!(f, "invalid BOCPD config: {why}"),
            Self::InvalidObservation(why) => write!(f, "invalid BOCPD observation: {why}"),
            Self::PrivacyTransformRequired => {
                write!(f, "privacy transformation must precede BOCPD monitoring")
            }
            Self::ClampViolation(why) => write!(f, "advisory clamp violation: {why}"),
            Self::HysteresisNotMet => write!(f, "hysteresis minimum consecutive triggers not met"),
            Self::CooldownActive => write!(f, "advisory adaptation cooldown active"),
            Self::StaleOrUncoveredHypothesis => {
                write!(f, "regime hypothesis expired or lacked required coverage")
            }
            Self::InvalidProposalState(why) => write!(f, "invalid proposal state: {why}"),
            Self::Cancelled => write!(f, "BOCPD monitor operation cancelled"),
        }
    }
}

impl std::error::Error for BocpdError {}

fn is_clean_label(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= MAX_BOCPD_LABEL_BYTES
        && !s
            .bytes()
            .any(|b| b.is_ascii_control() || b.is_ascii_whitespace())
}

#[derive(Clone, Copy, Debug)]
struct NigParams {
    mu: f64,
    kappa: f64,
    alpha: f64,
    beta: f64,
}

impl NigParams {
    fn from_prior(p: BocpdPrior) -> Self {
        Self {
            mu: p.mu0,
            kappa: p.kappa0,
            alpha: p.alpha0,
            beta: p.beta0,
        }
    }

    /// Exact log Student-t predictive density for scalar observation `x`.
    fn log_predictive_pdf(self, x: f64) -> f64 {
        let df = 2.0 * self.alpha;
        let scale_sq = (self.beta * (self.kappa + 1.0)) / (self.alpha * self.kappa);
        let diff = x - self.mu;
        let half_df = 0.5 * df;
        let half_df_plus_1 = half_df + 0.5;
        ln_gamma(half_df_plus_1)
            - ln_gamma(half_df)
            - 0.5 * (df * PI * scale_sq).ln()
            - half_df_plus_1 * ((diff * diff) / (df * scale_sq)).ln_1p()
    }

    /// Conjugate Normal-Inverse-Gamma posterior update with scalar `x`.
    fn update(self, x: f64) -> Self {
        let kappa_new = self.kappa + 1.0;
        let diff = x - self.mu;
        let mu_new = (self.kappa * self.mu + x) / kappa_new;
        let alpha_new = self.alpha + 0.5;
        let beta_new = self.beta + 0.5 * self.kappa * diff * diff / kappa_new;
        Self {
            mu: mu_new,
            kappa: kappa_new,
            alpha: alpha_new,
            beta: beta_new,
        }
    }
}

/// Deterministic Lanczos approximation of `ln(Gamma(z))` for `z > 0` (pure Rust, zero crates).
fn ln_gamma(z: f64) -> f64 {
    const COEFFS: [f64; 9] = [
        0.999_999_999_999_809_9,
        676.520_368_121_885_1,
        -1_259.139_216_722_402_9,
        771.323_428_777_653_1,
        -176.615_029_162_140_6,
        12.507_343_278_686_905,
        -0.138_571_095_265_720_12,
        9.984_369_578_019_572e-6,
        1.505_632_735_149_311_6e-7,
    ];
    if z < 0.5 {
        return PI.ln() - (PI * z).sin().ln() - ln_gamma(1.0 - z);
    }
    let z = z - 1.0;
    let mut x = COEFFS[0];
    for (idx, &c) in COEFFS.iter().enumerate().skip(1) {
        x += c / (z + idx as f64);
    }
    let t = z + 7.5;
    0.5 * (2.0 * PI).ln() + (z + 0.5) * t.ln() - t + x.ln()
}

fn log_sum_exp(a: f64, b: f64) -> f64 {
    if a == f64::NEG_INFINITY {
        return b;
    }
    if b == f64::NEG_INFINITY {
        return a;
    }
    let m = a.max(b);
    m + ((a - m).exp() + (b - m).exp()).ln()
}

/// Bounded deterministic scalar BOCPD monitor with hard-clamped advisory policy governance.
#[derive(Clone, Debug)]
pub struct BocpdRegimeMonitor {
    config: BocpdConfig,
    log_probs: Vec<f64>,
    stats: Vec<NigParams>,
    window_start_ns: Option<TimestampNs>,
    last_timestamp_ns: Option<TimestampNs>,
    consecutive_triggers: u16,
    active_generation: Generation,
    active_params: AdvisoryParameters,
    prior_generation: Option<(Generation, AdvisoryParameters)>,
    last_transition_ns: Option<TimestampNs>,
    staged_proposal: Option<StagedAdvisoryProposal>,
    negative_evidence: Vec<NegativeRegimeEvidence>,
}

impl BocpdRegimeMonitor {
    /// Creates a new bounded BOCPD monitor initialized at its registered prior and baseline policy.
    pub fn new(config: BocpdConfig) -> Result<Self, BocpdError> {
        config.validate()?;
        let active_generation = config.initial_generation;
        let active_params = config.baseline_params;
        let prior_state = NigParams::from_prior(config.prior);
        Ok(Self {
            config,
            log_probs: vec![0.0], // P(r_0 = 0) = 1.0 => ln(1.0) = 0.0
            stats: vec![prior_state],
            window_start_ns: None,
            last_timestamp_ns: None,
            consecutive_triggers: 0,
            active_generation,
            active_params,
            prior_generation: None,
            last_transition_ns: None,
            staged_proposal: None,
            negative_evidence: Vec::new(),
        })
    }

    /// Returns the currently active advisory policy generation.
    #[must_use]
    pub const fn active_generation(&self) -> Generation {
        self.active_generation
    }

    /// Returns the currently active clamped advisory parameters.
    #[must_use]
    pub const fn active_params(&self) -> AdvisoryParameters {
        self.active_params
    }

    /// Returns the preserved prior complete generation and parameters, if an activation occurred.
    #[must_use]
    pub const fn prior_generation(&self) -> Option<(Generation, AdvisoryParameters)> {
        self.prior_generation
    }

    /// Returns the currently staged proposal awaiting shadow evaluation, if any.
    #[must_use]
    pub fn staged_proposal(&self) -> Option<&StagedAdvisoryProposal> {
        self.staged_proposal.as_ref()
    }

    /// Returns retained negative evidence records from rolled-back harmful proposals.
    #[must_use]
    pub fn negative_evidence(&self) -> &[NegativeRegimeEvidence] {
        &self.negative_evidence
    }

    /// Returns the current bounded run-length vector size (`<= max_run_length + 1`).
    #[must_use]
    pub fn state_len(&self) -> usize {
        self.log_probs.len()
    }

    /// Explicitly resets the run-length distribution to its registered prior.
    pub fn reset_to_prior(&mut self) {
        self.log_probs.clear();
        self.log_probs.push(0.0);
        self.stats.clear();
        self.stats.push(NigParams::from_prior(self.config.prior));
        self.window_start_ns = None;
        self.consecutive_triggers = 0;
    }

    /// Ingests one typed, privacy-minimized observation and emits a bounded [`RegimeHypothesis`].
    pub fn observe(
        &mut self,
        obs: &RegimeObservation,
        mut is_cancelled: impl FnMut() -> bool,
    ) -> Result<RegimeHypothesis, BocpdError> {
        if is_cancelled() {
            return Err(BocpdError::Cancelled);
        }
        if !obs.privacy_minimized {
            return Err(BocpdError::PrivacyTransformRequired);
        }
        if !obs.value.is_finite() || obs.coverage_bps > 10_000 {
            return Err(BocpdError::InvalidObservation(
                "non_finite_or_invalid_coverage",
            ));
        }
        if let Some(prev) = self.last_timestamp_ns
            && obs.timestamp_ns.0 < prev.0
        {
            return Err(BocpdError::InvalidObservation("non_monotonic_timestamp"));
        }
        self.last_timestamp_ns = Some(obs.timestamp_ns);
        let expires_at_ns = TimestampNs(
            obs.timestamp_ns
                .0
                .saturating_add(self.config.hypothesis_ttl_ns),
        );

        // Separate operational boundaries (clock gap, reconnect, config change) trigger explicit
        // clean reset instead of false change-point alarms!
        if obs.cause != ObservationCause::Nominal {
            self.reset_to_prior();
            let explanation = format!("operational_reset:{}", obs.cause.as_str());
            return Ok(self.seal_hypothesis(
                0,
                0,
                0,
                obs.coverage_bps >= self.config.min_coverage_bps,
                true,
                obs.timestamp_ns,
                obs.timestamp_ns,
                expires_at_ns,
                explanation,
            ));
        }

        // Insufficient coverage preserves current baseline without corrupting sufficient statistics.
        if obs.coverage_bps < self.config.min_coverage_bps {
            self.consecutive_triggers = 0;
            let start_ns = self.window_start_ns.unwrap_or(obs.timestamp_ns);
            return Ok(self.seal_hypothesis(
                0,
                self.map_run_length(),
                self.entropy_milli_nats(),
                false,
                false,
                start_ns,
                obs.timestamp_ns,
                expires_at_ns,
                "insufficient_coverage_baseline_preserved".to_owned(),
            ));
        }

        if self.window_start_ns.is_none() {
            self.window_start_ns = Some(obs.timestamp_ns);
        }

        let h = f64::from(self.config.hazard_ppm) / 1_000_000.0;
        let ln_h = h.ln();
        let ln_1_minus_h = (1.0 - h).ln();

        let max_len = self.config.max_run_length;
        let prev_len = self.log_probs.len();
        let next_len = (prev_len + 1).min(max_len + 1);

        let mut next_log_probs = vec![f64::NEG_INFINITY; next_len];
        let mut next_stats = Vec::with_capacity(next_len);
        next_stats.push(NigParams::from_prior(self.config.prior));

        let mut cp_log_mass = f64::NEG_INFINITY;
        for r in 0..prev_len {
            let log_pred = self.stats[r].log_predictive_pdf(obs.value);
            let joint = self.log_probs[r] + log_pred;

            // Change-point branch -> r' = 0.
            cp_log_mass = log_sum_exp(cp_log_mass, joint + ln_h);

            // Growth branch -> r' = min(r + 1, max_len), conserving truncated tail mass cleanly.
            let target_r = (r + 1).min(max_len);
            let growth = joint + ln_1_minus_h;
            next_log_probs[target_r] = log_sum_exp(next_log_probs[target_r], growth);

            if r + 1 < next_len {
                next_stats.push(self.stats[r].update(obs.value));
            } else if target_r == max_len {
                // Fold tail stats deterministically toward the longest retained run.
                let updated = self.stats[r].update(obs.value);
                if let Some(last) = next_stats.last_mut() {
                    *last = updated;
                }
            }
        }
        next_log_probs[0] = cp_log_mass;

        // Normalize in log-space for exact probability mass conservation.
        let mut norm = f64::NEG_INFINITY;
        for &lp in &next_log_probs {
            norm = log_sum_exp(norm, lp);
        }
        if !norm.is_finite() {
            return Err(BocpdError::InvalidObservation("non_finite_posterior"));
        }
        for lp in &mut next_log_probs {
            *lp -= norm;
        }

        self.log_probs = next_log_probs;
        self.stats = next_stats;

        // Compute short-run regime-shift probability mass in basis points.
        let win_end = self
            .config
            .short_run_window
            .min(self.log_probs.len().saturating_sub(1));
        let mut short_mass = 0.0_f64;
        for &lp in &self.log_probs[..=win_end] {
            short_mass += lp.exp();
        }
        let cp_bps = (short_mass.clamp(0.0, 1.0) * 10_000.0).round() as u16;
        if cp_bps >= self.config.trigger_threshold_bps {
            self.consecutive_triggers = self.consecutive_triggers.saturating_add(1);
        } else {
            self.consecutive_triggers = 0;
        }

        let explanation = if self.consecutive_triggers >= self.config.hysteresis_min_steps {
            "regime_shift_hypothesis_ready_for_shadow_proposal".to_owned()
        } else if cp_bps >= self.config.trigger_threshold_bps {
            "regime_shift_candidate_hysteresis_pending".to_owned()
        } else {
            "steady_regime_baseline_maintained".to_owned()
        };

        let start_ns = self.window_start_ns.unwrap_or(obs.timestamp_ns);
        Ok(self.seal_hypothesis(
            cp_bps,
            self.map_run_length(),
            self.entropy_milli_nats(),
            true,
            false,
            start_ns,
            obs.timestamp_ns,
            expires_at_ns,
            explanation,
        ))
    }

    /// Stages a hard-clamped advisory tuning proposal for mandatory shadow evaluation.
    /// Does NOT mutate `active_generation` or `active_params`!
    pub fn stage_advisory_proposal(
        &mut self,
        hypothesis: &RegimeHypothesis,
        proposed_params: AdvisoryParameters,
        now_ns: TimestampNs,
        mut is_cancelled: impl FnMut() -> bool,
    ) -> Result<StagedAdvisoryProposal, BocpdError> {
        if is_cancelled() {
            return Err(BocpdError::Cancelled);
        }
        if self.staged_proposal.is_some() {
            return Err(BocpdError::InvalidProposalState("proposal_already_staged"));
        }
        if !hypothesis.sufficient_coverage
            || hypothesis.reset_by_operational_cause
            || now_ns.0 > hypothesis.expires_at_ns.0
            || hypothesis.policy_generation != self.active_generation
        {
            return Err(BocpdError::StaleOrUncoveredHypothesis);
        }
        if proposed_params.weakens_invariants {
            return Err(BocpdError::ClampViolation(
                "advisory_cannot_weaken_invariants",
            ));
        }
        if !self.config.clamp_bounds.admits(proposed_params) {
            return Err(BocpdError::ClampViolation("outside_hard_clamp_bounds"));
        }
        if hypothesis.consecutive_triggers < self.config.hysteresis_min_steps {
            return Err(BocpdError::HysteresisNotMet);
        }
        if let Some(last_tx) = self.last_transition_ns
            && now_ns.0.saturating_sub(last_tx.0) < self.config.cooldown_ns
        {
            return Err(BocpdError::CooldownActive);
        }

        let mut proposal = StagedAdvisoryProposal {
            hypothesis_digest: hypothesis.hypothesis_digest,
            prior_generation: self.active_generation,
            candidate_generation: Generation(self.active_generation.0.saturating_add(1)),
            proposed_params,
            staged_at_ns: now_ns,
            expires_at_ns: hypothesis.expires_at_ns,
            proposal_digest: ContentDigest::sha256(b"pending"),
        };
        proposal.proposal_digest = proposal.compute_digest();
        self.staged_proposal = Some(proposal.clone());
        Ok(proposal)
    }

    /// Finalizes mandatory shadow evaluation: root-last activates a passing proposal while
    /// preserving the prior generation, or rolls back a harmful proposal into negative evidence.
    pub fn finalize_shadow_evaluation(
        &mut self,
        outcome: ShadowEvalOutcome,
        now_ns: TimestampNs,
        mut is_cancelled: impl FnMut() -> bool,
    ) -> Result<BocpdAdvisoryReceipt, BocpdError> {
        if is_cancelled() {
            return Err(BocpdError::Cancelled);
        }
        let Some(staged) = self.staged_proposal.take() else {
            return Err(BocpdError::InvalidProposalState("no_staged_proposal"));
        };
        if now_ns.0 > staged.expires_at_ns.0 {
            return Err(BocpdError::StaleOrUncoveredHypothesis);
        }

        let prior_generation = self.active_generation;
        let (disposition, shadow_evidence_digest) = match outcome {
            ShadowEvalOutcome::Passed {
                shadow_evidence_digest,
            } => {
                // Preserve prior complete generation and root-last activate the new generation!
                self.prior_generation = Some((self.active_generation, self.active_params));
                self.active_generation = staged.candidate_generation;
                self.active_params = staged.proposed_params;
                self.last_transition_ns = Some(now_ns);
                self.consecutive_triggers = 0;
                (
                    BocpdAdvisoryDisposition::ActivatedRootLast,
                    shadow_evidence_digest,
                )
            }
            ShadowEvalOutcome::Harmful {
                shadow_evidence_digest,
                reason,
            } => {
                // Discard harmful proposal, preserve active generation, record negative evidence!
                let clean_reason = if is_clean_label(&reason) {
                    reason
                } else {
                    "shadow_eval_harmful_regression".to_owned()
                };
                if self.negative_evidence.len() >= MAX_NEGATIVE_EVIDENCE_RECORDS {
                    self.negative_evidence.remove(0);
                }
                self.negative_evidence.push(NegativeRegimeEvidence {
                    proposal_digest: staged.proposal_digest,
                    hypothesis_digest: staged.hypothesis_digest,
                    shadow_evidence_digest,
                    reason: clean_reason,
                    recorded_at_ns: now_ns,
                });
                self.last_transition_ns = Some(now_ns);
                self.consecutive_triggers = 0;
                (
                    BocpdAdvisoryDisposition::RolledBackNegativeEvidence,
                    shadow_evidence_digest,
                )
            }
        };

        let mut receipt = BocpdAdvisoryReceipt {
            format_version: BOCPD_ADVISORY_FORMAT_VERSION,
            monitor_id: self.config.monitor_id.clone(),
            prior_generation,
            active_generation: self.active_generation,
            active_params: self.active_params,
            hypothesis_digest: staged.hypothesis_digest,
            proposal_digest: staged.proposal_digest,
            shadow_evidence_digest,
            disposition,
            finalized_at_ns: now_ns,
            grants_effect_authority: false,
            receipt_digest: ContentDigest::sha256(b"pending"),
        };
        receipt.receipt_digest = receipt.computed_digest();
        Ok(receipt)
    }

    fn map_run_length(&self) -> u32 {
        let mut best_r = 0_usize;
        let mut best_lp = f64::NEG_INFINITY;
        for (r, &lp) in self.log_probs.iter().enumerate() {
            if lp > best_lp {
                best_lp = lp;
                best_r = r;
            }
        }
        best_r as u32
    }

    fn entropy_milli_nats(&self) -> u32 {
        let mut h = 0.0_f64;
        for &lp in &self.log_probs {
            if lp.is_finite() {
                let p = lp.exp();
                if p > 0.0 {
                    h -= p * lp;
                }
            }
        }
        (h.max(0.0) * 1_000.0).round() as u32
    }

    #[allow(clippy::too_many_arguments)]
    fn seal_hypothesis(
        &self,
        change_point_prob_bps: u16,
        map_run_length: u32,
        run_length_entropy_milli_nats: u32,
        sufficient_coverage: bool,
        reset_by_operational_cause: bool,
        evidence_window_start_ns: TimestampNs,
        evidence_window_end_ns: TimestampNs,
        expires_at_ns: TimestampNs,
        explanation: String,
    ) -> RegimeHypothesis {
        let mut hyp = RegimeHypothesis {
            policy_generation: self.active_generation,
            change_point_prob_bps,
            map_run_length,
            run_length_entropy_milli_nats,
            consecutive_triggers: self.consecutive_triggers,
            sufficient_coverage,
            reset_by_operational_cause,
            evidence_window_start_ns,
            evidence_window_end_ns,
            expires_at_ns,
            explanation,
            is_event_evidence: false,
            hypothesis_digest: ContentDigest::sha256(b"pending"),
        };
        hyp.hypothesis_digest = hyp.compute_digest();
        hyp
    }
}
