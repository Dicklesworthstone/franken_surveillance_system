//! Hypothesis-bound sequential milliban accumulator (`fss-becce`, plan §16.10, §17.5).
//!
//! Tracks sequential evidence across windows for one event hypothesis using exact integer
//! millibans (`1000 * log10` odds), with these explicit semantics:
//!
//! * **Ville's maximal inequality:** under the null hypothesis $H_0$, a nonnegative test
//!   supermartingale $E_t = 10^{M_t / 1000}$ satisfies
//!   $$\mathbb{P}_{H_0}\!\left(\sup_{t \ge 1} M_{t,\text{lo}} \ge \tau_{\text{mban}}\right) \le 10^{-\tau_{\text{mban}} / 1000}.$$
//!   [`ville_false_alarm_bound_ppm`] evaluates an outward-rounded integer parts-per-million bound
//!   from literal decimal mantissas with zero floating-point operations.
//! * **Cross-step common-cause hull clustering (`NEG-004`):** supporting observations that share
//!   any failure domain (including the intrinsic `sensor:<id>` domain) across time steps merge
//!   into a single supporting dependency cluster. A single camera firing across arbitrarily many
//!   windows can never satisfy `min_independent_clusters >= 2`.
//! * **Missing data is neutral (`NEG-005`):** `NotObservable`, `Redacted`, `Stale`, and
//!   `Uncalibrated` observations contribute `0` millibans and never depress the e-process.
//! * **CUSUM floor clamping and regime reset:** configurable floor clamping (`floor_mban = 0` for
//!   Page-Lorden sequential change detection) and explicit [`SequentialEProcess::reset_regime`]
//!   when sensor health degrades or clock continuity breaks.
//!
//! The numerical Ville formula is conditional on a valid test supermartingale. Arbitrary caller
//! likelihoods, repeated observations, floor clamping and restarts do not establish that property.
//! A transcript binds the exact supplied queries and transitions; it does not verify source custody,
//! qualify statistical independence or grant effect authority.

use std::collections::BTreeSet;

use fss_core::{CanonicalEncoder, ContentDigest};

use crate::decide::fuse;
use crate::model::{
    ClusterDirection, FusionError, FusionOutcome, FusionQuery, LlrInterval, MAX_ABS_LLR, valid_text,
};
use crate::probability::PPM;

mod transcript;
pub use transcript::{
    EPROCESS_RESET_DOMAIN, EPROCESS_STATE_DOMAIN, EPROCESS_SUPPORT_DOMAIN,
    EPROCESS_TRANSCRIPT_DOMAIN, EPROCESS_TRANSCRIPT_SCHEMA, EProcessStepInput, EProcessTranscript,
};

/// Sequential e-process step digest domain (`SCHEMA-DOMAIN-FUSION-EPROCESS-STEP-001`).
pub const EPROCESS_STEP_DOMAIN: &str = "fss.fusion.eprocess_step.v1";

/// Outward-rounded `ceil(1e9 * 10^(-r/10))` for deciban remainder `r in 0..10`.
const DECIBAN_MANTISSA_NANOS: [u64; 10] = [
    1_000_000_000,
    794_328_235,
    630_957_345,
    501_187_234,
    398_107_171,
    316_227_767,
    251_188_644,
    199_526_232,
    158_489_320,
    125_892_542,
];

/// Outward-rounded numerical Ville expression in parts per million (`0..=1_000_000`).
/// It is a false-alarm bound only under a separately established test-supermartingale assumption;
/// evaluating this expression does not qualify supplied likelihoods, dependence, clamps or resets.
#[must_use]
pub fn ville_false_alarm_bound_ppm(threshold_mban: i64) -> u32 {
    if threshold_mban <= 0 {
        return PPM;
    }
    let deciban = threshold_mban.div_euclid(100);
    if deciban >= 60 {
        return 1;
    }
    let k = (deciban / 10) as u32;
    let r = (deciban % 10) as usize;
    let divisor = 10_u64.pow(k + 3);
    DECIBAN_MANTISSA_NANOS[r].div_ceil(divisor) as u32
}

/// Policy parameters for a sequential milliban e-process accumulator.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EProcessConfig {
    /// Milliban lower-bound threshold $\tau_{\text{mban}} > 0$ required to trigger a corroborated alert.
    pub alert_threshold_mban: i64,
    /// Lower clamp bound (e.g. `0` for CUSUM / Page-Lorden regeneration, or negative for unclamped drift).
    pub floor_mban: i64,
    /// Upper clamp bound in millibans (`>= alert_threshold_mban` and `<= MAX_ABS_LLR`).
    pub ceiling_mban: i64,
    /// Minimum number of disjoint failure-domain clusters required before alerting (`>= 1`, default `2`).
    pub min_independent_clusters: u32,
}

impl Default for EProcessConfig {
    fn default() -> Self {
        Self {
            alert_threshold_mban: 1_800,
            floor_mban: 0,
            ceiling_mban: 10_000,
            min_independent_clusters: 2,
        }
    }
}

impl EProcessConfig {
    /// Validates configuration invariants.
    ///
    /// # Errors
    ///
    /// Returns [`FusionError::InvalidPolicy`] if thresholds or clamps violate contract bounds.
    pub fn validate(&self) -> Result<(), FusionError> {
        if self.alert_threshold_mban <= 0 || self.alert_threshold_mban > MAX_ABS_LLR {
            return Err(FusionError::InvalidPolicy(
                "e-process alert_threshold_mban must be in 1..=MAX_ABS_LLR".to_owned(),
            ));
        }
        if self.floor_mban > 0 || self.floor_mban < -MAX_ABS_LLR {
            return Err(FusionError::InvalidPolicy(
                "e-process floor_mban must be in -MAX_ABS_LLR..=0".to_owned(),
            ));
        }
        if self.ceiling_mban < self.alert_threshold_mban || self.ceiling_mban > MAX_ABS_LLR {
            return Err(FusionError::InvalidPolicy(
                "e-process ceiling_mban must be in alert_threshold_mban..=MAX_ABS_LLR".to_owned(),
            ));
        }
        if self.min_independent_clusters == 0 {
            return Err(FusionError::InvalidPolicy(
                "e-process min_independent_clusters must be >= 1".to_owned(),
            ));
        }
        Ok(())
    }
}

/// Explicit reason a sequential e-process regime was reset.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RegimeResetReason {
    /// Sensor health screening reported degraded pixel fidelity.
    SensorHealthDegraded {
        /// Producing sensor identity.
        sensor: String,
        /// Degradation reason.
        reason: String,
    },
    /// Capture clock continuity broke beyond the admissible gate.
    ClockContinuityBroken {
        /// Producing sensor identity.
        sensor: String,
        /// Observed gap in nanoseconds.
        gap_ns: u64,
    },
    /// Explicit operator or supervisor regime reset.
    OperatorReset {
        /// Reset explanation.
        reason: String,
    },
}

impl RegimeResetReason {
    fn encode(&self, encoder: &mut CanonicalEncoder) {
        match self {
            Self::SensorHealthDegraded { sensor, reason } => {
                encoder.text("sensor_health_degraded");
                encoder.text(sensor);
                encoder.text(reason);
            }
            Self::ClockContinuityBroken { sensor, gap_ns } => {
                encoder.text("clock_continuity_broken");
                encoder.text(sensor);
                encoder.u64(*gap_ns);
            }
            Self::OperatorReset { reason } => {
                encoder.text("operator_reset");
                encoder.text(reason);
            }
        }
    }
}

/// Digest-bearing outcome of one sequential step or regime reset; not a signature or effect grant.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EProcessStepOutcome {
    /// Monotone step index (`1..`).
    pub step_index: u64,
    /// Monotone regime epoch (`0..`, incremented on each regime reset).
    pub regime_epoch: u32,
    /// Net milliban increment contributed by this step's fused clusters.
    pub step_delta_llr: LlrInterval,
    /// Clamped cumulative milliban e-process interval $[M_{t,\text{lo}}, M_{t,\text{hi}}]$.
    pub accumulated_llr: LlrInterval,
    /// Running supremum $\sup_{s \le t} M_{s,\text{lo}}$ within the active regime.
    pub supremum_lo_mban: i64,
    /// Conditional Ville formula (ppm) at `supremum_lo_mban`; no statistical qualification.
    pub ville_false_alarm_bound_ppm: u32,
    /// Conditional Ville formula (ppm) at `config.alert_threshold_mban`.
    pub threshold_ville_bound_ppm: u32,
    /// Count of mutually disjoint supporting failure-domain clusters in the active regime.
    pub independent_supporting_clusters: u32,
    /// True iff `accumulated_llr.lo() >= alert_threshold_mban` and `independent_supporting_clusters >= min_independent_clusters`.
    pub crossed_alert_threshold: bool,
    /// Most recent regime reset reason, if any.
    pub last_reset: Option<RegimeResetReason>,
    /// Historical numerical v1 digest (`SCHEMA-DOMAIN-FUSION-EPROCESS-STEP-001`).
    /// It deliberately retains its original bytes and does not bind the evidence history.
    pub step_digest: ContentDigest,
    /// Separate evidence-bound transition receipt, chained across observations and resets.
    pub transcript: EProcessTranscript,
}

impl EProcessStepOutcome {
    fn seal(
        mut self,
        hypothesis_id: &str,
        config: &EProcessConfig,
        supporting_domains: &[BTreeSet<String>],
    ) -> Self {
        let mut encoder = CanonicalEncoder::new();
        encoder.text(EPROCESS_STEP_DOMAIN);
        encoder.text(hypothesis_id);
        encoder.u64(self.step_index);
        encoder.u32(self.regime_epoch);
        encoder.i128(i128::from(config.alert_threshold_mban));
        encoder.i128(i128::from(config.floor_mban));
        encoder.i128(i128::from(config.ceiling_mban));
        encoder.u32(config.min_independent_clusters);
        self.step_delta_llr.encode(&mut encoder);
        self.accumulated_llr.encode(&mut encoder);
        encoder.i128(i128::from(self.supremum_lo_mban));
        encoder.u32(self.ville_false_alarm_bound_ppm);
        encoder.u32(self.threshold_ville_bound_ppm);
        encoder.u32(self.independent_supporting_clusters);
        encoder.bool(self.crossed_alert_threshold);
        match &self.last_reset {
            Some(reason) => {
                encoder.bool(true);
                reason.encode(&mut encoder);
            }
            None => encoder.bool(false),
        }
        self.step_digest = ContentDigest::sha256(&encoder.finish());
        let state_digest = transcript::state_digest(hypothesis_id, config, &self);
        self.transcript
            .seal(self.step_digest, state_digest, supporting_domains);
        self
    }
}

/// Stateful sequential milliban e-process accumulator for one hypothesis.
#[derive(Clone, Debug)]
pub struct SequentialEProcess {
    hypothesis_id: String,
    config: EProcessConfig,
    step_index: u64,
    regime_epoch: u32,
    accumulated_llr: LlrInterval,
    supremum_lo_mban: i64,
    supporting_domain_components: Vec<BTreeSet<String>>,
    last_reset: Option<RegimeResetReason>,
    last_transcript: Option<ContentDigest>,
}

impl SequentialEProcess {
    /// Creates a new sequential e-process accumulator at `[0, 0]` millibans.
    ///
    /// # Errors
    ///
    /// Returns [`FusionError`] if `hypothesis_id` is invalid or `config` violates policy bounds.
    pub fn new(
        hypothesis_id: impl Into<String>,
        config: EProcessConfig,
    ) -> Result<Self, FusionError> {
        let hypothesis_id = hypothesis_id.into();
        if !valid_text(&hypothesis_id) {
            return Err(FusionError::InvalidInput(format!(
                "invalid e-process hypothesis_id {hypothesis_id:?}"
            )));
        }
        config.validate()?;
        Ok(Self {
            hypothesis_id,
            config,
            step_index: 0,
            regime_epoch: 0,
            accumulated_llr: LlrInterval::unchecked(0, 0),
            supremum_lo_mban: 0,
            supporting_domain_components: Vec::new(),
            last_reset: None,
            last_transcript: None,
        })
    }

    /// Returns the hypothesis identifier.
    #[must_use]
    pub fn hypothesis_id(&self) -> &str {
        &self.hypothesis_id
    }

    /// Returns the active e-process configuration.
    #[must_use]
    pub const fn config(&self) -> &EProcessConfig {
        &self.config
    }

    /// Number of accepted observation/reset transitions (saturating at `u64::MAX`).
    #[must_use]
    pub const fn step_index(&self) -> u64 {
        self.step_index
    }

    /// Returns the current clamped milliban interval.
    #[must_use]
    pub const fn accumulated_llr(&self) -> LlrInterval {
        self.accumulated_llr
    }

    /// Returns the number of mutually disjoint supporting failure-domain clusters accumulated so far.
    #[must_use]
    pub fn independent_supporting_clusters(&self) -> u32 {
        self.supporting_domain_components.len() as u32
    }

    /// Digest of the last accepted transition, including a reset, or `None` before any step.
    /// A reset clears numerical evidence while retaining this complete transcript ancestry.
    #[must_use]
    pub const fn transcript_head(&self) -> Option<ContentDigest> {
        self.last_transcript
    }

    /// Merges a supporting cluster's failure domains into the connected components of supporting
    /// domains across the active regime so repeated observations from the same camera or shared
    /// failure domain never inflate `independent_supporting_clusters`.
    fn merge_supporting_domains(&mut self, domains: &BTreeSet<String>) {
        let mut merged = domains.clone();
        let mut retained = Vec::with_capacity(self.supporting_domain_components.len() + 1);
        for existing in self.supporting_domain_components.drain(..) {
            if existing.is_disjoint(&merged) {
                retained.push(existing);
            } else {
                merged.extend(existing);
            }
        }
        retained.push(merged);
        // Canonicalize in the existing state allocation so transcript construction never needs
        // an additional inventory-sized buffer just to normalize component ordering.
        retained.sort();
        self.supporting_domain_components = retained;
    }

    /// Evaluates `query` via [`fuse`] and advances the sequential milliban e-process by one step.
    ///
    /// # Errors
    ///
    /// Refuses a different hypothesis before any mutation. Propagates [`FusionError`] if `query`
    /// fails validation or arithmetic overflows. A refusal does not advance the transcript.
    pub fn observe_step(
        &mut self,
        query: &FusionQuery,
    ) -> Result<(FusionOutcome, EProcessStepOutcome), FusionError> {
        if query.hypothesis != self.hypothesis_id {
            return Err(FusionError::InvalidInput(
                "sequential observation belongs to a different hypothesis".to_owned(),
            ));
        }
        let outcome = fuse(query)?;
        let delta_lo = outcome
            .posterior
            .lo()
            .checked_sub(query.prior.lo())
            .ok_or(FusionError::Overflow("e-process step delta lower bound"))?;
        let delta_hi = outcome
            .posterior
            .hi()
            .checked_sub(query.prior.hi())
            .ok_or(FusionError::Overflow("e-process step delta upper bound"))?;
        let step_delta_llr = LlrInterval::unchecked(delta_lo, delta_hi);

        let next_lo = self
            .accumulated_llr
            .lo()
            .checked_add(delta_lo)
            .ok_or(FusionError::Overflow("e-process accumulated lower bound"))?
            .clamp(self.config.floor_mban, self.config.ceiling_mban);
        let next_hi = self
            .accumulated_llr
            .hi()
            .checked_add(delta_hi)
            .ok_or(FusionError::Overflow("e-process accumulated upper bound"))?
            .clamp(self.config.floor_mban, self.config.ceiling_mban)
            .max(next_lo);
        self.accumulated_llr = LlrInterval::unchecked(next_lo, next_hi);

        // CUSUM regeneration at the floor clears prior supporting clusters when evidence drops back to <= 0.
        if self.config.floor_mban == 0 && next_lo == 0 && delta_lo < 0 {
            self.supporting_domain_components.clear();
        }

        for cluster in &outcome.clusters {
            if cluster.direction == ClusterDirection::Supports {
                self.merge_supporting_domains(&cluster.failure_domains);
            }
        }

        self.step_index = self.step_index.saturating_add(1);
        self.supremum_lo_mban = self.supremum_lo_mban.max(self.accumulated_llr.lo());
        let independent_supporting_clusters = self.independent_supporting_clusters();
        let crossed_alert_threshold = self.accumulated_llr.lo() >= self.config.alert_threshold_mban
            && independent_supporting_clusters >= self.config.min_independent_clusters;

        let step_outcome = EProcessStepOutcome {
            step_index: self.step_index,
            regime_epoch: self.regime_epoch,
            step_delta_llr,
            accumulated_llr: self.accumulated_llr,
            supremum_lo_mban: self.supremum_lo_mban,
            ville_false_alarm_bound_ppm: ville_false_alarm_bound_ppm(self.supremum_lo_mban),
            threshold_ville_bound_ppm: ville_false_alarm_bound_ppm(
                self.config.alert_threshold_mban,
            ),
            independent_supporting_clusters,
            crossed_alert_threshold,
            last_reset: self.last_reset.clone(),
            step_digest: ContentDigest::sha256(b""),
            transcript: EProcessTranscript::pending(
                self.last_transcript,
                EProcessStepInput::Observation {
                    query_digest: outcome.query_digest,
                    decision_digest: outcome.decision_digest,
                },
            ),
        }
        .seal(
            &self.hypothesis_id,
            &self.config,
            &self.supporting_domain_components,
        );
        self.last_transcript = Some(step_outcome.transcript.digest());

        Ok((outcome, step_outcome))
    }

    /// Resets the sequential e-process to `[0, 0]` millibans upon a camera-health or clock-continuity
    /// regime break, advancing `regime_epoch`.
    pub fn reset_regime(&mut self, reason: RegimeResetReason) -> EProcessStepOutcome {
        let reason_digest = transcript::reset_reason_digest(&reason);
        self.step_index = self.step_index.saturating_add(1);
        self.regime_epoch = self.regime_epoch.saturating_add(1);
        self.accumulated_llr = LlrInterval::unchecked(0, 0);
        self.supremum_lo_mban = 0;
        self.supporting_domain_components.clear();
        self.last_reset = Some(reason);
        let step_outcome = EProcessStepOutcome {
            step_index: self.step_index,
            regime_epoch: self.regime_epoch,
            step_delta_llr: LlrInterval::unchecked(0, 0),
            accumulated_llr: self.accumulated_llr,
            supremum_lo_mban: 0,
            ville_false_alarm_bound_ppm: PPM,
            threshold_ville_bound_ppm: ville_false_alarm_bound_ppm(
                self.config.alert_threshold_mban,
            ),
            independent_supporting_clusters: 0,
            crossed_alert_threshold: false,
            last_reset: self.last_reset.clone(),
            step_digest: ContentDigest::sha256(b""),
            transcript: EProcessTranscript::pending(
                self.last_transcript,
                EProcessStepInput::RegimeReset { reason_digest },
            ),
        }
        .seal(
            &self.hypothesis_id,
            &self.config,
            &self.supporting_domain_components,
        );
        self.last_transcript = Some(step_outcome.transcript.digest());
        step_outcome
    }
}

#[cfg(test)]
mod transcript_tests;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{
        Calibration, Coverage, EvidenceItem, FusionPolicy, Observability, Severity,
    };

    fn base_query(evidence: Vec<EvidenceItem>) -> FusionQuery {
        FusionQuery {
            hypothesis: "hyp:entry-door".to_owned(),
            kind: "zone_entry".to_owned(),
            prior: LlrInterval::point(0).unwrap(),
            evidence,
            coverage: Coverage::Complete,
            opportunities: Vec::new(),
            probes: Vec::new(),
            severity: Severity {
                expected_harm: 10_000,
                false_alert_cost: 500,
                delay_cost_per_second: 100,
                reversible: false,
            },
            policy: FusionPolicy {
                generation: "policy:v1".to_owned(),
                alert_threshold: 1_800,
                retain_threshold: 0,
                reject_threshold: -1_000,
                min_independent_support: 2,
                urgent_single_domain_threshold: None,
                max_wait_ns: 0,
                look_penalty_per_doubling: 0,
                operator_confirmation_available: false,
            },
            looks: 1,
            now_ns: 1_000_000_000,
        }
    }

    fn calibrated_item(id: &str, sensor: &str, lo: i64, hi: i64) -> EvidenceItem {
        EvidenceItem {
            id: id.to_owned(),
            sensor: sensor.to_owned(),
            failure_domains: [format!("sensor:{sensor}")].into_iter().collect(),
            calibration: Calibration::Calibrated {
                generation: "cal:v1".to_owned(),
                llr: LlrInterval::new(lo, hi).unwrap(),
            },
            observability: Observability::Observed,
        }
    }

    #[test]
    fn ville_bound_is_monotone_and_exact_at_decade_boundaries() {
        assert_eq!(ville_false_alarm_bound_ppm(0), 1_000_000);
        assert_eq!(ville_false_alarm_bound_ppm(1_000), 100_000);
        assert_eq!(ville_false_alarm_bound_ppm(1_800), 15_849);
        assert_eq!(ville_false_alarm_bound_ppm(2_000), 10_000);
        assert_eq!(ville_false_alarm_bound_ppm(3_000), 1_000);
        assert_eq!(ville_false_alarm_bound_ppm(6_000), 1);
        for d in 1..=60 {
            assert!(
                ville_false_alarm_bound_ppm(d * 100) <= ville_false_alarm_bound_ppm((d - 1) * 100)
            );
        }
    }

    #[test]
    fn single_camera_repeated_windows_never_corroborate_neg_004() {
        let mut ep = SequentialEProcess::new("hyp:entry-door", EProcessConfig::default()).unwrap();
        for step in 0..4 {
            let q = base_query(vec![calibrated_item(
                &format!("obs:east:{step}"),
                "east",
                700,
                900,
            )]);
            let (_, out) = ep.observe_step(&q).unwrap();
            assert_eq!(out.independent_supporting_clusters, 1);
            assert!(
                !out.crossed_alert_threshold,
                "single camera must never cross corroborated alert threshold (NEG-004)"
            );
        }
        assert_eq!(ep.accumulated_llr().lo(), 2_800);
    }

    #[test]
    fn two_independent_cameras_corroborate_while_occluded_camera_is_neutral_neg_005() {
        let mut ep = SequentialEProcess::new("hyp:entry-door", EProcessConfig::default()).unwrap();
        // Step 1: east camera + occluded south camera
        let occluded_south = EvidenceItem {
            id: "obs:south:0".to_owned(),
            sensor: "south".to_owned(),
            failure_domains: ["sensor:south".to_owned()].into_iter().collect(),
            calibration: Calibration::Uncalibrated {
                reason: "occluded".to_owned(),
            },
            observability: Observability::NotObservable {
                reason: "lens_occluded".to_owned(),
            },
        };
        let (_, s1) = ep
            .observe_step(&base_query(vec![
                calibrated_item("obs:east:0", "east", 1_000, 1_200),
                occluded_south,
            ]))
            .unwrap();
        assert_eq!(s1.accumulated_llr.lo(), 1_000);
        assert_eq!(s1.independent_supporting_clusters, 1);
        assert!(!s1.crossed_alert_threshold);

        // Step 2: independent west camera corroborates
        let (_, s2) = ep
            .observe_step(&base_query(vec![calibrated_item(
                "obs:west:1",
                "west",
                950,
                1_150,
            )]))
            .unwrap();
        assert_eq!(s2.accumulated_llr.lo(), 1_950);
        assert_eq!(s2.independent_supporting_clusters, 2);
        assert!(s2.crossed_alert_threshold);
        assert_eq!(s2.threshold_ville_bound_ppm, 15_849);
        assert!(s2.ville_false_alarm_bound_ppm <= s2.threshold_ville_bound_ppm);
    }

    #[test]
    fn regime_reset_clears_accumulator_and_increments_epoch() {
        let mut ep = SequentialEProcess::new("hyp:entry-door", EProcessConfig::default()).unwrap();
        let (_, s1) = ep
            .observe_step(&base_query(vec![calibrated_item(
                "obs:east:0",
                "east",
                1_100,
                1_300,
            )]))
            .unwrap();
        assert_eq!(s1.accumulated_llr.lo(), 1_100);
        let reset = ep.reset_regime(RegimeResetReason::SensorHealthDegraded {
            sensor: "east".to_owned(),
            reason: "flat_dark_field".to_owned(),
        });
        assert_eq!(reset.regime_epoch, 1);
        assert_eq!(reset.accumulated_llr.lo(), 0);
        assert_eq!(reset.independent_supporting_clusters, 0);
        assert!(!reset.crossed_alert_threshold);
    }
}
