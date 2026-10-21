#![forbid(unsafe_code)]
//! Experiential operational memory and trauma-guard anti-pattern warning derivation
//! (`GOAL-018`, `NS-13`, `NEG-004`, `GATE-090`).
//!
//! **Advisory only (`NEG-004`).** When a deployment accumulates repeated (`>= 2`) negative
//! operational memory signals (`AgentFeedbackProposal` records of kind `harmful`,
//! `hard_negative_candidate`, `bad_affordance`, or `adapter_quirk`, or terminal `Failed`
//! `ExecutionEpisode` records) on the same target and failure/attribution cause class, this module
//! deterministically derives an advisory [`AntiPatternWarning`] citing the exact episode/feedback
//! identities, evidence digests, and exponential half-life decay weight (`TRAUMA_HALF_LIFE_NS`).
//!
//! Deriving or surfacing an [`AntiPatternWarning`] never mutates policy, thresholds, retention,
//! calibration, models, or authority (`AntiPatternWarning::ACTIVE_POLICY_MUTATION == false`).

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use fss_core::{
    AttributionCauseClass, CanonicalEncoder, ContentDigest, EpisodeOutcomeState,
    FeedbackProposalKind,
};

use super::episode::{EpisodeRecord, TerminalOutcome};
use super::feedback::{FeedbackTarget, decode_proposal, target_json};
use super::plan::read_plan;
use super::{DeploymentSessionError, digest_of, hex, published_records};

/// Digest domain (`SCHEMA-DOMAIN-AGENT-TRAUMA-GUARD-001`).
pub const TRAUMA_GUARD_DOMAIN: &str = "fss.reference_agent_trauma_guard.v1";

/// Minimum number of negative operational memory records on the same `(target, cause_class)` tuple
/// required to trigger an advisory [`AntiPatternWarning`].
pub const TRAUMA_GUARD_MIN_NEGATIVE_COUNT: usize = 2;

/// Default exponential decay half-life in nanoseconds (24 hours).
pub const TRAUMA_HALF_LIFE_NS: i128 = 86_400_000_000_000;

/// Full decay weight for a zero-age negative record in parts-per-million (`1.0 == 1_000_000`).
pub const MAX_RECORD_WEIGHT_PPM: u64 = 1_000_000;

/// One deterministically derived advisory trauma-guard warning (`NS-13` / `GOAL-018`).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AntiPatternWarning {
    /// Deterministic warning identity (`trauma-guard:<32-hex>`).
    pub warning_id: String,
    /// Canonical target JSON (`{"id":...,"kind":...}`).
    pub target_json: String,
    /// Attribution / failure cause class of the recurring anti-pattern.
    pub cause_class: AttributionCauseClass,
    /// Count of negative episode/feedback records contributing to this warning.
    pub negative_count: usize,
    /// Half-life window in nanoseconds used for decay weighting.
    pub half_life_ns: i128,
    /// Summed half-life decay weight in parts-per-million across all cited negative records.
    pub decay_weight_ppm: u64,
    /// Sorted, deduplicated `episode:...` / `feedback:...` identities cited by this warning.
    pub cited_record_ids: Vec<String>,
    /// Sorted, deduplicated publication root and supporting evidence digests.
    pub cited_evidence_digests: Vec<ContentDigest>,
    /// Compile-time invariant (`NEG-004`): always `false`.
    pub active_policy_mutation: bool,
}

impl AntiPatternWarning {
    /// Compile-time `NEG-004` invariant: trauma-guard warnings never mutate active policy.
    pub const ACTIVE_POLICY_MUTATION: bool = false;

    /// Canonical content digest of this warning under [`TRAUMA_GUARD_DOMAIN`].
    #[must_use]
    pub fn canonical_digest(&self) -> ContentDigest {
        digest_of(TRAUMA_GUARD_DOMAIN, |encoder: &mut CanonicalEncoder| {
            encoder.text(&self.warning_id);
            encoder.text(&self.target_json);
            encoder.text(self.cause_class.as_str());
            encoder.u64(self.negative_count as u64);
            encoder.i128(self.half_life_ns);
            encoder.u64(self.decay_weight_ppm);
            encoder.u32(self.cited_record_ids.len() as u32);
            for id in &self.cited_record_ids {
                encoder.text(id);
            }
            encoder.u32(self.cited_evidence_digests.len() as u32);
            for digest in &self.cited_evidence_digests {
                encoder.digest(*digest);
            }
            encoder.bool(self.active_policy_mutation);
        })
    }

    /// Canonical single-line advisory warning surfaced in `SituationCapsule` / `orient` responses.
    #[must_use]
    pub fn summary(&self) -> String {
        let cites = self.cited_record_ids.join(",");
        let digests = self
            .cited_evidence_digests
            .iter()
            .map(|d| d.to_text())
            .collect::<Vec<_>>()
            .join(",");
        format!(
            "trauma_guard_warning[{}]: target={} cause={} negative_count={} decay_weight_ppm={} half_life_ns={} active_policy_mutation={} cites=[{}] digests=[{}]",
            self.warning_id,
            self.target_json,
            self.cause_class.as_str(),
            self.negative_count,
            self.decay_weight_ppm,
            self.half_life_ns,
            self.active_policy_mutation,
            cites,
            digests,
        )
    }
}

/// Computes deterministic integer exponential half-life decay weight in parts-per-million (`[1, 1_000_000]`).
///
/// Uses exact integer division `epochs = age_ns / half_life_ns` and linear fractional interpolation
/// between `2^-epochs` and `2^-(epochs + 1)` so no floating-point nondeterminism can ever occur.
#[must_use]
pub fn compute_decay_weight_ppm(
    reference_time_ns: i128,
    record_time_ns: i128,
    half_life_ns: i128,
) -> u64 {
    if half_life_ns <= 0 {
        return MAX_RECORD_WEIGHT_PPM;
    }
    let age_ns = reference_time_ns.saturating_sub(record_time_ns).max(0);
    let epochs = (age_ns / half_life_ns).min(20) as u32;
    let rem_ns = (age_ns % half_life_ns) as u128;
    let hl = half_life_ns as u128;
    let base = u128::from(MAX_RECORD_WEIGHT_PPM) >> epochs;
    let next = base >> 1;
    let drop = ((base - next) * rem_ns) / hl;
    (base.saturating_sub(drop) as u64).max(1)
}

fn negative_feedback_cause(kind: FeedbackProposalKind) -> Option<AttributionCauseClass> {
    match kind {
        FeedbackProposalKind::HardNegativeCandidate => Some(AttributionCauseClass::Hypothesis),
        FeedbackProposalKind::Harmful => Some(AttributionCauseClass::Execution),
        FeedbackProposalKind::BadAffordance => Some(AttributionCauseClass::ContextSelection),
        FeedbackProposalKind::AdapterQuirk => Some(AttributionCauseClass::Adapter),
        _ => None,
    }
}

#[derive(Default)]
struct Bucket {
    cause_class: Option<AttributionCauseClass>,
    record_ids: BTreeSet<String>,
    digests: BTreeSet<String>,
    decay_weight_ppm: u64,
}

/// Scans published `feedback-*` and `episode-*` records under `<root>/agent/publications/` and
/// deterministically derives advisory [`AntiPatternWarning`] entries for any `(target, cause)`
/// tuple that has accumulated at least [`TRAUMA_GUARD_MIN_NEGATIVE_COUNT`] negative records.
pub fn derive_trauma_guard_warnings(
    root: &Path,
    reference_time_ns: i128,
) -> Result<Vec<AntiPatternWarning>, DeploymentSessionError> {
    let mut buckets: BTreeMap<(String, &'static str), Bucket> = BTreeMap::new();

    for published in published_records(root, "feedback-")? {
        let proposal = decode_proposal(&published.record).map_err(|error| {
            DeploymentSessionError::StoreInvalid(format!(
                "a feedback record does not verify: {error}"
            ))
        })?;
        let Some(cause) = negative_feedback_cause(proposal.kind) else {
            continue;
        };
        let key = (proposal.target_json.clone(), cause.as_str());
        let bucket = buckets.entry(key).or_default();
        bucket.cause_class = Some(cause);
        if bucket.record_ids.insert(proposal.feedback_id.clone()) {
            let weight = compute_decay_weight_ppm(
                reference_time_ns,
                proposal.created_at_ns.max(0),
                TRAUMA_HALF_LIFE_NS,
            );
            bucket.decay_weight_ppm = bucket.decay_weight_ppm.saturating_add(weight);
        }
        bucket.digests.insert(published.root.to_text());
        for handle in &proposal.supporting_evidence {
            if ContentDigest::parse(handle).is_ok() {
                bucket.digests.insert(handle.clone());
            }
        }
    }

    for published in published_records(root, "episode-")? {
        let record = EpisodeRecord::from_bytes(&published.record).map_err(|error| {
            DeploymentSessionError::StoreInvalid(format!(
                "an episode record does not verify: {error}"
            ))
        })?;
        let is_failed = record.terminal_state == TerminalOutcome::Failed
            || record.episode.outcome.state == EpisodeOutcomeState::Failed;
        if !is_failed {
            continue;
        }
        let target = match read_plan(root, &record.plan_id) {
            Ok((plan, _)) => FeedbackTarget::Event(plan.event_id),
            Err(_) => FeedbackTarget::Plan(record.plan_id.clone()),
        };
        let target_str = target_json(&target);
        let cause = AttributionCauseClass::Execution;
        let key = (target_str, cause.as_str());
        let bucket = buckets.entry(key).or_default();
        bucket.cause_class = Some(cause);
        if bucket.record_ids.insert(record.episode.episode_id.clone()) {
            let weight = compute_decay_weight_ppm(
                reference_time_ns,
                record.recorded_at.0.max(0),
                TRAUMA_HALF_LIFE_NS,
            );
            bucket.decay_weight_ppm = bucket.decay_weight_ppm.saturating_add(weight);
        }
        bucket.digests.insert(published.root.to_text());
        for receipt in &record.episode.effect_receipts {
            if ContentDigest::parse(receipt).is_ok() {
                bucket.digests.insert(receipt.clone());
            }
        }
    }

    let mut warnings = Vec::new();
    for ((target_str, _), bucket) in buckets {
        let negative_count = bucket.record_ids.len();
        if negative_count < TRAUMA_GUARD_MIN_NEGATIVE_COUNT {
            continue;
        }
        let Some(cause_class) = bucket.cause_class else {
            continue;
        };
        let cited_record_ids: Vec<String> = bucket.record_ids.into_iter().collect();
        let cited_evidence_digests: Vec<ContentDigest> = bucket
            .digests
            .into_iter()
            .filter_map(|text| ContentDigest::parse(&text).ok())
            .collect();
        let id_digest = digest_of(TRAUMA_GUARD_DOMAIN, |encoder| {
            encoder.text(&target_str);
            encoder.text(cause_class.as_str());
            encoder.u32(cited_record_ids.len() as u32);
            for id in &cited_record_ids {
                encoder.text(id);
            }
        });
        let warning_id = format!(
            "trauma-guard:{}",
            hex(id_digest).chars().take(32).collect::<String>()
        );
        warnings.push(AntiPatternWarning {
            warning_id,
            target_json: target_str,
            cause_class,
            negative_count,
            half_life_ns: TRAUMA_HALF_LIFE_NS,
            decay_weight_ppm: bucket.decay_weight_ppm,
            cited_record_ids,
            cited_evidence_digests,
            active_policy_mutation: AntiPatternWarning::ACTIVE_POLICY_MUTATION,
        });
    }
    Ok(warnings)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decay_weight_halves_deterministically_at_each_half_life() {
        let t0 = 1_000_000_000_000_i128;
        assert_eq!(
            compute_decay_weight_ppm(t0, t0, TRAUMA_HALF_LIFE_NS),
            1_000_000
        );
        assert_eq!(
            compute_decay_weight_ppm(t0 + TRAUMA_HALF_LIFE_NS, t0, TRAUMA_HALF_LIFE_NS),
            500_000
        );
        assert_eq!(
            compute_decay_weight_ppm(t0 + 2 * TRAUMA_HALF_LIFE_NS, t0, TRAUMA_HALF_LIFE_NS),
            250_000
        );
        assert_eq!(
            compute_decay_weight_ppm(t0 + TRAUMA_HALF_LIFE_NS / 2, t0, TRAUMA_HALF_LIFE_NS),
            750_000
        );
    }
}
