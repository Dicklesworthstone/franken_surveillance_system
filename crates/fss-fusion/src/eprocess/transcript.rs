#![forbid(unsafe_code)]
//! Evidence-bound receipts alongside the unchanged historical numerical step digest.

use std::collections::BTreeSet;

use fss_core::{CanonicalEncoder, ContentDigest};

use super::{EProcessConfig, EProcessStepOutcome, RegimeResetReason};

/// Exact query/decision and predecessor binding for one sequential transition.
pub const EPROCESS_TRANSCRIPT_DOMAIN: &str = "fss.fusion.eprocess_transcript.v1";
/// JSON interchange schema; deliberately distinct from the canonical digest domain.
pub const EPROCESS_TRANSCRIPT_SCHEMA: &str = "fss.fusion_eprocess_transcript.v1";
/// Canonical inventory of supporting failure-domain components in the active regime.
pub const EPROCESS_SUPPORT_DOMAIN: &str = "fss.fusion.eprocess_support.v1";
/// Exact reset input, including reason bytes beyond the legacy numerical encoder's text ceiling.
pub const EPROCESS_RESET_DOMAIN: &str = "fss.fusion.eprocess_reset.v1";
/// Complete bounded numerical context, independent of legacy reset-text encoding limits.
pub const EPROCESS_STATE_DOMAIN: &str = "fss.fusion.eprocess_state.v1";

/// The executed transition distinguishes observed fusion input from an explicit reset.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EProcessStepInput {
    /// Digests returned by the actual validated `fuse` call, including its complete policy,
    /// calibration, source identities, coverage, uncertainty and decision.
    Observation {
        /// Canonical complete fusion query, independent of input vector order.
        query_digest: ContentDigest,
        /// Canonical decision from that exact query.
        decision_digest: ContentDigest,
    },
    /// No fusion query was executed. Reset ancestry is preserved even when numbers return to zero.
    RegimeReset {
        /// Exact variant and reset arguments, independently of the historical numerical encoding.
        reason_digest: ContentDigest,
    },
}

pub(super) fn reset_reason_digest(reason: &RegimeResetReason) -> ContentDigest {
    let mut encoder = CanonicalEncoder::new();
    encoder.text(EPROCESS_RESET_DOMAIN);
    // The legacy infallible reset API accepts arbitrary strings. Hash their exact bytes into
    // fixed-width fields so its over-bound numerical encoding cannot collapse transcript identity.
    match reason {
        RegimeResetReason::SensorHealthDegraded { sensor, reason } => {
            encoder.tag(0);
            encoder.digest(ContentDigest::sha256(sensor.as_bytes()));
            encoder.digest(ContentDigest::sha256(reason.as_bytes()));
        }
        RegimeResetReason::ClockContinuityBroken { sensor, gap_ns } => {
            encoder.tag(1);
            encoder.digest(ContentDigest::sha256(sensor.as_bytes()));
            encoder.u64(*gap_ns);
        }
        RegimeResetReason::OperatorReset { reason } => {
            encoder.tag(2);
            encoder.digest(ContentDigest::sha256(reason.as_bytes()));
        }
    }
    ContentDigest::sha256(&encoder.finish())
}

pub(super) fn state_digest(
    hypothesis_id: &str,
    config: &EProcessConfig,
    outcome: &EProcessStepOutcome,
) -> ContentDigest {
    let mut encoder = CanonicalEncoder::new();
    encoder.text(EPROCESS_STATE_DOMAIN);
    encoder.digest(ContentDigest::sha256(hypothesis_id.as_bytes()));
    encoder.u64(outcome.step_index);
    encoder.u32(outcome.regime_epoch);
    encoder.i128(i128::from(config.alert_threshold_mban));
    encoder.i128(i128::from(config.floor_mban));
    encoder.i128(i128::from(config.ceiling_mban));
    encoder.u32(config.min_independent_clusters);
    outcome.step_delta_llr.encode(&mut encoder);
    outcome.accumulated_llr.encode(&mut encoder);
    encoder.i128(i128::from(outcome.supremum_lo_mban));
    encoder.u32(outcome.ville_false_alarm_bound_ppm);
    encoder.u32(outcome.threshold_ville_bound_ppm);
    encoder.u32(outcome.independent_supporting_clusters);
    encoder.bool(outcome.crossed_alert_threshold);
    match &outcome.last_reset {
        Some(reason) => {
            encoder.bool(true);
            encoder.digest(reset_reason_digest(reason));
        }
        None => encoder.bool(false),
    }
    ContentDigest::sha256(&encoder.finish())
}

/// Immutable commitment to one actual sequential transition and its full predecessor chain.
///
/// A bounded state commitment binds hypothesis, configuration, step index, regime, statistics
/// and exact reset arguments independently of legacy v1 text limits. This separate transcript
/// domain also binds the unchanged historical numerical digest, actual query/decision (or an
/// explicit reset tag), full supporting-domain inventory and previous transcript digest.
/// It preserves v1 compatibility without treating old numerical receipts as source proofs.
///
/// Verification consists of replaying the exact ordered queries and reset reasons through
/// `SequentialEProcess`, then comparing these digests. Source custody and a test-supermartingale
/// assumption remain separate requirements; this receipt establishes neither.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EProcessTranscript {
    previous: Option<ContentDigest>,
    input: EProcessStepInput,
    numerical_step_digest: ContentDigest,
    state_digest: ContentDigest,
    supporting_domains_digest: ContentDigest,
    digest: ContentDigest,
}

impl EProcessTranscript {
    pub(super) fn pending(previous: Option<ContentDigest>, input: EProcessStepInput) -> Self {
        Self {
            previous,
            input,
            numerical_step_digest: ContentDigest::sha256(b""),
            state_digest: ContentDigest::sha256(b""),
            supporting_domains_digest: ContentDigest::sha256(b""),
            digest: ContentDigest::sha256(b""),
        }
    }

    pub(super) fn seal(
        &mut self,
        numerical_step_digest: ContentDigest,
        state_digest: ContentDigest,
        supporting_domains: &[BTreeSet<String>],
    ) {
        self.numerical_step_digest = numerical_step_digest;
        self.state_digest = state_digest;
        // The owner keeps components and domains sorted. Commit their complete inventory using
        // constant-size encodings instead of copying an ever-growing history into one buffer.
        // Seed: domain + component count. Boundary fold: tag 0 + previous digest + domain count.
        // Domain fold: tag 1 + previous digest + SHA-256 of the exact UTF-8 domain bytes.
        let mut support = CanonicalEncoder::new();
        support.text(EPROCESS_SUPPORT_DOMAIN);
        support.u64(supporting_domains.len() as u64);
        let mut support_digest = ContentDigest::sha256(&support.finish());
        for component in supporting_domains {
            let mut support = CanonicalEncoder::new();
            support.tag(0);
            support.digest(support_digest);
            support.u64(component.len() as u64);
            support_digest = ContentDigest::sha256(&support.finish());
            for domain in component {
                let mut support = CanonicalEncoder::new();
                support.tag(1);
                support.digest(support_digest);
                support.digest(ContentDigest::sha256(domain.as_bytes()));
                support_digest = ContentDigest::sha256(&support.finish());
            }
        }
        self.supporting_domains_digest = support_digest;

        let mut transcript = CanonicalEncoder::new();
        transcript.text(EPROCESS_TRANSCRIPT_DOMAIN);
        match self.previous {
            Some(previous) => {
                transcript.bool(true);
                transcript.digest(previous);
            }
            None => transcript.bool(false),
        }
        transcript.digest(self.numerical_step_digest);
        transcript.digest(self.state_digest);
        match self.input {
            EProcessStepInput::Observation {
                query_digest,
                decision_digest,
            } => {
                transcript.tag(0);
                transcript.digest(query_digest);
                transcript.digest(decision_digest);
            }
            EProcessStepInput::RegimeReset { reason_digest } => {
                transcript.tag(1);
                transcript.digest(reason_digest);
            }
        }
        transcript.digest(self.supporting_domains_digest);
        self.digest = ContentDigest::sha256(&transcript.finish());
    }

    /// Previous accepted transcript, or `None` only for the first transition of this accumulator.
    #[must_use]
    pub const fn previous(&self) -> Option<ContentDigest> {
        self.previous
    }

    /// Actual validated fusion inputs, or the explicit reset discriminator.
    #[must_use]
    pub const fn input(&self) -> EProcessStepInput {
        self.input
    }

    /// Unchanged historical numerical v1 identity, bound into this transcript.
    #[must_use]
    pub const fn numerical_step_digest(&self) -> ContentDigest {
        self.numerical_step_digest
    }

    /// Complete hypothesis, configuration and resulting state, independently of v1 text limits.
    #[must_use]
    pub const fn state_digest(&self) -> ContentDigest {
        self.state_digest
    }

    /// Exact canonical domain components remaining after the transition, not only their count.
    #[must_use]
    pub const fn supporting_domains_digest(&self) -> ContentDigest {
        self.supporting_domains_digest
    }

    /// Domain-separated receipt over this transition and its entire predecessor chain.
    #[must_use]
    pub const fn digest(&self) -> ContentDigest {
        self.digest
    }
}
