#![forbid(unsafe_code)]
//! Canonical decision receipts, typed corroboration outcomes, and zero-serde JSONL serialization
//! for live streaming multi-camera corroboration.

use std::collections::BTreeSet;
use std::fmt::Write as _;

use fss_core::{CanonicalEncoder, ContentDigest, EventHypothesis};
use fss_fusion::{Decision, LlrInterval};

use crate::policy::ReferencePolicyAction;

use super::clock::ClockOffsetReceipt;

/// Canonical digest domain for sealed [`LiveCorroborationDecision`] records.
pub const LIVE_CORROBORATE_DECISION_DOMAIN: &str = "fss.live_corroborate.decision.v1";

/// Spatial or corridor match proof connecting two observations in a decision.
#[derive(Clone, Debug, PartialEq)]
pub enum MatchMechanism {
    /// Ground-plane proximity match via calibrated homographies.
    GroundHomography {
        /// Shared zone label.
        zone_id: String,
        /// Projected ground distance.
        distance: f64,
        /// Distance gate ceiling.
        distance_gate: f64,
        /// Ground coordinates of observation A.
        ground_a: [f64; 2],
        /// Ground coordinates of observation B.
        ground_b: [f64; 2],
        /// Worst-case temporal separation (ns).
        max_separation_ns: u128,
    },
    /// Coarse shared-zone concurrent match.
    SharedZone {
        /// Shared zone identifier.
        zone_id: String,
        /// Worst-case temporal separation (ns).
        max_separation_ns: u128,
    },
    /// Directed physical transit corridor match.
    TransitCorridor {
        /// Corridor identifier.
        corridor_id: String,
        /// Origin camera ID.
        from_camera: String,
        /// Origin zone ID.
        from_zone: String,
        /// Destination camera ID.
        to_camera: String,
        /// Destination zone ID.
        to_zone: String,
        /// Minimum attainable signed transit duration (ns).
        min_elapsed_ns: i128,
        /// Maximum attainable signed transit duration (ns).
        max_elapsed_ns: i128,
    },
}

impl MatchMechanism {
    /// Stable lowercase spelling.
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::GroundHomography { .. } => "ground_homography",
            Self::SharedZone { .. } => "shared_zone",
            Self::TransitCorridor { .. } => "transit_corridor",
        }
    }

    pub(crate) fn encode_canonical(&self, encoder: &mut CanonicalEncoder) {
        encoder.text(self.as_str());
        match self {
            Self::GroundHomography {
                zone_id,
                distance,
                distance_gate,
                ground_a,
                ground_b,
                max_separation_ns,
            } => {
                encoder.u8(1);
                encoder.text(zone_id);
                encoder.u64(distance.to_bits());
                encoder.u64(distance_gate.to_bits());
                for v in [ground_a[0], ground_a[1], ground_b[0], ground_b[1]] {
                    encoder.u64(v.to_bits());
                }
                encode_u128(encoder, *max_separation_ns);
            }
            Self::SharedZone {
                zone_id,
                max_separation_ns,
            } => {
                encoder.u8(2);
                encoder.text(zone_id);
                encode_u128(encoder, *max_separation_ns);
            }
            Self::TransitCorridor {
                corridor_id,
                from_camera,
                from_zone,
                to_camera,
                to_zone,
                min_elapsed_ns,
                max_elapsed_ns,
            } => {
                encoder.u8(3);
                encoder.text(corridor_id);
                encoder.text(from_camera);
                encoder.text(from_zone);
                encoder.text(to_camera);
                encoder.text(to_zone);
                encoder.i128(*min_elapsed_ns);
                encoder.i128(*max_elapsed_ns);
            }
        }
    }
}

/// Typed outcome of evaluating a cross-camera observation match through `fss-fusion`.
#[derive(Clone, Debug, PartialEq)]
pub enum CorroborationOutcome {
    /// Independent failure-domain clusters met both support count and calibrated LLR alert threshold.
    Corroborated {
        /// Number of independent supporting failure-domain clusters (`>= 2`).
        supporting_clusters: u32,
        /// Exact milliban posterior log-odds interval from `fss-fusion`.
        posterior: LlrInterval,
        /// Outward-rounded posterior probability bounds in parts per million.
        probability_ppm: (u32, u32),
        /// Canonical `fss-fusion` decision digest.
        fusion_decision_digest: ContentDigest,
        /// Verified canonical `EventHypothesis` (`EventState::Corroborated`).
        event: EventHypothesis,
        /// Safe policy affordance (`ReferencePolicyAction::PrepareAlert`); never grants effect authority.
        policy_action: ReferencePolicyAction,
        /// True iff `verify_event_alert_eligibility` and `committed_reference_policy_action` pass.
        alert_eligible: bool,
    },
    /// Matched cameras collapsed into `< min_independent_support` clusters due to shared failure domains.
    SharedFailureDomainHeld {
        /// Effective independent supporting cluster count (e.g. `1`).
        supporting_clusters: u32,
        /// Shared or bridging failure domains that prevented independent corroboration.
        shared_domains: BTreeSet<String>,
        /// Always `true`: operator confirmation is required before acting.
        requires_operator_confirmation: bool,
        /// Human/agent-readable explanation citing exact shared domains.
        explanation: String,
        /// Exact milliban posterior log-odds interval (counted once per cluster hull).
        posterior: LlrInterval,
        /// Canonical `fss-fusion` decision digest.
        fusion_decision_digest: ContentDigest,
        /// Verified canonical `EventHypothesis` (`EventState::Indeterminate`, never `Corroborated`).
        event: EventHypothesis,
        /// Safe policy affordance (`ReferencePolicyAction::Hold`).
        policy_action: ReferencePolicyAction,
    },
    /// Clock uncertainty exceeded the operational cap; matching honestly abstained.
    ClockUncertaintyAbstained {
        /// Observed worst-case capture interval uncertainty (ns).
        uncertainty_ns: u128,
        /// Configured maximum tolerable uncertainty (ns).
        max_allowed_ns: u64,
        /// Sensor IDs whose observations were refused temporal matching.
        sensor_ids: Vec<String>,
        /// Human/agent-readable explanation of the abstention.
        explanation: String,
    },
    /// Independent domains existed, but calibrated posterior or calibration status did not reach alert.
    InsufficientEvidenceHeld {
        /// Independent supporting cluster count observed.
        supporting_clusters: u32,
        /// Milliban posterior log-odds interval.
        posterior: LlrInterval,
        /// Underlying `fss-fusion` sequential decision.
        fusion_decision: Decision,
        /// Canonical `fss-fusion` decision digest.
        fusion_decision_digest: ContentDigest,
        /// Verified canonical `EventHypothesis` (`EventState::Indeterminate`).
        event: EventHypothesis,
        /// Safe policy affordance (`ReferencePolicyAction::Hold`).
        policy_action: ReferencePolicyAction,
        /// Human/agent-readable explanation.
        explanation: String,
    },
}

impl CorroborationOutcome {
    /// Stable lowercase outcome tag.
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Corroborated { .. } => "corroborated",
            Self::SharedFailureDomainHeld { .. } => "shared_failure_domain_held",
            Self::ClockUncertaintyAbstained { .. } => "clock_uncertainty_abstained",
            Self::InsufficientEvidenceHeld { .. } => "insufficient_evidence_held",
        }
    }

    /// Returns the canonical [`EventHypothesis`] when one was emitted (absent on clock abstention).
    #[must_use]
    pub const fn event(&self) -> Option<&EventHypothesis> {
        match self {
            Self::Corroborated { event, .. }
            | Self::SharedFailureDomainHeld { event, .. }
            | Self::InsufficientEvidenceHeld { event, .. } => Some(event),
            Self::ClockUncertaintyAbstained { .. } => None,
        }
    }
}

/// Complete sealed decision emitted by [`super::LiveCorroborationEngine`] for one cross-camera pair.
#[derive(Clone, Debug, PartialEq)]
pub struct LiveCorroborationDecision {
    /// Monotonic engine evaluation sequence number.
    pub sequence: u64,
    /// Canonical [`super::SiteTopologyRegistry`] digest active during evaluation.
    pub topology_digest: ContentDigest,
    /// Per-camera clock offset receipts active during evaluation (sorted by `sensor_id`).
    pub clock_receipts: Vec<ClockOffsetReceipt>,
    /// Matched observation identity digests (sorted).
    pub observation_digests: Vec<ContentDigest>,
    /// Spatial or transit-corridor match mechanism, if temporal checks were not skipped.
    pub match_mechanism: Option<MatchMechanism>,
    /// Typed corroboration outcome.
    pub outcome: CorroborationOutcome,
    /// Domain-separated canonical SHA-256 digest (`LIVE_CORROBORATE_DECISION_DOMAIN`).
    pub decision_digest: ContentDigest,
}

impl LiveCorroborationDecision {
    /// Renders a single-line structured JSONL audit record without external serialization crates.
    #[must_use]
    pub fn to_jsonl(&self) -> String {
        let mut out = String::with_capacity(384);
        let _ = write!(
            out,
            "{{\"sequence\":{},\"outcome\":\"{}\",\"decision_digest\":\"{}\",\"topology_digest\":\"{}\"",
            self.sequence,
            self.outcome.as_str(),
            self.decision_digest,
            self.topology_digest
        );
        if let Some(mech) = &self.match_mechanism {
            let _ = write!(out, ",\"mechanism\":\"{}\"", mech.as_str());
        }
        match &self.outcome {
            CorroborationOutcome::Corroborated {
                supporting_clusters,
                posterior,
                probability_ppm,
                fusion_decision_digest,
                event,
                alert_eligible,
                ..
            } => {
                let _ = write!(
                    out,
                    concat!(
                        ",\"supporting_clusters\":{},\"posterior_mb\":[{},{}],",
                        "\"probability_ppm\":[{},{}],\"fusion_decision_digest\":\"{}\",",
                        "\"event_id\":\"{}\",\"event_state\":\"{}\",\"alert_eligible\":{}"
                    ),
                    supporting_clusters,
                    posterior.lo(),
                    posterior.hi(),
                    probability_ppm.0,
                    probability_ppm.1,
                    fusion_decision_digest,
                    json_escape(event.event_id.as_str()),
                    event.state.as_str(),
                    alert_eligible
                );
            }
            CorroborationOutcome::SharedFailureDomainHeld {
                supporting_clusters,
                shared_domains,
                requires_operator_confirmation,
                explanation,
                fusion_decision_digest,
                event,
                ..
            } => {
                let domains = json_string_list(shared_domains.iter().map(String::as_str));
                let _ = write!(
                    out,
                    concat!(
                        ",\"supporting_clusters\":{},\"shared_domains\":[{}],",
                        "\"requires_operator_confirmation\":{},\"fusion_decision_digest\":\"{}\",",
                        "\"event_id\":\"{}\",\"event_state\":\"{}\",\"explanation\":\"{}\""
                    ),
                    supporting_clusters,
                    domains,
                    requires_operator_confirmation,
                    fusion_decision_digest,
                    json_escape(event.event_id.as_str()),
                    event.state.as_str(),
                    json_escape(explanation)
                );
            }
            CorroborationOutcome::ClockUncertaintyAbstained {
                uncertainty_ns,
                max_allowed_ns,
                sensor_ids,
                explanation,
            } => {
                let sensors = json_string_list(sensor_ids.iter().map(String::as_str));
                let _ = write!(
                    out,
                    concat!(
                        ",\"uncertainty_ns\":{},\"max_allowed_ns\":{},",
                        "\"sensors\":[{}],\"explanation\":\"{}\""
                    ),
                    uncertainty_ns,
                    max_allowed_ns,
                    sensors,
                    json_escape(explanation)
                );
            }
            CorroborationOutcome::InsufficientEvidenceHeld {
                supporting_clusters,
                posterior,
                fusion_decision,
                fusion_decision_digest,
                event,
                explanation,
                ..
            } => {
                let _ = write!(
                    out,
                    concat!(
                        ",\"supporting_clusters\":{},\"posterior_mb\":[{},{}],",
                        "\"fusion_decision\":\"{}\",\"fusion_decision_digest\":\"{}\",",
                        "\"event_id\":\"{}\",\"event_state\":\"{}\",\"explanation\":\"{}\""
                    ),
                    supporting_clusters,
                    posterior.lo(),
                    posterior.hi(),
                    fusion_decision.as_str(),
                    fusion_decision_digest,
                    json_escape(event.event_id.as_str()),
                    event.state.as_str(),
                    json_escape(explanation)
                );
            }
        }
        out.push('}');
        out
    }
}

pub(crate) fn seal_decision(
    sequence: u64,
    topology_digest: ContentDigest,
    mut clock_receipts: Vec<ClockOffsetReceipt>,
    observation_digests: Vec<ContentDigest>,
    match_mechanism: Option<MatchMechanism>,
    outcome: CorroborationOutcome,
) -> LiveCorroborationDecision {
    clock_receipts.sort_by(|a, b| a.sensor_id.cmp(&b.sensor_id));
    let mut enc = CanonicalEncoder::new();
    enc.text(LIVE_CORROBORATE_DECISION_DOMAIN);
    enc.u64(sequence);
    enc.digest(topology_digest);
    enc.u64(clock_receipts.len() as u64);
    for r in &clock_receipts {
        enc.digest(r.receipt_digest);
    }
    enc.u64(observation_digests.len() as u64);
    for d in &observation_digests {
        enc.digest(*d);
    }
    match &match_mechanism {
        Some(m) => {
            enc.bool(true);
            m.encode_canonical(&mut enc);
        }
        None => enc.bool(false),
    }
    enc.text(outcome.as_str());
    match &outcome {
        CorroborationOutcome::Corroborated {
            supporting_clusters,
            fusion_decision_digest,
            event,
            alert_eligible,
            ..
        } => {
            enc.u32(*supporting_clusters);
            enc.digest(*fusion_decision_digest);
            enc.digest(event.revision_digest());
            enc.bool(*alert_eligible);
        }
        CorroborationOutcome::SharedFailureDomainHeld {
            supporting_clusters,
            shared_domains,
            fusion_decision_digest,
            event,
            ..
        } => {
            enc.u32(*supporting_clusters);
            enc.u64(shared_domains.len() as u64);
            for d in shared_domains {
                enc.text(d);
            }
            enc.digest(*fusion_decision_digest);
            enc.digest(event.revision_digest());
        }
        CorroborationOutcome::ClockUncertaintyAbstained {
            uncertainty_ns,
            max_allowed_ns,
            sensor_ids,
            ..
        } => {
            encode_u128(&mut enc, *uncertainty_ns);
            enc.u64(*max_allowed_ns);
            enc.u64(sensor_ids.len() as u64);
            for s in sensor_ids {
                enc.text(s);
            }
        }
        CorroborationOutcome::InsufficientEvidenceHeld {
            supporting_clusters,
            fusion_decision_digest,
            event,
            ..
        } => {
            enc.u32(*supporting_clusters);
            enc.digest(*fusion_decision_digest);
            enc.digest(event.revision_digest());
        }
    }
    LiveCorroborationDecision {
        sequence,
        topology_digest,
        clock_receipts,
        observation_digests,
        match_mechanism,
        outcome,
        decision_digest: ContentDigest::sha256(&enc.finish()),
    }
}

fn encode_u128(encoder: &mut CanonicalEncoder, value: u128) {
    encoder.u64((value >> 64) as u64);
    encoder.u64(value as u64);
}

fn json_string_list<'a>(items: impl Iterator<Item = &'a str>) -> String {
    items
        .map(|s| format!("\"{}\"", json_escape(s)))
        .collect::<Vec<_>>()
        .join(",")
}

fn json_escape(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    for ch in input.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => {
                let _ = write!(out, "\\u{:04x}", c as u32);
            }
            c => out.push(c),
        }
    }
    out
}
