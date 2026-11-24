#![forbid(unsafe_code)]
//! Streaming cross-camera milliban LLR fusion via `fss-fusion` and canonical `EventHypothesis`
//! revision construction.
//!
//! Every candidate multi-camera match passes through `fss_fusion::fuse` with explicit transitive
//! failure-domain clusters from [`super::topology::SiteTopologyRegistry`]. Only genuinely
//! independent clusters (`supporting_clusters >= min_independent_support` and `>= 2`) whose
//! calibrated milliban posterior reaches the sequential alert threshold may emit
//! `EventState::Corroborated` with `ReferencePolicyAction::PrepareAlert`.

use std::collections::{BTreeMap, BTreeSet};

use fss_core::event::{MAX_MODEL_RECEIPTS_COUNT, MAX_TRACK_ID_LEN, MAX_UNCERTAINTY_REASON_LEN};
use fss_core::{
    CanonicalEncoder, CaptureInterval, ContentDigest, EventEvidence, EventHypothesis, EventId,
    EventKind, EventState, EvidenceClass, EvidenceEdgeRelation, ProbabilityInterval, TimestampNs,
};
use fss_fusion::{
    Calibration, Coverage, Decision, EvidenceItem, FusionPolicy, FusionQuery, LlrInterval,
    Observability, ScoreCalibration, Severity, fuse, probability::PPM,
};

use crate::alert::{committed_reference_policy_action, verify_event_alert_eligibility};
use crate::policy::{ReferencePolicyAction, zone_entry_decision_path};

use super::LiveCorroborateError;
use super::clock::ClockOffsetReceipt;
use super::receipt::seal_decision;
pub use super::receipt::{
    CorroborationOutcome, LIVE_CORROBORATE_DECISION_DOMAIN, LiveCorroborationDecision,
    MatchMechanism,
};
use super::topology::SiteTopologyRegistry;
use super::window::LiveObservation;

/// Fusion and score-calibration configuration for live streaming corroboration.
#[derive(Clone, Debug, PartialEq)]
pub struct LiveFusionConfig {
    /// Base-rate prior log-odds interval in millibans.
    pub prior: LlrInterval,
    /// Calibrated sequential decision policy passed directly to `fss_fusion::fuse`.
    pub policy: FusionPolicy,
    /// Consequence profile passed to `fss_fusion::fuse`.
    pub severity: Severity,
    /// Coverage assumption applied when evaluating streaming matches.
    pub coverage: Coverage,
    /// Per-class measured `ScoreCalibration` tables (e.g., `"person"` -> calibrated bins).
    pub calibrations: BTreeMap<String, ScoreCalibration>,
    /// Optional fallback `ScoreCalibration` when a class label has no dedicated table.
    pub default_calibration: Option<ScoreCalibration>,
    /// When `false` (default), observations must share a class label (or be `"unclassified"`).
    pub allow_class_mismatch: bool,
}

impl LiveFusionConfig {
    /// Constructs a conservative default configuration requiring `>= 2` independent clusters.
    pub fn default_policy() -> Result<Self, LiveCorroborateError> {
        Ok(Self {
            prior: LlrInterval::new(-500, -400)?,
            policy: FusionPolicy {
                generation: "policy:live-corroborate:v1".to_owned(),
                alert_threshold: 1_500,
                retain_threshold: 0,
                reject_threshold: -1_000,
                min_independent_support: 2,
                urgent_single_domain_threshold: None,
                max_wait_ns: 0,
                look_penalty_per_doubling: 0,
                operator_confirmation_available: true,
            },
            severity: Severity {
                expected_harm: 1_000,
                false_alert_cost: 100,
                delay_cost_per_second: 10,
                reversible: true,
            },
            coverage: Coverage::Complete,
            calibrations: BTreeMap::new(),
            default_calibration: None,
            allow_class_mismatch: false,
        })
    }

    /// Registers a measured [`ScoreCalibration`] for one class label.
    #[must_use]
    pub fn with_calibration(
        mut self,
        class_label: impl Into<String>,
        calibration: ScoreCalibration,
    ) -> Self {
        self.calibrations.insert(class_label.into(), calibration);
        self
    }

    /// Sets a fallback [`ScoreCalibration`] applied when no per-class calibration is registered.
    #[must_use]
    pub fn with_default_calibration(mut self, calibration: ScoreCalibration) -> Self {
        self.default_calibration = Some(calibration);
        self
    }

    /// Validates that `policy.min_independent_support >= 2` and thresholds are strictly ordered.
    pub fn validate(&self) -> Result<(), LiveCorroborateError> {
        if self.policy.min_independent_support < 2 {
            return Err(LiveCorroborateError::InvalidConfig(
                "live corroboration requires min_independent_support >= 2",
            ));
        }
        if !(self.policy.reject_threshold < self.policy.retain_threshold
            && self.policy.retain_threshold <= self.policy.alert_threshold)
        {
            return Err(LiveCorroborateError::InvalidConfig(
                "fusion policy thresholds must satisfy reject < retain <= alert",
            ));
        }
        Ok(())
    }

    fn calibrate_observation(&self, obs: &LiveObservation) -> Calibration {
        if let Some(cal) = self.calibrations.get(&obs.class_label) {
            cal.calibrate(obs.score_ppm)
        } else if let Some(cal) = &self.default_calibration {
            cal.calibrate(obs.score_ppm)
        } else {
            Calibration::Uncalibrated {
                reason: format!("no_calibration_for_class:{}", obs.class_label),
            }
        }
    }
}

/// Evaluates a matched pair of cross-camera observations through `fss-fusion` and seals a
/// canonical [`LiveCorroborationDecision`].
#[allow(clippy::too_many_arguments)]
pub(crate) fn evaluate_matched_pair(
    sequence: u64,
    topology: &SiteTopologyRegistry,
    topology_digest: ContentDigest,
    config: &LiveFusionConfig,
    obs_pair: [&LiveObservation; 2],
    mechanism: MatchMechanism,
    clock_receipts: Vec<ClockOffsetReceipt>,
) -> Result<LiveCorroborationDecision, LiveCorroborateError> {
    let mut ordered = obs_pair;
    ordered.sort_by(|a, b| {
        a.sensor_id
            .cmp(&b.sensor_id)
            .then_with(|| a.observation_digest().cmp(&b.observation_digest()))
    });
    let obs_digests: Vec<ContentDigest> = ordered.iter().map(|o| o.observation_digest()).collect();
    let event_id = derive_event_id(topology_digest, &obs_digests, &mechanism)?;

    let mut evidence_items = Vec::with_capacity(ordered.len());
    let mut cluster_ids = Vec::with_capacity(ordered.len());
    for obs in ordered {
        let entry = topology
            .cameras
            .get(&obs.sensor_id)
            .ok_or_else(|| LiveCorroborateError::UnknownCamera(obs.sensor_id.clone()))?;
        let cluster = topology
            .cluster_for_camera(&obs.sensor_id)
            .ok_or_else(|| LiveCorroborateError::UnknownCamera(obs.sensor_id.clone()))?;
        let mut domains = entry.failure_domains.clone();
        domains.insert(cluster.cluster_id.clone());
        cluster_ids.push(cluster.cluster_id);
        evidence_items.push(EvidenceItem {
            id: obs.observation_digest().to_text(),
            sensor: obs.sensor_id.clone(),
            failure_domains: domains,
            calibration: config.calibrate_observation(obs),
            observability: Observability::Observed,
        });
    }

    let earliest_ns = ordered[0]
        .bounded_capture
        .earliest_ns
        .min(ordered[1].bounded_capture.earliest_ns);
    let latest_ns = ordered[0]
        .bounded_capture
        .latest_ns
        .max(ordered[1].bounded_capture.latest_ns);
    let now_ns = u64::try_from(latest_ns.max(0)).unwrap_or(u64::MAX);
    let event_kind = classify_event_kind(ordered);

    let fusion_outcome = fuse(&FusionQuery {
        hypothesis: event_id.as_str().to_owned(),
        kind: event_kind.as_str().to_owned(),
        prior: config.prior,
        evidence: evidence_items,
        coverage: config.coverage.clone(),
        opportunities: Vec::new(),
        probes: Vec::new(),
        severity: config.severity,
        policy: config.policy.clone(),
        looks: 1,
        now_ns,
    })?;

    let interval = CaptureInterval::new(TimestampNs(earliest_ns), TimestampNs(latest_ns))?;
    let probability = if !fusion_outcome.clusters.is_empty() {
        let (lo_ppm, hi_ppm) = fusion_outcome.probability_ppm;
        ProbabilityInterval::with_calibration(
            f64::from(lo_ppm) / f64::from(PPM),
            f64::from(hi_ppm) / f64::from(PPM),
            fusion_outcome.decision_digest,
        )?
    } else {
        ProbabilityInterval::new(0.0, 1.0)?
    };

    let mut evidence_edges = Vec::with_capacity(ordered.len() + 1);
    for (idx, obs) in ordered.iter().enumerate() {
        evidence_edges.push(EventEvidence {
            digest: obs_digests[idx],
            class: EvidenceClass::Derived,
            failure_domain: cluster_ids[idx].clone(),
            supports: true,
            relation: EvidenceEdgeRelation::Supports,
            capsule_digest: Some(obs.source_capsule_digest),
            identity_digest: Some(ContentDigest::sha256(obs.sensor_id.as_bytes())),
        });
    }
    evidence_edges.push(EventEvidence {
        digest: fusion_outcome.decision_digest,
        class: EvidenceClass::Derived,
        failure_domain: "live-corroborate:fss-fusion".to_owned(),
        supports: false,
        relation: EvidenceEdgeRelation::DerivedFrom,
        capsule_digest: None,
        identity_digest: None,
    });

    let zone_ids: Vec<String> = ordered
        .iter()
        .map(|o| o.zone_id.clone())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect();
    let track_ids: Vec<String> = ordered
        .iter()
        .map(|o| format_bounded_track_id(&o.sensor_id, o.track_id))
        .collect();
    let model_receipts: Vec<ContentDigest> = ordered
        .iter()
        .flat_map(|o| [o.model_receipt_digest, o.cascade_receipt_digest])
        .collect::<BTreeSet<_>>()
        .into_iter()
        .take(MAX_MODEL_RECEIPTS_COUNT)
        .collect();

    let distinct_clusters: BTreeSet<&str> = cluster_ids.iter().map(String::as_str).collect();
    let shared_domains =
        topology.shared_domains_between(&ordered[0].sensor_id, &ordered[1].sensor_id);
    let collapsed = distinct_clusters.len() < 2 || !shared_domains.is_empty();

    let outcome = if !collapsed
        && fusion_outcome.supporting_clusters >= config.policy.min_independent_support
        && fusion_outcome.supporting_clusters >= 2
        && matches!(
            fusion_outcome.decision,
            Decision::Alert | Decision::AlertDegradedCoverage
        ) {
        let reason = format!(
            "live_corroborated:{} clusters={} posterior=[{},{}]mb",
            mechanism.as_str(),
            fusion_outcome.supporting_clusters,
            fusion_outcome.posterior.lo(),
            fusion_outcome.posterior.hi()
        );
        let event = build_verified_event(
            event_id,
            EventState::Corroborated,
            ReferencePolicyAction::PrepareAlert,
            event_kind,
            interval,
            reason,
            zone_ids,
            track_ids,
            probability,
            evidence_edges,
            model_receipts,
        )?;
        let committed = committed_reference_policy_action(&event);
        let alert_eligible = committed == ReferencePolicyAction::PrepareAlert
            && verify_event_alert_eligibility(event.state, committed, &event.evidence).is_ok();
        CorroborationOutcome::Corroborated {
            supporting_clusters: fusion_outcome.supporting_clusters,
            posterior: fusion_outcome.posterior,
            probability_ppm: fusion_outcome.probability_ppm,
            fusion_decision_digest: fusion_outcome.decision_digest,
            event,
            policy_action: ReferencePolicyAction::PrepareAlert,
            alert_eligible,
        }
    } else if collapsed {
        let shared_list: Vec<&str> = shared_domains.iter().map(String::as_str).collect();
        let explanation = format!(
            "Cameras {} and {} collapsed into {} supporting failure-domain cluster (required {}) due to shared domains [{}]; operator confirmation required.",
            ordered[0].sensor_id,
            ordered[1].sensor_id,
            fusion_outcome.supporting_clusters,
            config.policy.min_independent_support,
            shared_list.join(", ")
        );
        let event = build_verified_event(
            event_id,
            EventState::Indeterminate,
            ReferencePolicyAction::Hold,
            event_kind,
            interval,
            explanation.clone(),
            zone_ids,
            track_ids,
            probability,
            evidence_edges,
            model_receipts,
        )?;
        CorroborationOutcome::SharedFailureDomainHeld {
            supporting_clusters: fusion_outcome.supporting_clusters,
            shared_domains,
            requires_operator_confirmation: true,
            explanation,
            posterior: fusion_outcome.posterior,
            fusion_decision_digest: fusion_outcome.decision_digest,
            event,
            policy_action: ReferencePolicyAction::Hold,
        }
    } else {
        let explanation = format!(
            "Independent observations held by fss-fusion ({}): supporting_clusters={}, posterior=[{},{}]mb, uncalibrated={}.",
            fusion_outcome.decision.as_str(),
            fusion_outcome.supporting_clusters,
            fusion_outcome.posterior.lo(),
            fusion_outcome.posterior.hi(),
            fusion_outcome.uncalibrated.len()
        );
        let event = build_verified_event(
            event_id,
            EventState::Indeterminate,
            ReferencePolicyAction::Hold,
            event_kind,
            interval,
            explanation.clone(),
            zone_ids,
            track_ids,
            probability,
            evidence_edges,
            model_receipts,
        )?;
        CorroborationOutcome::InsufficientEvidenceHeld {
            supporting_clusters: fusion_outcome.supporting_clusters,
            posterior: fusion_outcome.posterior,
            fusion_decision: fusion_outcome.decision,
            fusion_decision_digest: fusion_outcome.decision_digest,
            event,
            policy_action: ReferencePolicyAction::Hold,
            explanation,
        }
    };

    Ok(seal_decision(
        sequence,
        topology_digest,
        clock_receipts,
        obs_digests,
        Some(mechanism),
        outcome,
    ))
}

/// Seals a [`LiveCorroborationDecision`] when temporal matching abstained due to clock uncertainty.
pub(crate) fn seal_clock_abstention(
    sequence: u64,
    topology_digest: ContentDigest,
    clock_receipts: Vec<ClockOffsetReceipt>,
    obs_pair: [&LiveObservation; 2],
    uncertainty_ns: u128,
    max_allowed_ns: u64,
) -> LiveCorroborationDecision {
    let mut ordered = obs_pair;
    ordered.sort_by(|a, b| {
        a.sensor_id
            .cmp(&b.sensor_id)
            .then_with(|| a.observation_digest().cmp(&b.observation_digest()))
    });
    let obs_digests: Vec<ContentDigest> = ordered.iter().map(|o| o.observation_digest()).collect();
    let sensor_ids = vec![ordered[0].sensor_id.clone(), ordered[1].sensor_id.clone()];
    let explanation = format!(
        "Abstained from temporal match across [{}]: clock uncertainty {}ns exceeds ceiling {}ns.",
        sensor_ids.join(", "),
        uncertainty_ns,
        max_allowed_ns
    );
    seal_decision(
        sequence,
        topology_digest,
        clock_receipts,
        obs_digests,
        None,
        CorroborationOutcome::ClockUncertaintyAbstained {
            uncertainty_ns,
            max_allowed_ns,
            sensor_ids,
            explanation,
        },
    )
}

#[allow(clippy::too_many_arguments)]
fn build_verified_event(
    event_id: EventId,
    state: EventState,
    action: ReferencePolicyAction,
    kind: EventKind,
    interval: CaptureInterval,
    reason: String,
    zone_ids: Vec<String>,
    track_ids: Vec<String>,
    probability: ProbabilityInterval,
    evidence: Vec<EventEvidence>,
    model_receipts: Vec<ContentDigest>,
) -> Result<EventHypothesis, LiveCorroborateError> {
    let decision_path = zone_entry_decision_path(&event_id, &evidence, state, action);
    let event = EventHypothesis {
        schema: EventHypothesis::SCHEMA.to_owned(),
        event_id,
        revision: 1,
        supersedes: None,
        state,
        kind,
        interval,
        uncertainty_reason: Some(truncate_utf8(&reason, MAX_UNCERTAINTY_REASON_LEN)),
        zone_ids,
        track_ids,
        probability,
        evidence,
        model_receipts,
        decision_path,
    };
    event.verify()?;
    Ok(event)
}

fn derive_event_id(
    topology_digest: ContentDigest,
    obs_digests: &[ContentDigest],
    mechanism: &MatchMechanism,
) -> Result<EventId, LiveCorroborateError> {
    let mut enc = CanonicalEncoder::new();
    enc.text(LIVE_CORROBORATE_DECISION_DOMAIN);
    enc.text("event-id");
    enc.digest(topology_digest);
    enc.u64(obs_digests.len() as u64);
    for d in obs_digests {
        enc.digest(*d);
    }
    mechanism.encode_canonical(&mut enc);
    let digest = ContentDigest::sha256(&enc.finish());
    let hex: String = digest
        .bytes()
        .iter()
        .take(16)
        .map(|b| format!("{b:02x}"))
        .collect();
    EventId::parse(format!("event:live:{hex}")).map_err(LiveCorroborateError::Contract)
}

fn classify_event_kind(ordered: [&LiveObservation; 2]) -> EventKind {
    if ordered[0].class_label == "person" && ordered[1].class_label == "person" {
        EventKind::UnknownPresence
    } else {
        EventKind::Unclassified
    }
}

fn format_bounded_track_id(sensor_id: &str, track_id: u64) -> String {
    let full = format!("{sensor_id}:{track_id}");
    if full.len() <= MAX_TRACK_ID_LEN {
        return full;
    }
    let digest = ContentDigest::sha256(sensor_id.as_bytes());
    let short: String = digest
        .bytes()
        .iter()
        .take(8)
        .map(|b| format!("{b:02x}"))
        .collect();
    truncate_utf8(&format!("s:{short}:{track_id}"), MAX_TRACK_ID_LEN)
}

fn truncate_utf8(input: &str, max_bytes: usize) -> String {
    if input.len() <= max_bytes {
        return input.to_owned();
    }
    let mut end = max_bytes;
    while end > 0 && !input.is_char_boundary(end) {
        end -= 1;
    }
    input[..end].to_owned()
}
