#![forbid(unsafe_code)]
//! Timestamped network observations, never present pixel continuity.
use super::{AttentionItem, cell};
use crate::discovery::retained_liveness::RetainedSensorLiveness;
use crate::discovery::watchdog::WatchState;
use fss_core::{
    ContentDigest, ContractError, KnowledgeCell, KnowledgeCellParams, KnowledgeState,
    ProvenanceClass,
};
use std::collections::BTreeSet;

/// Stable per-sensor cell namespace observed by follow as sensor health.
pub const CLAIM_SENSOR_LIVENESS_PREFIX: &str = "claim:sensor-liveness:";
/// Whether this cell carries a retained owner-enrolled network observation.
#[must_use]
pub fn is_sensor_liveness_claim(claim: &str) -> bool {
    claim.starts_with(CLAIM_SENSOR_LIVENESS_PREFIX)
}
pub(super) struct Projection {
    pub cells: Vec<KnowledgeCell>,
    pub proof_roots: BTreeSet<ContentDigest>,
    pub unknown: Vec<String>,
    pub at_risk: Vec<String>,
    pub attention: Vec<AttentionItem>,
}
/// Orientation is pinned to committed evidence. It cannot manufacture a fresh sweep from
/// wall-clock time; literal historical observations remain known, current health unproved.
pub(super) fn project(retained: &[RetainedSensorLiveness]) -> Result<Projection, ContractError> {
    let mut projection = Projection {
        cells: Vec::new(),
        proof_roots: BTreeSet::new(),
        unknown: Vec::new(),
        at_risk: Vec::new(),
        attention: Vec::new(),
    };
    if retained.is_empty() {
        return Ok(projection);
    }
    projection.unknown.push(
        "Retained network observations end at their stated sweep timestamps. They do not establish present camera health, authenticated device identity, decoded pixels, continuous media, certified absence or authority for effects; network return cannot clear an earlier coverage gap.".into(),
    );
    for retained in retained {
        let record = &retained.record;
        let binding = record.enrollment();
        let state = record.state();
        let sensor_digest = ContentDigest::sha256(binding.sensor().as_str().as_bytes());
        let claim_id = format!("{CLAIM_SENSOR_LIVENESS_PREFIX}{sensor_digest}");
        let handle = format!("fss://proof/{}", record.digest());
        let evidence = vec![record.digest(), retained.root];
        projection.proof_roots.extend(evidence.iter().copied());
        let optional =
            |value: Option<u64>| value.map_or_else(|| "none".to_owned(), |value| value.to_string());
        let statement = format!(
            "Historical network observation for sensor {} at endpoint {} ({}): network_state={}, sweep_started_ns={}, sweep_completed_ns={}, last_response_earliest_ns={}, last_response_latest_ns={}, conservative_grace_until_ns={}, last_unobserved_ns={}. Response time is bounded by its sweep window; age uses the earliest possible response. The state applies to that sweep only; a later read does not extend the grace deadline. Network responses cannot establish pixel continuity or erase the retained unobserved sweep.",
            binding.sensor(),
            binding.endpoint(),
            binding.class().as_str(),
            state.as_str(),
            record.sweep_started_ns(),
            record.observed_at_ns(),
            optional(record.last_seen_ns()),
            optional(record.last_response_latest_ns()),
            optional(record.fresh_until_ns()),
            optional(record.last_unobserved_ns()),
        );
        projection.cells.push(cell(KnowledgeCellParams {
            claim_id,
            statement,
            knowledge_state: KnowledgeState::Known,
            provenance: ProvenanceClass::Derived,
            hypothesis: None,
            evidence,
            contradictions: Vec::new(),
            valid_until: None,
            state_basis: None,
        })?);
        if state != WatchState::Observable || record.last_unobserved_ns().is_some() {
            let reason = format!(
                "Sensor {}: retained network state {} at sweep completion {} ns; last_unobserved_ns={}. Present network status and media continuity need fresh source evidence.",
                binding.sensor(),
                state.as_str(),
                record.observed_at_ns(),
                optional(record.last_unobserved_ns()),
            );
            projection.at_risk.push(reason.clone());
            projection.attention.push(AttentionItem {
                item_id: format!("attention:sensor-liveness:{sensor_digest}"),
                kind: "sensor_liveness",
                priority_class: "normal",
                mission_relevance: 1.0,
                decision_impact: 1.0,
                reason,
                handle,
            });
        }
    }
    Ok(projection)
}
