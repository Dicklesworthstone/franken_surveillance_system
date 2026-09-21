#![forbid(unsafe_code)]
//! Existing lineage transitions, retained separately from transactional admission.
use super::*;
use fss_core::event::EventTransitionParams;
use crate::ingest::cross_camera::AssociatedPair;

impl ZoneEventGenerator {
    /// Attaches a continued observation and requests the existing Witnessed transition.
    pub fn witness(
        &self, grant: RuntimeGrant, lineage: &mut fss_core::event::EventLineage,
        _target: &TrackedTarget, failure_domain: &str, ts: TimestampNs,
        frame_digest: ContentDigest,
    ) -> Result<(), ZoneEventError> {
        if grant != RuntimeGrant::ObserveEvent {
            return Err(ZoneEventError::CapabilityDenied { required: RuntimeGrant::ObserveEvent.as_str() });
        }
        if failure_domain.is_empty() {
            return Err(ZoneEventError::InvalidConfig("failure_domain must not be empty"));
        }
        let current = lineage.current().clone();
        let edge = EventEvidence {
            digest: frame_digest, class: EvidenceClass::Observed,
            failure_domain: failure_domain.to_string(), supports: true,
            relation: EvidenceEdgeRelation::Supports, capsule_digest: None, identity_digest: None,
        };
        let mut evidence = current.evidence.clone();
        if evidence.iter().any(|e| e.digest == frame_digest) {
            return Err(ZoneEventError::DuplicateEvidenceDigest);
        }
        evidence.push(edge);
        let params = EventTransitionParams {
            target_state: EventState::Witnessed, kind: current.kind,
            interval: expand_interval(current.interval, ts), uncertainty_reason: None,
            zone_ids: current.zone_ids.clone(), track_ids: current.track_ids.clone(),
            probability: current.probability, evidence, model_receipts: current.model_receipts.clone(),
            decision_path: self.chain_fingerprint(&current, ts, frame_digest), urgent_single_sensor: false,
        };
        lineage.transition(params).map_err(|err| ZoneEventError::Lineage(Box::new(err)))?;
        Ok(())
    }

    /// Requests corroboration through the existing lineage owner; shared domains and
    /// reused evidence are refused. This method does not dispatch or authorize an alert.
    #[allow(clippy::too_many_arguments)] // Existing public API.
    pub fn corroborate(
        &self, grant: RuntimeGrant, lineage: &mut fss_core::event::EventLineage,
        pair: &AssociatedPair, corroborating_failure_domain: &str, ts: TimestampNs,
        corroborating_frame_digest: ContentDigest, upper_probability: f64,
    ) -> Result<(), ZoneEventError> {
        if grant != RuntimeGrant::ObserveEvent {
            return Err(ZoneEventError::CapabilityDenied { required: RuntimeGrant::ObserveEvent.as_str() });
        }
        if corroborating_failure_domain.is_empty() {
            return Err(ZoneEventError::InvalidConfig("failure_domain must not be empty"));
        }
        let current = lineage.current().clone();
        let existing_domains: Vec<&str> = current.evidence.iter()
            .filter(|edge| edge.counts_as_support()).map(|edge| edge.failure_domain.as_str()).collect();
        if existing_domains.contains(&corroborating_failure_domain) {
            return Err(ZoneEventError::SameFailureDomain(corroborating_failure_domain.to_string()));
        }
        if current.evidence.iter().any(|e| e.digest == corroborating_frame_digest) {
            return Err(ZoneEventError::DuplicateEvidenceDigest);
        }
        let edge = EventEvidence {
            digest: corroborating_frame_digest, class: EvidenceClass::Observed,
            failure_domain: corroborating_failure_domain.to_string(), supports: true,
            relation: EvidenceEdgeRelation::Supports, capsule_digest: None, identity_digest: None,
        };
        let mut evidence = current.evidence.clone(); evidence.push(edge);
        let mut track_ids = current.track_ids.clone();
        let second_track = format!("track:{}", pair.second.track_id);
        if !track_ids.contains(&second_track) { track_ids.push(second_track); }
        let upper = upper_probability.clamp(current.probability.lower, 1.0);
        let probability = ProbabilityInterval::new(current.probability.lower, upper)
            .map_err(|err| ZoneEventError::EventContract(Box::new(EventDecodeError::Contract(err))))?;
        let params = EventTransitionParams {
            target_state: EventState::Corroborated, kind: current.kind,
            interval: expand_interval(current.interval, ts), uncertainty_reason: None,
            zone_ids: current.zone_ids.clone(), track_ids, probability, evidence,
            model_receipts: current.model_receipts.clone(),
            decision_path: self.chain_fingerprint(&current, ts, corroborating_frame_digest),
            urgent_single_sensor: false,
        };
        lineage.transition(params).map_err(|err| ZoneEventError::Lineage(Box::new(err)))?;
        Ok(())
    }

    fn chain_fingerprint(&self, current: &EventHypothesis, ts: TimestampNs, frame_digest: ContentDigest) -> DecisionPath {
        let mut fp_input = Vec::new();
        fp_input.extend_from_slice(&current.decision_path.fingerprint.bytes());
        fp_input.extend_from_slice(&ts.0.to_le_bytes());
        fp_input.extend_from_slice(&frame_digest.bytes());
        DecisionPath { policy_generation: self.config.policy_generation,
            fingerprint: ContentDigest::sha256(&fp_input), abstained: false, abstention_reason: None }
    }
}
fn expand_interval(interval: CaptureInterval, ts: TimestampNs) -> CaptureInterval {
    CaptureInterval { earliest: TimestampNs(interval.earliest.0.min(ts.0)), latest: TimestampNs(interval.latest.0.max(ts.0)) }
}

#[cfg(test)]
#[path = "lineage_tests.rs"]
mod tests;
