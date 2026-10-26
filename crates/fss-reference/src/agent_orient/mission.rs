#![forbid(unsafe_code)]
//! The retained request is mission context, never proof that its desired outcome occurred.

use super::*;
use fss_core::DigestAlgorithm;

const CLAIM: &str = "claim:session:requested-mission";
const COMPLETION_UNKNOWN: &str = "Mission success, failure, stop criteria and terminal proof have not been supplied; completion is unassessed.";

#[cfg(test)]
mod tests;

/// Exact mission text admitted from the owning session's immutable mission record.
///
/// The native owner verifies the root-last record against its workspace objective digest before
/// constructing this brief. A pure compiler checks scope but does not read or authenticate a
/// journal. This is projection input, not a negotiated mission lifecycle or effect authority.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OrientMissionBrief {
    /// Mission owning the retained request.
    pub mission_id: MissionId,
    /// Session whose workspace pins the retained record.
    pub session_id: SessionId,
    /// Principal admitted to that workspace.
    pub principal: PrincipalId,
    /// Deployment namespace of the retained record.
    pub site_lineage: String,
    /// Literal requested mission, without summarization or inferred predicates.
    pub mission: String,
    /// Literal requested desired outcome.
    pub objective: String,
    /// SHA-256 of the complete canonical retained mission record.
    pub record_digest: ContentDigest,
}

#[derive(Default)]
pub(super) struct Projection {
    pub objective_id: Option<String>,
    pub cells: Vec<KnowledgeCell>,
    pub proof_roots: BTreeSet<ContentDigest>,
    pub unknown: Vec<String>,
    /// The complete prose belongs in the selector's mandatory frame summary, not an optional
    /// knowledge-cell candidate. A view that cannot retain it must refuse its context budget.
    pub protected_summary: Option<String>,
}

/// Binds the literal request before world, capsule, context-pack and compression identities.
pub(super) fn project(
    snapshot: &DeploymentSnapshot,
    request: &OrientRequest,
    binding: Option<&OrientSessionBinding>,
) -> Result<Projection, ContractError> {
    let Some(binding) = binding else {
        return Ok(Projection::default());
    };
    let Some(mission) = &binding.mission else {
        return Ok(Projection {
            unknown: vec![
                "The durable mission objective has not been loaded; this projection does not assess mission completion."
                    .to_owned(),
            ],
            ..Projection::default()
        });
    };
    if mission.mission_id != binding.mission_id
        || mission.session_id != binding.session_id
        || mission.principal != request.principal
        || mission.site_lineage != snapshot.site_lineage
    {
        // A foreign brief is not evidence for this session's request. Do not emit its text or
        // silently fall back to a generic objective after a scope failure.
        return Err(ContractError::EvidenceRequired);
    }
    if mission.mission.is_empty()
        || mission.mission.len() > crate::deployment_session::MAX_MISSION_BYTES
        || mission.objective.is_empty()
        || mission.objective.len() > crate::deployment_session::MAX_OBJECTIVE_BYTES
    {
        return Err(ContractError::InvalidIdentifier);
    }
    if mission.record_digest.algorithm() != DigestAlgorithm::Sha256
        || mission.record_digest.is_laboratory()
        || mission.record_digest.bytes() == [0; 32]
    {
        return Err(ContractError::InvalidDigest);
    }
    // The cell establishes retention of a request, not the truth of any user-authored sentence.
    // Literal prose stays in protected context. Its hashes also bind the generated capsule id
    // without reclassifying text containing a provenance marker as a present physical claim.
    let retained = cell(KnowledgeCellParams {
        claim_id: CLAIM.to_owned(),
        statement: format!(
            "The retained mission record binds requested mission text {} and objective text {}.",
            ContentDigest::sha256(mission.mission.as_bytes()),
            ContentDigest::sha256(mission.objective.as_bytes()),
        ),
        knowledge_state: KnowledgeState::Known,
        provenance: ProvenanceClass::Derived,
        hypothesis: None,
        evidence: vec![mission.record_digest],
        contradictions: Vec::new(),
        valid_until: None,
        state_basis: None,
    })?;
    Ok(Projection {
        objective_id: Some(format!("objective:mission:{}", mission.record_digest)),
        cells: vec![retained],
        proof_roots: BTreeSet::from([mission.record_digest]),
        // Workspace unknowns are conserved. This states the record format's permanent boundary,
        // without inventing volatile success, progress, deadlines or terminal-state claims.
        unknown: vec![COMPLETION_UNKNOWN.to_owned()],
        protected_summary: Some(format!(
            "Requested mission: {}\nRequested objective: {}",
            mission.mission, mission.objective,
        )),
    })
}

/// Preserve the mission's requested outcome without promoting rendering success into mission
/// success. The existing prose-only record supplies no executable completion criteria.
pub(super) fn objective(
    mut params: ObjectiveContractParams,
    binding: Option<&OrientSessionBinding>,
) -> Result<ObjectiveContract, ContractError> {
    if let Some(mission) = binding.and_then(|binding| binding.mission.as_ref()) {
        params.source_request_digest = mission.record_digest.to_text();
        params.desired_outcome = mission.objective.clone();
        params.success_predicates.clear();
        params.failure_predicates.clear();
        params.stop_conditions.clear();
        params.terminal_proof.clear();
    }
    ObjectiveContract::new(params)
}
