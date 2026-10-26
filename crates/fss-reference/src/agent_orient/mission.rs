#![forbid(unsafe_code)]
//! The retained request is mission context, never proof that its desired outcome occurred.

use super::*;
use crate::agent_session::mission::{MissionPlanCriterion, MissionRevision, same_generations};
use fss_core::{DigestAlgorithm, MissionLifecycleState};

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

/// An immutable execution-objective revision admitted by the durable session owner.
/// Freshness is derived from exact evidence, effect, and scoped closure inventories. A pure
/// projection authenticates no journal and cannot manufacture this native custody assessment.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OrientMissionProgress {
    /// Retained criterion and its proof-derived lifecycle revision.
    pub revision: MissionRevision,
    /// Whether this revision still describes the projection's exact current inputs.
    pub current: bool,
}

#[derive(Default)]
pub(super) struct Projection {
    pub state: Option<MissionLifecycleState>,
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
        if binding.mission_progress.is_some() {
            return Err(ContractError::EvidenceRequired);
        }
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
    let mut projection = Projection {
        state: None,
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
    };
    if let Some(progress) = &binding.mission_progress {
        projection.unknown = vec!["The original prose request has no executable success/failure/stop/proof predicates; completion is unassessed.".to_owned()];
        let revision = &progress.revision;
        let criterion = revision.criterion();
        if criterion.mission_id != binding.mission_id
            || criterion.session_id != binding.session_id
            || criterion.principal != request.principal
            || criterion.mission_record_digest != mission.record_digest
            || criterion.baseline_anchor.site_lineage != snapshot.site_lineage
            || criterion.contract_basis != fss_core::reference_contract_basis()
        {
            return Err(ContractError::EvidenceRequired);
        }
        if progress.current {
            if !same_generations(&criterion.baseline_anchor, &snapshot.anchor) {
                return Err(ContractError::EvidenceRequired);
            }
            if let Some(assessment) = revision.assessment() {
                if assessment.anchor != snapshot.anchor
                    || assessment.evidence_time != crate::deployment_session::evidence_now(snapshot)
                    || assessment.effect_journal_present != snapshot.effect_journal_present
                    || assessment.effect_journal_root != snapshot.effect_journal_root
                    || assessment.effect_record_count
                        != snapshot.position.effect_records.unwrap_or(0)
                {
                    return Err(ContractError::EvidenceRequired);
                }
            } else if criterion.baseline_anchor != snapshot.anchor {
                return Err(ContractError::EvidenceRequired);
            }
        }
        let criterion_digest = criterion.digest();
        projection.objective_id = Some(format!("objective:mission:{criterion_digest}"));
        projection.state = progress.current.then(|| revision.state());
        let roots = revision.proof_roots();
        projection.proof_roots.extend(roots.iter().copied());
        projection.proof_roots.insert(revision.digest());
        projection.proof_roots.insert(criterion_digest);
        projection.cells.push(cell(KnowledgeCellParams {
            claim_id: "claim:session:mission-progress".to_owned(),
            statement: format!(
                "The retained execution-objective revision {} at {} is {}; its assessment is {} for this projection.",
                revision.revision(), revision.digest(), revision.state().as_str(),
                if progress.current { "current" } else { "historical, requiring explicit reassessment" },
            ),
            knowledge_state: KnowledgeState::Known,
            provenance: ProvenanceClass::Derived,
            hypothesis: None,
            evidence: vec![criterion_digest, revision.digest()],
            contradictions: Vec::new(),
            valid_until: None,
            state_basis: None,
        })?);
        projection.protected_summary = Some(format!(
            "Mission: {}\nObjective: {}\n{}: {}\ncriterion={},planRoot={},event={}@{},op={},obligation={}\nEvidence-clock deadline {}ns is not terminal proof.\nRetained mission revision {}: {} at {}; {}. Terminal: agreed operation/obligation/episode proofs, current event revision/control generations, complete clear scoped closure. Physical truth and prose completion remain unassessed.",
            mission.mission,
            mission.objective,
            MissionPlanCriterion::PROFILE,
            criterion.plan_id,
            criterion_digest,
            criterion.plan_root,
            criterion.event_id.as_str(),
            criterion.event_revision,
            criterion.operation_id.as_str(),
            criterion.obligation_id.as_str(),
            criterion.decision_deadline.0,
            revision.revision(),
            revision.state().as_str(),
            revision.digest(),
            if progress.current {
                "current assessment"
            } else {
                "historical assessment; current lifecycle is unassessed"
            },
        ));
    }
    Ok(projection)
}

fn execution_outcome(criterion: &MissionPlanCriterion) -> String {
    format!(
        "Establish the proof-backed execution outcome of explicitly enrolled plan {}.",
        criterion.plan_id
    )
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
    if let Some(progress) = binding.and_then(|binding| binding.mission_progress.as_ref()) {
        let criterion = progress.revision.criterion();
        params.source_request_digest = criterion.digest().to_text();
        params.desired_outcome = execution_outcome(criterion);
        params.success_predicates = vec![
            format!("The exact operation {} and obligation {} are verified with the same nonempty proof digest and a matching retained execution episode.", criterion.operation_id.as_str(), criterion.obligation_id.as_str()),
            "The selected event revision and control generations remain current; every scoped other plan, case, claim, and supervision obligation is terminal or absent under a complete closure witness.".to_owned(),
        ];
        params.failure_predicates = vec![
            "The exact operation, obligation, and retained episode agree on failed execution under the same event, generation, proof, and closure checks.".to_owned(),
        ];
        params.stop_conditions = vec![
            "Retain resolved, failed, or cancelled only from matching terminal operation, obligation, and episode proofs with clear scoped closure inventory; indeterminate effects require reconciliation.".to_owned(),
            format!("At evidence-clock deadline {} ns, expose decision pressure; time passage alone neither cancels an effect nor proves failure.", criterion.decision_deadline.0),
        ];
        params.terminal_proof = vec![
            format!("fss://proof/{}", criterion.digest()),
            format!("fss://proof/{}", criterion.plan_root),
        ];
        params.hard_constraints.push("This explicit plan-outcome profile does not prove the underlying surveillance event or completion of the original prose objective. No lifecycle command grants effect authority.".to_owned());
    }
    ObjectiveContract::new(params)
}
