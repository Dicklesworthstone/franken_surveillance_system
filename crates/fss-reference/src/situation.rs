//! Deterministic agent-facing projection of the reference evidence/effect spine.

use std::collections::BTreeSet;

use fss_core::{
    ActionAffordance, AffordanceClass, BudgetVector, CanonicalEncode, CanonicalEncoder,
    Completeness, ContentDigest, ContractBasis, CoverageContinuity, CoverageStopReason,
    CoverageWitness, EffectState, EventKind, EventState, HandoffCapsule, HandoffId,
    HandoffPublishParams, HypothesisDisposition, KnowledgeCell, KnowledgeState,
    KnowledgeStateBasis, LedgerAnchor, MissionId, ObjectId, ObligationId, PossibleWorld,
    PrincipalId, ProvenanceClass, ReconciliationBasis, SessionId, SituationCapsule, SituationFrame,
    TimestampNs, WorldEnvelope,
};
use fss_ledger::DurableReferenceLedger;

use crate::{
    ReferenceAlertOutcomeReceipt, ReferenceAlertPlan, ReferenceError, ReferenceEventReceipt,
    ReferencePolicyAction, ReferencePolicyDecision, alert::validate_reference_alert_plan,
};

const MAX_OBJECTIVE_BYTES: usize = 512;
const CAPABILITY_EVIDENCE_QUERY: &str = "capability:evidence.query";
const CAPABILITY_ALERT_PREPARE: &str = "capability:alert.prepare";
const CAPABILITY_ALERT_COMMIT: &str = "capability:alert.commit";
const CAPABILITY_EFFECT_RECONCILE: &str = "capability:effect.reconcile";
const CAPABILITY_SESSION_WAIT: &str = "capability:session.wait";

/// Exact inputs used to compile one bounded situation projection.
#[derive(Clone, Debug)]
pub struct ReferenceSituationRequest<'a> {
    /// Mission identity.
    pub mission_id: MissionId,
    /// Session identity.
    pub session_id: SessionId,
    /// Principal identity.
    pub principal_id: PrincipalId,
    /// Stable objective identity.
    pub objective_id: String,
    /// Monotone situation revision within the caller-owned publication lineage.
    pub revision: u64,
    /// Exact semantic contract universe.
    pub contract_basis: ContractBasis,
    /// Prior authority anchor, when producing a delta-oriented projection.
    pub previous_anchor: Option<LedgerAnchor>,
    /// Canonical policy decision being projected.
    pub decision: &'a ReferencePolicyDecision,
    /// Authority receipt for the event revision.
    pub event_receipt: &'a ReferenceEventReceipt,
    /// Optional prepared effect intent. This remains non-terminal until a canonical outcome exists.
    pub alert_plan: Option<&'a ReferenceAlertPlan>,
    /// Optional canonical effect outcome publication.
    pub alert_outcome: Option<&'a ReferenceAlertOutcomeReceipt>,
    /// Optional coverage witness for negative reads / absence certification.
    pub coverage_witness: Option<&'a CoverageWitness>,
    /// Capabilities currently delegated to the principal.
    pub available_capabilities: BTreeSet<String>,
    /// Deterministic caller-supplied creation time.
    pub created_at: TimestampNs,
}

/// A compiled situation plus every proof root needed for a self-contained handoff.
#[derive(Clone, Debug, PartialEq)]
pub struct ReferenceSituation {
    /// Canonical handoff capsule after projection.
    pub capsule: SituationCapsule,
    /// Exact proof roots required to verify the handoff without re-running projection.
    pub proof_roots: BTreeSet<ContentDigest>,
}

impl ReferenceSituation {
    /// Revalidates the capsule and returns its deterministic decision fingerprint.
    pub fn verify(&self) -> Result<ContentDigest, ReferenceError> {
        self.capsule.validate()?;
        if self.proof_roots.is_empty() {
            return Err(fss_core::ContractError::IncompletePublicationGraph.into());
        }
        Ok(self.capsule.decision_fingerprint()?)
    }
}

/// Compiles one deterministic, conservative situation projection from canonical reference state.
///
/// Rejected or indeterminate event candidates never become certified absence. A published
/// indeterminate external effect always retains its obligation and exposes reconciliation rather
/// than resend. Capability loss changes an affordance to `Unavailable`; it never removes the
/// protected possible worlds or the reason the action is unavailable.
pub fn compile_reference_situation(
    request: ReferenceSituationRequest<'_>,
    authority: &DurableReferenceLedger,
) -> Result<ReferenceSituation, ReferenceError> {
    let coverage_witness = request.coverage_witness;
    validate_request(&request, authority, coverage_witness)?;

    let current_anchor = authority.current().anchor.clone();
    let event_name = request.decision.event.event_id.as_str();
    let event_revision_digest = request.decision.event.revision_digest();
    let physical_claim_id = format!("claim:event:{event_name}:unknown-presence");
    let policy_claim_id = format!("claim:event:{event_name}:policy-disposition");
    let absence_claim_id = format!("claim:event:{event_name}:absence-certification");

    let supporting: Vec<_> = request
        .decision
        .event
        .evidence
        .iter()
        .filter(|edge| edge.supports)
        .map(|edge| edge.digest)
        .collect();
    let contradicting: Vec<_> = request
        .decision
        .event
        .evidence
        .iter()
        .filter(|edge| !edge.supports)
        .map(|edge| edge.digest)
        .collect();

    let mut proof_roots = BTreeSet::from([
        request.event_receipt.event_root,
        request.event_receipt.event_object_digest,
        event_revision_digest,
    ]);
    proof_roots.extend(request.decision.event.model_receipts.iter().copied());
    proof_roots.extend(
        request
            .decision
            .event
            .evidence
            .iter()
            .map(|edge| edge.digest),
    );
    if let Some(plan) = request.alert_plan {
        proof_roots.insert(plan.event_root);
        proof_roots.insert(plan.event_revision_digest);
        proof_roots.insert(plan.intent.request_digest);
        proof_roots.insert(plan.intent.precondition_digest);
    }
    if let Some(outcome) = request.alert_outcome {
        proof_roots.insert(outcome.outcome_root);
        proof_roots.insert(outcome.outcome_object_digest);
        proof_roots.insert(outcome.outcome.operation_object_digest);
        if let Some(proof) = outcome.outcome.proof_object_digest {
            proof_roots.insert(proof);
        }
    }

    let policy_cell = KnowledgeCell {
        claim_id: policy_claim_id.clone(),
        statement: policy_statement(request.decision.event.state, request.decision.action)
            .to_owned(),
        knowledge_state: KnowledgeState::Known,
        provenance: ProvenanceClass::Derived,
        hypothesis: Some(policy_hypothesis(request.decision.event.state)),
        evidence: vec![event_revision_digest, request.event_receipt.event_root],
        contradictions: Vec::new(),
        valid_until: None,
        state_basis: None,
    }
    .validated()?;
    let mut knowledge_cells = vec![policy_cell];
    let physical_state =
        physical_knowledge_state(request.decision.event.state, &supporting, &contradicting);
    knowledge_cells.push(
        KnowledgeCell {
            claim_id: physical_claim_id.clone(),
            statement: physical_statement(request.decision.event.state).to_owned(),
            knowledge_state: physical_state,
            provenance: ProvenanceClass::Derived,
            hypothesis: Some(policy_hypothesis(request.decision.event.state)),
            evidence: supporting.clone(),
            contradictions: contradicting.clone(),
            valid_until: None,
            state_basis: reconciliation_basis_for(physical_state, event_revision_digest),
        }
        .validated()?,
    );

    let mut coverage_proof_root = None;
    let (absence_certified, absence_non_pass_reason, absence_cell) = if request.decision.event.state
        == EventState::Rejected
    {
        if let Some(witness) = coverage_witness {
            let matches_anchor = witness.anchor == current_anchor;
            let matches_generation = witness.authorized_generation > 0
                && witness.authorized_generation == witness.observed_generation
                && witness.authorized_generation == current_anchor.policy_epoch;
            let expected_predicate = match request.decision.event.kind {
                EventKind::UnknownPresence => "no_unknown_person_present",
                EventKind::PerimeterBreach => "no_perimeter_breach",
                EventKind::CovertApproach => "no_covert_approach",
                EventKind::SensorTamper => "no_sensor_tamper",
                EventKind::BenignRoutine => "no_benign_routine",
                EventKind::Unclassified => "no_unclassified_event",
            };
            let matches_predicate = witness.negative_predicate == expected_predicate;

            let mut required_domains = BTreeSet::new();
            for ev in &request.decision.event.evidence {
                if !ev.failure_domain.is_empty() {
                    required_domains.insert(ev.failure_domain.clone());
                }
            }
            for zone in &request.decision.event.zone_ids {
                if !zone.is_empty() {
                    required_domains.insert(zone.clone());
                }
            }
            let covers_event_domains = !required_domains.is_empty()
                && required_domains.is_subset(&witness.authorized_domain);
            let matches_domain = covers_event_domains
                && !witness.authorized_domain.is_empty()
                && witness.authorized_domain == witness.observed_domain;

            if witness.certifies_absence()
                && matches_anchor
                && matches_generation
                && matches_predicate
                && matches_domain
            {
                coverage_proof_root = Some(witness.witness_digest());
                let statement = format!(
                    "Physical absence is certified across authorized domain {:?} at generation {}.",
                    witness.authorized_domain, witness.authorized_generation
                );
                (
                    true,
                    None,
                    Some(
                        KnowledgeCell {
                            claim_id: absence_claim_id.clone(),
                            statement,
                            knowledge_state: KnowledgeState::Known,
                            provenance: ProvenanceClass::Derived,
                            hypothesis: Some(HypothesisDisposition::Refuted),
                            evidence: vec![event_revision_digest, witness.witness_digest()],
                            contradictions: Vec::new(),
                            valid_until: None,
                            state_basis: None,
                        }
                        .validated()?,
                    ),
                )
            } else {
                let reason = if !matches_generation {
                    format!(
                        "coverage witness generation {} conflicts with observed generation {} (policy epoch {})",
                        witness.authorized_generation,
                        witness.observed_generation,
                        current_anchor.policy_epoch
                    )
                } else if !matches_anchor {
                    format!(
                        "coverage witness anchor ({:?}, epoch {}, commit {}) conflicts with current anchor ({:?}, epoch {}, commit {})",
                        witness.anchor.site_lineage,
                        witness.anchor.ledger_epoch,
                        witness.anchor.commit_sequence,
                        current_anchor.site_lineage,
                        current_anchor.ledger_epoch,
                        current_anchor.commit_sequence,
                    )
                } else if !matches_predicate {
                    format!(
                        "coverage witness negative predicate '{}' does not match expected predicate '{expected_predicate}' for {:?}",
                        witness.negative_predicate, request.decision.event.kind,
                    )
                } else if !covers_event_domains {
                    format!(
                        "coverage witness authorized domain {:?} does not cover required event domains {:?}",
                        witness.authorized_domain, required_domains
                    )
                } else if witness.continuity != CoverageContinuity::Continuous {
                    format!(
                        "coverage witness continuity is {:?} (expected Continuous) for domain {:?}",
                        witness.continuity, witness.authorized_domain
                    )
                } else if witness.completeness != Completeness::Complete {
                    format!(
                        "coverage witness completeness is {:?} (expected Complete) for domain {:?}",
                        witness.completeness, witness.authorized_domain
                    )
                } else if witness.stop_reason != CoverageStopReason::Complete {
                    format!(
                        "coverage witness stop reason is {:?} (expected Complete) for domain {:?}",
                        witness.stop_reason, witness.authorized_domain
                    )
                } else if witness.authorized_domain != witness.observed_domain {
                    format!(
                        "coverage witness observed domain {:?} does not match authorized domain {:?}",
                        witness.observed_domain, witness.authorized_domain
                    )
                } else {
                    format!(
                        "coverage witness does not certify absence for domain {:?}",
                        witness.authorized_domain
                    )
                };
                let statement = format!("Physical absence is not certified because {reason}.");
                (
                    false,
                    Some(reason),
                    Some(
                        KnowledgeCell {
                            claim_id: absence_claim_id.clone(),
                            statement,
                            knowledge_state: KnowledgeState::Unknown,
                            provenance: ProvenanceClass::Derived,
                            hypothesis: None,
                            evidence: vec![event_revision_digest],
                            contradictions: Vec::new(),
                            valid_until: None,
                            state_basis: None,
                        }
                        .validated()?,
                    ),
                )
            }
        } else {
            let reason =
                "no complete continuous CoverageWitness is present in this reference projection"
                    .to_owned();
            (
                false,
                Some(reason),
                Some(
                    KnowledgeCell {
                        claim_id: absence_claim_id.clone(),
                        statement: "Physical absence is not certified because no complete continuous CoverageWitness is present in this reference projection.".to_owned(),
                        knowledge_state: KnowledgeState::Unknown,
                        provenance: ProvenanceClass::Derived,
                        hypothesis: None,
                        evidence: vec![event_revision_digest],
                        contradictions: Vec::new(),
                        valid_until: None,
                        state_basis: None,
                    }
                    .validated()?,
                ),
            )
        }
    } else {
        (false, None, None)
    };

    if let Some(cell) = absence_cell {
        knowledge_cells.push(cell);
    }
    if let Some(digest) = coverage_proof_root {
        proof_roots.insert(digest);
    }

    if let Some(outcome) = request.alert_outcome {
        let operation = &outcome.outcome.operation_receipt;
        // A terminal outcome may be published as `known` only with its retained proof root
        // (KSTATE-001); without it the effect cell would carry no evidence (fss-deir9).
        if matches!(operation.state, EffectState::Verified | EffectState::Failed)
            && operation.result_digest.is_none()
        {
            return Err(ReferenceError::InvalidSpec("situation_effect_outcome"));
        }
        let (knowledge_state, statement) = match operation.state {
            EffectState::Verified => (
                KnowledgeState::Known,
                "Alert delivery is terminally verified by retained provider proof.",
            ),
            EffectState::Failed => (
                KnowledgeState::Known,
                "Alert delivery is terminally failed by retained non-delivery proof.",
            ),
            EffectState::Indeterminate => (
                KnowledgeState::Indeterminate,
                "Alert delivery may have occurred; the external effect requires reconciliation.",
            ),
            _ => return Err(ReferenceError::InvalidSpec("situation_effect_state")),
        };
        knowledge_cells.push(
            KnowledgeCell {
                claim_id: format!(
                    "claim:effect:{}:outcome",
                    operation.intent.operation_id.as_str()
                ),
                statement: statement.to_owned(),
                knowledge_state,
                provenance: ProvenanceClass::Observed,
                hypothesis: None,
                evidence: operation.result_digest.into_iter().collect(),
                contradictions: Vec::new(),
                valid_until: None,
                state_basis: reconciliation_basis_for(knowledge_state, operation.receipt_digest()),
            }
            .validated()?,
        );
    }

    let (world_envelope, mut unknown, mut at_risk) = compile_worlds(WorldCompilationParams {
        anchor: &current_anchor,
        objective_id: &request.objective_id,
        decision: request.decision,
        event_receipt: request.event_receipt,
        physical_claim_id: &physical_claim_id,
        policy_claim_id: &policy_claim_id,
        absence_claim_id: &absence_claim_id,
        absence_certified,
        absence_non_pass_reason: absence_non_pass_reason.as_deref(),
    });
    let retained_worlds = world_envelope.world_ids();
    let presence_world = format!("world:event:{event_name}:present");
    let alert_supported_worlds = BTreeSet::from([presence_world.clone()]);
    let alert_unsafe_worlds: BTreeSet<String> = retained_worlds
        .iter()
        .filter(|w| *w != &presence_world)
        .cloned()
        .collect();
    let mut obligations = Vec::new();
    let mut affordances = Vec::new();

    match (
        request.decision.action,
        request.alert_plan,
        request.alert_outcome,
    ) {
        (ReferencePolicyAction::PrepareAlert, None, None) => {
            affordances.push(project_affordance(ProjectAffordanceSpec {
                affordance_id: "affordance:alert:prepare",
                operation: "plan",
                target: &format!("fss://event/{event_name}/alert"),
                rationale: "Prepare an idempotent alert effect from the corroborated canonical event.",
                available_class: AffordanceClass::Conditional,
                supported_worlds: alert_supported_worlds.clone(),
                unsafe_worlds: alert_unsafe_worlds.clone(),
                branch_predicate: Some(presence_world.clone()),
                required_capability: CAPABILITY_ALERT_PREPARE,
                cost: alert_prepare_cost()?,
                reversible: true,
                available_capabilities: &request.available_capabilities,
            }));
        }
        (ReferencePolicyAction::PrepareAlert, Some(plan), None) => {
            obligations.push(plan.obligation_id.clone());
            at_risk.push(format!(
                "Effect {} has a prepared terminal-proof obligation but no canonical outcome publication.",
                plan.intent.operation_id.as_str()
            ));
            affordances.push(project_affordance(ProjectAffordanceSpec {
                affordance_id: "affordance:alert:commit",
                operation: "commit",
                target: &format!("fss://operation/{}", plan.intent.operation_id.as_str()),
                rationale: "Commit the exact prepared alert intent; do not substitute a new request or idempotency key.",
                available_class: AffordanceClass::Conditional,
                supported_worlds: alert_supported_worlds.clone(),
                unsafe_worlds: alert_unsafe_worlds.clone(),
                branch_predicate: Some(presence_world.clone()),
                required_capability: CAPABILITY_ALERT_COMMIT,
                cost: alert_commit_cost()?,
                reversible: false,
                available_capabilities: &request.available_capabilities,
            }));
        }
        (ReferencePolicyAction::PrepareAlert, Some(_), Some(outcome)) => {
            match outcome.outcome.operation_receipt.state {
                EffectState::Indeterminate => {
                    obligations.push(outcome.outcome.obligation_id.clone());
                    unknown.push("The provider-side alert outcome is unresolved; delivery and non-delivery both remain live until independently reconciled.".to_owned());
                    at_risk.push(format!(
                        "Operation {} is indeterminate and must not be blindly resent.",
                        outcome
                            .outcome
                            .operation_receipt
                            .intent
                            .operation_id
                            .as_str()
                    ));
                    affordances.push(project_affordance(ProjectAffordanceSpec {
                        affordance_id: "affordance:alert:reconcile",
                        operation: "investigate",
                        target: &format!(
                            "fss://operation/{}/reconcile",
                            outcome.outcome.operation_receipt.intent.operation_id.as_str()
                        ),
                        rationale: "Read independent provider state and reconcile the existing effect without resending it.",
                        available_class: AffordanceClass::Probe,
                        supported_worlds: retained_worlds.clone(),
                        unsafe_worlds: BTreeSet::new(),
                        branch_predicate: None,
                        required_capability: CAPABILITY_EFFECT_RECONCILE,
                        cost: reconcile_cost()?,
                        reversible: true,
                        available_capabilities: &request.available_capabilities,
                    }));
                }
                EffectState::Failed => {
                    at_risk.push("The prior alert attempt is proved failed; a new effect requires a new witnessed plan and idempotency identity.".to_owned());
                    affordances.push(project_affordance(ProjectAffordanceSpec {
                        affordance_id: "affordance:alert:replan",
                        operation: "plan",
                        target: &format!("fss://event/{event_name}/alert"),
                        rationale: "Prepare a new alert operation only after reviewing the retained failure proof.",
                        available_class: AffordanceClass::Conditional,
                        supported_worlds: alert_supported_worlds.clone(),
                        unsafe_worlds: alert_unsafe_worlds.clone(),
                        branch_predicate: Some(presence_world.clone()),
                        required_capability: CAPABILITY_ALERT_PREPARE,
                        cost: alert_prepare_cost()?,
                        reversible: true,
                        available_capabilities: &request.available_capabilities,
                    }));
                }
                EffectState::Verified => {
                    affordances.push(project_affordance(ProjectAffordanceSpec {
                        affordance_id: "affordance:event:monitor",
                        operation: "wait",
                        target: &format!("fss://event/{event_name}"),
                        rationale: "Wait for a meaningful evidence or effect-state delta; the alert obligation is terminal.",
                        available_class: AffordanceClass::Wait,
                        supported_worlds: retained_worlds.clone(),
                        unsafe_worlds: BTreeSet::new(),
                        branch_predicate: None,
                        required_capability: CAPABILITY_SESSION_WAIT,
                        cost: wait_cost()?,
                        reversible: true,
                        available_capabilities: &request.available_capabilities,
                    }));
                }
                _ => return Err(ReferenceError::InvalidSpec("situation_effect_state")),
            }
        }
        (ReferencePolicyAction::Hold, None, None) => {
            affordances.push(project_affordance(ProjectAffordanceSpec {
                affordance_id: "affordance:event:investigate",
                operation: "investigate",
                target: &format!("fss://event/{event_name}/evidence"),
                rationale: "Acquire or inspect evidence that can distinguish the retained possible worlds.",
                available_class: AffordanceClass::Probe,
                supported_worlds: retained_worlds.clone(),
                unsafe_worlds: BTreeSet::new(),
                branch_predicate: None,
                required_capability: CAPABILITY_EVIDENCE_QUERY,
                cost: investigate_cost()?,
                reversible: true,
                available_capabilities: &request.available_capabilities,
            }));
            affordances.push(project_affordance(ProjectAffordanceSpec {
                affordance_id: "affordance:event:wait",
                operation: "wait",
                target: &format!("fss://event/{event_name}"),
                rationale: "Wait for a meaningful event or coverage delta while preserving every protected world.",
                available_class: AffordanceClass::Wait,
                supported_worlds: retained_worlds.clone(),
                unsafe_worlds: BTreeSet::new(),
                branch_predicate: None,
                required_capability: CAPABILITY_SESSION_WAIT,
                cost: wait_cost()?,
                reversible: true,
                available_capabilities: &request.available_capabilities,
            }));
            affordances.push(ActionAffordance {
                affordance_id: "affordance:alert:prepare".to_owned(),
                operation: "plan".to_owned(),
                target: format!("fss://event/{event_name}/alert"),
                rationale: "Alert preparation is blocked by Hold policy decision; uncorroborated evidence cannot trigger side-effects.".to_owned(),
                class: AffordanceClass::Blocked,
                supported_worlds: BTreeSet::new(),
                unsafe_worlds: retained_worlds,
                required_capabilities: BTreeSet::from([CAPABILITY_ALERT_PREPARE.to_owned()]),
                cost: alert_prepare_cost()?,
                reversible: true,
                branch_predicate: None,
            });
        }
        _ => return Err(ReferenceError::InvalidSpec("situation_effect_basis")),
    }

    affordances.sort_by(|left, right| left.affordance_id.cmp(&right.affordance_id));
    obligations.sort();
    obligations.dedup();
    let next: Vec<_> = affordances
        .iter()
        .filter(|affordance| {
            affordance.class != AffordanceClass::Unavailable
                && affordance.class != AffordanceClass::Blocked
        })
        .map(|affordance| affordance.affordance_id.clone())
        .collect();

    let identity = situation_identity(
        &request,
        &current_anchor,
        &world_envelope,
        &knowledge_cells,
        &obligations,
        &affordances,
    );
    let now = vec![format!(
        "Event {} is {} at authority commit {}.",
        event_name,
        request.decision.event.state.as_str(),
        current_anchor.commit_sequence
    )];
    let changed = match &request.previous_anchor {
        Some(previous) => vec![format!(
            "Authority advanced from commit {} to commit {} within ledger epoch {}.",
            previous.commit_sequence, current_anchor.commit_sequence, current_anchor.ledger_epoch
        )],
        None => vec![format!(
            "Initial situation projection at authority commit {}.",
            current_anchor.commit_sequence
        )],
    };
    let why = vec![format!(
        "The projection is bound to event revision {} and decision path {}.",
        event_revision_digest, request.decision.event.decision_path
    )];
    let evidence_handles = proof_roots
        .iter()
        .map(|digest| format!("fss://proof/{digest}"))
        .collect();
    let completeness = if request.decision.event.state == EventState::Corroborated
        && request.alert_outcome.is_none_or(|outcome| {
            outcome.outcome.operation_receipt.state != EffectState::Indeterminate
        })
        && affordances.iter().all(|affordance| {
            affordance.class != AffordanceClass::Unavailable
                && affordance.class != AffordanceClass::Blocked
        }) {
        Completeness::Bounded
    } else {
        Completeness::Partial
    };
    let frame = SituationFrame {
        frame_id: format!("frame:{identity}"),
        objective_id: request.objective_id.clone(),
        anchor: current_anchor.clone(),
        world_envelope,
        knowledge_cells,
        now,
        changed,
        why,
        unknown,
        at_risk,
        next,
        evidence_handles,
    };
    let capsule = SituationCapsule {
        capsule_id: format!("situation:{identity}"),
        revision: request.revision,
        contract_basis: request.contract_basis,
        mission_id: request.mission_id,
        session_id: request.session_id,
        principal_id: request.principal_id,
        anchor: current_anchor,
        previous_anchor: request.previous_anchor,
        frame,
        obligations,
        affordances,
        completeness,
        created_at: request.created_at,
        mission_state: None,
    };
    capsule.validate()?;
    Ok(ReferenceSituation {
        capsule,
        proof_roots,
    })
}

/// Seals a root-closed handoff from a verified reference situation.
pub fn seal_reference_handoff(
    situation: &ReferenceSituation,
    handoff_id: HandoffId,
    created_at: TimestampNs,
    expires_at: TimestampNs,
) -> Result<HandoffCapsule, ReferenceError> {
    let situation_root = situation.verify()?;
    let handoff = HandoffCapsule::publish(HandoffPublishParams {
        handoff_id,
        mission_id: situation.capsule.mission_id.clone(),
        source_session_id: situation.capsule.session_id.clone(),
        source_principal_id: situation.capsule.principal_id.clone(),
        anchor: situation.capsule.anchor.clone(),
        situation_capsule_root: situation_root,
        child_roots: situation.proof_roots.iter().copied(),
        contract_basis: situation.capsule.contract_basis.clone(),
        created_at,
        expires_at,
    })?;
    handoff.verify()?;
    Ok(handoff)
}

fn validate_request(
    request: &ReferenceSituationRequest<'_>,
    authority: &DurableReferenceLedger,
    coverage_witness: Option<&CoverageWitness>,
) -> Result<(), ReferenceError> {
    if request.objective_id.is_empty()
        || request.objective_id.len() > MAX_OBJECTIVE_BYTES
        || request.revision == 0
        || request.contract_basis.semantic_protocol != "fss/1"
    {
        return Err(ReferenceError::InvalidSpec("situation_request"));
    }
    if coverage_witness.is_some() && request.decision.event.state != EventState::Rejected {
        return Err(ReferenceError::InvalidSpec(
            "situation_coverage_witness_for_non_rejected_event",
        ));
    }
    request.decision.event.validate()?;
    let expected_action = if request.decision.event.state == EventState::Corroborated {
        ReferencePolicyAction::PrepareAlert
    } else {
        ReferencePolicyAction::Hold
    };
    if request.decision.action != expected_action {
        return Err(ReferenceError::InvalidSpec("situation_policy_action"));
    }
    if request.event_receipt.event_revision_digest != request.decision.event.revision_digest() {
        return Err(ReferenceError::InvalidSpec("situation_event_receipt"));
    }
    let current = &authority.current().anchor;
    if request.event_receipt.authority_anchor.site_lineage != current.site_lineage
        || request.event_receipt.authority_anchor.ledger_epoch != current.ledger_epoch
        || request.event_receipt.authority_anchor.commit_sequence > current.commit_sequence
    {
        return Err(fss_core::ContractError::StaleAnchor.into());
    }
    let event_is_published = authority.batches().iter().any(|batch| {
        batch.new_anchor == request.event_receipt.authority_anchor
            && batch.deltas.iter().any(|delta| {
                delta.family == "event_revision"
                    && delta.payload_digest == request.event_receipt.event_root
                    && delta.witness_digest == Some(request.event_receipt.event_revision_digest)
            })
    });
    if !event_is_published {
        return Err(ReferenceError::InvalidSpec("situation_event_basis"));
    }
    if let Some(previous) = &request.previous_anchor {
        let genesis = LedgerAnchor::genesis(current.site_lineage.clone());
        let previous_exists = previous == &genesis
            || authority
                .batches()
                .iter()
                .any(|batch| &batch.new_anchor == previous);
        if previous.site_lineage != current.site_lineage
            || previous.ledger_epoch != current.ledger_epoch
            || previous.commit_sequence >= current.commit_sequence
            || !previous_exists
        {
            return Err(fss_core::ContractError::StaleAnchor.into());
        }
    }

    match (request.alert_plan, request.alert_outcome) {
        (None, Some(_)) => return Err(ReferenceError::InvalidSpec("situation_effect_basis")),
        (Some(plan), outcome) => {
            validate_reference_alert_plan(plan)?;
            if request.decision.action != ReferencePolicyAction::PrepareAlert
                || plan.event_root != request.event_receipt.event_root
                || plan.event_revision_digest != request.event_receipt.event_revision_digest
            {
                return Err(ReferenceError::InvalidSpec("situation_effect_basis"));
            }
            let effect_object_id = ObjectId::parse(format!(
                "object:effect:{}",
                plan.intent.operation_id.as_str()
            ))?;
            match outcome {
                Some(outcome) => {
                    if outcome.authority_anchor != *current
                        || outcome.effect_object_id.as_str() != effect_object_id.as_str()
                        || outcome.outcome.operation_receipt.intent != plan.intent
                        || outcome.outcome.obligation_id.as_str() != plan.obligation_id.as_str()
                        || outcome.outcome.event_root != plan.event_root
                        || outcome.outcome.event_revision_digest != plan.event_revision_digest
                        || outcome.outcome.channel != plan.channel
                    {
                        return Err(ReferenceError::InvalidSpec("situation_effect_outcome"));
                    }
                    let current_effect = authority
                        .current()
                        .objects
                        .get(&effect_object_id)
                        .ok_or(ReferenceError::InvalidSpec("situation_effect_outcome"))?;
                    if current_effect.generation != outcome.effect_generation
                        || current_effect.payload_digest != outcome.outcome_root
                    {
                        return Err(ReferenceError::InvalidSpec("situation_effect_outcome"));
                    }
                }
                None if authority.current().objects.contains_key(&effect_object_id) => {
                    return Err(ReferenceError::InvalidSpec(
                        "situation_effect_outcome_omitted",
                    ));
                }
                None => {}
            }
        }
        (None, None) => {}
    }
    Ok(())
}

struct WorldCompilationParams<'a> {
    anchor: &'a LedgerAnchor,
    objective_id: &'a str,
    decision: &'a ReferencePolicyDecision,
    event_receipt: &'a ReferenceEventReceipt,
    physical_claim_id: &'a str,
    policy_claim_id: &'a str,
    absence_claim_id: &'a str,
    absence_certified: bool,
    absence_non_pass_reason: Option<&'a str>,
}

fn compile_worlds(params: WorldCompilationParams<'_>) -> (WorldEnvelope, Vec<String>, Vec<String>) {
    let event_name = params.decision.event.event_id.as_str();
    let event_evidence: Vec<_> = params
        .decision
        .event
        .evidence
        .iter()
        .map(|edge| edge.digest)
        .collect();
    let policy_evidence = vec![
        params.event_receipt.event_root,
        params.event_receipt.event_revision_digest,
    ];
    let mut alternatives = Vec::new();
    let mut residuals = Vec::new();
    let mut nominal_claim_ids = BTreeSet::from([params.policy_claim_id.to_owned()]);
    let mut certified_core_claim_ids = BTreeSet::from([params.policy_claim_id.to_owned()]);
    let mut unknown = Vec::new();
    let mut at_risk = Vec::new();

    match params.decision.event.state {
        EventState::Corroborated => {
            nominal_claim_ids.insert(params.physical_claim_id.to_owned());
            certified_core_claim_ids.insert(params.physical_claim_id.to_owned());
            alternatives.push(PossibleWorld {
                world_id: format!("world:event:{event_name}:present"),
                description: "The independently corroborated unknown-presence event is physically present within the retained interval.".to_owned(),
                claim_ids: BTreeSet::from([
                    params.policy_claim_id.to_owned(),
                    params.physical_claim_id.to_owned(),
                ]),
                evidence: event_evidence,
                consequence_severity: 5,
                protected: true,
            });
            residuals.push(PossibleWorld {
                world_id: format!("world:event:{event_name}:spoofing-or-simultaneous-error"),
                description: "Independent sensor sources are compromised by common-mode spoofing, simultaneous failure, or shared environmental artifact.".to_owned(),
                claim_ids: BTreeSet::from([params.policy_claim_id.to_owned()]),
                evidence: policy_evidence.clone(),
                consequence_severity: 4,
                protected: true,
            });
        }
        EventState::Witnessed => {
            nominal_claim_ids.insert(params.physical_claim_id.to_owned());
            alternatives.push(PossibleWorld {
                world_id: format!("world:event:{event_name}:present-single-domain"),
                description: "The unknown-presence event is real, but current support comes from only one failure domain.".to_owned(),
                claim_ids: BTreeSet::from([
                    params.policy_claim_id.to_owned(),
                    params.physical_claim_id.to_owned(),
                ]),
                evidence: event_evidence.clone(),
                consequence_severity: 5,
                protected: true,
            });
            residuals.push(PossibleWorld {
                world_id: format!("world:event:{event_name}:benign-or-error"),
                description: "The single-domain finding is benign, erroneous, or otherwise insufficient for an alert effect.".to_owned(),
                claim_ids: BTreeSet::from([params.policy_claim_id.to_owned()]),
                evidence: policy_evidence.clone(),
                consequence_severity: 4,
                protected: true,
            });
            unknown.push("Independent corroboration is absent; presence and benign/error worlds remain live.".to_owned());
        }
        EventState::Indeterminate => {
            alternatives.push(PossibleWorld {
                world_id: format!("world:event:{event_name}:presence-live"),
                description: "Unknown-person presence remains physically possible under the retained evidence.".to_owned(),
                claim_ids: BTreeSet::from([
                    params.policy_claim_id.to_owned(),
                    params.physical_claim_id.to_owned(),
                ]),
                evidence: event_evidence.clone(),
                consequence_severity: 5,
                protected: true,
            });
            alternatives.push(PossibleWorld {
                world_id: format!("world:event:{event_name}:unmitigated-exposure"),
                description: "Unmitigated consequence exposure remains possible under indeterminate evidence.".to_owned(),
                claim_ids: BTreeSet::from([params.policy_claim_id.to_owned()]),
                evidence: policy_evidence.clone(),
                consequence_severity: 4,
                protected: false,
            });
            residuals.push(PossibleWorld {
                world_id: format!("world:event:{event_name}:non-presence-live"),
                description: "A benign, contradictory, degraded, or otherwise non-presence explanation remains possible.".to_owned(),
                claim_ids: BTreeSet::from([params.policy_claim_id.to_owned()]),
                evidence: policy_evidence.clone(),
                consequence_severity: 4,
                protected: true,
            });
            unknown.push("The event remains indeterminate; contradictory, degraded, or incomplete evidence cannot be compressed away.".to_owned());
            at_risk.push("An alert effect is blocked until policy reaches independent corroboration or an explicit exception proof.".to_owned());
        }
        EventState::Rejected => {
            alternatives.push(PossibleWorld {
                world_id: format!("world:event:{event_name}:candidate-rejected"),
                description: "The retained event candidate is rejected by the reference policy within the evaluated evidence.".to_owned(),
                claim_ids: BTreeSet::from([params.policy_claim_id.to_owned()]),
                evidence: policy_evidence.clone(),
                consequence_severity: 1,
                protected: false,
            });
            if params.absence_certified {
                nominal_claim_ids.insert(params.absence_claim_id.to_owned());
                certified_core_claim_ids.insert(params.absence_claim_id.to_owned());
            } else {
                residuals.push(PossibleWorld {
                    world_id: format!("world:event:{event_name}:absence-uncertified"),
                    description: "Physical presence outside the evaluated evidence remains possible because no complete continuous coverage witness certifies absence.".to_owned(),
                    claim_ids: BTreeSet::from([
                        params.policy_claim_id.to_owned(),
                        params.absence_claim_id.to_owned(),
                    ]),
                    evidence: policy_evidence.clone(),
                    consequence_severity: 5,
                    protected: true,
                });
                let detail = params.absence_non_pass_reason.unwrap_or("no complete continuous CoverageWitness is present in this reference projection");
                unknown.push(format!(
                    "Policy rejection is not a certified negative read; physical absence remains unproved without a valid CoverageWitness over the authorized domain and generation ({detail})."
                ));
            }
        }
        // Candidate, policy, delivery, and resolution stages carry no stronger physical reading.
        EventState::Hypothesized
        | EventState::Adjudicated
        | EventState::AlertDelivered
        | EventState::Resolved => {
            alternatives.push(PossibleWorld {
                world_id: format!("world:event:{event_name}:policy-state"),
                description: "The current event state is retained without promoting it to physical certainty.".to_owned(),
                claim_ids: BTreeSet::from([params.policy_claim_id.to_owned()]),
                evidence: policy_evidence.clone(),
                consequence_severity: 3,
                protected: true,
            });
            unknown.push(
                "The event lifecycle state has no stronger reference-world interpretation."
                    .to_owned(),
            );
        }
    }

    let identity = world_identity(
        params.anchor,
        params.objective_id,
        params.decision,
        &alternatives,
        &residuals,
    );
    (
        WorldEnvelope {
            envelope_id: format!("world-envelope:{identity}"),
            objective_id: params.objective_id.to_owned(),
            anchor: params.anchor.clone(),
            nominal_claim_ids,
            certified_core_claim_ids,
            alternatives,
            adversarial_residuals: residuals,
            common_invariants: BTreeSet::from([
                "invariant:evidence-provenance-retained".to_owned(),
                "invariant:no-alert-authority-from-model-output-alone".to_owned(),
            ]),
            coverage_boundary_handles: BTreeSet::from([format!(
                "fss://event/{event_name}/coverage"
            )]),
        },
        unknown,
        at_risk,
    )
}

struct ProjectAffordanceSpec<'a> {
    affordance_id: &'a str,
    operation: &'a str,
    target: &'a str,
    rationale: &'a str,
    available_class: AffordanceClass,
    supported_worlds: BTreeSet<String>,
    unsafe_worlds: BTreeSet<String>,
    branch_predicate: Option<String>,
    required_capability: &'a str,
    cost: BudgetVector,
    reversible: bool,
    available_capabilities: &'a BTreeSet<String>,
}

fn project_affordance(spec: ProjectAffordanceSpec<'_>) -> ActionAffordance {
    let available = spec
        .available_capabilities
        .contains(spec.required_capability);
    ActionAffordance {
        affordance_id: spec.affordance_id.to_owned(),
        operation: spec.operation.to_owned(),
        target: spec.target.to_owned(),
        rationale: if available {
            spec.rationale.to_owned()
        } else {
            format!(
                "{} Required capability {} is not delegated.",
                spec.rationale, spec.required_capability
            )
        },
        class: if available {
            spec.available_class
        } else {
            AffordanceClass::Unavailable
        },
        supported_worlds: if available {
            spec.supported_worlds
        } else {
            BTreeSet::new()
        },
        unsafe_worlds: spec.unsafe_worlds,
        required_capabilities: BTreeSet::from([spec.required_capability.to_owned()]),
        cost: spec.cost,
        reversible: spec.reversible,
        branch_predicate: spec.branch_predicate,
    }
}

fn situation_identity(
    request: &ReferenceSituationRequest<'_>,
    anchor: &LedgerAnchor,
    worlds: &WorldEnvelope,
    knowledge: &[KnowledgeCell],
    obligations: &[ObligationId],
    affordances: &[ActionAffordance],
) -> ContentDigest {
    let mut encoder = CanonicalEncoder::new();
    encoder.text("fss.reference_situation_compilation.v1");
    request.mission_id.encode_canonical(&mut encoder);
    request.session_id.encode_canonical(&mut encoder);
    request.principal_id.encode_canonical(&mut encoder);
    encoder.text(&request.objective_id);
    encoder.u64(request.revision);
    encoder.digest(request.contract_basis.basis_digest());
    anchor.encode_canonical(&mut encoder);
    match &request.previous_anchor {
        Some(previous) => {
            encoder.bool(true);
            previous.encode_canonical(&mut encoder);
        }
        None => encoder.bool(false),
    }
    encoder.digest(worlds.envelope_digest());
    let mut cells = knowledge.to_vec();
    cells.sort_by(|left, right| left.claim_id.cmp(&right.claim_id));
    encoder.u64(cells.len() as u64);
    for cell in &cells {
        encoder.digest(cell.cell_digest());
    }
    let mut obligation_ids = obligations.to_vec();
    obligation_ids.sort();
    encoder.u64(obligation_ids.len() as u64);
    for obligation in &obligation_ids {
        obligation.encode_canonical(&mut encoder);
    }
    let mut projected = affordances.to_vec();
    projected.sort_by(|left, right| left.affordance_id.cmp(&right.affordance_id));
    encoder.u64(projected.len() as u64);
    for affordance in &projected {
        affordance.encode_canonical(&mut encoder);
    }
    request.created_at.encode_canonical(&mut encoder);
    ContentDigest::sha256(&encoder.finish())
}

fn world_identity(
    anchor: &LedgerAnchor,
    objective_id: &str,
    decision: &ReferencePolicyDecision,
    alternatives: &[PossibleWorld],
    residuals: &[PossibleWorld],
) -> ContentDigest {
    let mut encoder = CanonicalEncoder::new();
    encoder.text("fss.reference_world_compilation.v1");
    anchor.encode_canonical(&mut encoder);
    encoder.text(objective_id);
    encoder.digest(decision.event.revision_digest());
    let mut alternatives = alternatives.to_vec();
    alternatives.sort_by(|left, right| left.world_id.cmp(&right.world_id));
    encoder.u64(alternatives.len() as u64);
    for world in &alternatives {
        world.encode_canonical(&mut encoder);
    }
    let mut residuals = residuals.to_vec();
    residuals.sort_by(|left, right| left.world_id.cmp(&right.world_id));
    encoder.u64(residuals.len() as u64);
    for world in &residuals {
        world.encode_canonical(&mut encoder);
    }
    ContentDigest::sha256(&encoder.finish())
}

pub(crate) fn policy_statement(state: EventState, action: ReferencePolicyAction) -> &'static str {
    match (state, action) {
        (EventState::Corroborated, ReferencePolicyAction::PrepareAlert) => {
            "The reference policy independently corroborated unknown-person presence and exposed alert preparation as a separate affordance."
        }
        (EventState::Witnessed, ReferencePolicyAction::Hold) => {
            "The reference policy retained a witnessed candidate but withheld alert preparation pending independent corroboration."
        }
        (EventState::Indeterminate, ReferencePolicyAction::Hold) => {
            "The reference policy retained an indeterminate candidate and withheld alert preparation."
        }
        (EventState::Rejected, ReferencePolicyAction::Hold) => {
            "The reference policy rejected this event candidate without asserting complete physical absence."
        }
        // Every other pairing grants no effect authority; `Indeterminate` never prepares an alert.
        (EventState::Corroborated, ReferencePolicyAction::Hold)
        | (
            EventState::Witnessed | EventState::Indeterminate | EventState::Rejected,
            ReferencePolicyAction::PrepareAlert,
        )
        | (
            EventState::Hypothesized
            | EventState::Adjudicated
            | EventState::AlertDelivered
            | EventState::Resolved,
            ReferencePolicyAction::Hold | ReferencePolicyAction::PrepareAlert,
        ) => {
            "The reference policy retained the event lifecycle state without granting effect authority."
        }
    }
}

/// Reconciliation basis for an `indeterminate` cell whose unresolved outcome is rooted at `root`.
fn reconciliation_basis_for(
    state: KnowledgeState,
    root: ContentDigest,
) -> Option<KnowledgeStateBasis> {
    (state == KnowledgeState::Indeterminate)
        .then(|| KnowledgeStateBasis::Reconciliation(ReconciliationBasis::occurred_or_not(root)))
}

/// Maps an event lifecycle state onto the knowledge state of the physical-presence claim.
///
/// The match is exhaustive on purpose: a new `EventState` must choose its knowledge state here
/// instead of inheriting one. Lifecycle stages after corroboration record policy, delivery, or
/// resolution progress; those are dispositions and effect outcomes, not physical evidence, so
/// they never upgrade the physical proposition (`docs/AGENT_OPERATING_MODEL.md` §6). `estimated`
/// (KSTATE-002) requires a supporting derivation, so a stage with no retained supporting roots is
/// `unknown` (KSTATE-003) rather than estimated. Retained evidence that points both ways is an
/// unresolved contradiction: the model has no typed adjudication basis that could retire it, so a
/// post-corroboration stage keeps it `conflicted` exactly as `indeterminate` does, instead of
/// flattening it to `estimated` while the cell still carries the contradicting roots.
pub(crate) fn physical_knowledge_state(
    state: EventState,
    supporting: &[ContentDigest],
    contradicting: &[ContentDigest],
) -> KnowledgeState {
    let unresolved_conflict = !supporting.is_empty() && !contradicting.is_empty();
    let post_corroboration = if unresolved_conflict {
        KnowledgeState::Conflicted
    } else if supporting.is_empty() {
        KnowledgeState::Unknown
    } else {
        KnowledgeState::Estimated
    };
    match state {
        // Detector/rule candidate with no retained observation witness: nothing yet supports the
        // proposition, so it is unknown; support edges without a witness transition do not count.
        EventState::Hypothesized => KnowledgeState::Unknown,
        // One retained observation witness without independent corroboration.
        EventState::Witnessed => KnowledgeState::Estimated,
        // Independent failure domains (or an explicit exception proof) establish presence.
        EventState::Corroborated => KnowledgeState::Known,
        // Policy selected a disposition. Adjudication is also reachable through an urgent
        // single-sensor exception or policy reconciliation from indeterminate, so it cannot imply
        // corroboration: at most estimated from retained support, and conflicted while retained
        // contradicting roots remain unresolved.
        EventState::Adjudicated => post_corroboration,
        // A durable delivery receipt proves the alert effect, not the physical event.
        EventState::AlertDelivered => post_corroboration,
        // Resolution is a disposition; it neither confirms nor refutes physical presence.
        EventState::Resolved => post_corroboration,
        // Unresolved: conflicted when retained evidence points both ways, else indeterminate.
        EventState::Indeterminate => {
            if unresolved_conflict {
                KnowledgeState::Conflicted
            } else {
                KnowledgeState::Indeterminate
            }
        }
        // Rejection refutes the candidate but does not certify physical absence.
        EventState::Rejected => KnowledgeState::Unknown,
    }
}

pub(crate) fn physical_statement(state: EventState) -> &'static str {
    match state {
        EventState::Corroborated => {
            "Independent failure domains support unknown-person presence in the retained interval."
        }
        EventState::Witnessed => {
            "Unknown-person presence is supported by retained evidence but lacks independent corroboration."
        }
        EventState::Indeterminate => {
            "Unknown-person presence remains unresolved under retained supporting, contradictory, or degraded evidence."
        }
        EventState::Rejected => {
            "The event candidate is rejected, but physical absence is not certified by this policy result."
        }
        // Candidate, policy, delivery, and resolution stages are not physical evidence.
        EventState::Hypothesized
        | EventState::Adjudicated
        | EventState::AlertDelivered
        | EventState::Resolved => {
            "The physical event interpretation remains bounded by the retained lifecycle state."
        }
    }
}

pub(crate) fn policy_hypothesis(state: EventState) -> HypothesisDisposition {
    match state {
        // A detector/rule candidate with no retained witness is possible but not yet supported.
        EventState::Hypothesized => HypothesisDisposition::Live,
        EventState::Witnessed => HypothesisDisposition::Supported,
        EventState::Corroborated => HypothesisDisposition::Supported,
        // Adjudication may rest on an urgent single-sensor exception, so it claims no more support.
        EventState::Adjudicated => HypothesisDisposition::Live,
        // A delivery receipt proves the alert effect, not the physical hypothesis.
        EventState::AlertDelivered => HypothesisDisposition::Live,
        EventState::Resolved => HypothesisDisposition::Resolved,
        // Unresolved evidence neither supports nor disfavors it: only `live` keeps it fully open.
        EventState::Indeterminate => HypothesisDisposition::Live,
        EventState::Rejected => HypothesisDisposition::Refuted,
    }
}

fn alert_prepare_cost() -> Result<BudgetVector, ReferenceError> {
    BudgetVector::builder()
        .latency_ms(10)
        .bytes(2_048)
        .cpu_millis(5)
        .storage_operations(2)
        .operator_attention_seconds(1.0)
        .build()
        .map_err(|_| ReferenceError::InvalidSpec("alert_prepare_cost"))
}

fn alert_commit_cost() -> Result<BudgetVector, ReferenceError> {
    BudgetVector::builder()
        .latency_ms(5_000)
        .bytes(4_096)
        .network_bytes(4_096)
        .storage_operations(4)
        .privacy_exposure(1.0)
        .operator_attention_seconds(2.0)
        .build()
        .map_err(|_| ReferenceError::InvalidSpec("alert_commit_cost"))
}

fn reconcile_cost() -> Result<BudgetVector, ReferenceError> {
    BudgetVector::builder()
        .latency_ms(2_000)
        .bytes(2_048)
        .network_bytes(2_048)
        .storage_operations(2)
        .operator_attention_seconds(1.0)
        .build()
        .map_err(|_| ReferenceError::InvalidSpec("reconcile_cost"))
}

fn investigate_cost() -> Result<BudgetVector, ReferenceError> {
    BudgetVector::builder()
        .latency_ms(1_000)
        .bytes(16_384)
        .cpu_millis(50)
        .storage_operations(4)
        .privacy_exposure(0.25)
        .operator_attention_seconds(1.0)
        .build()
        .map_err(|_| ReferenceError::InvalidSpec("investigate_cost"))
}

fn wait_cost() -> Result<BudgetVector, ReferenceError> {
    BudgetVector::builder()
        .latency_ms(60_000)
        .bytes(512)
        .storage_operations(1)
        .build()
        .map_err(|_| ReferenceError::InvalidSpec("wait_cost"))
}
