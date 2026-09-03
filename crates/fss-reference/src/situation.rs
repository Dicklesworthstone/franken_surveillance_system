//! Deterministic agent-facing projection of the reference evidence/effect spine.

use std::collections::BTreeSet;

use fss_core::{
    ActionAffordance, AffordanceClass, BudgetVector, CanonicalEncode, CanonicalEncoder,
    Completeness, ContentDigest, ContractBasis, EffectState, EventState, HandoffCapsule, HandoffId,
    HypothesisDisposition, KnowledgeCell, KnowledgeState, LedgerAnchor, MissionId, ObjectId,
    ObligationId, PossibleWorld, PrincipalId, ProvenanceClass, SessionId, SituationCapsule,
    SituationFrame, TimestampNs, WorldEnvelope,
};
use fss_ledger::DurableReferenceLedger;

use crate::{
    ReferenceAlertOutcomeReceipt, ReferenceAlertPlan, ReferenceError, ReferenceEventReceipt,
    ReferencePolicyAction, ReferencePolicyDecision,
    alert::validate_reference_alert_plan,
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
    /// Capabilities currently delegated to the principal.
    pub available_capabilities: BTreeSet<String>,
    /// Deterministic caller-supplied creation time.
    pub created_at: TimestampNs,
}

/// A compiled situation plus every proof root needed for a self-contained handoff.
#[derive(Clone, Debug, PartialEq)]
pub struct ReferenceSituation {
    /// Validated agent-facing situation capsule.
    pub capsule: SituationCapsule,
    /// Complete set of evidence, witness, plan, and outcome roots cited by the projection.
    pub proof_roots: BTreeSet<ContentDigest>,
}

impl ReferenceSituation {
    /// Revalidates the capsule and returns its deterministic decision fingerprint.
    pub fn verify(&self) -> Result<ContentDigest, ReferenceError> {
        self.capsule.validate()?;
        if self.proof_roots.is_empty() {
            return Err(fss_core::ContractError::IncompletePublicationGraph.into());
        }
        Ok(self.capsule.decision_fingerprint())
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
    validate_request(&request, authority)?;

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
    proof_roots.extend(request.decision.event.evidence.iter().map(|edge| edge.digest));
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
        statement: policy_statement(request.decision).to_owned(),
        knowledge_state: KnowledgeState::Known,
        provenance: ProvenanceClass::Derived,
        hypothesis: Some(policy_hypothesis(request.decision.event.state)),
        evidence: vec![event_revision_digest, request.event_receipt.event_root],
        contradictions: Vec::new(),
        valid_until: None,
    };
    let mut knowledge_cells = vec![policy_cell];
    let physical_state = match request.decision.event.state {
        EventState::Corroborated => KnowledgeState::Known,
        EventState::Witnessed => KnowledgeState::Estimated,
        EventState::Rejected => KnowledgeState::Unknown,
        EventState::Indeterminate => {
            if !supporting.is_empty() && !contradicting.is_empty() {
                KnowledgeState::Conflicted
            } else {
                KnowledgeState::Indeterminate
            }
        }
        _ => KnowledgeState::Estimated,
    };
    knowledge_cells.push(KnowledgeCell {
        claim_id: physical_claim_id.clone(),
        statement: physical_statement(request.decision.event.state).to_owned(),
        knowledge_state: physical_state,
        provenance: ProvenanceClass::Derived,
        hypothesis: Some(policy_hypothesis(request.decision.event.state)),
        evidence: supporting.clone(),
        contradictions: contradicting.clone(),
        valid_until: None,
    });
    if request.decision.event.state == EventState::Rejected {
        knowledge_cells.push(KnowledgeCell {
            claim_id: absence_claim_id.clone(),
            statement: "Physical absence is not certified because no complete continuous CoverageWitness is present in this reference projection.".to_owned(),
            knowledge_state: KnowledgeState::Unknown,
            provenance: ProvenanceClass::Derived,
            hypothesis: None,
            evidence: vec![event_revision_digest],
            contradictions: Vec::new(),
            valid_until: None,
        });
    }

    if let Some(outcome) = request.alert_outcome {
        let operation = &outcome.outcome.operation_receipt;
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
        knowledge_cells.push(KnowledgeCell {
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
        });
    }

    let (world_envelope, mut unknown, mut at_risk) = compile_worlds(
        &current_anchor,
        &request.objective_id,
        request.decision,
        request.event_receipt,
        &physical_claim_id,
        &policy_claim_id,
        &absence_claim_id,
    );
    let retained_worlds = world_envelope.world_ids();
    let mut obligations = Vec::new();
    let mut affordances = Vec::new();

    match (
        request.decision.action,
        request.alert_plan,
        request.alert_outcome,
    ) {
        (ReferencePolicyAction::PrepareAlert, None, None) => {
            affordances.push(project_affordance(
                "affordance:alert:prepare",
                "plan",
                &format!("fss://event/{event_name}/alert"),
                "Prepare an idempotent alert effect from the corroborated canonical event.",
                AffordanceClass::Robust,
                retained_worlds.clone(),
                CAPABILITY_ALERT_PREPARE,
                alert_prepare_cost(),
                true,
                &request.available_capabilities,
            ));
        }
        (ReferencePolicyAction::PrepareAlert, Some(plan), None) => {
            obligations.push(plan.obligation_id.clone());
            at_risk.push(format!(
                "Effect {} has a prepared terminal-proof obligation but no canonical outcome publication.",
                plan.intent.operation_id.as_str()
            ));
            affordances.push(project_affordance(
                "affordance:alert:commit",
                "commit",
                &format!("fss://operation/{}", plan.intent.operation_id.as_str()),
                "Commit the exact prepared alert intent; do not substitute a new request or idempotency key.",
                AffordanceClass::Robust,
                retained_worlds.clone(),
                CAPABILITY_ALERT_COMMIT,
                alert_commit_cost(),
                false,
                &request.available_capabilities,
            ));
        }
        (ReferencePolicyAction::PrepareAlert, Some(_), Some(outcome)) => {
            match outcome.outcome.operation_receipt.state {
                EffectState::Indeterminate => {
                    obligations.push(outcome.outcome.obligation_id.clone());
                    unknown.push("The provider-side alert outcome is unresolved; delivery and non-delivery both remain live until independently reconciled.".to_owned());
                    at_risk.push(format!(
                        "Operation {} is indeterminate and must not be blindly resent.",
                        outcome.outcome.operation_receipt.intent.operation_id.as_str()
                    ));
                    affordances.push(project_affordance(
                        "affordance:alert:reconcile",
                        "investigate",
                        &format!(
                            "fss://operation/{}/reconcile",
                            outcome.outcome.operation_receipt.intent.operation_id.as_str()
                        ),
                        "Read independent provider state and reconcile the existing effect without resending it.",
                        AffordanceClass::Probe,
                        retained_worlds.clone(),
                        CAPABILITY_EFFECT_RECONCILE,
                        reconcile_cost(),
                        true,
                        &request.available_capabilities,
                    ));
                }
                EffectState::Failed => {
                    at_risk.push("The prior alert attempt is proved failed; a new effect requires a new witnessed plan and idempotency identity.".to_owned());
                    affordances.push(project_affordance(
                        "affordance:alert:replan",
                        "plan",
                        &format!("fss://event/{event_name}/alert"),
                        "Prepare a new alert operation only after reviewing the retained failure proof.",
                        AffordanceClass::Robust,
                        retained_worlds.clone(),
                        CAPABILITY_ALERT_PREPARE,
                        alert_prepare_cost(),
                        true,
                        &request.available_capabilities,
                    ));
                }
                EffectState::Verified => {
                    affordances.push(project_affordance(
                        "affordance:event:monitor",
                        "wait",
                        &format!("fss://event/{event_name}"),
                        "Wait for a meaningful evidence or effect-state delta; the alert obligation is terminal.",
                        AffordanceClass::Wait,
                        retained_worlds.clone(),
                        CAPABILITY_SESSION_WAIT,
                        wait_cost(),
                        true,
                        &request.available_capabilities,
                    ));
                }
                _ => return Err(ReferenceError::InvalidSpec("situation_effect_state")),
            }
        }
        (ReferencePolicyAction::Hold, None, None) => {
            affordances.push(project_affordance(
                "affordance:event:investigate",
                "investigate",
                &format!("fss://event/{event_name}/evidence"),
                "Acquire or inspect evidence that can distinguish the retained possible worlds.",
                AffordanceClass::Probe,
                retained_worlds.clone(),
                CAPABILITY_EVIDENCE_QUERY,
                investigate_cost(),
                true,
                &request.available_capabilities,
            ));
            affordances.push(project_affordance(
                "affordance:event:wait",
                "wait",
                &format!("fss://event/{event_name}"),
                "Wait for a meaningful event or coverage delta while preserving every protected world.",
                AffordanceClass::Wait,
                retained_worlds,
                CAPABILITY_SESSION_WAIT,
                wait_cost(),
                true,
                &request.available_capabilities,
            ));
        }
        _ => return Err(ReferenceError::InvalidSpec("situation_effect_basis")),
    }

    affordances.sort_by(|left, right| left.affordance_id.cmp(&right.affordance_id));
    obligations.sort();
    obligations.dedup();
    let next: Vec<_> = affordances
        .iter()
        .filter(|affordance| affordance.class != AffordanceClass::Unavailable)
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
        && affordances
            .iter()
            .all(|affordance| affordance.class != AffordanceClass::Unavailable)
    {
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
    let handoff = HandoffCapsule::publish(
        handoff_id,
        situation.capsule.mission_id.clone(),
        situation.capsule.session_id.clone(),
        situation.capsule.principal_id.clone(),
        situation.capsule.anchor.clone(),
        situation_root,
        situation.proof_roots.iter().copied(),
        situation.capsule.contract_basis.clone(),
        created_at,
        expires_at,
    )?;
    handoff.verify()?;
    Ok(handoff)
}

fn validate_request(
    request: &ReferenceSituationRequest<'_>,
    authority: &DurableReferenceLedger,
) -> Result<(), ReferenceError> {
    if request.objective_id.is_empty()
        || request.objective_id.len() > MAX_OBJECTIVE_BYTES
        || request.revision == 0
        || request.contract_basis.semantic_protocol != "fss/1"
    {
        return Err(ReferenceError::InvalidSpec("situation_request"));
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
                    return Err(ReferenceError::InvalidSpec("situation_effect_outcome_omitted"));
                }
                None => {}
            }
        }
        (None, None) => {}
    }
    Ok(())
}

fn compile_worlds(
    anchor: &LedgerAnchor,
    objective_id: &str,
    decision: &ReferencePolicyDecision,
    event_receipt: &ReferenceEventReceipt,
    physical_claim_id: &str,
    policy_claim_id: &str,
    absence_claim_id: &str,
) -> (WorldEnvelope, Vec<String>, Vec<String>) {
    let event_name = decision.event.event_id.as_str();
    let event_evidence: Vec<_> = decision.event.evidence.iter().map(|edge| edge.digest).collect();
    let policy_evidence = vec![event_receipt.event_root, event_receipt.event_revision_digest];
    let mut alternatives = Vec::new();
    let mut residuals = Vec::new();
    let mut nominal_claim_ids = BTreeSet::from([policy_claim_id.to_owned()]);
    let mut certified_core_claim_ids = BTreeSet::from([policy_claim_id.to_owned()]);
    let mut unknown = Vec::new();
    let mut at_risk = Vec::new();

    match decision.event.state {
        EventState::Corroborated => {
            nominal_claim_ids.insert(physical_claim_id.to_owned());
            certified_core_claim_ids.insert(physical_claim_id.to_owned());
            alternatives.push(PossibleWorld {
                world_id: format!("world:event:{event_name}:present"),
                description: "The independently corroborated unknown-presence event is physically present within the retained interval.".to_owned(),
                claim_ids: BTreeSet::from([
                    policy_claim_id.to_owned(),
                    physical_claim_id.to_owned(),
                ]),
                evidence: event_evidence,
                consequence_severity: 5,
                protected: true,
            });
        }
        EventState::Witnessed => {
            nominal_claim_ids.insert(physical_claim_id.to_owned());
            alternatives.push(PossibleWorld {
                world_id: format!("world:event:{event_name}:present-single-domain"),
                description: "The unknown-presence event is real, but current support comes from only one failure domain.".to_owned(),
                claim_ids: BTreeSet::from([
                    policy_claim_id.to_owned(),
                    physical_claim_id.to_owned(),
                ]),
                evidence: event_evidence.clone(),
                consequence_severity: 5,
                protected: true,
            });
            residuals.push(PossibleWorld {
                world_id: format!("world:event:{event_name}:benign-or-error"),
                description: "The single-domain finding is benign, erroneous, or otherwise insufficient for an alert effect.".to_owned(),
                claim_ids: BTreeSet::from([policy_claim_id.to_owned()]),
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
                    policy_claim_id.to_owned(),
                    physical_claim_id.to_owned(),
                ]),
                evidence: event_evidence.clone(),
                consequence_severity: 5,
                protected: true,
            });
            residuals.push(PossibleWorld {
                world_id: format!("world:event:{event_name}:non-presence-live"),
                description: "A benign, contradictory, degraded, or otherwise non-presence explanation remains possible.".to_owned(),
                claim_ids: BTreeSet::from([policy_claim_id.to_owned()]),
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
                claim_ids: BTreeSet::from([policy_claim_id.to_owned()]),
                evidence: policy_evidence.clone(),
                consequence_severity: 1,
                protected: false,
            });
            residuals.push(PossibleWorld {
                world_id: format!("world:event:{event_name}:absence-uncertified"),
                description: "Physical presence outside the evaluated evidence remains possible because no complete continuous coverage witness certifies absence.".to_owned(),
                claim_ids: BTreeSet::from([
                    policy_claim_id.to_owned(),
                    absence_claim_id.to_owned(),
                ]),
                evidence: policy_evidence.clone(),
                consequence_severity: 5,
                protected: true,
            });
            unknown.push("Policy rejection is not a certified negative read; physical absence remains unproved.".to_owned());
        }
        _ => {
            alternatives.push(PossibleWorld {
                world_id: format!("world:event:{event_name}:policy-state"),
                description: "The current event state is retained without promoting it to physical certainty.".to_owned(),
                claim_ids: BTreeSet::from([policy_claim_id.to_owned()]),
                evidence: policy_evidence.clone(),
                consequence_severity: 3,
                protected: true,
            });
            unknown.push("The event lifecycle state has no stronger reference-world interpretation.".to_owned());
        }
    }

    let identity = world_identity(anchor, objective_id, decision, &alternatives, &residuals);
    (
        WorldEnvelope {
            envelope_id: format!("world-envelope:{identity}"),
            objective_id: objective_id.to_owned(),
            anchor: anchor.clone(),
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

#[allow(clippy::too_many_arguments)]
fn project_affordance(
    affordance_id: &str,
    operation: &str,
    target: &str,
    rationale: &str,
    available_class: AffordanceClass,
    supported_worlds: BTreeSet<String>,
    required_capability: &str,
    cost: BudgetVector,
    reversible: bool,
    available_capabilities: &BTreeSet<String>,
) -> ActionAffordance {
    let available = available_capabilities.contains(required_capability);
    ActionAffordance {
        affordance_id: affordance_id.to_owned(),
        operation: operation.to_owned(),
        target: target.to_owned(),
        rationale: if available {
            rationale.to_owned()
        } else {
            format!("{rationale} Required capability {required_capability} is not delegated.")
        },
        class: if available {
            available_class
        } else {
            AffordanceClass::Unavailable
        },
        supported_worlds: if available {
            supported_worlds
        } else {
            BTreeSet::new()
        },
        unsafe_worlds: BTreeSet::new(),
        required_capabilities: BTreeSet::from([required_capability.to_owned()]),
        cost,
        reversible,
        branch_predicate: None,
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

fn policy_statement(decision: &ReferencePolicyDecision) -> &'static str {
    match (decision.event.state, decision.action) {
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
        _ => "The reference policy retained the event lifecycle state without granting effect authority.",
    }
}

fn physical_statement(state: EventState) -> &'static str {
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
        _ => "The physical event interpretation remains bounded by the retained lifecycle state.",
    }
}

fn policy_hypothesis(state: EventState) -> HypothesisDisposition {
    match state {
        EventState::Corroborated => HypothesisDisposition::Supported,
        EventState::Witnessed => HypothesisDisposition::Supported,
        EventState::Rejected => HypothesisDisposition::Refuted,
        EventState::Resolved => HypothesisDisposition::Resolved,
        _ => HypothesisDisposition::Live,
    }
}

fn alert_prepare_cost() -> BudgetVector {
    BudgetVector {
        latency_ms: 10,
        bytes: 2_048,
        cpu_millis: 5,
        storage_operations: 2,
        operator_attention_seconds: 1.0,
        ..BudgetVector::default()
    }
}

fn alert_commit_cost() -> BudgetVector {
    BudgetVector {
        latency_ms: 5_000,
        bytes: 4_096,
        network_bytes: 4_096,
        storage_operations: 4,
        privacy_exposure: 1.0,
        operator_attention_seconds: 2.0,
        ..BudgetVector::default()
    }
}

fn reconcile_cost() -> BudgetVector {
    BudgetVector {
        latency_ms: 2_000,
        bytes: 2_048,
        network_bytes: 2_048,
        storage_operations: 2,
        operator_attention_seconds: 1.0,
        ..BudgetVector::default()
    }
}

fn investigate_cost() -> BudgetVector {
    BudgetVector {
        latency_ms: 1_000,
        bytes: 16_384,
        cpu_millis: 50,
        storage_operations: 4,
        privacy_exposure: 0.25,
        operator_attention_seconds: 1.0,
        ..BudgetVector::default()
    }
}

fn wait_cost() -> BudgetVector {
    BudgetVector {
        latency_ms: 60_000,
        bytes: 512,
        storage_operations: 1,
        ..BudgetVector::default()
    }
}
