//! Fail-closed projection guard for agent-facing situation compilation.

use std::collections::BTreeSet;

use fss_core::{
    ActionAffordance, AffordanceClass, BudgetVector, CanonicalEncode, ContentDigest, EffectState,
    KnowledgeCell, KnowledgeState, OperationReceipt, ProvenanceClass,
};
use fss_ledger::DurableReferenceLedger;

use crate::{ReferenceAlertPlan, ReferenceError};

pub use crate::situation::{ReferenceSituation, ReferenceSituationRequest};

const CAPABILITY_EFFECT_RECONCILE: &str = "capability:effect.reconcile";
const EFFECT_STATUS_AFFORDANCE: &str = "affordance:alert:effect-status";

/// Compiles a conservative situation without trusting caller-hidden local effect state.
///
/// A plan without a canonical outcome is never enough to expose dispatch. The projection instead
/// exposes an effect-status probe, because the operation may already have crossed the external
/// boundary. Call [`compile_reference_situation_with_operation_receipt`] only when the exact local
/// receipt is available.
pub fn compile_reference_situation(
    request: ReferenceSituationRequest<'_>,
    authority: &DurableReferenceLedger,
) -> Result<ReferenceSituation, ReferenceError> {
    let plan = request.alert_plan.cloned();
    let outcome_is_absent = request.alert_outcome.is_none();
    let capabilities = request.available_capabilities.clone();
    let mut situation = crate::situation::compile_reference_situation(request, authority)?;

    if let Some(plan) = plan.filter(|_| outcome_is_absent) {
        replace_commit_with_status(
            &mut situation,
            &plan,
            None,
            &capabilities,
            "The exact local operation receipt is absent, so preparation cannot be distinguished \
             from a prior dispatch.",
        )?;
        situation.capsule.frame.unknown.push(
            "Local effect state is unavailable; the operation may already have crossed the \
             external boundary."
                .to_owned(),
        );
        situation.capsule.frame.at_risk.push(
            "Dispatch is fail-closed until the exact operation receipt is recovered; the alert \
             plan alone is not retry authority."
                .to_owned(),
        );
        situation.capsule.completeness = fss_core::Completeness::Partial;
        finalize_projection(&mut situation)?;
    }

    Ok(situation)
}

/// Compiles a situation bound to the exact local operation receipt.
///
/// Only an exact `Prepared` receipt can preserve the commit affordance. Every later state exposes
/// status/reconciliation instead, preventing a blind resend after dispatch or acknowledgement loss.
pub fn compile_reference_situation_with_operation_receipt(
    request: ReferenceSituationRequest<'_>,
    operation_receipt: &OperationReceipt,
    authority: &DurableReferenceLedger,
) -> Result<ReferenceSituation, ReferenceError> {
    let plan = request
        .alert_plan
        .cloned()
        .ok_or(ReferenceError::InvalidSpec("situation_effect_basis"))?;
    validate_operation_receipt(operation_receipt, &plan)?;
    if request.alert_outcome.is_some_and(|outcome| {
        operation_receipt != &outcome.outcome.operation_receipt
    }) {
        return Err(ReferenceError::InvalidSpec(
            "situation_operation_receipt_mismatch",
        ));
    }

    let outcome_is_absent = request.alert_outcome.is_none();
    let capabilities = request.available_capabilities.clone();
    let mut situation = crate::situation::compile_reference_situation(request, authority)?;
    annotate_operation_receipt(&mut situation, operation_receipt);

    if outcome_is_absent && operation_receipt.state != EffectState::Prepared {
        replace_commit_with_status(
            &mut situation,
            &plan,
            Some(operation_receipt.state),
            &capabilities,
            operation_state_rationale(operation_receipt.state),
        )?;
        situation.capsule.frame.unknown.push(format!(
            "The local operation state is {}, but no canonical effect outcome is published.",
            operation_receipt.state.as_str()
        ));
        situation.capsule.frame.at_risk.push(
            "The operation must be reconciled or canonically published before any new dispatch is \
             considered."
                .to_owned(),
        );
        situation.capsule.completeness = fss_core::Completeness::Partial;
    }

    finalize_projection(&mut situation)?;
    Ok(situation)
}

/// Seals a root-closed handoff from a verified guarded situation.
pub fn seal_reference_handoff(
    situation: &ReferenceSituation,
    handoff_id: fss_core::HandoffId,
    created_at: fss_core::TimestampNs,
    expires_at: fss_core::TimestampNs,
) -> Result<fss_core::HandoffCapsule, ReferenceError> {
    crate::situation::seal_reference_handoff(situation, handoff_id, created_at, expires_at)
}

fn validate_operation_receipt(
    receipt: &OperationReceipt,
    plan: &ReferenceAlertPlan,
) -> Result<(), ReferenceError> {
    if receipt.intent != plan.intent || receipt.updated_at < receipt.prepared_at {
        return Err(ReferenceError::InvalidSpec(
            "situation_operation_receipt_integrity",
        ));
    }
    if receipt.committed_at.is_some_and(|committed_at| {
        committed_at < receipt.prepared_at || committed_at > receipt.updated_at
    }) {
        return Err(ReferenceError::InvalidSpec(
            "situation_operation_receipt_integrity",
        ));
    }
    let structurally_valid = match receipt.state {
        EffectState::Prepared => {
            receipt.committed_at.is_none()
                && receipt.updated_at == receipt.prepared_at
                && receipt.result_digest.is_none()
                && receipt.error_code.is_none()
        }
        EffectState::Committed | EffectState::AdapterAccepted => {
            receipt.committed_at.is_some()
                && receipt.result_digest.is_none()
                && receipt.error_code.is_none()
        }
        EffectState::Observed | EffectState::Verified => {
            receipt.committed_at.is_some()
                && receipt.result_digest.is_some()
                && receipt.error_code.is_none()
        }
        EffectState::Cancelled => {
            receipt.committed_at.is_none()
                && receipt.result_digest.is_none()
                && receipt.error_code.is_none()
        }
        EffectState::Failed => receipt.result_digest.is_some() && receipt.error_code.is_some(),
        EffectState::Indeterminate => {
            receipt.committed_at.is_some() && receipt.error_code.is_some()
        }
    };
    if !structurally_valid {
        return Err(ReferenceError::InvalidSpec(
            "situation_operation_receipt_integrity",
        ));
    }
    Ok(())
}

fn annotate_operation_receipt(
    situation: &mut ReferenceSituation,
    operation_receipt: &OperationReceipt,
) {
    let digest: ContentDigest = operation_receipt.receipt_digest();
    let operation_id = operation_receipt.intent.operation_id.as_str();
    situation.proof_roots.insert(digest);
    situation
        .capsule
        .frame
        .evidence_handles
        .insert(format!("fss://proof/{digest}"));
    situation.capsule.frame.knowledge_cells.push(KnowledgeCell {
        claim_id: format!("claim:effect:{operation_id}:local-state"),
        statement: format!(
            "The exact local effect journal receipt records state {}.",
            operation_receipt.state.as_str()
        ),
        knowledge_state: KnowledgeState::Known,
        provenance: ProvenanceClass::Derived,
        hypothesis: None,
        evidence: vec![digest],
        contradictions: Vec::new(),
        valid_until: None,
    });
    situation.capsule.frame.now.push(format!(
        "Local operation {operation_id} is {}.",
        operation_receipt.state.as_str()
    ));
}

fn replace_commit_with_status(
    situation: &mut ReferenceSituation,
    plan: &ReferenceAlertPlan,
    state: Option<EffectState>,
    capabilities: &BTreeSet<String>,
    rationale: &str,
) -> Result<(), ReferenceError> {
    let had_commit = situation
        .capsule
        .affordances
        .iter()
        .any(|affordance| affordance.operation == "commit");
    if !had_commit {
        return Err(ReferenceError::InvalidSpec(
            "situation_commit_affordance_missing",
        ));
    }
    situation
        .capsule
        .affordances
        .retain(|affordance| affordance.operation != "commit");

    let available = capabilities.contains(CAPABILITY_EFFECT_RECONCILE);
    let retained_worlds = situation.capsule.frame.world_envelope.world_ids();
    let state_text = state.map_or("unknown", EffectState::as_str);
    situation.capsule.affordances.push(ActionAffordance {
        affordance_id: EFFECT_STATUS_AFFORDANCE.to_owned(),
        operation: "investigate".to_owned(),
        target: format!(
            "fss://operation/{}/status",
            plan.intent.operation_id.as_str()
        ),
        rationale: if available {
            format!("{rationale} Inspect and reconcile the existing {state_text} operation.")
        } else {
            format!(
                "{rationale} Required capability {CAPABILITY_EFFECT_RECONCILE} is not delegated."
            )
        },
        class: if available {
            AffordanceClass::Probe
        } else {
            AffordanceClass::Unavailable
        },
        supported_worlds: if available {
            retained_worlds
        } else {
            BTreeSet::new()
        },
        unsafe_worlds: BTreeSet::new(),
        required_capabilities: BTreeSet::from([CAPABILITY_EFFECT_RECONCILE.to_owned()]),
        cost: status_cost(),
        reversible: true,
        branch_predicate: None,
    });
    Ok(())
}

fn finalize_projection(situation: &mut ReferenceSituation) -> Result<(), ReferenceError> {
    situation
        .capsule
        .frame
        .knowledge_cells
        .sort_by(|left, right| left.claim_id.cmp(&right.claim_id));
    situation
        .capsule
        .affordances
        .sort_by(|left, right| left.affordance_id.cmp(&right.affordance_id));
    situation.capsule.frame.next = situation
        .capsule
        .affordances
        .iter()
        .filter(|affordance| {
            matches!(
                affordance.class,
                AffordanceClass::Robust
                    | AffordanceClass::Conditional
                    | AffordanceClass::Probe
                    | AffordanceClass::Wait
            )
        })
        .map(|affordance| affordance.affordance_id.clone())
        .collect();
    refresh_identity(situation);
    situation.capsule.validate()?;
    Ok(())
}

fn refresh_identity(situation: &mut ReferenceSituation) {
    let mut normalized = situation.capsule.clone();
    normalized.capsule_id.clear();
    normalized.frame.frame_id.clear();
    let digest = normalized.canonical_digest("fss.reference_guarded_situation_identity.v1");
    situation.capsule.frame.frame_id = format!("frame:{digest}");
    situation.capsule.capsule_id = format!("situation:{digest}");
}

fn operation_state_rationale(state: EffectState) -> &'static str {
    match state {
        EffectState::Prepared => "The operation is prepared and has not crossed the boundary.",
        EffectState::Committed => {
            "Dispatch authority was committed; another commit could duplicate an external effect."
        }
        EffectState::AdapterAccepted => {
            "The adapter accepted the operation, but terminal delivery proof is not canonical."
        }
        EffectState::Observed => {
            "An external result was observed, but terminal proof is not canonical."
        }
        EffectState::Verified => {
            "The local journal is terminally verified, but its canonical outcome is absent."
        }
        EffectState::Cancelled => {
            "The local journal records cancellation, but its canonical outcome is absent."
        }
        EffectState::Failed => {
            "The local journal records proved failure, but its canonical outcome is absent."
        }
        EffectState::Indeterminate => {
            "The effect may have happened and must be reconciled without resending."
        }
    }
}

fn status_cost() -> BudgetVector {
    BudgetVector {
        latency_ms: 2_000,
        bytes: 2_048,
        network_bytes: 2_048,
        storage_operations: 2,
        operator_attention_seconds: 1.0,
        ..BudgetVector::default()
    }
}
