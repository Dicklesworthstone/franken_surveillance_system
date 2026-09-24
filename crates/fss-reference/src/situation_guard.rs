//! Fail-closed projection guard for agent-facing situation compilation.

use std::collections::BTreeSet;

use fss_core::{
    ActionAffordance, AffordanceClass, BudgetVector, ContentDigest, ContractError, EffectJournal,
    EffectRecordVersion, EffectState, IndeterminateEffectReason, KnowledgeCell,
    KnowledgeCellParams, KnowledgeState, KnowledgeStateBasis, OperationReceipt, PreparedEffect,
    ProvenanceClass, ReconciliationBasis,
};
use fss_ledger::DurableReferenceLedger;

use crate::situation::EFFECT_CLAIM_PREFIX;
use crate::{DurableEffectJournal, ReferenceAlertPlan, ReferenceError};

pub use crate::situation::{EffectCellKind, ReferenceSituation, ReferenceSituationRequest};

/// Required capability to reconcile an in-flight or indeterminate effect.
pub const CAPABILITY_EFFECT_RECONCILE: &str = "capability:effect.reconcile";
/// Stable affordance identity for investigating an in-flight effect status.
pub const EFFECT_STATUS_AFFORDANCE: &str = "affordance:alert:effect-status";
/// Stable affordance identity for reconciling an indeterminate effect.
pub const EFFECT_RECONCILE_AFFORDANCE: &str = "affordance:alert:reconcile";

/// Claim-id prefix of the typed marker that a legacy (v1) operation entered `indeterminate` with
/// no recorded reason: an `unknown` cell per operation, next to its local-state cell (fss-deir9).
pub(crate) const INDETERMINATE_REASON_UNRECORDED_CLAIM_PREFIX: &str =
    "claim:indeterminate-reason-unrecorded:";

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
///
/// The receipt must not be a legacy (v1) receipt. A v1 receipt exists only as the product of the
/// durable journal's versioned replay, so it is admitted only through
/// [`compile_reference_situation_with_durable_journal`]; handed in here, it is refused as
/// `situation_operation_receipt_integrity` (fss-deir9). A cancelled receipt handed in here must
/// carry the cancellation proof binding the plan's prepared record to ledger-published evidence,
/// whatever its version (fss-thzlz).
///
/// The receipt is accepted only when the journal that owns the operation still holds it EXACTLY:
/// `journal` must contain an operation receipt equal to `operation_receipt`, and the compilation
/// binds that journal receipt (fss-gwwqe). A hand-built structurally valid receipt — for example a
/// fabricated `Verified` receipt with no published outcome — is refused and can never yield a
/// terminal local-state cell.
pub fn compile_reference_situation_with_operation_receipt(
    request: ReferenceSituationRequest<'_>,
    operation_receipt: &OperationReceipt,
    authority: &DurableReferenceLedger,
    journal: &EffectJournal,
) -> Result<ReferenceSituation, ReferenceError> {
    compile_with_operation_receipt(
        request,
        operation_receipt,
        authority,
        Some(journal),
        ReceiptSource::Caller,
    )
}

/// Where the operation receipt handed to the guard came from (fss-deir9), with the prepared
/// record a cancellation proof must bind (fss-thzlz).
#[derive(Clone, Debug, Eq, PartialEq)]
enum ReceiptSource {
    /// Supplied by the caller: never a v1 receipt, and a cancellation must be proof-bound. Its
    /// prepared record is the plan's intent and obligation, prepared with the reference alert
    /// terminal predicate at the receipt's preparation time.
    Caller,
    /// Read from the durable effect journal, whose versioned replay alone produces v1 and v2
    /// receipts, together with that journal's own prepared record of the operation and the
    /// version of the record that wrote its cancellation, if it is cancelled (fss-thzlz).
    DurableJournal {
        /// The journal's own prepared record of the operation.
        prepared: Box<PreparedEffect>,
        /// The version of the journal record that wrote the cancellation.
        cancelled_under: Option<EffectRecordVersion>,
    },
}

impl ReceiptSource {
    const fn is_durable_journal(&self) -> bool {
        matches!(self, Self::DurableJournal { .. })
    }
}

fn compile_with_operation_receipt(
    request: ReferenceSituationRequest<'_>,
    operation_receipt: &OperationReceipt,
    authority: &DurableReferenceLedger,
    journal: Option<&EffectJournal>,
    source: ReceiptSource,
) -> Result<ReferenceSituation, ReferenceError> {
    let plan = request
        .alert_plan
        .cloned()
        .ok_or(ReferenceError::InvalidSpec("situation_effect_basis"))?;
    // The receipt's own shape and, for a cancellation, its proof come first, so a cancellation
    // whose proof does not verify is refused with the typed error naming it (fss-thzlz), whoever
    // holds it.
    validate_operation_receipt(operation_receipt, &plan, &source, authority)?;
    // fss-gwwqe: on the caller path the journal that owns the operation must still hold EXACTLY
    // this receipt. A structurally valid but hand-built receipt (a fabricated `Verified` with no
    // published outcome, for instance) never yields a terminal local-state cell, because the
    // guard binds the journal's receipt, not the caller's.
    if source == ReceiptSource::Caller {
        let journal_matches = journal
            .and_then(|journal| journal.operation(&plan.intent.operation_id))
            .is_some_and(|held| held == operation_receipt);
        if !journal_matches {
            return Err(ReferenceError::InvalidSpec(
                "situation_operation_receipt_integrity",
            ));
        }
    }
    if request
        .alert_outcome
        .is_some_and(|outcome| operation_receipt != &outcome.outcome.operation_receipt)
    {
        return Err(ReferenceError::InvalidSpec(
            "situation_operation_receipt_mismatch",
        ));
    }

    let outcome_is_absent = request.alert_outcome.is_none();
    let capabilities = request.available_capabilities.clone();
    let mut situation = crate::situation::compile_reference_situation(request, authority)?;
    annotate_operation_receipt(&mut situation, operation_receipt)?;

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

/// Compiles a situation bound to the durable effect journal (INV-111).
///
/// If an alert plan is present, enforces that its obligation is durably recorded in the journal.
/// A transient-only obligation is rejected with [`ReferenceError::InvalidSpec("transient_obligation_rejected")`].
/// If the operation has already been dispatched or is indeterminate (e.g. across restart),
/// the commit affordance is replaced with the reconcile affordance [`EFFECT_RECONCILE_AFFORDANCE`].
///
/// The situation seals the durable journal root it was compiled against, so a journal-bound
/// meaningful delta checks the real journal rather than a caller-supplied set (fss-mnlz1).
pub fn compile_reference_situation_with_durable_journal(
    request: ReferenceSituationRequest<'_>,
    durable_journal: &DurableEffectJournal,
    authority: &DurableReferenceLedger,
) -> Result<ReferenceSituation, ReferenceError> {
    let mut situation = compile_against_durable_journal(request, durable_journal, authority)?;
    situation.set_journal_root(durable_journal.last_root());
    situation.seal_effect_bindings()?;
    Ok(situation)
}

fn compile_against_durable_journal(
    request: ReferenceSituationRequest<'_>,
    durable_journal: &DurableEffectJournal,
    authority: &DurableReferenceLedger,
) -> Result<ReferenceSituation, ReferenceError> {
    if let Some(plan) = request.alert_plan {
        let obligation = durable_journal
            .acknowledge_obligation(&plan.obligation_id)
            .map_err(|_| ReferenceError::InvalidSpec("transient_obligation_rejected"))?;
        if obligation.operation_id != plan.intent.operation_id {
            return Err(ReferenceError::InvalidSpec("obligation_operation_mismatch"));
        }
        let operation_receipt = durable_journal
            .operation(&plan.intent.operation_id)
            .ok_or(ReferenceError::InvalidSpec("transient_obligation_rejected"))?;
        let prepared = durable_journal
            .effect_journal()
            .prepared_record(&plan.intent.operation_id)?;
        compile_with_operation_receipt(
            request,
            operation_receipt,
            authority,
            None,
            ReceiptSource::DurableJournal {
                prepared: Box::new(prepared),
                cancelled_under: durable_journal
                    .effect_journal()
                    .cancellation_record_version(&operation_receipt.intent.operation_id),
            },
        )
    } else if let Some(outcome) = request.alert_outcome {
        let obligation = durable_journal
            .acknowledge_obligation(&outcome.outcome.obligation_id)
            .map_err(|_| ReferenceError::InvalidSpec("transient_obligation_rejected"))?;
        if obligation.operation_id != outcome.outcome.operation_receipt.intent.operation_id {
            return Err(ReferenceError::InvalidSpec("obligation_operation_mismatch"));
        }
        let operation_receipt = durable_journal
            .operation(&outcome.outcome.operation_receipt.intent.operation_id)
            .ok_or(ReferenceError::InvalidSpec("transient_obligation_rejected"))?;
        let prepared = durable_journal
            .effect_journal()
            .prepared_record(&outcome.outcome.operation_receipt.intent.operation_id)?;
        compile_with_operation_receipt(
            request,
            operation_receipt,
            authority,
            None,
            ReceiptSource::DurableJournal {
                prepared: Box::new(prepared),
                cancelled_under: durable_journal
                    .effect_journal()
                    .cancellation_record_version(&operation_receipt.intent.operation_id),
            },
        )
    } else {
        compile_reference_situation(request, authority)
    }
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
    source: &ReceiptSource,
    authority: &DurableReferenceLedger,
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
    // A legacy (v1) receipt exists only as the product of the durable journal's versioned
    // replay, so one reaching the guard any other way is refused; a v2 or v3 receipt never
    // carries the legacy `unrecorded` marker, which only that replay produces (fss-deir9).
    let version_admissible = match receipt.record_version() {
        EffectRecordVersion::V1 => source.is_durable_journal(),
        EffectRecordVersion::V2 | EffectRecordVersion::V3 => {
            receipt.indeterminate_reason != Some(IndeterminateEffectReason::Unrecorded)
        }
    };
    let structurally_valid = version_admissible
        && match receipt.state {
            EffectState::Prepared => {
                receipt.committed_at.is_none()
                    && receipt.updated_at == receipt.prepared_at
                    && receipt.result_digest.is_none()
                    && receipt.error_code.is_none()
                    && receipt.indeterminate_reason.is_none()
            }
            EffectState::Committed | EffectState::AdapterAccepted => {
                receipt.committed_at.is_some()
                    && receipt.result_digest.is_none()
                    && receipt.error_code.is_none()
                    && receipt.indeterminate_reason.is_none()
            }
            EffectState::Observed | EffectState::Verified => {
                receipt.committed_at.is_some()
                    && receipt.result_digest.is_some()
                    && carries_only_an_inherited_reason(receipt)
            }
            // The journal cancels only a prepared operation, strictly later than its preparation,
            // and only with a cancellation proof digest; a reason is optional but never empty. The
            // digest is verified as a proof below (fss-thzlz).
            EffectState::Cancelled => {
                receipt.committed_at.is_none()
                    && receipt.updated_at > receipt.prepared_at
                    && receipt.result_digest.is_some()
                    && receipt
                        .error_code
                        .as_deref()
                        .is_none_or(|reason| !reason.is_empty())
                    && receipt.indeterminate_reason.is_none()
            }
            // A failure names its own non-empty reason; an earlier indeterminate episode, if any,
            // keeps its recorded (never empty) or legacy unrecorded reason.
            EffectState::Failed => {
                receipt.result_digest.is_some()
                    && names_a_reason(receipt.error_code.as_deref())
                    && !matches!(
                        &receipt.indeterminate_reason,
                        Some(IndeterminateEffectReason::Recorded(reason)) if reason.is_empty()
                    )
            }
            EffectState::Indeterminate => {
                receipt.committed_at.is_some() && indeterminate_reason_is_consistent(receipt)
            }
        };
    if !structurally_valid {
        return Err(ReferenceError::InvalidSpec(
            "situation_operation_receipt_integrity",
        ));
    }
    // The journal records a cancellation with the evidence the canceller supplied; the guard
    // verifies it. A structurally valid cancellation whose proof does not verify against the
    // prepared record and the ledger-published evidence is refused with its own typed error, so it
    // is never projected as cancelled, and never as pending (fss-thzlz).
    if receipt.state == EffectState::Cancelled
        && !cancellation_proof_is_admissible(receipt, plan, source, authority)
    {
        return Err(ReferenceError::UnverifiableCancellationEvidence {
            operation_id: receipt.intent.operation_id.clone(),
            proof_digest: receipt.result_digest,
        });
    }
    Ok(())
}

/// Whether a cancelled receipt's result digest is an admissible cancellation proof (fss-thzlz).
///
/// The effect journal keeps the rule a v1 or v2 record was written under, so a cancellation that a
/// v1 or v2 record wrote carries the digest it was written with; the guard exempts exactly those
/// cancellations, keyed on the version of the record that wrote the cancellation (the same key the
/// journal checks it under, never the operation's prepare-time version), and only when it reads
/// them from the journal itself. Every other cancelled receipt, including
/// a v2 receipt handed in by a caller, must carry the proof the journal binds for a v3 record: the
/// [`fss_core::EffectCancellationRecord`] of the prepared record and the evidence that caused the
/// cancel. For a reference alert that evidence is [`crate::alert_cancel_proof`] over the plan's
/// prepared authority anchor and an anchor the authority ledger published at or after it. The
/// proof is recomputed from the journal's prepared record (the plan's, for a caller receipt) and
/// the ledger, never from the receipt's own fields.
fn cancellation_proof_is_admissible(
    receipt: &OperationReceipt,
    plan: &ReferenceAlertPlan,
    source: &ReceiptSource,
    authority: &DurableReferenceLedger,
) -> bool {
    // Keyed on the same thing the journal keys its rule on: the version of the record that wrote
    // the cancellation, never the version the operation was prepared under. A cancellation written
    // today is a v3 record, even for an operation a v1 or v2 record prepared (rthz2 H1/H3).
    let written_by_a_legacy_cancel_record = match source {
        ReceiptSource::DurableJournal {
            cancelled_under, ..
        } => cancelled_under.is_some_and(|version| version < EffectRecordVersion::V3),
        ReceiptSource::Caller => false,
    };
    if written_by_a_legacy_cancel_record {
        return true;
    }
    let prepared = match source {
        ReceiptSource::DurableJournal { prepared, .. } => PreparedEffect::clone(prepared),
        ReceiptSource::Caller => PreparedEffect {
            intent: plan.intent.clone(),
            obligation_id: plan.obligation_id.clone(),
            terminal_predicate: crate::REFERENCE_ALERT_TERMINAL_PREDICATE.to_owned(),
            prepared_at: receipt.prepared_at,
        },
    };
    prepared.intent == plan.intent
        && receipt.result_digest.is_some_and(|proof| {
            crate::alert::alert_cancellation_is_bound(proof, &prepared, plan, authority)
        })
}

/// Returns whether `code` names a non-empty reason, as the effect journal requires.
fn names_a_reason(code: Option<&str>) -> bool {
    code.is_some_and(|reason| !reason.is_empty())
}

/// An observed or verified receipt may carry an error code only as the reason recorded when the
/// operation entered `indeterminate`, which reconciliation keeps as provenance
/// (`EffectJournal::reconcile_verified`); the journal never attaches a new one. A legacy (v1)
/// reason-less episode left no code or an empty one behind its unrecorded marker (fss-deir9).
fn carries_only_an_inherited_reason(receipt: &OperationReceipt) -> bool {
    match (&receipt.indeterminate_reason, receipt.error_code.as_deref()) {
        (None, None) => true,
        (Some(IndeterminateEffectReason::Recorded(reason)), Some(code)) => {
            names_a_reason(Some(code)) && reason == code
        }
        (Some(IndeterminateEffectReason::Unrecorded), None | Some("")) => true,
        _ => false,
    }
}

/// An indeterminate receipt records the non-empty reason it names, or is a legacy (v1) entry whose
/// missing (absent or empty) reason replay made explicitly unrecorded (fss-deir9).
fn indeterminate_reason_is_consistent(receipt: &OperationReceipt) -> bool {
    match (&receipt.indeterminate_reason, receipt.error_code.as_deref()) {
        (Some(IndeterminateEffectReason::Recorded(reason)), Some(code)) => {
            names_a_reason(Some(code)) && reason == code
        }
        (Some(IndeterminateEffectReason::Unrecorded), None | Some("")) => true,
        _ => false,
    }
}

fn annotate_operation_receipt(
    situation: &mut ReferenceSituation,
    operation_receipt: &OperationReceipt,
) -> Result<(), ReferenceError> {
    let digest: ContentDigest = operation_receipt.receipt_digest();
    let operation_id = operation_receipt.intent.operation_id.as_str();
    let knowledge_state = local_effect_knowledge_state(operation_receipt.state);
    situation.proof_roots.insert(digest);
    situation
        .capsule
        .frame
        .evidence_handles
        .insert(format!("fss://proof/{digest}"));
    let cell = KnowledgeCell::new(KnowledgeCellParams {
        claim_id: format!(
            "{EFFECT_CLAIM_PREFIX}{operation_id}{}",
            EffectCellKind::LocalState.claim_suffix()
        ),
        statement: format!(
            "The exact local effect journal receipt records state {}.",
            operation_receipt.state.as_str()
        ),
        knowledge_state,
        // Local effect journal receipts are classified as Observed under PROV-001 because
        // they constitute direct canonical effect evidence of local runtime state, distinguishing
        // them from cognitive derivations and allowing effect reconciliation.
        provenance: ProvenanceClass::Observed,
        hypothesis: None,
        evidence: vec![digest],
        contradictions: Vec::new(),
        valid_until: None,
        state_basis: (knowledge_state == KnowledgeState::Indeterminate).then(|| {
            KnowledgeStateBasis::Reconciliation(ReconciliationBasis::occurred_or_not(digest))
        }),
    })?;
    // The caller validated the receipt against the plan (and against the published outcome, when
    // there is one), so the cell is compiled from verified material in every state. Binding it
    // also keeps an indeterminate local state from being dropped or relabeled later (fss-6sph6).
    situation.bind_effect_cell(
        EffectCellKind::LocalState,
        &operation_receipt.intent.operation_id,
        operation_receipt.state,
        &cell,
    )?;
    situation.capsule.frame.knowledge_cells.push(cell);
    // A legacy (v1) operation that entered `indeterminate` without a reason still projects, in
    // every state, with the missing reason as a typed `unknown` marker, never silently dropped
    // and never flattened into the terminal cell (fss-deir9).
    if operation_receipt.indeterminate_reason == Some(IndeterminateEffectReason::Unrecorded) {
        let marker = KnowledgeCell::new(KnowledgeCellParams {
            claim_id: format!("{INDETERMINATE_REASON_UNRECORDED_CLAIM_PREFIX}{operation_id}"),
            statement: format!(
                "The legacy effect journal recorded no reason when operation {operation_id} entered indeterminate."
            ),
            knowledge_state: KnowledgeState::Unknown,
            provenance: ProvenanceClass::Derived,
            hypothesis: None,
            evidence: vec![digest],
            contradictions: Vec::new(),
            valid_until: None,
            state_basis: None,
        })?;
        situation.capsule.frame.knowledge_cells.push(marker);
    }
    situation.capsule.frame.now.push(format!(
        "Local operation {operation_id} is {}.",
        operation_receipt.state.as_str()
    ));
    Ok(())
}

/// Knowledge state of the `claim:effect:*:local-state` cell for a local receipt in `state`.
///
/// The cell records the LOCAL journal state, not a proved external outcome, and it lives in the
/// effect-claim namespace, so its knowledge state must say what that local state proves about the
/// effect (fss-deir9). Only a terminal local state is a proved terminal postcondition and may be
/// `known` (KSTATE-001). `prepared` has not crossed the boundary, so the outcome is simply not
/// established (KSTATE-003). Every dispatched non-terminal state may already have produced the
/// external effect, so it keeps both reconciliation branches open (KSTATE-008). The match is
/// exhaustive so a new operation state must be classified here rather than defaulting to `known`.
const fn local_effect_knowledge_state(state: EffectState) -> KnowledgeState {
    match state {
        EffectState::Verified | EffectState::Failed | EffectState::Cancelled => {
            KnowledgeState::Known
        }
        EffectState::Prepared => KnowledgeState::Unknown,
        EffectState::Committed
        | EffectState::AdapterAccepted
        | EffectState::Observed
        | EffectState::Indeterminate => KnowledgeState::Indeterminate,
    }
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

    let (affordance_id, target, detail_text) = if state == Some(EffectState::Indeterminate) {
        (
            EFFECT_RECONCILE_AFFORDANCE,
            format!(
                "fss://operation/{}/reconcile",
                plan.intent.operation_id.as_str()
            ),
            "Read independent provider state and reconcile the existing indeterminate operation without resending.",
        )
    } else {
        (
            EFFECT_STATUS_AFFORDANCE,
            format!(
                "fss://operation/{}/status",
                plan.intent.operation_id.as_str()
            ),
            "Inspect and reconcile the existing operation.",
        )
    };

    let full_rationale = if available {
        if state == Some(EffectState::Indeterminate) {
            format!("{rationale} {detail_text}")
        } else {
            format!("{rationale} Inspect and reconcile the existing {state_text} operation.")
        }
    } else {
        format!("{rationale} Required capability {CAPABILITY_EFFECT_RECONCILE} is not delegated.")
    };

    situation.capsule.affordances.push(ActionAffordance {
        affordance_id: affordance_id.to_owned(),
        operation: "investigate".to_owned(),
        target,
        rationale: full_rationale,
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
        cost: status_cost()?,
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
        .sort_by(|left, right| left.claim_id().cmp(right.claim_id()));
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
    refresh_identity(situation)?;
    situation.capsule.validate()?;
    // This is the path's last capsule edit, so the bindings are sealed to the finished capsule.
    situation.seal_effect_bindings()?;
    Ok(())
}

fn refresh_identity(situation: &mut ReferenceSituation) -> Result<(), ReferenceError> {
    let mut normalized = situation.capsule.clone();
    normalized.capsule_id.clear();
    normalized.frame.frame_id.clear();
    let digest = normalized.validated_digest("fss.reference_guarded_situation_identity.v1")?;
    situation.capsule.frame.frame_id = format!("frame:{digest}");
    situation.capsule.capsule_id = format!("situation:{digest}");
    Ok(())
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

fn status_cost() -> Result<BudgetVector, ReferenceError> {
    BudgetVector::builder()
        .latency_ms(2_000)
        .bytes(2_048)
        .network_bytes(2_048)
        .storage_operations(2)
        .operator_attention_seconds(1.0)
        .build()
        .map_err(|e| ReferenceError::Contract(ContractError::InvalidBudget(e)))
}
