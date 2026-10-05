#![forbid(unsafe_code)]
//! Owner-approved cancellation of one durably prepared alert, addressed by operation identity.
//!
//! Cancellation does not require the current event revision, its source media, a relay route,
//! or provider access. It can only retire an operation which has never been committed. Any
//! possibly dispatched state is refused, not relabelled as cancelled, failed, or delivered.
//! A root-last, ledgered request precedes the cancellation; it cannot itself retire an operation.
//! The existing v3 effect journal owns the atomic transition and terminal obligation proof.
//!
//! Approval binds the whole immutable preparation, its effect authority, both physical store
//! pins, the deployment, and the cancelling principal. It deliberately does not bind unrelated
//! later ledger heads: a newer event must not prevent its old, unsent alert from being stopped.
//! The operation's actual state is checked again under the deployment lock at commit. Exact
//! retries of this principal's cancellation are no-ops, including after a cold restart.

use std::fmt;

use fss_core::{
    CanonicalEncode, CanonicalEncoder, CaptureInterval, ContentDigest, ContextAuthority,
    ContractError, EffectCancellationRecord, EffectState, Obligation, ObligationState, OperationId,
    OperationReceipt, PreparedEffect, PrincipalId, TimestampNs,
};
use fss_ledger::DurableReferenceLedger;
use fss_object::ObjectManifest;
use fss_publication::{ROOT_REACHABILITY_FAMILY, SlotName};

use crate::{
    DurableEffectError, ReferenceAlertPlan, ReferenceDeployment, ReferenceError, ReplayCx,
};

/// Existing capability for an owner or explicitly delegated supervisor to cancel owned work.
pub const CAP_ALERT_CANCEL: &str = "CAP-AGENT-CANCEL-001";
/// Existing capability for local operation/obligation inspection.
pub const CAP_ALERT_STATUS: &str = "CAP-AGENT-SITUATION-READ-001";
/// Maximum complete operation/obligation inventory inspected by one request.
pub const MAX_ALERT_OPERATIONS: usize = 4096;
/// Hard ceiling on the effect history verified before a cancellation.
pub const MAX_CONTROL_JOURNAL_BYTES: u64 = 64 * 1024 * 1024;
/// The principal is retained in the journal's bounded, typed cancellation reason.
pub const MAX_CANCEL_PRINCIPAL_BYTES: usize = 96;
/// Canonical operator request evidence, bound again to the whole prepared effect by the journal.
pub const CANCEL_EVIDENCE_DOMAIN: &str = "fss.alert_operator_cancel_evidence.v1";
/// Exact owner approval; not a grant of authority by itself.
pub const CANCEL_APPROVAL_DOMAIN: &str = "fss.alert_operator_cancel_approval.v1";
/// Read/preparation checkpoint; failure here writes nothing through this module.
pub const STAGE_CANCEL_READ: &str = "alert_cancel:read";
/// Last cooperative checkpoint before request publication begins.
pub const STAGE_CANCEL_REVALIDATED: &str = "alert_cancel:revalidated";
/// Intent is in root-last custody, but the operation is still prepared; exact retry resumes.
pub const STAGE_CANCEL_REQUEST_PUBLISHED: &str = "alert_cancel:request_published";
/// Post-commit checkpoint; cancellation here never erases an already completed transition.
pub const STAGE_CANCEL_COMMITTED: &str = "alert_cancel:committed";

const REASON_PREFIX: &str = "operator_cancel:";

/// Narrow, secret-free failures. No refusal permits a resend.
#[derive(Debug)]
pub enum AlertControlError {
    /// Explicit context authority does not grant this lifecycle operation on this deployment.
    Unauthorized,
    /// The operation is absent or is not an alert dispatch.
    NotAlert,
    /// Only a never-committed prepared alert can be cancelled.
    NotPrepared(EffectState),
    /// The presented approval belongs to another preparation, actor, or physical store.
    ApprovalMismatch,
    /// A different cancellation cannot be adopted as this request's success.
    CancellationMismatch,
    /// Preparation, receipt, and terminal-proof obligation disagree.
    Inconsistent,
    /// Hard inventory or input bound reached; never sample a prefix.
    Limit,
    /// The live context was cancelled before the effect-journal commit.
    Cancelled,
    /// Shared semantic contract refused the request.
    Contract(ContractError),
    /// Deployment or authority custody could not be verified.
    Deployment(ReferenceError),
    /// The durable journal refused the append; reopen and inspect, never resend.
    Journal(DurableEffectError),
}

impl AlertControlError {
    /// Existing registered error family; detailed variants do not invent effect outcomes.
    #[must_use]
    pub const fn stable_id(&self) -> &'static str {
        match self {
            Self::Unauthorized => "ERR-AUTH-DENIED-001",
            Self::ApprovalMismatch => "ERR-ALERT-APPROVAL-STALE-001",
            Self::NotAlert | Self::Inconsistent | Self::Deployment(_) => "ERR-ALERT-AUTHORITY-001",
            Self::NotPrepared(_)
            | Self::CancellationMismatch
            | Self::Limit
            | Self::Cancelled
            | Self::Contract(_)
            | Self::Journal(_) => "ERR-ALERT-DISPATCH-001",
        }
    }
}
impl fmt::Display for AlertControlError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Unauthorized => "alert lifecycle authority denied",
            Self::NotAlert => "no retained alert dispatch has this operation identity",
            Self::NotPrepared(_) => {
                "alert is no longer prepared; cancellation cannot erase a possible dispatch"
            }
            Self::ApprovalMismatch => {
                "cancellation approval does not match this preparation, principal and store"
            }
            Self::CancellationMismatch => {
                "the recorded cancellation is not this exact operator request"
            }
            Self::Inconsistent => "alert preparation, receipt and obligation are inconsistent",
            Self::Limit => "alert lifecycle input or inventory bound exceeded",
            Self::Cancelled => "alert cancellation request stopped before commit",
            Self::Contract(_) => "alert cancellation contract refused",
            Self::Deployment(_) => "alert lifecycle deployment authority is unavailable",
            Self::Journal(_) => {
                "cancellation append unresolved; reopen and inspect the existing operation"
            }
        })
    }
}
impl std::error::Error for AlertControlError {}
impl From<ContractError> for AlertControlError {
    fn from(value: ContractError) -> Self {
        Self::Contract(value)
    }
}
impl From<ReferenceError> for AlertControlError {
    fn from(value: ReferenceError) -> Self {
        Self::Deployment(value)
    }
}
impl From<DurableEffectError> for AlertControlError {
    fn from(value: DurableEffectError) -> Self {
        Self::Journal(value)
    }
}

/// Immutable, exact cancellation preview. Its fields cannot be substituted by a caller.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AlertCancellationPlan {
    prepared: PreparedEffect,
    principal: String,
    site: String,
    evidence: ContentDigest,
    proof: ContentDigest,
    approval: ContentDigest,
}
impl AlertCancellationPlan {
    /// Entire preparation, including obligation and its terminal predicate.
    #[must_use]
    pub fn prepared(&self) -> &PreparedEffect {
        &self.prepared
    }
    /// Explicit cancelling actor, not a model or an inferred provider identity.
    #[must_use]
    pub fn principal(&self) -> &str {
        &self.principal
    }
    /// Deployment lineage.
    #[must_use]
    pub fn site(&self) -> &str {
        &self.site
    }
    /// Operator-request evidence reconstructed from the durable reason and site.
    #[must_use]
    pub const fn evidence_digest(&self) -> ContentDigest {
        self.evidence
    }
    /// Expected terminal cancellation proof, not an external delivery receipt.
    #[must_use]
    pub const fn proof_digest(&self) -> ContentDigest {
        self.proof
    }
    /// Exact approval to present together with explicit cancellation capability.
    #[must_use]
    pub const fn approval_digest(&self) -> ContentDigest {
        self.approval
    }
}

/// Whether this invocation appended a cancellation or observed its exact prior commit.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AlertCancellationOutcome {
    /// This invocation durably cancelled the still-prepared operation.
    Cancelled,
    /// This principal's exact cancellation and obligation proof were already durable.
    AlreadyCancelled,
}
impl AlertCancellationOutcome {
    /// Stable report spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Cancelled => "cancelled",
            Self::AlreadyCancelled => "already_cancelled",
        }
    }
}

/// Complete local lifecycle result; never a claim about delivery.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AlertCancellationReceipt {
    /// Exact prepared request which was approved.
    pub plan: AlertCancellationPlan,
    /// Whether a transition was appended in this invocation.
    pub outcome: AlertCancellationOutcome,
    /// Journal-owned terminal operation receipt.
    pub operation: OperationReceipt,
    /// The same operation's journal-owned terminal obligation.
    pub obligation: Obligation,
}

fn checkpoint(cx: &ReplayCx, stage: &'static str) -> Result<(), AlertControlError> {
    cx.checkpoint(stage)
        .map_err(|_| AlertControlError::Cancelled)
}

fn valid_principal(principal: &str) -> bool {
    !principal.is_empty()
        && principal.len() <= MAX_CANCEL_PRINCIPAL_BYTES
        && !principal
            .chars()
            .any(|c| c.is_control() || c.is_whitespace())
        && PrincipalId::parse(principal).is_ok()
}

fn evidence_bytes(site: &str, principal: &str, prepared: &PreparedEffect) -> Vec<u8> {
    let mut e = CanonicalEncoder::new();
    e.text(CANCEL_EVIDENCE_DOMAIN);
    e.text(site);
    e.text(principal);
    e.digest(prepared.prepared_record_digest());
    e.finish()
}

fn authorize(
    deployment: &ReferenceDeployment,
    authority: &ContextAuthority,
    cx: &ReplayCx,
) -> Result<(), AlertControlError> {
    authority.validate()?;
    checkpoint(cx, STAGE_CANCEL_READ)?;
    if !authority.has_capability(CAP_ALERT_CANCEL)
        || authority.cancellation_reason.is_some()
        // This synchronous reference boundary has no independent deadline sampler. Refuse
        // finite-deadline delegation rather than silently treating its lease as unbounded.
        || authority.deadline.is_some()
        || cx.root_dir() != deployment.root()
        || authority.anchor_universe != ContentDigest::sha256(deployment.site_lineage().as_bytes())
        || !valid_principal(&authority.principal)
        || deployment.site_lineage().len() > 256
        || !deployment.ledger().store_pin_is_current()
        || !deployment.effects().store_pin_is_current()
    {
        return Err(AlertControlError::Unauthorized);
    }
    if deployment.effects().committed_len() > MAX_CONTROL_JOURNAL_BYTES {
        return Err(AlertControlError::Limit);
    }
    deployment
        .ledger()
        .verify_durable_head()
        .map_err(|_| AlertControlError::Inconsistent)?;
    // In-memory state must still be exactly the durable prefix owned by this locked handle.
    deployment.effects().committed_roots()?;
    Ok(())
}

fn plan(
    deployment: &ReferenceDeployment,
    operation_id: &OperationId,
    authority: &ContextAuthority,
    cx: &ReplayCx,
) -> Result<(AlertCancellationPlan, OperationReceipt, Obligation), AlertControlError> {
    authorize(deployment, authority, cx)?;
    let journal = deployment.effects();
    if journal.operations().take(MAX_ALERT_OPERATIONS + 1).count() > MAX_ALERT_OPERATIONS
        || journal.obligations().take(MAX_ALERT_OPERATIONS + 1).count() > MAX_ALERT_OPERATIONS
    {
        return Err(AlertControlError::Limit);
    }
    let operation = journal
        .operation(operation_id)
        .ok_or(AlertControlError::NotAlert)?
        .clone();
    if operation.intent.effect_class != "alert.dispatch" {
        return Err(AlertControlError::NotAlert);
    }
    let prepared = journal.effect_journal().prepared_record(operation_id)?;
    let obligation = journal
        .obligation(&prepared.obligation_id)
        .ok_or(AlertControlError::Inconsistent)?
        .clone();
    if prepared.intent != operation.intent
        || obligation.operation_id != *operation_id
        || journal
            .obligations()
            .filter(|o| o.operation_id == *operation_id)
            .count()
            != 1
    {
        return Err(AlertControlError::Inconsistent);
    }
    let ledger_pin = deployment
        .ledger()
        .store_pin()
        .ok_or(AlertControlError::Unauthorized)?;
    let journal_pin = journal.store_pin().ok_or(AlertControlError::Unauthorized)?;
    let evidence = ContentDigest::sha256(&evidence_bytes(
        deployment.site_lineage(),
        &authority.principal,
        &prepared,
    ));
    let proof = EffectCancellationRecord::for_prepared(&prepared, evidence).proof_digest();
    let mut e = CanonicalEncoder::new();
    e.text(CANCEL_APPROVAL_DOMAIN);
    e.text(deployment.site_lineage());
    e.text(&authority.principal);
    e.digest(prepared.prepared_record_digest());
    operation.authority.encode_canonical(&mut e);
    e.digest(ledger_pin);
    e.digest(journal_pin);
    e.digest(proof);
    let approval = ContentDigest::sha256(&e.finish());
    let result = AlertCancellationPlan {
        prepared,
        principal: authority.principal.clone(),
        site: deployment.site_lineage().to_owned(),
        evidence,
        proof,
        approval,
    };
    match operation.state {
        EffectState::Prepared
            if operation.committed_at.is_none()
                && operation.result_digest.is_none()
                && operation.updated_at == operation.prepared_at
                && operation.error_code.is_none()
                && operation.indeterminate_reason.is_none()
                && obligation.state == ObligationState::Pending
                && obligation.proof_digest.is_none() => {}
        EffectState::Cancelled if exact_cancel(&result, &operation, &obligation) => {}
        EffectState::Cancelled => return Err(AlertControlError::CancellationMismatch),
        EffectState::Prepared => return Err(AlertControlError::Inconsistent),
        other => return Err(AlertControlError::NotPrepared(other)),
    }
    Ok((result, operation, obligation))
}

fn exact_cancel(plan: &AlertCancellationPlan, op: &OperationReceipt, ob: &Obligation) -> bool {
    op.state == EffectState::Cancelled
        && op.committed_at.is_none()
        && op.updated_at > op.prepared_at
        && op.indeterminate_reason.is_none()
        && op.result_digest == Some(plan.proof)
        && op.error_code.as_deref() == Some(format!("{REASON_PREFIX}{}", plan.principal).as_str())
        && ob.state == ObligationState::Cancelled
        && ob.operation_id == op.intent.operation_id
        && ob.obligation_id == plan.prepared.obligation_id
        && ob.proof_digest == Some(plan.proof)
}

/// Preview exactly one cancellation. This function writes nothing and does not contact a relay.
/// The caller owns the locked deployment; opening it may already have performed restart recovery.
pub fn preview_alert_cancellation(
    deployment: &ReferenceDeployment,
    operation_id: &OperationId,
    authority: &ContextAuthority,
    cx: &ReplayCx,
) -> Result<AlertCancellationPlan, AlertControlError> {
    plan(deployment, operation_id, authority, cx).map(|(plan, _, _)| plan)
}

/// Recompute the immutable approval and live operation state, then append one v3 cancellation.
/// The supplied time is an explicit journal admission time, not a physical observation. No
/// fallible work is performed after the durable transition. A cold exact retry appends nothing.
pub fn cancel_prepared_alert(
    deployment: &mut ReferenceDeployment,
    operation_id: &OperationId,
    approval: ContentDigest,
    now: TimestampNs,
    authority: &ContextAuthority,
    cx: &ReplayCx,
) -> Result<AlertCancellationReceipt, AlertControlError> {
    let (plan, operation, mut obligation) = plan(deployment, operation_id, authority, cx)?;
    if approval != plan.approval {
        return Err(AlertControlError::ApprovalMismatch);
    }
    if operation.state == EffectState::Cancelled {
        verify_request_custody(deployment, &plan)?;
        return Ok(AlertCancellationReceipt {
            plan,
            outcome: AlertCancellationOutcome::AlreadyCancelled,
            operation,
            obligation,
        });
    }
    let reason = format!("{REASON_PREFIX}{}", plan.principal);
    deployment.effects().effect_journal().validate_cancel(
        operation_id,
        now,
        plan.evidence,
        Some(&reason),
    )?;
    checkpoint(cx, STAGE_CANCEL_REVALIDATED)?;
    publish_request(deployment, &plan, cx)?;
    checkpoint(cx, STAGE_CANCEL_REQUEST_PUBLISHED)?;
    let operation = deployment
        .effects_and_ledger()
        .0
        .cancel(operation_id, now, plan.evidence, Some(reason))?
        .clone();
    // The same core transition atomically installs this obligation state; constructing the
    // already-validated receipt here cannot fail after a successful durable append.
    obligation.state = ObligationState::Cancelled;
    obligation.proof_digest = Some(plan.proof);
    cx.checkpoint_post_commit(STAGE_CANCEL_COMMITTED);
    Ok(AlertCancellationReceipt {
        plan,
        outcome: AlertCancellationOutcome::Cancelled,
        operation,
        obligation,
    })
}

/// Situation compilation admits this new proof only from the same journal-owned prepared
/// record and a ledger-grounded alert plan. An arbitrary reason or actor substitution cannot
/// stand in for the exact full-preparation cancellation proof. This is local runtime evidence,
/// not an authenticated signature from the operator or an independent provider observation.
pub(crate) fn operator_cancellation_is_bound(
    proof: ContentDigest,
    reason: Option<&str>,
    prepared: &PreparedEffect,
    plan: &ReferenceAlertPlan,
    authority: &DurableReferenceLedger,
) -> bool {
    let Some(principal) = reason.and_then(|text| text.strip_prefix(REASON_PREFIX)) else {
        return false;
    };
    if !valid_principal(principal)
        || prepared.intent != plan.intent
        || prepared.intent.effect_class != "alert.dispatch"
        || authority.current().anchor.site_lineage != plan.authority_anchor.site_lineage
    {
        return false;
    }
    let grounded = authority.batches().iter().any(|batch| {
        batch.new_anchor == plan.authority_anchor
            && batch.deltas.iter().any(|delta| {
                delta.family == "event_revision"
                    && delta.payload_digest == plan.event_root
                    && delta.witness_digest == Some(plan.event_revision_digest)
            })
    });
    let request = ContentDigest::sha256(&evidence_bytes(
        &plan.authority_anchor.site_lineage,
        principal,
        prepared,
    ));
    grounded
        && request_is_ledgered(authority, request)
        && EffectCancellationRecord::for_prepared(prepared, request).proof_digest() == proof
}

// A retained request is not a completed cancellation. The v3 journal transition alone retires
// the operation; the root-last request provides the independently checked cause of that transition.
fn request_is_ledgered(authority: &DurableReferenceLedger, request: ContentDigest) -> bool {
    authority.batches().iter().any(|batch| {
        batch.children.contains(&request)
            && batch
                .deltas
                .iter()
                .any(|d| d.family == ROOT_REACHABILITY_FAMILY)
    })
}

fn request_slot(plan: &AlertCancellationPlan) -> Result<SlotName, AlertControlError> {
    let hex: String = plan
        .proof
        .bytes()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    SlotName::parse(&format!("alert-cancel-{hex}")).map_err(|_| AlertControlError::Inconsistent)
}

fn verify_request_custody(
    deployment: &ReferenceDeployment,
    plan: &AlertCancellationPlan,
) -> Result<(), AlertControlError> {
    if !request_is_ledgered(deployment.ledger(), plan.evidence) {
        return Err(AlertControlError::Inconsistent);
    }
    let bytes = deployment
        .publisher()
        .spool()
        .read(plan.evidence)
        .map_err(|_| AlertControlError::Inconsistent)?;
    if bytes != evidence_bytes(&plan.site, &plan.principal, &plan.prepared)
        || ContentDigest::sha256(&bytes) != plan.evidence
    {
        return Err(AlertControlError::Inconsistent);
    }
    Ok(())
}

fn publish_request(
    deployment: &mut ReferenceDeployment,
    plan: &AlertCancellationPlan,
    cx: &ReplayCx,
) -> Result<(), AlertControlError> {
    if request_is_ledgered(deployment.ledger(), plan.evidence) {
        return verify_request_custody(deployment, plan);
    }
    let bytes = evidence_bytes(&plan.site, &plan.principal, &plan.prepared);
    let slot = request_slot(plan)?;
    let _staged = deployment.stage_and_publish(&slot, &[bytes.as_slice()], cx)?;
    let manifest = ObjectManifest::new(slot.as_str(), vec![plan.evidence], None)
        .map_err(ReferenceError::from)?;
    // Validity names the preparation being retired, not a guessed request wall time. Keeping
    // this target scope immutable also makes recovery of an interrupted publication exact.
    let validity = CaptureInterval::new(plan.prepared.prepared_at, plan.prepared.prepared_at)?;
    deployment.publish_and_commit(&slot, &manifest, validity, cx)?;
    verify_request_custody(deployment, plan)
}

#[cfg(test)]
mod tests;
