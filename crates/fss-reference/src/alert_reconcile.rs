#![forbid(unsafe_code)]
//! Owner-attested reconciliation of one dispatched alert, addressed by operation identity.
//!
//! A webhook relay's 2xx proves relay acceptance only, and a lost acknowledgement leaves the
//! operation indeterminate; no provider lookup exists for webhook relays. The alert's terminal
//! obligation ("provider delivery is independently reconciled") can therefore only be discharged
//! by an observation independent of the relay: here, the owner's attestation that the alert was,
//! or was not, received, citing an evidence digest (for example the digest of the received
//! notification or of the recipient's confirmation). The attestation is `operator_asserted`
//! provenance, never a provider receipt, and every answer says so.
//!
//! **Order.** The attestation record is published root-last to the authority ledger first; only
//! then does the effect journal transition: `delivered` moves `adapter_accepted`/`indeterminate`
//! to `observed` with the attestation digest as its observation, then to `verified` with the same
//! digest as terminal proof; `not_delivered` moves `committed`/`adapter_accepted`/`indeterminate`
//! to `failed` with the attestation as proof. A crash between the two `delivered` records leaves
//! the operation `observed` under this exact attestation and an exact retry completes it.
//!
//! **Approval.** The approval binds the deployment, the attesting principal, the whole
//! preparation, the effect authority, both physical store pins, the attestation, and the exact
//! current receipt, so any state change in between makes the approval stale. Approval is never
//! a resend: no network I/O happens here.

use std::fmt;

use fss_core::{
    CanonicalDecoder, CanonicalEncode, CanonicalEncoder, CaptureInterval, ContentDigest,
    ContextAuthority, ContractError, EffectState, Obligation, OperationId, OperationReceipt,
    PreparedEffect, PrincipalId, TimestampNs,
};
use fss_object::ObjectManifest;
use fss_publication::{ROOT_REACHABILITY_FAMILY, SlotName};

use crate::alert_control::MAX_CONTROL_JOURNAL_BYTES;
use crate::{DurableEffectError, ReferenceDeployment, ReferenceError, ReplayCx};

/// Capability an owner needs to reconcile an effect (the registered commit row).
pub const CAP_ALERT_RECONCILE: &str = "CAP-AGENT-PLAN-COMMIT-001";
/// Canonical attestation record, published root-last before any journal transition.
pub const RECONCILE_EVIDENCE_DOMAIN: &str = "fss.alert_operator_reconciliation_evidence.v1";
/// Exact owner approval of one reconciliation; not a grant of authority by itself.
pub const RECONCILE_APPROVAL_DOMAIN: &str = "fss.alert_operator_reconciliation_approval.v1";
/// Largest attestation statement.
pub const MAX_RECONCILE_STATEMENT_BYTES: usize = 1024;
const STAGE_READ: &str = "alert_reconcile:read";
const STAGE_REVALIDATED: &str = "alert_reconcile:revalidated";
const STAGE_PUBLISHED: &str = "alert_reconcile:request_published";
const STAGE_COMMITTED: &str = "alert_reconcile:committed";
const FAILED_REASON_PREFIX: &str = "operator_reconciled_not_delivered:";

/// What the owner attests about the alert's delivery.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AlertReconciliationOutcome {
    /// The alert reached its human recipient.
    Delivered,
    /// The alert did not reach its human recipient.
    NotDelivered,
}

impl AlertReconciliationOutcome {
    /// Stable spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Delivered => "delivered",
            Self::NotDelivered => "not_delivered",
        }
    }
}

/// Narrow, secret-free failures. None of them permits a resend.
#[derive(Debug)]
pub enum AlertReconcileError {
    /// Explicit context authority does not grant reconciliation on this deployment.
    Unauthorized,
    /// The operation is absent or is not an alert dispatch.
    NotAlert,
    /// The operation's state cannot take this reconciliation (never dispatched, already
    /// terminal under different proof, or an outcome the state machine forbids).
    NotReconcilable(EffectState),
    /// The approval belongs to another attestation, state, actor, or physical store.
    ApprovalMismatch,
    /// The attestation statement or principal is out of bounds.
    InvalidAttestation,
    /// Preparation, receipt and obligation disagree.
    Inconsistent,
    /// The live context was cancelled before the journal transition.
    Cancelled,
    /// Shared semantic contract refused the request.
    Contract(ContractError),
    /// Deployment or authority custody could not be verified.
    Deployment(ReferenceError),
    /// The durable journal refused the append; reopen and inspect.
    Journal(DurableEffectError),
}

impl AlertReconcileError {
    /// Registered stable identity.
    #[must_use]
    pub const fn stable_id(&self) -> &'static str {
        match self {
            Self::Unauthorized => "ERR-AUTH-DENIED-001",
            Self::ApprovalMismatch => "ERR-ALERT-APPROVAL-STALE-001",
            Self::NotAlert | Self::Inconsistent | Self::Deployment(_) => "ERR-ALERT-AUTHORITY-001",
            Self::NotReconcilable(_) | Self::InvalidAttestation => "ERR-OP-PRECONDITION-FAILED-001",
            Self::Cancelled | Self::Contract(_) | Self::Journal(_) => "ERR-ALERT-DISPATCH-001",
        }
    }
}

impl fmt::Display for AlertReconcileError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unauthorized => f.write_str("alert reconciliation authority denied"),
            Self::NotAlert => f.write_str("no retained alert dispatch has this operation identity"),
            Self::NotReconcilable(state) => write!(
                f,
                "an operation in state {} cannot take this reconciliation",
                state.as_str()
            ),
            Self::ApprovalMismatch => f.write_str(
                "reconciliation approval does not match this attestation, state, principal and \
                 store",
            ),
            Self::InvalidAttestation => f.write_str("the attestation is out of bounds"),
            Self::Inconsistent => {
                f.write_str("alert preparation, receipt and obligation are inconsistent")
            }
            Self::Cancelled => f.write_str("alert reconciliation stopped before commit"),
            Self::Contract(_) => f.write_str("alert reconciliation contract refused"),
            Self::Deployment(_) => f.write_str("alert reconciliation deployment is unavailable"),
            Self::Journal(_) => f.write_str(
                "reconciliation append unresolved; reopen and inspect the existing operation",
            ),
        }
    }
}

impl std::error::Error for AlertReconcileError {}

impl From<ContractError> for AlertReconcileError {
    fn from(value: ContractError) -> Self {
        Self::Contract(value)
    }
}
impl From<ReferenceError> for AlertReconcileError {
    fn from(value: ReferenceError) -> Self {
        Self::Deployment(value)
    }
}
impl From<DurableEffectError> for AlertReconcileError {
    fn from(value: DurableEffectError) -> Self {
        Self::Journal(value)
    }
}

/// The owner's attestation about one alert's delivery.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AlertAttestation {
    /// Attested outcome.
    pub outcome: AlertReconciliationOutcome,
    /// Digest of the owner's evidence (never the evidence bytes themselves).
    pub evidence: ContentDigest,
    /// Short owner statement, verbatim.
    pub statement: String,
}

/// Immutable, exact reconciliation preview.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AlertReconciliationPlan {
    prepared: PreparedEffect,
    principal: String,
    site: String,
    attestation: AlertAttestation,
    observed: ContentDigest,
    record: ContentDigest,
    approval: ContentDigest,
}

impl AlertReconciliationPlan {
    /// The whole preparation being reconciled.
    #[must_use]
    pub const fn prepared(&self) -> &PreparedEffect {
        &self.prepared
    }
    /// Attesting principal.
    #[must_use]
    pub fn principal(&self) -> &str {
        &self.principal
    }
    /// The attestation.
    #[must_use]
    pub const fn attestation(&self) -> &AlertAttestation {
        &self.attestation
    }
    /// Digest of the receipt the attestation was made against.
    #[must_use]
    pub const fn observed_receipt(&self) -> ContentDigest {
        self.observed
    }
    /// Digest of the attestation record: the observation and terminal proof the journal binds.
    #[must_use]
    pub const fn record_digest(&self) -> ContentDigest {
        self.record
    }
    /// Exact approval to present together with the reconciliation capability.
    #[must_use]
    pub const fn approval_digest(&self) -> ContentDigest {
        self.approval
    }
}

/// Whether this invocation appended the reconciliation or observed its exact prior commit.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AlertReconcileOutcome {
    /// This invocation durably reconciled the operation.
    Reconciled,
    /// This exact reconciliation was already durable.
    AlreadyReconciled,
}

impl AlertReconcileOutcome {
    /// Stable spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Reconciled => "reconciled",
            Self::AlreadyReconciled => "already_reconciled",
        }
    }
}

/// Complete reconciliation result.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AlertReconcileReceipt {
    /// The approved plan.
    pub plan: AlertReconciliationPlan,
    /// Whether a transition was appended now.
    pub outcome: AlertReconcileOutcome,
    /// Journal-owned terminal receipt.
    pub operation: OperationReceipt,
    /// The terminal obligation.
    pub obligation: Obligation,
}

fn checkpoint(cx: &ReplayCx, stage: &'static str) -> Result<(), AlertReconcileError> {
    cx.checkpoint(stage)
        .map_err(|_| AlertReconcileError::Cancelled)
}

fn record_bytes(
    site: &str,
    principal: &str,
    prepared: &PreparedEffect,
    attestation: &AlertAttestation,
    observed: ContentDigest,
) -> Vec<u8> {
    let mut e = CanonicalEncoder::new();
    e.text(RECONCILE_EVIDENCE_DOMAIN);
    e.text(site);
    e.text(principal);
    e.digest(prepared.prepared_record_digest());
    e.text(attestation.outcome.as_str());
    e.digest(attestation.evidence);
    e.text(&attestation.statement);
    e.digest(observed);
    e.finish()
}

/// The receipt digest a retained record of exactly this attestation was made against.
fn recorded_observation(
    bytes: &[u8],
    site: &str,
    principal: &str,
    prepared: &PreparedEffect,
    attestation: &AlertAttestation,
) -> Option<ContentDigest> {
    let mut d = CanonicalDecoder::new(bytes);
    let matches = d.text().ok()? == RECONCILE_EVIDENCE_DOMAIN
        && d.text().ok()? == site
        && d.text().ok()? == principal
        && d.digest().ok()? == prepared.prepared_record_digest()
        && d.text().ok()? == attestation.outcome.as_str()
        && d.digest().ok()? == attestation.evidence
        && d.text().ok()? == attestation.statement;
    let observed = d.digest().ok()?;
    (matches && d.ensure_finished().is_ok()).then_some(observed)
}

fn authorize(
    deployment: &ReferenceDeployment,
    authority: &ContextAuthority,
    cx: &ReplayCx,
) -> Result<(), AlertReconcileError> {
    authority.validate()?;
    checkpoint(cx, STAGE_READ)?;
    if !authority.has_capability(CAP_ALERT_RECONCILE)
        || authority.cancellation_reason.is_some()
        || authority.deadline.is_some()
        || cx.root_dir() != deployment.root()
        || authority.anchor_universe != ContentDigest::sha256(deployment.site_lineage().as_bytes())
        || PrincipalId::parse(&authority.principal).is_err()
        || authority.principal.len() > 96
        || !deployment.ledger().store_pin_is_current()
        || !deployment.effects().store_pin_is_current()
    {
        return Err(AlertReconcileError::Unauthorized);
    }
    if deployment.effects().committed_len() > MAX_CONTROL_JOURNAL_BYTES {
        return Err(AlertReconcileError::Inconsistent);
    }
    deployment
        .ledger()
        .verify_durable_head()
        .map_err(|_| AlertReconcileError::Inconsistent)?;
    deployment.effects().committed_roots()?;
    Ok(())
}

/// The attestation-bearing receipt a retry must match: the pre-transition receipt is the one
/// bound into the record, so a retry recomputes against it, not against the reconciled state.
fn plan(
    deployment: &ReferenceDeployment,
    operation_id: &OperationId,
    attestation: &AlertAttestation,
    observed: Option<ContentDigest>,
    authority: &ContextAuthority,
    cx: &ReplayCx,
) -> Result<(AlertReconciliationPlan, OperationReceipt, Obligation), AlertReconcileError> {
    authorize(deployment, authority, cx)?;
    if attestation.statement.is_empty()
        || attestation.statement.len() > MAX_RECONCILE_STATEMENT_BYTES
        || attestation.statement.chars().any(char::is_control)
    {
        return Err(AlertReconcileError::InvalidAttestation);
    }
    let journal = deployment.effects();
    let operation = journal
        .operation(operation_id)
        .ok_or(AlertReconcileError::NotAlert)?
        .clone();
    if operation.intent.effect_class != "alert.dispatch" {
        return Err(AlertReconcileError::NotAlert);
    }
    let prepared = journal.effect_journal().prepared_record(operation_id)?;
    let obligation = journal
        .obligation(&prepared.obligation_id)
        .ok_or(AlertReconcileError::Inconsistent)?
        .clone();
    if prepared.intent != operation.intent || obligation.operation_id != *operation_id {
        return Err(AlertReconcileError::Inconsistent);
    }
    let observed = observed.unwrap_or_else(|| operation.receipt_digest());
    let site = deployment.site_lineage().to_owned();
    let record = ContentDigest::sha256(&record_bytes(
        &site,
        &authority.principal,
        &prepared,
        attestation,
        observed,
    ));
    let ledger_pin = deployment
        .ledger()
        .store_pin()
        .ok_or(AlertReconcileError::Unauthorized)?;
    let journal_pin = journal
        .store_pin()
        .ok_or(AlertReconcileError::Unauthorized)?;
    let mut e = CanonicalEncoder::new();
    e.text(RECONCILE_APPROVAL_DOMAIN);
    e.text(&site);
    e.text(&authority.principal);
    e.digest(prepared.prepared_record_digest());
    operation.authority.encode_canonical(&mut e);
    e.digest(ledger_pin);
    e.digest(journal_pin);
    e.digest(record);
    let approval = ContentDigest::sha256(&e.finish());
    Ok((
        AlertReconciliationPlan {
            prepared,
            principal: authority.principal.clone(),
            site,
            attestation: attestation.clone(),
            observed,
            record,
            approval,
        },
        operation,
        obligation,
    ))
}

fn startable(outcome: AlertReconciliationOutcome, state: EffectState) -> bool {
    match outcome {
        AlertReconciliationOutcome::Delivered => {
            matches!(
                state,
                EffectState::AdapterAccepted | EffectState::Indeterminate
            )
        }
        AlertReconciliationOutcome::NotDelivered => matches!(
            state,
            EffectState::Committed | EffectState::AdapterAccepted | EffectState::Indeterminate
        ),
    }
}

fn request_is_ledgered(deployment: &ReferenceDeployment, record: ContentDigest) -> bool {
    deployment.ledger().batches().iter().any(|batch| {
        batch.children.contains(&record)
            && batch
                .deltas
                .iter()
                .any(|delta| delta.family == ROOT_REACHABILITY_FAMILY)
    })
}

/// Previews exactly one reconciliation. Writes nothing and contacts nothing.
pub fn preview_alert_reconciliation(
    deployment: &ReferenceDeployment,
    operation_id: &OperationId,
    attestation: &AlertAttestation,
    authority: &ContextAuthority,
    cx: &ReplayCx,
) -> Result<AlertReconciliationPlan, AlertReconcileError> {
    let (plan, operation, _) = plan(deployment, operation_id, attestation, None, authority, cx)?;
    if !startable(attestation.outcome, operation.state) {
        return Err(AlertReconcileError::NotReconcilable(operation.state));
    }
    Ok(plan)
}

/// Recomputes the approval against the live state, publishes the attestation root-last, then
/// appends the journal transitions. An exact retry (including after a crash between the two
/// `delivered` transitions) completes or observes the same reconciliation.
pub fn reconcile_alert_operation(
    deployment: &mut ReferenceDeployment,
    operation_id: &OperationId,
    attestation: &AlertAttestation,
    approval: ContentDigest,
    now: TimestampNs,
    authority: &ContextAuthority,
    cx: &ReplayCx,
) -> Result<AlertReconcileReceipt, AlertReconcileError> {
    let (live, operation, _) = plan(deployment, operation_id, attestation, None, authority, cx)?;
    // Resume or observe: an earlier attempt of this exact attestation left a newer state.
    if !startable(attestation.outcome, operation.state) {
        return resume(
            deployment,
            operation_id,
            attestation,
            approval,
            now,
            authority,
            cx,
        );
    }
    if approval != live.approval {
        return Err(AlertReconcileError::ApprovalMismatch);
    }
    checkpoint(cx, STAGE_REVALIDATED)?;
    publish_record(deployment, &live, cx)?;
    checkpoint(cx, STAGE_PUBLISHED)?;
    complete(deployment, &live, now, cx)
}

fn resume(
    deployment: &mut ReferenceDeployment,
    operation_id: &OperationId,
    attestation: &AlertAttestation,
    approval: ContentDigest,
    now: TimestampNs,
    authority: &ContextAuthority,
    cx: &ReplayCx,
) -> Result<AlertReconcileReceipt, AlertReconcileError> {
    let operation = deployment
        .effects()
        .operation(operation_id)
        .cloned()
        .ok_or(AlertReconcileError::NotAlert)?;
    // Only a ledgered record of exactly this attestation, which the journal now binds as its
    // observation or terminal proof, is admitted as an earlier attempt of this request.
    let bound = operation
        .result_digest
        .filter(|digest| request_is_ledgered(deployment, *digest))
        .ok_or(AlertReconcileError::NotReconcilable(operation.state))?;
    let bytes = deployment
        .publisher()
        .spool()
        .read(bound)
        .map_err(|_| AlertReconcileError::Inconsistent)?;
    let prepared = deployment
        .effects()
        .effect_journal()
        .prepared_record(operation_id)?;
    let observed = recorded_observation(
        &bytes,
        deployment.site_lineage(),
        &authority.principal,
        &prepared,
        attestation,
    )
    .ok_or(AlertReconcileError::NotReconcilable(operation.state))?;
    let (plan, current, obligation) = plan(
        deployment,
        operation_id,
        attestation,
        Some(observed),
        authority,
        cx,
    )?;
    if plan.record != bound || plan.approval != approval {
        return Err(AlertReconcileError::ApprovalMismatch);
    }
    match (attestation.outcome, current.state) {
        (AlertReconciliationOutcome::Delivered, EffectState::Observed) => {
            complete(deployment, &plan, now, cx)
        }
        (AlertReconciliationOutcome::Delivered, EffectState::Verified)
        | (AlertReconciliationOutcome::NotDelivered, EffectState::Failed) => {
            Ok(AlertReconcileReceipt {
                plan,
                outcome: AlertReconcileOutcome::AlreadyReconciled,
                operation: current,
                obligation,
            })
        }
        (_, state) => Err(AlertReconcileError::NotReconcilable(state)),
    }
}

fn publish_record(
    deployment: &mut ReferenceDeployment,
    plan: &AlertReconciliationPlan,
    cx: &ReplayCx,
) -> Result<(), AlertReconcileError> {
    let bytes = record_bytes(
        &plan.site,
        &plan.principal,
        &plan.prepared,
        &plan.attestation,
        plan.observed,
    );
    if request_is_ledgered(deployment, plan.record) {
        return Ok(());
    }
    let hex: String = plan
        .record
        .bytes()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    let slot = SlotName::parse(&format!("alert-reconcile-{hex}"))
        .map_err(|_| AlertReconcileError::Inconsistent)?;
    let _staged = deployment.stage_and_publish(&slot, &[bytes.as_slice()], cx)?;
    let manifest = ObjectManifest::new(slot.as_str(), vec![plan.record], None)
        .map_err(ReferenceError::from)?;
    let validity = CaptureInterval::new(plan.prepared.prepared_at, plan.prepared.prepared_at)?;
    deployment.publish_and_commit(&slot, &manifest, validity, cx)?;
    if !request_is_ledgered(deployment, plan.record) {
        return Err(AlertReconcileError::Inconsistent);
    }
    Ok(())
}

fn complete(
    deployment: &mut ReferenceDeployment,
    plan: &AlertReconciliationPlan,
    now: TimestampNs,
    cx: &ReplayCx,
) -> Result<AlertReconcileReceipt, AlertReconcileError> {
    let operation_id = plan.prepared.intent.operation_id.clone();
    let journal = deployment.effects_and_ledger().0;
    let current = journal
        .operation(&operation_id)
        .cloned()
        .ok_or(AlertReconcileError::NotAlert)?;
    let at = |after: TimestampNs| TimestampNs(now.0.max(after.0.saturating_add(1)));
    let operation = match plan.attestation.outcome {
        AlertReconciliationOutcome::Delivered => {
            if current.state != EffectState::Observed {
                journal.transition(
                    &operation_id,
                    EffectState::Observed,
                    at(current.updated_at),
                    Some(plan.record),
                    None,
                )?;
            }
            let observed_at = journal
                .operation(&operation_id)
                .map(|operation| operation.updated_at)
                .ok_or(AlertReconcileError::NotAlert)?;
            journal
                .reconcile_verified(&operation_id, plan.record, at(observed_at))?
                .clone()
        }
        AlertReconciliationOutcome::NotDelivered => journal
            .reconcile_failed(
                &operation_id,
                plan.record,
                at(current.updated_at),
                format!("{FAILED_REASON_PREFIX}{}", plan.principal),
            )?
            .clone(),
    };
    let obligation = journal
        .obligation(&plan.prepared.obligation_id)
        .cloned()
        .ok_or(AlertReconcileError::Inconsistent)?;
    cx.checkpoint_post_commit(STAGE_COMMITTED);
    Ok(AlertReconcileReceipt {
        plan: plan.clone(),
        outcome: AlertReconcileOutcome::Reconciled,
        operation,
        obligation,
    })
}
