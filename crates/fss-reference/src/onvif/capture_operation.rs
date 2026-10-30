#![forbid(unsafe_code)]
//! Optional source-free owner fence for one native PullPoint capture operation.
//!
//! A stable owner ID is consumed at durable preparation, before any Create intent
//! or network dispatch. Only that call's live, non-cloneable guard can commit it.
//! Every existing state refuses another Create, including a Prepared operation
//! left by a crash before dispatch. There is deliberately no resume or reset API.
//!
//! The existing effect journal retains only fixed labels, domain-separated hashes
//! and timestamps. Private ONVIF source deletion cannot erase this fence. The
//! explicit authority principal is a hash of the owner's identity, not system
//! authority. The binding must match the live replay principal; the caller must
//! also admit current capture scope through its ReplayAdmission at this boundary.
//!
//! Committed records dispatch intent, not proof of a sent request or an active
//! remote subscription. Existing ONVIF control custody records own observations.
//! New reservations can bind their exact Create intent before dispatch and later
//! reconcile a retained successful cleanup into a terminal journal obligation.

mod reconciliation;
pub use reconciliation::{
    CLEANUP_PROOF_DOMAIN, CaptureCleanupEvidence, STAGE_CLEANUP_ACCEPTED, STAGE_CLEANUP_OBSERVED,
    STAGE_CLEANUP_RECONCILED, STAGE_CLEANUP_REVALIDATED, reconcile_cleanup,
};

use std::fmt;

use fss_core::effect::EffectAuthority;
use fss_core::{
    CanonicalEncoder, ContentDigest, ContractError, DigestAlgorithm, EffectIntent, EffectState,
    IdempotencyKey, ObligationId, ObligationState, OperationId, OperationReceipt, TimestampNs,
};

use super::control::{CreateIntentBinding, RetainedCreateIntent};
use crate::{DurableEffectError, ReferenceDeployment, ReplayAdmission, ReplayCx};

/// Canonical identity binds site lineage and the owner-provided operation ID only.
pub const KEY_DOMAIN: &str = "fss.onvif_capture_operation_key.v1";
/// Privacy-preserving owner principal identity; this hash grants no authority.
pub const PRINCIPAL_DOMAIN: &str = "fss.onvif_capture_operation_principal.v1";
/// Effect class reserved for this native capture owner.
pub const EFFECT_CLASS: &str = "onvif.pullpoint.capture";
/// Legacy unbound obligation predicate. Its historical records cannot be reconciled here.
pub const TERMINAL_PREDICATE: &str = "onvif.capture.control_reconciled";
/// An exact Create identity follows this prefix in a new bound obligation predicate.
pub const BOUND_TERMINAL_PREDICATE: &str = "onvif.capture.control_reconciled.v2:";
/// Maximum verified effect-journal history at this synchronous boundary.
pub const MAX_JOURNAL_BYTES: u64 = 64 * 1024 * 1024;
/// Maximum operation/obligation history inspected by this owner.
pub const MAX_OPERATIONS: usize = 65_536;
/// Last admission before the durable reservation.
pub const STAGE_PREPARE: &str = "onvif_capture_operation:prepare";
/// Admission after reservation; refusal leaves the ID consumed without a guard.
pub const STAGE_PREPARED: &str = "onvif_capture_operation:prepared";
/// Last admission before durable dispatch commitment.
pub const STAGE_COMMIT: &str = "onvif_capture_operation:commit";
/// Admission after commitment; refusal leaves dispatch fenced and the ID consumed.
pub const STAGE_COMMITTED: &str = "onvif_capture_operation:committed";

/// Stable owner request identity, excluding nonce and process-local clock samples.
///
/// The caller hashes normalized effective configuration, including actual owner,
/// route, attribution, authentication locator and bounds into these digests. It
/// must exclude receive origin, fresh message IDs and monotonic start time. The
/// raw principal and owner ID remain in memory only; no credential bytes belong
/// in either digest input or in this binding.
#[derive(Clone, Eq, PartialEq)]
pub struct CaptureOperationBinding {
    /// Owner-provided ID, stable across retries of the same intended capture.
    pub operation_id: OperationId,
    /// Actual admitted owner label, hashed before durable storage.
    pub principal: String,
    /// Canonical normalized capture configuration and bound owner identity.
    pub request_digest: ContentDigest,
    /// Exact owner, sensor/device/profile, authority and generation pins.
    pub precondition_digest: ContentDigest,
}

impl fmt::Debug for CaptureOperationBinding {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CaptureOperationBinding")
            .field("request_digest", &self.request_digest)
            .field("precondition_digest", &self.precondition_digest)
            .finish_non_exhaustive()
    }
}

/// Verified historical operation state; never a grant to send or resume Create.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CaptureOperationInspection {
    /// Supplied lookup ID; never read from or retained in the journal.
    pub owner_operation_id: OperationId,
    /// Domain-separated internal ID shared by every attempted use of that owner ID.
    pub internal_operation_id: OperationId,
    /// Exact durable state and hashed explicit owner authority.
    pub receipt: OperationReceipt,
    /// Deterministic obligation opened by the original reservation.
    pub obligation_id: ObligationId,
    /// Exact Create intent pinned before dispatch; absent only for legacy reservations.
    pub create_intent: Option<ContentDigest>,
    /// Current durable obligation state, distinct from dispatch or current remote state.
    pub obligation_state: ObligationState,
    /// Journal-owned terminal proof, if this obligation has been reconciled.
    pub proof_digest: Option<ContentDigest>,
    /// Verified current effect-journal root, suitable as an independent minimum pin.
    pub journal_root: ContentDigest,
}

/// One live process's newly reserved operation. Not Clone and not reconstructible.
///
/// Dropping it leaves Prepared durably consumed. A caller must invoke `commit`
/// before returning success from its pre-Create custody hook. Even after commit,
/// current network authority and the exact Create-intent receipt are required.
#[must_use = "dropping the guard leaves the stable operation ID durably consumed"]
pub struct CaptureOperationGuard {
    binding: CaptureOperationBinding,
    prepared: CaptureOperationInspection,
    ledger_store_pin: ContentDigest,
    effect_store_pin: ContentDigest,
    reserved_authority_sequence: u64,
}

impl fmt::Debug for CaptureOperationGuard {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CaptureOperationGuard")
            .field(
                "internal_operation_id",
                &self.prepared.internal_operation_id,
            )
            .field("journal_root", &self.prepared.journal_root)
            .finish_non_exhaustive()
    }
}

/// Payload-free errors; existing/conflicting receipts are explicitly inspectable.
pub enum CaptureOperationError {
    /// Invalid, empty, oversized or non-SHA-256 binding.
    InvalidBinding,
    /// Current root, owner admission or restored-copy effect authority was refused.
    Authority,
    /// Same binding has already consumed this ID, in any durable state.
    Existing(Box<CaptureOperationInspection>),
    /// This ID was consumed under a different principal, request or precondition.
    Conflict(Box<CaptureOperationInspection>),
    /// No typed operation exists at this owner key.
    Unavailable,
    /// Store identity, typed ownership or complete durable history is inconsistent.
    Custody,
    /// Independently saved minimum root is absent from the verified history.
    Minimum,
    /// Bounded history inspection exceeded its limits.
    Limit,
    /// Canonical identity or typed state was refused.
    Contract(ContractError),
    /// A journal operation failed; it may have committed before acknowledgement loss.
    Journal(Box<DurableEffectError>),
}

impl CaptureOperationError {
    /// Stable payload-free identifier, safe for native CLI reports.
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::InvalidBinding => "ERR-ONVIF-CAPTURE-OPERATION-BINDING-001",
            Self::Authority => "ERR-ONVIF-CAPTURE-OPERATION-AUTHORITY-001",
            Self::Existing(_) => "ERR-ONVIF-CAPTURE-OPERATION-EXISTING-001",
            Self::Conflict(_) => "ERR-ONVIF-CAPTURE-OPERATION-CONFLICT-001",
            Self::Unavailable => "ERR-ONVIF-CAPTURE-OPERATION-UNAVAILABLE-001",
            Self::Custody => "ERR-ONVIF-CAPTURE-OPERATION-CUSTODY-001",
            Self::Minimum => "ERR-ONVIF-CAPTURE-OPERATION-MINIMUM-001",
            Self::Limit => "ERR-ONVIF-CAPTURE-OPERATION-LIMIT-001",
            Self::Contract(_) => "ERR-ONVIF-CAPTURE-OPERATION-CONTRACT-001",
            Self::Journal(_) => "ERR-ONVIF-CAPTURE-OPERATION-JOURNAL-001",
        }
    }
}
impl fmt::Debug for CaptureOperationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.code())
    }
}
impl fmt::Display for CaptureOperationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.code())
    }
}
impl std::error::Error for CaptureOperationError {}
impl From<ContractError> for CaptureOperationError {
    fn from(error: ContractError) -> Self {
        Self::Contract(error)
    }
}
impl From<DurableEffectError> for CaptureOperationError {
    fn from(error: DurableEffectError) -> Self {
        Self::Journal(Box::new(error))
    }
}

struct Keys {
    operation_id: OperationId,
    idempotency_key: IdempotencyKey,
    obligation_id: ObligationId,
    capability: String,
}

/// Derives the same key even when the caller changes principal or configuration.
pub fn operation_key(
    site: &str,
    owner_operation_id: &OperationId,
) -> Result<OperationId, CaptureOperationError> {
    Ok(keys(site, owner_operation_id)?.operation_id)
}

fn keys(site: &str, owner_operation_id: &OperationId) -> Result<Keys, CaptureOperationError> {
    if !valid_label(site) || owner_operation_id.as_str().len() > 256 {
        return Err(CaptureOperationError::InvalidBinding);
    }
    let mut encoder = CanonicalEncoder::new();
    encoder.text(KEY_DOMAIN);
    encoder.text(site);
    encoder.text(owner_operation_id.as_str());
    let digest = ContentDigest::sha256(&encoder.finish_checked()?);
    let text = digest.to_text();
    let suffix = text
        .strip_prefix("sha256:")
        .ok_or(CaptureOperationError::Custody)?;
    Ok(Keys {
        operation_id: OperationId::parse(format!("operation:onvif-capture:{suffix}"))?,
        idempotency_key: IdempotencyKey::parse(format!("idempotency:onvif-capture:{suffix}"))?,
        obligation_id: ObligationId::parse(format!("obligation:onvif-capture:{suffix}"))?,
        capability: format!("onvif:capture:{suffix}"),
    })
}

fn valid_label(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 256
        && value.trim() == value
        && !value.chars().any(char::is_control)
}
fn valid_digest(value: ContentDigest) -> bool {
    value.algorithm() == DigestAlgorithm::Sha256 && value.bytes() != [0; 32]
}
fn validate(binding: &CaptureOperationBinding) -> Result<(), CaptureOperationError> {
    if !valid_label(&binding.principal)
        || !valid_digest(binding.request_digest)
        || !valid_digest(binding.precondition_digest)
    {
        return Err(CaptureOperationError::InvalidBinding);
    }
    Ok(())
}
fn owner_authority(
    binding: &CaptureOperationBinding,
    keys: &Keys,
) -> Result<EffectAuthority, CaptureOperationError> {
    validate(binding)?;
    EffectAuthority::new(
        owner_principal(&binding.principal)?,
        keys.capability.clone(),
        None,
    )
    .map_err(|_| CaptureOperationError::InvalidBinding)
}

fn owner_principal(principal: &str) -> Result<String, CaptureOperationError> {
    if !valid_label(principal) {
        return Err(CaptureOperationError::InvalidBinding);
    }
    let mut encoder = CanonicalEncoder::new();
    encoder.text(PRINCIPAL_DOMAIN);
    encoder.text(principal);
    let digest = ContentDigest::sha256(&encoder.finish_checked()?);
    Ok(format!("principal:onvif-capture:{}", digest.to_text()))
}

fn bound_intent(predicate: &str) -> Result<Option<ContentDigest>, CaptureOperationError> {
    if predicate == TERMINAL_PREDICATE {
        return Ok(None);
    }
    let text = predicate
        .strip_prefix(BOUND_TERMINAL_PREDICATE)
        .ok_or(CaptureOperationError::Custody)?;
    let identity = ContentDigest::parse(text).map_err(|_| CaptureOperationError::Custody)?;
    if !valid_digest(identity) || identity.to_text() != text {
        return Err(CaptureOperationError::Custody);
    }
    Ok(Some(identity))
}

fn checkpoint(
    cx: &ReplayCx<impl ReplayAdmission>,
    stage: &'static str,
) -> Result<(), CaptureOperationError> {
    if !cx.io_authority().is_valid() {
        return Err(CaptureOperationError::Authority);
    }
    cx.checkpoint(stage)
        .map_err(|_| CaptureOperationError::Authority)
}

fn verify_history(
    deployment: &ReferenceDeployment,
    write: bool,
    cx: &ReplayCx<impl ReplayAdmission>,
) -> Result<Vec<ContentDigest>, CaptureOperationError> {
    checkpoint(cx, "onvif_capture_operation:admit")?;
    if cx.root_dir() != deployment.root()
        || !deployment.ledger().store_pin_is_current()
        || !deployment.effects().store_pin_is_current()
    {
        return Err(CaptureOperationError::Authority);
    }
    if write {
        crate::alert::refuse_restored_effect_authority(deployment.ledger())
            .map_err(|_| CaptureOperationError::Authority)?;
    }
    let journal = deployment.effects();
    if journal.committed_len() > MAX_JOURNAL_BYTES
        || std::fs::metadata(journal.path())
            .map_err(|_| CaptureOperationError::Custody)?
            .len()
            > MAX_JOURNAL_BYTES
        || journal.operations().take(MAX_OPERATIONS + 1).count() > MAX_OPERATIONS
        || journal.obligations().take(MAX_OPERATIONS + 1).count() > MAX_OPERATIONS
    {
        return Err(CaptureOperationError::Limit);
    }
    deployment
        .ledger()
        .verify_durable_head()
        .map_err(|_| CaptureOperationError::Custody)?;
    let roots = journal.committed_roots()?;
    checkpoint(cx, "onvif_capture_operation:history_verified")?;
    Ok(roots)
}

fn inspection(
    deployment: &ReferenceDeployment,
    owner_operation_id: &OperationId,
    expected: Option<&CaptureOperationBinding>,
) -> Result<CaptureOperationInspection, CaptureOperationError> {
    let keys = keys(deployment.site_lineage(), owner_operation_id)?;
    let journal = deployment.effects();
    let receipt = journal
        .operation(&keys.operation_id)
        .ok_or(CaptureOperationError::Unavailable)?;
    let prepared = journal
        .effect_journal()
        .prepared_record(&keys.operation_id)?;
    let obligation = journal
        .obligation(&keys.obligation_id)
        .ok_or(CaptureOperationError::Custody)?;
    let create_intent = bound_intent(&prepared.terminal_predicate)?;
    let principal_hash = receipt
        .authority
        .principal
        .strip_prefix("principal:onvif-capture:")
        .and_then(|text| ContentDigest::parse(text).ok());
    if receipt.intent.effect_class != EFFECT_CLASS
        || receipt.intent.idempotency_key != keys.idempotency_key
        || receipt.authority.capability != keys.capability
        || receipt.authority.lease_fence.is_some()
        || !principal_hash.is_some_and(valid_digest)
        || !valid_digest(receipt.intent.request_digest)
        || !valid_digest(receipt.intent.precondition_digest)
        || prepared.obligation_id != keys.obligation_id
        || obligation.operation_id != keys.operation_id
        || obligation.terminal_predicate != prepared.terminal_predicate
        || (receipt.state == EffectState::Verified
            && (obligation.state != ObligationState::Verified
                || receipt.result_digest.is_none()
                || obligation.proof_digest != receipt.result_digest))
        || journal
            .obligations()
            .filter(|value| value.operation_id == keys.operation_id)
            .count()
            != 1
    {
        return Err(CaptureOperationError::Custody);
    }
    let result = CaptureOperationInspection {
        owner_operation_id: owner_operation_id.clone(),
        internal_operation_id: keys.operation_id.clone(),
        receipt: receipt.clone(),
        obligation_id: keys.obligation_id.clone(),
        create_intent,
        obligation_state: obligation.state,
        proof_digest: obligation.proof_digest,
        journal_root: journal.last_root(),
    };
    if let Some(expected) = expected {
        validate(expected)?;
        if expected.operation_id != *owner_operation_id
            || receipt.intent.request_digest != expected.request_digest
            || receipt.intent.precondition_digest != expected.precondition_digest
            || receipt.authority != owner_authority(expected, &keys)?
        {
            return Err(CaptureOperationError::Conflict(Box::new(result)));
        }
    }
    Ok(result)
}

/// Inspect an existing fence without dispatch, source hydration or mutation.
///
/// A saved minimum root must be a member of the complete verified effect history.
/// It detects loss of that known prefix, not an unobserved newer suffix. The caller
/// owns deployment opening; that existing boundary may conservatively reclassify
/// unobserved committed effects after restart before this read-only call.
pub fn inspect(
    deployment: &ReferenceDeployment,
    owner_operation_id: &OperationId,
    expected: Option<&CaptureOperationBinding>,
    minimum_journal_root: Option<ContentDigest>,
    cx: &ReplayCx<impl ReplayAdmission>,
) -> Result<CaptureOperationInspection, CaptureOperationError> {
    let roots = verify_history(deployment, false, cx)?;
    if minimum_journal_root
        .is_some_and(|minimum| !valid_digest(minimum) || !roots.contains(&minimum))
    {
        return Err(CaptureOperationError::Minimum);
    }
    inspection(deployment, owner_operation_id, expected)
}

/// Durably reserve a previously absent owner ID. Existing IDs never return a guard.
///
/// No retry follows an ambiguous append or a post-commit authority refusal. Such a
/// result can leave Prepared durably visible; cold inspection is the recovery path.
pub fn reserve(
    deployment: &mut ReferenceDeployment,
    binding: &CaptureOperationBinding,
    now: TimestampNs,
    cx: &ReplayCx<impl ReplayAdmission>,
) -> Result<CaptureOperationGuard, CaptureOperationError> {
    reserve_inner(deployment, binding, None, now, cx)
}

/// Reserve a new owner operation with its exact future Create intent already pinned.
///
/// The immutable predicate is part of the original durable preparation. Existing
/// reservations, including legacy ones, are never upgraded, rebound or redispatched.
/// Only `commit_with_intent` may commit this guard after exact fresh intent custody.
pub fn reserve_for_create(
    deployment: &mut ReferenceDeployment,
    binding: &CaptureOperationBinding,
    create: &CreateIntentBinding,
    now: TimestampNs,
    cx: &ReplayCx<impl ReplayAdmission>,
) -> Result<CaptureOperationGuard, CaptureOperationError> {
    if create.source.receive_interval.earliest != now {
        return Err(CaptureOperationError::InvalidBinding);
    }
    let identity = create
        .identity(deployment.site_lineage())
        .map_err(|_| CaptureOperationError::InvalidBinding)?;
    reserve_inner(deployment, binding, Some(identity), now, cx)
}

fn reserve_inner(
    deployment: &mut ReferenceDeployment,
    binding: &CaptureOperationBinding,
    create_intent: Option<ContentDigest>,
    now: TimestampNs,
    cx: &ReplayCx<impl ReplayAdmission>,
) -> Result<CaptureOperationGuard, CaptureOperationError> {
    validate(binding)?;
    if cx.io_authority().principal() != binding.principal {
        return Err(CaptureOperationError::Authority);
    }
    verify_history(deployment, true, cx)?;
    let keys = keys(deployment.site_lineage(), &binding.operation_id)?;
    if deployment.effects().operation(&keys.operation_id).is_some() {
        let existing = inspection(deployment, &binding.operation_id, Some(binding))?;
        return Err(CaptureOperationError::Existing(Box::new(existing)));
    }
    if let Some(identity) = create_intent {
        // A cloned fresh handle must not authorize the same Create through a
        // second stable owner ID. Reservations are serialized by this deployment.
        for operation in deployment.effects().operations() {
            if operation.intent.effect_class == EFFECT_CLASS {
                let prior = deployment
                    .effects()
                    .effect_journal()
                    .prepared_record(&operation.intent.operation_id)?;
                if bound_intent(&prior.terminal_predicate)? == Some(identity) {
                    return Err(CaptureOperationError::Custody);
                }
            }
        }
    }
    let ledger_store_pin = deployment
        .ledger()
        .store_pin()
        .ok_or(CaptureOperationError::Custody)?;
    let effect_store_pin = deployment
        .effects()
        .store_pin()
        .ok_or(CaptureOperationError::Custody)?;
    let authority = owner_authority(binding, &keys)?;
    let intent = EffectIntent::new(
        keys.operation_id,
        keys.idempotency_key,
        EFFECT_CLASS,
        binding.request_digest,
        binding.precondition_digest,
    )
    .map_err(|_| CaptureOperationError::InvalidBinding)?;
    checkpoint(cx, STAGE_PREPARE)?;
    let terminal_predicate = create_intent.map_or_else(
        || TERMINAL_PREDICATE.to_owned(),
        |identity| format!("{BOUND_TERMINAL_PREDICATE}{}", identity.to_text()),
    );
    deployment.effects_mut().prepare_with_authority(
        intent,
        keys.obligation_id,
        terminal_predicate,
        authority,
        now,
    )?;
    // Unlike ordinary source publication, this receipt is about permission to do
    // a subsequent effect. Preserve its history, but return no guard after refusal.
    checkpoint(cx, STAGE_PREPARED)?;
    let prepared = inspect(deployment, &binding.operation_id, Some(binding), None, cx)?;
    if prepared.receipt.state != EffectState::Prepared || prepared.receipt.committed_at.is_some() {
        return Err(CaptureOperationError::Custody);
    }
    Ok(CaptureOperationGuard {
        binding: binding.clone(),
        prepared,
        ledger_store_pin,
        effect_store_pin,
        reserved_authority_sequence: deployment.current_anchor().commit_sequence,
    })
}

impl CaptureOperationGuard {
    /// Read-only reservation receipt; copying it cannot reconstruct this guard.
    #[must_use]
    pub const fn prepared(&self) -> &CaptureOperationInspection {
        &self.prepared
    }

    /// Consume the sole live guard and durably record dispatch intent.
    ///
    /// This guard is consumed on every return, including pre-append refusal and
    /// ambiguous persistence failure. No network call belongs inside this method.
    pub fn commit(
        self,
        deployment: &mut ReferenceDeployment,
        now: TimestampNs,
        cx: &ReplayCx<impl ReplayAdmission>,
    ) -> Result<CaptureOperationInspection, CaptureOperationError> {
        if self.prepared.create_intent.is_some() {
            return Err(CaptureOperationError::Custody);
        }
        self.commit_inner(deployment, now, cx)
    }

    /// Commit a bound reservation only after the exact fresh Create intent is durable.
    ///
    /// The intent is reopened against current custody. A retained handle, an old
    /// intent or another operation's Create cannot grant this one dispatch.
    pub fn commit_with_intent(
        self,
        deployment: &mut ReferenceDeployment,
        intent: &RetainedCreateIntent,
        now: TimestampNs,
        cx: &ReplayCx<impl ReplayAdmission>,
    ) -> Result<CaptureOperationInspection, CaptureOperationError> {
        if self.prepared.create_intent != Some(intent.identity())
            || !intent.newly_prepared()
            || intent.authority_anchor().commit_sequence <= self.reserved_authority_sequence
        {
            return Err(CaptureOperationError::Custody);
        }
        let local = RetainedCreateIntent::open(
            deployment,
            intent.identity(),
            Some(intent.publication_root()),
            cx,
        )
        .map_err(|_| CaptureOperationError::Custody)?;
        if local.authority_anchor() != intent.authority_anchor()
            || local.authority_anchor().commit_sequence <= self.reserved_authority_sequence
        {
            return Err(CaptureOperationError::Custody);
        }
        self.commit_inner(deployment, now, cx)
    }

    fn commit_inner(
        self,
        deployment: &mut ReferenceDeployment,
        now: TimestampNs,
        cx: &ReplayCx<impl ReplayAdmission>,
    ) -> Result<CaptureOperationInspection, CaptureOperationError> {
        if cx.io_authority().principal() != self.binding.principal {
            return Err(CaptureOperationError::Authority);
        }
        verify_history(deployment, true, cx)?;
        if deployment.ledger().store_pin() != Some(self.ledger_store_pin)
            || deployment.effects().store_pin() != Some(self.effect_store_pin)
        {
            return Err(CaptureOperationError::Authority);
        }
        let current = inspect(
            deployment,
            &self.binding.operation_id,
            Some(&self.binding),
            Some(self.prepared.journal_root),
            cx,
        )?;
        if current.internal_operation_id != self.prepared.internal_operation_id
            || current.receipt != self.prepared.receipt
            || current.create_intent != self.prepared.create_intent
            || current.receipt.state != EffectState::Prepared
        {
            return Err(CaptureOperationError::Custody);
        }
        checkpoint(cx, STAGE_COMMIT)?;
        deployment.effects_mut().transition(
            &current.internal_operation_id,
            EffectState::Committed,
            now,
            None,
            None,
        )?;
        checkpoint(cx, STAGE_COMMITTED)?;
        inspect(
            deployment,
            &self.binding.operation_id,
            Some(&self.binding),
            Some(self.prepared.journal_root),
            cx,
        )
    }
}
