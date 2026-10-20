#![forbid(unsafe_code)]
//! Authority-owned multipart upload with explicit, recoverable terminal work.
//!
//! Preparation owns the actual ObjectStore child, its reserved allowance and its
//! pending obligation. Every transport call uses that child. Neither a failed
//! dispatch nor cancellation consumes the owner: completion/abort uncertainty
//! must be reconciled or explicitly closed locally with a bound unresolved receipt.
//! Conclusive receipts prove completion/abort; unresolved closure preserves uncertainty
//! and its follow-up note. Both drain/finalize the child and return only unused allowance.
//!
//! An optional bounded journal preserves exact transfer knowledge and ownership
//! across restart. Recovery validates an independently pinned intent and creates
//! a fresh explicitly authorized child; persisted bytes never recreate live authority.
//! Dropping unsettled work leaves a visible child obligation and charged reservation.
//! No network transport, encryption implementation or retrievability claim is added.

use std::collections::BTreeSet;

use fss_core::{
    BudgetVector, CanonicalDecode, CanonicalDecoder, CanonicalEncode, CanonicalEncoder,
    ContentDigest, ContextAuthority, DigestAlgorithm, Obligation, ObligationId, ObligationState,
    OperationId, RegionId, RegionKind, RegionState, RegionTree, RootAuthoritySpec, RuntimeGrant,
    TimestampNs,
};
use fss_runtime::authority::{AuthorityCx, AuthorityError};
use fss_runtime::grant::GrantSet;
use fss_runtime::obligation::{ObligationTerminal, new_obligation};

use crate::multipart::{
    AbortReceipt, CompletionReceipt, MultipartError, MultipartPhase, MultipartRecovery,
    MultipartSession, MultipartTransport, PartReceipt, TransportOperation, UploadIntent, UploadIo,
    UploadJournal, UploadJournalPin,
};
use crate::planner::{ChunkPlan, ChunkPolicy, PlannerError, plan_chunks};

/// Upload refusal. All methods after preparation borrow rather than consume the owner.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum UploaderError {
    /// Scope, obligation, grant, deadline or allowance refusal.
    Authority(String),
    /// Invalid bounded chunk plan.
    Planner(PlannerError),
    /// Typed protocol, I/O admission or uncertain-dispatch result.
    Protocol(MultipartError),
    /// Cancellation was observed before further work, but staging is still owned.
    CancellationRequested {
        /// Exactly acknowledged parts; an abort/reconciliation is still required.
        confirmed_parts: usize,
    },
}
impl std::fmt::Display for UploaderError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Authority(detail) => write!(f, "upload authority refusal: {detail}"),
            Self::Planner(error) => write!(f, "upload plan refusal: {error}"),
            Self::Protocol(error) => write!(f, "{error}"),
            Self::CancellationRequested { confirmed_parts } => write!(
                f,
                "upload cancellation requested after {confirmed_parts} confirmed parts; explicit drain required"
            ),
        }
    }
}
impl std::error::Error for UploaderError {}
impl From<AuthorityError> for UploaderError {
    fn from(error: AuthorityError) -> Self {
        Self::Authority(error.to_string())
    }
}
impl From<PlannerError> for UploaderError {
    fn from(error: PlannerError) -> Self {
        Self::Planner(error)
    }
}
impl From<MultipartError> for UploaderError {
    fn from(error: MultipartError) -> Self {
        Self::Protocol(error)
    }
}
fn authority(error: impl std::fmt::Display) -> UploaderError {
    UploaderError::Authority(error.to_string())
}

/// Maximum UTF-8 byte length of an operator's unresolved-upload recovery note.
pub const MAX_UPLOAD_RECOVERY_NOTE_BYTES: usize = 256;

/// Local ownership closure with an explicitly unresolved provider outcome.
///
/// This records a follow-up reference, not provider rollback or completion. The exact
/// bound note and proof remain on the canonical child obligation and, when attached,
/// the upload journal before the child's unused allowance can be released.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IndeterminateUploadReceipt {
    intent_digest: ContentDigest,
    region: RegionId,
    obligation: ObligationId,
    operation: TransportOperation,
    reconciliation_reference: ContentDigest,
    note: String,
    digest: ContentDigest,
}

impl IndeterminateUploadReceipt {
    /// Original immutable intent whose provider outcome remains unresolved.
    #[must_use]
    pub const fn intent_digest(&self) -> ContentDigest {
        self.intent_digest
    }
    /// Exact child whose local ownership is being closed.
    #[must_use]
    pub fn region(&self) -> &RegionId {
        &self.region
    }
    /// The canonical obligation carrying the unresolved outcome.
    #[must_use]
    pub fn obligation(&self) -> &ObligationId {
        &self.obligation
    }
    /// Original dispatched operation, not a claim that it was performed or rolled back.
    #[must_use]
    pub const fn operation(&self) -> TransportOperation {
        self.operation
    }
    /// Caller-owned follow-up record; it does not authenticate a provider outcome.
    #[must_use]
    pub const fn reconciliation_reference(&self) -> ContentDigest {
        self.reconciliation_reference
    }
    /// Exact bounded note recorded in the tree, including intent, operation and reference.
    #[must_use]
    pub fn note(&self) -> &str {
        &self.note
    }
    /// Proof identity binding every field of this unresolved ownership receipt.
    #[must_use]
    pub const fn digest(&self) -> ContentDigest {
        self.digest
    }
}

const MAX_UPLOAD_OWNER_BYTES: usize = 64 * 1024;
const UPLOAD_TERMINAL_PREDICATE: &str =
    "exact multipart intent completed or staging conclusively aborted";

fn checkpoint_error(_: impl std::fmt::Display) -> MultipartError {
    MultipartError::InvalidCheckpoint
}

fn operation_tag(operation: TransportOperation) -> (u8, &'static str) {
    match operation {
        TransportOperation::Initiate => (1, "initiate"),
        TransportOperation::UploadPart => (2, "upload_part"),
        TransportOperation::Complete => (3, "complete"),
        TransportOperation::Abort => (4, "abort"),
        TransportOperation::Reconcile => (5, "reconcile"),
    }
}

fn decode_operation(tag: u8) -> Result<TransportOperation, MultipartError> {
    match tag {
        1 => Ok(TransportOperation::Initiate),
        2 => Ok(TransportOperation::UploadPart),
        3 => Ok(TransportOperation::Complete),
        4 => Ok(TransportOperation::Abort),
        5 => Ok(TransportOperation::Reconcile),
        _ => Err(MultipartError::InvalidCheckpoint),
    }
}

fn unresolved_prefix(
    intent: ContentDigest,
    operation: TransportOperation,
    reference: ContentDigest,
) -> String {
    format!(
        "multipart unresolved; intent={intent}; operation={}; reference={reference}; note=",
        operation_tag(operation).1,
    )
}

fn make_indeterminate_receipt(
    intent_digest: ContentDigest,
    region: RegionId,
    obligation: ObligationId,
    operation: TransportOperation,
    reconciliation_reference: ContentDigest,
    note: &str,
) -> Result<IndeterminateUploadReceipt, UploaderError> {
    if note.trim().is_empty()
        || note.len() > MAX_UPLOAD_RECOVERY_NOTE_BYTES
        || note.chars().any(char::is_control)
        || reconciliation_reference.algorithm() != DigestAlgorithm::Sha256
        || reconciliation_reference.bytes() == [0; 32]
    {
        return Err(authority(
            "invalid unresolved-upload note or follow-up reference",
        ));
    }
    let note = format!(
        "{}{note}",
        unresolved_prefix(intent_digest, operation, reconciliation_reference),
    );
    if note.len() > 512 {
        return Err(authority("bound unresolved-upload note exceeds its limit"));
    }
    let mut encoder = CanonicalEncoder::new();
    encoder.text("fss.multipart_indeterminate.v1");
    encoder.digest(intent_digest);
    encoder.text(region.as_str());
    encoder.text(obligation.as_str());
    encoder.u8(operation_tag(operation).0);
    encoder.digest(reconciliation_reference);
    encoder.text(&note);
    let digest = ContentDigest::sha256(&encoder.finish_checked().map_err(authority)?);
    Ok(IndeterminateUploadReceipt {
        intent_digest,
        region,
        obligation,
        operation,
        reconciliation_reference,
        note,
        digest,
    })
}

/// Inert canonical ownership facts carried by the protocol checkpoint. These are
/// never an execution context. Effective authority can only narrow, and its
/// resource grants refer solely to the checkpoint's immutable upload intent.
#[derive(Clone, Debug, PartialEq)]
struct UploadOwnerRecord {
    intent_digest: ContentDigest,
    original_authority: ContextAuthority,
    effective_authority: ContextAuthority,
    grants: Vec<String>,
    cancelled: bool,
    obligation: Obligation,
    reconciliation_note: Option<String>,
    indeterminate_receipt: Option<IndeterminateUploadReceipt>,
}

impl UploadOwnerRecord {
    fn validate(&self) -> Result<(), MultipartError> {
        self.original_authority
            .validate()
            .map_err(checkpoint_error)?;
        self.effective_authority
            .validate()
            .map_err(checkpoint_error)?;
        self.effective_authority
            .verify_narrowing_of(&self.original_authority)
            .map_err(checkpoint_error)?;
        GrantSet::from_authority(&self.original_authority).map_err(checkpoint_error)?;
        if self.intent_digest.algorithm() != DigestAlgorithm::Sha256
            || self.intent_digest.bytes() == [0; 32]
            || self.original_authority.cancellation_reason.is_some()
            || self.effective_authority.cancellation_reason.is_some()
            || self.effective_authority.operation_id != self.original_authority.operation_id
            || self.effective_authority.privacy_scope != self.original_authority.privacy_scope
            || self.effective_authority.retention_scope != self.original_authority.retention_scope
            || self.effective_authority.lease_fence != self.original_authority.lease_fence
            || self.effective_authority.idempotency_key != self.original_authority.idempotency_key
            || self.effective_authority.lab_controls != self.original_authority.lab_controls
            || self.grants.len() > self.effective_authority.capabilities().len()
            || self.grants.windows(2).any(|pair| pair[0] >= pair[1])
            || self.grants.iter().any(|grant| {
                !self.effective_authority.has_capability(grant)
                    || RuntimeGrant::from_id(grant).is_err()
            })
        {
            return Err(MultipartError::InvalidCheckpoint);
        }
        let operation = &self.original_authority.operation_id;
        let pending = new_obligation(
            format!("obligation:upload:{}:drain", operation.as_str()),
            operation.clone(),
            UPLOAD_TERMINAL_PREDICATE,
        )
        .map_err(checkpoint_error)?;
        if self.obligation.obligation_id != pending.obligation_id
            || self.obligation.operation_id != pending.operation_id
            || self.obligation.terminal_predicate != pending.terminal_predicate
        {
            return Err(MultipartError::InvalidCheckpoint);
        }
        match self.obligation.state {
            ObligationState::Pending
                if self.obligation.proof_digest.is_none()
                    && self.reconciliation_note.is_none()
                    && self.indeterminate_receipt.is_none() => {}
            ObligationState::Verified | ObligationState::Cancelled
                if self.obligation.proof_digest.is_some_and(|digest| {
                    digest.algorithm() == DigestAlgorithm::Sha256 && digest.bytes() != [0; 32]
                }) && self.reconciliation_note.is_none()
                    && self.indeterminate_receipt.is_none() => {}
            ObligationState::Indeterminate => {
                let receipt = self
                    .indeterminate_receipt
                    .as_ref()
                    .ok_or(MultipartError::InvalidCheckpoint)?;
                let prefix = unresolved_prefix(
                    self.intent_digest,
                    receipt.operation,
                    receipt.reconciliation_reference,
                );
                let raw_note = receipt
                    .note
                    .strip_prefix(&prefix)
                    .ok_or(MultipartError::InvalidCheckpoint)?;
                let expected = make_indeterminate_receipt(
                    self.intent_digest,
                    RegionId::new(format!("region:upload:{}", operation.as_str()))
                        .map_err(checkpoint_error)?,
                    self.obligation.obligation_id.clone(),
                    receipt.operation,
                    receipt.reconciliation_reference,
                    raw_note,
                )
                .map_err(checkpoint_error)?;
                if receipt != &expected
                    || self.obligation.proof_digest != Some(receipt.digest())
                    || self.reconciliation_note.as_deref() != Some(receipt.note())
                {
                    return Err(MultipartError::InvalidCheckpoint);
                }
            }
            _ => return Err(MultipartError::InvalidCheckpoint),
        }
        Ok(())
    }

    fn encode(&self) -> Result<Vec<u8>, MultipartError> {
        self.validate()?;
        let mut encoder = CanonicalEncoder::new();
        encoder.text("fss.multipart_owner.v1");
        encoder.digest(self.intent_digest);
        self.original_authority.encode_canonical(&mut encoder);
        self.effective_authority.encode_canonical(&mut encoder);
        encoder.u64(self.grants.len() as u64);
        for grant in &self.grants {
            encoder.text(grant);
        }
        encoder.bool(self.cancelled);
        self.obligation.encode_canonical(&mut encoder);
        encoder.bool(self.reconciliation_note.is_some());
        if let Some(note) = &self.reconciliation_note {
            encoder.text(note);
        }
        encoder.bool(self.indeterminate_receipt.is_some());
        if let Some(receipt) = &self.indeterminate_receipt {
            encoder.u8(operation_tag(receipt.operation).0);
            encoder.digest(receipt.reconciliation_reference);
            encoder.text(&receipt.note);
            encoder.digest(receipt.digest);
        }
        let bytes = encoder.finish_checked().map_err(checkpoint_error)?;
        if bytes.len() > MAX_UPLOAD_OWNER_BYTES {
            return Err(MultipartError::InvalidCheckpoint);
        }
        Ok(bytes)
    }

    fn decode(bytes: &[u8]) -> Result<Self, MultipartError> {
        if bytes.len() > MAX_UPLOAD_OWNER_BYTES {
            return Err(MultipartError::InvalidCheckpoint);
        }
        let mut decoder = CanonicalDecoder::new(bytes);
        if decoder.text().map_err(checkpoint_error)? != "fss.multipart_owner.v1" {
            return Err(MultipartError::InvalidCheckpoint);
        }
        let intent_digest = decoder.digest().map_err(checkpoint_error)?;
        let original_authority =
            ContextAuthority::decode_canonical(&mut decoder).map_err(checkpoint_error)?;
        let effective_authority =
            ContextAuthority::decode_canonical(&mut decoder).map_err(checkpoint_error)?;
        let count = decoder.u64().map_err(checkpoint_error)?;
        if count > 64 {
            return Err(MultipartError::InvalidCheckpoint);
        }
        let mut grants = Vec::with_capacity(count as usize);
        for _ in 0..count {
            grants.push(decoder.text().map_err(checkpoint_error)?.to_string());
        }
        let cancelled = decoder.bool().map_err(checkpoint_error)?;
        let obligation = Obligation::decode_canonical(&mut decoder).map_err(checkpoint_error)?;
        let reconciliation_note = if decoder.bool().map_err(checkpoint_error)? {
            Some(decoder.text().map_err(checkpoint_error)?.to_string())
        } else {
            None
        };
        let indeterminate_receipt = if decoder.bool().map_err(checkpoint_error)? {
            Some(IndeterminateUploadReceipt {
                intent_digest,
                region: RegionId::new(format!(
                    "region:upload:{}",
                    original_authority.operation_id.as_str(),
                ))
                .map_err(checkpoint_error)?,
                obligation: obligation.obligation_id.clone(),
                operation: decode_operation(decoder.u8().map_err(checkpoint_error)?)?,
                reconciliation_reference: decoder.digest().map_err(checkpoint_error)?,
                note: decoder.text().map_err(checkpoint_error)?.to_string(),
                digest: decoder.digest().map_err(checkpoint_error)?,
            })
        } else {
            None
        };
        decoder.ensure_finished().map_err(checkpoint_error)?;
        let record = Self {
            intent_digest,
            original_authority,
            effective_authority,
            grants,
            cancelled,
            obligation,
            reconciliation_note,
            indeterminate_receipt,
        };
        if record.encode()? != bytes {
            return Err(MultipartError::InvalidCheckpoint);
        }
        Ok(record)
    }
}

/// Check the uploader-owned part of every journal transition without admitting
/// execution authority. Empty metadata is reserved for a protocol-only session.
pub(crate) fn validate_recovery_owner_transition(
    previous: Option<&[u8]>,
    next: &[u8],
) -> Result<(), MultipartError> {
    if next.is_empty() {
        return if previous.is_none_or(<[u8]>::is_empty) {
            Ok(())
        } else {
            Err(MultipartError::InvalidCheckpoint)
        };
    }
    let next = UploadOwnerRecord::decode(next)?;
    if let Some(previous) = previous {
        let previous = UploadOwnerRecord::decode(previous)?;
        next.effective_authority
            .verify_narrowing_of(&previous.effective_authority)
            .map_err(checkpoint_error)?;
        if previous.intent_digest != next.intent_digest
            || previous.original_authority != next.original_authority
            || (previous.cancelled && !next.cancelled)
            || next
                .grants
                .iter()
                .any(|grant| !previous.grants.contains(grant))
            || (previous.obligation.state != ObligationState::Pending
                && (previous.obligation != next.obligation
                    || previous.reconciliation_note != next.reconciliation_note
                    || previous.indeterminate_receipt != next.indeterminate_receipt))
        {
            return Err(MultipartError::InvalidCheckpoint);
        }
    }
    Ok(())
}

/// Minimum allowance for payload plus initiation, completion, two reconciliations
/// and one abort. Additional attempts require explicit additional reservation.
/// Network bytes cover payload here; a real transport must separately admit its
/// framing/response I/O rather than treating this estimate as measured wire usage.
pub fn minimum_upload_budget(
    object_bytes: u64,
    policy: ChunkPolicy,
) -> Result<BudgetVector, UploaderError> {
    let plan = plan_chunks(object_bytes, policy)?;
    let mut budget = BudgetVector::ZERO;
    budget.bytes = object_bytes;
    budget.network_bytes = object_bytes;
    budget.storage_operations = plan.chunks.len() as u64 + 5;
    Ok(budget)
}

/// An unfinished upload stays owned until completion, conclusive abort, or explicit local
/// indeterminate settlement with its unresolved follow-up record retained.
#[must_use = "retain the upload owner until completion, abort or explicit indeterminate settlement"]
pub struct StagedUpload<'a, T: MultipartTransport> {
    parent: &'a mut AuthorityCx,
    authority: AuthorityCx,
    original_authority: ContextAuthority,
    obligation: Obligation,
    reconciliation_note: Option<String>,
    indeterminate_receipt: Option<IndeterminateUploadReceipt>,
    session: MultipartSession<'a, T>,
    plan: ChunkPlan,
    observed_at: TimestampNs,
    cancellation_requested: bool,
    settled: bool,
}

impl<'a, T: MultipartTransport> StagedUpload<'a, T> {
    /// Pure owned preparation: validate intent and grants, reserve the caller's
    /// exact allowance, and register the pending obligation on the child itself.
    /// No provider call is hidden in this fallible constructor.
    #[allow(clippy::too_many_arguments)]
    pub fn stage(
        parent: &'a mut AuthorityCx,
        tree: &mut RegionTree,
        transport: &'a mut T,
        operation: OperationId,
        object_bytes: u64,
        policy: ChunkPolicy,
        manifest_root: ContentDigest,
        child_spec: RootAuthoritySpec,
        resource: &str,
        now: TimestampNs,
    ) -> Result<StagedUpload<'a, T>, UploaderError> {
        parent.is_cancel_requested(tree)?;
        let parent_node = tree.get(parent.region()).map_err(authority)?;
        if now < parent_node.created_at
            || parent_node.drain_requested_at.is_some_and(|at| now < at)
            || parent_node.closed_at.is_some_and(|at| now < at)
        {
            return Err(MultipartError::ClockRegression.into());
        }
        let plan = plan_chunks(object_bytes, policy)?;
        let minimum = minimum_upload_budget(object_bytes, policy)?;
        if child_spec.operation_id != operation || !minimum.fits_within(child_spec.budgets) {
            return Err(authority(
                "operation mismatch or insufficient explicit upload allowance",
            ));
        }
        if child_spec.deadline.is_some_and(|deadline| now >= deadline) {
            return Err(MultipartError::Deadline.into());
        }
        let canonical = ContextAuthority::new_root(child_spec.clone()).map_err(authority)?;
        canonical.validate().map_err(authority)?;
        let grants = parent
            .grants()
            .scope_for_child(&canonical)
            .map_err(authority)?;
        for grant in [
            RuntimeGrant::ObjectStage,
            RuntimeGrant::ObjectPublish,
            RuntimeGrant::AdapterNet,
        ] {
            grants
                .require_grant_for(grant, resource)
                .map_err(authority)?;
        }
        let obligation = new_obligation(
            format!("obligation:upload:{}:drain", operation.as_str()),
            operation.clone(),
            UPLOAD_TERMINAL_PREDICATE,
        )
        .map_err(authority)?;
        let region =
            RegionId::new(format!("region:upload:{}", operation.as_str())).map_err(authority)?;
        let session =
            MultipartSession::prepare(transport, &plan, manifest_root, operation, resource, now)?;
        // Preserve the caller's actual grants, deadline and allowance. Never enlarge
        // a zero/insufficient child budget merely to make scope construction pass.
        let child = parent.scope_down(
            tree,
            region,
            RegionKind::ObjectStore,
            child_spec.budgets,
            child_spec,
            now,
        )?;
        // The exclusive tree borrow has not escaped: this freshly attached child
        // is active, empty and unique. Registration's absent/inactive/duplicate/
        // capacity refusals therefore cannot occur after successful attachment.
        child.register_obligation(tree, obligation.clone())?;
        Ok(StagedUpload {
            parent,
            authority: child,
            original_authority: canonical,
            obligation,
            reconciliation_note: None,
            indeterminate_receipt: None,
            session,
            plan,
            observed_at: now,
            cancellation_requested: false,
            settled: false,
        })
    }

    /// Attach write-ahead persistence before the first provider effect. This
    /// borrows the existing owner: an append refusal cannot discard its child,
    /// pending obligation, or reserved allowance. Ambiguous append failures
    /// require cold journal recovery before further effects or refunds.
    pub fn attach_journal(
        &mut self,
        tree: &RegionTree,
        now: TimestampNs,
        journal: &'a mut dyn UploadJournal,
    ) -> Result<UploadJournalPin, UploaderError> {
        self.validate_owner(tree, now)?;
        if self.session.is_durable()
            || self.session.phase() != MultipartPhase::Prepared
            || self.obligation.state != ObligationState::Pending
            || self.settled
            || *self.authority.budget().consumed() != BudgetVector::ZERO
        {
            return Err(authority(
                "attach the upload journal before any provider dispatch",
            ));
        }
        let metadata = self.owner_record(tree)?.encode()?;
        self.observed_at = now;
        Ok(self.session.attach_journal(
            journal,
            UploadIo {
                authority: &mut self.authority,
                tree,
                now,
            },
            metadata,
        )?)
    }

    /// Rebind a validated, independently pinned checkpoint to fresh caller-owned
    /// runtime authority. The expected intent must come from the caller's saved
    /// workflow identity, not be inferred from an untrusted checkpoint alone.
    ///
    /// The fresh child reserves exactly the persisted remaining allowance.
    /// Historical consumption remains charged to the workflow and can never be
    /// refunded through this new parent. This constructor performs no transport
    /// or journal writes; the next checkpoint or operation persists any further
    /// caller restrictions before a provider effect can be admitted.
    #[allow(clippy::too_many_arguments)]
    pub fn recover(
        parent: &'a mut AuthorityCx,
        tree: &mut RegionTree,
        transport: &'a mut T,
        journal: &'a mut dyn UploadJournal,
        recovery: MultipartRecovery,
        expected_intent: &UploadIntent,
        child_spec: RootAuthoritySpec,
        now: TimestampNs,
    ) -> Result<Self, UploaderError> {
        recovery.validate_restore(journal, now)?;
        parent.is_cancel_requested(tree)?;
        let parent_node = tree.get(parent.region()).map_err(authority)?;
        if now < parent_node.created_at
            || parent_node.drain_requested_at.is_some_and(|at| now < at)
            || parent_node.closed_at.is_some_and(|at| now < at)
        {
            return Err(MultipartError::ClockRegression.into());
        }
        let record = UploadOwnerRecord::decode(recovery.owner_metadata())?;
        if recovery.intent() != expected_intent
            || record.intent_digest != expected_intent.digest()
            || record.original_authority.operation_id != *expected_intent.operation()
            || record.original_authority.budgets != recovery.original_budget()
            || &record.original_authority != recovery.original_authority()
        {
            return Err(MultipartError::InvalidCheckpoint.into());
        }
        match record.obligation.state {
            ObligationState::Pending => {}
            ObligationState::Verified
                if recovery.phase() == MultipartPhase::Completed
                    && record.obligation.proof_digest
                        == Some(recovery.completion_receipt()?.digest()) => {}
            ObligationState::Cancelled
                if recovery.phase() == MultipartPhase::Aborted
                    && record.obligation.proof_digest
                        == Some(recovery.abort_receipt()?.digest()) => {}
            ObligationState::Indeterminate
                if record
                    .indeterminate_receipt
                    .as_ref()
                    .is_some_and(|receipt| {
                        recovery.phase() == MultipartPhase::Uncertain(receipt.operation())
                    }) => {}
            _ => return Err(MultipartError::InvalidCheckpoint.into()),
        }
        let canonical = ContextAuthority::new_root(child_spec.clone()).map_err(authority)?;
        canonical.validate().map_err(authority)?;
        canonical
            .verify_narrowing_of(&record.effective_authority)
            .map_err(authority)?;
        canonical
            .verify_narrowing_of(recovery.effective_authority())
            .map_err(authority)?;
        if canonical.operation_id != *expected_intent.operation()
            || canonical.privacy_scope != record.effective_authority.privacy_scope
            || canonical.retention_scope != record.effective_authority.retention_scope
            || canonical.lease_fence != record.effective_authority.lease_fence
            || canonical.idempotency_key != record.effective_authority.idempotency_key
            || canonical.lab_controls != record.effective_authority.lab_controls
            || child_spec.budgets != recovery.remaining_budget()
        {
            return Err(authority(
                "recovery authority changed the upload scope or remaining allowance",
            ));
        }
        let offered_grants = parent
            .grants()
            .scope_for_child(&canonical)
            .map_err(authority)?;
        // The decoded grant strings constrain the fresh caller's authority;
        // they never supply it. Narrow the result to this one immutable resource.
        let mut grants = GrantSet::empty();
        for capability in canonical.capabilities() {
            let grant = RuntimeGrant::from_id(capability).map_err(authority)?;
            if record.grants.contains(capability)
                && offered_grants
                    .require_grant_for(grant, expected_intent.resource())
                    .is_ok()
            {
                grants = grants.with_scope(
                    grant,
                    BTreeSet::from([expected_intent.resource().to_string()]),
                );
            }
        }
        offered_grants
            .verify_narrowed_by(&grants)
            .map_err(authority)?;
        recovery.validate_authority(&canonical, &grants)?;
        let region = RegionId::new(format!(
            "region:upload:{}",
            expected_intent.operation().as_str(),
        ))
        .map_err(authority)?;
        let plan = recovery.plan().clone();
        let mut child = parent.scope_down(
            tree,
            region,
            RegionKind::ObjectStore,
            recovery.remaining_budget(),
            child_spec,
            now,
        )?;
        // Every following precondition was validated above. This exclusive new
        // child has no competing task, obligation, or mutable authority owner.
        child.narrow_grants(grants).map_err(authority)?;
        child.register_obligation(tree, record.obligation.clone())?;
        if let Some(note) = &record.reconciliation_note {
            child.resolve_obligation(
                tree,
                &record.obligation.obligation_id,
                ObligationTerminal::Indeterminate,
                record.obligation.proof_digest,
                Some(note),
            )?;
        }
        let cancellation_requested = record.cancelled || recovery.cancelled();
        if cancellation_requested {
            child.request_cancellation(tree, now)?;
        }
        let session = MultipartSession::restore_prevalidated(
            transport,
            journal,
            &recovery,
            UploadIo {
                authority: &mut child,
                tree,
                now,
            },
        );
        Ok(Self {
            parent,
            authority: child,
            original_authority: record.original_authority,
            obligation: record.obligation,
            reconciliation_note: record.reconciliation_note,
            indeterminate_receipt: record.indeterminate_receipt,
            session,
            plan,
            observed_at: now,
            cancellation_requested,
            settled: false,
        })
    }

    /// Request a stop of this exact runtime child without claiming provider
    /// rollback or resolving its upload obligation. Journaled owners persist
    /// the cancellation intent before mutating the live tree or reporting success.
    /// A crash at that boundary therefore cannot authorize new work on recovery.
    ///
    /// Failed persistence retains the owner and its allowance; ambiguous writes
    /// require cold recovery. An accepted request is monotone and idempotent,
    /// including after later closure. A new request on a finalizing or closed
    /// child is refused. Abort, reconciliation, and known terminal receipt reads
    /// remain available; they still require their normal authority and budget.
    pub fn request_cancellation(
        &mut self,
        tree: &mut RegionTree,
        now: TimestampNs,
    ) -> Result<(), UploaderError> {
        self.validate_owner(tree, now)?;
        let state = tree.get(self.region()).map_err(authority)?.state;
        if self.cancellation_requested && state != RegionState::Active {
            self.observed_at = now;
            return Ok(());
        }
        if matches!(state, RegionState::Finalizing | RegionState::Closed) {
            return Err(authority(
                "upload owner cannot accept a new cancellation after finalization",
            ));
        }
        self.observed_at = now;
        let mut record = self.owner_record(tree)?;
        record.cancelled = true;
        self.persist_record(tree, now, record)?;
        // Keep the committed stop even if the following live mutation refuses.
        // A later retry dates its live change after a new durable clock boundary.
        // Forward work cannot erase or bypass this restriction.
        self.cancellation_requested = true;
        self.authority.request_cancellation(tree, now)?;
        Ok(())
    }

    /// Persist the current authority restrictions, cancellation, and canonical
    /// ownership facts without touching the provider. A successful returned pin
    /// can be retained independently to reject a truncated or stale journal.
    pub fn checkpoint(
        &mut self,
        tree: &RegionTree,
        now: TimestampNs,
    ) -> Result<UploadJournalPin, UploaderError> {
        self.validate_owner(tree, now)?;
        if !self.session.is_durable() {
            return Err(authority("upload has no attached journal"));
        }
        let metadata = self.owner_record(tree)?.encode()?;
        self.observed_at = now;
        Ok(self.session.persist_owner(
            UploadIo {
                authority: &mut self.authority,
                tree,
                now,
            },
            metadata,
        )?)
    }

    fn owner_record(&self, tree: &RegionTree) -> Result<UploadOwnerRecord, UploaderError> {
        let mut effective_authority = tree
            .get(self.region())
            .map_err(authority)?
            .authority
            .clone();
        effective_authority.cancellation_reason = None;
        let mut grants = Vec::new();
        for capability in effective_authority.capabilities() {
            let grant = RuntimeGrant::from_id(capability).map_err(authority)?;
            if self
                .authority
                .grants()
                .require_grant_for(grant, self.intent().resource())
                .is_ok()
            {
                grants.push(capability.clone());
            }
        }
        let mut obligation = self.obligation.clone();
        let mut reconciliation_note = self.reconciliation_note.clone();
        if let Some(receipt) = &self.indeterminate_receipt {
            obligation.state = ObligationState::Indeterminate;
            obligation.proof_digest = Some(receipt.digest());
            reconciliation_note = Some(receipt.note().to_string());
        }
        Ok(UploadOwnerRecord {
            intent_digest: self.intent().digest(),
            original_authority: self.original_authority.clone(),
            effective_authority,
            grants,
            cancelled: self.authority.is_cancel_requested(tree)? || self.cancellation_requested,
            obligation,
            reconciliation_note,
            indeterminate_receipt: self.indeterminate_receipt.clone(),
        })
    }

    fn persist_record(
        &mut self,
        tree: &RegionTree,
        now: TimestampNs,
        record: UploadOwnerRecord,
    ) -> Result<(), UploaderError> {
        if self.session.is_durable() {
            self.session.persist_owner(
                UploadIo {
                    authority: &mut self.authority,
                    tree,
                    now,
                },
                record.encode()?,
            )?;
        }
        Ok(())
    }

    /// Explicit initiation; failures retain the stable intent and pending child.
    pub fn start(&mut self, tree: &RegionTree, now: TimestampNs) -> Result<(), UploaderError> {
        self.validate_dispatch_owner(tree, now)?;
        self.require_forward_work()?;
        self.session.start(UploadIo {
            authority: &mut self.authority,
            tree,
            now,
        })?;
        Ok(())
    }

    /// Upload one part. Retry and conflicting bytes are checked against the first
    /// dispatched digest even if that dispatch lost its acknowledgement.
    pub fn upload_part(
        &mut self,
        tree: &RegionTree,
        now: TimestampNs,
        index: u64,
        bytes: &[u8],
    ) -> Result<PartReceipt, UploaderError> {
        self.validate_dispatch_owner(tree, now)?;
        self.require_forward_work()?;
        Ok(self.session.upload_part(
            UploadIo {
                authority: &mut self.authority,
                tree,
                now,
            },
            &self.plan,
            index,
            bytes,
        )?)
    }

    /// Start if necessary, then supply and upload every remaining part. The clock
    /// is sampled before source access and again after it, before each dispatch.
    /// Cancellation never implies that the provider staging has been aborted.
    pub fn upload_chunks(
        &mut self,
        tree: &RegionTree,
        mut clock: impl FnMut() -> TimestampNs,
        mut bytes_for: impl FnMut(u64) -> Vec<u8>,
    ) -> Result<(), UploaderError> {
        let now = clock();
        self.check_source_access(tree, now)?;
        if self.session.phase() == MultipartPhase::Prepared {
            self.start(tree, now)?;
        }
        if let MultipartPhase::Uncertain(operation) = self.session.phase() {
            return Err(MultipartError::RequiresReconciliation { operation }.into());
        }
        if self.session.phase() != MultipartPhase::Uploading {
            return Err(MultipartError::WrongState {
                operation: crate::multipart::TransportOperation::UploadPart,
                state: self.session.phase(),
            }
            .into());
        }
        for chunk in self.plan.chunks.clone() {
            if self.session.confirmed_part(chunk.index).is_some() {
                continue;
            }
            self.check_source_access(tree, clock())?;
            let bytes = bytes_for(chunk.index);
            self.upload_part(tree, clock(), chunk.index, &bytes)?;
        }
        Ok(())
    }

    fn check_source_access(
        &mut self,
        tree: &RegionTree,
        now: TimestampNs,
    ) -> Result<(), UploaderError> {
        self.validate_dispatch_owner(tree, now)?;
        if self.authority.is_cancel_requested(tree)? || self.cancellation_requested {
            return Err(UploaderError::CancellationRequested {
                confirmed_parts: self.confirmed_parts(),
            });
        }
        if now < self.session.observed_at() {
            return Err(MultipartError::ClockRegression.into());
        }
        let node = tree.get(self.authority.region()).map_err(authority)?;
        if node
            .authority
            .deadline
            .is_some_and(|deadline| now >= deadline)
        {
            return Err(MultipartError::Deadline.into());
        }
        self.authority
            .require_grant_for(RuntimeGrant::ObjectStage, self.intent().resource())
            .map_err(authority)?;
        self.authority
            .require_grant_for(RuntimeGrant::AdapterNet, self.intent().resource())
            .map_err(authority)?;
        Ok(())
    }

    /// Publish the bound root, then resolve and finalize the actual owning child.
    /// On any error, retain this handle and reconcile or retry the remaining local
    /// terminal work. A lost completion ACK never authorizes a blind abort.
    pub fn finish(
        &mut self,
        tree: &mut RegionTree,
        now: TimestampNs,
    ) -> Result<CompletionReceipt, UploaderError> {
        self.validate_dispatch_owner(tree, now)?;
        if self.session.phase() != MultipartPhase::Completed {
            self.require_forward_work()?;
        }
        let root = self.session.intent().manifest_root();
        let receipt = self.session.complete(
            UploadIo {
                authority: &mut self.authority,
                tree,
                now,
            },
            &self.plan,
            root,
        )?;
        self.settle(tree, now, ObligationTerminal::Completed, receipt.digest())?;
        Ok(receipt)
    }

    /// Explicitly abort known uncommitted staging, then resolve/finalize its owner.
    /// Cleanup remains bounded and grant-checked after cancellation or deadline.
    pub fn cancel(
        &mut self,
        tree: &mut RegionTree,
        now: TimestampNs,
    ) -> Result<AbortReceipt, UploaderError> {
        self.validate_dispatch_owner(tree, now)?;
        let receipt = self.session.abort(UploadIo {
            authority: &mut self.authority,
            tree,
            now,
        })?;
        self.settle(tree, now, ObligationTerminal::Drained, receipt.digest())?;
        Ok(receipt)
    }

    /// Query an uncertain dispatch. Unknown leaves its obligation pending. A
    /// conclusive terminal result settles the owner without repeating the effect.
    pub fn reconcile(
        &mut self,
        tree: &mut RegionTree,
        now: TimestampNs,
    ) -> Result<MultipartPhase, UploaderError> {
        self.validate_dispatch_owner(tree, now)?;
        let phase = self.session.reconcile(UploadIo {
            authority: &mut self.authority,
            tree,
            now,
        })?;
        match phase {
            MultipartPhase::Completed => {
                let receipt = self.session.completion_receipt()?;
                self.settle(tree, now, ObligationTerminal::Completed, receipt.digest())?;
            }
            MultipartPhase::Aborted => {
                self.cancel(tree, now.max(self.session.observed_at()))?;
            }
            _ => {}
        }
        Ok(phase)
    }

    /// Close local ownership of a currently uncertain dispatch with a bounded follow-up
    /// record. This makes no provider rollback/completion claim and performs no transport I/O.
    /// Spent work stays charged. Once recorded, further source/transport work is refused even
    /// if local finalization still needs retrying; identical settlement retries retain the proof.
    pub fn settle_indeterminate(
        &mut self,
        tree: &mut RegionTree,
        now: TimestampNs,
        note: &str,
        reconciliation_reference: ContentDigest,
    ) -> Result<IndeterminateUploadReceipt, UploaderError> {
        self.validate_owner(tree, now)?;
        let MultipartPhase::Uncertain(operation) = self.session.phase() else {
            return Err(authority(
                "only an uncertain dispatch can close as indeterminate",
            ));
        };
        let receipt = make_indeterminate_receipt(
            self.intent().digest(),
            self.region().clone(),
            self.obligation.obligation_id.clone(),
            operation,
            reconciliation_reference,
            note,
        )?;
        if let Some(existing) = &self.indeterminate_receipt {
            if existing != &receipt {
                return Err(authority("unresolved-upload settlement request changed"));
            }
            if self.settled {
                return Ok(receipt);
            }
        } else {
            if self.obligation.state != ObligationState::Pending {
                return Err(authority("upload already has a different terminal outcome"));
            }
            // Retain the proposed receipt even if persistence refuses. The
            // provider must remain relinquished while its durable outcome is
            // uncertain; the canonical pending obligation is not yet resolved.
            self.indeterminate_receipt = Some(receipt.clone());
        }
        self.persist_record(tree, now, self.owner_record(tree)?)?;
        if self.obligation.state == ObligationState::Pending {
            self.authority.resolve_obligation(
                tree,
                &self.obligation.obligation_id,
                ObligationTerminal::Indeterminate,
                Some(receipt.digest()),
                Some(receipt.note()),
            )?;
            self.obligation.state = ObligationState::Indeterminate;
            self.obligation.proof_digest = Some(receipt.digest());
            self.reconciliation_note = Some(receipt.note().to_string());
        } else if self.obligation.state != ObligationState::Indeterminate
            || self.obligation.proof_digest != Some(receipt.digest())
            || self.reconciliation_note.as_deref() != Some(receipt.note())
        {
            return Err(authority("unresolved-upload terminal receipt mismatch"));
        }
        self.close_and_release(tree, now)?;
        Ok(receipt)
    }

    fn validate_owner(&self, tree: &RegionTree, now: TimestampNs) -> Result<(), UploaderError> {
        // Validate both actual contexts, not only region labels or a session's terminal flag.
        self.parent.is_cancel_requested(tree)?;
        self.authority.is_cancel_requested(tree)?;
        if now < self.observed_at.max(self.session.observed_at()) {
            return Err(MultipartError::ClockRegression.into());
        }
        for region in [self.parent.region(), self.authority.region()] {
            let node = tree.get(region).map_err(authority)?;
            if now < node.created_at
                || node.drain_requested_at.is_some_and(|at| now < at)
                || node.closed_at.is_some_and(|at| now < at)
            {
                return Err(MultipartError::ClockRegression.into());
            }
        }
        let node = tree.get(self.authority.region()).map_err(authority)?;
        if node.obligations.get(&self.obligation.obligation_id) != Some(&self.obligation)
            || node
                .reconciliation_obligations
                .get(&self.obligation.obligation_id)
                != self.reconciliation_note.as_ref()
        {
            return Err(authority(
                "owned upload obligation or reconciliation note changed",
            ));
        }
        Ok(())
    }

    fn validate_dispatch_owner(
        &mut self,
        tree: &RegionTree,
        now: TimestampNs,
    ) -> Result<(), UploaderError> {
        self.validate_owner(tree, now)?;
        if self.indeterminate_receipt.is_some() {
            return Err(authority(
                "upload ownership is closing as indeterminate; transport is relinquished",
            ));
        }
        self.observed_at = now;
        if self.session.is_durable() && !self.settled {
            // Capture cancellation and any fresh recovery restrictions before
            // the protocol is allowed to dispatch or touch a payload source.
            self.checkpoint(tree, now)?;
        }
        Ok(())
    }

    fn require_forward_work(&self) -> Result<(), UploaderError> {
        // Preserve the original uncertain operation rather than implying that
        // cancellation made an unresolved dispatch safe to retry or abort.
        if let MultipartPhase::Uncertain(operation) = self.session.phase() {
            return Err(MultipartError::RequiresReconciliation { operation }.into());
        }
        if self.cancellation_requested {
            return Err(MultipartError::CancellationRequested.into());
        }
        Ok(())
    }

    fn settle(
        &mut self,
        tree: &mut RegionTree,
        now: TimestampNs,
        terminal: ObligationTerminal,
        proof: ContentDigest,
    ) -> Result<(), UploaderError> {
        // A transport can advance its explicit clock while an admitted call is
        // in flight. Never date terminal closure before that observed boundary.
        let now = now.max(self.session.observed_at());
        self.validate_owner(tree, now)?;
        if self.obligation.state != ObligationState::Pending
            && (self.obligation.state != terminal.to_state()
                || self.obligation.proof_digest != Some(proof)
                || self.reconciliation_note.is_some())
        {
            return Err(authority("upload terminal receipt mismatch"));
        }
        if self.settled {
            return Ok(());
        }
        let mut record = self.owner_record(tree)?;
        record.obligation.state = terminal.to_state();
        record.obligation.proof_digest = Some(proof);
        self.persist_record(tree, now, record)?;
        if self.obligation.state == ObligationState::Pending {
            self.authority.resolve_obligation(
                tree,
                &self.obligation.obligation_id,
                terminal,
                Some(proof),
                None,
            )?;
            self.obligation.state = terminal.to_state();
            self.obligation.proof_digest = Some(proof);
        }
        self.close_and_release(tree, now)
    }

    fn close_and_release(
        &mut self,
        tree: &mut RegionTree,
        now: TimestampNs,
    ) -> Result<(), UploaderError> {
        self.validate_owner(tree, now)?;
        self.observed_at = now;
        if self.settled {
            return Ok(());
        }
        if self.obligation.state == ObligationState::Pending {
            return Err(authority("pending upload has no terminal closure record"));
        }
        let region = self.authority.region().clone();
        if tree.get(&region).map_err(authority)?.state != RegionState::Closed {
            match tree.get(&region).map_err(authority)?.state {
                RegionState::Active => {
                    tree.request_drain(&region, Some("multipart ownership receipt recorded"), now)
                        .map_err(authority)?;
                    self.authority.begin_drain(tree, now)?;
                }
                RegionState::DrainRequested => {
                    self.authority.begin_drain(tree, now)?;
                }
                RegionState::Draining | RegionState::Finalizing => {}
                RegionState::Closed => {}
            }
            self.authority.finalize(tree, now)?;
        }
        self.parent
            .release_scope_reservation(tree, &mut self.authority)?;
        self.settled = true;
        Ok(())
    }

    /// Narrow or revoke this child's actual resource grants; widening is refused.
    /// Journaled owners must use `narrow_grants_durable` so a crash cannot erase
    /// a successful revocation.
    pub fn narrow_grants(&mut self, grants: GrantSet) -> Result<(), UploaderError> {
        if self.session.is_durable() {
            return Err(authority(
                "journaled grant changes require narrow_grants_durable",
            ));
        }
        self.authority.narrow_grants(grants).map_err(authority)
    }

    /// Durably narrow resource grants before applying the live revocation.
    /// Persistence failure preserves the owner and blocks further dispatch.
    pub fn narrow_grants_durable(
        &mut self,
        tree: &RegionTree,
        now: TimestampNs,
        grants: GrantSet,
    ) -> Result<(), UploaderError> {
        self.validate_owner(tree, now)?;
        if !self.session.is_durable() {
            return Err(authority("upload has no attached journal"));
        }
        self.authority
            .grants()
            .verify_narrowed_by(&grants)
            .map_err(authority)?;
        let mut record = self.owner_record(tree)?;
        record.grants.retain(|capability| {
            RuntimeGrant::from_id(capability).is_ok_and(|grant| {
                grants
                    .require_grant_for(grant, self.intent().resource())
                    .is_ok()
            })
        });
        self.persist_record(tree, now, record)?;
        self.authority.narrow_grants(grants).map_err(authority)?;
        self.observed_at = now;
        Ok(())
    }
    /// Current immutable child grants, including inherited resource restrictions.
    #[must_use]
    pub fn grants(&self) -> &GrantSet {
        self.authority.grants()
    }
    /// Actual consumed/remaining child allowance.
    #[must_use]
    pub fn budget(&self) -> &fss_runtime::budget::BudgetLedger {
        self.authority.budget()
    }

    /// Consumption across every recovered execution epoch, including the
    /// current child's actual ledger. Historical work is never a fresh allowance.
    pub fn cumulative_consumed(&self) -> Result<BudgetVector, UploaderError> {
        Ok(self.session.cumulative_consumed(&self.authority)?)
    }

    /// Latest successfully persisted checkpoint pin for independent retention.
    #[must_use]
    pub fn journal_pin(&self) -> Option<UploadJournalPin> {
        self.session.journal_pin()
    }

    /// Whether this owner requires journal persistence before further effects.
    #[must_use]
    pub fn is_durable(&self) -> bool {
        self.session.is_durable()
    }

    /// An ambiguous append cannot be retried in place; cold recovery must first
    /// establish which exact checkpoint is durable.
    #[must_use]
    pub fn durability_failed(&self) -> bool {
        self.session.durability_failed()
    }
    /// Pending or terminal obligation on this exact child.
    #[must_use]
    pub const fn obligation(&self) -> &ObligationId {
        &self.obligation.obligation_id
    }

    /// Retained unresolved receipt, including while local finalization is still blocked.
    #[must_use]
    pub fn indeterminate_receipt(&self) -> Option<&IndeterminateUploadReceipt> {
        self.indeterminate_receipt.as_ref()
    }
    /// Actual child region, not a label attached to work owned by its parent.
    #[must_use]
    pub fn region(&self) -> &RegionId {
        self.authority.region()
    }
    /// Immutable upload identity for reconciliation.
    #[must_use]
    pub fn intent(&self) -> &UploadIntent {
        self.session.intent()
    }
    /// Current protocol knowledge; cancellation requests are not terminal states.
    #[must_use]
    pub fn phase(&self) -> MultipartPhase {
        self.session.phase()
    }
    /// Exactly confirmed parts, unaffected by idempotent replay.
    #[must_use]
    pub fn confirmed_parts(&self) -> usize {
        self.session.confirmed_parts()
    }
}
