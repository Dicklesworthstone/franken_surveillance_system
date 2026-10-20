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
//! The region tree is an in-process owner, not a durable transfer journal. Dropping
//! unsettled work leaves a visible child obligation and charged reservation.
//! No network transport, encryption implementation or retrievability claim is added.

use fss_core::{
    BudgetVector, CanonicalEncoder, ContentDigest, ContextAuthority, DigestAlgorithm, Obligation,
    ObligationId, ObligationState, OperationId, RegionId, RegionKind, RegionState, RegionTree,
    RootAuthoritySpec, RuntimeGrant, TimestampNs,
};
use fss_runtime::authority::{AuthorityCx, AuthorityError};
use fss_runtime::grant::GrantSet;
use fss_runtime::obligation::{ObligationTerminal, new_obligation};

use crate::multipart::{
    AbortReceipt, CompletionReceipt, MultipartError, MultipartPhase, MultipartSession,
    MultipartTransport, PartReceipt, TransportOperation, UploadIntent, UploadIo,
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
/// This records a follow-up reference, not provider rollback, completion, or durable external
/// journal persistence. The exact bound note and proof remain on the canonical child obligation.
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
    obligation: Obligation,
    reconciliation_note: Option<String>,
    indeterminate_receipt: Option<IndeterminateUploadReceipt>,
    session: MultipartSession<'a, T>,
    plan: ChunkPlan,
    observed_at: TimestampNs,
    settled: bool,
}

impl<T: MultipartTransport> StagedUpload<'_, T> {
    /// Pure owned preparation: validate intent and grants, reserve the caller's
    /// exact allowance, and register the pending obligation on the child itself.
    /// No provider call is hidden in this fallible constructor.
    #[allow(clippy::too_many_arguments)]
    pub fn stage<'a>(
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
            "exact multipart intent completed or staging conclusively aborted",
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
            obligation,
            reconciliation_note: None,
            indeterminate_receipt: None,
            session,
            plan,
            observed_at: now,
            settled: false,
        })
    }

    /// Explicit initiation; failures retain the stable intent and pending child.
    pub fn start(&mut self, tree: &RegionTree, now: TimestampNs) -> Result<(), UploaderError> {
        self.validate_dispatch_owner(tree, now)?;
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
        if self.authority.is_cancel_requested(tree)? {
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
        let (operation_tag, operation_name) = match operation {
            TransportOperation::Initiate => (1, "initiate"),
            TransportOperation::UploadPart => (2, "upload_part"),
            TransportOperation::Complete => (3, "complete"),
            TransportOperation::Abort => (4, "abort"),
            TransportOperation::Reconcile => (5, "reconcile"),
        };
        let note = format!(
            "multipart unresolved; intent={}; operation={operation_name}; reference={reconciliation_reference}; note={note}",
            self.intent().digest(),
        );
        // The human note plus fixed SHA-256 bindings remain within the canonical note budget.
        if note.len() > 512 {
            return Err(authority("bound unresolved-upload note exceeds its limit"));
        }
        let mut encoder = CanonicalEncoder::new();
        encoder.text("fss.multipart_indeterminate.v1");
        encoder.digest(self.intent().digest());
        encoder.text(self.region().as_str());
        encoder.text(self.obligation.obligation_id.as_str());
        encoder.u8(operation_tag);
        encoder.digest(reconciliation_reference);
        encoder.text(&note);
        let bytes = encoder.finish_checked().map_err(authority)?;
        let receipt = IndeterminateUploadReceipt {
            intent_digest: self.intent().digest(),
            region: self.region().clone(),
            obligation: self.obligation.obligation_id.clone(),
            operation,
            reconciliation_reference,
            note,
            digest: ContentDigest::sha256(&bytes),
        };
        if let Some(existing) = &self.indeterminate_receipt {
            if existing != &receipt {
                return Err(authority("unresolved-upload settlement request changed"));
            }
        } else {
            if self.obligation.state != ObligationState::Pending {
                return Err(authority("upload already has a different terminal outcome"));
            }
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
            self.indeterminate_receipt = Some(receipt.clone());
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
        } else if self.obligation.state != terminal.to_state()
            || self.obligation.proof_digest != Some(proof)
            || self.reconciliation_note.is_some()
        {
            return Err(authority("upload terminal receipt mismatch"));
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
    pub fn narrow_grants(&mut self, grants: GrantSet) -> Result<(), UploaderError> {
        self.authority.narrow_grants(grants).map_err(authority)
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
