#![forbid(unsafe_code)]
//! Authority-owned multipart upload with explicit, recoverable terminal work.
//!
//! Preparation owns the actual ObjectStore child, its reserved allowance and its
//! pending obligation. Every transport call uses that child. Neither a failed
//! dispatch nor cancellation consumes the owner: completion/abort uncertainty
//! must be reconciled. Only a conclusive terminal receipt resolves the obligation,
//! drains/finalizes the child and returns unused allowance to its exact parent.
//!
//! The region tree is an in-process owner, not a durable transfer journal. Dropping
//! unfinished work leaves a visible pending child obligation and charged reservation.
//! No network transport, encryption implementation or retrievability claim is added.

use fss_core::{
    BudgetVector, ContentDigest, ContextAuthority, ObligationId, OperationId, RegionId, RegionKind,
    RegionState, RegionTree, RootAuthoritySpec, RuntimeGrant, TimestampNs,
};
use fss_runtime::authority::{AuthorityCx, AuthorityError};
use fss_runtime::grant::GrantSet;
use fss_runtime::obligation::{ObligationTerminal, new_obligation};

use crate::multipart::{
    AbortReceipt, CompletionReceipt, MultipartError, MultipartPhase, MultipartSession,
    MultipartTransport, PartReceipt, UploadIntent, UploadIo,
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

/// An unfinished upload must stay owned until it is completed or conclusively aborted.
#[must_use = "retain the upload owner until completion, abort or explicit reconciliation"]
pub struct StagedUpload<'a, T: MultipartTransport> {
    parent: &'a mut AuthorityCx,
    authority: AuthorityCx,
    obligation: ObligationId,
    session: MultipartSession<'a, T>,
    plan: ChunkPlan,
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
        let obligation_id = obligation.obligation_id.clone();
        // The exclusive tree borrow has not escaped: this freshly attached child
        // is active, empty and unique. Registration's absent/inactive/duplicate/
        // capacity refusals therefore cannot occur after successful attachment.
        child.register_obligation(tree, obligation)?;
        Ok(StagedUpload {
            parent,
            authority: child,
            obligation: obligation_id,
            session,
            plan,
            settled: false,
        })
    }

    /// Explicit initiation; failures retain the stable intent and pending child.
    pub fn start(&mut self, tree: &RegionTree, now: TimestampNs) -> Result<(), UploaderError> {
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
        &self,
        tree: &RegionTree,
        now: TimestampNs,
    ) -> Result<(), UploaderError> {
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
                self.cancel(tree, now)?;
            }
            _ => {}
        }
        Ok(phase)
    }

    fn settle(
        &mut self,
        tree: &mut RegionTree,
        now: TimestampNs,
        terminal: ObligationTerminal,
        proof: ContentDigest,
    ) -> Result<(), UploaderError> {
        self.authority.is_cancel_requested(tree)?;
        // A transport can advance its explicit clock while an admitted call is
        // in flight. Never date terminal closure before that observed boundary.
        let now = now.max(self.session.observed_at());
        if self.settled {
            return Ok(());
        }
        let region = self.authority.region().clone();
        if tree.get(&region).map_err(authority)?.state != RegionState::Closed {
            self.authority.resolve_obligation(
                tree,
                &self.obligation,
                terminal,
                Some(proof),
                None,
            )?;
            match tree.get(&region).map_err(authority)?.state {
                RegionState::Active => {
                    tree.request_drain(&region, Some("multipart terminal receipt recorded"), now)
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
        } else {
            let recorded = tree
                .get(&region)
                .map_err(authority)?
                .obligations
                .get(&self.obligation)
                .ok_or_else(|| authority("closed upload has no terminal obligation"))?;
            if recorded.state != terminal.to_state() || recorded.proof_digest != Some(proof) {
                return Err(authority("closed upload terminal receipt mismatch"));
            }
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
        &self.obligation
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
