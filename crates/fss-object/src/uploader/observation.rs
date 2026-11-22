#![forbid(unsafe_code)]
//! A new read-only owner can observe a locally relinquished upload without
//! reopening that upload's mutation authority or rewriting its terminal record.

use super::*;
use crate::multipart::{ProviderUploadState, admit_observation};

/// Bound on one canonical, payload-free observation receipt.
pub const MAX_COMPLETION_OBSERVATION_BYTES: usize = 64 * 1024;
const DOMAIN: &str = "fss.multipart_completion_observation.v1";
const PREDICATE: &str = "bounded read-only upload observation finalized with an immutable receipt";

/// Provider knowledge established by one independently authorized read.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CompletionObservationOutcome {
    /// No provider observation was dispatched. The old outcome is unchanged.
    NotObserved,
    /// A read was attempted but did not prove the exact completion.
    Unknown,
    /// The exact intent, upload, root and full acknowledged part inventory were
    /// independently confirmed. This is not a retrievability or replica proof.
    Completed,
}

/// Immutable observation of an older indeterminate upload. Its source pin and
/// receipt identify unchanged historical records; this is not an amended upload
/// checkpoint. Persist these canonical bytes through the caller's scoped local
/// custody before presenting a durable observation claim.
#[derive(Clone, Debug, PartialEq)]
pub struct CompletionObservationReceipt {
    source_pin: UploadJournalPin,
    source_operation: OperationId,
    indeterminate_receipt: ContentDigest,
    intent_digest: ContentDigest,
    plan_digest: ContentDigest,
    manifest_root: ContentDigest,
    authority: ContextAuthority,
    started_at: TimestampNs,
    observed_at: TimestampNs,
    consumed: BudgetVector,
    outcome: CompletionObservationOutcome,
    completion_digest: Option<ContentDigest>,
}

fn good_digest(digest: ContentDigest) -> bool {
    digest.algorithm() == DigestAlgorithm::Sha256 && digest.bytes() != [0; 32]
}

fn observer_capabilities() -> Vec<String> {
    let mut capabilities: Vec<_> = [
        RuntimeGrant::AdapterAuth,
        RuntimeGrant::AdapterNet,
        RuntimeGrant::ObserveStatus,
    ]
    .into_iter()
    .map(|grant| grant.as_str().to_owned())
    .collect();
    capabilities.sort();
    capabilities
}

impl CompletionObservationReceipt {
    fn validate(&self) -> Result<(), MultipartError> {
        self.authority.validate().map_err(checkpoint_error)?;
        if self.source_pin.sequence == 0
            || ![
                self.source_pin.root,
                self.indeterminate_receipt,
                self.intent_digest,
                self.plan_digest,
                self.manifest_root,
            ]
            .into_iter()
            .all(good_digest)
            || self.source_operation == self.authority.operation_id
            || self.authority.capabilities() != observer_capabilities()
            || self.authority.cancellation_reason.is_some()
            || self
                .authority
                .deadline
                .is_none_or(|at| at <= self.started_at)
            || self.started_at > self.observed_at
            || !self.consumed.is_valid()
            || !self.consumed.fits_within(self.authority.budgets)
            || self
                .completion_digest
                .is_some_and(|digest| !good_digest(digest))
            || (self.outcome == CompletionObservationOutcome::Completed)
                != self.completion_digest.is_some()
            || (self.outcome == CompletionObservationOutcome::NotObserved
                && self.consumed.storage_operations != 0)
            || (self.outcome != CompletionObservationOutcome::NotObserved
                && self.consumed.storage_operations != 1)
        {
            return Err(MultipartError::InvalidCheckpoint);
        }
        Ok(())
    }

    /// Strict canonical bytes. They contain no object path, provider token,
    /// credential, response body, source media or arbitrary provider error.
    pub fn encode(&self) -> Result<Vec<u8>, MultipartError> {
        self.validate()?;
        let mut e = CanonicalEncoder::new();
        e.text(DOMAIN);
        e.u64(self.source_pin.sequence);
        e.digest(self.source_pin.root);
        e.text(self.source_operation.as_str());
        e.digest(self.indeterminate_receipt);
        e.digest(self.intent_digest);
        e.digest(self.plan_digest);
        e.digest(self.manifest_root);
        self.authority.encode_canonical(&mut e);
        e.i128(self.started_at.0);
        e.i128(self.observed_at.0);
        self.consumed.encode_canonical(&mut e);
        e.u8(match self.outcome {
            CompletionObservationOutcome::NotObserved => 0,
            CompletionObservationOutcome::Unknown => 1,
            CompletionObservationOutcome::Completed => 2,
        });
        e.bool(self.completion_digest.is_some());
        if let Some(digest) = self.completion_digest {
            e.digest(digest);
        }
        let bytes = e.finish_checked().map_err(checkpoint_error)?;
        if bytes.len() > MAX_COMPLETION_OBSERVATION_BYTES {
            return Err(MultipartError::InvalidCheckpoint);
        }
        Ok(bytes)
    }

    /// Decode a retained observation, rejecting noncanonical or unbounded data.
    /// Bytes describe evidence and never reconstruct runtime authority.
    pub fn decode(bytes: &[u8]) -> Result<Self, MultipartError> {
        if bytes.len() > MAX_COMPLETION_OBSERVATION_BYTES {
            return Err(MultipartError::InvalidCheckpoint);
        }
        let mut d = CanonicalDecoder::new(bytes);
        if d.text().map_err(checkpoint_error)? != DOMAIN {
            return Err(MultipartError::InvalidCheckpoint);
        }
        let source_pin = UploadJournalPin {
            sequence: d.u64().map_err(checkpoint_error)?,
            root: d.digest().map_err(checkpoint_error)?,
        };
        let source_operation =
            OperationId::parse(d.text().map_err(checkpoint_error)?).map_err(checkpoint_error)?;
        let indeterminate_receipt = d.digest().map_err(checkpoint_error)?;
        let intent_digest = d.digest().map_err(checkpoint_error)?;
        let plan_digest = d.digest().map_err(checkpoint_error)?;
        let manifest_root = d.digest().map_err(checkpoint_error)?;
        let authority = ContextAuthority::decode_canonical(&mut d).map_err(checkpoint_error)?;
        let started_at = TimestampNs(d.i128().map_err(checkpoint_error)?);
        let observed_at = TimestampNs(d.i128().map_err(checkpoint_error)?);
        let consumed = BudgetVector::decode_canonical(&mut d).map_err(checkpoint_error)?;
        let outcome = match d.u8().map_err(checkpoint_error)? {
            0 => CompletionObservationOutcome::NotObserved,
            1 => CompletionObservationOutcome::Unknown,
            2 => CompletionObservationOutcome::Completed,
            _ => return Err(MultipartError::InvalidCheckpoint),
        };
        let completion_digest = if d.bool().map_err(checkpoint_error)? {
            Some(d.digest().map_err(checkpoint_error)?)
        } else {
            None
        };
        d.ensure_finished().map_err(checkpoint_error)?;
        let receipt = Self {
            source_pin,
            source_operation,
            indeterminate_receipt,
            intent_digest,
            plan_digest,
            manifest_root,
            authority,
            started_at,
            observed_at,
            consumed,
            outcome,
            completion_digest,
        };
        if receipt.encode()? != bytes {
            return Err(MultipartError::InvalidCheckpoint);
        }
        Ok(receipt)
    }

    /// Identity of the complete canonical observation, not only its outcome.
    pub fn digest(&self) -> Result<ContentDigest, MultipartError> {
        Ok(ContentDigest::sha256(&self.encode()?))
    }
    /// Exact unchanged source journal head inspected by this new owner.
    #[must_use]
    pub const fn source_pin(&self) -> UploadJournalPin {
        self.source_pin
    }
    /// Original upload operation, distinct from the new read operation.
    #[must_use]
    pub fn source_operation(&self) -> &OperationId {
        &self.source_operation
    }
    /// Original local indeterminate closure proof; never replaced by this read.
    #[must_use]
    pub const fn indeterminate_receipt_digest(&self) -> ContentDigest {
        self.indeterminate_receipt
    }
    /// Original immutable multipart intent.
    #[must_use]
    pub const fn intent_digest(&self) -> ContentDigest {
        self.intent_digest
    }
    /// Original immutable chunk plan.
    #[must_use]
    pub const fn plan_digest(&self) -> ContentDigest {
        self.plan_digest
    }
    /// Originally requested root; not by itself proof of observed completion.
    #[must_use]
    pub const fn manifest_root(&self) -> ContentDigest {
        self.manifest_root
    }
    /// New read-only operation whose separately authorized allowance was spent.
    #[must_use]
    pub fn operation(&self) -> &OperationId {
        &self.authority.operation_id
    }
    /// Inert complete fresh authority recipe, including purpose, scope and ceiling.
    #[must_use]
    pub fn authority(&self) -> &ContextAuthority {
        &self.authority
    }
    /// Fresh observation's reservation time, unrelated to the original deadline.
    #[must_use]
    pub const fn started_at(&self) -> TimestampNs {
        self.started_at
    }
    /// Final observed time, including refused later transport checkpoints.
    #[must_use]
    pub const fn observed_at(&self) -> TimestampNs {
        self.observed_at
    }
    /// Separate observation ceiling; the source upload budget is untouched.
    #[must_use]
    pub const fn budget(&self) -> BudgetVector {
        self.authority.budgets
    }
    /// Actual read-attempt consumption, also charged through its fresh parent.
    #[must_use]
    pub const fn consumed(&self) -> BudgetVector {
        self.consumed
    }
    /// Honest positive, unknown or undispatched result.
    #[must_use]
    pub const fn outcome(&self) -> CompletionObservationOutcome {
        self.outcome
    }
    /// Exact CompletionReceipt identity only after independently confirmed success.
    #[must_use]
    pub const fn completion_digest(&self) -> Option<ContentDigest> {
        self.completion_digest
    }
}

/// One fresh, bounded, read-only observation of a previously relinquished
/// completion. The old owner remains terminal and its journal is borrowed
/// immutably. Unknown results cannot authorize a mutation or replenish a budget.
#[must_use = "settle the observation owner even when its single read fails"]
pub struct CompletionObservation<'a> {
    parent: &'a mut AuthorityCx,
    authority: AuthorityCx,
    source: &'a MultipartRecovery,
    journal: &'a dyn UploadJournal,
    original_receipt: ContentDigest,
    canonical: ContextAuthority,
    obligation: Obligation,
    started_at: TimestampNs,
    observed_at: TimestampNs,
    attempted: bool,
    completion_digest: Option<ContentDigest>,
    receipt: Option<CompletionObservationReceipt>,
    settled: bool,
}

impl<'a> CompletionObservation<'a> {
    /// Pure eligibility check, suitable before credential access. Only an exact,
    /// independently pinned, locally indeterminate COMPLETE with every part
    /// acknowledged is eligible. Revoked network/auth grants stay revoked.
    pub fn validate_source(
        recovery: &MultipartRecovery,
        expected_intent: &UploadIntent,
    ) -> Result<(), UploaderError> {
        let record =
            validated_recovery_owner(recovery)?.ok_or(MultipartError::InvalidCheckpoint)?;
        if recovery.intent() != expected_intent
            || recovery.phase() != MultipartPhase::Uncertain(TransportOperation::Complete)
            || record.obligation.state != ObligationState::Indeterminate
            || record.indeterminate_receipt.is_none()
            || recovery.upload_id().is_none()
            || recovery.confirmed_parts() != recovery.plan().chunks.len()
            || recovery.plan().chunks.is_empty()
        {
            return Err(MultipartError::InvalidCheckpoint.into());
        }
        for grant in [RuntimeGrant::AdapterNet, RuntimeGrant::AdapterAuth] {
            if !record.grants.iter().any(|cap| cap == grant.as_str()) {
                return Err(authority(
                    "original upload no longer permits this provider read",
                ));
            }
        }
        Ok(())
    }

    /// Validate historical evidence and explicit new authority before reserving
    /// a child. No credential, provider or journal write occurs. A new operation,
    /// finite deadline and allowance permit a read after the old deadline; they
    /// do not revive the old upload or broaden its identity/privacy restrictions.
    #[allow(clippy::too_many_arguments)]
    pub fn begin(
        parent: &'a mut AuthorityCx,
        tree: &mut RegionTree,
        journal: &'a dyn UploadJournal,
        recovery: &'a MultipartRecovery,
        expected_intent: &UploadIntent,
        child_spec: RootAuthoritySpec,
        now: TimestampNs,
    ) -> Result<Self, UploaderError> {
        Self::validate_source(recovery, expected_intent)?;
        recovery.validate_restore(journal, now)?;
        if parent.is_cancel_requested(tree)? {
            return Err(MultipartError::CancellationRequested.into());
        }
        let parent_node = tree.get(parent.region()).map_err(authority)?;
        if now < parent_node.created_at
            || parent_node.drain_requested_at.is_some_and(|at| now < at)
            || parent_node.closed_at.is_some_and(|at| now < at)
        {
            return Err(MultipartError::ClockRegression.into());
        }
        let canonical = ContextAuthority::new_root(child_spec.clone()).map_err(authority)?;
        canonical.validate().map_err(authority)?;
        canonical
            .verify_narrowing_of(&parent_node.authority)
            .map_err(authority)?;
        let original = recovery.effective_authority();
        if canonical.operation_id == *expected_intent.operation()
            || canonical.capabilities() != observer_capabilities()
            || canonical.trace_id != original.trace_id
            || canonical.principal != original.principal
            || canonical.anchor_universe != original.anchor_universe
            || canonical.generation != original.generation
            || canonical.priority < original.priority
            || canonical.privacy_scope != original.privacy_scope
            || canonical.retention_scope != original.retention_scope
            || canonical.lease_fence != original.lease_fence
            || canonical.idempotency_key != original.idempotency_key
            || canonical.lab_controls != original.lab_controls
            || canonical.budgets.storage_operations == 0
        {
            return Err(authority(
                "observation authority changed the upload scope or read-only purpose",
            ));
        }
        if canonical.deadline.is_none_or(|at| now >= at) {
            return Err(MultipartError::Deadline.into());
        }
        let offered = parent
            .grants()
            .scope_for_child(&canonical)
            .map_err(authority)?;
        let mut grants = GrantSet::empty();
        for grant in [
            RuntimeGrant::AdapterNet,
            RuntimeGrant::AdapterAuth,
            RuntimeGrant::ObserveStatus,
        ] {
            offered
                .require_grant_for(grant, expected_intent.resource())
                .map_err(authority)?;
            grants = grants.with_scope(
                grant,
                BTreeSet::from([expected_intent.resource().to_owned()]),
            );
        }
        offered.verify_narrowed_by(&grants).map_err(authority)?;
        let original_receipt = validated_recovery_owner(recovery)?
            .and_then(|record| record.indeterminate_receipt)
            .ok_or(MultipartError::InvalidCheckpoint)?
            .digest();
        let region = RegionId::new(format!(
            "region:upload-observation:{}",
            canonical.operation_id.as_str()
        ))
        .map_err(authority)?;
        let obligation = new_obligation(
            format!(
                "obligation:upload-observation:{}:drain",
                canonical.operation_id.as_str()
            ),
            canonical.operation_id.clone(),
            PREDICATE,
        )
        .map_err(authority)?;
        let mut child = parent.scope_down(
            tree,
            region,
            RegionKind::ObjectStore,
            child_spec.budgets,
            child_spec,
            now,
        )?;
        child.narrow_grants(grants).map_err(authority)?;
        child.register_obligation(tree, obligation.clone())?;
        Ok(Self {
            parent,
            authority: child,
            source: recovery,
            journal,
            original_receipt,
            canonical,
            obligation,
            started_at: now,
            observed_at: now,
            attempted: false,
            completion_digest: None,
            receipt: None,
            settled: false,
        })
    }

    /// Perform at most one admitted provider read. Only Unknown or the exact
    /// completed upload is accepted; no active, aborted or not-started result
    /// can release mutation authority. A failure retains this owner for settle.
    pub fn observe<T: MultipartTransport>(
        &mut self,
        tree: &mut RegionTree,
        transport: &mut T,
        now: TimestampNs,
    ) -> Result<CompletionObservationReceipt, UploaderError> {
        self.validate_owner(tree, now)?;
        if self.attempted || self.receipt.is_some() {
            return Err(authority(
                "observation already attempted; settle or retain its receipt",
            ));
        }
        self.source.validate_restore(self.journal, now)?;
        self.observed_at = now;
        let mut cx = admit_observation(
            UploadIo {
                authority: &mut self.authority,
                tree,
                now,
            },
            self.source.intent().resource(),
            self.source.origin_binding(),
        )?;
        self.attempted = true;
        let result = transport.reconcile(&mut cx, self.source.intent());
        let checked = cx.checkpoint(cx.now());
        self.observed_at = cx.now();
        drop(cx);
        checked?;
        let response = result.map_err(|_| MultipartError::Transport {
            operation: TransportOperation::Reconcile,
            detail: "read-only completion observation was inconclusive".into(),
        })?;
        if response.intent_digest != self.source.intent().digest() {
            return Err(MultipartError::ReconciliationMismatch.into());
        }
        match response.state {
            ProviderUploadState::Unknown => {}
            ProviderUploadState::Completed {
                upload,
                manifest_root,
                parts,
            } => {
                if Some(&upload) != self.source.upload_id()
                    || manifest_root != self.source.intent().manifest_root()
                    || parts.len() != self.source.plan().chunks.len()
                    || !parts.iter().eq(self.source.part_receipts())
                {
                    return Err(MultipartError::ReconciliationMismatch.into());
                }
                self.completion_digest = Some(
                    CompletionReceipt {
                        intent_digest: response.intent_digest,
                        upload,
                        manifest_root,
                        parts,
                    }
                    .digest(),
                );
            }
            _ => return Err(MultipartError::ReconciliationMismatch.into()),
        }
        self.settle(tree, self.observed_at)
    }

    /// Finalize a successful, inconclusive, refused or cancelled observation.
    /// This makes no provider call, needs no live deadline and is idempotent
    /// after closure. Only this new child's unused reservation is returned.
    pub fn settle(
        &mut self,
        tree: &mut RegionTree,
        now: TimestampNs,
    ) -> Result<CompletionObservationReceipt, UploaderError> {
        self.validate_owner(tree, now)?;
        self.observed_at = now;
        let receipt = if let Some(receipt) = &self.receipt {
            receipt.clone()
        } else {
            let receipt = CompletionObservationReceipt {
                source_pin: self.source.head(),
                source_operation: self.source.intent().operation().clone(),
                indeterminate_receipt: self.original_receipt,
                intent_digest: self.source.intent().digest(),
                plan_digest: self.source.intent().plan_digest(),
                manifest_root: self.source.intent().manifest_root(),
                authority: self.canonical.clone(),
                started_at: self.started_at,
                observed_at: now,
                consumed: *self.authority.budget().consumed(),
                outcome: if self.completion_digest.is_some() {
                    CompletionObservationOutcome::Completed
                } else if self.attempted {
                    CompletionObservationOutcome::Unknown
                } else {
                    CompletionObservationOutcome::NotObserved
                },
                completion_digest: self.completion_digest,
            };
            receipt.validate()?;
            self.receipt = Some(receipt.clone());
            receipt
        };
        if self.settled {
            return Ok(receipt);
        }
        if self.obligation.state == ObligationState::Pending {
            let proof = receipt.digest()?;
            self.authority.resolve_obligation(
                tree,
                &self.obligation.obligation_id,
                ObligationTerminal::Completed,
                Some(proof),
                None,
            )?;
            self.obligation.state = ObligationState::Verified;
            self.obligation.proof_digest = Some(proof);
        }
        let region = self.authority.region().clone();
        match tree.get(&region).map_err(authority)?.state {
            RegionState::Active => {
                tree.request_drain(&region, Some("read-only upload observation recorded"), now)
                    .map_err(authority)?;
                self.authority.begin_drain(tree, now)?;
            }
            RegionState::DrainRequested => self.authority.begin_drain(tree, now)?,
            RegionState::Draining | RegionState::Finalizing | RegionState::Closed => {}
        }
        if tree.get(&region).map_err(authority)?.state != RegionState::Closed {
            self.authority.finalize(tree, now)?;
        }
        self.parent
            .release_scope_reservation(tree, &mut self.authority)?;
        self.settled = true;
        Ok(receipt)
    }

    fn validate_owner(&self, tree: &RegionTree, now: TimestampNs) -> Result<(), UploaderError> {
        self.parent.is_cancel_requested(tree)?;
        self.authority.is_cancel_requested(tree)?;
        if now < self.observed_at {
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
        if tree
            .get(self.region())
            .map_err(authority)?
            .obligations
            .get(&self.obligation.obligation_id)
            != Some(&self.obligation)
        {
            return Err(authority("read-only observation obligation changed"));
        }
        Ok(())
    }

    /// Scope for cancellation/status; no mutable transport authority is exposed.
    #[must_use]
    pub fn region(&self) -> &RegionId {
        self.authority.region()
    }
    /// Actual separate read allowance and consumption.
    #[must_use]
    pub fn budget(&self) -> &fss_runtime::budget::BudgetLedger {
        self.authority.budget()
    }
    /// Latest observed boundary, including a failed transport checkpoint.
    #[must_use]
    pub const fn observed_at(&self) -> TimestampNs {
        self.observed_at
    }
    /// Receipt retained even when local finalization needs another attempt.
    #[must_use]
    pub fn receipt(&self) -> Option<&CompletionObservationReceipt> {
        self.receipt.as_ref()
    }
    /// True only after actual region closure and unused-reservation release.
    #[must_use]
    pub const fn is_settled(&self) -> bool {
        self.settled
    }
}
