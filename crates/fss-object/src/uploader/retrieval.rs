#![forbid(unsafe_code)]
//! Bounded independent byte verification of one completed multipart object.
//! The historical upload is immutable; every range belongs to a fresh read-only
//! child. A failed read never revives upload, overwrite, abort or delete authority.

use super::*;
use crate::multipart::{TransportCx, admit_retrieval};
use fss_core::Sha256Hasher;

mod receipt;
pub use receipt::{MAX_RETRIEVAL_RECEIPT_BYTES, RetrievalOutcome, RetrievalReceipt};

/// Largest single object supported by this bounded verification profile.
pub const MAX_RETRIEVAL_BYTES: u64 = 64 * 1024 * 1024;
/// Largest returned range; ranges never cross an acknowledged part boundary.
pub const MAX_RETRIEVAL_RANGE_BYTES: u64 = 256 * 1024;
const PREDICATE: &str = "bounded independent object retrieval finalized with an immutable receipt";

fn good_digest(digest: ContentDigest) -> bool {
    digest.algorithm() == DigestAlgorithm::Sha256
        && digest.bytes() != [0; 32]
        && !digest.is_laboratory()
}

fn reader_capabilities() -> Vec<String> {
    let mut capabilities: Vec<_> = [
        RuntimeGrant::AdapterAuth,
        RuntimeGrant::AdapterNet,
        RuntimeGrant::ReadMedia,
    ]
    .into_iter()
    .map(|grant| grant.as_str().to_owned())
    .collect();
    capabilities.sort();
    capabilities
}

/// Explicit admission for exactly one bounded range. Only the retrieval owner
/// can construct this context; a status observer cannot obtain media authority.
pub struct RetrievalCx<'a> {
    inner: TransportCx<'a>,
    expected_bytes: u64,
    expected_digest: ContentDigest,
    completion_digest: ContentDigest,
    completion_observation: Option<ContentDigest>,
}

impl<'a> RetrievalCx<'a> {
    /// Shared socket/clock/budget boundary. This context is always a read-only
    /// media retrieval, with a fresh deadline and no durable mutation owner.
    pub fn transport_context(&mut self) -> &mut TransportCx<'a> {
        &mut self.inner
    }
    /// Exact total object length, not the size of the current range.
    #[must_use]
    pub const fn expected_bytes(&self) -> u64 {
        self.expected_bytes
    }
    /// Independently supplied whole-object SHA-256, distinct from graph roots.
    #[must_use]
    pub const fn expected_digest(&self) -> ContentDigest {
        self.expected_digest
    }
    /// Exact completion inventory independently bound to the source journal.
    #[must_use]
    pub const fn completion_digest(&self) -> ContentDigest {
        self.completion_digest
    }
    /// Pinned positive read-only completion evidence for an indeterminate upload.
    /// Its presence never changes the historical upload's phase or authority.
    #[must_use]
    pub const fn completion_observation_digest(&self) -> Option<ContentDigest> {
        self.completion_observation
    }
}

/// A media reader must bind every range to one immutable provider representation
/// and the exact upload origin/intent. No mutation method exists on this surface.
pub trait RetrievalTransport {
    /// Read one exact range. The owner verifies length, every acknowledged part,
    /// and the complete independent digest. Adapters must admit response/framing
    /// buffers and wire work before I/O, enforce bounds before allocation, and
    /// omit credentials/media from errors. No implicit retry is permitted.
    fn retrieve_range(
        &mut self,
        cx: &mut RetrievalCx<'_>,
        intent: &UploadIntent,
        offset: u64,
        length: u64,
    ) -> Result<Vec<u8>, String>;
}

struct ReadBytes(Vec<u8>);
impl Drop for ReadBytes {
    fn drop(&mut self) {
        self.0.fill(0);
    }
}

/// Exact object bytes returned only after independent part and whole-object
/// verification, final authority/source checks, and successful reader settlement.
///
/// The bytes remain private, sensitive media. Possession grants no filesystem,
/// disclosure, publication, or upload authority. A caller must separately admit
/// any destination before writing them. There is deliberately no `Clone`, owned
/// byte extraction, serialization, or media-bearing debug output. Drop clears the
/// retained buffer; callers should keep the immutable borrowed view short-lived.
#[must_use = "use the verified bytes under separately scoped destination authority"]
pub struct VerifiedRetrievalBytes {
    bytes: ReadBytes,
    receipt: RetrievalReceipt,
}

impl VerifiedRetrievalBytes {
    /// Complete, verified bytes in their original order, never a partial range.
    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        &self.bytes.0
    }

    /// The exact settled retrieval proof for these bytes and their source pin.
    /// It proves byte verification, not destination publication or durability.
    #[must_use]
    pub fn receipt(&self) -> &RetrievalReceipt {
        &self.receipt
    }
}

impl std::fmt::Debug for VerifiedRetrievalBytes {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VerifiedRetrievalBytes")
            .field("byte_len", &self.bytes.0.len())
            .finish_non_exhaustive()
    }
}

/// One independently authorized complete verification attempt. Inconclusive or
/// corrupt reads still require settlement of this new child and its receipt.
#[must_use = "settle the retrieval owner even when verification fails"]
pub struct RetrievalObservation<'a> {
    parent: &'a mut AuthorityCx,
    authority: AuthorityCx,
    source: &'a MultipartRecovery,
    journal: &'a dyn UploadJournal,
    canonical: ContextAuthority,
    obligation: Obligation,
    expected_digest: ContentDigest,
    origin: ContentDigest,
    completion: ContentDigest,
    completion_observation: Option<(ContentDigest, ContentDigest)>,
    started_at: TimestampNs,
    observed_at: TimestampNs,
    started: bool,
    attempted_ranges: u64,
    bytes_read: u64,
    verified_parts: u64,
    outcome: RetrievalOutcome,
    receipt: Option<RetrievalReceipt>,
    settled: bool,
}

impl<'a> RetrievalObservation<'a> {
    /// Pure eligibility check before credential access. A completed protocol
    /// record alone is insufficient: its actual local owner must also have
    /// settled the exact completion proof, with a proven journal origin.
    pub fn validate_source(
        recovery: &MultipartRecovery,
        expected_intent: &UploadIntent,
        expected_digest: ContentDigest,
    ) -> Result<(), UploaderError> {
        let record =
            validated_recovery_owner(recovery)?.ok_or(MultipartError::InvalidCheckpoint)?;
        if recovery.intent() != expected_intent
            || recovery.phase() != MultipartPhase::Completed
            || record.obligation.state != ObligationState::Verified
            || record.indeterminate_receipt.is_some()
            || recovery.upload_id().is_none()
            || recovery.confirmed_parts() != recovery.plan().chunks.len()
            || recovery.plan().chunks.is_empty()
            || !(1..=MAX_RETRIEVAL_BYTES).contains(&recovery.plan().object_bytes)
            || !recovery.origin_binding().is_some_and(good_digest)
            || !good_digest(expected_digest)
        {
            return Err(MultipartError::InvalidCheckpoint.into());
        }
        // ReadMedia is fresh, explicit authority. Previously revoked network or
        // authentication scopes must not be recovered from an old success record.
        for grant in [RuntimeGrant::AdapterNet, RuntimeGrant::AdapterAuth] {
            if !record.grants.iter().any(|cap| cap == grant.as_str()) {
                return Err(authority(
                    "original upload no longer permits this provider read",
                ));
            }
        }
        Ok(())
    }

    /// Bind an independently pinned positive completion observation to the exact
    /// locally closed indeterminate upload. A HEAD result only admits a fresh
    /// byte verification attempt; it does not itself prove any retrieved bytes.
    pub fn validate_observed_source(
        recovery: &MultipartRecovery,
        expected_intent: &UploadIntent,
        expected_digest: ContentDigest,
        observation: &CompletionObservationReceipt,
        expected_observation_digest: ContentDigest,
    ) -> Result<(), UploaderError> {
        CompletionObservation::validate_source(recovery, expected_intent)?;
        let record =
            validated_recovery_owner(recovery)?.ok_or(MultipartError::InvalidCheckpoint)?;
        let indeterminate = record
            .indeterminate_receipt
            .ok_or(MultipartError::InvalidCheckpoint)?
            .digest();
        let completion = CompletionReceipt {
            intent_digest: expected_intent.digest(),
            upload: recovery
                .upload_id()
                .cloned()
                .ok_or(MultipartError::InvalidCheckpoint)?,
            manifest_root: expected_intent.manifest_root(),
            parts: recovery.part_receipts().cloned().collect(),
        }
        .digest();
        let original = recovery.effective_authority();
        let observed = observation.authority();
        if !(1..=MAX_RETRIEVAL_BYTES).contains(&recovery.plan().object_bytes)
            || !recovery.origin_binding().is_some_and(good_digest)
            || !good_digest(expected_digest)
            || !good_digest(expected_observation_digest)
            || observation.digest()? != expected_observation_digest
            || observation.outcome() != CompletionObservationOutcome::Completed
            || observation.source_pin() != recovery.head()
            || observation.started_at() < recovery.observed_at()
            || observed
                .deadline
                .is_none_or(|at| observation.observed_at() >= at)
            || observation.source_operation() != expected_intent.operation()
            || observation.indeterminate_receipt_digest() != indeterminate
            || observation.intent_digest() != expected_intent.digest()
            || observation.plan_digest() != expected_intent.plan_digest()
            || observation.manifest_root() != expected_intent.manifest_root()
            || observation.completion_digest() != Some(completion)
            || observed.trace_id != original.trace_id
            || observed.principal != original.principal
            || observed.anchor_universe != original.anchor_universe
            || observed.generation != original.generation
            || observed.priority < original.priority
            || observed.privacy_scope != original.privacy_scope
            || observed.retention_scope != original.retention_scope
            || observed.lease_fence != original.lease_fence
            || observed.idempotency_key != original.idempotency_key
            || observed.lab_controls != original.lab_controls
        {
            return Err(MultipartError::InvalidCheckpoint.into());
        }
        Ok(())
    }

    /// Reserve a fresh object-store read child. The source journal is borrowed
    /// immutably, never reopened as a mutation owner; old deadlines and budgets
    /// are historical facts, not the new read's allowance.
    #[allow(clippy::too_many_arguments)]
    pub fn begin(
        parent: &'a mut AuthorityCx,
        tree: &mut RegionTree,
        journal: &'a dyn UploadJournal,
        recovery: &'a MultipartRecovery,
        expected_intent: &UploadIntent,
        expected_digest: ContentDigest,
        child_spec: RootAuthoritySpec,
        now: TimestampNs,
    ) -> Result<Self, UploaderError> {
        Self::validate_source(recovery, expected_intent, expected_digest)?;
        Self::begin_validated(
            parent,
            tree,
            journal,
            recovery,
            expected_intent,
            expected_digest,
            recovery.completion_receipt()?.digest(),
            None,
            child_spec,
            now,
        )
    }

    /// Reserve a distinct read owner from a retained completion observation.
    /// Both evidence inputs remain immutable and the old owner stays terminal.
    #[allow(clippy::too_many_arguments)]
    pub fn begin_from_observation(
        parent: &'a mut AuthorityCx,
        tree: &mut RegionTree,
        journal: &'a dyn UploadJournal,
        recovery: &'a MultipartRecovery,
        expected_intent: &UploadIntent,
        expected_digest: ContentDigest,
        observation: &CompletionObservationReceipt,
        expected_observation_digest: ContentDigest,
        child_spec: RootAuthoritySpec,
        now: TimestampNs,
    ) -> Result<Self, UploaderError> {
        Self::validate_observed_source(
            recovery,
            expected_intent,
            expected_digest,
            observation,
            expected_observation_digest,
        )?;
        // Validate that the retained observation could have seen this exact
        // journal, and that a later reader cannot precede its evidence.
        recovery.validate_restore(journal, observation.started_at())?;
        if now < observation.observed_at() {
            return Err(MultipartError::ClockRegression.into());
        }
        if &child_spec.operation_id == observation.operation() {
            return Err(authority(
                "retrieval requires a distinct operation from its completion observation",
            ));
        }
        Self::begin_validated(
            parent,
            tree,
            journal,
            recovery,
            expected_intent,
            expected_digest,
            observation
                .completion_digest()
                .ok_or(MultipartError::InvalidCheckpoint)?,
            Some((
                expected_observation_digest,
                observation.indeterminate_receipt_digest(),
            )),
            child_spec,
            now,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn begin_validated(
        parent: &'a mut AuthorityCx,
        tree: &mut RegionTree,
        journal: &'a dyn UploadJournal,
        recovery: &'a MultipartRecovery,
        expected_intent: &UploadIntent,
        expected_digest: ContentDigest,
        completion: ContentDigest,
        completion_observation: Option<(ContentDigest, ContentDigest)>,
        child_spec: RootAuthoritySpec,
        now: TimestampNs,
    ) -> Result<Self, UploaderError> {
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
            || canonical.capabilities() != reader_capabilities()
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
                "retrieval authority changed the upload scope or read-only purpose",
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
            RuntimeGrant::ReadMedia,
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
        let origin = recovery
            .origin_binding()
            .ok_or(MultipartError::UnboundJournal)?;
        let region = RegionId::new(format!(
            "region:upload-retrieval:{}",
            canonical.operation_id.as_str()
        ))
        .map_err(authority)?;
        let obligation = new_obligation(
            format!(
                "obligation:upload-retrieval:{}:drain",
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
            canonical,
            obligation,
            expected_digest,
            origin,
            completion,
            completion_observation,
            started_at: now,
            observed_at: now,
            started: false,
            attempted_ranges: 0,
            bytes_read: 0,
            verified_parts: 0,
            outcome: RetrievalOutcome::NotObserved,
            receipt: None,
            settled: false,
        })
    }

    /// Verify all bytes once, in canonical part/range order. The supplied clock
    /// is called before admission and after hashing each bounded range, including
    /// before proof publication. No partial hash is a retrievability claim.
    pub fn verify<T: RetrievalTransport>(
        &mut self,
        tree: &mut RegionTree,
        transport: &mut T,
        clock: impl FnMut() -> Result<TimestampNs, UploaderError>,
    ) -> Result<RetrievalReceipt, UploaderError> {
        self.verify_inner(tree, transport, clock, false)
            .map(|(receipt, _)| receipt)
    }

    /// Verify and retain the complete object for an explicitly authorized local
    /// restore or other caller-owned destination. The reader is already settled
    /// when this returns successfully, exactly as for [`Self::verify`].
    ///
    /// This opt-in path charges one additional full object against the original
    /// byte allowance before allocating a bounded buffer or contacting the
    /// provider. The existing streaming verifier's allocation and accounting are
    /// unchanged. Any error, cancellation, corrupt range, final source drift, or
    /// failed settlement clears the private buffer and returns no media. The
    /// caller must still settle an unsuccessful attempt.
    pub fn verify_with_bytes<T: RetrievalTransport>(
        &mut self,
        tree: &mut RegionTree,
        transport: &mut T,
        clock: impl FnMut() -> Result<TimestampNs, UploaderError>,
    ) -> Result<VerifiedRetrievalBytes, UploaderError> {
        let (receipt, bytes) = self.verify_inner(tree, transport, clock, true)?;
        Ok(VerifiedRetrievalBytes {
            bytes: bytes.ok_or_else(|| authority("verified retrieval buffer is absent"))?,
            receipt,
        })
    }

    fn verify_inner<T: RetrievalTransport>(
        &mut self,
        tree: &mut RegionTree,
        transport: &mut T,
        mut clock: impl FnMut() -> Result<TimestampNs, UploaderError>,
        retain_bytes: bool,
    ) -> Result<(RetrievalReceipt, Option<ReadBytes>), UploaderError> {
        let now = clock()?;
        self.validate_owner(tree, now)?;
        if self.started || self.receipt.is_some() {
            return Err(authority(
                "retrieval already attempted; settle or retain its receipt",
            ));
        }
        self.source.validate_restore(self.journal, now)?;
        self.started = true;
        let mut retained = if retain_bytes {
            crate::multipart::check_retrieval(
                &self.authority,
                tree,
                self.source.intent().resource(),
                now,
            )?;
            let length = self.source.plan().object_bytes;
            if !(1..=MAX_RETRIEVAL_BYTES).contains(&length) {
                return Err(authority(
                    "retrieved object exceeds the bounded restore profile",
                ));
            }
            let capacity = usize::try_from(length)
                .map_err(|_| authority("retrieved object is not addressable"))?;
            let mut cost = BudgetVector::ZERO;
            cost.bytes = length;
            self.authority
                .budget_mut(tree)?
                .spend_vector(&cost)
                .map_err(authority)?;
            let mut bytes = Vec::new();
            bytes
                .try_reserve_exact(capacity)
                .map_err(|_| authority("retrieval buffer allocation refused"))?;
            Some(ReadBytes(bytes))
        } else {
            None
        };
        let mut whole = Sha256Hasher::new();
        for (chunk, expected_part) in self
            .source
            .plan()
            .chunks
            .iter()
            .zip(self.source.part_receipts())
        {
            let mut part = Sha256Hasher::new();
            let mut within = 0;
            while within < chunk.len {
                let now = clock()?;
                self.validate_owner(tree, now)?;
                self.observed_at = now;
                let length = (chunk.len - within).min(MAX_RETRIEVAL_RANGE_BYTES);
                let inner = admit_retrieval(
                    UploadIo {
                        authority: &mut self.authority,
                        tree,
                        now,
                    },
                    self.source.intent().resource(),
                    self.origin,
                    length,
                )?;
                let mut cx = RetrievalCx {
                    inner,
                    expected_bytes: self.source.plan().object_bytes,
                    expected_digest: self.expected_digest,
                    completion_digest: self.completion,
                    completion_observation: self.completion_observation.map(|value| value.0),
                };
                self.attempted_ranges += 1;
                self.outcome = RetrievalOutcome::Unknown;
                let result = transport.retrieve_range(
                    &mut cx,
                    self.source.intent(),
                    chunk.offset + within,
                    length,
                );
                let checked = cx.inner.checkpoint(cx.inner.now());
                self.observed_at = cx.inner.now();
                // Own the buffer before any fallible check so failure also clears it.
                let bytes = result.map(ReadBytes);
                checked?;
                let bytes =
                    bytes.map_err(|_| authority("independent object read was inconclusive"))?;
                if bytes.0.len() as u64 != length {
                    self.outcome = RetrievalOutcome::Mismatch;
                    return Err(MultipartError::ReconciliationMismatch.into());
                }
                if let Some(retained) = &mut retained {
                    let end = retained.0.len().checked_add(bytes.0.len());
                    if end.is_none_or(|end| {
                        end as u64 > self.source.plan().object_bytes || end > retained.0.capacity()
                    }) {
                        return Err(authority("retrieval buffer exceeded its admitted bound"));
                    }
                    retained.0.extend_from_slice(&bytes.0);
                }
                whole.update(&bytes.0);
                part.update(&bytes.0);
                self.bytes_read += length;
                within += length;
                let checked = clock().and_then(|now| cx.inner.checkpoint(now).map_err(Into::into));
                self.observed_at = cx.inner.now();
                checked?;
            }
            let digest =
                ContentDigest::new(DigestAlgorithm::Sha256, part.finalize().map_err(authority)?);
            if digest != expected_part.content_digest {
                self.outcome = RetrievalOutcome::Mismatch;
                return Err(MultipartError::ReconciliationMismatch.into());
            }
            self.verified_parts += 1;
        }
        let digest = ContentDigest::new(
            DigestAlgorithm::Sha256,
            whole.finalize().map_err(authority)?,
        );
        if digest != self.expected_digest {
            self.outcome = RetrievalOutcome::Mismatch;
            return Err(MultipartError::ReconciliationMismatch.into());
        }
        let now = clock()?;
        self.validate_owner(tree, now)?;
        self.observed_at = now;
        // Final admission uses no new request; it rechecks the same live read
        // authority after hashing and source-history validation.
        self.source.validate_restore(self.journal, now)?;
        crate::multipart::check_retrieval(
            &self.authority,
            tree,
            self.source.intent().resource(),
            now,
        )?;
        self.outcome = RetrievalOutcome::Verified;
        let receipt = self.settle(tree, now)?;
        Ok((receipt, retained))
    }

    /// Settle even after cancellation, expiry or a failed read. This records the
    /// exact result, closes only this child and returns its unused reservation.
    /// It never contacts the provider or changes the historical upload.
    pub fn settle(
        &mut self,
        tree: &mut RegionTree,
        now: TimestampNs,
    ) -> Result<RetrievalReceipt, UploaderError> {
        self.validate_owner(tree, now)?;
        self.observed_at = now;
        let receipt = if let Some(receipt) = &self.receipt {
            receipt.clone()
        } else {
            let receipt = RetrievalReceipt {
                source_pin: self.source.head(),
                source_operation: self.source.intent().operation().clone(),
                completion_digest: self.completion,
                completion_observation: self.completion_observation,
                origin: self.origin,
                intent_digest: self.source.intent().digest(),
                plan_digest: self.source.intent().plan_digest(),
                manifest_root: self.source.intent().manifest_root(),
                expected_digest: self.expected_digest,
                expected_bytes: self.source.plan().object_bytes,
                expected_parts: self.source.plan().chunks.len() as u64,
                authority: self.canonical.clone(),
                started_at: self.started_at,
                observed_at: now,
                consumed: *self.authority.budget().consumed(),
                outcome: self.outcome,
                attempted_ranges: self.attempted_ranges,
                bytes_read: self.bytes_read,
                verified_parts: self.verified_parts,
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
                tree.request_drain(&region, Some("independent object retrieval recorded"), now)
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
            return Err(authority("retrieval obligation changed"));
        }
        Ok(())
    }

    /// Actual child for cancellation/status, never a mutable transport grant.
    #[must_use]
    pub fn region(&self) -> &RegionId {
        self.authority.region()
    }
    /// Fresh allowance and consumption, separate from original upload spend.
    #[must_use]
    pub fn budget(&self) -> &fss_runtime::budget::BudgetLedger {
        self.authority.budget()
    }
    /// Latest observed boundary, including a refused transport checkpoint.
    #[must_use]
    pub const fn observed_at(&self) -> TimestampNs {
        self.observed_at
    }
    /// Canonical receipt retained even if finalization must be retried.
    #[must_use]
    pub fn receipt(&self) -> Option<&RetrievalReceipt> {
        self.receipt.as_ref()
    }
    /// True only after closure and unused-reservation release.
    #[must_use]
    pub const fn is_settled(&self) -> bool {
        self.settled
    }
}
