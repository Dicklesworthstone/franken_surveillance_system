#![forbid(unsafe_code)]
//! Atomic local reference deletion, with explicit projected authority and exact retry receipts.

use fss_core::{Generation, ObjectId, TombstoneReason, TombstoneRecord};
use super::*;

/// Authenticated runtime projection for ONE exact plan, never inferred from a plan or checksum.
///
/// The caller must verify actual authority before constructing this value. The witness must be
/// a registered, verified object outside the deletion set. Its bytes are audit evidence, not a
/// cryptographic authorization protocol. These fields are not an unauthenticated agent request.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RetentionAuthorization {
    /// Exact accepted policy generation.
    pub policy_digest: ContentDigest,
    /// Exact plan authorized by the runtime.
    pub plan_digest: ContentDigest,
    /// Stored audit witness for that authorization.
    pub witness: ContentDigest,
    /// Explicit object scope, which must include every selected object.
    pub permitted_objects: BTreeSet<ContentDigest>,
    /// Trusted authority lease start.
    pub issued_at: TimestampNs,
    /// Exclusive authority lease end.
    pub expires_at: TimestampNs,
}

/// Historical proof of deletion from this owner's local object graph ONLY.
///
/// This does not attest to filesystem erasure, allocator zeroization, remote copies, external
/// caches, or unregistered derivatives. Exact retries return this historical receipt, not a new
/// claim about present global availability. Permanent custody tombstones prevent local reimport.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DeletionReceipt {
    plan: ContentDigest,
    policy: ContentDigest,
    witness: ContentDigest,
    before: ContentDigest,
    after: ContentDigest,
    deleted: Vec<ContentDigest>,
    released_bytes: u64,
    committed_at: TimestampNs,
    digest: ContentDigest,
}
impl DeletionReceipt {
    /// Exact operation identity for retry/inspection.
    #[must_use]
    pub const fn plan_digest(&self) -> ContentDigest { self.plan }
    /// Exact local objects now permanently tombstoned.
    #[must_use]
    pub fn deleted(&self) -> &[ContentDigest] { &self.deleted }
    /// Locally released payload quota, not storage-provider billing or physical erasure.
    #[must_use]
    pub const fn released_bytes(&self) -> u64 { self.released_bytes }
    /// Metadata root before the atomic local reference mutation.
    #[must_use]
    pub const fn before_state(&self) -> ContentDigest { self.before }
    /// Metadata root after the atomic local reference mutation.
    #[must_use]
    pub const fn after_state(&self) -> ContentDigest { self.after }
    /// Historical receipt identity to retain in authorized audit custody.
    #[must_use]
    pub const fn digest(&self) -> ContentDigest { self.digest }

    fn computed_digest(&self) -> Result<ContentDigest, RetentionError> {
        let mut e = CanonicalEncoder::new();
        e.text("fss.reference_local_retention_deletion.v1");
        for digest in [self.plan, self.policy, self.witness, self.before, self.after] { e.digest(digest); }
        e.u64(self.deleted.len() as u64);
        for digest in &self.deleted { e.digest(*digest); }
        e.u64(self.released_bytes); e.i128(self.committed_at.0);
        Ok(ContentDigest::sha256(&e.finish_checked()?))
    }
}

impl RetentionStore {
    /// Executes a still-current expiry plan atomically over the local reference graph.
    ///
    /// Authority, time, complete graph identity, selected custody, witness, receipt capacity, and
    /// additional staging memory are checked before cloning payloads. Mutations occur only in a
    /// bounded temporary store. Any failure drops that candidate, returning no success receipt
    /// and leaving the original store, graph, holds and quota untouched. This is in-process
    /// atomicity, NOT a crash-durable transaction or proof about other custody owners.
    pub fn execute_expiry(&mut self, plan: &RetentionPlan, authority: &RetentionAuthorization,
        now: TimestampNs) -> Result<DeletionReceipt, RetentionError>
    {
        if plan.digest != plan.computed_digest()? { return Err(RetentionError::StalePlan); }
        if authority.policy_digest != self.policy || authority.policy_digest != plan.policy
            || authority.plan_digest != plan.digest || authority.issued_at > now
            || now >= authority.expires_at || authority.issued_at >= authority.expires_at
            || plan.selected.iter().any(|digest| !authority.permitted_objects.contains(digest))
            || plan.selected.contains(&authority.witness)
        { return Err(RetentionError::Unauthorized); }
        if now < plan.prepared_at || self.last_commit_at.is_some_and(|last| now < last) {
            return Err(RetentionError::ClockRegression);
        }
        self.live_entry(authority.witness)?;
        self.custody.read_verified(authority.witness)?;
        if let Some(receipt) = self.receipts.get(&plan.digest) {
            if receipt.witness != authority.witness { return Err(RetentionError::Unauthorized); }
            return Ok(receipt.clone());
        }
        if plan.state != self.state_digest()?
            || self.prepare_expiry(plan.prepared_at, plan.budget)? != *plan
        { return Err(RetentionError::StalePlan); }
        if plan.selected.is_empty() { return Err(RetentionError::NoWork); }
        if self.receipts.len() >= self.limits.max_receipts.min(MAX_RETENTION_RECEIPTS) {
            return Err(RetentionError::CapacityExceeded);
        }
        if self.custody.total_bytes() > plan.budget.max_staging_bytes {
            return Err(RetentionError::StagingBudgetExceeded);
        }
        let next = self.revision.checked_add(1).ok_or(RetentionError::CapacityExceeded)?;
        let prior_generation = Generation::parse_positive(1)?;
        let mut tombstones = Vec::with_capacity(plan.selected.len());
        for digest in &plan.selected {
            self.live_entry(*digest)?; self.custody.read_verified(*digest)?;
            tombstones.push((*digest, TombstoneRecord::new(
                ObjectId::parse(format!("object:retention:{digest}"))?,
                prior_generation.next()?, prior_generation, TombstoneReason::Deleted,
                Some(authority.witness), *digest,
            )?));
        }
        let mut staged = Self { custody: self.custody.clone(), policy: self.policy,
            limits: self.limits, entries: self.entries.clone(), holds: self.holds.clone(),
            receipts: self.receipts.clone(), revision: next, last_commit_at: Some(now) };
        for (digest, tombstone) in tombstones {
            staged.custody.tombstone(digest, tombstone)?;
            staged.entries.get_mut(&digest).ok_or(RetentionError::InvalidRecord)?.deleted_by = Some(plan.digest);
        }
        staged.verify_live_graph()?;
        let released_bytes = self.custody.total_bytes().checked_sub(staged.custody.total_bytes())
            .ok_or(RetentionError::InvalidRecord)?;
        if released_bytes != plan.selected_bytes { return Err(RetentionError::InvalidRecord); }
        let mut receipt = DeletionReceipt { plan: plan.digest, policy: self.policy,
            witness: authority.witness, before: plan.state, after: staged.state_digest()?,
            deleted: plan.selected.clone(), released_bytes, committed_at: now,
            digest: ContentDigest::sha256(b"unpublished-retention-deletion") };
        receipt.digest = receipt.computed_digest()?;
        staged.receipts.insert(plan.digest, receipt.clone());
        *self = staged;
        Ok(receipt)
    }
}
