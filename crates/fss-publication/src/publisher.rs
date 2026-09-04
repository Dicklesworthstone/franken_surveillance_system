//! Child-first authority publisher.

use fss_core::{BatchId, ContentDigest, EvidenceDelta, EvidenceDeltaBatch, LedgerAnchor};
use fss_ledger::{DurableAppendReconciliation, DurableReferenceLedger, IncompleteTailPolicy};
use fss_object::VerifiedObjectCatalog;

use crate::PublicationError;

/// Borrow-scoped coordinator for one object catalog and one durable authority ledger.
///
/// The immutable catalog borrow prevents this publication path from mutating child custody while
/// validating a commit. Other processes remain a production concern, so exact child roots are
/// revalidated on every `append` even if they were already checked during `prepare_batch`.
pub struct AuthorityPublisher<'a, C: VerifiedObjectCatalog> {
    objects: &'a C,
    ledger: &'a mut DurableReferenceLedger,
}

impl<'a, C: VerifiedObjectCatalog> AuthorityPublisher<'a, C> {
    /// Creates a coordinator over explicit object and authority owners.
    #[must_use]
    pub fn new(objects: &'a C, ledger: &'a mut DurableReferenceLedger) -> Self {
        Self { objects, ledger }
    }

    /// Current canonical authority anchor.
    #[must_use]
    pub fn current_anchor(&self) -> &LedgerAnchor {
        &self.ledger.current().anchor
    }

    /// Prepares an authority batch only after proving its complete direct child set verified.
    ///
    /// The ledger remains the owner of canonical child ordering and batch/anchor construction.
    pub fn prepare_batch(
        &self,
        batch_id: BatchId,
        deltas: Vec<EvidenceDelta>,
        child_roots: impl IntoIterator<Item = ContentDigest>,
    ) -> Result<EvidenceDeltaBatch, PublicationError> {
        let children: Vec<_> = child_roots.into_iter().collect();
        self.objects.require_all_verified(&children)?;
        Ok(self.ledger.prepare_batch(batch_id, deltas, children)?)
    }

    /// Revalidates child custody immediately before durable authority publication.
    ///
    /// Missing, merely staged, or corrupt children fail before journal I/O and leave the authority
    /// sequence unchanged. An indeterminate journal outcome remains owned by `fss-ledger` and must
    /// be reconciled rather than retried blindly.
    pub fn append(&mut self, batch: EvidenceDeltaBatch) -> Result<LedgerAnchor, PublicationError> {
        self.objects.require_all_verified(&batch.children)?;
        let anchor = self.ledger.append(batch)?.anchor.clone();
        Ok(anchor)
    }

    /// Reconciles a previously indeterminate durable authority append.
    ///
    /// Reconciliation does not require child revalidation: the authority record may already have
    /// committed exactly once after child custody was proved at append time. Any later child loss
    /// is a separate custody/repair obligation, not evidence that the historical commit vanished.
    pub fn reconcile_pending(
        &mut self,
        tail_policy: IncompleteTailPolicy,
    ) -> Result<DurableAppendReconciliation, PublicationError> {
        Ok(self.ledger.reconcile_pending(tail_policy)?)
    }

    /// Returns the sequence of a durable append whose outcome still requires reconciliation.
    #[must_use]
    pub fn pending_append_sequence(&self) -> Option<u64> {
        self.ledger.pending_append_sequence()
    }
}
