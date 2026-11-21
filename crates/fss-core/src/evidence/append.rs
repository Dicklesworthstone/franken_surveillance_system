//! Prevalidated, owner-bound append stages for crash-safe persistence.
//!
//! Staging computes only one successor snapshot. The guard keeps its base ledger
//! exclusively borrowed until publication or suspension, so successful durable
//! I/O is followed by infallible semantic installation rather than revalidation.

use std::error::Error;
use std::fmt;
use std::sync::Arc;

use super::{
    EvidenceDeltaBatch, LedgerSnapshot, LedgerSnapshotRetention, ReferenceLedger, apply_deltas,
    state_root,
};
use crate::{BatchId, ContractError};

/// A fully validated successor detached from its ledger while persistence is
/// indeterminate. It retains one successor snapshot and batch, not prior history.
///
/// Fields are private and the token is not clonable. It can be resumed only on
/// its original live ledger at the unchanged basis anchor. Replaying the durable
/// journal is the recovery path after the original owner is lost.
#[derive(Debug)]
#[must_use = "a suspended append must be resumed or explicitly abandoned"]
pub struct PreparedLedgerAppend {
    owner: Arc<()>,
    snapshot: LedgerSnapshot,
    batch: EvidenceDeltaBatch,
    committed_id: BatchId,
}

impl PreparedLedgerAppend {
    /// Exact validated batch that the persistence owner attempted to write.
    #[must_use]
    pub const fn batch(&self) -> &EvidenceDeltaBatch {
        &self.batch
    }
}

/// Exclusive installation guard for one already validated successor.
///
/// Dropping this guard abandons the unpublished successor without changing the
/// ledger's canonical head, history, or committed identities. A persistence owner
/// whose write may have committed must instead retain it with [`Self::suspend`].
///
/// The mutable borrow prevents a second append between validation and installation:
///
/// ```compile_fail,E0499
/// use fss_core::{ContractError, EvidenceDeltaBatch, ReferenceLedger};
///
/// fn competing_append(
///     ledger: &mut ReferenceLedger,
///     first: EvidenceDeltaBatch,
///     second: EvidenceDeltaBatch,
/// ) -> Result<(), ContractError> {
///     let staged = ledger.stage_append(first)?;
///     ledger.append(second)?;
///     staged.commit();
///     Ok(())
/// }
/// ```
#[derive(Debug)]
#[must_use = "a staged append must be committed, suspended, or explicitly abandoned"]
pub struct LedgerAppendGuard<'ledger> {
    ledger: &'ledger mut ReferenceLedger,
    prepared: PreparedLedgerAppend,
}

impl<'ledger> LedgerAppendGuard<'ledger> {
    /// Exact validated batch to encode before attempting persistence.
    #[must_use]
    pub const fn batch(&self) -> &EvidenceDeltaBatch {
        self.prepared.batch()
    }

    /// Canonical snapshot that remains visible until this guard commits.
    #[must_use]
    pub fn basis(&self) -> &LedgerSnapshot {
        self.ledger.current()
    }

    /// Retains the successor for reconciliation without publishing it.
    #[must_use]
    pub fn suspend(self) -> PreparedLedgerAppend {
        self.prepared
    }

    /// Installs the prevalidated successor without a fallible semantic transition.
    ///
    /// Vector capacity and the batch-identity string are prepared before the
    /// guard is returned. The identity map may still allocate; an allocator abort
    /// after a durable write requires ordinary journal replay, not a new append.
    pub fn commit(self) -> &'ledger LedgerSnapshot {
        let Self { ledger, prepared } = self;
        match ledger.snapshot_retention {
            LedgerSnapshotRetention::FullHistory => ledger.snapshots.push(prepared.snapshot),
            // Construction installs one snapshot and this mode never adds another. Replacing
            // it only after commit drops the old materialization without pruning batch history.
            LedgerSnapshotRetention::CurrentOnly => ledger.snapshots[0] = prepared.snapshot,
        }
        ledger
            .committed_batches
            .insert(prepared.committed_id, prepared.batch.batch_digest);
        ledger.batches.push(prepared.batch);
        ledger.current()
    }
}

/// Refusal to reattach a suspended successor, retaining the token unchanged.
///
/// `StaleAnchor` means the live owner or its head differs from the one that
/// validated the token. Equal-looking anchors on another ledger are insufficient.
#[derive(Debug)]
pub struct ResumeLedgerAppendError {
    error: ContractError,
    prepared: Box<PreparedLedgerAppend>,
}

impl ResumeLedgerAppendError {
    /// Existing core contract classification of the refusal.
    #[must_use]
    pub const fn error(&self) -> &ContractError {
        &self.error
    }

    /// Recovers both the refusal and the unchanged suspended successor.
    #[must_use]
    pub fn into_parts(self) -> (ContractError, PreparedLedgerAppend) {
        (self.error, *self.prepared)
    }
}

impl fmt::Display for ResumeLedgerAppendError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "cannot resume staged ledger append: {}",
            self.error
        )
    }
}

impl Error for ResumeLedgerAppendError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        Some(&self.error)
    }
}

impl ReferenceLedger {
    /// Validates and reserves one complete successor without publishing it.
    ///
    /// The guard owns only the next materialized snapshot and batch. Historical
    /// snapshots and batches remain in place. Dropping a refused or abandoned
    /// stage leaves canonical state unchanged.
    pub fn stage_append(
        &mut self,
        batch: EvidenceDeltaBatch,
    ) -> Result<LedgerAppendGuard<'_>, ContractError> {
        let offered_digest = batch.computed_digest();
        if let Some(committed_digest) = self.committed_batches.get(&batch.batch_id)
            && offered_digest != *committed_digest
        {
            return Err(ContractError::IdempotencyConflict);
        }
        if batch.basis_anchor != self.current().anchor {
            return Err(ContractError::StaleAnchor);
        }
        let expected_sequence = batch
            .basis_anchor
            .commit_sequence
            .checked_add(1)
            .ok_or(ContractError::InvalidAnchorSuccessor)?;
        if batch.new_anchor.site_lineage != batch.basis_anchor.site_lineage
            || batch.new_anchor.ledger_epoch != batch.basis_anchor.ledger_epoch
            || batch.new_anchor.commit_sequence != expected_sequence
            || batch.new_anchor.adapter_registry_epoch != batch.basis_anchor.adapter_registry_epoch
            || batch.new_anchor.schema_epoch != batch.basis_anchor.schema_epoch
            || batch.new_anchor.policy_epoch != batch.basis_anchor.policy_epoch
            || batch.new_anchor.privacy_epoch != batch.basis_anchor.privacy_epoch
        {
            return Err(ContractError::InvalidAnchorSuccessor);
        }
        if !batch.is_canonically_ordered() {
            return Err(ContractError::NonCanonicalOrdering);
        }
        if offered_digest != batch.batch_digest {
            return Err(ContractError::DigestMismatch);
        }
        let next_objects = apply_deltas(&self.current().objects, &batch.deltas)?;
        if state_root(&next_objects) != batch.new_anchor.state_root {
            return Err(ContractError::DigestMismatch);
        }
        self.reserve_append_capacity()?;
        let prepared = PreparedLedgerAppend {
            owner: Arc::clone(&self.append_owner),
            snapshot: LedgerSnapshot {
                anchor: batch.new_anchor.clone(),
                objects: next_objects,
            },
            committed_id: batch.batch_id.clone(),
            batch,
        };
        Ok(LedgerAppendGuard {
            ledger: self,
            prepared,
        })
    }

    /// Reattaches a suspended stage only to its original unchanged live owner.
    ///
    /// This check must happen before persistence reconciliation can establish a
    /// committed outcome. After it succeeds, the guard prevents head changes and
    /// [`LedgerAppendGuard::commit`] requires no further semantic validation.
    /// A refusal preserves the token in [`ResumeLedgerAppendError::into_parts`].
    pub fn resume_append(
        &mut self,
        prepared: PreparedLedgerAppend,
    ) -> Result<LedgerAppendGuard<'_>, ResumeLedgerAppendError> {
        if !Arc::ptr_eq(&self.append_owner, &prepared.owner)
            || self.current().anchor != prepared.batch.basis_anchor
        {
            return Err(ResumeLedgerAppendError {
                error: ContractError::StaleAnchor,
                prepared: Box::new(prepared),
            });
        }
        if let Err(error) = self.reserve_append_capacity() {
            return Err(ResumeLedgerAppendError {
                error,
                prepared: Box::new(prepared),
            });
        }
        Ok(LedgerAppendGuard {
            ledger: self,
            prepared,
        })
    }

    fn reserve_append_capacity(&mut self) -> Result<(), ContractError> {
        if self.snapshot_retention == LedgerSnapshotRetention::FullHistory {
            self.snapshots
                .try_reserve(1)
                .map_err(|_| ContractError::BudgetExhausted)?;
        }
        self.batches
            .try_reserve(1)
            .map_err(|_| ContractError::BudgetExhausted)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests;
