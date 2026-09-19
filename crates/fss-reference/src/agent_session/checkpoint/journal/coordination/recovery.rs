#![forbid(unsafe_code)]
//! Explicit cold recovery when the original pending-append handle no longer exists.
//!
//! The caller independently authorizes the exact committed root. Complete newer history is never
//! discarded to satisfy an older root. A damaged complete prefix is never repaired by this path.

use std::fs::OpenOptions;
use std::io::Read;
use std::path::Path;

use fss_core::{CanonicalEncode, CanonicalEncoder, ContentDigest};
use fss_ledger::{IncompleteTailPolicy, Journal, JournalError};

use super::super::{
    DurableSessionError, DurableSessionLimits, DurableSessionStore, MAX_SESSION_JOURNAL_BYTES,
    SessionJournalInspection, read_report, replay,
};
use super::WorkClaimLimits;

/// Diagnostic evidence of an explicit cold recovery, not authentication or permission to retry.
///
/// Hashes identify the observed bytes and any discarded incomplete suffix without disclosing
/// private commands. Only the validated committed prefix is retained as authority. Keep the
/// independent root pin and this receipt in the owning runtime's protected audit custody.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SessionRecoveryReceipt {
    observed_file_digest: ContentDigest,
    discarded_tail_digest: Option<ContentDigest>,
    discarded_bytes: u64,
    restored: SessionJournalInspection,
}

impl SessionRecoveryReceipt {
    /// Identity of all bytes observed immediately before recovery, including any torn suffix.
    #[must_use]
    pub const fn observed_file_digest(&self) -> ContentDigest { self.observed_file_digest }

    /// Exact bytes removed, absent when no incomplete suffix existed.
    #[must_use]
    pub const fn discarded_tail_digest(&self) -> Option<ContentDigest> { self.discarded_tail_digest }

    /// Number of incomplete bytes removed, never bytes from a complete record.
    #[must_use]
    pub const fn discarded_bytes(&self) -> u64 { self.discarded_bytes }

    /// Exact verified and synchronized committed prefix installed by recovery.
    #[must_use]
    pub const fn restored(&self) -> &SessionJournalInspection { &self.restored }

    /// Stable identity for the diagnostic receipt; a checksum is not an authority grant.
    #[must_use]
    pub fn digest(&self) -> ContentDigest {
        self.canonical_digest("fss.reference_session_recovery_receipt.v1")
    }
}

impl CanonicalEncode for SessionRecoveryReceipt {
    fn encode_canonical(&self, encoder: &mut CanonicalEncoder) {
        encoder.digest(self.observed_file_digest);
        encoder.bool(self.discarded_tail_digest.is_some());
        if let Some(digest) = self.discarded_tail_digest { encoder.digest(digest); }
        encoder.u64(self.discarded_bytes);
        encoder.digest(self.restored.root);
        encoder.digest(self.restored.checkpoint_digest);
        encoder.u64(self.restored.records as u64);
        encoder.u64(self.restored.committed_bytes);
    }
}

impl DurableSessionStore {
    /// Recovers an existing legacy session-only journal after losing the original writer.
    ///
    /// `Reject` never trims; `Truncate` removes only a validated incomplete suffix. The exact
    /// expected root is checked BEFORE any write. Missing paths are never created. Sync/open
    /// failures return no usable store and require inspection, not a guessed rollback or retry.
    pub fn recover_existing(
        path: impl AsRef<Path>, expected_root: ContentDigest, limits: DurableSessionLimits,
        tail_policy: IncompleteTailPolicy,
    ) -> Result<(Self, SessionRecoveryReceipt), DurableSessionError> {
        recover(path.as_ref(), expected_root, limits, None, tail_policy)
    }

    /// Recovers session authority AND coordination at one independently trusted committed root.
    ///
    /// Every complete command is semantically replayed before truncation. A fully committed
    /// transfer must be recovered at its NEW root; supplying its predecessor is refused, even
    /// with `Truncate`. No response is redelivered and no domain effect is retried. An inspected
    /// root is diagnostic only: the trusted owner must authorize it independently of this file.
    pub fn recover_existing_with_coordination(
        path: impl AsRef<Path>, expected_root: ContentDigest, limits: DurableSessionLimits,
        claim_ceilings: WorkClaimLimits, tail_policy: IncompleteTailPolicy,
    ) -> Result<(Self, SessionRecoveryReceipt), DurableSessionError> {
        recover(path.as_ref(), expected_root, limits, Some(claim_ceilings), tail_policy)
    }
}

fn recover(
    path: &Path, expected_root: ContentDigest, limits: DurableSessionLimits,
    claim_ceilings: Option<WorkClaimLimits>, tail_policy: IncompleteTailPolicy,
) -> Result<(DurableSessionStore, SessionRecoveryReceipt), DurableSessionError> {
    // read_report enforces a regular non-symlink path and hard byte/record ceilings.
    let report = read_report(path, limits)?;
    if report.last_root() != expected_root { return Err(DurableSessionError::RootMismatch); }
    let (memory, coordination) = replay(&report, limits, claim_ceilings)?;
    let checkpoint_digest = memory.checkpoint(limits.max_checkpoint_bytes)?.digest();
    if tail_policy == IncompleteTailPolicy::Reject
        && let Some(offset) = report.incomplete_tail()
    {
        return Err(JournalError::IncompleteTail { offset }.into());
    }

    // Never use create(true) at the repair boundary. Recheck the complete bounded file on the
    // SAME descriptor that will be trimmed; reject committed-state changes since semantic preflight. The path
    // and directory still require the existing exclusive/protected-owner contract.
    let mut file = OpenOptions::new().read(true).write(true).open(path)?;
    if !file.metadata()?.is_file() { return Err(DurableSessionError::InvalidLayout); }
    let limit = limits.max_journal_bytes.min(MAX_SESSION_JOURNAL_BYTES);
    let read_limit = u64::try_from(limit.saturating_add(1))
        .map_err(|_| DurableSessionError::CapacityExceeded)?;
    let mut bytes = Vec::new();
    file.by_ref().take(read_limit).read_to_end(&mut bytes)?;
    if bytes.len() > limit { return Err(DurableSessionError::CapacityExceeded); }
    if fss_ledger::recover_bytes(&bytes)? != report {
        return Err(DurableSessionError::RootMismatch);
    }
    let committed_len = usize::try_from(report.committed_len())
        .map_err(|_| DurableSessionError::CapacityExceeded)?;
    let tail = bytes.get(committed_len..).ok_or(DurableSessionError::InvalidHistory)?;
    if tail.is_empty() != report.incomplete_tail().is_none() {
        return Err(DurableSessionError::InvalidHistory);
    }
    let receipt = SessionRecoveryReceipt {
        observed_file_digest: ContentDigest::sha256(&bytes),
        discarded_tail_digest: if tail.is_empty() { None } else { Some(ContentDigest::sha256(tail)) },
        discarded_bytes: u64::try_from(tail.len()).map_err(|_| DurableSessionError::CapacityExceeded)?,
        restored: SessionJournalInspection {
            root: report.last_root(), checkpoint_digest, records: report.records().len(),
            committed_bytes: report.committed_len(), incomplete_tail: None,
        },
    };
    if !tail.is_empty() { file.set_len(report.committed_len())?; }
    // Also synchronize a complete CommitWrite record after losing its original unsynced handle.
    file.sync_all()?;
    drop(file);
    // Revalidate the exact bounded prefix before installing a new writer. No partial semantic
    // state or receipt escapes on an I/O error, layout mutation, or root/length mismatch.
    let after = read_report(path, limits)?;
    if after.last_root() != expected_root || after.committed_len() != report.committed_len()
        || after.incomplete_tail().is_some() || after.records() != report.records()
    { return Err(DurableSessionError::RootMismatch); }
    let journal = Journal::open(path, IncompleteTailPolicy::Reject)?;
    if journal.last_root() != expected_root || journal.committed_len() != report.committed_len() {
        return Err(DurableSessionError::RootMismatch);
    }
    let store = DurableSessionStore {
        journal, memory, checkpoint_digest, limits, records: report.records().len(),
        fenced: false, pending: None, coordination,
    };
    Ok((store, receipt))
}
