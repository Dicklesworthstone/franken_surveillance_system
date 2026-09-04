//! Writable two-phase journal publication with explicit ambiguous-append reconciliation.

use std::fs::{File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use fss_core::{ContentDigest, DigestAlgorithm, sha256};

use crate::MAX_RECORD_PAYLOAD_BYTES;
use crate::error::{AppendPhase, JournalError};
use crate::format::{
    COMMIT_MAGIC, FORMAT_VERSION, HEADER_LEN, RECORD_MAGIC, TRAILER_LEN, record_root,
};
use crate::recovery::{JournalRecord, RecoveryReport, recover_bytes};

/// Explicit policy for a validated incomplete final record.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IncompleteTailPolicy {
    /// Refuse to open or reconcile a journal that ends with an incomplete record.
    Reject,
    /// Truncate exactly the incomplete suffix after validating every committed record.
    Truncate,
}

/// Result of reconciling one previously indeterminate append.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AppendReconciliation {
    /// The exact pending record is committed and synchronized.
    Committed(JournalRecord),
    /// The pending record never committed and any incomplete suffix is gone.
    NotCommitted {
        /// Sequence that remains available for a safe retry.
        sequence: u64,
    },
}

#[derive(Clone, Debug)]
struct PendingAppend {
    record: JournalRecord,
    previous_root: [u8; 32],
    base_committed_len: u64,
    expected_end: u64,
    next_sequence: u64,
}

/// Writable crash-classifying reference journal.
///
/// One `Journal` handle is the sole writer for its path. The handle checks for externally changed
/// length before every append, but cross-process mutual exclusion belongs to the future
/// Asupersync-owned production adapter. Any I/O failure after append bytes may have been written
/// moves this handle into a reconciliation-required state.
#[derive(Debug)]
pub struct Journal {
    path: PathBuf,
    file: File,
    next_sequence: u64,
    last_root: [u8; 32],
    committed_len: u64,
    pending: Option<PendingAppend>,
    #[cfg(test)]
    fail_after: Option<AppendPhase>,
}

impl Journal {
    /// Opens or creates a journal after verifying its complete prefix.
    ///
    /// `Truncate` removes only a suffix already classified as incomplete. Corruption is never
    /// repaired or skipped. All validation that can fail happens before truncation.
    pub fn open(
        path: impl AsRef<Path>,
        tail_policy: IncompleteTailPolicy,
    ) -> Result<Self, JournalError> {
        let path = path.as_ref().to_path_buf();
        let mut file = OpenOptions::new()
            .create(true)
            .read(true)
            .write(true)
            .truncate(false)
            .open(&path)?;
        file.seek(SeekFrom::Start(0))?;
        let mut bytes = Vec::new();
        file.read_to_end(&mut bytes)?;
        let recovery = recover_bytes(&bytes)?;
        let next_sequence = recovery.records.last().map_or(Ok(1_u64), |record| {
            record
                .sequence
                .checked_add(1)
                .ok_or(JournalError::SequenceExhausted)
        })?;
        if let Some(offset) = recovery.incomplete_tail {
            match tail_policy {
                IncompleteTailPolicy::Reject => {
                    return Err(JournalError::IncompleteTail { offset });
                }
                IncompleteTailPolicy::Truncate => {
                    file.set_len(recovery.committed_len)?;
                    file.sync_all()?;
                }
            }
        }
        file.seek(SeekFrom::Start(recovery.committed_len))?;
        Ok(Self {
            path,
            file,
            next_sequence,
            last_root: recovery.last_root.bytes(),
            committed_len: recovery.committed_len,
            pending: None,
            #[cfg(test)]
            fail_after: None,
        })
    }

    /// Path backing this journal.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Root of the latest reconciled committed record.
    #[must_use]
    pub const fn last_root(&self) -> ContentDigest {
        ContentDigest::new(DigestAlgorithm::Sha256, self.last_root)
    }

    /// Sequence requiring reconciliation, if an append outcome is unresolved.
    #[must_use]
    pub fn pending_sequence(&self) -> Option<u64> {
        self.pending.as_ref().map(|pending| pending.record.sequence)
    }

    /// Appends and durably commits one record.
    ///
    /// Every fallible semantic check and allocation happens before I/O. The record body is
    /// synchronized before the commit trailer. Any I/O error after writing begins returns
    /// `AppendIndeterminate` and blocks append/verify until `reconcile_pending` classifies the
    /// exact attempted record as committed or not committed.
    pub fn append(&mut self, kind: u16, payload: &[u8]) -> Result<JournalRecord, JournalError> {
        if let Some(pending) = &self.pending {
            return Err(JournalError::ReconciliationRequired {
                sequence: pending.record.sequence,
            });
        }
        if payload.len() > MAX_RECORD_PAYLOAD_BYTES {
            return Err(JournalError::PayloadTooLarge {
                length: payload.len(),
                maximum: MAX_RECORD_PAYLOAD_BYTES,
            });
        }
        let observed_len = self.file.metadata()?.len();
        if observed_len != self.committed_len {
            return Err(JournalError::ExternalMutation {
                expected_len: self.committed_len,
                observed_len,
            });
        }

        let sequence = self.next_sequence;
        let next_sequence = sequence
            .checked_add(1)
            .ok_or(JournalError::SequenceExhausted)?;
        let payload_copy = payload.to_vec();
        let payload_len =
            u32::try_from(payload.len()).map_err(|_| JournalError::PayloadTooLarge {
                length: payload.len(),
                maximum: MAX_RECORD_PAYLOAD_BYTES,
            })?;
        let payload_digest = sha256(payload);
        let root = record_root(sequence, kind, payload_len, self.last_root, payload_digest);

        let mut body = Vec::with_capacity(HEADER_LEN + payload.len());
        body.extend_from_slice(&RECORD_MAGIC);
        body.extend_from_slice(&FORMAT_VERSION.to_be_bytes());
        body.extend_from_slice(&sequence.to_be_bytes());
        body.extend_from_slice(&kind.to_be_bytes());
        body.extend_from_slice(&payload_len.to_be_bytes());
        body.extend_from_slice(&self.last_root);
        body.extend_from_slice(&payload_digest);
        body.extend_from_slice(payload);

        let mut trailer = Vec::with_capacity(TRAILER_LEN);
        trailer.extend_from_slice(&COMMIT_MAGIC);
        trailer.extend_from_slice(&root);

        let encoded_len =
            body.len()
                .checked_add(trailer.len())
                .ok_or(JournalError::PayloadTooLarge {
                    length: payload.len(),
                    maximum: MAX_RECORD_PAYLOAD_BYTES,
                })?;
        let encoded_len =
            u64::try_from(encoded_len).map_err(|_| JournalError::PayloadTooLarge {
                length: payload.len(),
                maximum: MAX_RECORD_PAYLOAD_BYTES,
            })?;
        let expected_end = self
            .committed_len
            .checked_add(encoded_len)
            .ok_or(JournalError::SequenceExhausted)?;
        let record = JournalRecord {
            sequence,
            kind,
            payload: payload_copy,
            payload_digest: ContentDigest::new(DigestAlgorithm::Sha256, payload_digest),
            root: ContentDigest::new(DigestAlgorithm::Sha256, root),
        };
        let pending = PendingAppend {
            record: record.clone(),
            previous_root: self.last_root,
            base_committed_len: self.committed_len,
            expected_end,
            next_sequence,
        };

        self.file.seek(SeekFrom::Start(self.committed_len))?;
        self.pending = Some(pending.clone());

        if let Err(source) = self.file.write_all(&body) {
            return Err(self.indeterminate(AppendPhase::BodyWrite, source));
        }
        #[cfg(test)]
        if let Err(source) = self.maybe_fail(AppendPhase::BodyWrite) {
            return Err(self.indeterminate(AppendPhase::BodyWrite, source));
        }
        if let Err(source) = self.file.sync_data() {
            return Err(self.indeterminate(AppendPhase::BodySync, source));
        }
        #[cfg(test)]
        if let Err(source) = self.maybe_fail(AppendPhase::BodySync) {
            return Err(self.indeterminate(AppendPhase::BodySync, source));
        }
        if let Err(source) = self.file.write_all(&trailer) {
            return Err(self.indeterminate(AppendPhase::CommitWrite, source));
        }
        #[cfg(test)]
        if let Err(source) = self.maybe_fail(AppendPhase::CommitWrite) {
            return Err(self.indeterminate(AppendPhase::CommitWrite, source));
        }
        if let Err(source) = self.file.sync_all() {
            return Err(self.indeterminate(AppendPhase::CommitSync, source));
        }
        #[cfg(test)]
        if let Err(source) = self.maybe_fail(AppendPhase::CommitSync) {
            return Err(self.indeterminate(AppendPhase::CommitSync, source));
        }

        Ok(self.commit_pending(pending))
    }

    /// Reconciles the exact unresolved append retained by this handle.
    ///
    /// A fully present expected record is synchronized again and committed exactly once. A proven
    /// incomplete suffix is either rejected or truncated according to `tail_policy`. Any divergent
    /// complete history is refused as external mutation rather than guessed or overwritten.
    pub fn reconcile_pending(
        &mut self,
        tail_policy: IncompleteTailPolicy,
    ) -> Result<AppendReconciliation, JournalError> {
        let pending = self.pending.clone().ok_or(JournalError::NoPendingAppend)?;

        if let Err(source) = self.file.seek(SeekFrom::Start(0)) {
            return Err(self.indeterminate(AppendPhase::ReconcileRead, source));
        }
        let mut bytes = Vec::new();
        if let Err(source) = self.file.read_to_end(&mut bytes) {
            return Err(self.indeterminate(AppendPhase::ReconcileRead, source));
        }
        let report = recover_bytes(&bytes)?;

        let expected_committed = report.incomplete_tail.is_none()
            && report.committed_len == pending.expected_end
            && report.last_root == pending.record.root
            && report
                .records
                .last()
                .is_some_and(|record| record == &pending.record);
        if expected_committed {
            if let Err(source) = self.file.sync_all() {
                return Err(self.indeterminate(AppendPhase::ReconcileSync, source));
            }
            let record = self.commit_pending(pending);
            return Ok(AppendReconciliation::Committed(record));
        }

        let previous_prefix = report.last_root.bytes() == pending.previous_root
            && report.committed_len == pending.base_committed_len;
        if previous_prefix {
            if let Some(offset) = report.incomplete_tail {
                if tail_policy == IncompleteTailPolicy::Reject {
                    return Err(JournalError::IncompleteTail { offset });
                }
                if let Err(source) = self.file.set_len(pending.base_committed_len) {
                    return Err(self.indeterminate(AppendPhase::ReconcileTruncate, source));
                }
                if let Err(source) = self.file.sync_all() {
                    return Err(self.indeterminate(AppendPhase::ReconcileSync, source));
                }
                if let Err(source) = self.file.seek(SeekFrom::Start(pending.base_committed_len)) {
                    return Err(self.indeterminate(AppendPhase::ReconcileSeek, source));
                }
                self.pending = None;
                return Ok(AppendReconciliation::NotCommitted {
                    sequence: pending.record.sequence,
                });
            }
            if bytes.len() as u64 == pending.base_committed_len {
                self.pending = None;
                return Ok(AppendReconciliation::NotCommitted {
                    sequence: pending.record.sequence,
                });
            }
        }

        Err(JournalError::ExternalMutation {
            expected_len: pending.expected_end,
            observed_len: bytes.len() as u64,
        })
    }

    /// Re-reads durable bytes and proves they match this handle's reconciled root and length.
    pub fn verify(&mut self) -> Result<RecoveryReport, JournalError> {
        if let Some(pending) = &self.pending {
            return Err(JournalError::ReconciliationRequired {
                sequence: pending.record.sequence,
            });
        }
        self.file.sync_all()?;
        self.file.seek(SeekFrom::Start(0))?;
        let mut bytes = Vec::new();
        self.file.read_to_end(&mut bytes)?;
        let report = recover_bytes(&bytes)?;
        if let Some(offset) = report.incomplete_tail {
            return Err(JournalError::IncompleteTail { offset });
        }
        if report.last_root.bytes() != self.last_root || report.committed_len != self.committed_len
        {
            return Err(JournalError::ExternalMutation {
                expected_len: self.committed_len,
                observed_len: report.committed_len,
            });
        }
        self.file.seek(SeekFrom::Start(self.committed_len))?;
        Ok(report)
    }

    fn commit_pending(&mut self, pending: PendingAppend) -> JournalRecord {
        self.next_sequence = pending.next_sequence;
        self.last_root = pending.record.root.bytes();
        self.committed_len = pending.expected_end;
        self.pending = None;
        pending.record
    }

    fn indeterminate(&self, phase: AppendPhase, source: io::Error) -> JournalError {
        let sequence = self
            .pending
            .as_ref()
            .map_or(self.next_sequence, |pending| pending.record.sequence);
        JournalError::AppendIndeterminate {
            sequence,
            phase,
            source,
        }
    }

    #[cfg(test)]
    fn maybe_fail(&mut self, phase: AppendPhase) -> io::Result<()> {
        if self.fail_after == Some(phase) {
            self.fail_after = None;
            Err(io::Error::other(format!(
                "injected failure after {phase:?}"
            )))
        } else {
            Ok(())
        }
    }

    #[cfg(test)]
    pub(crate) fn fail_after_phase(&mut self, phase: AppendPhase) {
        self.fail_after = Some(phase);
    }
}
