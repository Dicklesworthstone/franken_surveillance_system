#![forbid(unsafe_code)]
//! Two-phase active epoch writer and crash-tail quarantine/truncation helper.

use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use fss_core::{ContentDigest, sha256};

use crate::MAX_RECORD_PAYLOAD_BYTES;
use crate::error::AppendPhase;
use crate::journal::IncompleteTailPolicy;

use super::segment::{
    EPOCH_HEADER_LEN, EPOCH_RECORD_HEADER_LEN, EPOCH_RECORD_MAGIC, EPOCH_RECORD_TRAILER_LEN,
    EPOCH_TRAILER_MAGIC, EpochHeader, epoch_file_path,
};
use super::{EpochLedgerError, crc32_ieee, sync_directory};

/// Quarantines a validated incomplete tail to `<dir>/quarantine/` and truncates the active epoch.
pub(crate) fn quarantine_and_truncate_tail(
    root_dir: &Path,
    epochs_dir: &Path,
    epoch_id: u64,
    committed_len: u64,
) -> Result<PathBuf, EpochLedgerError> {
    let epoch_path = epoch_file_path(epochs_dir, epoch_id);
    let mut file = OpenOptions::new()
        .read(true)
        .write(true)
        .open(&epoch_path)?;
    file.seek(SeekFrom::Start(committed_len))?;
    let mut tail_bytes = Vec::new();
    file.read_to_end(&mut tail_bytes)?;

    let quarantine_path = quarantine_tail_bytes(root_dir, epoch_id, committed_len, &tail_bytes)?;
    file.set_len(committed_len)?;
    file.sync_all()?;
    Ok(quarantine_path)
}

/// Persists the exact observed suffix before the owning descriptor may truncate it.
fn quarantine_tail_bytes(
    root_dir: &Path,
    epoch_id: u64,
    committed_len: u64,
    tail_bytes: &[u8],
) -> Result<PathBuf, EpochLedgerError> {
    let quarantine_dir = root_dir.join("quarantine");
    fs::create_dir_all(&quarantine_dir)?;
    let mut quarantine_path =
        quarantine_dir.join(format!("epoch-{epoch_id:016}-offset-{committed_len}.tail"));
    let mut attempt = 1_u32;
    while quarantine_path.exists() {
        quarantine_path = quarantine_dir.join(format!(
            "epoch-{epoch_id:016}-offset-{committed_len}.{attempt}.tail"
        ));
        attempt = attempt.checked_add(1).ok_or(EpochLedgerError::SequenceExhausted)?;
    }
    {
        let mut qfile = OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&quarantine_path)?;
        qfile.write_all(tail_bytes)?;
        qfile.sync_all()?;
    }
    sync_directory(&quarantine_dir)?;
    sync_directory(root_dir)?;
    Ok(quarantine_path)
}

/// Writable handle to the currently active epoch segment file.
#[derive(Debug)]
pub(crate) struct EpochSegmentWriter {
    file: File,
    epoch_id: u64,
    committed_len: u64,
    batch_count: u64,
    history_root: ContentDigest,
    pending: Option<PendingEpochAppend>,
    fail_after: Option<AppendPhase>,
}

/// Exact bounded record retained while an append's durability is unresolved.
#[derive(Debug)]
struct PendingEpochAppend {
    sequence: u64,
    body: Vec<u8>,
    trailer: [u8; EPOCH_RECORD_TRAILER_LEN],
    next_committed_len: u64,
    next_batch_count: u64,
    next_history_root: ContentDigest,
}

impl EpochSegmentWriter {
    /// Opens an existing active epoch file positioned at `committed_len`.
    pub(crate) fn open(
        epochs_dir: &Path,
        header: EpochHeader,
        committed_len: u64,
        batch_count: u64,
        history_root: ContentDigest,
    ) -> Result<Self, EpochLedgerError> {
        let path = epoch_file_path(epochs_dir, header.epoch_id);
        let mut file = OpenOptions::new().read(true).write(true).open(&path)?;
        file.seek(SeekFrom::Start(committed_len))?;
        Ok(Self {
            file,
            epoch_id: header.epoch_id,
            committed_len,
            batch_count,
            history_root,
            pending: None,
            fail_after: None,
        })
    }

    #[must_use]
    pub(crate) const fn epoch_id(&self) -> u64 {
        self.epoch_id
    }

    #[must_use]
    pub(crate) const fn committed_len(&self) -> u64 {
        self.committed_len
    }

    #[must_use]
    pub(crate) const fn batch_count(&self) -> u64 {
        self.batch_count
    }

    pub(crate) fn pending_sequence(&self) -> Option<u64> {
        self.pending.as_ref().map(|pending| pending.sequence)
    }

    pub(crate) fn ensure_reconciled(&self) -> Result<(), EpochLedgerError> {
        if let Some(sequence) = self.pending_sequence() {
            return Err(EpochLedgerError::ReconciliationRequired { sequence });
        }
        Ok(())
    }

    /// Computes the exact on-disk framed length of a record carrying `payload_len` bytes.
    pub(crate) fn framed_record_len(payload_len: usize) -> Result<u64, EpochLedgerError> {
        let total = EPOCH_RECORD_HEADER_LEN
            .checked_add(payload_len)
            .and_then(|n| n.checked_add(EPOCH_RECORD_TRAILER_LEN))
            .ok_or(EpochLedgerError::SequenceExhausted)?;
        Ok(total as u64)
    }

    /// Flushes and syncs this epoch file before sealing it during rollover.
    pub(crate) fn seal(&mut self) -> Result<(), EpochLedgerError> {
        self.ensure_reconciled()?;
        self.file.sync_all()?;
        Ok(())
    }

    /// Appends one length-framed, CRC32 + SHA-256 + commit-trailer verified batch record.
    pub(crate) fn append_record(
        &mut self,
        commit_seq: u64,
        payload: &[u8],
        next_history_root: ContentDigest,
    ) -> Result<u64, EpochLedgerError> {
        self.ensure_reconciled()?;
        let payload_len_u32 = u32::try_from(payload.len())
            .map_err(|_| EpochLedgerError::InvalidConfig("record payload exceeds u32"))?;
        if payload.len() > MAX_RECORD_PAYLOAD_BYTES {
            return Err(EpochLedgerError::InvalidConfig(
                "record payload exceeds MAX_RECORD_PAYLOAD_BYTES",
            ));
        }

        let payload_crc = crc32_ieee(payload);
        let payload_sha = sha256(payload);

        let mut body = Vec::with_capacity(EPOCH_RECORD_HEADER_LEN + payload.len());
        body.extend_from_slice(&EPOCH_RECORD_MAGIC);
        body.extend_from_slice(&0_u16.to_be_bytes());
        body.extend_from_slice(&commit_seq.to_be_bytes());
        body.extend_from_slice(&payload_len_u32.to_be_bytes());
        body.extend_from_slice(&payload_crc.to_be_bytes());
        body.extend_from_slice(&payload_sha);
        let header_crc = crc32_ieee(&body);
        body.extend_from_slice(&header_crc.to_be_bytes());
        body.extend_from_slice(payload);

        let mut trailer = [0_u8; EPOCH_RECORD_TRAILER_LEN];
        trailer[0..4].copy_from_slice(&EPOCH_TRAILER_MAGIC);
        trailer[4..36].copy_from_slice(&next_history_root.bytes());
        let trailer_crc = crc32_ieee(&trailer[0..36]);
        trailer[36..40].copy_from_slice(&trailer_crc.to_be_bytes());

        let framed_len = Self::framed_record_len(payload.len())?;
        let new_committed_len = self
            .committed_len
            .checked_add(framed_len)
            .ok_or(EpochLedgerError::SequenceExhausted)?;

        let next_batch_count = self
            .batch_count
            .checked_add(1)
            .ok_or(EpochLedgerError::SequenceExhausted)?;

        // Cooperating writers are excluded by the root lock. Independently changed tail bytes
        // must still be refused rather than silently overwritten at the cached boundary.
        if self.file.metadata()?.len() != self.committed_len {
            return Err(EpochLedgerError::LiveStateDivergence(
                "active epoch length changed before append",
            ));
        }
        self.verify_committed_boundary()?;
        self.file.seek(SeekFrom::Start(self.committed_len))?;

        let mut phase = AppendPhase::BodyWrite;
        let result = (|| -> io::Result<()> {
            self.file.write_all(&body)?;
            self.maybe_fail(phase)?;
            phase = AppendPhase::BodySync;
            self.file.sync_data()?;
            self.maybe_fail(phase)?;
            phase = AppendPhase::CommitWrite;
            self.file.write_all(&trailer)?;
            self.maybe_fail(phase)?;
            phase = AppendPhase::CommitSync;
            self.file.sync_all()?;
            self.maybe_fail(phase)
        })();
        if let Err(source) = result {
            self.pending = Some(PendingEpochAppend {
                sequence: commit_seq,
                body,
                trailer,
                next_committed_len: new_committed_len,
                next_batch_count,
                next_history_root,
            });
            return Err(EpochLedgerError::AppendIndeterminate {
                epoch_id: self.epoch_id,
                sequence: commit_seq,
                phase,
                source,
            });
        }

        self.committed_len = new_committed_len;
        self.batch_count = next_batch_count;
        self.history_root = next_history_root;
        Ok(self.committed_len)
    }

    /// Verifies only the last reconciled boundary; full historical verification remains separate.
    fn verify_committed_boundary(&mut self) -> Result<(), EpochLedgerError> {
        if self.committed_len == EPOCH_HEADER_LEN as u64 {
            self.file.seek(SeekFrom::Start(0))?;
            let mut bytes = [0_u8; EPOCH_HEADER_LEN];
            self.file.read_exact(&mut bytes)?;
            let header = EpochHeader::decode(&bytes, self.epoch_id)?;
            if header.prev_history_root != self.history_root {
                return Err(EpochLedgerError::LiveStateDivergence(
                    "active epoch header no longer matches the reconciled history root",
                ));
            }
        } else {
            let offset = self
                .committed_len
                .checked_sub(EPOCH_RECORD_TRAILER_LEN as u64)
                .ok_or(EpochLedgerError::SequenceExhausted)?;
            self.file.seek(SeekFrom::Start(offset))?;
            let mut trailer = [0_u8; EPOCH_RECORD_TRAILER_LEN];
            self.file.read_exact(&mut trailer)?;
            if trailer[..4] != EPOCH_TRAILER_MAGIC
                || trailer[4..36] != self.history_root.bytes()
                || trailer[36..] != crc32_ieee(&trailer[..36]).to_be_bytes()
            {
                return Err(EpochLedgerError::LiveStateDivergence(
                    "active epoch commit trailer changed before append",
                ));
            }
        }
        Ok(())
    }

    /// Classifies only the exact attempted record, keeping the fence on every failure.
    pub(crate) fn reconcile_pending(
        &mut self,
        root_dir: &Path,
        tail_policy: IncompleteTailPolicy,
    ) -> Result<bool, EpochLedgerError> {
        let sequence = self
            .pending_sequence()
            .ok_or(EpochLedgerError::NoPendingAppend)?;
        let mut phase = AppendPhase::ReconcileRead;
        let result = (|| -> Result<bool, EpochLedgerError> {
            self.verify_committed_boundary()?;
            let pending = self.pending.as_ref().ok_or(EpochLedgerError::NoPendingAppend)?;
            let file_len = self.file.metadata()?.len();
            if file_len < self.committed_len || file_len > pending.next_committed_len {
                return Err(EpochLedgerError::LiveStateDivergence(
                    "pending epoch append length differs from the attempted record",
                ));
            }
            let suffix_len = usize::try_from(file_len - self.committed_len)
                .map_err(|_| EpochLedgerError::SequenceExhausted)?;
            let mut observed = vec![0_u8; suffix_len];
            self.file.seek(SeekFrom::Start(self.committed_len))?;
            self.file.read_exact(&mut observed)?;
            let body_len = suffix_len.min(pending.body.len());
            if observed[..body_len] != pending.body[..body_len]
                || observed[body_len..] != pending.trailer[..suffix_len - body_len]
            {
                return Err(EpochLedgerError::LiveStateDivergence(
                    "pending epoch append bytes differ from the attempted record",
                ));
            }
            let committed = file_len == pending.next_committed_len;
            let committed_len = if committed {
                pending.next_committed_len
            } else {
                self.committed_len
            };
            self.maybe_fail(phase)?;

            if !committed && suffix_len != 0 {
                if tail_policy == IncompleteTailPolicy::Reject {
                    return Err(EpochLedgerError::IncompleteTail {
                        epoch_id: self.epoch_id,
                        offset: self.committed_len,
                    });
                }
                phase = AppendPhase::ReconcileTruncate;
                let _quarantine = quarantine_tail_bytes(
                    root_dir,
                    self.epoch_id,
                    self.committed_len,
                    &observed,
                )?;
                self.file.set_len(self.committed_len)?;
                self.maybe_fail(phase)?;
            }

            phase = AppendPhase::ReconcileSync;
            self.file.sync_all()?;
            self.maybe_fail(phase)?;
            phase = AppendPhase::ReconcileSeek;
            self.file.seek(SeekFrom::Start(committed_len))?;
            self.maybe_fail(phase)?;
            Ok(committed)
        })();
        let committed = match result {
            Ok(committed) => committed,
            Err(EpochLedgerError::Io(source)) => {
                return Err(EpochLedgerError::AppendIndeterminate {
                    epoch_id: self.epoch_id,
                    sequence,
                    phase,
                    source,
                });
            }
            Err(error) => return Err(error),
        };
        if let Some(pending) = self.pending.take()
            && committed
        {
            self.committed_len = pending.next_committed_len;
            self.batch_count = pending.next_batch_count;
            self.history_root = pending.next_history_root;
        }
        Ok(committed)
    }

    fn maybe_fail(&mut self, phase: AppendPhase) -> io::Result<()> {
        if self.fail_after == Some(phase) {
            self.fail_after = None;
            Err(io::Error::other(format!("injected failure after {phase:?}")))
        } else {
            Ok(())
        }
    }

    pub(crate) fn fail_after_phase(&mut self, phase: AppendPhase) {
        self.fail_after = Some(phase);
    }

    pub(crate) fn take_failure_injection(&mut self) -> Option<AppendPhase> {
        self.fail_after.take()
    }
}
