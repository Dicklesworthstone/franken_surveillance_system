#![forbid(unsafe_code)]
//! Two-phase active epoch writer and crash-tail quarantine/truncation helper.

use std::fs::{self, File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use fss_core::{ContentDigest, sha256};

use crate::MAX_RECORD_PAYLOAD_BYTES;

use super::segment::{
    EPOCH_RECORD_HEADER_LEN, EPOCH_RECORD_MAGIC, EPOCH_RECORD_TRAILER_LEN, EPOCH_TRAILER_MAGIC,
    EpochHeader, epoch_file_path,
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

    let quarantine_dir = root_dir.join("quarantine");
    fs::create_dir_all(&quarantine_dir)?;
    let mut quarantine_path =
        quarantine_dir.join(format!("epoch-{epoch_id:016}-offset-{committed_len}.tail"));
    let mut attempt = 1_u32;
    while quarantine_path.exists() {
        quarantine_path = quarantine_dir.join(format!(
            "epoch-{epoch_id:016}-offset-{committed_len}.{attempt}.tail"
        ));
        attempt = attempt.saturating_add(1);
    }
    {
        let mut qfile = OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&quarantine_path)?;
        qfile.write_all(&tail_bytes)?;
        qfile.sync_all()?;
    }
    sync_directory(&quarantine_dir)?;

    file.set_len(committed_len)?;
    file.sync_all()?;
    Ok(quarantine_path)
}

/// Writable handle to the currently active epoch segment file.
#[derive(Debug)]
pub(crate) struct EpochSegmentWriter {
    file: File,
    epoch_id: u64,
    committed_len: u64,
    batch_count: u64,
}

impl EpochSegmentWriter {
    /// Opens an existing active epoch file positioned at `committed_len`.
    pub(crate) fn open(
        epochs_dir: &Path,
        header: EpochHeader,
        committed_len: u64,
        batch_count: u64,
    ) -> Result<Self, EpochLedgerError> {
        let path = epoch_file_path(epochs_dir, header.epoch_id);
        let mut file = OpenOptions::new().read(true).write(true).open(&path)?;
        file.seek(SeekFrom::Start(committed_len))?;
        Ok(Self {
            file,
            epoch_id: header.epoch_id,
            committed_len,
            batch_count,
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

        self.file.seek(SeekFrom::Start(self.committed_len))?;
        self.file.write_all(&body)?;
        self.file.sync_data()?;
        self.file.write_all(&trailer)?;
        self.file.sync_all()?;

        self.committed_len = new_committed_len;
        self.batch_count = self
            .batch_count
            .checked_add(1)
            .ok_or(EpochLedgerError::SequenceExhausted)?;
        Ok(self.committed_len)
    }
}
