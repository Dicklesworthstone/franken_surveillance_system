#![forbid(unsafe_code)]
//! Verified sealed-epoch archival receipts and safe local epoch pruning for [`MerkleEpochLedger`].
//!
//! Identifies immutable sealed epoch segment files (`<dir>/epochs/{epoch_id:016}.fssj`) strictly
//! older than the latest cryptographically verified `FSSC` checkpoint, verifies every header,
//! record CRC32/SHA-256, `FSST` commit trailer, and canonical `successor_history_root_v2` chain
//! right into the checkpoint anchor, and produces a canonical digest-bound [`EpochArchivalReceipt`].
//!
//! Active epochs and epochs not strictly covered by a verified `FSSC` checkpoint are ALWAYS refused.

use std::error::Error;
use std::fmt;
use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};

use fss_core::{
    CanonicalDecode, CanonicalDecoder, CanonicalEncode, CanonicalEncoder, ContentDigest,
    DigestAlgorithm, TimestampNs, sha256,
};

use crate::batch_codec::decode_batch;

use super::checkpoint::{list_checkpoint_files_desc, read_and_verify_checkpoint};
use super::segment::{
    EPOCH_HEADER_LEN, EpochHeader, epoch_file_path, scan_epoch_from, verify_checkpoint_epoch_anchor,
};
use super::{
    EpochCorruptionKind, EpochLedgerError, MerkleEpochLedger, genesis_history_root_v2,
    successor_history_root_v2, sync_directory,
};

/// Canonical digest domain for [`EpochArchivalReceipt::receipt_digest`].
pub const EPOCH_ARCHIVAL_RECEIPT_DOMAIN: &str = "fss.ledger.epoch_archival_receipt.v2";
/// Magic prefix for persisted canonical archival receipt files (`*.fssa`).
pub const EPOCH_ARCHIVAL_RECEIPT_MAGIC: [u8; 4] = *b"FSSA";
/// Supported format version for persisted archival receipt files.
pub const EPOCH_ARCHIVAL_RECEIPT_VERSION: u16 = 2;

const RECEIPT_PREFIX_LEN: usize = 6;
const RECEIPT_TRAILER_LEN: usize = 32;

/// Policy governing sealed ledger epoch archival verification, copying, and optional local pruning.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct EpochArchivalPolicy {
    /// Additional sealed epochs immediately preceding the checkpoint anchor epoch to keep locally.
    pub retain_recent_sealed_epochs: u64,
    /// Optional destination directory where verified epoch files and archival receipts are copied.
    pub archive_dir: Option<PathBuf>,
    /// If `true`, unlink locally archived `.fssj` files ONLY AFTER verified archival copy and
    /// durable receipt persistence (never touches checkpoint anchor epoch, active epoch, or `FSSC`s).
    pub prune_local_epochs: bool,
    /// Optional explicit set of epoch IDs requested for archival (active or uncheckpointed IDs refuse).
    pub requested_epochs: Option<Vec<u64>>,
}

impl EpochArchivalPolicy {
    /// Validates archival policy safety preconditions.
    pub fn validate(&self) -> Result<(), EpochArchivalError> {
        if self.prune_local_epochs && self.archive_dir.is_none() {
            return Err(EpochArchivalError::InvalidPolicy(
                "prune_local_epochs requires an explicit archive_dir",
            ));
        }
        Ok(())
    }
}

/// Typed refusal and verification error taxonomy for ledger epoch archival.
#[derive(Debug)]
pub enum EpochArchivalError {
    /// Archival policy violated a safety invariant.
    InvalidPolicy(&'static str),
    /// No verified `FSSC` checkpoint exists on disk to anchor archival.
    NoVerifiedCheckpoint,
    /// Attempted to archive the active (or future) epoch segment.
    ActiveEpochNotArchivable {
        /// Requested epoch identifier.
        epoch_id: u64,
        /// Current active writable epoch identifier.
        active_epoch_id: u64,
    },
    /// Attempted to archive an epoch not strictly older than the latest verified `FSSC` checkpoint.
    EpochNotCoveredByCheckpoint {
        /// Requested epoch identifier.
        epoch_id: u64,
        /// Epoch anchored by the latest verified `FSSC` checkpoint.
        checkpoint_epoch_id: u64,
        /// Commit sequence of the latest verified `FSSC` checkpoint.
        checkpoint_commit_seq: u64,
    },
    /// No sealed epochs are strictly older than the latest verified checkpoint (after retention).
    NoEligibleEpochs {
        /// Epoch anchored by the latest verified checkpoint.
        checkpoint_epoch_id: u64,
        /// Current active writable epoch.
        active_epoch_id: u64,
    },
    /// Expected contiguous epoch file is missing on disk.
    MissingEpochFile {
        /// Missing epoch identifier.
        epoch_id: u64,
    },
    /// Recomputed history-root continuity broke at an epoch or checkpoint boundary.
    HistoryChainBroken {
        /// Epoch where history-root continuity diverged.
        epoch_id: u64,
        /// Expected canonical history root.
        expected: ContentDigest,
        /// Observed history root in file or checkpoint.
        observed: ContentDigest,
    },
    /// Copied archive file SHA-256 disagreed with the verified source epoch SHA-256.
    ArchivedCopyDigestMismatch {
        /// Epoch identifier whose copy mismatched.
        epoch_id: u64,
        /// Expected source SHA-256.
        expected: ContentDigest,
        /// Observed archived copy SHA-256.
        actual: ContentDigest,
    },
    /// Persisted archival receipt failed magic, version, decode, or digest verification.
    InvalidReceipt(&'static str),
    /// Underlying canonical epoch/batch verification failure.
    Ledger(EpochLedgerError),
    /// Filesystem I/O error.
    Io(io::Error),
}

impl fmt::Display for EpochArchivalError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidPolicy(msg) => write!(f, "invalid epoch archival policy: {msg}"),
            Self::NoVerifiedCheckpoint => {
                f.write_str("cannot archive epochs without a verified FSSC checkpoint")
            }
            Self::ActiveEpochNotArchivable {
                epoch_id,
                active_epoch_id,
            } => write!(
                f,
                "refusing to archive active epoch {epoch_id} (active={active_epoch_id})"
            ),
            Self::EpochNotCoveredByCheckpoint {
                epoch_id,
                checkpoint_epoch_id,
                checkpoint_commit_seq,
            } => write!(
                f,
                "epoch {epoch_id} is not strictly older than verified checkpoint epoch {checkpoint_epoch_id} (seq {checkpoint_commit_seq})"
            ),
            Self::NoEligibleEpochs {
                checkpoint_epoch_id,
                active_epoch_id,
            } => write!(
                f,
                "no sealed epochs strictly older than checkpoint epoch {checkpoint_epoch_id} (active={active_epoch_id})"
            ),
            Self::MissingEpochFile { epoch_id } => {
                write!(f, "missing epoch file {epoch_id:016}.fssj")
            }
            Self::HistoryChainBroken {
                epoch_id,
                expected,
                observed,
            } => write!(
                f,
                "history chain discontinuity at epoch {epoch_id}: expected {expected}, observed {observed}"
            ),
            Self::ArchivedCopyDigestMismatch {
                epoch_id,
                expected,
                actual,
            } => write!(
                f,
                "archived copy digest mismatch for epoch {epoch_id}: expected {expected}, actual {actual}"
            ),
            Self::InvalidReceipt(msg) => write!(f, "invalid epoch archival receipt: {msg}"),
            Self::Ledger(err) => write!(f, "epoch verification error: {err}"),
            Self::Io(err) => write!(f, "epoch archival I/O error: {err}"),
        }
    }
}

impl Error for EpochArchivalError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Ledger(err) => Some(err),
            Self::Io(err) => Some(err),
            _ => None,
        }
    }
}

impl From<EpochLedgerError> for EpochArchivalError {
    fn from(value: EpochLedgerError) -> Self {
        Self::Ledger(value)
    }
}

impl From<io::Error> for EpochArchivalError {
    fn from(value: io::Error) -> Self {
        Self::Io(value)
    }
}

/// Cryptographically verified metadata for one archived sealed epoch segment.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ArchivedEpochEntry {
    /// Zero-based immutable epoch segment identifier.
    pub epoch_id: u64,
    /// First committed batch sequence inside this epoch (inclusive).
    pub first_commit_seq: u64,
    /// Last committed batch sequence inside this epoch (inclusive).
    pub last_commit_seq: u64,
    /// Total committed batches verified inside this epoch.
    pub batch_count: u64,
    /// History root immediately preceding `first_commit_seq`.
    pub prev_history_root: ContentDigest,
    /// History root sealed by the final record's `FSST` commit trailer.
    pub end_history_root: ContentDigest,
    /// Exact byte length of the sealed `.fssj` file.
    pub file_bytes: u64,
    /// Whole-file SHA-256 digest of the immutable sealed `.fssj` file.
    pub file_sha256: ContentDigest,
    /// True if the local copy in `<root>/epochs/` was pruned after verified archive persistence.
    pub pruned_locally: bool,
}

impl CanonicalEncode for ArchivedEpochEntry {
    fn encode_canonical(&self, enc: &mut CanonicalEncoder) {
        enc.u64(self.epoch_id);
        enc.u64(self.first_commit_seq);
        enc.u64(self.last_commit_seq);
        enc.u64(self.batch_count);
        enc.digest(self.prev_history_root);
        enc.digest(self.end_history_root);
        enc.u64(self.file_bytes);
        enc.digest(self.file_sha256);
        enc.bool(self.pruned_locally);
    }
}

impl CanonicalDecode for ArchivedEpochEntry {
    fn decode_canonical(dec: &mut CanonicalDecoder<'_>) -> Result<Self, fss_core::ContractError> {
        Ok(Self {
            epoch_id: dec.u64()?,
            first_commit_seq: dec.u64()?,
            last_commit_seq: dec.u64()?,
            batch_count: dec.u64()?,
            prev_history_root: dec.digest()?,
            end_history_root: dec.digest()?,
            file_bytes: dec.u64()?,
            file_sha256: dec.digest()?,
            pruned_locally: dec.bool()?,
        })
    }
}

/// Canonical digest-bound receipt witnessing verified archival of sealed ledger epochs while
/// retaining the verified `FSSC` checkpoint anchor and canonical history-root proofs.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EpochArchivalReceipt {
    /// Site lineage identifier bound to this ledger.
    pub site_lineage: String,
    /// Caller-supplied archival timestamp (no ambient clock).
    pub archived_at_ns: TimestampNs,
    /// Commit sequence of the verified retaining `FSSC` checkpoint.
    pub retaining_checkpoint_seq: u64,
    /// Epoch segment identifier anchored by the verified retaining `FSSC` checkpoint.
    pub retaining_checkpoint_epoch_id: u64,
    /// Canonical v2 history root at the retaining checkpoint.
    pub retaining_checkpoint_history_root: ContentDigest,
    /// Canonical v2 Radix-Merkle state root at the retaining checkpoint.
    pub retaining_checkpoint_state_root: ContentDigest,
    /// Whole-file SHA-256 of the retained `FSSC` checkpoint file.
    pub retaining_checkpoint_sha256: ContentDigest,
    /// Sorted list of verified archived sealed epochs (`epoch_id` strictly ascending).
    pub archived_epochs: Vec<ArchivedEpochEntry>,
    /// Canonical SHA-256 commitment under [`EPOCH_ARCHIVAL_RECEIPT_DOMAIN`].
    pub receipt_digest: ContentDigest,
}

impl EpochArchivalReceipt {
    /// Recomputes and verifies [`Self::receipt_digest`], failing closed on any mutation.
    pub fn verify_receipt_digest(&self) -> Result<(), EpochArchivalError> {
        let expected = compute_receipt_digest(self)?;
        if expected != self.receipt_digest {
            return Err(EpochArchivalError::InvalidReceipt(
                "archival receipt digest mismatch",
            ));
        }
        Ok(())
    }

    /// Encodes this receipt into its self-verifying binary `FSSA` v2 file format.
    pub fn encode_canonical_file(&self) -> Result<Vec<u8>, EpochArchivalError> {
        let mut enc = CanonicalEncoder::new();
        enc.text(EPOCH_ARCHIVAL_RECEIPT_DOMAIN);
        encode_receipt_fields(self, &mut enc);
        enc.digest(self.receipt_digest);
        let body = enc
            .finish_checked()
            .map_err(|err| EpochArchivalError::Ledger(EpochLedgerError::Contract(err)))?;
        let mut out = Vec::with_capacity(RECEIPT_PREFIX_LEN + body.len() + RECEIPT_TRAILER_LEN);
        out.extend_from_slice(&EPOCH_ARCHIVAL_RECEIPT_MAGIC);
        out.extend_from_slice(&EPOCH_ARCHIVAL_RECEIPT_VERSION.to_be_bytes());
        out.extend_from_slice(&body);
        let whole_sha = sha256(&out);
        out.extend_from_slice(&whole_sha);
        Ok(out)
    }

    /// Decodes and verifies a persisted `FSSA` v2 archival receipt file.
    pub fn decode_canonical_file(raw: &[u8]) -> Result<Self, EpochArchivalError> {
        if raw.len() < RECEIPT_PREFIX_LEN + RECEIPT_TRAILER_LEN {
            return Err(EpochArchivalError::InvalidReceipt("receipt file too short"));
        }
        if raw[0..4] != EPOCH_ARCHIVAL_RECEIPT_MAGIC {
            return Err(EpochArchivalError::InvalidReceipt("invalid FSSA magic"));
        }
        let version = u16::from_be_bytes([raw[4], raw[5]]);
        if version != EPOCH_ARCHIVAL_RECEIPT_VERSION {
            return Err(EpochArchivalError::InvalidReceipt("unsupported version"));
        }
        let body_end = raw.len() - RECEIPT_TRAILER_LEN;
        if raw[body_end..] != sha256(&raw[..body_end]) {
            return Err(EpochArchivalError::InvalidReceipt(
                "trailing SHA-256 mismatch",
            ));
        }
        let mut dec = CanonicalDecoder::new(&raw[RECEIPT_PREFIX_LEN..body_end]);
        let domain = dec
            .text()
            .map_err(|_| EpochArchivalError::InvalidReceipt("canonical decode failed"))?;
        if domain != EPOCH_ARCHIVAL_RECEIPT_DOMAIN {
            return Err(EpochArchivalError::InvalidReceipt(
                "unexpected receipt domain",
            ));
        }
        let site_lineage = dec
            .text()
            .map_err(|_| EpochArchivalError::InvalidReceipt("canonical decode failed"))?
            .to_owned();
        let archived_at_ns = TimestampNs::decode_canonical(&mut dec)
            .map_err(|_| EpochArchivalError::InvalidReceipt("canonical decode failed"))?;
        let retaining_checkpoint_seq = dec
            .u64()
            .map_err(|_| EpochArchivalError::InvalidReceipt("canonical decode failed"))?;
        let retaining_checkpoint_epoch_id = dec
            .u64()
            .map_err(|_| EpochArchivalError::InvalidReceipt("canonical decode failed"))?;
        let retaining_checkpoint_history_root = dec
            .digest()
            .map_err(|_| EpochArchivalError::InvalidReceipt("canonical decode failed"))?;
        let retaining_checkpoint_state_root = dec
            .digest()
            .map_err(|_| EpochArchivalError::InvalidReceipt("canonical decode failed"))?;
        let retaining_checkpoint_sha256 = dec
            .digest()
            .map_err(|_| EpochArchivalError::InvalidReceipt("canonical decode failed"))?;
        let count = usize::try_from(
            dec.u64()
                .map_err(|_| EpochArchivalError::InvalidReceipt("canonical decode failed"))?,
        )
        .map_err(|_| EpochArchivalError::InvalidReceipt("epoch count overflow"))?;
        let mut archived_epochs = Vec::with_capacity(count);
        for _ in 0..count {
            archived_epochs.push(
                ArchivedEpochEntry::decode_canonical(&mut dec)
                    .map_err(|_| EpochArchivalError::InvalidReceipt("canonical decode failed"))?,
            );
        }
        let receipt_digest = dec
            .digest()
            .map_err(|_| EpochArchivalError::InvalidReceipt("canonical decode failed"))?;
        dec.ensure_finished()
            .map_err(|_| EpochArchivalError::InvalidReceipt("trailing bytes in receipt"))?;

        let receipt = Self {
            site_lineage,
            archived_at_ns,
            retaining_checkpoint_seq,
            retaining_checkpoint_epoch_id,
            retaining_checkpoint_history_root,
            retaining_checkpoint_state_root,
            retaining_checkpoint_sha256,
            archived_epochs,
            receipt_digest,
        };
        receipt.verify_receipt_digest()?;
        Ok(receipt)
    }

    /// Independently re-verifies every archived `.fssj` file in `archive_dir` against this receipt.
    pub fn verify_archived_files(&self, archive_dir: &Path) -> Result<(), EpochArchivalError> {
        self.verify_receipt_digest()?;
        for entry in &self.archived_epochs {
            let path = epoch_file_path(archive_dir, entry.epoch_id);
            if !path.exists() {
                return Err(EpochArchivalError::MissingEpochFile {
                    epoch_id: entry.epoch_id,
                });
            }
            let bytes = fs::read(&path)?;
            let actual = ContentDigest::sha256(&bytes);
            if actual != entry.file_sha256 {
                return Err(EpochArchivalError::ArchivedCopyDigestMismatch {
                    epoch_id: entry.epoch_id,
                    expected: entry.file_sha256,
                    actual,
                });
            }
        }
        Ok(())
    }
}

fn encode_receipt_fields(receipt: &EpochArchivalReceipt, enc: &mut CanonicalEncoder) {
    enc.text(&receipt.site_lineage);
    receipt.archived_at_ns.encode_canonical(enc);
    enc.u64(receipt.retaining_checkpoint_seq);
    enc.u64(receipt.retaining_checkpoint_epoch_id);
    enc.digest(receipt.retaining_checkpoint_history_root);
    enc.digest(receipt.retaining_checkpoint_state_root);
    enc.digest(receipt.retaining_checkpoint_sha256);
    enc.u64(receipt.archived_epochs.len() as u64);
    for entry in &receipt.archived_epochs {
        entry.encode_canonical(enc);
    }
}

fn compute_receipt_digest(
    receipt: &EpochArchivalReceipt,
) -> Result<ContentDigest, EpochArchivalError> {
    let mut enc = CanonicalEncoder::new();
    enc.text("fss.canonical.v1");
    enc.text(EPOCH_ARCHIVAL_RECEIPT_DOMAIN);
    encode_receipt_fields(receipt, &mut enc);
    let bytes = enc
        .finish_checked()
        .map_err(|err| EpochArchivalError::Ledger(EpochLedgerError::Contract(err)))?;
    Ok(ContentDigest::sha256(&bytes))
}

/// Identifies and cryptographically verifies sealed epochs strictly older than the latest verified
/// `FSSC` checkpoint, emits a canonical [`EpochArchivalReceipt`], and optionally copies/prunes them.
pub fn archive_sealed_epochs(
    ledger: &MerkleEpochLedger,
    policy: &EpochArchivalPolicy,
    archived_at_ns: TimestampNs,
) -> Result<EpochArchivalReceipt, EpochArchivalError> {
    policy.validate()?;

    let root_dir = ledger.root_dir();
    let epochs_dir = root_dir.join("epochs");
    let checkpoints_dir = root_dir.join("checkpoints");
    let site_lineage = &ledger.genesis_anchor().site_lineage;

    // 1. Independently locate and cryptographically verify the latest FSSC checkpoint on disk.
    let (cp_data, cp_sha256) =
        find_latest_verified_checkpoint(&epochs_dir, &checkpoints_dir, site_lineage)?;

    let active_epoch_id = ledger.active_epoch_id();
    let checkpoint_epoch_id = cp_data.epoch_id;
    let on_disk_ids = list_present_epoch_ids(&epochs_dir)?;

    // 2. Determine target epochs, strictly refusing active or uncheckpointed epochs.
    let target_ids = select_target_epochs(
        &on_disk_ids,
        policy,
        checkpoint_epoch_id,
        cp_data.commit_sequence,
        active_epoch_id,
    )?;

    // 3. Verify every contiguous epoch from the earliest on-disk epoch through checkpoint_epoch_id.
    let earliest_epoch = on_disk_ids
        .first()
        .copied()
        .ok_or(EpochArchivalError::MissingEpochFile { epoch_id: 0 })?;
    for expected in earliest_epoch..=checkpoint_epoch_id {
        if on_disk_ids.binary_search(&expected).is_err() {
            return Err(EpochArchivalError::MissingEpochFile { epoch_id: expected });
        }
    }

    let (mut expected_seq, mut expected_hist) = if earliest_epoch == 0 {
        (1_u64, genesis_history_root_v2(ledger.genesis_anchor())?)
    } else {
        let first_path = epoch_file_path(&epochs_dir, earliest_epoch);
        let first_bytes = fs::read(&first_path)?;
        let header = EpochHeader::decode(&first_bytes, earliest_epoch)?;
        (header.first_commit_seq, header.prev_history_root)
    };

    let mut archived_entries = Vec::with_capacity(target_ids.len());
    for epoch_id in earliest_epoch..=checkpoint_epoch_id {
        let path = epoch_file_path(&epochs_dir, epoch_id);
        let raw_bytes = fs::read(&path)?;
        let file_bytes = raw_bytes.len() as u64;
        let file_sha256 = ContentDigest::sha256(&raw_bytes);

        let scan = scan_epoch_from(
            &epochs_dir,
            epoch_id,
            EPOCH_HEADER_LEN as u64,
            expected_seq,
            expected_hist,
        )?;
        if epoch_id < active_epoch_id && scan.incomplete_tail.is_some() {
            return Err(EpochArchivalError::Ledger(EpochLedgerError::CorruptEpoch {
                epoch_id,
                offset: scan.committed_len,
                kind: EpochCorruptionKind::IncompleteTailInSealedEpoch,
            }));
        }

        let mut running_hist = scan.header.prev_history_root;
        let mut checkpoint_matched = epoch_id == checkpoint_epoch_id
            && cp_data.epoch_byte_offset == EPOCH_HEADER_LEN as u64
            && running_hist == cp_data.history_root;

        for record in &scan.records {
            let batch =
                decode_batch(&record.payload).map_err(|_| EpochLedgerError::CorruptEpoch {
                    epoch_id,
                    offset: record.start_offset,
                    kind: EpochCorruptionKind::BatchCodec,
                })?;
            let computed = batch.computed_digest();
            if batch.batch_digest != computed {
                return Err(EpochArchivalError::Ledger(
                    EpochLedgerError::BatchDigestMismatch {
                        batch_id: batch.batch_id,
                        declared: batch.batch_digest,
                        computed,
                    },
                ));
            }
            if batch.new_anchor.commit_sequence != record.commit_seq {
                return Err(EpochArchivalError::Ledger(EpochLedgerError::CorruptEpoch {
                    epoch_id,
                    offset: record.start_offset,
                    kind: EpochCorruptionKind::RecordSequence,
                }));
            }
            let recomputed = successor_history_root_v2(
                running_hist,
                record.commit_seq,
                batch.batch_digest,
                &batch.new_anchor,
            )?;
            if recomputed != record.history_root {
                return Err(EpochArchivalError::HistoryChainBroken {
                    epoch_id,
                    expected: recomputed,
                    observed: record.history_root,
                });
            }
            running_hist = recomputed;
            if epoch_id == checkpoint_epoch_id && record.end_offset == cp_data.epoch_byte_offset {
                if running_hist != cp_data.history_root {
                    return Err(EpochArchivalError::HistoryChainBroken {
                        epoch_id,
                        expected: cp_data.history_root,
                        observed: running_hist,
                    });
                }
                checkpoint_matched = true;
            }
        }

        if epoch_id == checkpoint_epoch_id && !checkpoint_matched {
            return Err(EpochArchivalError::HistoryChainBroken {
                epoch_id,
                expected: cp_data.history_root,
                observed: running_hist,
            });
        }

        let batch_count = scan.records.len() as u64;
        let last_commit_seq = scan
            .records
            .last()
            .map_or(scan.header.first_commit_seq.saturating_sub(1), |r| {
                r.commit_seq
            });

        if target_ids.binary_search(&epoch_id).is_ok() {
            archived_entries.push(ArchivedEpochEntry {
                epoch_id,
                first_commit_seq: scan.header.first_commit_seq,
                last_commit_seq,
                batch_count,
                prev_history_root: scan.header.prev_history_root,
                end_history_root: running_hist,
                file_bytes,
                file_sha256,
                pruned_locally: policy.prune_local_epochs,
            });
        }

        expected_hist = running_hist;
        expected_seq = last_commit_seq
            .checked_add(1)
            .ok_or(EpochLedgerError::SequenceExhausted)?;
    }

    // 4. Atomically copy verified epochs to archive_dir (if configured) and verify each copy's SHA-256.
    if let Some(archive_dir) = &policy.archive_dir {
        fs::create_dir_all(archive_dir)?;
        for entry in &archived_entries {
            let src_path = epoch_file_path(&epochs_dir, entry.epoch_id);
            let dst_path = epoch_file_path(archive_dir, entry.epoch_id);
            let tmp_path = archive_dir.join(format!(".{:016}.fssj.tmp", entry.epoch_id));
            let bytes = fs::read(&src_path)?;
            {
                let mut f = OpenOptions::new()
                    .create(true)
                    .write(true)
                    .truncate(true)
                    .open(&tmp_path)?;
                f.write_all(&bytes)?;
                f.sync_all()?;
            }
            fs::rename(&tmp_path, &dst_path)?;
            sync_directory(archive_dir)?;
            let verified_copy_sha = ContentDigest::sha256(&fs::read(&dst_path)?);
            if verified_copy_sha != entry.file_sha256 {
                return Err(EpochArchivalError::ArchivedCopyDigestMismatch {
                    epoch_id: entry.epoch_id,
                    expected: entry.file_sha256,
                    actual: verified_copy_sha,
                });
            }
        }
    }

    let mut receipt = EpochArchivalReceipt {
        site_lineage: site_lineage.clone(),
        archived_at_ns,
        retaining_checkpoint_seq: cp_data.commit_sequence,
        retaining_checkpoint_epoch_id: checkpoint_epoch_id,
        retaining_checkpoint_history_root: cp_data.history_root,
        retaining_checkpoint_state_root: cp_data.merkle_state_root,
        retaining_checkpoint_sha256: cp_sha256,
        archived_epochs: archived_entries,
        receipt_digest: ContentDigest::new(DigestAlgorithm::Sha256, [0_u8; 32]),
    };
    receipt.receipt_digest = compute_receipt_digest(&receipt)?;

    // 5. Persist canonical archival receipt atomically BEFORE pruning any local epoch file.
    if let Some(archive_dir) = &policy.archive_dir {
        let receipt_bytes = receipt.encode_canonical_file()?;
        let final_receipt = archive_dir.join(format!(
            "archival-receipt-seq-{:020}.fssa",
            receipt.retaining_checkpoint_seq
        ));
        let tmp_receipt = archive_dir.join(format!(
            ".archival-receipt-seq-{:020}.fssa.tmp",
            receipt.retaining_checkpoint_seq
        ));
        {
            let mut f = OpenOptions::new()
                .create(true)
                .write(true)
                .truncate(true)
                .open(&tmp_receipt)?;
            f.write_all(&receipt_bytes)?;
            f.sync_all()?;
        }
        fs::rename(&tmp_receipt, &final_receipt)?;
        sync_directory(archive_dir)?;
    }

    // 6. Optionally prune ONLY the verified archived epochs strictly older than the checkpoint.
    if policy.prune_local_epochs {
        for entry in &receipt.archived_epochs {
            let local_path = epoch_file_path(&epochs_dir, entry.epoch_id);
            if local_path.exists() {
                fs::remove_file(&local_path)?;
            }
        }
        sync_directory(&epochs_dir)?;
    }

    Ok(receipt)
}

fn find_latest_verified_checkpoint(
    epochs_dir: &Path,
    checkpoints_dir: &Path,
    site_lineage: &str,
) -> Result<(super::CheckpointData, ContentDigest), EpochArchivalError> {
    for (seq, path) in list_checkpoint_files_desc(checkpoints_dir)? {
        if let Ok((data, _)) = read_and_verify_checkpoint(&path, Some(seq), site_lineage, true)
            && verify_checkpoint_epoch_anchor(
                epochs_dir,
                data.epoch_id,
                data.epoch_byte_offset,
                data.history_root,
            )
            .is_ok()
        {
            let cp_sha = ContentDigest::sha256(&fs::read(&path)?);
            return Ok((data, cp_sha));
        }
    }
    Err(EpochArchivalError::NoVerifiedCheckpoint)
}

fn list_present_epoch_ids(epochs_dir: &Path) -> Result<Vec<u64>, EpochArchivalError> {
    if !epochs_dir.exists() {
        return Ok(Vec::new());
    }
    let mut ids = Vec::new();
    for entry in fs::read_dir(epochs_dir)? {
        let entry = entry?;
        let name = entry.file_name();
        let Some(s) = name.to_str() else {
            continue;
        };
        if s.starts_with('.') {
            continue;
        }
        if let Some(stem) = s.strip_suffix(".fssj")
            && stem.len() == 16
            && stem.bytes().all(|b| b.is_ascii_digit())
            && let Ok(id) = stem.parse::<u64>()
        {
            ids.push(id);
        }
    }
    ids.sort_unstable();
    Ok(ids)
}

fn select_target_epochs(
    on_disk_ids: &[u64],
    policy: &EpochArchivalPolicy,
    checkpoint_epoch_id: u64,
    checkpoint_commit_seq: u64,
    active_epoch_id: u64,
) -> Result<Vec<u64>, EpochArchivalError> {
    if let Some(requested) = &policy.requested_epochs {
        let mut sorted = requested.clone();
        sorted.sort_unstable();
        sorted.dedup();
        if sorted.is_empty() {
            return Err(EpochArchivalError::NoEligibleEpochs {
                checkpoint_epoch_id,
                active_epoch_id,
            });
        }
        for &eid in &sorted {
            if eid >= active_epoch_id {
                return Err(EpochArchivalError::ActiveEpochNotArchivable {
                    epoch_id: eid,
                    active_epoch_id,
                });
            }
            if eid >= checkpoint_epoch_id {
                return Err(EpochArchivalError::EpochNotCoveredByCheckpoint {
                    epoch_id: eid,
                    checkpoint_epoch_id,
                    checkpoint_commit_seq,
                });
            }
            if on_disk_ids.binary_search(&eid).is_err() {
                return Err(EpochArchivalError::MissingEpochFile { epoch_id: eid });
            }
        }
        return Ok(sorted);
    }

    let cutoff = checkpoint_epoch_id.saturating_sub(policy.retain_recent_sealed_epochs);
    let eligible: Vec<u64> = on_disk_ids
        .iter()
        .copied()
        .filter(|&eid| eid < active_epoch_id && eid < cutoff)
        .collect();
    if eligible.is_empty() {
        return Err(EpochArchivalError::NoEligibleEpochs {
            checkpoint_epoch_id,
            active_epoch_id,
        });
    }
    Ok(eligible)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::epochs::{EpochLedgerConfig, checkpoint_file_path};
    use crate::journal::IncompleteTailPolicy;
    use fss_core::{BatchId, CaptureInterval, EvidenceDelta, ObjectId, Plane};

    type TestResult = Result<(), Box<dyn Error>>;
    const SITE: &str = "site:epoch-archive-unit";

    fn fresh_dir(label: &str) -> Result<PathBuf, Box<dyn Error>> {
        let dir = std::env::temp_dir()
            .join(format!("fss-ledger-archive-{}", std::process::id()))
            .join(label);
        if dir.exists() {
            fs::remove_dir_all(&dir)?;
        }
        fs::create_dir_all(&dir)?;
        Ok(dir)
    }

    fn append_obj(ledger: &mut MerkleEpochLedger, idx: u64) -> Result<(), Box<dyn Error>> {
        let start = i128::from(idx) * 1_000;
        let delta = EvidenceDelta {
            delta_id: format!("delta:arch:{idx}"),
            family: "sensor_capsule".to_owned(),
            object_id: ObjectId::parse(format!("object:arch-{idx}"))?,
            prior_generation: None,
            new_generation: 1,
            validity: CaptureInterval::new(TimestampNs(start), TimestampNs(start + 100))?,
            plane: Plane::Authority,
            payload_digest: ContentDigest::sha256(format!("arch-payload:{idx}").as_bytes()),
            witness_digest: None,
            operation_id: None,
        };
        let batch = ledger.prepare_batch(
            BatchId::parse(format!("batch:arch:{idx}"))?,
            vec![delta],
            [],
        )?;
        let _ = ledger.append_batch(batch)?;
        Ok(())
    }

    #[test]
    fn archives_verified_sealed_epochs_before_checkpoint_and_prunes_safely() -> TestResult {
        let dir = fresh_dir("archive-verified")?;
        let archive_dir = dir.join("cold-archive");
        let cfg = EpochLedgerConfig {
            max_epoch_bytes: 64 * 1024 * 1024,
            max_batches_per_epoch: 3,
            checkpoint_stride: 100,
            max_objects: None,
        };
        let mut ledger = MerkleEpochLedger::open(&dir, SITE, cfg, IncompleteTailPolicy::Reject)?;
        // 10 commits -> epochs 0 (1..=3), 1 (4..=6), 2 (7..=9, checkpoint seq 9), 3 (10, active).
        for i in 1..=10_u64 {
            append_obj(&mut ledger, i)?;
        }
        assert_eq!(ledger.active_epoch_id(), 3);

        let policy = EpochArchivalPolicy {
            retain_recent_sealed_epochs: 0,
            archive_dir: Some(archive_dir.clone()),
            prune_local_epochs: true,
            requested_epochs: None,
        };
        let receipt = archive_sealed_epochs(&ledger, &policy, TimestampNs(50_000))?;
        receipt.verify_receipt_digest()?;
        receipt.verify_archived_files(&archive_dir)?;

        // Epochs 0 and 1 archived; epoch 2 (checkpoint anchor) and epoch 3 (active) retained!
        assert_eq!(receipt.retaining_checkpoint_seq, 9);
        assert_eq!(receipt.retaining_checkpoint_epoch_id, 2);
        assert_eq!(receipt.archived_epochs.len(), 2);
        assert_eq!(receipt.archived_epochs[0].epoch_id, 0);
        assert_eq!(receipt.archived_epochs[0].first_commit_seq, 1);
        assert_eq!(receipt.archived_epochs[0].last_commit_seq, 3);
        assert_eq!(receipt.archived_epochs[1].epoch_id, 1);
        assert_eq!(receipt.archived_epochs[1].first_commit_seq, 4);
        assert_eq!(receipt.archived_epochs[1].last_commit_seq, 6);
        assert_eq!(
            receipt.archived_epochs[0].end_history_root,
            receipt.archived_epochs[1].prev_history_root
        );

        // Local pruning removed 0 and 1 while preserving epoch 2, active epoch 3, and FSSC checkpoint!
        assert!(!epoch_file_path(&dir.join("epochs"), 0).exists());
        assert!(!epoch_file_path(&dir.join("epochs"), 1).exists());
        assert!(epoch_file_path(&dir.join("epochs"), 2).exists());
        assert!(epoch_file_path(&dir.join("epochs"), 3).exists());
        assert!(checkpoint_file_path(&dir.join("checkpoints"), 9).exists());

        // Persisted FSSA receipt round-trips and verifies identically.
        let receipt_path = archive_dir.join("archival-receipt-seq-00000000000000000009.fssa");
        let decoded = EpochArchivalReceipt::decode_canonical_file(&fs::read(&receipt_path)?)?;
        assert_eq!(decoded, receipt);
        Ok(())
    }

    #[test]
    fn refuses_active_uncheckpointed_and_tampered_epochs() -> TestResult {
        let dir = fresh_dir("archive-refusals")?;
        let cfg = EpochLedgerConfig {
            max_epoch_bytes: 64 * 1024 * 1024,
            max_batches_per_epoch: 3,
            checkpoint_stride: 100,
            max_objects: None,
        };
        let mut ledger = MerkleEpochLedger::open(&dir, SITE, cfg, IncompleteTailPolicy::Reject)?;
        append_obj(&mut ledger, 1)?;
        append_obj(&mut ledger, 2)?;

        // Before any checkpoint exists -> refuses with NoVerifiedCheckpoint.
        let err_no_cp =
            archive_sealed_epochs(&ledger, &EpochArchivalPolicy::default(), TimestampNs(1));
        assert!(matches!(
            err_no_cp,
            Err(EpochArchivalError::NoVerifiedCheckpoint)
        ));

        // Advance through 10 commits -> active epoch 3, latest checkpoint on epoch 2 (seq 9).
        for i in 3..=10_u64 {
            append_obj(&mut ledger, i)?;
        }

        // Refuses archiving active epoch 3.
        let active_policy = EpochArchivalPolicy {
            requested_epochs: Some(vec![3]),
            ..EpochArchivalPolicy::default()
        };
        assert!(matches!(
            archive_sealed_epochs(&ledger, &active_policy, TimestampNs(2)),
            Err(EpochArchivalError::ActiveEpochNotArchivable {
                epoch_id: 3,
                active_epoch_id: 3
            })
        ));

        // Refuses archiving checkpoint anchor epoch 2 (not strictly older than checkpoint!).
        let cp_epoch_policy = EpochArchivalPolicy {
            requested_epochs: Some(vec![2]),
            ..EpochArchivalPolicy::default()
        };
        assert!(matches!(
            archive_sealed_epochs(&ledger, &cp_epoch_policy, TimestampNs(3)),
            Err(EpochArchivalError::EpochNotCoveredByCheckpoint {
                epoch_id: 2,
                checkpoint_epoch_id: 2,
                checkpoint_commit_seq: 9
            })
        ));

        // Refuses prune_local_epochs without archive_dir.
        let bad_prune = EpochArchivalPolicy {
            prune_local_epochs: true,
            archive_dir: None,
            ..EpochArchivalPolicy::default()
        };
        assert!(matches!(
            archive_sealed_epochs(&ledger, &bad_prune, TimestampNs(4)),
            Err(EpochArchivalError::InvalidPolicy(_))
        ));

        // Flip 1 byte inside sealed epoch 0 -> refuses archival on corruption!
        let epoch0_path = epoch_file_path(&dir.join("epochs"), 0);
        let mut raw = fs::read(&epoch0_path)?;
        raw[EPOCH_HEADER_LEN + 62] ^= 0xAA;
        fs::write(&epoch0_path, &raw)?;

        let tamper_res =
            archive_sealed_epochs(&ledger, &EpochArchivalPolicy::default(), TimestampNs(5));
        assert!(matches!(
            tamper_res,
            Err(EpochArchivalError::Ledger(EpochLedgerError::CorruptEpoch {
                epoch_id: 0,
                ..
            }))
        ));
        Ok(())
    }
}
