#![forbid(unsafe_code)]
//! Bounded receipt proofs joining an exact retained batch to the verified current history head.
//!
//! The starting epoch's previous history root is not accepted as authority by itself. Every
//! intervening canonical batch and history link must reach the owner's already verified head.
//! This proves inclusion in that history without inferring old state from current objects or
//! replaying the entire deployment from genesis.

use std::fs::File;
use std::io::{ErrorKind, Read};
use std::path::Path;

use fss_core::{ContentDigest, EvidenceDeltaBatch, LedgerAnchor};

use crate::batch_codec::{decode_batch, encode_batch};
use crate::oracle::CommitReceipt;

use super::segment::{
    EPOCH_HEADER_LEN, EpochHeader, epoch_file_path, scan_epoch_from_budgeted,
};
use super::validate::{check_counts, check_deltas, check_successor, check_texts};
use super::{EpochCorruptionKind, EpochLedgerError, successor_history_root_v2};

/// Explicit cumulative work limits for exact historical receipt verification.
///
/// Zero limits refuse historical proofs while preserving the cached exact-head fast path.
/// A budget exhaustion is a refusal, never evidence that the offered batch did not commit.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReceiptProofBudget {
    /// Maximum distinct epoch files inspected, including backward header probes.
    pub max_epochs: u64,
    /// Maximum records examined, including records before the target in its starting epoch.
    pub max_records: u64,
    /// Maximum cumulative bytes read, including every header probe and repeated header read.
    pub max_bytes: u64,
}

impl Default for ReceiptProofBudget {
    fn default() -> Self {
        Self {
            max_epochs: 16,
            max_records: 32_768,
            max_bytes: 128 * 1024 * 1024,
        }
    }
}

/// Resource whose exact receipt proof exhausted its explicit allowance.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReceiptProofResource {
    /// Distinct epoch files inspected.
    Epochs,
    /// Framed records examined.
    Records,
    /// Cumulative bytes read from epoch files.
    Bytes,
}

/// Actual bounded work performed by a successful receipt proof.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ReceiptProofUsage {
    /// Distinct epoch files inspected, including their locator headers.
    pub epochs_scanned: u64,
    /// Records verified, including the starting epoch's pre-target prefix.
    pub records_verified: u64,
    /// Bytes read, including locator headers and headers reread by the scanner.
    pub bytes_read: u64,
}

/// An original receipt proven to belong to this exact verified current history.
///
/// The current-head fields let callers require a matching materialized projection while
/// returning an older immutable receipt. This proves canonical publication, not continued
/// custody of referenced payloads or completion of an external device effect.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedBatchReceipt {
    /// Exact receipt at the offered batch's original commit sequence.
    pub receipt: CommitReceipt,
    /// Complete current native ledger head to which the proof is anchored.
    pub head_anchor: LedgerAnchor,
    /// Verified append-only history root at that current head.
    pub head_history_root: ContentDigest,
    /// Digest of the final canonical batch at that current head.
    pub head_batch_digest: ContentDigest,
    /// Work charged to this verification; all zero for the cached exact-head fast path.
    pub usage: ReceiptProofUsage,
}

pub(super) struct ReceiptProofMeter {
    budget: ReceiptProofBudget,
    pub(super) usage: ReceiptProofUsage,
}

impl ReceiptProofMeter {
    fn new(budget: ReceiptProofBudget) -> Self {
        Self {
            budget,
            usage: ReceiptProofUsage::default(),
        }
    }

    fn charge_epoch(&mut self) -> Result<(), EpochLedgerError> {
        charge(
            &mut self.usage.epochs_scanned,
            1,
            self.budget.max_epochs,
            ReceiptProofResource::Epochs,
        )
    }

    pub(super) fn charge_records(&mut self, count: u64) -> Result<(), EpochLedgerError> {
        charge(
            &mut self.usage.records_verified,
            count,
            self.budget.max_records,
            ReceiptProofResource::Records,
        )
    }

    pub(super) fn charge_bytes(&mut self, count: u64) -> Result<(), EpochLedgerError> {
        charge(
            &mut self.usage.bytes_read,
            count,
            self.budget.max_bytes,
            ReceiptProofResource::Bytes,
        )
    }
}

fn charge(
    used: &mut u64,
    requested: u64,
    maximum: u64,
    resource: ReceiptProofResource,
) -> Result<(), EpochLedgerError> {
    let next = used
        .checked_add(requested)
        .filter(|next| *next <= maximum)
        .ok_or(EpochLedgerError::ReceiptProofLimitExceeded {
            resource,
            used: *used,
            requested,
            maximum,
        })?;
    *used = next;
    Ok(())
}

fn read_locator_header(
    epochs_dir: &Path,
    epoch_id: u64,
    meter: &mut ReceiptProofMeter,
) -> Result<EpochHeader, EpochLedgerError> {
    meter.charge_epoch()?;
    meter.charge_bytes(EPOCH_HEADER_LEN as u64)?;
    let mut file = File::open(epoch_file_path(epochs_dir, epoch_id)).map_err(|error| {
        if error.kind() == ErrorKind::NotFound {
            EpochLedgerError::MissingEpoch {
                expected_epoch_id: epoch_id,
            }
        } else {
            error.into()
        }
    })?;
    let mut bytes = [0_u8; EPOCH_HEADER_LEN];
    file.read_exact(&mut bytes).map_err(|error| {
        if error.kind() == ErrorKind::UnexpectedEof {
            EpochLedgerError::CorruptEpoch {
                epoch_id,
                offset: 0,
                kind: EpochCorruptionKind::TruncatedHeader,
            }
        } else {
            error.into()
        }
    })?;
    let header = EpochHeader::decode(&bytes, epoch_id)?;
    if header.first_commit_seq == 0 {
        return Err(EpochLedgerError::CorruptEpoch {
            epoch_id,
            offset: 0,
            kind: EpochCorruptionKind::FirstCommitSeqMismatch,
        });
    }
    Ok(header)
}

/// The owner has already checked the original batch against its immutable batch index.
pub(super) fn verify_receipt_from_epochs(
    epochs_dir: &Path,
    offered: &EvidenceDeltaBatch,
    active_epoch_id: u64,
    head_anchor: &LedgerAnchor,
    head_history_root: ContentDigest,
    budget: ReceiptProofBudget,
) -> Result<VerifiedBatchReceipt, EpochLedgerError> {
    let mut meter = ReceiptProofMeter::new(budget);
    let target_sequence = offered.new_anchor.commit_sequence;
    let mut first_epoch_id = active_epoch_id;
    let first_header = loop {
        let header = read_locator_header(epochs_dir, first_epoch_id, &mut meter)?;
        if header.first_commit_seq <= target_sequence {
            break header;
        }
        first_epoch_id = first_epoch_id.checked_sub(1).ok_or(
            EpochLedgerError::LiveStateDivergence("indexed receipt precedes retained epoch history"),
        )?;
    };

    let expected_payload = encode_batch(offered)?;
    let mut next_sequence = first_header.first_commit_seq;
    let mut history_root = first_header.prev_history_root;
    let mut previous_anchor: Option<LedgerAnchor> = None;
    let mut head_batch_digest = None;
    let mut receipt = None;

    for epoch_id in first_epoch_id..=active_epoch_id {
        let report = scan_epoch_from_budgeted(
            epochs_dir,
            epoch_id,
            EPOCH_HEADER_LEN as u64,
            next_sequence,
            history_root,
            &mut meter,
        )?;
        if let Some(offset) = report.incomplete_tail {
            return Err(EpochLedgerError::IncompleteTail { epoch_id, offset });
        }
        for record in report.records {
            let batch =
                decode_batch(&record.payload).map_err(|_| EpochLedgerError::CorruptEpoch {
                    epoch_id,
                    offset: record.start_offset,
                    kind: EpochCorruptionKind::BatchCodec,
                })?;
            check_counts(batch.deltas.len(), batch.children.len())?;
            check_texts(&batch.deltas, &batch.basis_anchor, &batch.new_anchor)?;
            check_deltas(&batch.deltas)?;
            if !batch.is_canonically_ordered() {
                return Err(EpochLedgerError::NonCanonicalOrdering {
                    batch_id: batch.batch_id,
                });
            }
            let computed = batch.computed_digest();
            if computed != batch.batch_digest {
                return Err(EpochLedgerError::BatchDigestMismatch {
                    batch_id: batch.batch_id,
                    declared: batch.batch_digest,
                    computed,
                });
            }
            if batch.basis_anchor.commit_sequence.checked_add(1) != Some(record.commit_seq) {
                return Err(EpochLedgerError::CorruptEpoch {
                    epoch_id,
                    offset: record.start_offset,
                    kind: EpochCorruptionKind::RecordSequence,
                });
            }
            check_successor(&batch.basis_anchor, &batch.new_anchor, record.commit_seq)?;
            if previous_anchor
                .as_ref()
                .is_some_and(|previous| previous != &batch.basis_anchor)
            {
                return Err(EpochLedgerError::BasisForked {
                    basis_sequence: batch.basis_anchor.commit_sequence,
                });
            }
            let next_history = successor_history_root_v2(
                history_root,
                record.commit_seq,
                batch.batch_digest,
                &batch.new_anchor,
            )?;
            if next_history != record.history_root {
                return Err(EpochLedgerError::CorruptEpoch {
                    epoch_id,
                    offset: record.start_offset,
                    kind: EpochCorruptionKind::HistoryRootMismatch,
                });
            }
            if record.commit_seq == target_sequence {
                if record.payload != expected_payload || &batch != offered {
                    return Err(EpochLedgerError::LiveStateDivergence(
                        "indexed receipt differs from the exact retained batch bytes",
                    ));
                }
                receipt = Some(CommitReceipt {
                    sequence: record.commit_seq,
                    batch_id: batch.batch_id.clone(),
                    batch_digest: batch.batch_digest,
                    anchor: batch.new_anchor.clone(),
                    history_root: next_history,
                });
            }
            next_sequence = record
                .commit_seq
                .checked_add(1)
                .ok_or(EpochLedgerError::SequenceExhausted)?;
            history_root = next_history;
            previous_anchor = Some(batch.new_anchor);
            head_batch_digest = Some(batch.batch_digest);
        }
    }

    // A self-consistent epoch suffix is not enough: its entire endpoint must equal the
    // already verified live owner. This binds the initially untrusted prefix root and
    // every historical receipt to this history, including forks with identical state roots.
    if previous_anchor.as_ref() != Some(head_anchor) || history_root != head_history_root {
        return Err(EpochLedgerError::LiveStateDivergence(
            "receipt proof does not reach the verified current history head",
        ));
    }
    let receipt = receipt.ok_or(EpochLedgerError::LiveStateDivergence(
        "indexed receipt is absent from its retained epoch history",
    ))?;
    let head_batch_digest = head_batch_digest.ok_or(EpochLedgerError::LiveStateDivergence(
        "receipt proof has no current canonical batch",
    ))?;
    Ok(VerifiedBatchReceipt {
        receipt,
        head_anchor: head_anchor.clone(),
        head_history_root,
        head_batch_digest,
        usage: meter.usage,
    })
}
