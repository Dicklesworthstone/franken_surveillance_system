#![forbid(unsafe_code)]
//! Canonical deletion denial at original-RTP read and publication boundaries.
//!
//! Recovery charges proof reads to its existing caller allowance. Compatibility readback
//! and publication use a separate, fixed 512 MiB proof allowance. A failed proof is never
//! absence of a deletion. These helpers neither delete nor resurrect retained objects.

use super::import::RtpImportError;
use crate::deletion::{DeletionError, DeletionIndex, MAX_DELETION_RECORD_BYTES, has_records};
use crate::{ReferenceDeployment, ReplayCx};
use fss_core::ContentDigest;

type Result<T> = std::result::Result<T, RtpImportError>;

impl From<DeletionError> for RtpImportError {
    fn from(error: DeletionError) -> Self {
        match error {
            DeletionError::Cancelled { .. } => Self::Cancelled,
            _ => Self::DeletionAuthority,
        }
    }
}

pub(super) fn read_index_with(
    deployment: &ReferenceDeployment,
    read: impl FnMut(ContentDigest) -> Result<Vec<u8>>,
) -> Result<DeletionIndex> {
    let batches = deployment.ledger().batches();
    if !has_records(batches) {
        return Ok(DeletionIndex::default());
    }
    DeletionIndex::from_batches(batches, read)
}

pub(super) fn read_index(deployment: &ReferenceDeployment, cx: &ReplayCx) -> Result<DeletionIndex> {
    let mut remaining = 512_u64 * 1024 * 1024;
    read_index_with(deployment, |digest| {
        cx.checkpoint("rtpdump:deletion_authority")
            .map_err(|_| RtpImportError::Cancelled)?;
        let reservation = MAX_DELETION_RECORD_BYTES as u64;
        remaining = remaining
            .checked_sub(reservation)
            .ok_or(RtpImportError::Limit)?;
        let bytes = deployment
            .publisher()
            .spool()
            .read_bounded(digest, MAX_DELETION_RECORD_BYTES)
            .map_err(|_| RtpImportError::DeletionAuthority)?;
        remaining += reservation - bytes.len() as u64;
        Ok(bytes)
    })
}

pub(super) fn refuse_deleted(
    index: &DeletionIndex,
    root: ContentDigest,
    object: ContentDigest,
) -> Result<()> {
    if let Some(entry) = index.import(root).or_else(|| index.object(object)) {
        return Err(RtpImportError::EvidenceDeleted {
            root,
            plan: entry.plan_digest,
        });
    }
    Ok(())
}
