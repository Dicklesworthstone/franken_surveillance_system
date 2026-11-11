#![forbid(unsafe_code)]
//! Recorder UTC queries over current retained custody after the source archive is unavailable.

use fss_core::ContentDigest;
use fss_publication::{PublishCancellation, PublishCutPoint};

use crate::ingest::{FileIngestError, RetainedFileImport, RetainedReadLimits};
use crate::rtsp::recording::local::RecordingIoError;
use crate::rtsp::recording_replay::time::{
    ReplayTimeError, ReplayTimeQuery, ReplayTimeReport, query_with_originals,
};
use crate::rtsp::recording_replay::{MAX_REPLAY_RECEIPT_BYTES, ReplayReceiptError};
use crate::{ReferenceDeployment, ReplayCx};

use super::{ADAPTER, GENERATION, MAX_PROOF_BYTES, corrupt, provenance};

/// Whole-query refusal. No partial rows survive a custody, limit or cancellation failure.
#[derive(Debug)]
pub enum RetainedReplayTimeError {
    /// Existing independent recorder-query pins, native projection or limit refusal.
    Query(ReplayTimeError),
    /// Current retained completion, origin proof, original bytes or deletion state failed.
    Custody(FileIngestError),
}
impl RetainedReplayTimeError {
    /// Existing stable recorder-time error identity, without source bytes or private paths.
    #[must_use]
    pub fn code(&self) -> &'static str {
        match self {
            Self::Query(error) => error.code(),
            Self::Custody(FileIngestError::CancellationRequested { .. }) => {
                "ERR-REPLAY-TIME-CANCELLED-001"
            }
            Self::Custody(_) => "ERR-REPLAY-TIME-CUSTODY-001",
        }
    }
}
impl std::fmt::Display for RetainedReplayTimeError {
    fn fmt(&self, out: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        out.write_str(self.code())
    }
}
impl std::error::Error for RetainedReplayTimeError {}
impl From<ReplayTimeError> for RetainedReplayTimeError {
    fn from(error: ReplayTimeError) -> Self {
        Self::Query(error)
    }
}
impl From<ReplayReceiptError> for RetainedReplayTimeError {
    fn from(error: ReplayReceiptError) -> Self {
        Self::Query(error.into())
    }
}
impl From<FileIngestError> for RetainedReplayTimeError {
    fn from(error: FileIngestError) -> Self {
        Self::Custody(error)
    }
}

struct Access<'a> {
    cx: &'a ReplayCx,
    cancel: &'a dyn PublishCancellation,
}
impl PublishCancellation for Access<'_> {
    fn cancel_requested(&self, at: PublishCutPoint) -> bool {
        self.cancel.cancel_requested(at) || super::checkpoint(self.cx).is_err()
    }
}
impl Access<'_> {
    fn check(&self) -> Result<(), RetainedReplayTimeError> {
        if self.cancel_requested(PublishCutPoint::AfterChildrenVerified) {
            return Err(ReplayReceiptError::Storage(RecordingIoError::Cancelled).into());
        }
        Ok(())
    }
}

/// Query exact recorder UTC assertions from a completed whole-receipt retained import.
///
/// The caller independently supplies the original codec, scope, receipt/request pins, NTP era,
/// half-open UTC interval and query limits. The current import identity supplies destination
/// completion authority; it does not select any missing query pin. Every original is replayed
/// through the same native codec and packet-association owners as [`query_replay_time`]. The
/// resulting rows, index and report digests are identical for identical original custody.
///
/// Query source limits reserve 32 MiB per window before any original reads. Proof reads have
/// their separate fixed 4 MiB ceiling; companion readbacks are each bounded by 64 KiB. All
/// reads check cancellation, and current completion/root/deletion state is rechecked before
/// return. No archive lock, fabricated native slot, network request, publication or decode is
/// needed. Recorder assertions remain distinct from calibrated capture time and coverage.
///
/// [`query_replay_time`]: crate::rtsp::recording_replay::time::query_replay_time
pub fn query_retained_replay_time(
    deployment: &ReferenceDeployment,
    import_identity: ContentDigest,
    query: &ReplayTimeQuery,
    limits: RetainedReadLimits,
    cx: &ReplayCx,
    cancel: &dyn PublishCancellation,
) -> Result<ReplayTimeReport, RetainedReplayTimeError> {
    query.validate()?;
    let access = Access { cx, cancel };
    access.check()?;
    if cx.root_dir() != deployment.root() {
        return Err(corrupt("retained replay query requires destination authority").into());
    }
    let retained = RetainedFileImport::open(deployment, import_identity, limits, cx)?;
    if retained.manifest().adapter_id != ADAPTER {
        return Err(ReplayTimeError::Scope.into());
    }
    let suffix = retained
        .manifest()
        .adapter_generation
        .strip_prefix(GENERATION)
        .ok_or_else(|| corrupt("retained replay query origin generation"))?;
    let proof_digest =
        ContentDigest::parse(&format!("sha256:{suffix}")).map_err(FileIngestError::from)?;
    let mut remaining = query
        .limits
        .max_source_bytes
        .checked_add(MAX_PROOF_BYTES as u64 + 2 * MAX_REPLAY_RECEIPT_BYTES as u64)
        .ok_or(ReplayTimeError::Limit)?;
    let mut reserve = |bytes: u64| -> Result<(), FileIngestError> {
        if access.cancel_requested(PublishCutPoint::AfterChildrenVerified) {
            return Err(FileIngestError::CancellationRequested {
                stage: "rtsp_replay_time:retained_original",
            });
        }
        remaining = remaining
            .checked_sub(bytes)
            .ok_or_else(|| corrupt("retained replay query read allowance"))?;
        Ok(())
    };
    let proof = provenance::proof(deployment, proof_digest, cx, &mut reserve)?;
    let receipt = proof.receipt()?;
    if receipt.root() != query.receipt_root
        || receipt.request().digest() != query.request
        || receipt.request().codec() != query.codec
        || receipt.scope() != &query.scope
    {
        return Err(ReplayTimeError::Scope.into());
    }
    let report = query_with_originals(query, &access, |visitor| {
        proof.visit_originals(deployment, cx, visitor, &mut reserve)
    })?;
    access.check()?;
    if RetainedFileImport::open(deployment, import_identity, limits, cx)? != retained {
        return Err(corrupt("retained replay query authority changed").into());
    }
    access.check()?;
    Ok(report)
}
