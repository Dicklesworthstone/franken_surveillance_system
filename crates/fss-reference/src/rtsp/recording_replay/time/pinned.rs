#![forbid(unsafe_code)]
//! Native recorder-time queries through explicitly supplied read-only I/O.
//!
//! Receipt admission precedes original payload reads. Native codec verification and the
//! existing source projection are unchanged. One metadata observation spans the receipt
//! and every original root/index, including final exact-slot and deletion-marker checks.
//! Each source closure is independently rehashed before projection. These checks detect
//! observed changes; they do not provide an atomic filesystem snapshot or a future lease.

use std::fmt;
use std::path::Path;

use fss_core::CanonicalEncode;
use fss_object::{ObjectManifest, SpoolIo};
use fss_publication::custody_audit::pinned_closure::{
    PinnedClosureError, PinnedClosureReader, PinnedClosureUsage,
};
use fss_publication::custody_audit::pinned_metadata::{
    MetadataReadUsage, PinnedMetadataError, PinnedMetadataReader,
};
use fss_publication::custody_audit::{
    CustodyAuditError, CustodyAuditLimits, MAX_AUDIT_IO_CALLS, MAX_AUDIT_READ_BYTES,
};
use fss_publication::{PublishCancellation, PublishCutPoint};

use super::super::{
    MAX_REPLAY_RECEIPT_BYTES, MAX_REPLAY_WINDOWS, ReplayCodec, ReplayReceiptError,
    ReplayWindowProof, codec_replay_slot, storage::VerifiedOriginal, wire,
};
use super::{ReplayTimeError, ReplayTimeQuery, ReplayTimeReport, query_with_originals};
use crate::rtsp::recording::hevc::local::load_pinned_hevc_recording;
use crate::rtsp::recording::local::RecordingIoError;
use crate::rtsp::recording::pinned::load_pinned_recording;
use crate::rtsp::recording::{MAX_RECORDING_BYTES, RecordingError};

const MAX_METADATA_OBJECT_BYTES: usize = 2 * 1024 * 1024;
const MAX_REPLAY_ROOT_BYTES: usize = 16 * 1024;

/// Separate nonrefillable allowances for metadata and native original verification.
///
/// All file reads, envelope overhead, absent-marker probes and final revalidation are
/// metered by the supplied readers. Zero refuses the first corresponding work. Roots,
/// objects and edges cannot exceed the exact maximum receipt closure; no scan occurs.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReplayTimeReadLimits {
    /// Receipt plus every selected original root/index, retained for final revalidation.
    /// At most 65 roots, 130 metadata objects, 577 edges and 2 MiB per object.
    pub metadata: CustodyAuditLimits,
    /// Native flat closures, cumulatively charged across every selected original.
    /// At most 64 roots, 320 objects, 256 edges and 32 MiB per object.
    pub originals: CustodyAuditLimits,
}

impl Default for ReplayTimeReadLimits {
    fn default() -> Self {
        Self {
            metadata: CustodyAuditLimits {
                max_catalogue_entries: MAX_REPLAY_WINDOWS + 1,
                max_objects: (MAX_REPLAY_WINDOWS + 1) * 2,
                max_edges: MAX_REPLAY_WINDOWS * 9 + 1,
                max_object_bytes: MAX_METADATA_OBJECT_BYTES,
                max_read_bytes: 64 * 1024 * 1024,
                max_io_calls: 100_000,
            },
            originals: CustodyAuditLimits {
                max_catalogue_entries: MAX_REPLAY_WINDOWS,
                max_objects: MAX_REPLAY_WINDOWS * 5,
                max_edges: MAX_REPLAY_WINDOWS * 4,
                max_object_bytes: MAX_RECORDING_BYTES,
                max_read_bytes: 1024 * 1024 * 1024,
                max_io_calls: 1_000_000,
            },
        }
    }
}

impl ReplayTimeReadLimits {
    /// Validate pure request bounds before invoking the supplied I/O capability.
    pub fn validate(&self) -> Result<(), ReplayTimeReadError> {
        let maximum = Self::default();
        for (limits, ceilings) in [
            (self.metadata, maximum.metadata),
            (self.originals, maximum.originals),
        ] {
            if limits.max_catalogue_entries > ceilings.max_catalogue_entries
                || limits.max_objects > ceilings.max_objects
                || limits.max_edges > ceilings.max_edges
                || limits.max_object_bytes > ceilings.max_object_bytes
                || limits.max_read_bytes > MAX_AUDIT_READ_BYTES
                || limits.max_io_calls > MAX_AUDIT_IO_CALLS
            {
                return Err(ReplayTimeReadError::InvalidLimits);
            }
        }
        Ok(())
    }
}

/// The unchanged native query report and the actual work of both read capabilities.
#[derive(Debug)]
pub struct ReplayTimeReadReport {
    /// Source-linked recorder assertions and explicit unknowns; contains no source bytes.
    pub report: ReplayTimeReport,
    /// Whole-query receipt/original metadata and final revalidation accounting.
    pub metadata_usage: MetadataReadUsage,
    /// Aggregate native original reads, including each completed closure's revalidation.
    pub original_usage: PinnedClosureUsage,
}

/// No failed observation returns a partial successful report or source payload.
#[derive(Debug)]
pub enum ReplayTimeReadError {
    /// The declared read capabilities exceed the public hard bounds.
    InvalidLimits,
    /// Exact query, receipt, descriptor or source projection was refused.
    Query(ReplayTimeError),
    /// Exact receipt/original metadata custody was refused.
    Metadata(PinnedMetadataError),
    /// Native original closure or codec verification was refused.
    Original(RecordingIoError),
}

impl ReplayTimeReadError {
    /// The existing recorder-time error family; no paths, payloads or credentials.
    #[must_use]
    pub fn code(&self) -> &'static str {
        match self {
            Self::InvalidLimits => "ERR-REPLAY-TIME-LIMIT-001",
            Self::Query(error) => error.code(),
            Self::Metadata(error) => metadata_code(error),
            Self::Original(RecordingIoError::Pinned(PinnedClosureError::Observation(error))) => {
                metadata_code(error)
            }
            Self::Original(RecordingIoError::Cancelled) => "ERR-REPLAY-TIME-CANCELLED-001",
            Self::Original(
                RecordingIoError::Budget | RecordingIoError::Content(RecordingError::Limit),
            ) => "ERR-REPLAY-TIME-LIMIT-001",
            Self::Original(_) => "ERR-REPLAY-TIME-CUSTODY-001",
        }
    }

    /// Stable payload-free detail for operator diagnostics.
    #[must_use]
    pub fn reason(&self) -> &'static str {
        match self {
            Self::InvalidLimits => "invalid_replay_time_read_limits",
            Self::Query(_) => "replay_time_query_refused",
            Self::Metadata(error) => error.reason(),
            Self::Original(RecordingIoError::Pinned(error)) => error.reason(),
            Self::Original(RecordingIoError::Cancelled) => "replay_time_query_cancelled",
            Self::Original(
                RecordingIoError::Budget | RecordingIoError::Content(RecordingError::Limit),
            ) => "replay_time_original_budget_exhausted",
            Self::Original(_) => "replay_time_original_unverifiable",
        }
    }
}

fn metadata_code(error: &PinnedMetadataError) -> &'static str {
    match error {
        PinnedMetadataError::Audit(CustodyAuditError::Cancelled) => "ERR-REPLAY-TIME-CANCELLED-001",
        PinnedMetadataError::Audit(
            CustodyAuditError::Limit(_) | CustodyAuditError::InvalidRequest,
        ) => "ERR-REPLAY-TIME-LIMIT-001",
        _ => "ERR-REPLAY-TIME-CUSTODY-001",
    }
}

impl fmt::Display for ReplayTimeReadError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.code(), self.reason())
    }
}
impl std::error::Error for ReplayTimeReadError {}
impl From<ReplayTimeError> for ReplayTimeReadError {
    fn from(error: ReplayTimeError) -> Self {
        Self::Query(error)
    }
}
impl From<ReplayReceiptError> for ReplayTimeReadError {
    fn from(error: ReplayReceiptError) -> Self {
        Self::Query(error.into())
    }
}
impl From<PinnedMetadataError> for ReplayTimeReadError {
    fn from(error: PinnedMetadataError) -> Self {
        Self::Metadata(error)
    }
}
impl From<RecordingIoError> for ReplayTimeReadError {
    fn from(error: RecordingIoError) -> Self {
        Self::Original(error)
    }
}
impl From<PinnedClosureError> for ReplayTimeReadError {
    fn from(error: PinnedClosureError) -> Self {
        Self::Original(RecordingIoError::Pinned(error))
    }
}

struct Cancellation<'a>(&'a (dyn Fn() -> bool + Sync));
impl PublishCancellation for Cancellation<'_> {
    fn cancel_requested(&self, _: PublishCutPoint) -> bool {
        (self.0)()
    }
}

/// Query exact retained native originals without opening a publisher or changing the archive.
///
/// The caller supplies its own read authority, exact pins, independent finite metadata and
/// source budgets, and cancellation/revocation probe. No lock, recovery, directory enumeration,
/// staging or source disclosure occurs. Receipt scope/counts are admitted before original
/// I/O. Every original is natively verified before the shared recorder-time projection; final
/// receipt and original root/index/deletion checks precede releasing the complete report.
pub fn query_replay_time_read_only(
    io: &dyn SpoolIo,
    root: &Path,
    query: &ReplayTimeQuery,
    limits: ReplayTimeReadLimits,
    cancelled: &(impl Fn() -> bool + Sync),
) -> Result<ReplayTimeReadReport, ReplayTimeReadError> {
    query.validate()?;
    limits.validate()?;
    let cancel = Cancellation(cancelled);
    let mut usage = None;
    let report = query_with_originals(query, &cancel, |visitor| {
        let mut metadata = PinnedMetadataReader::new(io, root, limits.metadata, cancelled)?;
        let slot = codec_replay_slot(query.codec, &query.scope, query.request)?;
        let manifest = metadata.manifest(&slot, query.receipt_root)?;
        let root_bytes = manifest.canonical_bytes().len();
        if root_bytes > MAX_REPLAY_ROOT_BYTES {
            return Err(ReplayReceiptError::Limit.into());
        }
        if manifest.kind() != query.codec.receipt_kind()
            || manifest.children().len() > MAX_REPLAY_WINDOWS * 5 + 1
        {
            return Err(ReplayReceiptError::Digest.into());
        }
        let bytes = metadata.metadata(&manifest)?;
        if bytes
            .len()
            .checked_add(root_bytes)
            .is_none_or(|n| n > MAX_REPLAY_RECEIPT_BYTES)
        {
            return Err(ReplayReceiptError::Limit.into());
        }
        let receipt = wire::decode(&bytes, query.codec, &query.scope, query.request)?;
        if receipt.manifest() != &manifest {
            return Err(ReplayReceiptError::Digest.into());
        }
        visitor.admit_receipt(&receipt)?;

        // Retain all exact original root/index observations until the whole query ends.
        // Receipt role pins prevent a source object being selected as typed metadata.
        for window in receipt.windows() {
            let original = metadata.manifest(window.slot(), window.root())?;
            let leaves = window.original_leaf_digests();
            let expected = ObjectManifest::new(
                query.codec.recording_kind(),
                [leaves[0], leaves[1], leaves[2]],
                Some(leaves[3]),
            )
            .map_err(|_| ReplayReceiptError::Malformed)?;
            if original != expected {
                return Err(ReplayReceiptError::WindowMismatch.into());
            }
            metadata.metadata(&original)?;
        }

        let mut originals = PinnedClosureReader::new(io, root, limits.originals, cancelled)?;
        for (ordinal, window) in receipt.windows().iter().enumerate() {
            match query.codec {
                ReplayCodec::Avc => {
                    let recording = load_pinned_recording(
                        &mut originals,
                        window.slot(),
                        window.root(),
                        &query.scope.recording,
                        &cancel,
                    )?;
                    if ReplayWindowProof::from_avc(window.slot().clone(), &recording)? != *window {
                        return Err(ReplayReceiptError::WindowMismatch.into());
                    }
                    visitor.original(ordinal, window, VerifiedOriginal::Avc(&recording))?;
                }
                ReplayCodec::Hevc => {
                    let recording = load_pinned_hevc_recording(
                        &mut originals,
                        window.slot(),
                        window.root(),
                        &query.scope.recording,
                        &cancel,
                    )?;
                    if ReplayWindowProof::from_hevc(window.slot().clone(), &recording)? != *window {
                        return Err(ReplayReceiptError::WindowMismatch.into());
                    }
                    visitor.original(ordinal, window, VerifiedOriginal::Hevc(&recording))?;
                }
            }
        }
        let original_usage = originals.finish()?;
        let metadata_usage = metadata.finish()?;
        usage = Some((metadata_usage, original_usage));
        Ok::<_, ReplayTimeReadError>(receipt)
    })?;
    let (metadata_usage, original_usage) = usage.ok_or(PinnedMetadataError::MetadataInvalid)?;
    Ok(ReplayTimeReadReport {
        report,
        metadata_usage,
        original_usage,
    })
}
