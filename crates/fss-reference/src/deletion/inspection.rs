#![forbid(unsafe_code)]
//! Read-only retention inspection at one verified authority head.
//!
//! These entrypoints never open a publisher, acquire a writer lock or recover a journal.
//! Native hold transitions and policy generations remain authoritative. Opening metadata,
//! reconstructing records and rechecking every dependency share one nonrenewing allowance.

use std::path::Path;

use fss_core::region::ContextAuthority;
use fss_core::{ContentDigest, LedgerAnchor};

use super::holds::{CAP_HOLD_PREPARE, HoldError, HoldRecord, retained_hold_records};
use super::retention::policy::{PolicyError, RetentionPolicyRecord, retained_policy_records};
use crate::ReplayCx;
use crate::agent_orient::OrientLimits;
use crate::ingest::FileIngestError;
use crate::retained_source::{
    ImmutableRetainedReadLimits, ImmutableRetainedSource, RetainedReadUsage, RetainedSource,
};

#[cfg(test)]
#[path = "inspection/tests.rs"]
mod tests;

/// Maximum payload bytes across metadata, native records and final revalidation.
pub const MAX_INSPECTION_READ_BYTES: usize = 256 * 1024 * 1024;
/// Maximum payload read attempts across the complete inspection.
pub const MAX_INSPECTION_READ_OBJECTS: usize = 65_536;
/// Final cooperative checkpoint, before any successful result escapes the owner.
pub const STAGE_INSPECTION_FINAL: &str = "retention_inspection:final";

/// Bounded defaults; callers may narrow these allowances but cannot widen them.
#[must_use]
pub fn inspection_limits() -> ImmutableRetainedReadLimits {
    ImmutableRetainedReadLimits {
        snapshot: OrientLimits::default(),
        max_read_bytes: MAX_INSPECTION_READ_BYTES,
        max_read_objects: MAX_INSPECTION_READ_OBJECTS,
    }
}

/// Fully verified native retention records at one unchanged committed authority head.
#[derive(Clone, Debug)]
pub struct RetentionInspection<Record> {
    /// Exact opening anchor, verified again immediately before return.
    pub anchor: LedgerAnchor,
    /// Current records in the native owner's deterministic order, including terminal states.
    pub records: Vec<Record>,
    /// Aggregate payload bytes and read attempts, including final verification.
    pub read_usage: RetainedReadUsage,
}

/// Inspect current holds, including release and approved-expiry records, alongside a writer.
/// Requires retention-prepare authority; it grants neither media access nor a hold mutation.
pub fn inspect_holds(
    root: &Path,
    authority: &ContextAuthority,
    limits: ImmutableRetainedReadLimits,
    cx: &ReplayCx,
    cancelled: &(dyn Fn() -> bool + Sync),
) -> Result<RetentionInspection<HoldRecord>, HoldError> {
    inspect(root, authority, limits, cx, cancelled, |source| {
        retained_hold_records(source, cx)
    })
}

/// Inspect current policy generations and their retained impact records alongside a writer.
/// All history is verified before any caller applies a sensor filter. Missing custody is a
/// refusal, never an absent policy; reading policy metadata does not read source media.
pub fn inspect_policies(
    root: &Path,
    authority: &ContextAuthority,
    limits: ImmutableRetainedReadLimits,
    cx: &ReplayCx,
    cancelled: &(dyn Fn() -> bool + Sync),
) -> Result<RetentionInspection<RetentionPolicyRecord>, PolicyError> {
    inspect(root, authority, limits, cx, cancelled, |source| {
        retained_policy_records(source, cx)
    })
}

trait InspectionFailure: From<FileIngestError> {
    fn unauthorized() -> Self;
    fn limit() -> Self;
    fn cancelled() -> Self;
}

impl InspectionFailure for HoldError {
    fn unauthorized() -> Self {
        Self::Unauthorized
    }
    fn limit() -> Self {
        Self::Limit
    }
    fn cancelled() -> Self {
        Self::Cancelled
    }
}
impl InspectionFailure for PolicyError {
    fn unauthorized() -> Self {
        Self::Unauthorized
    }
    fn limit() -> Self {
        Self::Limit
    }
    fn cancelled() -> Self {
        Self::Cancelled
    }
}

fn inspect<Record, Failure: InspectionFailure>(
    root: &Path,
    authority: &ContextAuthority,
    limits: ImmutableRetainedReadLimits,
    cx: &ReplayCx,
    cancelled: &(dyn Fn() -> bool + Sync),
    read: impl FnOnce(&ImmutableRetainedSource<'_>) -> Result<Vec<Record>, Failure>,
) -> Result<RetentionInspection<Record>, Failure> {
    // Admission happens before filesystem access. Binding only the principal while allowing
    // a different site, root or enlarged read budget would silently widen the caller's grant.
    if authority.validate().is_err()
        || authority.cancellation_reason.is_some()
        || !authority.has_capability(CAP_HOLD_PREPARE)
        || authority.principal != cx.io_authority().principal()
        || authority.principal.len() > 256
        || root != cx.root_dir()
    {
        return Err(Failure::unauthorized());
    }
    let ceiling = inspection_limits();
    let snapshot = limits.snapshot;
    if limits.max_read_bytes == 0
        || limits.max_read_bytes > ceiling.max_read_bytes
        || limits.max_read_bytes as u64 > authority.budgets.bytes
        || limits.max_read_objects == 0
        || limits.max_read_objects > ceiling.max_read_objects
        || limits.max_read_objects as u64 > authority.budgets.storage_operations
        || snapshot.max_layout_bytes == 0
        || snapshot.max_layout_bytes > ceiling.snapshot.max_layout_bytes
        || snapshot.max_journal_bytes == 0
        || snapshot.max_journal_bytes > ceiling.snapshot.max_journal_bytes
        || snapshot.max_object_bytes == 0
        || snapshot.max_object_bytes > ceiling.snapshot.max_object_bytes
        || snapshot.max_events == 0
        || snapshot.max_events > ceiling.snapshot.max_events
        || snapshot.max_revisions_per_event == 0
        || snapshot.max_revisions_per_event > ceiling.snapshot.max_revisions_per_event
    {
        return Err(Failure::limit());
    }
    if cancelled() || cx.checkpoint("retention_inspection:read").is_err() {
        return Err(Failure::cancelled());
    }
    let source = ImmutableRetainedSource::open_cancellable(root, limits, cx, cancelled)?;
    if authority.anchor_universe != ContentDigest::sha256(source.site_lineage().as_bytes())
        || source.site_lineage().len() > 256
    {
        return Err(Failure::unauthorized());
    }
    let records = read(&source)?;
    if cancelled() || cx.checkpoint(STAGE_INSPECTION_FINAL).is_err() {
        return Err(Failure::cancelled());
    }
    // Even an empty registry is a statement about an exact head. Rehash metadata, selected
    // records, custody and both journal roots before exposing either records or emptiness.
    source.revalidate_snapshot_metadata()?;
    source.revalidate()?;
    Ok(RetentionInspection {
        anchor: source.current_anchor().clone(),
        records,
        read_usage: source.usage(),
    })
}
