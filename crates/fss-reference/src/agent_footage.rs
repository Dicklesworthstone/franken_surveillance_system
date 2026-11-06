#![forbid(unsafe_code)]
//! Bounded AOP-005 discovery of retained recorded-file capsule metadata.
//!
//! This read never opens a writable deployment, runs recovery, or reads source-media chunks.
//! Completion, native publication records, ledger reachability, import custody and exact
//! capsule bytes must agree. Availability here means verified metadata; payload availability,
//! clock precision, physical coverage and absence remain unknown. Closed time predicates
//! compare declared source-native intervals conservatively, without converting them to UTC.
//!
//! A shared allowance covers history replay, metadata, and final revalidation. A changed head,
//! a local tombstone, corrupt selected metadata, cancellation or exhaustion returns no page.

mod read;
mod result;
#[cfg(test)]
mod tests;

use crate::agent_follow::AnchorToken;
use crate::agent_orient::OrientLimits;
use crate::deployment_status::StatusError;
use fss_core::{
    CanonicalEncode, CanonicalEncoder, ContentDigest, ContinuationError, ContractBasisError,
    ContractError, PrincipalId, SensorCapsule, SensorId, StreamId,
};
pub use result::DeploymentFootageQuery;
use std::path::Path;

/// Maximum complete capsule index; filters never bypass this bound.
pub const MAX_FOOTAGE_CAPSULES: usize = 16_384;
/// Maximum returned capsule metadata records on one page.
pub const MAX_FOOTAGE_ENTRIES: u32 = 32;
/// Default page size, shared with the committed-event query.
pub const DEFAULT_FOOTAGE_ENTRIES: u32 = 16;

/// Exact conjunctive predicates over declared capsule metadata.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct FootageQueryFilter {
    /// Exact sensor identity.
    pub sensor: Option<SensorId>,
    /// Exact immutable stream identity.
    pub stream: Option<StreamId>,
    /// Inclusive lower endpoint; broad intervals remain eligible if they overlap.
    pub from_ns: Option<i128>,
    /// Inclusive upper endpoint in the capsule's source-native clock domain.
    pub through_ns: Option<i128>,
}
impl FootageQueryFilter {
    /// Rejects an inverted closed interval before any I/O.
    pub fn validate(&self) -> Result<(), FootageQueryError> {
        if self
            .from_ns
            .zip(self.through_ns)
            .is_some_and(|(a, b)| a > b)
        {
            return Err(FootageQueryError::InvalidRequest(
                "inverted footage interval",
            ));
        }
        Ok(())
    }
    /// Interval overlap, never a claim of precise capture time or physical presence.
    pub fn matches(&self, capsule: &SensorCapsule) -> bool {
        self.sensor
            .as_ref()
            .is_none_or(|id| id == &capsule.sensor_id)
            && self
                .stream
                .as_ref()
                .is_none_or(|id| id == &capsule.stream_id)
            && self.from_ns.is_none_or(|t| capsule.capture.latest.0 >= t)
            && self
                .through_ns
                .is_none_or(|t| capsule.capture.earliest.0 <= t)
    }
    /// Literal, reviewable interpretation of the typed predicates.
    pub fn description(&self) -> String {
        format!(
            "Completed ADP-FILE-001 import capsule metadata; sensor={}; stream={}; closed source-native overlap [{},{}]; clock conversion and physical absence are not established",
            self.sensor.as_ref().map_or("any", |id| id.as_str()),
            self.stream.as_ref().map_or("any", |id| id.as_str()),
            self.from_ns
                .map_or_else(|| "unbounded".to_owned(), |t| t.to_string()),
            self.through_ns
                .map_or_else(|| "unbounded".to_owned(), |t| t.to_string())
        )
    }
}
impl CanonicalEncode for FootageQueryFilter {
    fn encode_canonical(&self, e: &mut CanonicalEncoder) {
        e.bool(self.sensor.is_some());
        if let Some(id) = &self.sensor {
            id.encode_canonical(e);
        }
        e.bool(self.stream.is_some());
        if let Some(id) = &self.stream {
            id.encode_canonical(e);
        }
        for t in [self.from_ns, self.through_ns] {
            e.bool(t.is_some());
            if let Some(t) = t {
                e.i128(t);
            }
        }
    }
}

/// One anchor-pinned reference read; the principal is an audit label, not authentication.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FootageQueryRequest {
    /// Exact predicates applied only after verifying the bounded metadata index.
    pub filter: FootageQueryFilter,
    /// Caller audit identity; admission does not grant source-media or effect authority.
    pub principal: PrincipalId,
    /// Page size in 1..=32.
    pub max_entries: u32,
    /// Exact committed authority/effect token precondition.
    pub expected_anchor: Option<AnchorToken>,
    /// Exact native continuation returned by the previous page.
    pub continuation: Option<String>,
}
impl FootageQueryRequest {
    /// Checks scalars and cursor spelling before reading anything.
    pub fn validate(&self) -> Result<(), FootageQueryError> {
        self.filter.validate()?;
        if !(1..=MAX_FOOTAGE_ENTRIES).contains(&self.max_entries) {
            return Err(FootageQueryError::InvalidRequest(
                "footage page size outside bounds",
            ));
        }
        if self.continuation.as_ref().is_some_and(|t| {
            t.len() > 256
                || !t.starts_with("continuation:")
                || !t.bytes().all(|b| {
                    b.is_ascii_lowercase()
                        || b.is_ascii_digit()
                        || matches!(b, b':' | b'+' | b'.' | b'_' | b'-')
                })
        }) {
            return Err(FootageQueryError::InvalidRequest(
                "invalid footage continuation spelling",
            ));
        }
        Ok(())
    }
}

/// Non-replenishing read and index ceilings. Every exceeded limit refuses the entire page.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FootageQueryLimits {
    /// Per-input bounds for native history and snapshot readers.
    pub snapshot: OrientLimits,
    /// Maximum complete import declarations considered.
    pub max_imports: usize,
    /// Maximum capsules before selection; cannot exceed the hard reference ceiling.
    pub max_capsules: usize,
    /// Maximum distinct ledger objects indexed.
    pub max_objects: usize,
    /// Total payload bytes read, including initial and final history/snapshot verification.
    pub max_metadata_bytes: usize,
    /// Total file/object reads, including repeated integrity verification.
    pub max_metadata_objects: usize,
}
impl Default for FootageQueryLimits {
    fn default() -> Self {
        Self {
            snapshot: OrientLimits::default(),
            max_imports: 1024,
            max_capsules: MAX_FOOTAGE_CAPSULES,
            max_objects: 65_536,
            max_metadata_bytes: 256 * 1024 * 1024,
            max_metadata_objects: 65_536,
        }
    }
}
impl FootageQueryLimits {
    fn validate(&self) -> Result<(), FootageQueryError> {
        let ceiling = Self::default();
        if self.max_imports == 0
            || self.max_imports > ceiling.max_imports
            || self.max_capsules == 0
            || self.max_capsules > MAX_FOOTAGE_CAPSULES
            || self.max_objects == 0
            || self.max_objects > ceiling.max_objects
            || self.max_metadata_bytes == 0
            || self.max_metadata_bytes > ceiling.max_metadata_bytes
            || self.max_metadata_objects == 0
            || self.max_metadata_objects > ceiling.max_metadata_objects
            || self.snapshot.max_layout_bytes == 0
            || self.snapshot.max_layout_bytes > ceiling.snapshot.max_layout_bytes
            || self.snapshot.max_journal_bytes == 0
            || self.snapshot.max_journal_bytes > ceiling.snapshot.max_journal_bytes
            || self.snapshot.max_object_bytes == 0
            || self.snapshot.max_object_bytes > ceiling.snapshot.max_object_bytes
            || self.snapshot.max_events > ceiling.snapshot.max_events
            || self.snapshot.max_revisions_per_event > ceiling.snapshot.max_revisions_per_event
        {
            return Err(FootageQueryError::InvalidRequest(
                "footage read limits outside bounds",
            ));
        }
        Ok(())
    }
}

/// One verified metadata row; no raw source bytes or current payload-availability claim.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FootageQueryRow {
    /// Stable file-import identity, independent of the operator's original filesystem path.
    pub import_identity: ContentDigest,
    /// Native completed import publication root.
    pub import_root: ContentDigest,
    /// Exact canonical file-import metadata digest.
    pub manifest_digest: ContentDigest,
    /// SHA-256 of exact retained capsule canonical bytes (H0 metadata handle).
    pub capsule_digest: ContentDigest,
    /// Unmodified declared interval, clock basis, sensor/stream, gap and source digest.
    pub capsule: SensorCapsule,
    /// Segment ordinal within the original source file.
    pub segment_index: u64,
    /// Source-file byte offset; no source path is disclosed.
    pub source_offset: u64,
    /// Declared length of the segment.
    pub source_len: u64,
    /// Digest of the complete original file, not rehashed by this metadata query.
    pub input_digest: ContentDigest,
    /// Declared full source-file length.
    pub input_bytes: u64,
    /// Retained adapter format identifier.
    pub format: String,
    /// `unknown` or `operator_assumption`, never upgraded to trusted UTC.
    pub capture_time_label: String,
    /// Commit sequence completing the enclosing import.
    pub committed_sequence: u64,
}
impl FootageQueryRow {
    /// Canonical result identity also binds import membership and source range.
    pub fn row_digest(&self) -> ContentDigest {
        let mut e = CanonicalEncoder::new();
        e.text("fss.agent_footage.row.v1");
        for d in [
            self.import_identity,
            self.import_root,
            self.manifest_digest,
            self.capsule_digest,
            self.input_digest,
        ] {
            e.digest(d);
        }
        self.capsule.encode_canonical(&mut e);
        for n in [
            self.segment_index,
            self.source_offset,
            self.source_len,
            self.input_bytes,
            self.committed_sequence,
        ] {
            e.u64(n);
        }
        e.text(&self.format);
        e.text(&self.capture_time_label);
        ContentDigest::sha256(&e.finish())
    }
}

/// Typed fail-closed refusal. None of these outcomes is an empty successful result.
#[derive(Debug)]
pub enum FootageQueryError {
    /// Invalid input or limits, before I/O.
    InvalidRequest(&'static str),
    /// Native read classification, preserving missing-layout and unreadable distinctions.
    Read(StatusError),
    /// Committed authority/effects, layout, or selected custody changed during the read.
    AnchorChanged,
    /// Invalid metadata, publication membership, tombstone state or canonical identity.
    InvalidRecord,
    /// A shared byte, object, index or output bound was exhausted.
    OverBudget,
    /// Caller cancellation checkpoint returned false.
    Cancelled,
    /// Native cursor owner refused the continuation.
    Continuation(ContinuationError),
    /// Native query-plan/admission contract refused the request.
    Contract(ContractBasisError),
}
impl std::fmt::Display for FootageQueryError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidRequest(s) => f.write_str(s),
            Self::Read(e) => write!(f, "footage read refused: {e}"),
            Self::AnchorChanged => {
                f.write_str("footage authority or custody changed; start a new query")
            }
            Self::InvalidRecord => {
                f.write_str("retained footage metadata or custody failed verification")
            }
            Self::OverBudget => f.write_str("footage metadata read exceeds its shared budget"),
            Self::Cancelled => f.write_str("footage metadata read cancelled"),
            Self::Continuation(e) => write!(f, "footage continuation refused: {e}"),
            Self::Contract(e) => write!(f, "footage query contract refused: {e}"),
        }
    }
}
impl std::error::Error for FootageQueryError {}
impl From<ContinuationError> for FootageQueryError {
    fn from(e: ContinuationError) -> Self {
        Self::Continuation(e)
    }
}
impl From<ContractBasisError> for FootageQueryError {
    fn from(e: ContractBasisError) -> Self {
        Self::Contract(e)
    }
}
impl From<ContractError> for FootageQueryError {
    fn from(e: ContractError) -> Self {
        Self::Contract(ContractBasisError::Contract(e))
    }
}

fn checkpoint(
    check: &mut dyn FnMut(&'static str) -> bool,
    stage: &'static str,
) -> Result<(), FootageQueryError> {
    if check(stage) {
        Ok(())
    } else {
        Err(FootageQueryError::Cancelled)
    }
}

/// Reads and verifies one native capsule-metadata page without recovery, writes or media reads.
/// `checkpoint` returns true to continue; cancellation discards the entire pending result.
pub fn query_footage(
    root: &Path,
    request: &FootageQueryRequest,
    limits: &FootageQueryLimits,
    checkpoint: &mut dyn FnMut(&'static str) -> bool,
) -> Result<DeploymentFootageQuery, FootageQueryError> {
    read::query(root, request, limits, checkpoint)
}
