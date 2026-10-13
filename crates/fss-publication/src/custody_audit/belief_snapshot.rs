#![forbid(unsafe_code)]
//! Captured native disk custody for deterministic belief re-derivation.
//!
//! Capture is an observation, not a lease. The existing audit establishes the selected graph;
//! exact payloads are then re-read and rehashed, with publication metadata checked around the
//! entire operation. One outer meter charges both the audit and capture: budgets do not refill.

use std::collections::BTreeMap;
use std::fmt;
use std::path::Path;

use fss_core::ContentDigest;
use fss_core::belief_verification::{BeliefEvidenceReadError, RetainedBeliefEvidence};
use fss_core::belief_verification::graph::RetainedBeliefGraph;
use fss_object::SpoolIo;

use super::{
    CustodyAuditError, CustodyAuditLimits, CustodyObjectState, CustodyRootBasis, LocalCustodyAudit,
    audit_roots, catalogue, check, classify, sha, MAX_AUDIT_OBJECTS, MAX_AUDIT_READ_BYTES,
    MAX_AUDIT_ROOTS,
};
use super::io::AuditIo;
use crate::{SlotName, read_verified_with_io};

/// Durable-journal binding and independently rederived beliefs over ledgered local slots.
pub mod durable;

/// A complete captured byte set was not established. Partial payloads never leave this boundary.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CustodyCaptureError {
    /// Existing audit refusal, including cancellation and exhausted resource allowances.
    Audit(CustodyAuditError),
    /// One exact object in the selected closure could not be verified.
    Object {
        /// Exact unavailable or invalid object.
        digest: ContentDigest,
        /// Deletion, missing bytes, corruption and unreadability remain distinct.
        state: CustodyObjectState,
    },
}
impl fmt::Display for CustodyCaptureError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Audit(error) => write!(f, "custody capture: {error}"),
            Self::Object { digest, state } => write!(f, "custody capture {digest}: {}", state.as_str()),
        }
    }
}
impl std::error::Error for CustodyCaptureError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self { Self::Audit(error) => Some(error), Self::Object { .. } => None }
    }
}
impl From<CustodyAuditError> for CustodyCaptureError {
    fn from(error: CustodyAuditError) -> Self { Self::Audit(error) }
}

/// Immutable native bytes and graph roles bracketed by matching publication observations.
///
/// No public field, decoder or mutable accessor can manufacture this state. It does not keep files
/// alive or authenticate the caller's ledger, scope or derivation engine. Debug omits raw payloads.
pub struct CapturedBeliefCustody {
    audit: LocalCustodyAudit,
    payloads: BTreeMap<ContentDigest, Vec<u8>>,
    retained_bytes: u64,
    // Kept private: the durable adapter compares ONLY its selected slot records. Equal roots
    // published under another slot cannot silently substitute for a selected slot's identity.
    records: BTreeMap<SlotName, (ContentDigest, u64, ContentDigest)>,
}
impl fmt::Debug for CapturedBeliefCustody {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CapturedBeliefCustody")
            .field("objects", &self.payloads.len())
            .field("retained_bytes", &self.retained_bytes)
            .finish_non_exhaustive()
    }
}
impl CapturedBeliefCustody {
    /// Verified observations; counters include ALL audit, capture and catalogue filesystem calls.
    #[must_use]
    pub const fn audit(&self) -> &LocalCustodyAudit { &self.audit }
    /// Owned payload bytes, excluding graph-index and allocator overhead.
    #[must_use]
    pub const fn retained_bytes(&self) -> u64 { self.retained_bytes }
}
impl RetainedBeliefEvidence for CapturedBeliefCustody {
    fn read_belief_evidence(&self, digest: ContentDigest, max_bytes: usize) -> Result<Vec<u8>, BeliefEvidenceReadError> {
        let bytes = self.payloads.get(&digest).ok_or(BeliefEvidenceReadError::Missing)?;
        if bytes.len() > max_bytes { return Err(BeliefEvidenceReadError::LimitExceeded); }
        // No filesystem work or publication side effect; the core independently hashes the copy.
        Ok(bytes.clone())
    }
}
impl RetainedBeliefGraph for CapturedBeliefCustody {
    fn belief_children(&self, digest: ContentDigest, verified_bytes: &[u8], max_children: usize) -> Result<Vec<ContentDigest>, BeliefEvidenceReadError> {
        let bytes = self.payloads.get(&digest).ok_or(BeliefEvidenceReadError::Missing)?;
        if bytes.as_slice() != verified_bytes { return Err(BeliefEvidenceReadError::Corrupt); }
        let index = self.audit.objects.binary_search_by_key(&digest, |row| row.digest)
            .map_err(|_| BeliefEvidenceReadError::Unavailable)?;
        let row = &self.audit.objects[index];
        if row.state != CustodyObjectState::Verified { return Err(BeliefEvidenceReadError::NotVerified); }
        if row.children.len() > max_children { return Err(BeliefEvidenceReadError::LimitExceeded); }
        // The auditor decoded these edges from bytes with this same content identity. Opaque
        // payloads never acquire edges merely because their bytes resemble a native manifest.
        Ok(row.children.clone())
    }
}

/// Capture complete selected closures through explicit read-only I/O and cancellation authority.
///
/// `basis` preserves the native auditor's contract. LocalPublicationRecords requires root records;
/// CallerVerifiedAuthority requires the caller to establish exact manifest roles from its ledger.
/// `denied` must come from verified deletion authority, not the offered belief, and only narrows reads.
/// Every discovered object, including unused siblings and metadata, must verify.
///
/// The native auditor is reused unchanged. Capture then reads each exact payload with its audited
/// length as the allocation ceiling and rehashes it. Outer catalogue observations bracket both
/// phases; an observed publication change returns no capture. This detects observed races, not an
/// atomic filesystem snapshot or a guarantee of availability after return.
///
/// One outer AuditIo charges every inner audit call plus capture and extra catalogue reads against
/// the SAME nonrefillable limits. Retention is separately bounded before each payload allocation.
/// The native auditor may transiently allocate one max_object_bytes payload; captured payloads
/// never exceed max_retained_bytes. Later core graph verification has an independent copy budget.
/// No files, locks, holds, publication records or verification flags are written by this operation.
pub fn capture_belief_custody(
    io: &dyn SpoolIo,
    root: &Path,
    selected_roots: &[ContentDigest],
    denied: &BTreeMap<ContentDigest, ContentDigest>,
    limits: CustodyAuditLimits,
    cancelled: &(impl Fn() -> bool + Sync),
    basis: CustodyRootBasis,
    max_retained_bytes: u64,
) -> Result<CapturedBeliefCustody, CustodyCaptureError> {
    check(cancelled)?;
    limits.validate()?;
    if max_retained_bytes > MAX_AUDIT_READ_BYTES
        || selected_roots.is_empty() || selected_roots.len() > MAX_AUDIT_ROOTS
        || selected_roots.iter().any(|d| !sha(*d))
        || denied.len() > MAX_AUDIT_OBJECTS || denied.iter().any(|(d, proof)| !sha(*d) || !sha(*proof))
        || selected_roots.iter().copied().collect::<std::collections::BTreeSet<_>>().len() != selected_roots.len()
    { return Err(CustodyAuditError::InvalidRequest.into()); }
    let metered = AuditIo::new(io, limits, cancelled);
    let result = (|| {
        let before = catalogue(&metered, root, limits.max_catalogue_entries)?;
        let mut audit = audit_roots(&metered, root, selected_roots, denied, limits, cancelled, basis)?;
        if let Some(row) = audit.objects.iter().find(|row| row.state != CustodyObjectState::Verified) {
            return Err(CustodyCaptureError::Object { digest: row.digest, state: row.state });
        }
        let mut payloads = BTreeMap::new();
        let mut retained_bytes = 0_u64;
        for row in &audit.objects {
            check(cancelled)?;
            let length = row.verified_payload_bytes.ok_or(CustodyAuditError::IoContract)?;
            let next = retained_bytes.checked_add(length)
                .ok_or(CustodyAuditError::Limit("retained_payload_bytes"))?;
            if next > max_retained_bytes { return Err(CustodyAuditError::Limit("retained_payload_bytes").into()); }
            let length_limit = usize::try_from(length).map_err(|_| CustodyAuditError::InvalidRequest)?;
            let bytes = read_verified_with_io(root, row.digest, length_limit, &metered)
                .map_err(|error| CustodyCaptureError::Object { digest: row.digest, state: classify(error) })?;
            if bytes.len() as u64 != length || ContentDigest::sha256(&bytes) != row.digest {
                return Err(CustodyCaptureError::Object { digest: row.digest, state: CustodyObjectState::Corrupt });
            }
            payloads.insert(row.digest, bytes);
            retained_bytes = next;
        }
        let after = catalogue(&metered, root, limits.max_catalogue_entries)?;
        if before != after { return Err(CustodyAuditError::CatalogueChanged.into()); }
        check(cancelled)?;
        // Do not expose the inner audit's smaller counters as the cost of the whole capture.
        audit.charged_read_bytes = metered.bytes();
        audit.peak_reserved_read_bytes = metered.peak();
        audit.io_calls = metered.calls();
        Ok(CapturedBeliefCustody { audit, payloads, retained_bytes, records: before.records })
    })();
    // An outer budget/cancellation failure must not be flattened by an inner reader's error map.
    metered.check()?;
    result
}
