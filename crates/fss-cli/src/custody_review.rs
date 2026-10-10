#![forbid(unsafe_code)]
//! Request-owned custody observations for an already authorized, verified local event read.
//!
//! This adapter selects no arbitrary artifact and grants no media-disclosure permission. The
//! publication owner verifies the exact current event's declared manifest closure; the existing
//! deployment reader revalidates the authority and deletion basis afterwards. Both observations
//! must agree. Successful checks are not an atomic snapshot or a future-availability guarantee.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use fss_core::{
    ContentDigest, EnvelopeProposition, EventHypothesis, EventId, ExplainQuestion, ExplainReceipt,
    KnowledgeState, LedgerAnchor,
};
use fss_object::{HostSpoolIo, SpoolIo};
use fss_publication::custody_audit::{
    CustodyAuditError, CustodyAuditLimits, CustodyObjectState, LocalCustodyAudit,
    MAX_AUDIT_OBJECTS, audit_authority_roots,
};
use fss_reference::agent_orient::{
    DeploymentReadError, DeploymentSnapshot, HistoryPosition, OrientLimits, read_deployment,
};
use fss_reference::reference_deployment::RELATIVE_PATH_OBJECTS;

use crate::agent_json::{array, object, string, strings};

/// Maximum individually disclosed faults or unexamined direct evidence references.
/// Exhaustion refuses the summary rather than hiding a fault or implying complete provenance.
pub const MAX_CUSTODY_DETAILS: usize = 32;
/// Admission bound for the counters reported by the subsequent deployment read. The existing
/// reader applies its own per-read limits; this is checked afterwards, not a syscall byte meter.
pub const MAX_RECHECK_ACCOUNTED_BYTES: u64 = 128 * 1024 * 1024;
/// Admission bound for file reads reported by that subsequent deployment read, not all syscalls.
pub const MAX_RECHECK_ACCOUNTED_FILES: u64 = 65_536;

/// Why no custody-bearing explanation can be served.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CustodyReviewError {
    /// The caller's verified snapshot does not bind the requested complete event lineage.
    InvalidBinding,
    /// Authority, event publication, deletion denials or journal tails changed during the check.
    BasisChanged,
    /// No revalidated authority snapshot was obtained.
    RecheckFailed,
    /// The complete diagnostic or recheck counters exceed their admission bounds.
    ContextBound,
    /// Caller-owned cancellation or deadline reached a checkpoint.
    Cancelled,
    /// The publication owner refused its bounded check.
    Audit(CustodyAuditError),
}

impl CustodyReviewError {
    /// Deterministic reason with no source bytes, filesystem paths or secret values.
    #[must_use]
    pub const fn reason(&self) -> &'static str {
        match self {
            Self::InvalidBinding => "custody event is not bound to the verified current lineage",
            Self::BasisChanged => "custody authority or deletion basis changed; reorient before retry",
            Self::RecheckFailed => "custody authority could not be revalidated; no checked answer is served",
            Self::ContextBound => "complete custody context or recheck accounting exceeds its bound",
            Self::Cancelled => "custody check cancelled or deadline reached",
            Self::Audit(error) => error.reason(),
        }
    }
}

impl std::fmt::Display for CustodyReviewError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.reason())
    }
}
impl std::error::Error for CustodyReviewError {}

/// Complete decision-relevant observations. Only the checked constructor can produce this type.
#[derive(Debug)]
pub struct CustodyReview {
    audit: LocalCustodyAudit,
    propositions: Vec<EnvelopeProposition>,
    receipt: ExplainReceipt,
    recheck_bytes: u64,
    recheck_files: u64,
}

impl CustodyReview {
    /// Immutable full publication-owner observations, including every discovered fault.
    #[must_use]
    pub const fn audit(&self) -> &LocalCustodyAudit { &self.audit }
    /// Counts, every faulty object, and every direct reference outside the audited closure.
    #[must_use]
    pub fn propositions(&self) -> &[EnvelopeProposition] { &self.propositions }
    /// Non-durable receipt over the exact emitted observations and committed event identity.
    /// It is not a retained proof object or a certificate for arbitrary embedded provenance.
    #[must_use]
    pub const fn receipt(&self) -> &ExplainReceipt { &self.receipt }
    /// Bytes reported by the revalidation reader; its doctor preflight is not included.
    #[must_use]
    pub const fn recheck_bytes(&self) -> u64 { self.recheck_bytes }
    /// File reads reported by the revalidation reader, not a complete syscall measurement.
    #[must_use]
    pub const fn recheck_files(&self) -> u64 { self.recheck_files }
}

#[derive(Clone, Debug, PartialEq)]
struct Basis {
    site: String,
    anchor: LedgerAnchor,
    position: HistoryPosition,
    ledger: ContentDigest,
    effects: ContentDigest,
    tails: (bool, bool),
    event: EventHypothesis,
    root: ContentDigest,
    revision: ContentDigest,
    denied: BTreeMap<ContentDigest, ContentDigest>,
}

fn binding(snapshot: &DeploymentSnapshot, event_id: &EventId) -> Result<Basis, CustodyReviewError> {
    let retained = snapshot.event(event_id).ok_or(CustodyReviewError::InvalidBinding)?;
    if snapshot.anchor.site_lineage != snapshot.site_lineage
        || snapshot.position.commit_sequence != snapshot.anchor.commit_sequence
        || retained.event.event_id != *event_id
        || retained.revisions.last() != Some(&retained.event)
        || retained.revision_digest != retained.event.revision_digest()
        || retained.committed_sequence > snapshot.anchor.commit_sequence
    {
        return Err(CustodyReviewError::InvalidBinding);
    }
    EventHypothesis::verify_chain(&retained.revisions)
        .map_err(|_| CustodyReviewError::InvalidBinding)?;
    let mut denied = BTreeMap::new();
    for entry in snapshot.deletions.entries() {
        for object in &entry.plan.deletable {
            if !denied.contains_key(&object.digest) && denied.len() >= MAX_AUDIT_OBJECTS {
                return Err(CustodyReviewError::ContextBound);
            }
            denied.insert(object.digest, entry.plan_digest);
        }
    }
    Ok(Basis {
        site: snapshot.site_lineage.clone(), anchor: snapshot.anchor.clone(),
        position: snapshot.position, ledger: snapshot.ledger_root,
        effects: snapshot.effect_journal_root,
        tails: (snapshot.ledger_tail_uncommitted, snapshot.effect_tail_uncommitted),
        event: retained.event.clone(), root: retained.event_root,
        revision: retained.revision_digest, denied,
    })
}

fn checkpoint(cancelled: &(impl Fn() -> bool + Sync)) -> Result<(), CustodyReviewError> {
    if cancelled() { Err(CustodyReviewError::Cancelled) } else { Ok(()) }
}

/// Check one event from an already verified and authorized `read_deployment` snapshot.
///
/// `before` is the caller's same-request snapshot, not an authentication credential. Callers
/// must apply their local metadata authorization before entering this adapter. The principal
/// label alone is not authentication, and this is not a multi-tenant projection boundary.
/// No historical support branch is silently substituted for this current publication root.
/// The additional reader uses the existing `OrientLimits`; cancellation brackets that reader
/// and is checked at every custody I/O boundary. Blocking filesystem calls are not preempted.
pub fn check_event(
    root: &Path,
    before: &DeploymentSnapshot,
    event_id: &EventId,
    limits: CustodyAuditLimits,
    cancelled: &(impl Fn() -> bool + Sync),
) -> Result<CustodyReview, CustodyReviewError> {
    check_with(root, before, event_id, limits, &HostSpoolIo,
        || read_deployment(root, &OrientLimits::default()), cancelled)
}

fn check_with(
    root: &Path,
    before: &DeploymentSnapshot,
    event_id: &EventId,
    limits: CustodyAuditLimits,
    io: &dyn SpoolIo,
    recheck: impl FnOnce() -> Result<DeploymentSnapshot, DeploymentReadError>,
    cancelled: &(impl Fn() -> bool + Sync),
) -> Result<CustodyReview, CustodyReviewError> {
    checkpoint(cancelled)?;
    let basis = binding(before, event_id)?;
    checkpoint(cancelled)?;
    let audit = audit_authority_roots(io, &root.join(RELATIVE_PATH_OBJECTS), &[basis.root],
        &basis.denied, limits, cancelled).map_err(CustodyReviewError::Audit)?;
    checkpoint(cancelled)?;
    let after = recheck().map_err(|_| CustodyReviewError::RecheckFailed)?;
    checkpoint(cancelled)?;
    let after_basis = binding(&after, event_id).map_err(|error| match error {
        CustodyReviewError::ContextBound => error,
        _ => CustodyReviewError::BasisChanged,
    })?;
    if after_basis != basis {
        return Err(CustodyReviewError::BasisChanged);
    }
    if after.bytes_read > MAX_RECHECK_ACCOUNTED_BYTES || after.files_read > MAX_RECHECK_ACCOUNTED_FILES {
        return Err(CustodyReviewError::ContextBound);
    }
    let propositions = project(&basis, &audit)?;
    // This is a hash of exact non-durable JSON projection bytes, not a new durable schema.
    // Every fault identity and denial reference participates; physical event state is untouched.
    let projected = array(&propositions.iter().map(|p| object(&[
        ("id", string(&p.id)), ("statement", string(&p.statement)),
        ("state", string(p.state.as_str())), ("provenance", string(&p.provenance)),
        ("evidence", strings(&p.evidence)),
    ])).collect::<Vec<_>>());
    let receipt = ExplainReceipt::compile(ExplainQuestion::Why, basis.revision,
        vec![basis.root, basis.anchor.state_root, ContentDigest::sha256(projected.as_bytes())],
        Vec::new(), 0).map_err(|_| CustodyReviewError::InvalidBinding)?;
    checkpoint(cancelled)?;
    Ok(CustodyReview { audit, propositions, receipt,
        recheck_bytes: after.bytes_read, recheck_files: after.files_read })
}

fn proposition(basis: &Basis, suffix: &str, statement: String, state: KnowledgeState,
    evidence: Vec<String>) -> EnvelopeProposition {
    EnvelopeProposition {
        id: format!("claim:event-custody:{}:{suffix}", basis.revision),
        statement, state, provenance: "derived".to_owned(), evidence,
    }
}

fn project(basis: &Basis, audit: &LocalCustodyAudit) -> Result<Vec<EnvelopeProposition>, CustodyReviewError> {
    if audit.roots() != [basis.root] { return Err(CustodyReviewError::InvalidBinding); }
    let observed: BTreeSet<_> = audit.objects().iter().map(|row| row.digest).collect();
    // These are referenced identities, not permission to read beyond the published closure.
    let direct: BTreeSet<_> = basis.event.evidence.iter().flat_map(|edge| {
        std::iter::once(edge.digest).chain(edge.capsule_digest).chain(edge.identity_digest)
    }).chain(basis.event.model_receipts.iter().copied()).collect();
    let outside: Vec<_> = direct.difference(&observed).copied().collect();
    let faults: Vec<_> = audit.objects().iter()
        .filter(|row| row.state != CustodyObjectState::Verified).collect();
    if faults.len().saturating_add(outside.len()) > MAX_CUSTODY_DETAILS {
        return Err(CustodyReviewError::ContextBound);
    }
    let mut counts = BTreeMap::new();
    for row in audit.objects() { *counts.entry(row.state.as_str()).or_insert(0_usize) += 1; }
    let counts = counts.iter().map(|(state, count)| format!("{state}={count}"))
        .collect::<Vec<_>>().join(", ");
    let mut result = vec![proposition(basis, "publication-closure", format!(
        "Current event publication closure: {counts}; {} discovered objects, {} manifest edges; all_verified={}, manifest_expansion_complete={}. Sequential byte observations only, not event truth, independence, future availability or complete embedded provenance.",
        audit.objects().len(), audit.edges(), audit.all_verified(), audit.manifest_expansion_complete(),
    ), KnowledgeState::Known, vec![basis.root.to_text()])];
    for row in faults {
        let mut evidence = vec![row.digest.to_text()];
        evidence.extend(row.denial_digest.map(ContentDigest::to_text));
        result.push(proposition(basis, &format!("fault:{}", row.digest), format!(
            "Publication-closure object is {}; declared_manifest={}. {} No event retraction or probability change was performed.",
            row.state.as_str(), row.declared_manifest,
            if row.declared_manifest { "Its undiscovered descendants remain unknown." }
            else { "This is a byte-availability finding, not evidence of physical absence." },
        ), KnowledgeState::Known, evidence));
    }
    if !outside.is_empty() {
        result.push(proposition(basis, "unexamined-references", format!(
            "{} direct evidence, capsule, identity or model references are outside the discoverable publication closure. All are listed here; their availability remains unexamined. Historical support roots are not included unless actually reached in this closure.", outside.len(),
        ), KnowledgeState::Unknown, outside.iter().map(|digest| digest.to_text()).collect()));
    }
    Ok(result)
}

#[cfg(test)]
#[path = "custody_review/tests.rs"]
mod tests;
