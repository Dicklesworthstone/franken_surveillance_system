#![forbid(unsafe_code)]
//! Explicit, indefinite evidence holds over retained import closures (FSS-037 / GOAL-009).
//!
//! A hold is a local retention decision, not a legal conclusion or an erasure promise.
//! Placement and release require the existing retention prepare/commit capabilities and an
//! exact principal- and anchor-bound approval. One identifier has exactly two possible
//! generations: held, then released. Released identifiers are never reused, and time alone
//! never releases a hold. Records are retained authority history, not deletable derivatives.
//!
//! The deployment lock serializes holds with deletion. No new hold mutation is admitted while
//! a deletion record lacks completion: preservation cannot be promised after removal started.
//! Deletion checks the *current* closure of each held import, including shared derivatives,
//! rather than freezing only the objects that happened to exist when the hold was placed.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use fss_core::region::ContextAuthority;
use fss_core::{
    BatchId, CanonicalDecode, CanonicalDecoder, CanonicalEncode, CanonicalEncoder,
    CaptureInterval, ContentDigest, ContractError, DigestAlgorithm, EvidenceDelta,
    LedgerAnchor, ObjectId, Plane, PrincipalId, TimestampNs,
};

use super::walk::Universe;
use super::{DeletionError, DeletionIndex, DeletionPlan, Finding};
use crate::ingest::{FileIngestError, RetainedFileImport, RetainedReadLimits};
use crate::reference_deployment::FAMILY_EVIDENCE_HOLD;
use crate::{ReferenceDeployment, ReferenceError, ReplayCx};

/// Existing registered capability for inspection and preparation of retention changes.
pub const CAP_HOLD_PREPARE: &str = "CAP-RETENTION-PREPARE-001";
/// Existing registered capability for exact approval of retention changes, including release.
pub const CAP_HOLD_COMMIT: &str = "CAP-RETENTION-COMMIT-001";
/// Canonical record domain; its bytes are the payload of an `evidence_hold` ledger delta.
pub const HOLD_DOMAIN: &str = "fss.evidence_hold.v1";
/// Approval binds the complete record, principal, scope, transition, and authority anchor.
pub const HOLD_APPROVAL_DOMAIN: &str = "fss.evidence_hold_approval.v1";
/// Reserved object namespace; generic ledger writes must not shadow a hold under another family.
pub const HOLD_OBJECT_PREFIX: &str = "object:evidence-hold:";
/// Bound on lifetime identifiers, including released tombstones. Never evict audit history.
pub const MAX_HOLDS: usize = 256;
/// Bound on simultaneous held import closures evaluated during deletion.
pub const MAX_ACTIVE_HOLDS: usize = 32;
/// Hard record size ceiling, checked before canonical decoding.
pub const MAX_HOLD_RECORD_BYTES: usize = 8_192;
/// Cooperative read/prepare checkpoint.
pub const STAGE_HOLD_READ: &str = "evidence_hold:read";
/// Last checkpoint before any payload is staged.
pub const STAGE_HOLD_REVALIDATED: &str = "evidence_hold:revalidated";
/// A staged record is not yet an effective hold or release.
pub const STAGE_HOLD_STAGED: &str = "evidence_hold:staged";
/// Post-commit checkpoint, never converted into a failed operation.
pub const STAGE_HOLD_COMMITTED: &str = "evidence_hold:committed";

/// One-way lifecycle of a site-local hold identifier.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HoldState {
    /// Preserve the named import's current and later retained derivative closure.
    Held,
    /// Explicitly released. History remains; no content is deleted by this transition.
    Released,
}

impl HoldState {
    /// Stable machine spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Held => "held",
            Self::Released => "released",
        }
    }

    fn generation(self) -> u64 {
        match self {
            Self::Held => 1,
            Self::Released => 2,
        }
    }
}

/// Complete operator request. The principal is taken from explicit context authority.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HoldRequest {
    /// Site-local, never-reused identifier: 1..64 ASCII letters, digits, underscores or hyphens.
    pub hold_id: String,
    /// Exact completed import identity, not a filename or sensor alias.
    pub import_identity: ContentDigest,
    /// Desired lifecycle transition.
    pub state: HoldState,
    /// Nonempty bounded operator rationale; must not contain secrets or media content.
    pub reason: String,
}

impl HoldRequest {
    /// Checks bounds before reading custody or allocating history state.
    pub fn validate(&self) -> Result<(), HoldError> {
        if self.hold_id.is_empty()
            || self.hold_id.len() > 64
            || !self.hold_id.bytes().all(|b| b.is_ascii_alphanumeric() || b"_-".contains(&b))
        {
            return Err(HoldError::InvalidRequest("hold id must be 1..64 of [A-Za-z0-9_-]"));
        }
        if self.import_identity.algorithm() != DigestAlgorithm::Sha256 {
            return Err(HoldError::InvalidRequest("import identity must be SHA-256"));
        }
        if self.reason.trim().is_empty()
            || self.reason.len() > 512
            || self.reason.chars().any(char::is_control)
        {
            return Err(HoldError::InvalidRequest("reason must be 1..512 bytes without controls"));
        }
        Ok(())
    }
}

/// Validated, immutable retained record. Construction is owned by preparation and decoding.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HoldRecord {
    request: HoldRequest,
    principal: String,
    site: String,
    basis: LedgerAnchor,
    predecessor: Option<ContentDigest>,
}

impl HoldRecord {
    /// Exact request, including scope, lifecycle state, and rationale.
    #[must_use]
    pub fn request(&self) -> &HoldRequest { &self.request }
    /// Audit principal whose approval was required. Not remote authentication.
    #[must_use]
    pub fn principal(&self) -> &str { &self.principal }
    /// Site lineage in which the record is authoritative.
    #[must_use]
    pub fn site(&self) -> &str { &self.site }
    /// Exact authority position against which the transition was prepared.
    #[must_use]
    pub fn basis(&self) -> &LedgerAnchor { &self.basis }
    /// Held record this release succeeds, or no predecessor for initial placement.
    #[must_use]
    pub fn predecessor(&self) -> Option<ContentDigest> { self.predecessor }

    /// Canonical payload. Holds have commit-sequence semantics, not inferred capture times.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut e = CanonicalEncoder::new();
        e.bytes(b"FSSHLD01");
        e.u32(1);
        e.text(HOLD_DOMAIN);
        e.text(&self.request.hold_id);
        e.digest(self.request.import_identity);
        e.u8(match self.request.state { HoldState::Held => 0, HoldState::Released => 1 });
        e.text(&self.request.reason);
        e.text(&self.principal);
        e.text(&self.site);
        self.basis.encode_canonical(&mut e);
        match self.predecessor {
            None => e.u8(0),
            Some(digest) => { e.u8(1); e.digest(digest); }
        }
        e.finish()
    }

    /// Exact record identity.
    #[must_use]
    pub fn digest(&self) -> ContentDigest { ContentDigest::sha256(&self.to_bytes()) }

    /// Exact approval of the record; no write is implied by possessing this digest.
    #[must_use]
    pub fn approval(&self) -> ContentDigest {
        let mut e = CanonicalEncoder::new();
        e.text(HOLD_APPROVAL_DOMAIN);
        e.digest(self.digest());
        ContentDigest::sha256(&e.finish())
    }

    /// Decode against the retained payload digest, refusing noncanonical or oversized records.
    pub fn from_bytes(bytes: &[u8], expected: ContentDigest) -> Result<Self, HoldError> {
        if bytes.len() > MAX_HOLD_RECORD_BYTES || ContentDigest::sha256(bytes) != expected {
            return Err(HoldError::InvalidRecord);
        }
        let mut d = CanonicalDecoder::new(bytes);
        if d.bytes()? != b"FSSHLD01" || d.u32()? != 1 || d.text()? != HOLD_DOMAIN {
            return Err(HoldError::InvalidRecord);
        }
        let hold_id = d.text()?.to_owned();
        let import_identity = d.digest()?;
        let state = match d.u8()? {
            0 => HoldState::Held,
            1 => HoldState::Released,
            _ => return Err(HoldError::InvalidRecord),
        };
        let reason = d.text()?.to_owned();
        let principal = d.text()?.to_owned();
        let site = d.text()?.to_owned();
        let basis = LedgerAnchor::decode_canonical(&mut d)?;
        let predecessor = match d.u8()? {
            0 => None,
            1 => Some(d.digest()?),
            _ => return Err(HoldError::InvalidRecord),
        };
        d.ensure_finished()?;
        let record = Self {
            request: HoldRequest { hold_id, import_identity, state, reason },
            principal, site, basis, predecessor,
        };
        record.request.validate().map_err(|_| HoldError::InvalidRecord)?;
        PrincipalId::parse(&record.principal).map_err(|_| HoldError::InvalidRecord)?;
        crate::reference_deployment::validate_site_lineage(&record.site)
            .map_err(|_| HoldError::InvalidRecord)?;
        if record.site.len() > 256 || record.principal.len() > 256
            || (state == HoldState::Held) != predecessor.is_none()
            || predecessor.is_some_and(|p| p.algorithm() != DigestAlgorithm::Sha256)
            || record.to_bytes() != bytes
        {
            return Err(HoldError::InvalidRecord);
        }
        Ok(record)
    }

    fn object_id(&self) -> Result<ObjectId, HoldError> {
        let mut e = CanonicalEncoder::new();
        e.text(HOLD_DOMAIN);
        e.text(&self.site);
        e.text(&self.request.hold_id);
        Ok(ObjectId::parse(format!("{HOLD_OBJECT_PREFIX}{}", hex(ContentDigest::sha256(&e.finish()))))?)
    }

    fn batch_id(&self) -> Result<BatchId, HoldError> {
        Ok(BatchId::parse(format!("batch:evidence-hold:{}", hex(self.digest())))?)
    }

    fn children(&self) -> Vec<ContentDigest> {
        let mut children = vec![self.digest()];
        children.extend(self.predecessor);
        children.sort_unstable();
        children.dedup();
        children
    }

    fn delta(&self) -> Result<EvidenceDelta, HoldError> {
        Ok(EvidenceDelta {
            delta_id: format!("delta:evidence-hold:{}", hex(self.digest())),
            family: FAMILY_EVIDENCE_HOLD.to_owned(),
            object_id: self.object_id()?,
            prior_generation: self.predecessor.map(|_| 1),
            new_generation: self.request.state.generation(),
            // As with privacy declarations, this is administrative metadata, not sensor time.
            validity: CaptureInterval::new(TimestampNs(0), TimestampNs(0))?,
            plane: Plane::Authority,
            payload_digest: self.digest(),
            witness_digest: self.predecessor,
            operation_id: None,
        })
    }
}

/// Why no retention change or trustworthy hold read was produced.
#[derive(Debug)]
pub enum HoldError {
    /// Invalid bounded request.
    InvalidRequest(&'static str),
    /// Retention capability, principal, site, or cancellation authority does not match.
    Unauthorized,
    /// No placement exists for the requested release.
    UnknownHold,
    /// Identifier already belongs to another import or a different placement request.
    Conflict,
    /// A released identifier cannot be reactivated.
    ReleasedIdentifier,
    /// Approval no longer names the exact prepared transition.
    StaleApproval,
    /// A deletion is already committed but not complete; preservation can no longer be promised.
    DeletionInProgress,
    /// Bounds on retained history or active closures were exhausted; never evict holds.
    Limit,
    /// Missing, corrupt, shadowed, or inconsistent retained authority. Never treated as no hold.
    InvalidRecord,
    /// Cooperative cancellation, including a pre-append staged record.
    Cancelled,
    /// Underlying canonical refusal.
    Contract(ContractError),
    /// Underlying authority/custody refusal.
    Reference(Box<ReferenceError>),
    /// Spool read failed.
    Spool(fss_object::SpoolError),
    /// The named retained import cannot be opened.
    Import(Box<FileIngestError>),
    /// Deletion history cannot be verified, or evidence has already been deleted.
    Deletion(Box<DeletionError>),
}

impl HoldError {
    /// Stable refusal identity declared in the hold contract registry.
    #[must_use]
    pub const fn stable_id(&self) -> &'static str {
        match self {
            Self::Unauthorized => "ERR-AUTH-DENIED-001",
            Self::StaleApproval => "ERR-HOLD-APPROVAL-STALE-001",
            Self::DeletionInProgress => "ERR-HOLD-DELETION-IN-PROGRESS-001",
            Self::InvalidRequest(_) | Self::UnknownHold | Self::Conflict | Self::ReleasedIdentifier => "ERR-HOLD-REQUEST-001",
            Self::Limit => "ERR-HOLD-BOUND-001",
            Self::Cancelled => "ERR-HOLD-CANCELLED-001",
            _ => "ERR-HOLD-STORAGE-001",
        }
    }
}

impl fmt::Display for HoldError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidRequest(why) => write!(f, "invalid evidence hold: {why}"),
            Self::Unauthorized => f.write_str("retention authority denied or mismatched"),
            Self::UnknownHold => f.write_str("no placement exists for this hold identifier"),
            Self::Conflict => f.write_str("hold identifier already names a different request or import"),
            Self::ReleasedIdentifier => f.write_str("released hold identifiers are never reused; choose a new identifier"),
            Self::StaleApproval => f.write_str("hold approval is stale or mismatched; preview the exact transition again"),
            Self::DeletionInProgress => f.write_str("a deletion has started but is incomplete; hold mutation refused"),
            Self::Limit => f.write_str("evidence hold history or active-closure bound exhausted"),
            Self::InvalidRecord => f.write_str("evidence hold authority or custody is inconsistent"),
            Self::Cancelled => f.write_str("evidence hold operation cancelled before commit"),
            Self::Contract(e) => write!(f, "hold contract: {e}"),
            Self::Reference(e) => write!(f, "hold authority: {e}"),
            Self::Spool(e) => write!(f, "hold custody: {e}"),
            Self::Import(e) => write!(f, "hold import: {e}"),
            Self::Deletion(e) => write!(f, "hold deletion history: {e}"),
        }
    }
}
impl std::error::Error for HoldError {}
impl From<ContractError> for HoldError { fn from(e: ContractError) -> Self { Self::Contract(e) } }
impl From<ReferenceError> for HoldError { fn from(e: ReferenceError) -> Self { Self::Reference(Box::new(e)) } }
impl From<fss_object::SpoolError> for HoldError { fn from(e: fss_object::SpoolError) -> Self { Self::Spool(e) } }
impl From<FileIngestError> for HoldError { fn from(e: FileIngestError) -> Self { Self::Import(Box::new(e)) } }
impl From<DeletionError> for HoldError { fn from(e: DeletionError) -> Self { Self::Deletion(Box::new(e)) } }

fn hex(digest: ContentDigest) -> String {
    digest.bytes().iter().map(|b| format!("{b:02x}")).collect()
}
fn checkpoint(cx: &ReplayCx, stage: &'static str) -> Result<(), HoldError> {
    cx.checkpoint(stage).map_err(|_| HoldError::Cancelled)
}
fn authorize(deployment: &ReferenceDeployment, authority: &ContextAuthority, cx: &ReplayCx, cap: &str) -> Result<(), HoldError> {
    authority.validate()?;
    checkpoint(cx, STAGE_HOLD_READ)?;
    if cx.root_dir() != deployment.root() || !authority.has_capability(cap) || authority.cancellation_reason.is_some()
        || authority.anchor_universe != ContentDigest::sha256(deployment.site_lineage().as_bytes())
        || authority.principal.len() > 256 || deployment.site_lineage().len() > 256
    {
        return Err(HoldError::Unauthorized);
    }
    Ok(())
}

/// Preparation/commit result. `Proposed` changes no retention authority.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HoldOutcome {
    /// Nothing was written; exact approval is required.
    Proposed,
    /// This call appended the authoritative transition.
    Committed,
    /// Exact current request and approval were already committed; no write.
    AlreadyCurrent,
}
impl HoldOutcome {
    /// Stable machine spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self { Self::Proposed => "proposed", Self::Committed => "committed", Self::AlreadyCurrent => "already_current" }
    }
}

/// Exact prepared or committed retention transition.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HoldReceipt {
    /// Immutable record whose approval is required or was consumed.
    pub record: HoldRecord,
    /// Whether authority changed.
    pub outcome: HoldOutcome,
}

#[derive(Default)]
pub(super) struct HoldIndex {
    current: BTreeMap<String, HoldRecord>,
}
impl HoldIndex {
    /// Rebuild solely from validated authoritative batches; never infer missing custody as release.
    pub(super) fn read(deployment: &ReferenceDeployment, cx: &ReplayCx) -> Result<Self, HoldError> {
        checkpoint(cx, STAGE_HOLD_READ)?;
        let mut index = Self::default();
        let mut records = 0;
        for batch in deployment.ledger().batches() {
            checkpoint(cx, STAGE_HOLD_READ)?;
            for delta in &batch.deltas {
                if delta.family != FAMILY_EVIDENCE_HOLD
                    && !delta.object_id.as_str().starts_with(HOLD_OBJECT_PREFIX)
                { continue; }
                records += 1;
                if records > MAX_HOLDS * 2 { return Err(HoldError::Limit); }
                let bytes = deployment.publisher().spool().read(delta.payload_digest)?;
                let record = HoldRecord::from_bytes(&bytes, delta.payload_digest)?;
                if record.site != deployment.site_lineage()
                    || record.basis != batch.basis_anchor
                    || batch.deltas.len() != 1
                    || *delta != record.delta()?
                    || batch.batch_id != record.batch_id()?
                    || batch.children != record.children()
                { return Err(HoldError::InvalidRecord); }
                let prior = index.current.get(&record.request.hold_id);
                match (prior, record.request.state) {
                    (None, HoldState::Held) => {
                        if index.current.len() == MAX_HOLDS { return Err(HoldError::Limit); }
                    }
                    (Some(prior), HoldState::Released)
                        if prior.request.state == HoldState::Held
                            && prior.request.import_identity == record.request.import_identity
                            && record.predecessor == Some(prior.digest()) => {}
                    _ => return Err(HoldError::InvalidRecord),
                }
                index.current.insert(record.request.hold_id.clone(), record);
                if index.active_count() > MAX_ACTIVE_HOLDS { return Err(HoldError::Limit); }
            }
        }
        for record in index.current.values() {
            let object = record.object_id()?;
            let current = deployment.ledger().current().objects.get(&object)
                .ok_or(HoldError::InvalidRecord)?;
            if current.family != FAMILY_EVIDENCE_HOLD || current.plane != Plane::Authority
                || current.generation != record.request.state.generation()
                || current.payload_digest != record.digest()
            { return Err(HoldError::InvalidRecord); }
        }
        Ok(index)
    }

    fn active_count(&self) -> usize {
        self.current.values().filter(|r| r.request.state == HoldState::Held).count()
    }

    /// Add blockers for every held closure touched by the requested deletion. No hold means
    /// byte-identical legacy plans. A shared derivative can block deletion of another import.
    pub(super) fn protect(
        &self, universe: &Universe, deployment: &ReferenceDeployment,
        mut plan: DeletionPlan, cx: &ReplayCx,
    ) -> Result<DeletionPlan, DeletionError> {
        let mut closures = BTreeMap::new();
        let removed: BTreeSet<_> = plan.deletable.iter().map(|o| o.digest).collect();
        let retracted: BTreeSet<_> = plan.retractions.iter().map(|r| r.slot.as_str()).collect();
        let tombstoned: BTreeSet<_> = plan.tombstones.iter().map(|t| t.object_id.as_str()).collect();
        for hold in self.current.values().filter(|r| r.request.state == HoldState::Held) {
            checkpoint(cx, STAGE_HOLD_READ)?;
            let held_import = hold.request.import_identity;
            if let std::collections::btree_map::Entry::Vacant(entry) = closures.entry(held_import) {
                entry.insert(universe.plan(deployment, held_import)?);
            }
            let held = closures.get(&held_import).ok_or(HoldError::InvalidRecord)?;
            let overlap = held_import == plan.import_identity
                || held.deletable.iter().any(|o| removed.contains(&o.digest))
                || held.retained.iter().any(|o| removed.contains(&o.digest))
                || held.retractions.iter().any(|r| retracted.contains(r.slot.as_str()))
                || held.tombstones.iter().any(|t| tombstoned.contains(t.object_id.as_str()));
            if overlap {
                plan.blockers.push(Finding {
                    kind: "evidence_hold".to_owned(),
                    subject: hold.request.hold_id.clone(),
                    detail: format!("held import {held_import}; record {}; explicit release required before deleting overlapping evidence", hold.digest()),
                });
            }
        }
        plan.blockers.sort();
        plan.blockers.dedup();
        Ok(plan)
    }
}

/// Lists current records, including terminal releases, in identifier order. Writes nothing.
pub fn list_holds(
    deployment: &ReferenceDeployment, authority: &ContextAuthority, cx: &ReplayCx,
) -> Result<Vec<HoldRecord>, HoldError> {
    authorize(deployment, authority, cx, CAP_HOLD_PREPARE)?;
    Ok(HoldIndex::read(deployment, cx)?.current.into_values().collect())
}

/// Prepare one placement or release at the exact authority head. Never writes custody or history.
pub fn preview_hold(
    deployment: &ReferenceDeployment, request: &HoldRequest,
    authority: &ContextAuthority, cx: &ReplayCx,
) -> Result<HoldReceipt, HoldError> {
    authorize(deployment, authority, cx, CAP_HOLD_PREPARE)?;
    request.validate()?;
    checkpoint(cx, STAGE_HOLD_READ)?;
    let index = HoldIndex::read(deployment, cx)?;
    let prior = index.current.get(&request.hold_id);
    if let Some(record) = prior {
        if record.request.import_identity != request.import_identity { return Err(HoldError::Conflict); }
        if record.request == *request && record.principal == authority.principal {
            return Ok(HoldReceipt { record: record.clone(), outcome: HoldOutcome::AlreadyCurrent });
        }
    }
    let predecessor = match (prior, request.state) {
        (None, HoldState::Released) => return Err(HoldError::UnknownHold),
        (Some(record), _) if record.request.state == HoldState::Released => return Err(HoldError::ReleasedIdentifier),
        (Some(_), HoldState::Held) => return Err(HoldError::Conflict),
        (Some(record), HoldState::Released) => Some(record.digest()),
        (None, HoldState::Held) => {
            if index.current.len() == MAX_HOLDS || index.active_count() == MAX_ACTIVE_HOLDS {
                return Err(HoldError::Limit);
            }
            None
        }
    };
    let deletions = DeletionIndex::read(deployment)?;
    if deletions.entries().iter().any(|entry| !entry.is_complete()) {
        return Err(HoldError::DeletionInProgress);
    }
    if let Some(entry) = deletions.import(request.import_identity) {
        return Err(DeletionError::EvidenceDeleted {
            import: request.import_identity, plan: entry.plan_digest,
        }.into());
    }
    RetainedFileImport::open(deployment, request.import_identity, RetainedReadLimits::default(), cx)?;
    let record = HoldRecord {
        request: request.clone(), principal: authority.principal.clone(),
        site: deployment.site_lineage().to_owned(), basis: deployment.current_anchor().clone(), predecessor,
    };
    if record.to_bytes().len() > MAX_HOLD_RECORD_BYTES { return Err(HoldError::Limit); }
    Ok(HoldReceipt { record, outcome: HoldOutcome::Proposed })
}

/// Commit an exact, freshly revalidated retention transition. A retry of the last identical
/// request requires its original approval and never appends again. Release does not delete bytes.
pub fn commit_hold(
    deployment: &mut ReferenceDeployment, request: &HoldRequest, approval: ContentDigest,
    authority: &ContextAuthority, cx: &ReplayCx,
) -> Result<HoldReceipt, HoldError> {
    authorize(deployment, authority, cx, CAP_HOLD_COMMIT)?;
    let mut receipt = preview_hold(deployment, request, authority, cx)?;
    if approval != receipt.record.approval() { return Err(HoldError::StaleApproval); }
    if receipt.outcome == HoldOutcome::AlreadyCurrent { return Ok(receipt); }
    checkpoint(cx, STAGE_HOLD_REVALIDATED)?;
    let record = &receipt.record;
    let digest = deployment.stage_payload(&record.to_bytes())?;
    if digest != record.digest() { return Err(HoldError::InvalidRecord); }
    checkpoint(cx, STAGE_HOLD_STAGED)?;
    deployment.append_evidence_hold_batch(record.batch_id()?, vec![record.delta()?], record.children(), cx)?;
    receipt.outcome = HoldOutcome::Committed;
    cx.checkpoint_post_commit(STAGE_HOLD_COMMITTED);
    Ok(receipt)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn record() -> HoldRecord {
        HoldRecord {
            request: HoldRequest { hold_id: "incident-7".into(), import_identity: ContentDigest::sha256(b"import"), state: HoldState::Held, reason: "Preserve incident evidence".into() },
            principal: "principal:owner".into(), site: "site:hold".into(),
            basis: LedgerAnchor::genesis("site:hold"), predecessor: None,
        }
    }

    #[test]
    fn canonical_hold_roundtrip_and_mutation_rejection() -> Result<(), HoldError> {
        let r = record();
        let bytes = r.to_bytes();
        assert_eq!(HoldRecord::from_bytes(&bytes, r.digest())?, r);
        for offset in 0..bytes.len() {
            let mut changed = bytes.clone(); changed[offset] ^= 1;
            assert!(HoldRecord::from_bytes(&changed, r.digest()).is_err());
        }
        let mut suffix = bytes.clone(); suffix.push(0);
        assert!(HoldRecord::from_bytes(&suffix, ContentDigest::sha256(&suffix)).is_err());
        for length in 0..bytes.len() {
            assert!(HoldRecord::from_bytes(&bytes[..length], ContentDigest::sha256(&bytes[..length])).is_err());
        }
        Ok(())
    }

    #[test]
    fn approval_binds_scope_reason_actor_anchor_and_transition() {
        let original = record();
        let mut variants = Vec::new();
        let mut r = original.clone(); r.request.hold_id.push('x'); variants.push(r);
        let mut r = original.clone(); r.request.import_identity = ContentDigest::sha256(b"other"); variants.push(r);
        let mut r = original.clone(); r.request.reason.push('!'); variants.push(r);
        let mut r = original.clone(); r.principal.push('x'); variants.push(r);
        let mut r = original.clone(); r.basis.commit_sequence += 1; variants.push(r);
        let mut r = original.clone(); r.request.state = HoldState::Released; r.predecessor = Some(original.digest()); variants.push(r);
        assert!(variants.iter().all(|r| r.approval() != original.approval()));
    }

    #[test]
    fn lifecycle_shape_and_request_bounds_fail_closed() {
        let original = record();
        for id in ["", "has space", "a:b", "../../hold", "unicodé"] {
            let mut request = original.request.clone(); request.hold_id = id.into();
            assert!(request.validate().is_err());
        }
        for reason in ["".to_owned(), "  ".to_owned(), "line\nbreak".to_owned(), "x".repeat(513)] {
            let mut request = original.request.clone(); request.reason = reason;
            assert!(request.validate().is_err());
        }
        let mut released = original.clone(); released.request.state = HoldState::Released;
        let bytes = released.to_bytes();
        assert!(HoldRecord::from_bytes(&bytes, ContentDigest::sha256(&bytes)).is_err());
        let mut first = original.clone(); first.predecessor = Some(original.digest());
        let bytes = first.to_bytes();
        assert!(HoldRecord::from_bytes(&bytes, ContentDigest::sha256(&bytes)).is_err());
    }
}
