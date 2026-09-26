#![forbid(unsafe_code)]
//! Exact-approval operator review of an existing event, never a new sensor observation.
//!
//! Reviews preserve the complete event lineage, source evidence, model receipts, probability,
//! class, capture uncertainty and open sensor-integrity risks. The only added evidence is an
//! explicitly labelled operator assertion (neutral explanation, or contradiction for rejection).
//! The core event state machine owns all transitions. No urgent exception, corroboration,
//! alert receipt, retention change, or effect reconciliation is manufactured here.
//!
//! Publication is provenance-root first, event authority last. Interrupted provenance publication
//! is retryable while the expected event revision is still current. An exact committed retry is
//! verified, not repaired. Approvals are event-revision-scoped: unrelated ledger appends do not
//! invalidate them, but another event revision or an outstanding effect blocks a new review.

use std::fmt;

use fss_core::event::{EventDecodeError, EventSupersedeParams, MAX_EVENT_ID_LEN, MAX_LINEAGE_DEPTH};
use fss_core::region::ContextAuthority;
use fss_core::{
    CanonicalDecode, CanonicalDecoder, CanonicalEncode, CanonicalEncoder, ContentDigest,
    ContractError, DecisionPath, DigestAlgorithm, EffectState, EventEvidence, EventHypothesis,
    EventId, EventState, EvidenceClass, EvidenceEdgeRelation, LedgerAnchor, PrincipalId,
};
use fss_object::{ObjectError, ObjectManifest, SpoolError};
use fss_publication::SlotName;

use crate::reference_deployment::{FAMILY_EVENT_REVISION, validate_site_lineage};
use crate::{
    ReferenceDeployment, ReferenceError, ReferenceEventReceipt, ReferencePolicyAction,
    ReferencePolicyDecision, ReplayCx,
};

/// Read and preview permission; no event mutation is implied.
pub const CAP_REVIEW_PREPARE: &str = "CAP-EVENT-REVIEW-PREPARE-001";
/// Explicit permission to commit the exact reviewed successor.
pub const CAP_REVIEW_COMMIT: &str = "CAP-EVENT-REVIEW-COMMIT-001";
/// Canonical source-labelled operator statement, not a model or sensor receipt.
pub const REVIEW_DOMAIN: &str = "fss.operator_event_review.v1";
/// Approval binds the statement, proposed event, provenance root and immutable policy.
pub const REVIEW_APPROVAL_DOMAIN: &str = "fss.operator_event_review_approval.v1";
/// Maximum review statement bytes, before decoding.
pub const MAX_REVIEW_RECORD_BYTES: usize = 8_192;
/// Maximum authority batches examined by a single review; refuse, never truncate history.
pub const MAX_REVIEW_LEDGER_BATCHES: usize = 65_536;
/// Maximum total canonical event payload bytes read for one lineage.
pub const MAX_REVIEW_HISTORY_BYTES: usize = 32 * 1024 * 1024;
/// Maximum effect operations examined before a new lifecycle review.
pub const MAX_REVIEW_EFFECT_OPERATIONS: usize = 4_096;
/// Last cancellable boundary before any publication work.
pub const STAGE_REVIEW_REVALIDATED: &str = "event_review:revalidated";
/// Provenance is durable but the successor event has not yet been published.
pub const STAGE_REVIEW_PROVENANCE: &str = "event_review:provenance";
/// Successor is authoritative; cancellation cannot turn it into an apparent failed write.
pub const STAGE_REVIEW_COMMITTED: &str = "event_review:committed";

const POLICY: &[u8] = b"fss.operator_event_review.policy.v1:core-transitions:complete-lineage:\
operator-assertion-only:preserve-source-model-probability-kind-time-tamper:\
no-support-no-urgent-exception-no-effects:outstanding-effects-block-new-review";
const ABSTENTION: &str = "Operator lifecycle review; no sensor corroboration, intent classification or external effect is authorized.";

/// Restricted operator outcomes. Presence/identity and delivered-alert claims are not options.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReviewDisposition {
    /// Keep the event unresolved, with the operator's investigation rationale.
    Investigate,
    /// Operator asserts that the case is resolved; does not assert benignity or delivery.
    Resolve,
    /// Operator asserts that the candidate was benign or erroneous; not verified ground truth.
    Reject,
}

impl ReviewDisposition {
    /// CLI and registry spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self { Self::Investigate => "investigate", Self::Resolve => "resolve", Self::Reject => "reject" }
    }
    /// Destination in the existing canonical event lifecycle.
    #[must_use]
    pub const fn state(self) -> EventState {
        match self { Self::Investigate => EventState::Indeterminate, Self::Resolve => EventState::Resolved, Self::Reject => EventState::Rejected }
    }
    /// Parse only the explicitly supported operator outcomes.
    pub fn parse(text: &str) -> Result<Self, ReviewError> {
        match text {
            "investigate" => Ok(Self::Investigate), "resolve" => Ok(Self::Resolve), "reject" => Ok(Self::Reject),
            _ => Err(ReviewError::InvalidRequest("expected investigate, resolve or reject")),
        }
    }
    /// Whether the core table permits this direct transition, without an urgent exception.
    #[must_use]
    pub fn allowed_from(self, state: EventState) -> bool { state.can_transition_to(self.state(), false) }
}

/// Explicit target and operator rationale. No ambient "latest" revision is accepted on writes.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReviewRequest {
    /// Existing event identity.
    pub event_id: EventId,
    /// Exact revision reviewed by the operator, obtained from a prior read.
    pub expected_revision: ContentDigest,
    /// Requested lifecycle outcome, subject to the core transition table.
    pub disposition: ReviewDisposition,
    /// 1..512 UTF-8 bytes without controls. Do not include secrets or unnecessary personal data.
    pub reason: String,
}
impl ReviewRequest {
    /// Bound the complete request before reading authority.
    pub fn validate(&self) -> Result<(), ReviewError> {
        if self.event_id.as_str().len() > MAX_EVENT_ID_LEN
            || self.expected_revision.algorithm() != DigestAlgorithm::Sha256
            || self.reason.trim().is_empty() || self.reason.len() > 512
            || self.reason.chars().any(char::is_control)
        { return Err(ReviewError::InvalidRequest("invalid event, SHA-256 revision, or bounded nonempty reason")); }
        Ok(())
    }
}

/// Immutable operator assertion tied to the actual predecessor's committed authority.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReviewRecord {
    request: ReviewRequest,
    principal: String,
    site: String,
    previous_event_root: ContentDigest,
    previous_anchor: LedgerAnchor,
}
impl ReviewRecord {
    /// Exact reviewed request.
    #[must_use]
    pub fn request(&self) -> &ReviewRequest { &self.request }
    /// Context principal; an audit label, not proof of remote authentication.
    #[must_use]
    pub fn principal(&self) -> &str { &self.principal }
    /// Exact deployment site.
    #[must_use]
    pub fn site(&self) -> &str { &self.site }
    /// The anchor which actually published the predecessor, not a guessed current time.
    #[must_use]
    pub fn previous_anchor(&self) -> &LedgerAnchor { &self.previous_anchor }
    /// Original retained event root.
    #[must_use]
    pub fn previous_event_root(&self) -> ContentDigest { self.previous_event_root }
    /// Canonical bytes containing the complete attribution and rationale.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut e = CanonicalEncoder::new();
        e.bytes(b"FSSREV01"); e.u32(1); e.text(REVIEW_DOMAIN);
        e.text(self.request.event_id.as_str()); e.digest(self.request.expected_revision);
        e.text(self.request.disposition.as_str()); e.text(&self.request.reason);
        e.text(&self.principal); e.text(&self.site); e.digest(self.previous_event_root);
        self.previous_anchor.encode_canonical(&mut e);
        e.finish()
    }
    /// SHA-256 of the canonical statement.
    #[must_use]
    pub fn digest(&self) -> ContentDigest { ContentDigest::sha256(&self.to_bytes()) }
    /// Verify exact canonical retained bytes, refusing tampering and unknown versions.
    pub fn from_bytes(bytes: &[u8], expected: ContentDigest) -> Result<Self, ReviewError> {
        if bytes.len() > MAX_REVIEW_RECORD_BYTES || ContentDigest::sha256(bytes) != expected {
            return Err(ReviewError::CustodyMismatch);
        }
        let mut d = CanonicalDecoder::new(bytes);
        if d.bytes()? != b"FSSREV01" || d.u32()? != 1 || d.text()? != REVIEW_DOMAIN {
            return Err(ReviewError::CustodyMismatch);
        }
        let request = ReviewRequest {
            event_id: EventId::parse(d.text()?)?, expected_revision: d.digest()?,
            disposition: ReviewDisposition::parse(d.text()?)?, reason: d.text()?.to_owned(),
        };
        let record = Self {
            request, principal: d.text()?.to_owned(), site: d.text()?.to_owned(),
            previous_event_root: d.digest()?, previous_anchor: LedgerAnchor::decode_canonical(&mut d)?,
        };
        d.ensure_finished()?;
        record.request.validate()?;
        PrincipalId::parse(&record.principal)?;
        validate_site_lineage(&record.site)?;
        if record.principal.len() > 256 || record.site.len() > 256
            || record.previous_event_root.algorithm() != DigestAlgorithm::Sha256
            || record.to_bytes() != bytes
        { return Err(ReviewError::CustodyMismatch); }
        Ok(record)
    }
    fn slot(&self) -> Result<SlotName, ReviewError> {
        SlotName::parse(&format!("review-{}", hex(self.digest())))
            .map_err(|_| ReviewError::InvalidRequest("review slot identity"))
    }
    fn manifest(&self) -> Result<ObjectManifest, ReviewError> {
        Ok(ObjectManifest::new(self.slot()?.as_str(), [self.digest(), self.previous_event_root], None)?)
    }
}

/// Read-only exact preview. Its candidate and approval cannot be mutated independently.
#[derive(Clone, Debug)]
pub struct ReviewPreview {
    record: ReviewRecord,
    event: EventHypothesis,
    provenance_root: ContentDigest,
    already_published: bool,
}
impl ReviewPreview {
    /// Operator statement and its original event authority.
    #[must_use]
    pub fn record(&self) -> &ReviewRecord { &self.record }
    /// Proposed or already published successor; not yet effect authority.
    #[must_use]
    pub fn event(&self) -> &EventHypothesis { &self.event }
    /// Root of statement and predecessor event custody.
    #[must_use]
    pub fn provenance_root(&self) -> ContentDigest { self.provenance_root }
    /// Whether the exact successor was already committed.
    #[must_use]
    pub fn already_published(&self) -> bool { self.already_published }
    /// Required approval for precisely this successor and its provenance.
    #[must_use]
    pub fn approval(&self) -> ContentDigest {
        let mut e = CanonicalEncoder::new();
        e.text(REVIEW_APPROVAL_DOMAIN); e.digest(ContentDigest::sha256(POLICY));
        e.digest(self.record.digest()); e.digest(self.event.revision_digest()); e.digest(self.provenance_root);
        ContentDigest::sha256(&e.finish())
    }
}

/// Verified commit result. This never says an alert was sent, cancelled, or reconciled.
#[derive(Clone, Debug)]
pub struct ReviewReceipt {
    /// Exact reviewed candidate and statement.
    pub review: ReviewPreview,
    /// Existing event publisher's authoritative receipt.
    pub authority: ReferenceEventReceipt,
    /// True only when this call published the successor (not an idempotent retry).
    pub published: bool,
}

/// Typed refusals; none before publication is a successful empty review.
#[derive(Debug)]
pub enum ReviewError {
    /// Malformed or unsupported bounded input.
    InvalidRequest(&'static str),
    /// Missing, cancelled, or mismatched explicit review authority.
    Unauthorized,
    /// Expected event revision is no longer the exact current basis or exact current retry.
    StaleRevision,
    /// Approval names another statement or successor.
    StaleApproval,
    /// Outstanding effect work must be reconciled or cancelled through its own owner first.
    OpenEffects,
    /// Source, predecessor or review provenance could not be verified; never auto-repaired.
    CustodyMismatch,
    /// A complete lineage or bounded scan exceeds capacity.
    Limit,
    /// Cooperative pre-commit cancellation.
    Cancelled,
    /// Core state/lineage rejection, preserved rather than bypassed.
    Transition(EventDecodeError),
    /// Shared canonical contract rejection.
    Contract(ContractError),
    /// Existing publication/authority refusal.
    Reference(Box<ReferenceError>),
    /// Manifest construction refusal.
    Object(ObjectError),
    /// Retained custody read failed.
    Spool(SpoolError),
}
impl ReviewError {
    /// Stable identities declared by `registries/event_review.json`.
    #[must_use]
    pub fn stable_id(&self) -> &'static str {
        match self {
            Self::InvalidRequest(_) => "ERR-EVENT-REVIEW-REQUEST-001",
            Self::Unauthorized => "ERR-AUTH-DENIED-001",
            Self::StaleRevision => "ERR-EVENT-REVIEW-REVISION-STALE-001",
            Self::StaleApproval => "ERR-EVENT-REVIEW-APPROVAL-STALE-001",
            Self::OpenEffects => "ERR-EVENT-REVIEW-OPEN-EFFECTS-001",
            Self::Transition(_) => "ERR-EVENT-REVIEW-TRANSITION-001",
            Self::Limit => "ERR-EVENT-REVIEW-BOUND-001",
            Self::Cancelled => "ERR-EVENT-REVIEW-CANCELLED-001",
            _ => "ERR-EVENT-REVIEW-STORAGE-001",
        }
    }
}
impl fmt::Display for ReviewError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidRequest(why) => write!(f, "invalid event review: {why}"),
            Self::Unauthorized => f.write_str("event review authority denied or mismatched"),
            Self::StaleRevision => f.write_str("reviewed event revision is stale; read and review the current revision"),
            Self::StaleApproval => f.write_str("review approval is stale or mismatched; preview this exact request"),
            Self::OpenEffects => f.write_str("outstanding deployment effects block a new review; reconcile or cancel them through their owning effect API"),
            Self::CustodyMismatch => f.write_str("review provenance or event history does not match retained authority"),
            Self::Limit => f.write_str("complete event review history or record exceeds its bound"),
            Self::Cancelled => f.write_str("event review cancelled before successor publication"),
            Self::Transition(e) => write!(f, "event review transition: {e}"),
            Self::Contract(e) => write!(f, "event review contract: {e}"),
            Self::Reference(e) => write!(f, "event review authority: {e}"),
            Self::Object(e) => write!(f, "event review manifest: {e}"),
            Self::Spool(e) => write!(f, "event review custody: {e}"),
        }
    }
}
impl std::error::Error for ReviewError {}
impl From<ContractError> for ReviewError { fn from(e: ContractError) -> Self { Self::Contract(e) } }
impl From<EventDecodeError> for ReviewError { fn from(e: EventDecodeError) -> Self { Self::Transition(e) } }
impl From<ReferenceError> for ReviewError { fn from(e: ReferenceError) -> Self { Self::Reference(Box::new(e)) } }
impl From<ObjectError> for ReviewError { fn from(e: ObjectError) -> Self { Self::Object(e) } }
impl From<SpoolError> for ReviewError { fn from(e: SpoolError) -> Self { Self::Spool(e) } }

fn hex(d: ContentDigest) -> String { d.bytes().iter().map(|b| format!("{b:02x}")).collect() }
fn checkpoint(cx: &ReplayCx, stage: &'static str) -> Result<(), ReviewError> {
    cx.checkpoint(stage).map_err(|_| ReviewError::Cancelled)
}
fn authorize(d: &ReferenceDeployment, a: &ContextAuthority, cx: &ReplayCx, cap: &str) -> Result<(), ReviewError> {
    a.validate()?;
    checkpoint(cx, "event_review:authority")?;
    if !a.has_capability(cap) || a.cancellation_reason.is_some() || cx.root_dir() != d.root()
        || a.anchor_universe != ContentDigest::sha256(d.site_lineage().as_bytes())
        || a.principal.len() > 256 || d.site_lineage().len() > 256
    { return Err(ReviewError::Unauthorized); }
    Ok(())
}

struct Revision { event: EventHypothesis, root: ContentDigest, anchor: LedgerAnchor }
fn history(d: &ReferenceDeployment, id: &EventId, cx: &ReplayCx) -> Result<Vec<Revision>, ReviewError> {
    if d.ledger().batches().len() > MAX_REVIEW_LEDGER_BATCHES { return Err(ReviewError::Limit); }
    let object_id = format!("object:event:{}", id.as_str());
    let mut history = Vec::new();
    let mut used = 0_usize;
    for batch in d.ledger().batches() {
        checkpoint(cx, "event_review:history")?;
        for delta in &batch.deltas {
            if delta.object_id.as_str() != object_id { continue; }
            if delta.family != FAMILY_EVENT_REVISION { return Err(ReviewError::CustodyMismatch); }
            if history.len() >= MAX_LINEAGE_DEPTH { return Err(ReviewError::Limit); }
            let manifest_bytes = d.publisher().spool().read(delta.payload_digest)?;
            used = used.checked_add(manifest_bytes.len()).ok_or(ReviewError::Limit)?;
            if used > MAX_REVIEW_HISTORY_BYTES { return Err(ReviewError::Limit); }
            let manifest = ObjectManifest::from_canonical_bytes(&manifest_bytes)?;
            let payload = manifest.metadata_digest().ok_or(ReviewError::CustodyMismatch)?;
            let bytes = d.publisher().spool().read(payload)?;
            used = used.checked_add(bytes.len()).ok_or(ReviewError::Limit)?;
            if used > MAX_REVIEW_HISTORY_BYTES { return Err(ReviewError::Limit); }
            let event = EventHypothesis::from_canonical_bytes(&bytes)?;
            if event.event_id != *id || event.revision != history.len() as u64 + 1
                || delta.new_generation != event.revision
                || delta.witness_digest != Some(event.revision_digest())
            { return Err(ReviewError::CustodyMismatch); }
            history.push(Revision { event, root: delta.payload_digest, anchor: batch.new_anchor.clone() });
        }
    }
    Ok(history)
}

/// Read the current event through the same guarded authority path used by publication.
/// This reads retained event metadata, not original media or a reconstructed model result.
pub fn read_review_event(
    deployment: &ReferenceDeployment, event: &EventId, authority: &ContextAuthority, cx: &ReplayCx,
) -> Result<(EventHypothesis, ReferenceEventReceipt), ReviewError> {
    authorize(deployment, authority, cx, CAP_REVIEW_PREPARE)?;
    if event.as_str().len() > MAX_EVENT_ID_LEN || deployment.ledger().batches().len() > MAX_REVIEW_LEDGER_BATCHES {
        return Err(ReviewError::Limit);
    }
    let _ = history(deployment, event, cx)?;
    Ok(deployment.current_event_authority(event)?)
}

fn derive(record: ReviewRecord, chain: &[EventHypothesis]) -> Result<ReviewPreview, ReviewError> {
    let prior = chain.last().ok_or(ReviewError::CustodyMismatch)?;
    if !record.request.disposition.allowed_from(prior.state) {
        return Err(ReviewError::Transition(EventDecodeError::Contradiction {
            field: "state", detail: format!("operator review cannot transition {} to {}", prior.state.as_str(), record.request.disposition.state().as_str()),
        }));
    }
    if record.to_bytes().len() > MAX_REVIEW_RECORD_BYTES { return Err(ReviewError::Limit); }
    if chain.len() >= MAX_LINEAGE_DEPTH { return Err(ReviewError::Limit); }
    let root = record.manifest()?.root();
    let mut evidence = prior.evidence.clone();
    evidence.push(EventEvidence {
        digest: record.digest(), class: EvidenceClass::Assertion,
        failure_domain: format!("operator-review:{}", hex(ContentDigest::sha256(record.principal.as_bytes()))),
        supports: false,
        relation: if record.request.disposition == ReviewDisposition::Reject { EvidenceEdgeRelation::Contradicts } else { EvidenceEdgeRelation::Explains },
        capsule_digest: None, identity_digest: Some(ContentDigest::sha256(record.principal.as_bytes())),
    });
    let event = prior.supersede(EventSupersedeParams {
        state: record.request.disposition.state(), kind: prior.kind, interval: prior.interval,
        uncertainty_reason: prior.uncertainty_reason.clone(), zone_ids: prior.zone_ids.clone(),
        track_ids: prior.track_ids.clone(), probability: prior.probability, evidence,
        model_receipts: prior.model_receipts.clone(),
        decision_path: DecisionPath {
            policy_generation: ContentDigest::sha256(POLICY), fingerprint: root,
            abstained: true, abstention_reason: Some(ABSTENTION.to_owned()),
        },
    }, chain)?;
    Ok(ReviewPreview { record, event, provenance_root: root, already_published: false })
}

fn verify_provenance(d: &ReferenceDeployment, preview: &ReviewPreview) -> Result<(), ReviewError> {
    let record = &preview.record;
    let slot = record.slot()?;
    let visible = d.publisher().root(&slot).ok_or(ReviewError::CustodyMismatch)?;
    if visible.root != preview.provenance_root { return Err(ReviewError::CustodyMismatch); }
    let root = d.publisher().spool().read(preview.provenance_root)?;
    if root != record.manifest()?.canonical_bytes() { return Err(ReviewError::CustodyMismatch); }
    let bytes = d.publisher().spool().read(record.digest())?;
    if ReviewRecord::from_bytes(&bytes, record.digest())? != *record { return Err(ReviewError::CustodyMismatch); }
    // Verify the exact original event root too; an idempotent read is not a repair mechanism.
    d.publisher().spool().read(record.previous_event_root)?;
    Ok(())
}

fn effect_blocks_review(state: EffectState) -> bool {
    !matches!(state, EffectState::Verified | EffectState::Failed | EffectState::Cancelled)
}

/// Construct an exact, non-authorizing successor. The core validates the complete lineage.
pub fn preview_review(
    deployment: &ReferenceDeployment, request: &ReviewRequest,
    authority: &ContextAuthority, cx: &ReplayCx,
) -> Result<ReviewPreview, ReviewError> {
    authorize(deployment, authority, cx, CAP_REVIEW_PREPARE)?;
    request.validate()?;
    let history = history(deployment, &request.event_id, cx)?;
    let current = history.last().ok_or(ReviewError::StaleRevision)?;
    let retry = current.event.revision_digest() != request.expected_revision;
    let index = if retry {
        if current.event.supersedes != Some(request.expected_revision) { return Err(ReviewError::StaleRevision); }
        history.len().checked_sub(2).ok_or(ReviewError::StaleRevision)?
    } else { history.len() - 1 };
    let prior = &history[index];
    if prior.event.revision_digest() != request.expected_revision { return Err(ReviewError::StaleRevision); }
    let chain: Vec<_> = history[..=index].iter().map(|r| r.event.clone()).collect();
    let record = ReviewRecord {
        request: request.clone(), principal: authority.principal.clone(), site: deployment.site_lineage().to_owned(),
        previous_event_root: prior.root, previous_anchor: prior.anchor.clone(),
    };
    let mut preview = derive(record, &chain)?;
    // Recheck the current authority and accumulated tamper through the existing owner as well.
    let (authoritative, _) = deployment.current_event_authority(&request.event_id)?;
    if authoritative != current.event { return Err(ReviewError::CustodyMismatch); }
    if retry {
        if preview.event.canonical_bytes() != current.event.canonical_bytes() { return Err(ReviewError::StaleRevision); }
        verify_provenance(deployment, &preview)?;
        preview.already_published = true;
    } else {
        for (index, operation) in deployment.effects().operations().enumerate() {
            checkpoint(cx, "event_review:effects")?;
            if index >= MAX_REVIEW_EFFECT_OPERATIONS { return Err(ReviewError::Limit); }
            // Conservative across the deployment, including unrelated outstanding effects.
            if effect_blocks_review(operation.state) { return Err(ReviewError::OpenEffects); }
        }
    }
    checkpoint(cx, "event_review:prepared")?;
    Ok(preview)
}

/// Revalidate and publish under exact approval. The deployment's exclusive lock owns the whole
/// operation. No fallible work follows the event commit, and an exact retry never appends again.
pub fn commit_review(
    deployment: &mut ReferenceDeployment, request: &ReviewRequest, approval: ContentDigest,
    authority: &ContextAuthority, cx: &ReplayCx,
) -> Result<ReviewReceipt, ReviewError> {
    authorize(deployment, authority, cx, CAP_REVIEW_COMMIT)?;
    let preview = preview_review(deployment, request, authority, cx)?;
    if approval != preview.approval() { return Err(ReviewError::StaleApproval); }
    if preview.already_published {
        let (_, receipt) = deployment.current_event_authority(&request.event_id)?;
        return Ok(ReviewReceipt { review: preview, authority: receipt, published: false });
    }
    checkpoint(cx, STAGE_REVIEW_REVALIDATED)?;
    let record = &preview.record;
    let bytes = record.to_bytes();
    let previous = deployment.publisher().spool().read(record.previous_event_root)?;
    let slot = record.slot()?;
    if let Some(visible) = deployment.publisher().root(&slot) {
        if visible.root != preview.provenance_root { return Err(ReviewError::CustodyMismatch); }
        verify_provenance(deployment, &preview)?;
    } else {
        let staged = deployment.stage_and_publish(&slot, &[&bytes, &previous], cx)?;
        if staged.root != preview.provenance_root { return Err(ReviewError::CustodyMismatch); }
    }
    // Reconcile root visibility with ledger reachability even after a root-rename/journal cut.
    // The existing publisher makes an already ledgered identical root an exact retry.
    deployment.publish_and_commit(&slot, &record.manifest()?, preview.event.interval, cx)?;
    checkpoint(cx, STAGE_REVIEW_PROVENANCE)?;
    let receipt = deployment.publish_event(&ReferencePolicyDecision {
        event: preview.event.clone(), action: ReferencePolicyAction::Hold,
    }, cx)?;
    cx.checkpoint_post_commit(STAGE_REVIEW_COMMITTED);
    Ok(ReviewReceipt { review: preview, authority: receipt, published: true })
}

#[cfg(test)]
mod tests;
