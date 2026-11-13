#![forbid(unsafe_code)]
//! Exact adjacent event-revision changes under current immutable metadata authority.
//!
//! The comparison describes retained declarations, never physical causation or restored old
//! permissions. The latest native orientation and explanation retain their original uncertainty,
//! protected worlds and obligations. No media, model payload, writer or session journal is opened.
//! Verification observes changes cooperatively; it does not create an atomic filesystem lease.

mod wire;

use std::path::Path;

use fss_core::{
    AgentView, BudgetQuantitiesSpec, BudgetVector, CanonicalEncode, CanonicalEncoder,
    ContentDigest, ContractError, DigestAlgorithm, EventHypothesis, EventId, ExplainQuestion,
    ExplainReceipt, LedgerAnchor, Plane, PrincipalId, TimestampNs,
};
use fss_object::ObjectManifest;

use crate::ReplayCx;
use crate::agent_follow::{AnchorToken, snapshot_anchor_token};
use crate::agent_orient::{
    DeploymentOrientation, DeploymentSnapshot, EventExplanation, OrientError, OrientLimits,
    OrientRequest, explain_event, orient_deployment,
};
use crate::ingest::FileIngestError;
use crate::retained_source::{
    ImmutableRetainedReadLimits, ImmutableRetainedSource, RetainedReadUsage, RetainedSource,
};

/// Complete comparison projection, independent of the existing frozen event-record schema.
pub const EVENT_CHANGES_SCHEMA: &str = "fss.event_revision_comparison.v1";
/// Canonical comparison domain; both records, publication witnesses and current scope are bound.
pub const EVENT_CHANGES_DIGEST_DOMAIN: &str = "fss.event_revision_comparison.v1";
/// Immutable comparison policy, never a claim about source availability or physical causation.
pub const EVENT_CHANGES_POLICY: &str = "fss.event_revision_comparison_policy.v1:current-authority;adjacent-current-head;complete-native-records;all-canonical-fields;complete-evidence-edge-identity;current-deletion;no-media-or-physical-causation";
/// Maximum whole JSON projection; no field, edge or uncertainty text is truncated.
pub const MAX_EVENT_CHANGES_REPORT_BYTES: usize = 256 * 1024;
/// Shared metadata allowance, including selected lineage rereads and final verification.
pub const MAX_EVENT_CHANGES_READ_BYTES: usize = 256 * 1024 * 1024;
/// Shared payload-read attempt allowance, not a syscall or CPU measurement.
pub const MAX_EVENT_CHANGES_READ_OBJECTS: usize = 65_536;

/// Exact immutable endpoints. The second endpoint must still be the current lineage head.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EventChangesRequest {
    /// Selected event lineage.
    pub event_id: EventId,
    /// Digest of the current revision's immediate predecessor.
    pub from_revision_digest: ContentDigest,
    /// Exact expected current revision, never a latest alias silently following a successor.
    pub to_revision_digest: ContentDigest,
    /// Audit principal matching the explicit metadata I/O context.
    pub principal: PrincipalId,
    /// Optional exact current authority and effect-prefix precondition.
    pub expected_anchor: Option<AnchorToken>,
    /// Existing explanation view: decision_diff or forensic.
    pub view: AgentView,
    /// Explicit total context allowance; no view is automatically widened.
    pub budget_tokens: Option<u64>,
}

impl EventChangesRequest {
    /// Existing explanation default and maximum, without performing I/O.
    pub fn token_limit(&self) -> Result<u64, EventChangesError> {
        let default = match self.view {
            AgentView::DecisionDiff => self.view.maximum_tokens(),
            AgentView::Forensic => self.view.target_tokens(),
            _ => return Err(failure(EventChangesErrorKind::InvalidRequest)),
        };
        let tokens = self.budget_tokens.unwrap_or(u64::from(default));
        if !(1..=u64::from(self.view.maximum_tokens())).contains(&tokens) {
            return Err(failure(EventChangesErrorKind::InvalidRequest));
        }
        Ok(tokens)
    }

    /// Validate exact scalar identities before storage is touched.
    pub fn validate(&self) -> Result<(), EventChangesError> {
        self.token_limit()?;
        if self.event_id.as_str().len() > fss_core::event::MAX_EVENT_ID_LEN
            || self.from_revision_digest == self.to_revision_digest
            || [self.from_revision_digest, self.to_revision_digest]
                .iter()
                .any(|digest| {
                    digest.algorithm() != DigestAlgorithm::Sha256
                        || digest.is_laboratory()
                        || digest.bytes() == [0; 32]
                })
        {
            return Err(failure(EventChangesErrorKind::InvalidRequest));
        }
        Ok(())
    }
}

/// Caller-narrowable metadata ceilings, shared through final revalidation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EventChangesLimits {
    /// Same native owner allowance for history, canonical metadata and final verification.
    pub read: ImmutableRetainedReadLimits,
}

impl Default for EventChangesLimits {
    fn default() -> Self {
        Self {
            read: ImmutableRetainedReadLimits {
                snapshot: OrientLimits::default(),
                max_read_bytes: MAX_EVENT_CHANGES_READ_BYTES,
                max_read_objects: MAX_EVENT_CHANGES_READ_OBJECTS,
            },
        }
    }
}

impl EventChangesLimits {
    /// Reject empty or widened limits before constructing the immutable owner.
    pub fn validate(&self) -> Result<(), EventChangesError> {
        let maximum = Self::default();
        for (value, ceiling) in [
            (self.read.max_read_bytes, maximum.read.max_read_bytes),
            (self.read.max_read_objects, maximum.read.max_read_objects),
            (
                self.read.snapshot.max_layout_bytes,
                maximum.read.snapshot.max_layout_bytes,
            ),
            (
                self.read.snapshot.max_journal_bytes,
                maximum.read.snapshot.max_journal_bytes,
            ),
            (
                self.read.snapshot.max_object_bytes,
                maximum.read.snapshot.max_object_bytes,
            ),
            (
                self.read.snapshot.max_events,
                maximum.read.snapshot.max_events,
            ),
            (
                self.read.snapshot.max_revisions_per_event,
                maximum.read.snapshot.max_revisions_per_event,
            ),
        ] {
            if value == 0 || value > ceiling {
                return Err(failure(EventChangesErrorKind::InvalidRequest));
            }
        }
        Ok(())
    }

    /// Metadata bytes and payload-read attempts admitted by the caller, never replenished.
    pub fn allowance(&self) -> Result<BudgetVector, EventChangesError> {
        self.validate()?;
        Ok(BudgetVector::from_quantities(BudgetQuantitiesSpec {
            latency_ms: 60_000,
            bytes: self.read.max_read_bytes as u64,
            storage_operations: self.read.max_read_objects as u64,
            ..BudgetQuantitiesSpec::ZERO
        }))
    }
}

/// One changed native canonical field, including complete nested evidence-edge attributes.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EventFieldChange {
    field: &'static str,
    before: String,
    after: String,
}

impl EventFieldChange {
    /// Exact existing EventHypothesis JSON key.
    pub const fn field(&self) -> &'static str {
        self.field
    }
    /// Complete native JSON value before the transition.
    pub fn before_json(&self) -> &str {
        &self.before
    }
    /// Complete native JSON value after the transition.
    pub fn after_json(&self) -> &str {
        &self.after
    }
    /// Complete canonical row; no caller-supplied JSON enters this type.
    pub fn to_json(&self) -> String {
        format!(
            "{{\"after\":{},\"before\":{},\"field\":\"{}\"}}",
            self.after, self.before, self.field
        )
    }
}

/// Complete immutable metadata comparison with both exact publication witnesses.
#[derive(Clone, Debug, PartialEq)]
pub struct EventChangesReport {
    from: EventHypothesis,
    to: EventHypothesis,
    from_root: ContentDigest,
    to_root: ContentDigest,
    from_sequence: u64,
    to_sequence: u64,
    changes: Vec<EventFieldChange>,
    digest: ContentDigest,
    json: String,
}

impl EventChangesReport {
    /// Complete predecessor metadata, never current physical truth.
    pub const fn from(&self) -> &EventHypothesis {
        &self.from
    }
    /// Complete current retained revision metadata.
    pub const fn to(&self) -> &EventHypothesis {
        &self.to
    }
    /// Manifest root published by the predecessor's exact committed authority delta.
    pub const fn from_publication_root(&self) -> ContentDigest {
        self.from_root
    }
    /// Manifest root published by the current revision's exact committed authority delta.
    pub const fn to_publication_root(&self) -> ContentDigest {
        self.to_root
    }
    /// Commit sequence of the predecessor's publication.
    pub const fn from_commit_sequence(&self) -> u64 {
        self.from_sequence
    }
    /// Commit sequence of the current revision's publication.
    pub const fn to_commit_sequence(&self) -> u64 {
        self.to_sequence
    }
    /// Every changed field in lexical order. Unchanged fields remain in both complete records.
    pub fn changes(&self) -> &[EventFieldChange] {
        &self.changes
    }
    /// Canonical comparison identity, including current authority/effect scope.
    pub const fn digest(&self) -> ContentDigest {
        self.digest
    }
    /// Complete JSON projection. Its native integer values are never converted through f64.
    pub fn to_json(&self) -> &str {
        &self.json
    }
}

/// Current verified metadata observation available even when later comparison work refuses.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EventChangesObservation {
    /// Already observed full authority anchor; no renewed source-read authority is implied.
    pub anchor: LedgerAnchor,
    /// Exact authority/effect-prefix token of that observation.
    pub anchor_token: String,
    /// Native evidence watermark, not an invented wall clock.
    pub observed_at: TimestampNs,
    /// Payload usage through the refusal boundary.
    pub read_usage: RetainedReadUsage,
}

/// Cause of a whole-comparison refusal; no partial comparison is returned.
#[derive(Debug)]
pub enum EventChangesErrorKind {
    /// Malformed request, invalid view or widened limits.
    InvalidRequest,
    /// Root or audit principal differs from explicit metadata I/O authority.
    Unauthorized,
    /// No committed lineage names the requested event.
    UnknownEvent,
    /// The expected current revision no longer names the retained head.
    RevisionChanged,
    /// Requested predecessor is not the current revision's immediate predecessor.
    NonAdjacent,
    /// Canonical chain, publication declaration or metadata does not agree.
    InvalidRecord,
    /// Complete comparison exceeds its whole-output bound.
    BudgetExceeded,
    /// The caller's exact authority/effect-prefix pin differs.
    AnchorChanged,
    /// Live cancellation, deadline or I/O checkpoint refused.
    Cancelled,
    /// Existing immutable metadata owner refused custody or a read allowance.
    Source(FileIngestError),
    /// Existing protected orientation or explanation refused.
    Orientation(OrientError),
    /// Native canonical or explanation contract refused.
    Contract(ContractError),
}

/// Typed refusal with optional already verified metadata; never performs fallback I/O.
#[derive(Debug)]
pub struct EventChangesError {
    /// Owning typed reason.
    pub kind: EventChangesErrorKind,
    /// Already observed scope, absent before the first successful immutable snapshot.
    pub observation: Option<EventChangesObservation>,
}

impl EventChangesError {
    /// Existing registered diagnostic identity.
    pub const fn code(&self) -> &'static str {
        match self.kind {
            EventChangesErrorKind::InvalidRequest => "ERR-AGENT-PROTOCOL-001",
            EventChangesErrorKind::Unauthorized | EventChangesErrorKind::Cancelled => {
                "ERR-AUTH-DENIED-001"
            }
            EventChangesErrorKind::UnknownEvent => "ERR-AGENT-EVENT-NOT-FOUND-001",
            EventChangesErrorKind::RevisionChanged
            | EventChangesErrorKind::NonAdjacent
            | EventChangesErrorKind::AnchorChanged => "ERR-AGENT-RESNAPSHOT-001",
            EventChangesErrorKind::BudgetExceeded => "ERR-BUDGET-EXHAUSTED-001",
            _ => "ERR-AGENT-CONTEXT-INCOMPLETE-001",
        }
    }
    /// Stable, payload-free reason; private paths and retained text are not formatted.
    pub const fn reason(&self) -> &'static str {
        match self.kind {
            EventChangesErrorKind::InvalidRequest => "event_changes.invalid_request",
            EventChangesErrorKind::Unauthorized => "event_changes.unauthorized",
            EventChangesErrorKind::UnknownEvent => "event_changes.unknown_event",
            EventChangesErrorKind::RevisionChanged => "event_changes.revision_changed",
            EventChangesErrorKind::NonAdjacent => "event_changes.adjacent_predecessor_required",
            EventChangesErrorKind::InvalidRecord => "event_changes.invalid_record",
            EventChangesErrorKind::BudgetExceeded => "event_changes.over_budget",
            EventChangesErrorKind::AnchorChanged => "event_changes.anchor_changed",
            EventChangesErrorKind::Cancelled => "event_changes.cancelled",
            EventChangesErrorKind::Source(_) => "event_changes.metadata_unavailable",
            EventChangesErrorKind::Orientation(_) => "event_changes.context_unavailable",
            EventChangesErrorKind::Contract(_) => "event_changes.contract_refused",
        }
    }
}
impl std::fmt::Display for EventChangesError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.reason())
    }
}
impl std::error::Error for EventChangesError {}

fn failure(kind: EventChangesErrorKind) -> EventChangesError {
    EventChangesError {
        kind,
        observation: None,
    }
}
fn source(error: FileIngestError) -> EventChangesError {
    failure(EventChangesErrorKind::Source(error))
}

/// Complete comparison plus the unchanged current native protected context.
#[derive(Clone, Debug, PartialEq)]
pub struct DeploymentEventChanges {
    /// Current verified metadata, with aggregate completed read counters.
    pub snapshot: DeploymentSnapshot,
    /// Existing latest orientation, without historical authority substitution.
    pub orientation: DeploymentOrientation,
    /// Existing latest explanation; its own Why receipt remains unchanged.
    pub explanation: EventExplanation,
    /// Complete adjacent transition and exact retained identities.
    pub report: EventChangesReport,
    /// New WhatChanged receipt binding both revisions and the complete comparison.
    pub receipt: ExplainReceipt,
    /// Same canonical identity as report.digest().
    pub comparison_digest: ContentDigest,
    /// Request identity binding exact endpoints, current scope, view and admitted limits.
    pub request_digest: ContentDigest,
    /// Exact current authority/effect-prefix token.
    pub anchor_token: String,
    /// Whole immutable-owner payload usage through final revalidation.
    pub read_usage: RetainedReadUsage,
}

/// Resolve and retain every selected-lineage metadata dependency for final verification.
fn retain_lineage(
    owner: &ImmutableRetainedSource<'_>,
    revisions: &[EventHypothesis],
    maximum: usize,
) -> Result<Vec<(ContentDigest, u64)>, EventChangesError> {
    let event = &revisions[0].event_id;
    let object = format!("object:event:{}", event.as_str());
    let mut publications = Vec::with_capacity(revisions.len());
    for batch in owner.ledger().batches() {
        for delta in &batch.deltas {
            if delta.family != "event_revision" || delta.object_id.as_str() != object {
                continue;
            }
            let revision = revisions
                .get(publications.len())
                .ok_or_else(|| failure(EventChangesErrorKind::InvalidRecord))?;
            if delta.plane != Plane::Authority
                || delta.new_generation != revision.revision
                || delta.prior_generation
                    != revision.revision.checked_sub(1).filter(|prior| *prior != 0)
                || delta.witness_digest != Some(revision.revision_digest())
                || delta.validity != revision.interval
                || delta.operation_id.is_some()
            {
                return Err(failure(EventChangesErrorKind::InvalidRecord));
            }
            let bytes = owner
                .read_object_bounded(delta.payload_digest, maximum)
                .map_err(source)?;
            let manifest = ObjectManifest::from_canonical_bytes(&bytes)
                .map_err(|_| failure(EventChangesErrorKind::InvalidRecord))?;
            let payload = manifest
                .metadata_digest()
                .ok_or_else(|| failure(EventChangesErrorKind::InvalidRecord))?;
            let mut receipts = revision.model_receipts.clone();
            receipts.push(payload);
            receipts.sort_unstable();
            receipts.dedup();
            if manifest.kind() != "event-revision" || manifest.children() != receipts {
                return Err(failure(EventChangesErrorKind::InvalidRecord));
            }
            let retained = owner
                .read_object_bounded(payload, maximum)
                .map_err(source)?;
            if retained != revision.canonical_bytes() {
                return Err(failure(EventChangesErrorKind::InvalidRecord));
            }
            // The witness is independently bound by the canonical record and committed delta.
            // It is a metadata handle, never permission to open model or source children.
            owner
                .check_object_available(revision.revision_digest())
                .map_err(source)?;
            publications.push((delta.payload_digest, batch.new_anchor.commit_sequence));
        }
    }
    if publications.len() != revisions.len() {
        return Err(failure(EventChangesErrorKind::InvalidRecord));
    }
    Ok(publications)
}

fn request_digest(
    request: &EventChangesRequest,
    limits: EventChangesLimits,
    token: &str,
) -> ContentDigest {
    let mut encoder = CanonicalEncoder::new();
    encoder.text("fss.agent_event_changes.request.v1");
    encoder.text(request.event_id.as_str());
    encoder.digest(request.from_revision_digest);
    encoder.digest(request.to_revision_digest);
    request.principal.encode_canonical(&mut encoder);
    encoder.text(request.view.id());
    encoder.bool(request.budget_tokens.is_some());
    encoder.u64(request.budget_tokens.unwrap_or(0));
    encoder.text(token);
    encoder.bool(request.expected_anchor.is_some());
    if let Some(pin) = &request.expected_anchor {
        encoder.text(pin.as_str());
    }
    for value in [
        limits.read.max_read_bytes,
        limits.read.max_read_objects,
        limits.read.snapshot.max_layout_bytes,
        limits.read.snapshot.max_journal_bytes,
        limits.read.snapshot.max_object_bytes,
        limits.read.snapshot.max_events,
        limits.read.snapshot.max_revisions_per_event,
    ] {
        encoder.u64(value as u64);
    }
    ContentDigest::sha256(&encoder.finish())
}

/// Compare the current event revision to its exact immediate predecessor, with no writes.
///
/// ReplayCx binds root/principal metadata I/O, not an inherited ContextAuthority grant set.
/// Canonical transports must admit CAP-AGENT-EXPLAIN-001, bind these limits, and pass their live
/// cancellation/deadline guard. No ReadMedia grant is required or inferred. The shared owner
/// verifies current deletion, selected metadata and the full authority/effect prefix before return.
pub fn explain_event_changes_in_deployment(
    root: &Path,
    request: &EventChangesRequest,
    limits: EventChangesLimits,
    cx: &ReplayCx,
    cancelled: &(impl Fn() -> bool + Sync),
) -> Result<DeploymentEventChanges, EventChangesError> {
    prepare_event_changes_in_deployment(root, request, limits, cx, cancelled)?.finish()
}

/// Nondeliverable comparison prepared under one live immutable metadata owner.
///
/// A transport may construct and bound its protected projection from answer(), but must withhold
/// it until finish() succeeds. Finish performs selected metadata and full-history revalidation
/// under the original allowance. Afterwards only pure serialization of the returned counters and
/// whole-output checking may follow; this guard does not grant an atomic filesystem lease.
pub struct PreparedEventChanges<'a> {
    owner: ImmutableRetainedSource<'a>,
    answer: DeploymentEventChanges,
}

impl PreparedEventChanges<'_> {
    /// Private preview for complete protected rendering and budget admission, not disclosure.
    pub const fn answer(&self) -> &DeploymentEventChanges {
        &self.answer
    }

    /// Finish the live read after rendering admission, or return no deliverable comparison.
    pub fn finish(mut self) -> Result<DeploymentEventChanges, EventChangesError> {
        if let Err(error) = self.owner.revalidate() {
            return Err(EventChangesError {
                kind: EventChangesErrorKind::Source(error),
                observation: Some(EventChangesObservation {
                    anchor: self.answer.snapshot.anchor.clone(),
                    anchor_token: self.answer.anchor_token.clone(),
                    observed_at: self.answer.snapshot.latest_evidence_time,
                    read_usage: self.owner.usage(),
                }),
            });
        }
        let usage = self.owner.usage();
        self.answer.read_usage = usage;
        self.answer.snapshot.bytes_read = usage.read_bytes;
        self.answer.snapshot.files_read = usage.read_objects;
        self.answer.orientation.consumed.bytes = usage.read_bytes;
        self.answer.orientation.consumed.storage_operations = usage.read_objects;
        Ok(self.answer)
    }
}

/// Prepare a complete current-head comparison while retaining its immutable owner for finish.
/// The caller must not disclose answer() before finish() succeeds under the same allowance.
pub fn prepare_event_changes_in_deployment<'a>(
    root: &Path,
    request: &EventChangesRequest,
    limits: EventChangesLimits,
    cx: &'a ReplayCx,
    cancelled: &'a (impl Fn() -> bool + Sync),
) -> Result<PreparedEventChanges<'a>, EventChangesError> {
    request.validate()?;
    limits.validate()?;
    if root != cx.root_dir() || request.principal.as_str() != cx.io_authority().principal() {
        return Err(failure(EventChangesErrorKind::Unauthorized));
    }
    if cancelled() || cx.checkpoint("event_changes:open").is_err() {
        return Err(failure(EventChangesErrorKind::Cancelled));
    }
    let owner = ImmutableRetainedSource::open_cancellable(root, limits.read, cx, cancelled)
        .map_err(source)?;
    let mut observation = EventChangesObservation {
        anchor: owner.snapshot().anchor.clone(),
        anchor_token: snapshot_anchor_token(owner.snapshot()),
        observed_at: owner.snapshot().latest_evidence_time,
        read_usage: owner.usage(),
    };
    let result = (|| {
        let snapshot = owner.snapshot();
        let token = &observation.anchor_token;
        if request
            .expected_anchor
            .as_ref()
            .is_some_and(|pin| pin.as_str() != token)
        {
            return Err(failure(EventChangesErrorKind::AnchorChanged));
        }
        let selected = snapshot
            .event(&request.event_id)
            .ok_or_else(|| failure(EventChangesErrorKind::UnknownEvent))?;
        if selected.event.revision_digest() != request.to_revision_digest
            || selected.revision_digest != request.to_revision_digest
            || selected.revisions.last() != Some(&selected.event)
        {
            return Err(failure(EventChangesErrorKind::RevisionChanged));
        }
        EventHypothesis::verify_chain(&selected.revisions)
            .map_err(|_| failure(EventChangesErrorKind::InvalidRecord))?;
        let prior = selected
            .revisions
            .len()
            .checked_sub(2)
            .ok_or_else(|| failure(EventChangesErrorKind::NonAdjacent))?;
        let from = &selected.revisions[prior];
        if from.revision_digest() != request.from_revision_digest
            || selected.event.supersedes != Some(request.from_revision_digest)
        {
            return Err(failure(EventChangesErrorKind::NonAdjacent));
        }
        let publications = retain_lineage(
            &owner,
            &selected.revisions,
            limits.read.snapshot.max_object_bytes,
        )?;
        let from_publication = publications[prior];
        let to_publication = publications[prior + 1];
        if to_publication != (selected.event_root, selected.committed_sequence) {
            return Err(failure(EventChangesErrorKind::InvalidRecord));
        }
        if cancelled() || cx.checkpoint("event_changes:compile").is_err() {
            return Err(failure(EventChangesErrorKind::Cancelled));
        }
        // Admit the complete metadata projection before spending protected-context work.
        let report = wire::build(
            from,
            &selected.event,
            from_publication,
            to_publication,
            token,
        )?;
        let comparison_digest = report.digest();
        let mut orientation = orient_deployment(
            snapshot,
            &OrientRequest {
                view: AgentView::Brief,
                principal: request.principal.clone(),
                budget_tokens: request
                    .budget_tokens
                    .map(|tokens| tokens.min(u64::from(AgentView::Brief.maximum_tokens()))),
            },
            &limits.read.snapshot,
        )
        .map_err(|error| failure(EventChangesErrorKind::Orientation(error)))?;
        let explanation = explain_event(snapshot, &orientation, &request.event_id)
            .map_err(|error| failure(EventChangesErrorKind::Orientation(error)))?
            .ok_or_else(|| failure(EventChangesErrorKind::UnknownEvent))?;
        let receipt = ExplainReceipt::compile(
            ExplainQuestion::WhatChanged,
            request.to_revision_digest,
            vec![
                comparison_digest,
                request.from_revision_digest,
                request.to_revision_digest,
                from_publication.0,
                to_publication.0,
                snapshot.ledger_root,
                snapshot.effect_journal_root,
                snapshot.anchor.state_root,
            ],
            vec![
                format!(
                    "fss://event/{}/revision/{}",
                    request.event_id.as_str(),
                    from.revision
                ),
                format!(
                    "fss://event/{}/revision/{}",
                    request.event_id.as_str(),
                    selected.event.revision
                ),
            ],
            2,
        )
        .map_err(|error| failure(EventChangesErrorKind::Contract(error)))?;
        let request_digest = request_digest(request, limits, token);
        if cancelled() || cx.checkpoint("event_changes:prepared").is_err() {
            return Err(failure(EventChangesErrorKind::Cancelled));
        }
        let read_usage = owner.usage();
        let mut snapshot = snapshot.clone();
        snapshot.bytes_read = read_usage.read_bytes;
        snapshot.files_read = read_usage.read_objects;
        orientation.consumed.bytes = read_usage.read_bytes;
        orientation.consumed.storage_operations = read_usage.read_objects;
        Ok(DeploymentEventChanges {
            snapshot,
            orientation,
            explanation,
            report,
            receipt,
            comparison_digest,
            request_digest,
            anchor_token: token.clone(),
            read_usage,
        })
    })();
    observation.read_usage = owner.usage();
    let answer = result.map_err(|mut error: EventChangesError| {
        error.observation = Some(observation);
        error
    })?;
    Ok(PreparedEventChanges { owner, answer })
}
