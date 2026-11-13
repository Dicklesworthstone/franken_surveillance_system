#![forbid(unsafe_code)]
//! Exact retained-event metadata hydration through the deployment's sole session owner.
//!
//! H0 discovers the native immutable descriptor for an explicitly selected event revision.
//! H1 requires that descriptor and preserves the native synopsis/receipt without reading media.
//! Each delivered level commits its token charge and continuation state in the existing session
//! journal. A later refusal may withhold the payload, but never refunds a committed disclosure.

use std::fmt;
use std::path::Path;

use fss_core::{
    AgentSession, AgentView, BudgetVector, ContentDigest, ContextAuthority, ContinuationCursor,
    DigestAlgorithm, EventId, HydrationError, HydrationLevel, HydrationPurpose, HydrationRequest,
    HydrationRequestSpec, HydrationResponse, LedgerAnchor, OperationId, PrincipalId,
    RootAuthoritySpec, SemanticHandle, SessionId, TimestampNs,
};

use super::orient::{
    OrientSessionRequest, project_session_read, with_admitted_session_metadata_read,
};
use super::{DeploymentSessionError, SessionJournal, ensure_agent_writable, evidence_now};
use crate::agent_event_hydration::{
    EventHydrationBuildError, MAX_EVENT_HYDRATION_READ_BYTES, MAX_EVENT_HYDRATION_READ_OBJECTS,
    build_event_hydration_catalog, event_hydration_cost,
};
use crate::agent_follow::{AnchorToken, snapshot_anchor_token};
use crate::agent_orient::{
    DeploymentOrientation, EventExplanation, MetadataReadBudget, OrientLimits,
};
use crate::agent_session::checkpoint::journal::DurableSessionError;
use crate::agent_session::checkpoint::journal::disclosure::DisclosureError;
use crate::agent_session::{SessionAlias, SessionBindingRequest};
use crate::ingest::FileIngestError;
use crate::retained_source::{
    ImmutableRetainedReadLimits, ImmutableRetainedSource, RetainedSource,
};
use crate::{ADP_REPLAY_ROW_ID, ReplayCx};

/// The richest supported response quote. Original media and laboratory levels are unavailable.
pub const MAX_EVIDENCE_HYDRATION_TOKENS: u64 = 16_000;
/// Stored session grant, never a transport-supplied capability.
pub const EVIDENCE_HYDRATION_CAPABILITY: &str = "CAP-AGENT-EVIDENCE-HYDRATE-001";
/// Existing AOP-005 read grant required alongside the exact hydration grant.
pub const EVIDENCE_QUERY_CAPABILITY: &str = "CAP-AGENT-QUERY-001";

/// One exact event revision at the current, unchanged session basis.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EvidenceHydrationRequest {
    /// Existing live session, independently bound to `principal`.
    pub session_id: SessionId,
    /// Locally admitted owner identity; a session ID grants no authority by itself.
    pub principal: PrincipalId,
    /// Current symbol-table generation; no implicit refresh or rebase occurs.
    pub generation: u64,
    /// Event selected through the existing query/explanation surface.
    pub event_id: EventId,
    /// Exact canonical revision digest, distinct from its publication manifest root.
    pub expected_revision: ContentDigest,
    /// Exact complete authority and effect-journal position.
    pub expected_anchor: AnchorToken,
    /// Required for H1; absent only for a first H0 identity discovery without continuation.
    pub expected_descriptor: Option<ContentDigest>,
    /// H0 identity or H1 semantic synopsis only.
    pub level: HydrationLevel,
    /// Per-invocation ceiling within the unchanged cumulative session grant.
    pub budget_tokens: u64,
    /// Complete native cursor from a previous receipt; never reconstructed or newly issued here.
    pub continuation: Option<ContinuationCursor>,
}

impl EvidenceHydrationRequest {
    /// Refuses malformed scalar scope before any deployment/session read.
    pub fn validate(&self) -> Result<(), EvidenceHydrationError> {
        let digest_valid = |digest: ContentDigest| {
            digest.algorithm() == DigestAlgorithm::Sha256 && digest.bytes() != [0; 32]
        };
        if self.generation == 0
            || !digest_valid(self.expected_revision)
            || self
                .expected_descriptor
                .is_some_and(|digest| !digest_valid(digest))
            || self.event_id.as_str().len() > fss_core::event::MAX_EVENT_ID_LEN
            || !(1..=MAX_EVIDENCE_HYDRATION_TOKENS).contains(&self.budget_tokens)
            || (self.continuation.is_some() && self.level != HydrationLevel::H1)
            || (self.expected_descriptor.is_none()
                && (self.level != HydrationLevel::H0 || self.continuation.is_some()))
        {
            return Err(EvidenceHydrationError::InvalidRequest);
        }
        if !matches!(self.level, HydrationLevel::H0 | HydrationLevel::H1) {
            return Err(EvidenceHydrationError::Hydration(
                HydrationError::LevelUnavailable,
            ));
        }
        if self.budget_tokens < event_hydration_cost(self.level)?.tokens {
            return Err(EvidenceHydrationError::Hydration(
                HydrationError::BudgetExceeded,
            ));
        }
        Ok(())
    }
}

/// A definitely committed disclosure charge, including after a later refusal.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EvidenceHydrationCharge {
    /// Journal root containing both the token debit and exact cursor transition.
    pub journal_root: ContentDigest,
    /// Canonical authority basis at admission, not a claim of freshness after a failure.
    pub anchor: LedgerAnchor,
    /// Evidence-clock observation retained by the charge.
    pub observed_at: TimestampNs,
    /// Native descriptor quote, not a measurement of model or transport tokens.
    pub charged_tokens: u64,
    /// Cumulative session allowance after the committed debit; never refunded on response loss.
    pub remaining_tokens: u64,
}

/// Complete native result withheld until journal and selected metadata revalidation finish.
#[derive(Clone, Debug, PartialEq)]
pub struct EvidenceHydrationAnswer {
    /// Unchanged admitted session authority, including its generation and expiry.
    pub session: AgentSession,
    /// Protected deployment/session context; no selected event suppresses unrelated obligations.
    pub orientation: DeploymentOrientation,
    /// Exact native descriptor, stable for this revision, anchor, policy and session expiry.
    pub descriptor: SemanticHandle,
    /// Bound session-local symbol; raw descriptor identity remains alongside it.
    pub alias: SessionAlias,
    /// Request constructed only from stored grants and the verified current descriptor.
    pub request: HydrationRequest,
    /// Unchanged native artifact and receipt, including a complete progressive cursor if issued.
    pub response: HydrationResponse,
    /// Original typed explanation retains uncertainty, counterevidence and residual worlds.
    pub explanation: EventExplanation,
    /// Existing event-revision URI, distinct from the descriptor's semantic-handle identity.
    pub event_handle: String,
    /// Full committed authority/effect position used for this read.
    pub anchor_token: AnchorToken,
    /// Journal root containing the durable disclosure.
    pub journal_root: ContentDigest,
    /// Quote consumed by this exact delivery.
    pub charged_tokens: u64,
    /// Lifetime session tokens remaining after this delivery.
    pub remaining_tokens: u64,
}

impl EvidenceHydrationAnswer {
    /// Registered composite response retaining the native descriptor, receipt and artifact.
    pub const SCHEMA: &'static str = "fss.agent_evidence_hydration.v1";
}

/// Payload-free admission, current-custody or durable-session failure.
#[derive(Debug)]
pub enum EvidenceHydrationError {
    /// Malformed or incomplete explicit request scope.
    InvalidRequest,
    /// Cancellation/deadline before the final authority observation.
    Cancelled,
    /// Current session, workspace, generation, grant or pinned journal refused the request.
    Session(DeploymentSessionError),
    /// Selected complete authority/effect prefix changed; explicit rebase is required.
    Stale,
    /// Exact metadata/descriptor reconstruction refused.
    Catalog(EventHydrationBuildError),
    /// Native level, budget, descriptor or continuation contract refused.
    Hydration(HydrationError),
    /// Existing atomic journal transaction could not deliver a durable answer.
    Disclosure(DisclosureError),
    /// Current retained metadata custody or bounded read refused.
    Source(FileIngestError),
}

impl EvidenceHydrationError {
    /// Existing stable refusal identities; no source values appear in this diagnostic.
    pub fn code(&self) -> &'static str {
        match self {
            Self::InvalidRequest => "ERR-CLI-MALFORMED-VALUE-001",
            Self::Cancelled => "ERR-OP-CANCELLED-001",
            Self::Stale => "ERR-AGENT-RESNAPSHOT-001",
            Self::Hydration(error) => error.code(),
            Self::Catalog(_) => "ERR-AGENT-CONTEXT-INCOMPLETE-001",
            Self::Session(_) => "ERR-AUTH-DENIED-001",
            Self::Disclosure(_) => "ERR-AGENT-CONTEXT-INCOMPLETE-001",
            Self::Source(error) => error
                .stable_id()
                .unwrap_or("ERR-AGENT-CONTEXT-INCOMPLETE-001"),
        }
    }
}
impl fmt::Display for EvidenceHydrationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.code())
    }
}
impl std::error::Error for EvidenceHydrationError {}
impl From<DeploymentSessionError> for EvidenceHydrationError {
    fn from(value: DeploymentSessionError) -> Self {
        Self::Session(value)
    }
}
impl From<DurableSessionError> for EvidenceHydrationError {
    fn from(value: DurableSessionError) -> Self {
        Self::Session(value.into())
    }
}
impl From<EventHydrationBuildError> for EvidenceHydrationError {
    fn from(value: EventHydrationBuildError) -> Self {
        Self::Catalog(value)
    }
}
impl From<HydrationError> for EvidenceHydrationError {
    fn from(value: HydrationError) -> Self {
        Self::Hydration(value)
    }
}
impl From<DisclosureError> for EvidenceHydrationError {
    fn from(value: DisclosureError) -> Self {
        Self::Disclosure(value)
    }
}
impl From<FileIngestError> for EvidenceHydrationError {
    fn from(value: FileIngestError) -> Self {
        if matches!(&value, FileIngestError::CancellationRequested { .. }) {
            Self::Cancelled
        } else {
            Self::Source(value)
        }
    }
}

/// Historical metadata observation usable for a payload-free refusal, never a session grant.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EvidenceHydrationObservation {
    /// Verified metadata anchor observed during admission, without a later freshness claim.
    pub anchor: LedgerAnchor,
    /// Evidence-clock observation at that anchor.
    pub observed_at: TimestampNs,
}

/// Refusal never contains hydrated payload. A known charge survives post-commit failures.
#[derive(Debug)]
pub struct EvidenceHydrationFailure {
    /// Native refusal reason.
    pub error: EvidenceHydrationError,
    /// Definitely committed charge, if the failure occurred after synchronized disclosure.
    pub committed: Option<EvidenceHydrationCharge>,
    /// An already observed metadata anchor; rendering must not open another reader on failure.
    pub observed: Option<EvidenceHydrationObservation>,
}
impl fmt::Display for EvidenceHydrationFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.error.fmt(f)
    }
}
impl std::error::Error for EvidenceHydrationFailure {}

fn cancelled_check(cancelled: &(dyn Fn() -> bool + Sync)) -> Result<(), EvidenceHydrationError> {
    if cancelled() {
        Err(EvidenceHydrationError::Cancelled)
    } else {
        Ok(())
    }
}

// Snapshot reconstruction verifies canonical metadata, but the immutable owner's explicit
// object set must retain the selected lineage for every later revalidation. The event's whole
// revision history contributes to sticky tamper/uncertainty, so checking only its latest manifest
// would omit a dependency of the delivered explanation. This reads no model or media child.
fn retain_event_custody(
    owner: &ImmutableRetainedSource<'_>,
    event: &EventId,
) -> Result<(), EvidenceHydrationError> {
    let object_id = format!("object:event:{}", event.as_str());
    let maximum = OrientLimits::default().max_object_bytes;
    for batch in owner.ledger().batches() {
        for delta in &batch.deltas {
            if delta.family != "event_revision" || delta.object_id.as_str() != object_id {
                continue;
            }
            let bytes = owner.read_object_bounded(delta.payload_digest, maximum)?;
            let manifest = fss_object::ObjectManifest::from_canonical_bytes(&bytes)
                .map_err(|_| HydrationError::Contract(fss_core::ContractError::EvidenceRequired))?;
            let payload = manifest
                .metadata_digest()
                .or_else(|| manifest.children().first().copied())
                .ok_or(HydrationError::Contract(
                    fss_core::ContractError::EvidenceRequired,
                ))?;
            let _ = owner.read_object_bounded(payload, maximum)?;
        }
    }
    Ok(())
}

/// Hydrate an existing session's exact retained event metadata without opening a media reader.
///
/// Only the existing agent journal is written. Original authority, effect and object stores are
/// read through the bounded immutable owner. A failed transport or final admission can consume a
/// charge and cursor; explicit retry never refunds it, revives a cursor or replays an effect.
/// The shared metadata allowance includes admission snapshots and final revalidation. Existing
/// journal/pin verification and restore-fence checks retain their separate native owner bounds.
pub fn hydrate_event_evidence(
    root: &Path,
    request: &EvidenceHydrationRequest,
    cancelled: &(dyn Fn() -> bool + Sync),
) -> Result<EvidenceHydrationAnswer, EvidenceHydrationFailure> {
    let mut committed = None;
    let mut observed = None;
    let result = (|| -> Result<EvidenceHydrationAnswer, EvidenceHydrationError> {
        request.validate()?;
        cancelled_check(cancelled)?;
        let root = ensure_agent_writable(root)?;
        // The initial authority snapshots and every later immutable payload read consume one
        // allowance. Existing session-journal/pin I/O keeps its independent bounded owner rules.
        let read_budget = MetadataReadBudget::new(
            MAX_EVENT_HYDRATION_READ_BYTES,
            MAX_EVENT_HYDRATION_READ_OBJECTS,
        );
        // This read never creates a missing session journal or grants a capability. All stored
        // session and workspace checks precede descriptor construction and the writer boundary.
        let (oriented, _, _) = with_admitted_session_metadata_read(
            &root,
            &request.principal,
            &request.session_id,
            &read_budget,
            cancelled,
            |snapshot| {
                observed = Some(EvidenceHydrationObservation {
                    anchor: snapshot.anchor.clone(),
                    observed_at: evidence_now(snapshot),
                });
            },
            |read| {
                if read.session.symbol_table_generation != request.generation
                    || read.session.current_anchor != read.head.anchor
                    || read.anchor_moved
                    || snapshot_anchor_token(read.head) != request.expected_anchor.as_str()
                    || ![EVIDENCE_HYDRATION_CAPABILITY, EVIDENCE_QUERY_CAPABILITY]
                        .iter()
                        .all(|capability| read.session.capabilities.contains(*capability))
                    || request.budget_tokens > read.remaining_tokens
                {
                    return Err(DeploymentSessionError::SessionStale(
                        "exact hydration session, generation, grant, budget or anchor refused"
                            .into(),
                    ));
                }
                project_session_read(
                    read,
                    &OrientSessionRequest {
                        session_id: request.session_id.clone(),
                        principal: request.principal.clone(),
                        view: AgentView::Brief,
                        budget_tokens: None,
                    },
                )
            },
        )?;
        cancelled_check(cancelled)?;
        let session = oriented.session;
        let mut capabilities: Vec<_> = session.capabilities.iter().cloned().collect();
        capabilities.push(ADP_REPLAY_ROW_ID.to_owned());
        let authority = ContextAuthority::new_root(RootAuthoritySpec {
            trace_id: "trace:event-evidence-hydration".into(),
            operation_id: OperationId::parse("operation:event-evidence-hydration")
                .map_err(|_| EvidenceHydrationError::InvalidRequest)?,
            principal: request.principal.as_str().to_owned(),
            capabilities,
            deadline: None,
            priority: 10,
            budgets: BudgetVector::builder()
                .bytes(MAX_EVENT_HYDRATION_READ_BYTES as u64)
                .storage_operations(MAX_EVENT_HYDRATION_READ_OBJECTS as u64)
                .tokens(request.budget_tokens)
                .build()
                .map_err(|_| EvidenceHydrationError::InvalidRequest)?,
            privacy_scope: super::SESSION_PRIVACY_SCOPE.to_owned(),
            retention_scope: "retention:current-deletion-restrictions".into(),
            anchor_universe: session.current_anchor.state_root,
            generation: 1,
        })
        .map_err(|_| EvidenceHydrationError::InvalidRequest)?;
        let cx = ReplayCx::from_context_authority_read_only(&authority, root.clone())
            .map_err(|_| EvidenceHydrationError::InvalidRequest)?;
        let owner = ImmutableRetainedSource::open_with_metadata_budget(
            &root,
            ImmutableRetainedReadLimits {
                snapshot: OrientLimits::default(),
                max_read_bytes: MAX_EVENT_HYDRATION_READ_BYTES,
                max_read_objects: MAX_EVENT_HYDRATION_READ_OBJECTS,
            },
            &cx,
            cancelled,
            read_budget,
        )?;
        let snapshot = owner.snapshot();
        let anchor_token = snapshot_anchor_token(snapshot);
        if anchor_token != request.expected_anchor.as_str()
            || snapshot.anchor != session.current_anchor
            || oriented.orientation.anchor_token != anchor_token.as_str()
        {
            return Err(EvidenceHydrationError::Stale);
        }
        let anchor_token = request.expected_anchor.clone();
        let now = evidence_now(snapshot);
        let mut built = build_event_hydration_catalog(
            snapshot,
            &oriented.orientation,
            &request.event_id,
            request.expected_revision,
            TimestampNs(session.expires_at_ns),
        )?;
        retain_event_custody(&owner, &request.event_id)?;
        if request
            .expected_descriptor
            .is_some_and(|expected| expected != built.descriptor.descriptor_digest)
        {
            return Err(HydrationError::DescriptorNotFound.into());
        }
        let mut budget = event_hydration_cost(request.level)?;
        budget.tokens = request.budget_tokens;
        let hydration = HydrationRequest::publish(HydrationRequestSpec {
            contract_basis: built.descriptor.contract_basis.clone(),
            session_id: session.session_id.clone(),
            handle_id: built.descriptor.handle_id.clone(),
            expected_descriptor_digest: built.descriptor.descriptor_digest,
            expected_subject_digest: built.descriptor.subject_digest,
            anchor: snapshot.anchor.clone(),
            requested_level: request.level,
            allow_lower_level: false,
            available_capabilities: session.capabilities.clone(),
            authorized_privacy_classes: session.privacy_scope.clone(),
            budget,
            purpose: HydrationPurpose::Routine,
            continuation: request.continuation.clone(),
            issued_at: now,
        })?;
        cancelled_check(cancelled)?;
        let mut journal = SessionJournal::open(&root)?;
        if journal.store.committed_root() != oriented.journal_root {
            return Err(EvidenceHydrationError::Stale);
        }
        let current_session =
            journal
                .store
                .session(&request.principal, &request.session_id, now)?;
        if current_session != session {
            return Err(EvidenceHydrationError::Stale);
        }
        let remaining_before =
            journal
                .store
                .remaining_token_budget(&request.principal, &request.session_id, now)?;
        owner.revalidate()?;
        let bound = journal.store.bind(
            &request.principal,
            &SessionBindingRequest {
                session_id: request.session_id.clone(),
                generation: request.generation,
                handle_id: built.descriptor.handle_id.clone(),
                descriptor_digest: built.descriptor.descriptor_digest,
            },
            &built.catalog,
            now,
        );
        // Even refusal can retain a clock/expiry observation. Never leave its root unpinned.
        journal.commit_pin()?;
        let alias = bound?;
        cancelled_check(cancelled)?;
        let delivered = journal.store.hydrate_atomic(
            &request.principal,
            &alias,
            &hydration,
            &mut built.catalog,
            now,
        );
        if let Ok(value) = &delivered {
            let charged_tokens = value.admission.charged_tokens();
            let remaining_tokens =
                remaining_before
                    .checked_sub(charged_tokens)
                    .ok_or_else(|| {
                        EvidenceHydrationError::Session(DeploymentSessionError::Internal(
                            "native disclosure charged beyond admitted session balance".into(),
                        ))
                    })?;
            committed = Some(EvidenceHydrationCharge {
                journal_root: value.committed_root,
                anchor: snapshot.anchor.clone(),
                observed_at: now,
                charged_tokens,
                remaining_tokens,
            });
        }
        journal.commit_pin()?;
        let delivered = delivered?;
        // The immutable owner keeps live cancellation and refuses observed metadata/custody
        // drift through its bounded final pass; it does not claim an atomic filesystem lease.
        // Verify the exclusively owned session journal afterward without caller callbacks.
        owner.revalidate()?;
        journal.store.verify_storage()?;
        ensure_agent_writable(&root)?;
        let charge = committed.as_ref().ok_or_else(|| {
            EvidenceHydrationError::Session(DeploymentSessionError::Internal(
                "missing committed native disclosure receipt".into(),
            ))
        })?;
        Ok(EvidenceHydrationAnswer {
            session,
            orientation: oriented.orientation,
            descriptor: built.descriptor,
            alias,
            request: hydration,
            response: delivered.response,
            explanation: built.explanation,
            event_handle: built.event_handle,
            anchor_token,
            journal_root: charge.journal_root,
            charged_tokens: charge.charged_tokens,
            remaining_tokens: charge.remaining_tokens,
        })
    })();
    result.map_err(|error| EvidenceHydrationFailure {
        error,
        committed,
        observed,
    })
}

#[cfg(test)]
mod tests;
