#![forbid(unsafe_code)]
//! Durable AOP-004 delivery over exact adjacent deployment-history prefixes.
//!
//! The session owns the frozen range, page receipt and explicit acknowledgement. Native replay
//! owns classification. No command changes source history, prepares an effect, rewrites a
//! workspace, renews a lease, or acknowledges a page merely because a renderer ran.
//!
//! This bounded synchronous adapter has no detached task or parked writer. One call reconstructs
//! at most the pending page being ACKed and its successor. Journal capacity is finite; history
//! loss, changed custody, authority drift and ambiguous cross-journal order require explicit
//! recovery/resnapshot and never silently skip a protected transition.
//!
//! A populated mission may start a subscription at the exact current deployment head. Its
//! complete semantic journal/publication scope is pinned there; subsequent evidence or effect
//! prefixes derive their own case freshness, lease validity and operation state. Any change to
//! that semantic scope requires an explicit new subscription at a newly admitted head. This
//! profile never claims to reconstruct the relative order of agent and deployment journals.

use std::fmt;
use std::path::Path;

use fss_core::{
    AgentSession, AgentView, CanonicalEncoder, ContentDigest, LedgerAnchor, PrincipalId, SessionId,
    TimestampNs,
};

use super::{DeploymentSessionError, PUBLICATIONS_RELPATH, SessionJournal, publication_limits};
use crate::agent_follow::replay::{
    ReplayControl, ReplayDenial, ReplayError, ReplayStep, follow_replay_step_for,
    follow_replay_step_projected,
};
use crate::agent_follow::{
    AnchorToken, DeploymentFollow, FollowError, FollowRequest, history_anchor_token, resolve_anchor,
};
use crate::agent_orient::{
    DeploymentHistory, DeploymentSnapshot, OrientLimits, OrientSessionBinding,
};
use crate::agent_session::checkpoint::journal::coordination::investigations::InvestigationRevision;
use crate::agent_session::checkpoint::journal::follow::{
    DurableFollowError, FollowRegistration, FollowSubscription, PendingFollowDelivery,
};
use crate::agent_session::checkpoint::journal::mission::{DurableMissionError, MissionRevision};
use crate::agent_session::checkpoint::journal::projection::SessionProjection;
use crate::agent_session::checkpoint::journal::supervision::{
    DurableSupervisionError, SupervisionInventoryEntry,
};
use crate::agent_session::checkpoint::journal::{DurableSessionError, SessionRecoveryState};
use crate::agent_session::work_claims::WorkClaimRevision;

/// All request fields are explicit; the registration's original anchor remains its retry identity.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FollowSessionRequest {
    /// Existing durable authenticated session.
    pub session_id: SessionId,
    /// Label scoped to this session; not a path, authority token, or public operation.
    pub subscription_id: String,
    /// Exact original anchor used to register this subscription.
    pub since: AnchorToken,
    /// Registered view frozen for all pages of this subscription.
    pub view: AgentView,
    /// Immutable page ceiling.
    pub max_entries: u32,
    /// Explicit ACK of exactly the pending delivery, or retry of the most recent ACK.
    pub acknowledge: Option<ContentDigest>,
}

impl FollowSessionRequest {
    fn registration(&self, semantic_history: ContentDigest) -> FollowRegistration {
        FollowRegistration {
            session_id: self.session_id.clone(),
            subscription_id: self.subscription_id.clone(),
            since: self.since.as_str().to_owned(),
            view: self.view,
            max_entries: self.max_entries,
            semantic_history,
        }
    }
}

/// Caller-owned authority sees the exact immutable session request at every I/O/mutation boundary.
pub struct FollowSessionBinding<'a> {
    root: &'a Path,
    principal: &'a PrincipalId,
    request: &'a FollowSessionRequest,
    limits: &'a OrientLimits,
}

impl<'a> FollowSessionBinding<'a> {
    /// Deployment namespace; possession of a path itself grants nothing.
    #[must_use]
    pub const fn root(&self) -> &'a Path {
        self.root
    }
    /// Principal authenticated by the calling runtime.
    #[must_use]
    pub const fn principal(&self) -> &'a PrincipalId {
        self.principal
    }
    /// Original immutable command, including any exact acknowledgement receipt.
    #[must_use]
    pub const fn request(&self) -> &'a FollowSessionRequest {
        self.request
    }
    /// Native read bounds; no hidden widening occurs.
    #[must_use]
    pub const fn limits(&self) -> &'a OrientLimits {
        self.limits
    }
}

/// Bounded session-owner work. There are no sleeps, worker threads, or implicit effects.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FollowSessionBoundary {
    /// Before reading bounded deployment journals and deriving their exact head/time.
    ReadHistory,
    /// Before acquiring the existing exclusive agent-journal owner for this one command.
    OpenJournal,
    /// Before live session admission, registration, or retry lookup.
    ReadSubscription,
    /// Before committing exactly the explicit pending acknowledgement.
    Acknowledge,
    /// Before retaining the computed pending page and synchronizing its root pin.
    PublishDelivery,
    /// Before re-reading current authority to detect concurrent advancement or generation changes.
    RevalidateHistory,
    /// Before releasing the private page whose delivery receipt is already durable.
    Deliver,
}

/// Explicit synchronous equivalent of request-owned Cx. No permissive implementation is provided.
pub trait FollowSessionControl: ReplayControl {
    /// Admission applies to the exact binding and current cancellation/deadline/authority state.
    fn admit_session(
        &mut self,
        binding: &FollowSessionBinding<'_>,
        boundary: FollowSessionBoundary,
    ) -> Result<(), ReplayDenial>;
}

/// One real session-bound native page and its persisted delivery metadata.
#[derive(Clone, Debug, PartialEq)]
pub struct FollowSessionDelivery {
    /// Existing AOP-004 native payload; session binding was applied before publication sealing.
    pub follow: DeploymentFollow,
    /// Current live session; no lease, grant, budget or workspace was reset.
    pub session: AgentSession,
    /// Session-local subscription label.
    pub subscription_id: String,
    /// Exact receipt to submit explicitly on the next command.
    pub delivery_receipt: ContentDigest,
    /// Pinned committed session journal, including this pending delivery.
    pub journal_root: ContentDigest,
    /// True when this page was already pending before the command.
    pub replayed: bool,
    /// Exact requested ACK that this command confirmed, including an idempotent retry.
    pub acknowledged: Option<ContentDigest>,
    /// Start of this adjacent transition; it advances only after its last page is ACKed.
    pub since_anchor: AnchorToken,
    /// Exact adjacent endpoint of this page's complete native delta.
    pub result_anchor: AnchorToken,
    /// Frozen end of the current replay window.
    pub horizon_anchor: AnchorToken,
    /// True when this transition reaches the frozen horizon (remaining item pages still matter).
    pub horizon_reached: bool,
}

/// Verified current authority observed from bounded journals, without an invented wall clock.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FollowSessionHead {
    /// Current authority anchor, including all generation epochs.
    pub anchor: LedgerAnchor,
    /// Exact authority/effect prefix token.
    pub token: AnchorToken,
    /// The existing deployment evidence-clock watermark.
    pub observed_at: TimestampNs,
}

/// Error variants preserve the owning error rather than flattening a gap into an empty stream.
#[derive(Debug)]
pub enum FollowSessionError {
    /// Syntax/view/page bounds failed before any I/O.
    InvalidRequest,
    /// Existing session or agent-journal owner refused.
    Session(DeploymentSessionError),
    /// Exact history, classification or source hydration refused.
    Replay(ReplayError),
    /// Registration, ACK/CAS, scope or durable journal refused.
    Store(DurableFollowError),
    /// Caller-owned Cx no longer admits the requested boundary.
    Denied(ReplayDenial),
    /// The retained page no longer reconstructs exactly, or history advanced during this call.
    ChangedDelivery,
    /// Current authority generations no longer match the live session interpretation basis.
    StaleAuthority,
}

impl fmt::Display for FollowSessionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidRequest => f.write_str("invalid session follow request"),
            Self::Session(error) => write!(f, "{error}"),
            Self::Replay(error) => write!(f, "{error}"),
            Self::Store(error) => write!(f, "{error}"),
            Self::Denied(reason) => write!(f, "session follow owner refused {reason:?}"),
            Self::ChangedDelivery => f.write_str(
                "follow delivery changed or cannot be reproduced; explicit resnapshot required",
            ),
            Self::StaleAuthority => f.write_str(
                "session follow authority generation is stale; a fresh session and explicit resnapshot are required",
            ),
        }
    }
}

impl std::error::Error for FollowSessionError {}

impl From<ReplayError> for FollowSessionError {
    fn from(value: ReplayError) -> Self {
        Self::Replay(value)
    }
}

/// Failure also states which durable actions may have completed. Rendering failure is not rollback.
#[derive(Debug)]
pub struct FollowSessionFailure {
    /// Owning typed refusal.
    pub error: FollowSessionError,
    /// Verified journal head, if read admission succeeded.
    pub head: Option<FollowSessionHead>,
    /// Exact acknowledged subscription position, disclosed only after live session admission.
    pub since_anchor: Option<AnchorToken>,
    /// Exact frozen horizon, disclosed only after live session admission.
    pub horizon_anchor: Option<AnchorToken>,
    /// ACK definitely committed or matched its previous committed retry before this failure.
    pub acknowledged: Option<ContentDigest>,
    /// Registration, clock, pending receipt or ACK may already be durable; never claim not-started.
    pub journal_may_have_changed: bool,
}

impl fmt::Display for FollowSessionFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.error.fmt(f)
    }
}

impl std::error::Error for FollowSessionFailure {}

fn observe_head(history: &DeploymentHistory) -> Result<FollowSessionHead, FollowSessionError> {
    let position = history.head();
    let (anchor, _, _) = history
        .roots_at(position)
        .ok_or(FollowSessionError::ChangedDelivery)?;
    let token =
        history_anchor_token(history, position).ok_or(FollowSessionError::ChangedDelivery)?;
    let observed_at = history
        .batches_through_head()
        .iter()
        .flat_map(|batch| &batch.deltas)
        .map(|delta| delta.validity.latest)
        .max()
        .unwrap_or(TimestampNs::ZERO);
    Ok(FollowSessionHead {
        anchor,
        token,
        observed_at: TimestampNs(observed_at.0.max(0)),
    })
}

fn same_generations(left: &LedgerAnchor, right: &LedgerAnchor) -> bool {
    left.site_lineage == right.site_lineage
        && left.ledger_epoch == right.ledger_epoch
        && left.adapter_registry_epoch == right.adapter_registry_epoch
        && left.schema_epoch == right.schema_epoch
        && left.policy_epoch == right.policy_epoch
        && left.privacy_epoch == right.privacy_epoch
}

fn native_request(
    state: &FollowSubscription,
    principal: &PrincipalId,
    input: Option<&str>,
) -> FollowRequest {
    FollowRequest {
        view: state.registration().view,
        principal: principal.clone(),
        max_entries: state.registration().max_entries,
        continuation: input.map(str::to_owned),
    }
}

/// A journal admitted at the current live clock, whose unchanged semantic history was pinned
/// when this subscription began at the exact deployment head. Historical snapshot time is
/// used only to derive freshness, expiry and effect progress; it never authenticates a session
/// backwards in time or rewrites the journal's monotonic clock.
struct SessionReplayScope<'a> {
    root: &'a Path,
    store: &'a dyn SessionProjection,
    session: &'a AgentSession,
    mission: &'a super::MissionRecord,
    admission_now: TimestampNs,
    populated: bool,
}

impl SessionProjection for SessionReplayScope<'_> {
    fn mission_head_for_projection(
        &self,
        session: &AgentSession,
        _now: TimestampNs,
    ) -> Result<Option<MissionRevision>, DurableMissionError> {
        self.store
            .mission_head_for_projection(session, self.admission_now)
    }

    fn supervision_inventory(
        &self,
        session: &AgentSession,
        _now: TimestampNs,
    ) -> Result<Vec<SupervisionInventoryEntry>, DurableSupervisionError> {
        self.store
            .supervision_inventory(session, self.admission_now)
    }

    fn recovery_state_for_projection(
        &self,
        session: &AgentSession,
        _now: TimestampNs,
    ) -> Result<SessionRecoveryState, DurableSessionError> {
        self.store
            .recovery_state_for_projection(session, self.admission_now)
    }

    fn investigation_heads(&self) -> Vec<InvestigationRevision> {
        self.store.investigation_heads()
    }

    fn work_claim_heads(&self) -> Vec<WorkClaimRevision> {
        self.store.work_claim_heads()
    }
}

impl SessionReplayScope<'_> {
    fn project(
        &self,
        snapshot: &DeploymentSnapshot,
    ) -> Result<OrientSessionBinding, FollowSessionError> {
        let now = super::evidence_now(snapshot);
        let briefs = super::session_briefs(self.root, self, self.session, snapshot, now)
            .map_err(FollowSessionError::Session)?;
        Ok(OrientSessionBinding {
            mission_id: self.session.mission_id.clone(),
            session_id: self.session.session_id.clone(),
            mission: Some(self.mission.orientation_brief()),
            mission_progress: briefs.mission_progress,
            cases: briefs.cases,
            claims: briefs.claims,
            findings: briefs.findings,
            captured_learning: briefs.captured_learning.map(|inventory| inventory.briefs),
            plans: super::plan::plan_briefs(
                self.root,
                snapshot,
                &self.session.mission_id,
                &self.session.principal_id,
            )
            .map_err(FollowSessionError::Session)?,
            supervisions: briefs.supervisions,
            trauma_warnings: if briefs.advisory_memory_allowed {
                Some(
                    super::trauma_guard::derive_trauma_guard_warnings(
                        self.root,
                        &self.session.principal_id,
                        now.0,
                    )
                    .map_err(FollowSessionError::Session)?,
                )
            } else {
                None
            },
        })
    }
}

fn reconstruct(
    history: &DeploymentHistory,
    state: &FollowSubscription,
    scope: &SessionReplayScope<'_>,
    horizon: &AnchorToken,
    input: Option<&str>,
    control: &mut impl FollowSessionControl,
) -> Result<ReplayStep, FollowSessionError> {
    let session = scope.session;
    let since = AnchorToken::parse(state.acknowledged_anchor())
        .ok_or(FollowSessionError::ChangedDelivery)?;
    let binding = OrientSessionBinding {
        mission_id: session.mission_id.clone(),
        session_id: session.session_id.clone(),
        mission: Some(scope.mission.orientation_brief()),
        mission_progress: None,
        cases: Vec::new(),
        claims: Vec::new(),
        findings: Vec::new(),
        plans: Vec::new(),
        supervisions: None,
        trauma_warnings: None,
        captured_learning: None,
    };
    let request = native_request(state, &session.principal_id, input);
    let step = if scope.populated {
        follow_replay_step_projected(
            history,
            &since,
            horizon,
            &request,
            Some(&binding),
            control,
            |snapshot| scope.project(snapshot).map(Some),
        )?
    } else {
        // Preserve the exact sealed publications and pending receipts of existing empty-facet
        // subscriptions, including their explicit lack of supervision/advisory metadata.
        follow_replay_step_for(history, &since, horizon, &request, Some(&binding), control)?
    };
    if let Some(acknowledged) = state.acknowledged_fingerprint() {
        let basis = step
            .follow
            .basis
            .capsule()
            .decision_fingerprint()
            .map_err(|_| FollowSessionError::ChangedDelivery)?;
        if basis != acknowledged {
            return Err(FollowSessionError::ChangedDelivery);
        }
    }
    Ok(step)
}

struct SemanticHistory {
    digest: ContentDigest,
    populated: bool,
}

fn semantic_history(
    root: &Path,
    journal: &mut SessionJournal,
    session: &AgentSession,
    now: TimestampNs,
) -> Result<SemanticHistory, FollowSessionError> {
    // Presence alone is now supported at a newly pinned current-head baseline. Every subsequent
    // mutation still invalidates that baseline; no agent-journal transition is backprojected.
    let mut populated = journal
        .store
        .mission_head_for_projection(session, now)
        .map_err(|_| {
            FollowSessionError::Session(DeploymentSessionError::StoreInvalid(
                "retained mission history is unavailable for follow replay".to_owned(),
            ))
        })?
        .is_some()
        || !journal.store.work_claim_heads().is_empty()
        || !journal.store.investigation_heads().is_empty();
    let workspace = journal
        .store
        .workspace_head(&session.principal_id, &session.session_id, now)
        .map_err(|error| FollowSessionError::Session(error.into()))?;
    populated |= workspace.result.revision.capsule().revision != 0;
    if session.capabilities.contains("CAP-AGENT-INVESTIGATE-001") {
        populated |= !journal
            .store
            .supervision_inventory(session, now)
            .map_err(|error| {
                FollowSessionError::Session(DeploymentSessionError::StoreInvalid(error.to_string()))
            })?
            .is_empty();
    }
    let mut limits = publication_limits();
    limits.max_roots = 128;
    limits.max_scan_entries = 4096;
    let inspection = fss_publication::inspect(root.join(PUBLICATIONS_RELPATH), limits)
        .map_err(|error| FollowSessionError::Session(error.into()))?;
    if !inspection.is_clean() {
        return Err(FollowSessionError::ChangedDelivery);
    }
    populated |= inspection.visible_roots().any(|visible| {
        !visible.slot.as_str().starts_with("mission-")
            && !visible.slot.as_str().starts_with("handoff-")
    });
    let (legacy_root, semantic_root) = journal
        .store
        .follow_semantic_journal_roots()
        .map_err(|error| FollowSessionError::Session(error.into()))?;
    let mut e = CanonicalEncoder::new();
    e.text("fss.reference_follow_session_registration.v1");
    if populated {
        e.text("pinned_semantic_snapshot.v1");
        e.digest(session.session_digest());
        e.digest(semantic_root);
    } else {
        e.text("semantic_history");
        e.digest(legacy_root);
    }
    e.u64(inspection.report.roots.len() as u64);
    for visible in inspection.visible_roots() {
        e.text(visible.slot.as_str());
        e.digest(visible.root);
        e.digest(visible.record_digest);
    }
    e.u64(inspection.report.tombstones.len() as u64);
    for tombstone in &inspection.report.tombstones {
        e.digest(*tombstone);
    }
    Ok(SemanticHistory {
        digest: ContentDigest::sha256(&e.finish()),
        populated,
    })
}

fn revalidate(
    binding: &FollowSessionBinding<'_>,
    journal: &mut SessionJournal,
    session: &AgentSession,
    state: &FollowSubscription,
    head: &FollowSessionHead,
    control: &mut impl FollowSessionControl,
    progress: &mut FollowSessionFailure,
) -> Result<(), FollowSessionError> {
    control
        .admit_session(binding, FollowSessionBoundary::RevalidateHistory)
        .map_err(FollowSessionError::Denied)?;
    let current = DeploymentHistory::read(binding.root, binding.limits)
        .map_err(|error| FollowSessionError::Session(error.into()))?;
    let current_head = observe_head(&current)?;
    progress.head = Some(current_head.clone());
    if current_head.token != head.token
        || !same_generations(&session.current_anchor, &current_head.anchor)
        || semantic_history(binding.root, journal, session, head.observed_at)?.digest
            != state.registration().semantic_history
    {
        return Err(FollowSessionError::ChangedDelivery);
    }
    Ok(())
}

/// Delivers one adjacent delta page and persists its receipt before release.
///
/// An explicit ACK is committed before obtaining the next page; a later failure reports that
/// progress and an exact retry remains safe. Without ACK, a pending page is reconstructed and
/// compared against its original digest. No requested continuation may skip stored progress.
/// Populated semantic state is admitted only at a new current-head baseline; semantic drift
/// refuses before an ACK is consumed and requires an explicit new baseline/subscription.
pub fn follow_session(
    root: &Path,
    principal: &PrincipalId,
    request: &FollowSessionRequest,
    limits: &OrientLimits,
    control: &mut impl FollowSessionControl,
) -> Result<FollowSessionDelivery, Box<FollowSessionFailure>> {
    let mut progress = FollowSessionFailure {
        error: FollowSessionError::InvalidRequest,
        head: None,
        since_anchor: None,
        horizon_anchor: None,
        acknowledged: None,
        journal_may_have_changed: false,
    };
    match execute(root, principal, request, limits, control, &mut progress) {
        Ok(delivery) => Ok(delivery),
        Err(error) => {
            progress.error = error;
            Err(Box::new(progress))
        }
    }
}

fn execute(
    root: &Path,
    principal: &PrincipalId,
    request: &FollowSessionRequest,
    limits: &OrientLimits,
    control: &mut impl FollowSessionControl,
    progress: &mut FollowSessionFailure,
) -> Result<FollowSessionDelivery, FollowSessionError> {
    let mut registration = request.registration(ContentDigest::sha256(&[]));
    registration
        .validate()
        .map_err(|_| FollowSessionError::InvalidRequest)?;
    let defaults = OrientLimits::default();
    if ![
        (limits.max_layout_bytes, defaults.max_layout_bytes),
        (limits.max_journal_bytes, defaults.max_journal_bytes),
        (limits.max_object_bytes, defaults.max_object_bytes),
        (limits.max_events, defaults.max_events),
        (
            limits.max_revisions_per_event,
            defaults.max_revisions_per_event,
        ),
    ]
    .into_iter()
    .all(|(value, ceiling)| value > 0 && value <= ceiling)
    {
        return Err(FollowSessionError::Replay(ReplayError::InvalidBounds));
    }
    let binding = FollowSessionBinding {
        root,
        principal,
        request,
        limits,
    };
    control
        .admit_session(&binding, FollowSessionBoundary::ReadHistory)
        .map_err(FollowSessionError::Denied)?;
    let history =
        DeploymentHistory::read(root, limits).map_err(|e| FollowSessionError::Session(e.into()))?;
    let head = observe_head(&history)?;
    progress.head = Some(head.clone());
    resolve_anchor(&history, &request.since).map_err(|error| {
        FollowSessionError::Replay(ReplayError::Follow(FollowError::Anchor(error)))
    })?;
    control
        .admit_session(&binding, FollowSessionBoundary::OpenJournal)
        .map_err(FollowSessionError::Denied)?;
    progress.journal_may_have_changed = true;
    let mut journal = SessionJournal::open(root).map_err(FollowSessionError::Session)?;
    control
        .admit_session(&binding, FollowSessionBoundary::ReadSubscription)
        .map_err(FollowSessionError::Denied)?;
    let session = journal
        .store
        .session(principal, &request.session_id, head.observed_at)
        .map_err(|e| FollowSessionError::Session(e.into()))?;
    if !same_generations(&session.current_anchor, &head.anchor) {
        return Err(FollowSessionError::StaleAuthority);
    }
    let retained = journal
        .store
        .follow_subscription(
            principal,
            &request.session_id,
            &request.subscription_id,
            head.observed_at,
        )
        .map_err(FollowSessionError::Store)?;
    let semantics = semantic_history(root, &mut journal, &session, head.observed_at)?;
    registration.semantic_history = semantics.digest;
    if let Some(retained) = &retained {
        progress.since_anchor = AnchorToken::parse(retained.acknowledged_anchor());
        progress.horizon_anchor = retained.horizon().and_then(AnchorToken::parse);
        if retained.registration().semantic_history != semantics.digest {
            return Err(FollowSessionError::ChangedDelivery);
        }
    } else if semantics.populated && request.since != head.token {
        // The current agent journal has no cross-journal chronology. A new populated baseline
        // can begin only now; its current heads prove nothing about an earlier evidence prefix.
        return Err(ReplayError::UnsupportedSessionFacets.into());
    }
    let workspace = journal
        .store
        .workspace_head(principal, &session.session_id, head.observed_at)
        .map_err(|error| FollowSessionError::Session(error.into()))?
        .result
        .revision;
    let mission = super::mission_for_workspace(root, &session, &workspace)
        .map_err(FollowSessionError::Session)?;
    let mut state = journal
        .store
        .register_follow(principal, registration, head.observed_at)
        .map_err(FollowSessionError::Store)?;
    journal.commit_pin().map_err(FollowSessionError::Session)?;
    progress.since_anchor = AnchorToken::parse(state.acknowledged_anchor());
    progress.horizon_anchor = state
        .horizon()
        .and_then(AnchorToken::parse)
        .or_else(|| Some(head.token.clone()));

    if let Some(receipt) = request.acknowledge {
        if state.last_acknowledged() != Some(receipt) {
            let pending = state
                .pending()
                .filter(|pending| pending.receipt() == receipt)
                .ok_or(FollowSessionError::Store(DurableFollowError::Conflict))?;
            let horizon =
                AnchorToken::parse(pending.horizon()).ok_or(FollowSessionError::ChangedDelivery)?;
            let prior = reconstruct(
                &history,
                &state,
                &SessionReplayScope {
                    root,
                    store: &journal.store,
                    session: &session,
                    mission: &mission,
                    admission_now: head.observed_at,
                    populated: semantics.populated,
                },
                &horizon,
                pending.input_continuation(),
                control,
            )?;
            if prior.page_digest() != pending.page_digest() {
                return Err(FollowSessionError::ChangedDelivery);
            }
            // A newly accepted ACK must still refer to the admitted authority at commit time.
            // A concurrent deletion/privacy or agent-semantic change cannot consume the page.
            revalidate(
                &binding,
                &mut journal,
                &session,
                &state,
                &head,
                control,
                progress,
            )?;
        }
        control
            .admit_session(&binding, FollowSessionBoundary::Acknowledge)
            .map_err(FollowSessionError::Denied)?;
        state = journal
            .store
            .acknowledge_follow(
                principal,
                &request.session_id,
                &request.subscription_id,
                receipt,
                head.observed_at,
            )
            .map_err(FollowSessionError::Store)?;
        // The ACK is durable even if the atomic pin replacement or subsequent delivery fails.
        progress.acknowledged = Some(receipt);
        progress.since_anchor = AnchorToken::parse(state.acknowledged_anchor());
        journal.commit_pin().map_err(FollowSessionError::Session)?;
    }

    let replayed = state.pending().is_some();
    let horizon = match state
        .pending()
        .map(PendingFollowDelivery::horizon)
        .or_else(|| state.horizon())
    {
        Some(token) => AnchorToken::parse(token).ok_or(FollowSessionError::ChangedDelivery)?,
        None => head.token.clone(),
    };
    progress.horizon_anchor = Some(horizon.clone());
    let input = state
        .pending()
        .and_then(PendingFollowDelivery::input_continuation)
        .or_else(|| state.next_continuation());
    let step = reconstruct(
        &history,
        &state,
        &SessionReplayScope {
            root,
            store: &journal.store,
            session: &session,
            mission: &mission,
            admission_now: head.observed_at,
            populated: semantics.populated,
        },
        &horizon,
        input,
        control,
    )?;
    let expected_basis = journal
        .store
        .follow_contract_basis(&request.session_id)
        .ok_or(FollowSessionError::StaleAuthority)?;
    if &step.follow.result.capsule().contract_basis != expected_basis
        || &step.follow.basis.capsule().contract_basis != expected_basis
    {
        return Err(FollowSessionError::StaleAuthority);
    }
    if state
        .pending()
        .is_some_and(|pending| pending.page_digest() != step.page_digest())
    {
        return Err(FollowSessionError::ChangedDelivery);
    }

    // Source availability is current even for an old prefix. Refuse concurrent journal movement
    // instead of releasing a page compiled across a deletion or authority-generation change.
    revalidate(
        &binding,
        &mut journal,
        &session,
        &state,
        &head,
        control,
        progress,
    )?;
    let receipt = if let Some(pending) = state.pending() {
        pending.receipt()
    } else {
        let pending =
            PendingFollowDelivery::from_step(&state, &step).map_err(FollowSessionError::Store)?;
        let receipt = pending.receipt();
        control
            .admit_session(&binding, FollowSessionBoundary::PublishDelivery)
            .map_err(FollowSessionError::Denied)?;
        journal
            .store
            .publish_follow_delivery(principal, &state, pending, head.observed_at)
            .map_err(FollowSessionError::Store)?;
        journal.commit_pin().map_err(FollowSessionError::Session)?;
        receipt
    };
    control
        .admit_session(&binding, FollowSessionBoundary::Deliver)
        .map_err(FollowSessionError::Denied)?;
    Ok(FollowSessionDelivery {
        follow: step.follow,
        session,
        subscription_id: request.subscription_id.clone(),
        delivery_receipt: receipt,
        journal_root: journal.store.committed_root(),
        replayed,
        acknowledged: progress.acknowledged,
        since_anchor: step.since,
        result_anchor: step.result_anchor,
        horizon_anchor: step.horizon,
        horizon_reached: step.horizon_reached,
    })
}
