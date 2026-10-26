#![forbid(unsafe_code)]
//! Explicit PlanOutcomeV1 mission enrollment and assessment (AOP-007 intent families).
//!
//! The selected target is exactly one own-session plan. Its original mission prose is retained
//! unchanged; this profile assesses execution of that plan's operation, not physical threat,
//! whether an alert was warranted, or whether an arbitrary prose objective has been achieved.
//!
//! The caller must hold the deployment's sole-writer lock for this complete call, as for
//! `episode::close_plan`. This module retains the session-journal lock through admission,
//! private custody reads, complete scoped inventory, immutable revision commit and projection.
//! It writes only the existing agent session journal and its root pin. No effect, source evidence,
//! episode, claim, case, subscription or workspace is created, cancelled, acknowledged or changed.

use std::fmt;
use std::net::SocketAddr;
use std::path::Path;

use crate::agent_session::checkpoint::journal::projection::SessionProjection;

use fss_core::{
    AgentSession, CanonicalEncode, CanonicalEncoder, ContentDigest, ContractError, DigestAlgorithm,
    EventId, ObligationId, OperationId, PrincipalId, SessionId, TimestampNs, WorkClaimState,
};
use fss_publication::SlotName;

use crate::agent_follow::{AnchorToken, resolve_anchor};
use crate::agent_orient::{
    DeploymentHistory, DeploymentOrientation, DeploymentSnapshot, HistoryPosition, OrientError,
    OrientLimits,
};
use crate::agent_session::ReferenceSessionError;
use crate::agent_session::checkpoint::journal::DurableSessionError;
use crate::agent_session::checkpoint::journal::mission::DurableMissionError;
pub use crate::agent_session::mission::MissionRevision;
use crate::agent_session::mission::{
    MissionAssessmentFacts, MissionClosureFacts, MissionEpisodeFacts, MissionEpisodeOutcome,
    MissionError as OwnerMissionError, MissionObligationFacts, MissionObligationState,
    MissionOperationFacts, MissionOperationState, MissionPlanCriterion, same_generations,
};
use crate::webhook::WebhookEndpoint;

use super::episode::{PublishedEpisode, read_episode};
use super::plan::{PlanRecord, read_control_plan};
use super::{
    DeploymentSessionError, MissionRecord, OperationFacts, SESSION_PRIVACY_SCOPE, SessionJournal,
    digest_of, evidence_now, hex, mission_for_workspace, operation_facts, orient_bound,
};

const REQUEST_DOMAIN: &str = "fss.reference_mission_native_request.v1";
const CLOSURE_DOMAIN: &str = "fss.reference_mission_closure.v1";
const PLAN_ID_LIMIT: usize = 256;
const REQUIRED_CAPABILITIES: [&str; 7] = [
    "CAP-AGENT-SESSION-READ-001",
    "CAP-AGENT-SESSION-WRITE-001",
    "CAP-AGENT-SITUATION-READ-001",
    "CAP-AGENT-PLAN-PREPARE-001",
    "CAP-AGENT-CASE-WRITE-001",
    "CAP-AGENT-INVESTIGATE-001",
    "CAP-AGENT-WORK-CLAIM-001",
];

/// One explicit mission intent. There is no caller-selected lifecycle state.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum MissionAction {
    /// Enroll one exact own-session plan and an immutable evidence-clock decision deadline.
    Adopt {
        /// Existing root-last plan identity.
        plan_id: String,
        /// Absolute deadline on the deployment's evidence clock, in nanoseconds.
        decision_deadline: TimestampNs,
    },
    /// Assess only the enrolled plan against exactly the named retained mission head.
    Assess {
        /// Exact previously enrolled plan.
        plan_id: String,
        /// Full mission revision digest; an old predecessor never overwrites a newer result.
        expected: ContentDigest,
    },
}

impl MissionAction {
    /// Exact selected plan identity.
    #[must_use]
    pub fn plan_id(&self) -> &str {
        match self {
            Self::Adopt { plan_id, .. } | Self::Assess { plan_id, .. } => plan_id,
        }
    }

    /// Existing AOP-007 intent-family label.
    #[must_use]
    pub const fn name(&self) -> &'static str {
        match self {
            Self::Adopt { .. } => "mission_bind",
            Self::Assess { .. } => "mission_assess",
        }
    }
}

/// The caller selects a session, plan and explicit intent; time and evidence come from owners.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MissionRequest {
    /// Existing live session.
    pub session_id: SessionId,
    /// Session principal, authenticated by the shared owner.
    pub principal: PrincipalId,
    /// Explicit enrollment or exact-predecessor assessment.
    pub action: MissionAction,
}

/// One immutable mission result plus the same registered control-plan payload it assessed.
#[derive(Clone, Debug)]
pub struct MissionAnswer {
    /// Current retained revision; terminal history is never rewritten.
    pub revision: MissionRevision,
    /// Live session, with its original anchor, lease and cumulative budgets preserved.
    pub session: AgentSession,
    /// Current-head situation; this does not rebase the retained workspace.
    pub orientation: DeploymentOrientation,
    /// Original verified fss.agent_control_plan.v1 rendering, byte-for-byte.
    pub control_plan: Vec<u8>,
    /// Exact root-last plan publication.
    pub plan_root: ContentDigest,
    /// Whether this intent appended a mission revision.
    pub committed: bool,
    /// Pinned session-journal root after all admission and mission work.
    pub journal_root: ContentDigest,
    /// Canonical explicit request identity.
    pub request_digest: ContentDigest,
    /// True when this head lies beyond the session's retained workspace anchor.
    pub head_moved: bool,
}

/// No refusal carries private plan, episode, route or mission prose.
#[derive(Debug)]
pub enum MissionError {
    /// Existing session, deployment, custody or orientation boundary refused.
    Session(DeploymentSessionError),
    /// Shared mission state machine or durable journal refused.
    Store(DurableMissionError),
    /// A bounded input or proof encoding is invalid.
    Contract(ContractError),
    /// The current grants cannot disclose a complete mission closure inventory.
    Denied,
    /// Immutable plan, episode or effect links disagree.
    InvalidProof,
    /// Control generations differ; a read cannot silently refresh authority.
    StaleAuthority,
}

impl fmt::Display for MissionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Session(_) => "mission session or retained custody unavailable",
            Self::Store(_) => "durable mission request refused",
            Self::Contract(_) => "mission request or proof encoding invalid",
            Self::Denied => "mission assessment authority unavailable",
            Self::InvalidProof => "mission plan, episode and journal proof do not agree",
            Self::StaleAuthority => "mission control generations require explicit recovery",
        })
    }
}
impl std::error::Error for MissionError {}
impl From<DeploymentSessionError> for MissionError {
    fn from(value: DeploymentSessionError) -> Self {
        Self::Session(value)
    }
}
impl From<DurableMissionError> for MissionError {
    fn from(value: DurableMissionError) -> Self {
        Self::Store(value)
    }
}
impl From<ContractError> for MissionError {
    fn from(value: ContractError) -> Self {
        Self::Contract(value)
    }
}

impl MissionError {
    /// Existing registered error identity, without a competing mission-specific vocabulary.
    #[must_use]
    pub fn stable_id(&self) -> &'static str {
        match self {
            Self::Denied => "ERR-AUTH-DENIED-001",
            Self::StaleAuthority => "ERR-AGENT-SESSION-STALE-001",
            Self::Contract(_) | Self::InvalidProof => "ERR-OP-PRECONDITION-FAILED-001",
            Self::Session(DeploymentSessionError::SessionUnknown) => {
                "ERR-AGENT-SESSION-NOT-FOUND-001"
            }
            Self::Session(DeploymentSessionError::SessionStale(_)) => "ERR-AGENT-SESSION-STALE-001",
            Self::Session(DeploymentSessionError::PlanDenied) => "ERR-AUTH-DENIED-001",
            Self::Session(DeploymentSessionError::PlanUnknown) => "ERR-EVIDENCE-MISSING-001",
            Self::Session(DeploymentSessionError::StoreLocked) => {
                "ERR-AGENT-SESSION-STORE-LOCKED-001"
            }
            Self::Session(DeploymentSessionError::Orient(
                OrientError::ContextBudgetExceeded { .. } | OrientError::TooManyEvents { .. },
            )) => "ERR-AGENT-CONTEXT-INCOMPLETE-001",
            Self::Session(_) => "ERR-AGENT-SESSION-STORE-INVALID-001",
            Self::Store(DurableMissionError::Refused(error)) => match error {
                OwnerMissionError::Session(ReferenceSessionError::Unavailable) => {
                    "ERR-AGENT-SESSION-NOT-FOUND-001"
                }
                OwnerMissionError::Session(ReferenceSessionError::ClockRegression) => {
                    "ERR-CLOCK-UNCERTAIN-001"
                }
                OwnerMissionError::Session(_) | OwnerMissionError::ScopeMismatch => {
                    "ERR-AGENT-SESSION-STALE-001"
                }
                OwnerMissionError::Unauthorized => "ERR-AUTH-DENIED-001",
                OwnerMissionError::Conflict => "ERR-PRECONDITION-STALE-001",
                OwnerMissionError::CapacityExceeded => "ERR-BUDGET-EXHAUSTED-001",
                OwnerMissionError::InvalidRequest | OwnerMissionError::Terminal => {
                    "ERR-OP-PRECONDITION-FAILED-001"
                }
            },
            Self::Store(DurableMissionError::Durability(DurableSessionError::CapacityExceeded)) => {
                "ERR-BUDGET-EXHAUSTED-001"
            }
            Self::Store(DurableMissionError::Durability(_)) => {
                "ERR-AGENT-SESSION-STORE-INVALID-001"
            }
        }
    }
}

fn owner_error(error: OwnerMissionError) -> MissionError {
    MissionError::Store(DurableMissionError::Refused(error))
}

fn admit_scope(session: &AgentSession) -> Result<(), MissionError> {
    if !REQUIRED_CAPABILITIES
        .iter()
        .all(|cap| session.capabilities.contains(*cap))
        || !session.privacy_scope.contains(SESSION_PRIVACY_SCOPE)
    {
        return Err(MissionError::Denied);
    }
    Ok(())
}

fn admit(session: &AgentSession, snapshot: &DeploymentSnapshot) -> Result<(), MissionError> {
    admit_scope(session)?;
    if !same_generations(&session.current_anchor, &snapshot.anchor)
        || snapshot.anchor.commit_sequence < session.current_anchor.commit_sequence
    {
        return Err(MissionError::StaleAuthority);
    }
    if snapshot.ledger_tail_uncommitted || snapshot.effect_tail_uncommitted {
        return Err(MissionError::InvalidProof);
    }
    Ok(())
}

fn plan_slot(plan_id: &str) -> Result<SlotName, MissionError> {
    SlotName::parse(&format!(
        "plan-{}",
        hex(ContentDigest::sha256(plan_id.as_bytes()))
    ))
    .map_err(|_| MissionError::InvalidProof)
}

struct SelectedPlan {
    record: PlanRecord,
    root: ContentDigest,
    rendering: Vec<u8>,
    endpoint: WebhookEndpoint,
}

fn selected_plan(
    root: &Path,
    session: &AgentSession,
    plan_id: &str,
) -> Result<SelectedPlan, MissionError> {
    let (record, plan_root, rendering) = read_control_plan(root, plan_id)?;
    if record.session_id != session.session_id
        || record.principal != session.principal_id
        || record.mission_id != session.mission_id
    {
        return Err(DeploymentSessionError::PlanUnknown.into());
    }
    if record.intent != "alert"
        || record.plan_id
            != PlanRecord::identity(
                &record.session_id,
                &record.anchor_token,
                record.plan_approval,
            )
        || record.route.deadline_ms == 0
        || record.route.deadline_ms > 60_000
        || record.created_at.0 < 0
    {
        return Err(MissionError::InvalidProof);
    }
    let published = super::read_published(root, &plan_slot(plan_id)?)?
        .ok_or(DeploymentSessionError::PlanUnknown)?;
    if published.root != plan_root
        || published.record != record.to_bytes()
        || published.children.as_slice() != [record.control_plan_digest]
        || ContentDigest::sha256(&rendering) != record.control_plan_digest
    {
        return Err(MissionError::InvalidProof);
    }
    let peer: SocketAddr = record
        .route
        .relay
        .parse()
        .map_err(|_| MissionError::InvalidProof)?;
    let endpoint = WebhookEndpoint::new(peer, &record.route.path, record.route.plaintext_approval)
        .map_err(|_| MissionError::InvalidProof)?;
    // Existing alert identity domain, shared with the canonical CLI effect lane. This is
    // verification of a retained binding, not a new intent or authority path.
    let identity = digest_of("fss.cli_alert_operation.v1", |e| {
        e.digest(record.event_revision);
        e.digest(endpoint.digest());
    });
    let key = hex(identity);
    if record.operation_id != format!("operation:alert:{key}")
        || record.obligation_id != format!("obligation:alert:{key}")
    {
        return Err(MissionError::InvalidProof);
    }
    Ok(SelectedPlan {
        record,
        root: plan_root,
        rendering,
        endpoint,
    })
}

fn same_selected(
    selected: &SelectedPlan,
    session: &AgentSession,
    mission: &MissionRecord,
    criterion: &MissionPlanCriterion,
) -> bool {
    let plan = &selected.record;
    criterion.session_id == session.session_id
        && criterion.mission_id == session.mission_id
        && criterion.principal == session.principal_id
        && criterion.mission_record_digest == mission.digest()
        && criterion.plan_id == plan.plan_id
        && criterion.plan_record_digest == ContentDigest::sha256(&plan.to_bytes())
        && criterion.plan_root == selected.root
        && criterion.control_plan_digest == plan.control_plan_digest
        && criterion.operation_id.as_str() == plan.operation_id
        && criterion.obligation_id.as_str() == plan.obligation_id
        && criterion.event_id.as_str() == plan.event_id
        && criterion.event_revision == plan.event_revision
}

/// Check the complete original plan at its compile-time anchor, never at a substituted head.
fn plan_event_root(
    history: &DeploymentHistory,
    selected: &SelectedPlan,
    session: &AgentSession,
) -> Result<ContentDigest, MissionError> {
    let token =
        AnchorToken::parse(&selected.record.anchor_token).ok_or(MissionError::InvalidProof)?;
    let position = resolve_anchor(history, &token).map_err(|_| MissionError::InvalidProof)?;
    let original = history
        .snapshot_at(position)
        .map_err(DeploymentSessionError::from)?;
    if !same_generations(&original.anchor, &session.current_anchor)
        || original.anchor.commit_sequence > session.current_anchor.commit_sequence
    {
        return Err(MissionError::StaleAuthority);
    }
    original
        .events
        .iter()
        .find(|event| {
            event.event.event_id.as_str() == selected.record.event_id
                && event.revision_digest == selected.record.event_revision
        })
        .map(|event| event.event_root)
        .ok_or(MissionError::InvalidProof)
}

fn checked_operation(
    head: &DeploymentSnapshot,
    selected: &SelectedPlan,
    event_root: ContentDigest,
) -> Result<Option<OperationFacts>, MissionError> {
    let plan = &selected.record;
    let Some(facts) = operation_facts(head, &plan.operation_id, &plan.obligation_id) else {
        return Ok(None);
    };
    let request_digest = digest_of("fss.reference_alert_request.v1", |e| {
        e.digest(event_root);
        e.digest(plan.event_revision);
        e.text(selected.endpoint.channel());
    });
    let expected_key = format!(
        "idempotency:alert:{}",
        plan.operation_id
            .strip_prefix("operation:alert:")
            .ok_or(MissionError::InvalidProof)?
    );
    if facts.operation_id != plan.operation_id
        || facts.effect_class != "alert.dispatch"
        || facts.request_digest != request_digest
        || facts.idempotency_key != expected_key
        || facts.authority_principal.is_empty()
        || facts.obligation.as_ref().is_some_and(|obligation| {
            obligation.operation_id != plan.operation_id
                || obligation.obligation_id != plan.obligation_id
        })
    {
        return Err(MissionError::InvalidProof);
    }
    // This repeats the frozen plan-approval encoding, not its authority. Effect preparation
    // records its own authority (currently the internal system principal); the operator's
    // session principal is bound here by the selected immutable plan's exact approval.
    let approval = digest_of("fss.cli_alert_plan_approval.v1", |e| {
        e.text(&facts.operation_id);
        e.text(&facts.idempotency_key);
        e.text(&facts.effect_class);
        e.digest(facts.request_digest);
        e.digest(facts.precondition_digest);
        e.text(&plan.obligation_id);
        e.text(selected.endpoint.channel());
        e.digest(event_root);
        e.digest(plan.event_revision);
        e.digest(selected.endpoint.digest());
        e.text(plan.principal.as_str());
    });
    if approval != plan.plan_approval {
        return Err(MissionError::InvalidProof);
    }
    Ok(Some(facts))
}

fn project_operation(facts: &OperationFacts) -> Result<MissionOperationFacts, MissionError> {
    Ok(MissionOperationFacts {
        operation_id: OperationId::parse(&facts.operation_id)?,
        state: MissionOperationState::parse(facts.state).map_err(owner_error)?,
        dispatched: facts.dispatched,
        receipt_digest: facts.receipt_digest,
        result_digest: facts.result_digest,
    })
}

fn project_obligation(
    facts: &OperationFacts,
) -> Result<Option<MissionObligationFacts>, MissionError> {
    facts
        .obligation
        .as_ref()
        .map(|obligation| {
            Ok(MissionObligationFacts {
                obligation_id: ObligationId::parse(&obligation.obligation_id)?,
                operation_id: OperationId::parse(&obligation.operation_id)?,
                state: MissionObligationState::parse(obligation.state).map_err(owner_error)?,
                proof_digest: obligation.proof_digest,
            })
        })
        .transpose()
}

/// Custody and immutable identity can be checked even for a historical projection whose
/// effect prefix predates this episode. Cross-time receipt comparisons belong to assessment.
fn episode_custody(
    root: &Path,
    plan: &PlanRecord,
) -> Result<Option<(MissionEpisodeFacts, PublishedEpisode)>, MissionError> {
    let Some(published) = read_episode(root, &plan.plan_id)? else {
        return Ok(None);
    };
    let record = &published.record;
    let episode = &record.episode;
    let plan_digest = ContentDigest::sha256(&plan.to_bytes());
    if record.mission_id != plan.mission_id
        || record.principal != plan.principal
        || record.plan_id != plan.plan_id
        || record.operation_id != plan.operation_id
        || episode.session_id != plan.session_id
        || episode.objective_id != plan.mission_id.as_str()
        || episode.plan_digest != plan_digest.to_text()
        || episode.decision_digest != plan.control_plan_digest.to_text()
    {
        return Err(MissionError::InvalidProof);
    }
    let outcome =
        MissionEpisodeOutcome::parse(record.terminal_state.as_str()).map_err(owner_error)?;
    let episode_state = episode.outcome.state.as_str();
    let outcome_matches = match outcome {
        MissionEpisodeOutcome::Verified => {
            matches!(episode_state, "succeeded" | "partially_succeeded")
                && episode
                    .outcome
                    .success_predicates
                    .iter()
                    .any(|value| value == "delivered")
        }
        MissionEpisodeOutcome::Failed => {
            episode_state == "failed"
                && episode
                    .outcome
                    .failed_predicates
                    .iter()
                    .any(|value| value == "delivered")
        }
        MissionEpisodeOutcome::Cancelled | MissionEpisodeOutcome::Withdrawn => {
            episode_state == "cancelled"
        }
    };
    if !outcome_matches
        || !episode
            .outcome
            .indeterminate_predicates
            .iter()
            .any(|value| value == "warranted")
    {
        return Err(MissionError::InvalidProof);
    }
    let projected = MissionEpisodeFacts {
        episode_id: episode.episode_id.clone(),
        record_digest: ContentDigest::sha256(&record.to_bytes()),
        publication_root: published.root,
        plan_record_digest: plan_digest,
        control_plan_digest: plan.control_plan_digest,
        operation_id: OperationId::parse(&record.operation_id)?,
        outcome,
    };
    Ok(Some((projected, published)))
}
pub(super) fn checked_episode(
    root: &Path,
    plan: &PlanRecord,
    facts: Option<&OperationFacts>,
) -> Result<Option<(MissionEpisodeFacts, PublishedEpisode)>, MissionError> {
    let Some((projected, published)) = episode_custody(root, plan)? else {
        return Ok(None);
    };
    verify_episode_receipts(plan, &published, projected.outcome, facts)?;
    Ok(Some((projected, published)))
}

fn verify_episode_receipts(
    plan: &PlanRecord,
    published: &PublishedEpisode,
    outcome: MissionEpisodeOutcome,
    facts: Option<&OperationFacts>,
) -> Result<(), MissionError> {
    let record = &published.record;
    let episode = &record.episode;
    match (outcome, facts) {
        (MissionEpisodeOutcome::Withdrawn, None) => {
            if !episode.effect_receipts.is_empty() || !episode.obligations.is_empty() {
                return Err(MissionError::InvalidProof);
            }
        }
        (MissionEpisodeOutcome::Withdrawn, Some(_)) | (_, None) => {
            return Err(MissionError::InvalidProof);
        }
        (_, Some(facts)) => {
            let obligation = facts
                .obligation
                .as_ref()
                .ok_or(MissionError::InvalidProof)?;
            if record.terminal_state.as_str() != facts.state
                || obligation.operation_id != plan.operation_id
                || obligation.obligation_id != plan.obligation_id
                || obligation.state != facts.state
                || facts.result_digest.is_none()
                || facts.result_digest != obligation.proof_digest
                || !episode
                    .effect_receipts
                    .contains(&format!("operation-receipt:{}", facts.receipt_digest))
                || !episode.effect_receipts.contains(&format!(
                    "result:{}",
                    facts.result_digest.ok_or(MissionError::InvalidProof)?
                ))
                || !episode.effect_receipts.contains(&format!(
                    "obligation-proof:{}",
                    obligation.proof_digest.ok_or(MissionError::InvalidProof)?
                ))
                || episode.obligations
                    != vec![format!("{}={}", plan.obligation_id, obligation.state)]
            {
                return Err(MissionError::InvalidProof);
            }
        }
    }
    Ok(())
}

fn bounded_count(value: usize) -> Result<u32, MissionError> {
    u32::try_from(value)
        .ok()
        .filter(|count| *count <= 4096)
        .ok_or(MissionError::InvalidProof)
}

/// Complete scoped inventory, including settled records, so disappearing or replaced custody
/// changes the witness instead of being silently read as an empty successful closure.
fn closure(
    root: &Path,
    snapshot: &DeploymentSnapshot,
    store: &dyn SessionProjection,
    session: &AgentSession,
    selected_plan_id: &str,
    now: TimestampNs,
    allow_historical_receipts: bool,
) -> Result<(MissionClosureFacts, bool), MissionError> {
    let mut e = CanonicalEncoder::new();
    e.text(CLOSURE_DOMAIN);
    session.principal_id.encode_canonical(&mut e);
    session.session_id.encode_canonical(&mut e);
    session.mission_id.encode_canonical(&mut e);
    // Broken roots are absent from visible_roots. Inspect them before enumeration so a
    // damaged retained plan cannot disappear from the closure inventory and permit a false
    // terminal state. Ownership cannot be established from corrupt custody, so refuse with
    // the same private-safe error for any broken plan slot; never disclose its identity.
    let inspection = fss_publication::inspect(
        root.join(super::PUBLICATIONS_RELPATH),
        super::publication_limits(),
    )
    .map_err(|_| MissionError::InvalidProof)?;
    if inspection
        .broken_slots()
        .any(|slot| slot.as_str().starts_with("plan-"))
    {
        return Err(MissionError::InvalidProof);
    }
    let mut plans = Vec::new();
    for published in super::published_records(root, "plan-")? {
        let record = PlanRecord::from_bytes(&published.record)?;
        if record.principal != session.principal_id
            || record.session_id != session.session_id
            || record.mission_id != session.mission_id
            || record.plan_id == selected_plan_id
        {
            continue;
        }
        if record.plan_id
            != PlanRecord::identity(
                &record.session_id,
                &record.anchor_token,
                record.plan_approval,
            )
            || published.children.as_slice() != [record.control_plan_digest]
        {
            return Err(MissionError::InvalidProof);
        }
        plans.push((record, published.root));
    }
    plans.sort_by(|a, b| a.0.plan_id.cmp(&b.0.plan_id));
    e.u32(bounded_count(plans.len())?);
    let mut unsettled_plans = 0;
    let mut receipts_current = true;
    for (plan, plan_root) in &plans {
        e.text(&plan.plan_id);
        e.digest(*plan_root);
        e.digest(ContentDigest::sha256(&plan.to_bytes()));
        let facts = operation_facts(snapshot, &plan.operation_id, &plan.obligation_id);
        let episode = episode_custody(root, plan)?;
        e.bool(episode.is_some());
        if let Some((episode, published)) = episode {
            let valid = verify_episode_receipts(plan, &published, episode.outcome, facts.as_ref());
            if !allow_historical_receipts {
                valid?;
            } else if valid.is_err() {
                // Custody and immutable links were checked above. A newer root-last episode
                // can legitimately lack a matching receipt in an older projection prefix.
                receipts_current = false;
            }
            e.digest(episode.record_digest);
            e.digest(episode.publication_root);
        } else {
            unsettled_plans += 1;
        }
        e.bool(facts.is_some());
        if let Some(facts) = facts {
            e.digest(facts.receipt_digest);
        }
    }

    let mut cases: Vec<_> = store
        .investigation_heads()
        .into_iter()
        .filter(|case| {
            case.principal() == &session.principal_id
                && case.record().mission_id == session.mission_id
        })
        .collect();
    cases.sort_by(|a, b| {
        a.record()
            .investigation_id
            .cmp(&b.record().investigation_id)
    });
    e.u32(bounded_count(cases.len())?);
    let mut active_cases = 0;
    for case in cases {
        if !session.privacy_scope.contains(case.privacy_class()) {
            return Err(MissionError::Denied);
        }
        e.text(&case.record().investigation_id);
        e.digest(case.digest());
        if super::investigation::is_open_state(case.record().state) {
            active_cases += 1;
        }
    }

    let mut claims: Vec<_> = store
        .work_claim_heads()
        .into_iter()
        .filter(|claim| {
            claim.principal() == &session.principal_id
                && claim.mission() == &session.mission_id
                && claim.claim().owner_session_id == session.session_id.as_str()
        })
        .collect();
    claims.sort_by(|a, b| a.claim().claim_id.cmp(&b.claim().claim_id));
    e.u32(bounded_count(claims.len())?);
    let mut active_claims = 0;
    for claim in claims {
        if !session.privacy_scope.contains(claim.privacy_class()) {
            return Err(MissionError::Denied);
        }
        e.text(&claim.claim().claim_id);
        e.digest(claim.digest());
        if matches!(
            claim.claim().state,
            WorkClaimState::Claimed | WorkClaimState::Active | WorkClaimState::Blocked
        ) {
            active_claims += 1;
        }
    }

    let inventory = store
        .supervision_inventory(session, now)
        .map_err(|_| MissionError::InvalidProof)?;
    e.u32(bounded_count(inventory.len())?);
    let mut active_supervisions = 0;
    for supervision in inventory {
        e.text(&supervision.subscription_id);
        e.digest(supervision.state_digest);
        let schedule_open = supervision.schedule.as_ref().is_some_and(|schedule| {
            schedule.active_window_count() != schedule.total_windows()
                || schedule.resolved_receipt().is_none()
        });
        if supervision.pending.is_some() || supervision.reservation.is_some() || schedule_open {
            active_supervisions += 1;
        }
    }
    for count in [
        unsettled_plans,
        active_cases,
        active_claims,
        active_supervisions,
    ] {
        e.u32(count);
    }
    Ok((
        MissionClosureFacts {
            witness_digest: ContentDigest::sha256(&e.finish()),
            unsettled_plans,
            active_cases,
            active_claims,
            active_supervisions,
        },
        receipts_current,
    ))
}

fn assess_facts(
    root: &Path,
    snapshot: &DeploymentSnapshot,
    store: &dyn SessionProjection,
    session: &AgentSession,
    selected: &SelectedPlan,
    original_event_root: ContentDigest,
) -> Result<MissionAssessmentFacts, MissionError> {
    let facts = checked_operation(snapshot, selected, original_event_root)?;
    let episode = checked_episode(root, &selected.record, facts.as_ref())?.map(|pair| pair.0);
    Ok(MissionAssessmentFacts {
        anchor: snapshot.anchor.clone(),
        evidence_time: evidence_now(snapshot),
        effect_journal_present: snapshot.effect_journal_present,
        effect_journal_root: snapshot.effect_journal_root,
        effect_record_count: snapshot.position.effect_records.unwrap_or(0),
        event_revision: snapshot
            .events
            .iter()
            .find(|event| event.event.event_id.as_str() == selected.record.event_id)
            .map(|event| event.revision_digest),
        operation: facts.as_ref().map(project_operation).transpose()?,
        obligation: facts
            .as_ref()
            .map(project_obligation)
            .transpose()?
            .flatten(),
        episode,
        closure: closure(
            root,
            snapshot,
            store,
            session,
            &selected.record.plan_id,
            evidence_now(snapshot),
            false,
        )?
        .0,
    })
}

/// Read-only validity of retained lifecycle metadata at this projection's exact semantic inputs.
/// This does not reassess or rewrite terminal history. Selected immutable custody failures refuse;
/// changed current facts remain explicit historical state rather than becoming current truth.
pub(super) fn projection_current(
    root: &Path,
    snapshot: &DeploymentSnapshot,
    store: &dyn SessionProjection,
    session: &AgentSession,
    revision: &MissionRevision,
    now: TimestampNs,
) -> Result<bool, MissionError> {
    admit_scope(session)?;
    let criterion = revision.criterion();
    // Current session authority admits the metadata. A historical projection may precede the
    // live session's rebase, but it cannot authorize private reads across control generations.
    if !same_generations(&session.current_anchor, &snapshot.anchor)
        || !same_generations(&criterion.baseline_anchor, &snapshot.anchor)
    {
        return Ok(false);
    }
    if snapshot.ledger_tail_uncommitted || snapshot.effect_tail_uncommitted {
        return Err(MissionError::InvalidProof);
    }
    let selected = selected_plan(root, session, &criterion.plan_id)?;
    if selected.root != criterion.plan_root
        || ContentDigest::sha256(&selected.record.to_bytes()) != criterion.plan_record_digest
        || selected.record.control_plan_digest != criterion.control_plan_digest
        || criterion.session_id != session.session_id
        || criterion.principal != session.principal_id
        || criterion.mission_id != session.mission_id
        || criterion.operation_id.as_str() != selected.record.operation_id
        || criterion.obligation_id.as_str() != selected.record.obligation_id
        || criterion.event_id.as_str() != selected.record.event_id
        || criterion.event_revision != selected.record.event_revision
    {
        return Err(MissionError::InvalidProof);
    }
    let episode = episode_custody(root, &selected.record)?.map(|pair| pair.0);
    let Some(assessment) = revision.assessment() else {
        return Ok(criterion.baseline_anchor == snapshot.anchor);
    };
    if let Some(retained) = &assessment.episode {
        if episode.as_ref().is_none_or(|current| {
            current.record_digest != retained.record_digest
                || current.publication_root != retained.publication_root
        }) {
            return Err(MissionError::InvalidProof);
        }
    }
    // An immutable episode may be newer than this view. Verify its custody above, then
    // classify the retained assessment as historical before comparing receipts across times.
    if assessment.episode != episode
        || assessment.anchor != snapshot.anchor
        || assessment.evidence_time != evidence_now(snapshot)
        || assessment.effect_journal_present != snapshot.effect_journal_present
        || assessment.effect_journal_root != snapshot.effect_journal_root
        || assessment.effect_record_count != snapshot.position.effect_records.unwrap_or(0)
    {
        return Ok(false);
    }
    let facts = operation_facts(
        snapshot,
        &selected.record.operation_id,
        &selected.record.obligation_id,
    );
    let checked = checked_episode(root, &selected.record, facts.as_ref())?.map(|pair| pair.0);
    let (closure, receipts_current) = closure(
        root,
        snapshot,
        store,
        session,
        &selected.record.plan_id,
        now,
        true,
    )?;
    if assessment.closure != closure {
        return Ok(false);
    }
    if !receipts_current {
        // Equal authenticated inventory roots with a mismatched receipt is a proof failure,
        // not a historical change. Only a changed witness can be classified as stale.
        return Err(MissionError::InvalidProof);
    }
    Ok(
        assessment.operation == facts.as_ref().map(project_operation).transpose()?
            && assessment.obligation
                == facts
                    .as_ref()
                    .map(project_obligation)
                    .transpose()?
                    .flatten()
            && assessment.episode == checked
            && assessment.event_revision
                == snapshot
                    .events
                    .iter()
                    .find(|event| event.event.event_id.as_str() == selected.record.event_id)
                    .map(|event| event.revision_digest),
    )
}

/// Enroll or assess an explicitly selected plan while the caller holds the deployment lock.
/// Exact retries preserve the original criterion, all budgets, and every immutable revision.
pub fn execute(root: &Path, request: &MissionRequest) -> Result<MissionAnswer, MissionError> {
    let plan_id = request.action.plan_id();
    if plan_id.is_empty() || plan_id.len() > PLAN_ID_LIMIT || !plan_id.starts_with("plan:") {
        return Err(MissionError::Contract(ContractError::InvalidIdentifier));
    }
    if let MissionAction::Assess { expected, .. } = &request.action {
        if expected.algorithm() != DigestAlgorithm::Sha256
            || expected.bytes() == [0; 32]
            || expected.is_laboratory()
        {
            return Err(MissionError::Contract(ContractError::InvalidDigest));
        }
    }
    let limits = OrientLimits::default();
    let history = DeploymentHistory::read(root, &limits).map_err(DeploymentSessionError::from)?;
    let head = history
        .snapshot_at(history.head())
        .map_err(DeploymentSessionError::from)?;
    let now = evidence_now(&head);
    let mut journal = SessionJournal::open(root)?;
    let result = (|| {
        let position = super::session_position(
            &mut journal,
            &history,
            &request.principal,
            &request.session_id,
            now,
        )?;
        let session = position.session;
        admit(&session, &head)?;
        let mission = mission_for_workspace(root, &session, &position.workspace)?;
        let retained = journal.store.mission_head(
            &request.principal,
            &request.session_id,
            mission.digest(),
            now,
        )?;
        if let Some(assessment) = retained.as_ref().and_then(MissionRevision::assessment) {
            // A syntactically valid journal is not enough: previously admitted evidence and
            // effect prefixes must still belong to it. This checks the already loaded record
            // roots without another source read, and refuses truncation or a rewritten prefix
            // even when a divergent replacement has the same or a larger record count.
            let retained_position = HistoryPosition {
                commit_sequence: assessment.anchor.commit_sequence,
                effect_records: assessment
                    .effect_journal_present
                    .then_some(assessment.effect_record_count),
            };
            let Some((anchor, _, effect_root)) = history.roots_at(retained_position) else {
                return Err(MissionError::InvalidProof);
            };
            if anchor != assessment.anchor || effect_root != assessment.effect_journal_root {
                return Err(MissionError::InvalidProof);
            }
        }
        if retained.as_ref().is_some_and(|revision| {
            !same_generations(&revision.criterion().baseline_anchor, &head.anchor)
                || revision.criterion().contract_basis != *position.workspace.contract_basis()
        }) {
            return Err(MissionError::StaleAuthority);
        }
        let selected = selected_plan(root, &session, plan_id)?;
        let original_event_root = plan_event_root(&history, &selected, &session)?;
        if retained.as_ref().is_some_and(|revision| {
            !same_selected(&selected, &session, &mission, revision.criterion())
        }) {
            return Err(owner_error(OwnerMissionError::Conflict));
        }
        let before = journal.store.committed_root();
        let revision = match &request.action {
            MissionAction::Adopt {
                decision_deadline, ..
            } => {
                let criterion = match retained {
                    Some(ref revision)
                        if revision.criterion().decision_deadline == *decision_deadline =>
                    {
                        revision.criterion().clone()
                    }
                    Some(_) => return Err(owner_error(OwnerMissionError::Conflict)),
                    None => MissionPlanCriterion {
                        session_id: session.session_id.clone(),
                        mission_id: session.mission_id.clone(),
                        principal: session.principal_id.clone(),
                        mission_record_digest: mission.digest(),
                        plan_id: selected.record.plan_id.clone(),
                        plan_record_digest: ContentDigest::sha256(&selected.record.to_bytes()),
                        plan_root: selected.root,
                        control_plan_digest: selected.record.control_plan_digest,
                        operation_id: OperationId::parse(&selected.record.operation_id)?,
                        obligation_id: ObligationId::parse(&selected.record.obligation_id)?,
                        event_id: EventId::parse(&selected.record.event_id)?,
                        event_revision: selected.record.event_revision,
                        contract_basis: position.workspace.contract_basis().clone(),
                        baseline_anchor: session.current_anchor.clone(),
                        decision_deadline: *decision_deadline,
                    },
                };
                // Verify any already present execution before enrollment; never bind a label
                // to another event, route or approval just because its ID happens to match.
                checked_operation(&head, &selected, original_event_root)?;
                journal
                    .store
                    .register_mission_plan(&request.principal, criterion, now)?
            }
            MissionAction::Assess { expected, .. } => {
                let current = retained.ok_or_else(|| owner_error(OwnerMissionError::Conflict))?;
                let facts = assess_facts(
                    root,
                    &head,
                    &journal.store,
                    &session,
                    &selected,
                    original_event_root,
                )?;
                if current.state().is_terminal() && current.digest() == *expected {
                    // Terminal history is an as-of proof. Revalidation may mark its projection
                    // historical, but a later observation cannot replace its retained receipt.
                    current
                } else {
                    journal.store.assess_mission_plan(
                        &request.principal,
                        &request.session_id,
                        mission.digest(),
                        *expected,
                        facts,
                        now,
                    )?
                }
            }
        };
        let committed = before != journal.store.committed_root();
        let orientation = orient_bound(
            Some((root, &head)),
            &head,
            session.view,
            &session.principal_id,
            &session.mission_id,
            &session.session_id,
            &limits,
            super::session_briefs(root, &journal.store, &session, &head, now)?,
            &mission,
        )?;
        let request_digest = digest_of(REQUEST_DOMAIN, |e| {
            request.session_id.encode_canonical(e);
            request.principal.encode_canonical(e);
            e.digest(mission.digest());
            e.text(request.action.name());
            e.text(plan_id);
            match &request.action {
                MissionAction::Adopt {
                    decision_deadline, ..
                } => e.i128(decision_deadline.0),
                MissionAction::Assess { expected, .. } => e.digest(*expected),
            }
        });
        Ok(MissionAnswer {
            revision,
            session,
            orientation,
            control_plan: selected.rendering,
            plan_root: selected.root,
            committed,
            journal_root: journal.store.committed_root(),
            request_digest,
            head_moved: position.head_moved,
        })
    })();
    // All live-session clock/expiry and mission transitions are pinned even when later checks
    // refuse. No partially committed result is exposed before this succeeds.
    journal.commit_pin()?;
    result
}
