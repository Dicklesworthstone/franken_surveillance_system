#![forbid(unsafe_code)]
//! Bounded work-claim leases over mission cases (FSS-226), projected onto deployment roots as
//! the work-claiming intent family of AOP-006 `investigate`.
//!
//! **Coordination only.** A claim reserves one exact unit of cognitive work (a whole case, or one
//! hypothesis, discriminator, or probe of it) for one session so collaborating sessions do not
//! duplicate it. It never confers effect authority, never dispatches anything, and never settles
//! an obligation. Every command (reads included, because they can advance clocks) is committed to
//! the deployment's session journal through the journaled coordination engine, and the journal
//! root is pinned before the answer or refusal is returned.
//!
//! **Identity.** The work root is derived from the case and the exact work item, and the claim
//! identity from the work root, so two sessions claiming the same work name the same claim and
//! the second is refused as a conflict. Leases run on the deployment evidence clock (the clock
//! sessions already use) and are bounded by the engine's ceiling and the session's own expiry.

use std::collections::BTreeSet;
use std::path::Path;

use fss_core::{
    AgentSession, CanonicalEncode, CaseId, ContentDigest, PrincipalId, SessionId, TimestampNs,
    WorkClaimState,
};

use crate::agent_orient::OrientClaimBrief;
use crate::agent_session::checkpoint::journal::DurableSessionStore;
use crate::agent_session::checkpoint::journal::coordination::CoordinationCommand;
use crate::agent_session::checkpoint::journal::coordination::investigations::InvestigationRevision;
use crate::agent_session::work_claims::{
    WorkClaimError, WorkClaimRecovery, WorkClaimRequest, WorkClaimRevision, WorkClaimUpdate,
};

pub use crate::agent_session::work_claims::{CAPABILITY_WORK_CLAIM, WorkClaimError as ClaimError};

use super::investigation::{CASE_PRIVACY_CLASS, visible_cases};
use super::{
    DeploymentHistory, DeploymentOrientation, DeploymentSessionError, OrientLimits, SessionJournal,
    digest_of, evidence_now, hex, orient_bound,
};

const WORK_SCOPE_DOMAIN: &str = "fss.reference_agent_work_scope.v1";
const CLAIM_REQUEST_DOMAIN: &str = "fss.reference_agent_claim_request.v1";
/// Lease a claim takes when none is requested.
pub const DEFAULT_LEASE_MS: u64 = 60_000;
/// Most dependencies one claim may name.
pub const MAX_CLAIM_DEPENDENCIES: usize = 64;

/// The exact unit of work a claim reserves.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ClaimWork {
    /// The whole case.
    Case,
    /// One hypothesis of the case.
    Hypothesis(String),
    /// One discriminator of the case.
    Discriminator(String),
    /// One probe handle of the case.
    Probe(String),
}

impl ClaimWork {
    /// Registered spelling: `case`, or `<kind>:<id>`.
    #[must_use]
    pub fn label(&self) -> String {
        match self {
            Self::Case => "case".to_owned(),
            Self::Hypothesis(id) => format!("hypothesis:{id}"),
            Self::Discriminator(id) => format!("discriminator:{id}"),
            Self::Probe(id) => format!("probe:{id}"),
        }
    }
}

/// The work root and claim identity of `work` in `case_id`.
#[must_use]
pub fn claim_identity(case_id: &str, work: &ClaimWork) -> (String, ContentDigest) {
    let work_root = digest_of(WORK_SCOPE_DOMAIN, |encoder| {
        encoder.text(case_id);
        encoder.text(&work.label());
    });
    (
        format!(
            "claim:{}",
            hex(work_root).chars().take(32).collect::<String>()
        ),
        work_root,
    )
}

/// A lifecycle change of a held claim.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ClaimChange {
    /// Begin or resume the work (every dependency must be completed).
    Activate,
    /// Record a progress artifact without changing the active state.
    Progress(ContentDigest),
    /// Block the work, preserving a progress artifact.
    Block(ContentDigest),
    /// Record the work result (a result, not a verified physical fact or effect outcome).
    Complete(ContentDigest),
    /// Stop coordinating the work.
    Release,
    /// Extend the lease to `lease_ms` past the evidence clock (strictly later than before).
    Renew {
        /// Lease length from now.
        lease_ms: u64,
    },
}

/// An explicit recovery of a claim.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ClaimRecovery {
    /// Record the lapsed lease's expiry.
    Expire,
    /// Hand the work to another live session of the same principal and mission.
    Transfer(SessionId),
    /// Reacquire released, expired, or lapsed work under a fresh fence.
    Reclaim {
        /// Lease length from now.
        lease_ms: u64,
    },
}

/// One work-claim action.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ClaimAction {
    /// Reserve exact work in a case visible to the session.
    Acquire {
        /// Case the work belongs to.
        case_id: String,
        /// The exact work item.
        work: ClaimWork,
        /// Lease length from now.
        lease_ms: u64,
        /// Claims that must complete first.
        dependencies: BTreeSet<String>,
    },
    /// Read one claim's current head (journaled; it never extends the lease).
    Inspect {
        /// Claim identity.
        claim_id: String,
    },
    /// Change the held claim's exact current revision.
    Change {
        /// Claim identity.
        claim_id: String,
        /// Exact current revision digest (CAS precondition, not permission).
        expected: ContentDigest,
        /// The change.
        change: ClaimChange,
    },
    /// Explicitly expire, transfer, or reclaim.
    Recover {
        /// Claim identity.
        claim_id: String,
        /// Exact current revision digest.
        expected: ContentDigest,
        /// The recovery.
        recovery: ClaimRecovery,
    },
    /// List the claims of the mission visible to the session.
    List,
}

/// One work-claim request.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ClaimRequest {
    /// Session whose authority admits the command.
    pub session_id: SessionId,
    /// The session's principal.
    pub principal: PrincipalId,
    /// The action.
    pub action: ClaimAction,
}

/// The answer to one work-claim request.
#[derive(Clone, Debug)]
pub struct ClaimAnswer {
    /// The live session.
    pub session: AgentSession,
    /// The claim the action produced or read (`None` for a list).
    pub claim: Option<WorkClaimRevision>,
    /// Every claim of the mission visible to the session, in identity order.
    pub claims: Vec<WorkClaimRevision>,
    /// True when a new claim revision was committed.
    pub committed: bool,
    /// Session-bound situation as of the session's anchor.
    pub orientation: DeploymentOrientation,
    /// Committed session-journal root after the command.
    pub journal_root: ContentDigest,
    /// Canonical request digest.
    pub request_digest: ContentDigest,
    /// Deployment evidence time the command ran at.
    pub now: TimestampNs,
    /// True when the deployment head lies past the session's anchor.
    pub head_moved: bool,
}

/// Claims of the session's mission visible to it (principal, mission, privacy), by identity.
pub(super) fn visible_claims(
    store: &DurableSessionStore,
    session: &AgentSession,
) -> Vec<WorkClaimRevision> {
    let mut claims: Vec<WorkClaimRevision> = store
        .work_claim_heads()
        .into_iter()
        .filter(|head| {
            head.principal() == &session.principal_id
                && head.mission() == &session.mission_id
                && session.privacy_scope.contains(head.privacy_class())
        })
        .collect();
    claims.sort_by(|left, right| left.claim().claim_id.cmp(&right.claim().claim_id));
    claims
}

/// Whether a claim is non-terminal (a lease someone holds or must expire).
fn is_open(state: WorkClaimState) -> bool {
    matches!(
        state,
        WorkClaimState::Claimed | WorkClaimState::Active | WorkClaimState::Blocked
    )
}

/// The non-terminal claims `session` sees, as its situation lists them at `now`.
pub(super) fn claim_briefs(
    store: &DurableSessionStore,
    session: &AgentSession,
    now: TimestampNs,
) -> Vec<OrientClaimBrief> {
    visible_claims(store, session)
        .iter()
        .filter(|head| is_open(head.claim().state))
        .map(|head| {
            let claim = head.claim();
            OrientClaimBrief {
                claim_id: claim.claim_id.clone(),
                case_id: claim.case_id.clone().unwrap_or_default(),
                state: claim.state.as_str().to_owned(),
                owner_session: claim.owner_session_id.clone(),
                expires_at: TimestampNs(claim.expires_at_ns),
                lease_live: head.lease_covers(now),
                held_here: claim.owner_session_id == session.session_id.as_str(),
            }
        })
        .collect()
}

fn lease_end(now: TimestampNs, lease_ms: u64) -> Option<TimestampNs> {
    let lease_ns = i128::from(lease_ms).checked_mul(1_000_000)?;
    now.0.checked_add(lease_ns).map(TimestampNs)
}

/// Whether `work` names an element of the case revision `head`.
fn work_exists(head: &InvestigationRevision, work: &ClaimWork) -> bool {
    let record = head.record();
    match work {
        ClaimWork::Case => true,
        ClaimWork::Hypothesis(id) => record
            .hypotheses
            .iter()
            .any(|hypothesis| hypothesis.hypothesis_id == *id),
        ClaimWork::Discriminator(id) => record
            .discriminators
            .iter()
            .any(|discriminator| discriminator.discriminator_id == *id),
        ClaimWork::Probe(id) => record.probes.iter().any(|probe| probe == id),
    }
}

fn encode_action(encoder: &mut fss_core::CanonicalEncoder, action: &ClaimAction) {
    match action {
        ClaimAction::Acquire {
            case_id,
            work,
            lease_ms,
            dependencies,
        } => {
            encoder.text("acquire");
            encoder.text(case_id);
            encoder.text(&work.label());
            encoder.u64(*lease_ms);
            encoder.u32(dependencies.len() as u32);
            for dependency in dependencies {
                encoder.text(dependency);
            }
        }
        ClaimAction::Inspect { claim_id } => {
            encoder.text("inspect");
            encoder.text(claim_id);
        }
        ClaimAction::Change {
            claim_id,
            expected,
            change,
        } => {
            encoder.text("change");
            encoder.text(claim_id);
            encoder.digest(*expected);
            match change {
                ClaimChange::Activate => encoder.text("activate"),
                ClaimChange::Progress(root) => {
                    encoder.text("progress");
                    encoder.digest(*root);
                }
                ClaimChange::Block(root) => {
                    encoder.text("block");
                    encoder.digest(*root);
                }
                ClaimChange::Complete(root) => {
                    encoder.text("complete");
                    encoder.digest(*root);
                }
                ClaimChange::Release => encoder.text("release"),
                ClaimChange::Renew { lease_ms } => {
                    encoder.text("renew");
                    encoder.u64(*lease_ms);
                }
            }
        }
        ClaimAction::Recover {
            claim_id,
            expected,
            recovery,
        } => {
            encoder.text("recover");
            encoder.text(claim_id);
            encoder.digest(*expected);
            match recovery {
                ClaimRecovery::Expire => encoder.text("expire"),
                ClaimRecovery::Transfer(recipient) => {
                    encoder.text("transfer");
                    recipient.encode_canonical(encoder);
                }
                ClaimRecovery::Reclaim { lease_ms } => {
                    encoder.text("reclaim");
                    encoder.u64(*lease_ms);
                }
            }
        }
        ClaimAction::List => encoder.text("list"),
    }
}

/// The coordination command of `action` at `now`, after deployment-side validation.
fn command(
    store: &DurableSessionStore,
    session: &AgentSession,
    action: &ClaimAction,
    now: TimestampNs,
) -> Result<Option<CoordinationCommand>, WorkClaimError> {
    let lease = |lease_ms: u64| lease_end(now, lease_ms).ok_or(WorkClaimError::InvalidLease);
    Ok(Some(match action {
        ClaimAction::List => return Ok(None),
        ClaimAction::Acquire {
            case_id,
            work,
            lease_ms,
            dependencies,
        } => {
            if dependencies.len() > MAX_CLAIM_DEPENDENCIES {
                return Err(WorkClaimError::CapacityExceeded);
            }
            // The work must name an element of a case this session can see, as it stands now.
            let case = visible_cases(store, session)
                .into_iter()
                .find(|case| case.record().investigation_id == *case_id)
                .ok_or(WorkClaimError::Unavailable)?;
            if !work_exists(&case, work) {
                return Err(WorkClaimError::Unavailable);
            }
            let (claim_id, work_root) = claim_identity(case_id, work);
            CoordinationCommand::Acquire(WorkClaimRequest {
                claim_id,
                case_id: CaseId::parse(case_id.clone())?,
                work_root,
                privacy_class: CASE_PRIVACY_CLASS.to_owned(),
                expires_at: lease(*lease_ms)?,
                dependencies: dependencies.clone(),
            })
        }
        ClaimAction::Inspect { claim_id } => CoordinationCommand::Inspect {
            claim_id: claim_id.clone(),
        },
        ClaimAction::Change {
            claim_id,
            expected,
            change,
        } => CoordinationCommand::Update {
            claim_id: claim_id.clone(),
            expected: *expected,
            change: match change {
                ClaimChange::Activate => WorkClaimUpdate::Activate,
                ClaimChange::Progress(root) => WorkClaimUpdate::Progress(*root),
                ClaimChange::Block(root) => WorkClaimUpdate::Block(*root),
                ClaimChange::Complete(root) => WorkClaimUpdate::Complete(*root),
                ClaimChange::Release => WorkClaimUpdate::Release,
                ClaimChange::Renew { lease_ms } => WorkClaimUpdate::Renew(lease(*lease_ms)?),
            },
        },
        ClaimAction::Recover {
            claim_id,
            expected,
            recovery,
        } => CoordinationCommand::Recover {
            claim_id: claim_id.clone(),
            expected: *expected,
            recovery: match recovery {
                ClaimRecovery::Expire => WorkClaimRecovery::Expire,
                ClaimRecovery::Transfer(recipient) => WorkClaimRecovery::Transfer {
                    recipient: recipient.clone(),
                },
                ClaimRecovery::Reclaim { lease_ms } => WorkClaimRecovery::Reclaim {
                    expires_at: lease(*lease_ms)?,
                },
            },
        },
    }))
}

/// Applies one work-claim action to a deployment's session journal.
///
/// The session must be live and hold the work-claim grant. Coordination is initialized on first
/// use (one-way, fixed ceilings). Refusals are typed (`ClaimRefused`), and every command and any
/// refusal-side session change is committed and pinned before the answer is returned. The
/// situation returned is the one as of the session's anchor.
pub fn work_claim(
    root: &Path,
    request: &ClaimRequest,
) -> Result<ClaimAnswer, DeploymentSessionError> {
    let limits = OrientLimits::default();
    let history = DeploymentHistory::read(root, &limits)?;
    let head = history.snapshot_at(history.head())?;
    let now = evidence_now(&head);
    let request_digest = digest_of(CLAIM_REQUEST_DOMAIN, |encoder| {
        request.session_id.encode_canonical(encoder);
        request.principal.encode_canonical(encoder);
        encode_action(encoder, &request.action);
        head.anchor.encode_canonical(encoder);
    });
    let mut journal = SessionJournal::open(root)?;
    let principal = &request.principal;
    let session_id = &request.session_id;
    let position = super::session_position(&mut journal, &history, principal, session_id, now)?;
    let refused = |journal: &SessionJournal, error: WorkClaimError| {
        journal.commit_pin()?;
        Err(DeploymentSessionError::ClaimRefused(error))
    };
    if !position
        .session
        .capabilities
        .contains(CAPABILITY_WORK_CLAIM)
    {
        return refused(
            &journal,
            WorkClaimError::Session(crate::agent_session::ReferenceSessionError::GrantEscalation),
        );
    }
    let heads_before: Vec<ContentDigest> = journal
        .store
        .work_claim_heads()
        .iter()
        .map(WorkClaimRevision::digest)
        .collect();
    let command = match command(&journal.store, &position.session, &request.action, now) {
        Ok(command) => command,
        Err(error) => return refused(&journal, error),
    };
    let claim = match command {
        None => None,
        Some(command) => {
            if !journal.store.investigations_enabled() {
                // Coordination is enabled together with case history; claims need a case.
                journal.enable_cases()?;
            }
            match journal
                .store
                .coordinate(principal, session_id, command, now)
            {
                Ok(revision) => Some(revision),
                Err(error) => {
                    let error = DeploymentSessionError::from(error);
                    if matches!(error, DeploymentSessionError::ClaimRefused(_)) {
                        journal.commit_pin()?;
                    }
                    return Err(error);
                }
            }
        }
    };
    let session = journal.store.session(principal, session_id, now)?;
    journal.commit_pin()?;
    let heads_after: Vec<ContentDigest> = journal
        .store
        .work_claim_heads()
        .iter()
        .map(WorkClaimRevision::digest)
        .collect();
    let committed = heads_before != heads_after;
    let claims = visible_claims(&journal.store, &session);
    let orientation = orient_bound(
        Some((root, &head)),
        &position.snapshot,
        session.view,
        &session.principal_id,
        &session.mission_id,
        &session.session_id,
        &limits,
        super::session_briefs(root, &journal.store, &session, &session.current_anchor, now)?,
    )?;
    Ok(ClaimAnswer {
        session,
        claim,
        claims,
        committed,
        orientation,
        journal_root: journal.store.committed_root(),
        request_digest,
        now,
        head_moved: position.head_moved,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn claim_identity_is_the_exact_work_item() {
        let (case, case_root) = claim_identity("case:a", &ClaimWork::Case);
        let (probe, probe_root) = claim_identity("case:a", &ClaimWork::Probe("p1".to_owned()));
        assert_ne!(case, probe);
        assert_ne!(case_root, probe_root);
        assert_eq!(
            claim_identity("case:a", &ClaimWork::Probe("p1".to_owned())),
            (probe.clone(), probe_root)
        );
        assert_ne!(
            claim_identity("case:b", &ClaimWork::Probe("p1".to_owned())).0,
            probe
        );
        assert_ne!(
            claim_identity("case:a", &ClaimWork::Hypothesis("p1".to_owned())).0,
            probe
        );
        assert!(probe.starts_with("claim:") && probe.len() == "claim:".len() + 32);
    }

    #[test]
    fn leases_are_bounded_arithmetic() {
        assert_eq!(
            lease_end(TimestampNs(5), 2),
            Some(TimestampNs(5 + 2_000_000))
        );
        assert_eq!(lease_end(TimestampNs(i128::MAX), 1), None);
    }
}
