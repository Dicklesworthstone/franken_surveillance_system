#![forbid(unsafe_code)]
//! Published, witnessed control plans for the canonical agent effect grammar (AOP-007 `plan`,
//! consumed by AOP-008 `commit`).
//!
//! **Agent plane only.** A plan record is cognition: it names an exact effect intent (today: one
//! alert webhook for one event revision over one approved relay route), the session and anchor it
//! was compiled at, the exact operator approval digest that admits preparation, and the digest of
//! the rendered `fss.agent_control_plan.v1` DAG published beside it. Publishing a plan writes only
//! under `<root>/agent/publications/` (root-last; a crash leaves the root absent or complete).
//! Preparing, committing, and cancelling the effect are effect-plane transitions owned by the
//! durable effect journal and are never performed here.
//!
//! **Identity.** A plan identity is derived from the session, the anchor token, and the plan
//! approval digest, so replanning the same intent at the same anchor is an exact retry, while a
//! new event revision, route, principal, or anchor yields a different plan.

use std::path::Path;

use fss_core::{AgentSession, ContentDigest, MissionId, PrincipalId, SessionId, TimestampNs};
use fss_publication::SlotName;

use crate::agent_orient::{DeploymentSnapshot, OrientPlanBrief};

use super::{
    DeploymentHistory, DeploymentOrientation, DeploymentSessionError, MAX_RECORD_BYTES,
    OrientLimits, SessionJournal, hex, orient_bound, publish_record, read_published,
};
use crate::agent_session::checkpoint::journal::coordination::investigations::{
    InvestigationError, InvestigationRevision,
};

mod record;
pub use record::{AlertRoute, PlanRecord};

// The pure codec and published-record reader share the same admission ceiling.
const _: () = assert!(record::MAX_PLAN_RECORD_BYTES == MAX_RECORD_BYTES);

impl PlanRecord {
    fn slot(plan_id: &str) -> Result<SlotName, DeploymentSessionError> {
        SlotName::parse(&format!(
            "plan-{}",
            hex(ContentDigest::sha256(plan_id.as_bytes()))
        ))
        .map_err(|_| DeploymentSessionError::Internal("plan slot name".to_owned()))
    }
}

/// What a plan is compiled against: the live session, its situation at its anchor, and the
/// investigation case revision it rests on (when named).
#[derive(Clone, Debug)]
pub struct PlanningContext {
    /// The live session.
    pub session: AgentSession,
    /// Session-bound situation as of the session's anchor.
    pub orientation: DeploymentOrientation,
    /// The named case's current head (visible to the session).
    pub case: Option<InvestigationRevision>,
    /// True when the deployment head lies past the session's anchor.
    pub head_moved: bool,
    /// Deployment evidence time.
    pub now: TimestampNs,
    /// Deployment site lineage.
    pub site_lineage: String,
    /// Committed session-journal root after the read.
    pub journal_root: ContentDigest,
}

/// A planning context whose agent-session journal remains exclusively owned.
///
/// Keep this guard alive while preparing or committing an effect that relies on the session or
/// an investigation revision. A competing session/case writer is refused until the guard drops.
/// This owns no effect capability and does not authorize any network operation.
pub struct PlanningContextGuard {
    context: PlanningContext,
    // Last field: context is retired before its session-journal ownership.
    journal: SessionJournal,
}

impl PlanningContextGuard {
    /// The exact session and situation admitted under the held journal.
    #[must_use]
    pub fn context(&self) -> &PlanningContext {
        &self.context
    }

    /// Revalidates a published plan's mission, anchor and optional exact case witness.
    ///
    /// Call only for a new commitment. An already committed operation must still be reported
    /// through its durable receipt even if its old planning witnesses have since changed.
    pub fn validate_plan(&self, record: &PlanRecord) -> Result<(), DeploymentSessionError> {
        let session = &self.context.session;
        if record.principal != session.principal_id
            || record.session_id != session.session_id
            || record.mission_id != session.mission_id
        {
            return Err(DeploymentSessionError::PlanInvalid(
                "the plan's principal, session or mission no longer matches".to_owned(),
            ));
        }
        if record.anchor_token != self.context.orientation.anchor_token {
            return Err(DeploymentSessionError::PlanInvalid(
                "the session was rebased beyond the plan's exact situation anchor".to_owned(),
            ));
        }
        if let Some((case_id, expected)) = &record.case {
            let current = super::investigation::visible_cases(&self.journal.store, session)
                .into_iter()
                .find(|case| &case.record().investigation_id == case_id)
                .ok_or_else(|| {
                    DeploymentSessionError::PlanInvalid(
                        "the plan's investigation witness is no longer available".to_owned(),
                    )
                })?;
            if current.digest() != *expected {
                return Err(DeploymentSessionError::PlanInvalid(format!(
                    "case {case_id} no longer has the exact revision witnessed by plan {}",
                    record.plan_id
                )));
            }
            validate_case_basis(&current, session)?;
        }
        Ok(())
    }
}

fn validate_case_basis(
    case: &InvestigationRevision,
    session: &AgentSession,
) -> Result<(), DeploymentSessionError> {
    if case.record().basis_anchor != session.current_anchor
        || case.record().contract_basis != fss_core::reference_contract_basis()
    {
        return Err(DeploymentSessionError::PlanInvalid(
            "the named investigation needs an explicit rebase before it can support a plan"
                .to_owned(),
        ));
    }
    Ok(())
}

/// Locates a live session and compiles its situation; the session lock is released on return.
///
/// Fails with `SessionUnknown`/`SessionStale` for an unknown or unresolvable session and with
/// `CaseRefused(Unavailable)` when a named case is not visible to the session.
pub fn planning_context(
    root: impl super::SessionRoot,
    principal: &PrincipalId,
    session_id: &SessionId,
    case_id: Option<&str>,
) -> Result<PlanningContext, DeploymentSessionError> {
    hold_planning_context(root, principal, session_id, case_id).map(|guard| guard.context)
}

/// Locates a live session and retains its exclusive journal ownership with the returned context.
///
/// A named case must be applicable at the session's exact anchor and current contract basis.
/// The caller bounds the lifetime of this guard; it must not outlive its owned operation.
pub fn hold_planning_context(
    root: impl super::SessionRoot,
    principal: &PrincipalId,
    session_id: &SessionId,
    case_id: Option<&str>,
) -> Result<PlanningContextGuard, DeploymentSessionError> {
    let context = root.session_context();
    let root = context.root();
    let limits = OrientLimits::default();
    let history = DeploymentHistory::read(root, &limits)?;
    let head = history.snapshot_at(history.head())?;
    let now = context.now(&head, principal)?;
    let mut journal = SessionJournal::open(root)?;
    let position = super::session_position(&mut journal, &history, principal, session_id, now);
    // Refused admission can still advance durable session clock watermarks.
    journal.commit_pin()?;
    let position = position?;
    let session = position.session;
    let cases = super::investigation::visible_cases(&journal.store, &session);
    let case = match case_id {
        None => None,
        Some(id) => Some(
            cases
                .iter()
                .find(|case| case.record().investigation_id == id)
                .cloned()
                .ok_or(DeploymentSessionError::CaseRefused(
                    InvestigationError::Unavailable,
                ))?,
        ),
    };
    if let Some(case) = &case {
        validate_case_basis(case, &session)?;
    }
    // A plan binds the world situation and immutable requested goal at the session's anchor.
    // No mutable case, plan or mission-assessment briefs enter that frame: enrolling this
    // exact plan as a mission criterion must not change its bytes when approval is retried.
    // Current lifecycle assessments are projected by the mission and session surfaces.
    let orientation = orient_bound(
        None,
        &position.snapshot,
        session.view,
        &session.principal_id,
        &session.mission_id,
        &session.session_id,
        &limits,
        super::SessionBriefs::default(),
        &super::mission_for_workspace(root, &session, &position.workspace)?,
    )?;
    let context = PlanningContext {
        site_lineage: position.snapshot.site_lineage.clone(),
        session,
        orientation,
        case,
        head_moved: position.head_moved,
        now,
        journal_root: journal.store.committed_root(),
    };
    Ok(PlanningContextGuard { context, journal })
}

/// Publishes `record` root-last with the rendered control plan beside it. Republishing an
/// identical plan is idempotent; a different plan under the same identity is refused.
pub fn publish_plan(
    root: &Path,
    record: &PlanRecord,
    control_plan_json: &[u8],
) -> Result<ContentDigest, DeploymentSessionError> {
    validate_disclosure(record)?;
    if ContentDigest::sha256(control_plan_json) != record.control_plan_digest {
        return Err(DeploymentSessionError::Internal(
            "the control plan rendering does not match the record".to_owned(),
        ));
    }
    let slot = PlanRecord::slot(&record.plan_id)?;
    if let Some(published_root) = verify_plan_publication(root, record)? {
        return Ok(published_root);
    }
    Ok(publish_record(
        root,
        &slot,
        "agent-plan",
        &record.to_bytes(),
        &[control_plan_json.to_vec()],
        None,
    )?
    .root)
}

/// Verifies that any existing publication matches the full proposed plan record.
///
/// Call before preparing an effect while retaining the planning guard. A changed case witness,
/// route, deadline or rendering cannot reuse a previous preview's identity and approval.
/// Returns the verified existing root, or `None` if this plan has not been published.
pub fn verify_plan_publication(
    root: &Path,
    record: &PlanRecord,
) -> Result<Option<ContentDigest>, DeploymentSessionError> {
    validate_disclosure(record)?;
    let slot = PlanRecord::slot(&record.plan_id)?;
    match read_plan_at(root, &slot)? {
        Some((existing, published_root)) if existing == *record => Ok(Some(published_root)),
        Some(_) => Err(DeploymentSessionError::PlanInvalid(
            "a different plan is already published under this identity; refresh the session and \
             rebase its case before approving a new plan"
                .to_owned(),
        )),
        None => Ok(None),
    }
}

fn validate_disclosure(record: &PlanRecord) -> Result<(), DeploymentSessionError> {
    record.route.validate_disclosure().map_err(|_| {
        DeploymentSessionError::PlanInvalid(
            "the alert disclosure profile and its separate metadata approval do not agree"
                .to_owned(),
        )
    })
}

fn read_plan_at(
    root: &Path,
    slot: &SlotName,
) -> Result<Option<(PlanRecord, ContentDigest)>, DeploymentSessionError> {
    let published = read_published(root, slot).map_err(|error| match error {
        DeploymentSessionError::HandoffInvalid(reason) => {
            DeploymentSessionError::PlanInvalid(reason)
        }
        other => other,
    })?;
    published
        .map(|published| {
            PlanRecord::from_bytes(&published.record)
                .map(|record| (record, published.root))
                .map_err(|error| {
                    DeploymentSessionError::PlanInvalid(format!(
                        "the plan record does not verify: {error}"
                    ))
                })
        })
        .transpose()
}

/// Active plans of `mission_id` by `principal`, as a session-bound orientation lists them:
/// every published plan without a published execution episode (an episode closes a plan whose
/// operation is terminal in the head snapshot, or withdraws one never prepared).
pub(super) fn plan_briefs(
    root: &Path,
    head: &DeploymentSnapshot,
    mission_id: &MissionId,
    principal: &PrincipalId,
) -> Result<Vec<OrientPlanBrief>, DeploymentSessionError> {
    let closed = super::episode::closed_plans(root, mission_id, principal)?;
    let mut briefs = Vec::new();
    for published in super::published_records(root, "plan-")? {
        let record = PlanRecord::from_bytes(&published.record).map_err(|error| {
            DeploymentSessionError::StoreInvalid(format!("a plan record does not verify: {error}"))
        })?;
        if record.mission_id != *mission_id || record.principal != *principal {
            continue;
        }
        let state = head
            .operations
            .iter()
            .find(|operation| operation.intent.operation_id.as_str() == record.operation_id)
            .map(|operation| operation.state);
        // A closed plan (terminal, or withdrawn before preparation) is no longer active; its
        // operation, if any, stays visible through the effect journal's own lists.
        if closed.contains(&record.plan_id) {
            continue;
        }
        briefs.push(OrientPlanBrief {
            plan_id: record.plan_id,
            operation_id: record.operation_id,
            state: state.map(|state| state.as_str().to_owned()),
        });
    }
    briefs.sort_by(|left, right| left.plan_id.cmp(&right.plan_id));
    Ok(briefs)
}

/// Reads the published plan `plan_id` with its rendered `fss.agent_control_plan.v1` child, whose
/// digest must be the record's control-plan digest.
pub fn read_control_plan(
    root: &Path,
    plan_id: &str,
) -> Result<(PlanRecord, ContentDigest, Vec<u8>), DeploymentSessionError> {
    let (record, published_root) = read_plan(root, plan_id)?;
    let invalid = || {
        DeploymentSessionError::PlanInvalid(
            "the published control plan does not match the plan record".to_owned(),
        )
    };
    let published = read_published(root, &PlanRecord::slot(plan_id)?)?.ok_or_else(invalid)?;
    let child = published.children.first().copied().ok_or_else(invalid)?;
    if child != record.control_plan_digest || published.root != published_root {
        return Err(invalid());
    }
    let bytes = fss_publication::read_verified(
        root.join(super::PUBLICATIONS_RELPATH),
        child,
        MAX_RECORD_BYTES,
    )
    .map_err(|_| invalid())?;
    Ok((record, published_root, bytes))
}

/// Reads and verifies the published plan `plan_id` (record, control-plan child, and root).
pub fn read_plan(
    root: &Path,
    plan_id: &str,
) -> Result<(PlanRecord, ContentDigest), DeploymentSessionError> {
    let slot = PlanRecord::slot(plan_id)?;
    let (record, published_root) =
        read_plan_at(root, &slot)?.ok_or(DeploymentSessionError::PlanUnknown)?;
    if record.plan_id != plan_id {
        return Err(DeploymentSessionError::PlanInvalid(
            "the published record names another plan".to_owned(),
        ));
    }
    Ok((record, published_root))
}
