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

use fss_core::{
    AgentSession, CanonicalDecode, CanonicalDecoder, CanonicalEncode, CanonicalEncoder,
    ContentDigest, ContractError, MissionId, PrincipalId, SessionId, TimestampNs,
};
use fss_publication::SlotName;

use crate::agent_orient::{DeploymentSnapshot, OrientPlanBrief};

use super::{
    DeploymentHistory, DeploymentOrientation, DeploymentSessionError, MAX_RECORD_BYTES,
    OrientLimits, SessionJournal, digest_of, evidence_now, hex, orient_bound, publish_record,
    read_published,
};
use crate::agent_session::checkpoint::journal::coordination::investigations::{
    InvestigationError, InvestigationRevision,
};

const PLAN_RECORD_DOMAIN: &str = "fss.reference_agent_plan.v1";
const PLAN_IDENTITY_DOMAIN: &str = "fss.reference_agent_plan_identity.v1";

/// The exact relay route an alert plan sends over.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AlertRoute {
    /// Literal `IP:PORT` socket address (no DNS).
    pub relay: String,
    /// Absolute request path.
    pub path: String,
    /// Owner approval of the plaintext relay.
    pub plaintext_approval: ContentDigest,
    /// Explicit dispatch deadline in milliseconds.
    pub deadline_ms: u64,
}

/// One published control plan.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PlanRecord {
    /// Stable plan identity (`plan:<32 hex>`).
    pub plan_id: String,
    /// Session the plan was compiled in.
    pub session_id: SessionId,
    /// The session's mission.
    pub mission_id: MissionId,
    /// The session's principal (an audit label; it approves nothing by itself).
    pub principal: PrincipalId,
    /// Anchor token of the session situation the plan was compiled against.
    pub anchor_token: String,
    /// Registered intent family (`alert`).
    pub intent: String,
    /// Event the alert is about.
    pub event_id: String,
    /// Exact event revision the plan was compiled against.
    pub event_revision: ContentDigest,
    /// Exact relay route.
    pub route: AlertRoute,
    /// Effect operation identity the plan prepares and commits.
    pub operation_id: String,
    /// Terminal-proof obligation identity.
    pub obligation_id: String,
    /// Exact operator approval digest that admits preparation.
    pub plan_approval: ContentDigest,
    /// Digest of the published `fss.agent_control_plan.v1` rendering.
    pub control_plan_digest: ContentDigest,
    /// Investigation case and exact revision the plan rests on, when one was named.
    pub case: Option<(String, ContentDigest)>,
    /// Compile time on the deployment evidence clock.
    pub created_at: TimestampNs,
}

impl PlanRecord {
    /// The plan identity of `session` at `anchor_token` for an exact plan approval.
    #[must_use]
    pub fn identity(
        session: &SessionId,
        anchor_token: &str,
        plan_approval: ContentDigest,
    ) -> String {
        let digest = digest_of(PLAN_IDENTITY_DOMAIN, |encoder| {
            session.encode_canonical(encoder);
            encoder.text(anchor_token);
            encoder.digest(plan_approval);
        });
        format!("plan:{}", hex(digest).chars().take(32).collect::<String>())
    }

    /// Canonical record bytes.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut encoder = CanonicalEncoder::new();
        encoder.text(PLAN_RECORD_DOMAIN);
        encoder.text(&self.plan_id);
        self.session_id.encode_canonical(&mut encoder);
        self.mission_id.encode_canonical(&mut encoder);
        self.principal.encode_canonical(&mut encoder);
        encoder.text(&self.anchor_token);
        encoder.text(&self.intent);
        encoder.text(&self.event_id);
        encoder.digest(self.event_revision);
        encoder.text(&self.route.relay);
        encoder.text(&self.route.path);
        encoder.digest(self.route.plaintext_approval);
        encoder.u64(self.route.deadline_ms);
        encoder.text(&self.operation_id);
        encoder.text(&self.obligation_id);
        encoder.digest(self.plan_approval);
        encoder.digest(self.control_plan_digest);
        encoder.bool(self.case.is_some());
        if let Some((case_id, revision)) = &self.case {
            encoder.text(case_id);
            encoder.digest(*revision);
        }
        encoder.i128(self.created_at.0);
        encoder.finish()
    }

    /// Decodes exactly canonical record bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, ContractError> {
        if bytes.len() > MAX_RECORD_BYTES {
            return Err(ContractError::CountBoundExceeded);
        }
        let mut decoder = CanonicalDecoder::new(bytes);
        if decoder.text()? != PLAN_RECORD_DOMAIN {
            return Err(ContractError::DigestMismatch);
        }
        let plan_id = decoder.text()?.to_owned();
        let session_id = SessionId::parse(decoder.text()?)?;
        let mission_id = MissionId::parse(decoder.text()?)?;
        let principal = PrincipalId::parse(decoder.text()?)?;
        let anchor_token = decoder.text()?.to_owned();
        let intent = decoder.text()?.to_owned();
        let event_id = decoder.text()?.to_owned();
        let event_revision = ContentDigest::decode_canonical(&mut decoder)?;
        let route = AlertRoute {
            relay: decoder.text()?.to_owned(),
            path: decoder.text()?.to_owned(),
            plaintext_approval: ContentDigest::decode_canonical(&mut decoder)?,
            deadline_ms: decoder.u64()?,
        };
        let operation_id = decoder.text()?.to_owned();
        let obligation_id = decoder.text()?.to_owned();
        let plan_approval = ContentDigest::decode_canonical(&mut decoder)?;
        let control_plan_digest = ContentDigest::decode_canonical(&mut decoder)?;
        let case = if decoder.bool()? {
            Some((
                decoder.text()?.to_owned(),
                ContentDigest::decode_canonical(&mut decoder)?,
            ))
        } else {
            None
        };
        let record = Self {
            plan_id,
            session_id,
            mission_id,
            principal,
            anchor_token,
            intent,
            event_id,
            event_revision,
            route,
            operation_id,
            obligation_id,
            plan_approval,
            control_plan_digest,
            case,
            created_at: TimestampNs(decoder.i128()?),
        };
        decoder.ensure_finished()?;
        if record.to_bytes() != bytes {
            return Err(ContractError::DigestMismatch);
        }
        Ok(record)
    }

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

/// Locates a live session and compiles its situation; the session lock is released on return.
///
/// Fails with `SessionUnknown`/`SessionStale` for an unknown or unresolvable session and with
/// `CaseRefused(Unavailable)` when a named case is not visible to the session.
pub fn planning_context(
    root: &Path,
    principal: &PrincipalId,
    session_id: &SessionId,
    case_id: Option<&str>,
) -> Result<PlanningContext, DeploymentSessionError> {
    let limits = OrientLimits::default();
    let history = DeploymentHistory::read(root, &limits)?;
    let head = history.snapshot_at(history.head())?;
    let now = evidence_now(&head);
    let mut journal = SessionJournal::open(root)?;
    let position = super::session_position(&mut journal, &history, principal, session_id, now)?;
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
    // A plan binds the world situation at the session's anchor, never the agent's own cognition:
    // no case or plan briefs enter the frame it binds, so recording a case or a plan cannot
    // change the identity of the plans compiled at that anchor.
    let orientation = orient_bound(
        None,
        &position.snapshot,
        session.view,
        &session.principal_id,
        &session.mission_id,
        &session.session_id,
        &limits,
        super::SessionBriefs::default(),
    )?;
    journal.commit_pin()?;
    Ok(PlanningContext {
        site_lineage: position.snapshot.site_lineage.clone(),
        session,
        orientation,
        case,
        head_moved: position.head_moved,
        now,
        journal_root: journal.store.committed_root(),
    })
}

/// Publishes `record` root-last with the rendered control plan beside it. Republishing an
/// identical plan is idempotent; a different plan under the same identity is refused.
pub fn publish_plan(
    root: &Path,
    record: &PlanRecord,
    control_plan_json: &[u8],
) -> Result<ContentDigest, DeploymentSessionError> {
    if ContentDigest::sha256(control_plan_json) != record.control_plan_digest {
        return Err(DeploymentSessionError::Internal(
            "the control plan rendering does not match the record".to_owned(),
        ));
    }
    let slot = PlanRecord::slot(&record.plan_id)?;
    if let Some((existing, published_root)) = read_plan_at(root, &slot)? {
        return if existing == *record {
            Ok(published_root)
        } else {
            Err(DeploymentSessionError::PlanInvalid(
                "a different plan is already published under this identity".to_owned(),
            ))
        };
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

#[cfg(test)]
mod tests {
    use super::*;

    fn record() -> Result<PlanRecord, ContractError> {
        Ok(PlanRecord {
            plan_id: "plan:00".to_owned(),
            session_id: SessionId::parse("session:a")?,
            mission_id: MissionId::parse("mission:a")?,
            principal: PrincipalId::parse("principal:local-operator")?,
            anchor_token: "anchor:x".to_owned(),
            intent: "alert".to_owned(),
            event_id: "event:a".to_owned(),
            event_revision: ContentDigest::sha256(b"revision"),
            route: AlertRoute {
                relay: "127.0.0.1:9".to_owned(),
                path: "/fss/alert".to_owned(),
                plaintext_approval: ContentDigest::sha256(b"approval"),
                deadline_ms: 5_000,
            },
            operation_id: "operation:alert:x".to_owned(),
            obligation_id: "obligation:alert:x".to_owned(),
            plan_approval: ContentDigest::sha256(b"plan"),
            control_plan_digest: ContentDigest::sha256(b"dag"),
            case: Some(("case:a".to_owned(), ContentDigest::sha256(b"case"))),
            created_at: TimestampNs(7),
        })
    }

    #[test]
    fn plan_records_round_trip_exactly_and_refuse_any_other_bytes() -> Result<(), ContractError> {
        let record = record()?;
        let bytes = record.to_bytes();
        assert_eq!(PlanRecord::from_bytes(&bytes)?, record);
        let mut without_case = record.clone();
        without_case.case = None;
        assert_eq!(
            PlanRecord::from_bytes(&without_case.to_bytes())?,
            without_case
        );
        let mut trailing = bytes.clone();
        trailing.push(0);
        assert!(PlanRecord::from_bytes(&trailing).is_err());
        assert!(PlanRecord::from_bytes(&bytes[..bytes.len() - 1]).is_err());
        Ok(())
    }

    #[test]
    fn plan_identity_binds_session_anchor_and_approval() -> Result<(), ContractError> {
        let session = SessionId::parse("session:a")?;
        let approval = ContentDigest::sha256(b"plan");
        let base = PlanRecord::identity(&session, "anchor:x", approval);
        assert_eq!(base, PlanRecord::identity(&session, "anchor:x", approval));
        assert_ne!(base, PlanRecord::identity(&session, "anchor:y", approval));
        assert_ne!(
            base,
            PlanRecord::identity(&session, "anchor:x", ContentDigest::sha256(b"other"))
        );
        assert_ne!(
            base,
            PlanRecord::identity(&SessionId::parse("session:b")?, "anchor:x", approval)
        );
        Ok(())
    }
}
