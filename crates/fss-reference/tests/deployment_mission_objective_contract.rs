#![forbid(unsafe_code)]
//! Real durable mission recovery keeps the requested goal in canonical protected context.
//! Metadata commits below are synthetic fixtures; no test establishes a physical outcome.

use std::error::Error;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use fss_core::{
    AgentView, BatchId, BudgetVector, CaptureInterval, ContentDigest, ContextAuthority,
    EvidenceDelta, ObjectId, OperationId, Plane, PrincipalId, RootAuthoritySpec, TimestampNs,
};
use fss_reference::agent_follow::AnchorToken;
use fss_reference::agent_follow::replay::{
    ReplayBinding, ReplayBoundary, ReplayControl, ReplayDenial,
};
use fss_reference::agent_orient::{DeploymentOrientation, OrientError, OrientLimits};
use fss_reference::deployment_session::follow::{
    FollowSessionBinding, FollowSessionBoundary, FollowSessionControl, FollowSessionRequest,
    follow_session,
};
use fss_reference::deployment_session::investigation::{
    CaseAction, InvestigateRequest, investigate,
};
use fss_reference::deployment_session::plan::planning_context;
use fss_reference::deployment_session::{
    DeploymentSessionError, HandoffRequest, MAX_MISSION_BYTES, MAX_OBJECTIVE_BYTES, MissionRecord,
    OpenSessionRequest, OpenedSession, ResumeRequest, open_session, prepare_handoff,
    resume_session,
};
use fss_reference::{ADP_REPLAY_ROW_ID, ReferenceDeployment, ReplayCx, ReplayIoAuthority};

type TestResult<T = ()> = Result<T, Box<dyn Error>>;
static NEXT_PATH: AtomicU64 = AtomicU64::new(0);
const SITE: &str = "site:mission-objective-contract";

struct Fixture {
    root: PathBuf,
    scratch: PathBuf,
    cx: ReplayCx,
    commits: u64,
}

impl Fixture {
    fn new(tag: &str) -> TestResult<Self> {
        let root = std::env::temp_dir().join(format!(
            "fss-mission-objective-{tag}-{}-{}",
            std::process::id(),
            NEXT_PATH.fetch_add(1, Ordering::Relaxed),
        ));
        fs::create_dir(&root)?;
        let scratch = root.with_extension("cx");
        let authority = ContextAuthority::new_root(RootAuthoritySpec {
            trace_id: format!("trace:mission-objective:{tag}"),
            operation_id: OperationId::parse(format!("operation:mission-objective:{tag}"))?,
            principal: "operator:mission-objective-fixture".to_owned(),
            capabilities: vec![ADP_REPLAY_ROW_ID.to_owned()],
            deadline: None,
            priority: 10,
            budgets: BudgetVector::ZERO,
            privacy_scope: "privacy:internal".to_owned(),
            retention_scope: "retention:ephemeral".to_owned(),
            anchor_universe: ContentDigest::sha256(b"explicit mission objective fixture"),
            generation: 1,
        })?;
        let cx = ReplayCx::new(ReplayIoAuthority::from_context_authority(
            &authority, &scratch,
        )?);
        drop(ReferenceDeployment::open(&root, SITE, &cx)?);
        Ok(Self {
            root,
            scratch,
            cx,
            commits: 0,
        })
    }

    fn append(&mut self) -> TestResult {
        self.commits += 1;
        let index = self.commits;
        let mut deployment = ReferenceDeployment::open(&self.root, SITE, &self.cx)?;
        let payload =
            deployment.stage_payload(format!("synthetic mission metadata {index}").as_bytes())?;
        deployment.append_batch(
            BatchId::parse(format!("batch:mission-objective:{index}"))?,
            vec![EvidenceDelta {
                delta_id: format!("delta:mission-objective:{index}"),
                family: "decode_receipt".to_owned(),
                object_id: ObjectId::parse(format!("object:mission-objective:{index}"))?,
                prior_generation: None,
                new_generation: 1,
                validity: CaptureInterval::new(TimestampNs(0), TimestampNs(10_000))?,
                plane: Plane::Cognition,
                payload_digest: payload,
                witness_digest: None,
                operation_id: None,
            }],
            vec![payload],
            &self.cx,
        )?;
        Ok(())
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
        let _ = fs::remove_dir_all(&self.scratch);
    }
}

fn request() -> TestResult<OpenSessionRequest> {
    Ok(OpenSessionRequest {
        mission: "Watch the east entrance.\nKeep uncertainty explicit.".to_owned(),
        objective: "Establish whether the east door opened during the retained interval."
            .to_owned(),
        principal: PrincipalId::parse("principal:mission-objective")?,
        view: AgentView::Brief,
        token_budget: 100_000,
    })
}

fn preserves_goal(orientation: &DeploymentOrientation, mission: &MissionRecord) -> TestResult {
    assert_eq!(orientation.objective.desired_outcome, mission.objective);
    assert_eq!(
        orientation.objective.source_request_digest,
        mission.digest().to_text()
    );
    assert_eq!(
        orientation.objective.objective_id,
        orientation.capsule().frame.objective_id
    );
    assert!(orientation.objective.success_predicates.is_empty());
    assert!(orientation.objective.failure_predicates.is_empty());
    assert!(orientation.objective.stop_conditions.is_empty());
    assert!(orientation.objective.terminal_proof.is_empty());
    let summary = orientation
        .publication
        .context_pack
        .items
        .iter()
        .find(|item| item.item_id == "context:frame:summary")
        .ok_or("protected mission summary")?;
    assert!(summary.content.contains(&mission.mission));
    assert!(summary.content.contains(&mission.objective));
    assert!(orientation.publication.context_pack.items.iter().any(|item|
        item.kind == "unknown" && item.content.contains("completion is unassessed")));
    assert!(
        orientation
            .publication
            .compression_receipt
            .critical_preservation
            .is_lossless()
    );
    assert!(orientation.capsule().mission_state.is_none());
    Ok(())
}

#[test]
fn open_retry_and_native_cognition_keep_the_same_literal_mission() -> TestResult {
    let fixture = Fixture::new("open-cognition")?;
    let request = request()?;
    let opened = open_session(&fixture.root, &request)?;
    preserves_goal(&opened.orientation, &opened.mission)?;
    assert_eq!(
        opened.revision.capsule().objective_digest,
        opened.mission.digest().to_text()
    );
    let journal = fs::read(fixture.root.join("agent/sessions/journal.fssj"))?;
    let retry = open_session(&fixture.root, &request)?;
    assert_eq!(opened.mission.to_bytes(), retry.mission.to_bytes());
    assert_eq!(opened.session.session_id, retry.session.session_id);
    assert_eq!(opened.revision, retry.revision);
    assert_eq!(
        opened.orientation.capsule().decision_fingerprint()?,
        retry.orientation.capsule().decision_fingerprint()?
    );
    assert_eq!(
        journal,
        fs::read(fixture.root.join("agent/sessions/journal.fssj"))?
    );

    let context = planning_context(
        &fixture.root,
        &request.principal,
        &opened.session.session_id,
        None,
    )?;
    preserves_goal(&context.orientation, &opened.mission)?;
    drop(context);
    let listed = investigate(
        &fixture.root,
        &InvestigateRequest {
            session_id: opened.session.session_id.clone(),
            principal: request.principal,
            action: CaseAction::List,
        },
    )?;
    preserves_goal(&listed.orientation, &opened.mission)?;
    Ok(())
}

#[test]
fn cold_handoff_resume_and_anchor_rebase_never_replace_the_goal() -> TestResult {
    let mut fixture = Fixture::new("resume")?;
    let request = request()?;
    let opened = open_session(&fixture.root, &request)?;
    let prepared = prepare_handoff(
        &fixture.root,
        &HandoffRequest {
            session_id: opened.session.session_id.clone(),
            principal: request.principal.clone(),
            note: Some("Continue from this retained mission record".to_owned()),
        },
    )?;
    preserves_goal(&prepared.orientation, &opened.mission)?;
    let published = prepared.publish(&[])?;
    let resume = ResumeRequest {
        handoff_id: published.record.capsule.handoff_id,
        principal: request.principal,
    };
    let unchanged = resume_session(&fixture.root, &resume)?;
    assert!(!unchanged.committed);
    assert!(!unchanged.handoff_situation_changed);
    preserves_goal(&unchanged.basis, &opened.mission)?;
    preserves_goal(&unchanged.result, &opened.mission)?;
    fixture.append()?;
    let advanced = resume_session(&fixture.root, &resume)?;
    assert!(advanced.anchor_moved);
    assert!(advanced.committed);
    assert_eq!(advanced.mission.to_bytes(), opened.mission.to_bytes());
    assert_eq!(
        advanced.revision.capsule().objective_digest,
        opened.mission.digest().to_text()
    );
    preserves_goal(&advanced.basis, &opened.mission)?;
    preserves_goal(&advanced.result, &opened.mission)?;
    let retry = resume_session(&fixture.root, &resume)?;
    assert!(!retry.committed);
    assert_eq!(advanced.revision, retry.revision);
    assert_eq!(
        advanced.result.capsule().decision_fingerprint()?,
        retry.result.capsule().decision_fingerprint()?
    );
    preserves_goal(&retry.result, &opened.mission)?;
    Ok(())
}

struct FollowControl<'a> {
    root: &'a Path,
    opened: &'a OpenedSession,
    request: &'a FollowSessionRequest,
}

impl ReplayControl for FollowControl<'_> {
    fn admit(&mut self, binding: &ReplayBinding, _: ReplayBoundary) -> Result<(), ReplayDenial> {
        if !binding.objects_root().starts_with(self.root)
            || binding.request().principal != self.opened.session.principal_id
            || binding.request().view != self.request.view
            || binding.request().max_entries != self.request.max_entries
            || binding.session().is_none_or(|session| {
                session.session_id != self.opened.session.session_id
                    || session.mission_id != self.opened.session.mission_id
                    || session
                        .mission
                        .as_ref()
                        .is_none_or(|mission| mission.record_digest != self.opened.mission.digest())
            })
        {
            return Err(ReplayDenial::Unauthorized);
        }
        Ok(())
    }
}

impl FollowSessionControl for FollowControl<'_> {
    fn admit_session(
        &mut self,
        binding: &FollowSessionBinding<'_>,
        _: FollowSessionBoundary,
    ) -> Result<(), ReplayDenial> {
        if binding.root() != self.root
            || binding.principal() != &self.opened.session.principal_id
            || binding.request() != self.request
        {
            return Err(ReplayDenial::Unauthorized);
        }
        Ok(())
    }
}

#[test]
fn durable_follow_and_pending_redelivery_use_the_retained_goal_on_both_axes() -> TestResult {
    let mut fixture = Fixture::new("follow")?;
    let opened = open_session(&fixture.root, &request()?)?;
    fixture.append()?;
    let request = FollowSessionRequest {
        session_id: opened.session.session_id.clone(),
        subscription_id: "mission-watch".to_owned(),
        since: AnchorToken::parse(&opened.orientation.anchor_token).ok_or("opening anchor")?,
        view: AgentView::Brief,
        max_entries: 64,
        acknowledge: None,
    };
    let mut control = FollowControl {
        root: &fixture.root,
        opened: &opened,
        request: &request,
    };
    let first = follow_session(
        &fixture.root,
        &opened.session.principal_id,
        &request,
        &OrientLimits::default(),
        &mut control,
    )?;
    preserves_goal(&first.follow.basis, &opened.mission)?;
    preserves_goal(&first.follow.result, &opened.mission)?;
    let retry = follow_session(
        &fixture.root,
        &opened.session.principal_id,
        &request,
        &OrientLimits::default(),
        &mut control,
    )?;
    assert!(retry.replayed);
    assert_eq!(first.delivery_receipt, retry.delivery_receipt);
    assert_eq!(first.follow, retry.follow);
    Ok(())
}

#[test]
fn insufficient_view_budget_refuses_before_publishing_or_dropping_the_mission() -> TestResult {
    let fixture = Fixture::new("bounded")?;
    let mut request = request()?;
    request.mission = "m".repeat(MAX_MISSION_BYTES);
    request.objective = "o".repeat(MAX_OBJECTIVE_BYTES);
    request.view = AgentView::Pulse;
    assert!(matches!(
        open_session(&fixture.root, &request),
        Err(DeploymentSessionError::Orient(
            OrientError::ContextBudgetExceeded { .. }
        ))
    ));
    assert!(!fixture.root.join("agent/sessions/journal.fssj").exists());
    Ok(())
}
