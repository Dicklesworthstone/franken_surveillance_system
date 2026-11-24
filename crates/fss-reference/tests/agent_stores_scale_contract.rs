#![forbid(unsafe_code)]
//! Scale regression contract proving that `deployment_session` (`open_session`, `publish_feedback`,
//! `close_plan`, and captured-learning inventory preflight/discovery) handles 64+ captured
//! learning proposals cleanly without hitting the former `MAX_CAPTURED_LEARNING = 16` or
//! `MAX_SCAN_OBJECTS = 512` hard failure walls, while preserving 100% of tamper/rehash checks.

use std::fs;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

use fss_core::{
    AgentView, BudgetVector, ContentDigest, ContextAuthority, FeedbackProposalKind, OperationId,
    PrincipalId, PromotionState, RequestedDisposition, RootAuthoritySpec, TimestampNs,
};
use fss_reference::deployment_session::episode::{CloseRequest, TerminalOutcome, close_plan};
use fss_reference::deployment_session::feedback::{
    FeedbackRequest, FeedbackTarget, publish_feedback,
};
use fss_reference::deployment_session::learning::{MAX_CAPTURED_LEARNING, PublishedLearning};
use fss_reference::deployment_session::plan::{AlertRoute, PlanRecord, publish_plan};
use fss_reference::deployment_session::{
    DeploymentSessionError, OpenSessionRequest, OpenedSession, PUBLICATIONS_RELPATH, open_session,
};
use fss_reference::webhook::WebhookDisclosureProfile;
use fss_reference::{ADP_REPLAY_ROW_ID, ReferenceDeployment, ReplayCx, ReplayIoAuthority};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

static SCALE_DIR_SEQ: AtomicU64 = AtomicU64::new(0);
const SITE: &str = "site:agent-stores-scale";
const PRINCIPAL: &str = "principal:scale-operator";

struct DeploymentFixture {
    root: PathBuf,
    scratch: PathBuf,
    cx: ReplayCx,
}

impl DeploymentFixture {
    fn new(tag: &str) -> TestResult<Self> {
        let seq = SCALE_DIR_SEQ.fetch_add(1, Ordering::Relaxed);
        let root = std::env::temp_dir().join(format!(
            "fss-agent-stores-scale-{tag}-{}-{seq}",
            std::process::id()
        ));
        let scratch = std::env::temp_dir().join(format!(
            "fss-agent-stores-scale-cx-{tag}-{}-{seq}",
            std::process::id()
        ));
        for p in [&root, &scratch] {
            if p.exists() {
                fs::remove_dir_all(p)?;
            }
        }
        let spec = RootAuthoritySpec {
            trace_id: format!("trace:agent-scale-{tag}-{seq}"),
            operation_id: OperationId::parse(format!("operation:agent-scale-{tag}-{seq}"))?,
            principal: format!("operator:agent-scale-{tag}-{seq}"),
            capabilities: vec![ADP_REPLAY_ROW_ID.to_owned()],
            deadline: None,
            priority: 10,
            budgets: BudgetVector::default(),
            privacy_scope: "privacy:internal".to_owned(),
            retention_scope: "retention:ephemeral".to_owned(),
            anchor_universe: ContentDigest::sha256(b"agent-stores-scale"),
            generation: 1,
        };
        let authority = ContextAuthority::new_root(spec)?;
        let cx = ReplayCx::new(ReplayIoAuthority::from_context_authority(
            &authority,
            scratch.clone(),
        )?);
        drop(ReferenceDeployment::open(&root, SITE, &cx)?);
        Ok(Self { root, scratch, cx })
    }
}

impl Drop for DeploymentFixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
        let _ = fs::remove_dir_all(&self.scratch);
    }
}

fn plan_for_session(opened: &OpenedSession, idx: usize) -> PlanRecord {
    let approval = ContentDigest::sha256(format!("scale-plan-approval-{idx}").as_bytes());
    PlanRecord {
        plan_id: PlanRecord::identity(
            &opened.session.session_id,
            &opened.orientation.anchor_token,
            approval,
        ),
        session_id: opened.session.session_id.clone(),
        mission_id: opened.session.mission_id.clone(),
        principal: opened.session.principal_id.clone(),
        anchor_token: opened.orientation.anchor_token.clone(),
        intent: "alert".into(),
        event_id: format!("event:scale-fixture-{idx}"),
        event_revision: ContentDigest::sha256(format!("scale-event-rev-{idx}").as_bytes()),
        route: AlertRoute {
            relay: "127.0.0.1:9".into(),
            path: "/fss/alert".into(),
            plaintext_approval: ContentDigest::sha256(b"scale-route-approval"),
            deadline_ms: 5_000,
            disclosure_profile: WebhookDisclosureProfile::ReferencesV1,
            metadata_approval: None,
        },
        operation_id: format!("operation:scale-fixture-{idx}"),
        obligation_id: format!("obligation:scale-fixture-{idx}"),
        plan_approval: approval,
        control_plan_digest: ContentDigest::sha256(b"scale-native-plan-child"),
        case: None,
        created_at: TimestampNs(0),
    }
}

#[test]
fn sixty_four_plus_captured_learning_proposals_succeed_without_store_invalid() -> TestResult {
    // Former micro-scale ceiling (16) is lifted to match publication_limits().max_roots.
    const {
        assert!(
            MAX_CAPTURED_LEARNING >= 64,
            "MAX_CAPTURED_LEARNING must support > 64 proposals"
        );
    }

    let fixture = DeploymentFixture::new("72-learning")?;
    let principal = PrincipalId::parse(PRINCIPAL)?;

    // Publish 72 real captured learning proposals across 24 sessions (3 captures per session ->
    // 72 learning-* roots, 72 feedback-* roots, 24 mission/plan/episode roots, and 500+ objects,
    // exceeding both the old MAX_CAPTURED_LEARNING=16 and MAX_SCAN_OBJECTS=512 ceilings).
    let mut first_request: Option<FeedbackRequest> = None;
    let mut first_learning: Option<PublishedLearning> = None;
    let mut total_captured = 0_usize;

    for sess_idx in 0..24_usize {
        let opened = open_session(
            &fixture.root,
            &OpenSessionRequest {
                mission: format!("Scale learning capture mission {sess_idx:03}"),
                objective: "Verify bounded paginated learning discovery at scale.".into(),
                principal: principal.clone(),
                view: AgentView::EpistemicMap,
                token_budget: 64_000,
            },
        )?;
        let plan = plan_for_session(&opened, sess_idx);
        publish_plan(&fixture.root, &plan, b"scale-native-plan-child")?;
        let owner = ReferenceDeployment::open(&fixture.root, SITE, &fixture.cx)?;
        let closed = close_plan(
            &fixture.root,
            &CloseRequest {
                session_id: opened.session.session_id.clone(),
                principal: principal.clone(),
                plan_id: plan.plan_id.clone(),
            },
            &|ep| format!("scale episode rendering {}", ep.episode_id),
        )?;
        drop(owner);
        assert_eq!(
            closed.episode.record.terminal_state,
            TerminalOutcome::Withdrawn
        );

        for cap_idx in 0..3_usize {
            let req = FeedbackRequest {
                session_id: opened.session.session_id.clone(),
                principal: principal.clone(),
                target: FeedbackTarget::Plan(plan.plan_id.clone()),
                kind: FeedbackProposalKind::RunbookCandidate,
                statement: format!(
                    "Advisory capture s={sess_idx:03} c={cap_idx:02}; requires held-out review."
                ),
                supporting: vec![closed.episode.root],
                contradicting: Vec::new(),
                disposition: RequestedDisposition::CreateLearningProposal,
            };
            let published = publish_feedback(&fixture.root, &req)?;
            assert!(
                published.learning_refusal.is_none(),
                "unexpected refusal at s={sess_idx} c={cap_idx}: {:?}",
                published.learning_refusal
            );
            let learning = published
                .learning
                .ok_or("expected committed learning capture")?;
            assert!(learning.committed);
            assert_eq!(learning.proposal.promotion_state, PromotionState::Captured);
            if first_request.is_none() {
                first_request = Some(req);
                first_learning = Some(learning);
            }
            total_captured += 1;
        }
    }
    assert_eq!(total_captured, 72);

    // Count verified learning-* roots on disk.
    let roots_dir = fixture.root.join(PUBLICATIONS_RELPATH).join("roots");
    let learning_roots: Vec<_> = fs::read_dir(&roots_dir)?
        .filter_map(Result::ok)
        .filter(|e| {
            e.file_name()
                .to_str()
                .is_some_and(|n| n.starts_with("learning-") && n.ends_with(".root"))
        })
        .collect();
    assert_eq!(learning_roots.len(), 72);

    // Opening a brand-new Brief session on a deployment with 72 captured learning proposals MUST
    // succeed cleanly (no ERR-AGENT-SESSION-STORE-INVALID-001 during preflight or inventory).
    let fresh_brief = open_session(
        &fixture.root,
        &OpenSessionRequest {
            mission: "Post-scale Brief orientation check".into(),
            objective: "Confirm clean open_session above 64 retained learning roots.".into(),
            principal: principal.clone(),
            view: AgentView::Brief,
            token_budget: 32_000,
        },
    )?;
    assert_eq!(fresh_brief.session.view, AgentView::Brief);

    // Exact retry of the very first capture remains idempotent with bit-identical root.
    let req0 = first_request.ok_or("missing first request")?;
    let learn0 = first_learning.ok_or("missing first learning")?;
    let retry = publish_feedback(&fixture.root, &req0)?;
    assert!(retry.learning_refusal.is_none());
    let retry_learning = retry.learning.ok_or("missing retry learning")?;
    assert!(!retry_learning.committed);
    assert_eq!(retry_learning.root, learn0.root);

    // Tamper preservation: corrupting a single learning root among the 72 MUST still cause
    // open_session preflight to fail closed with StoreInvalid.
    let victim = learning_roots[50].path();
    let original = fs::read(&victim)?;
    fs::write(&victim, b"corrupted-learning-root-slot")?;
    let tampered_open = open_session(
        &fixture.root,
        &OpenSessionRequest {
            mission: "Must fail closed on tampered root 50".into(),
            objective: "Verify tamper detection across all 72 roots.".into(),
            principal,
            view: AgentView::Brief,
            token_budget: 32_000,
        },
    );
    fs::write(&victim, original)?;
    assert!(
        matches!(tampered_open, Err(DeploymentSessionError::StoreInvalid(_))),
        "expected StoreInvalid on tampered learning root, got {tampered_open:?}"
    );
    Ok(())
}
