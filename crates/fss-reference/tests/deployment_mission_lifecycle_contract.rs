#![forbid(unsafe_code)]
//! Native PlanOutcomeV1 lifecycle over real retained plans, journals and execution episodes.
//! The model observations and reconciliation attestations are explicit synthetic fixtures.
//! No network provider is contacted and no test establishes a physical surveillance outcome.
//! Control-plan/episode child renderings are labelled custody fixtures, not JSON qualification.

use std::error::Error;
use std::fs;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

use fss_core::{
    AgentView, BatchId, BudgetVector, CanonicalEncode, CanonicalEncoder, CapsuleId,
    CaptureInterval, ContentDigest, ContextAuthority, EffectJournal, EffectState, EventId,
    EvidenceDelta, IdempotencyKey, MissionLifecycleState, ObjectId, ObligationId, OperationId,
    Plane, PrincipalId, ProbabilityInterval, RootAuthoritySpec, SensorId, TimestampNs,
};
use fss_ledger::{DurableReferenceLedger, IncompleteTailPolicy};
use fss_object::{InMemoryObjectStore, ObjectLimits};
use fss_reference::alert_reconcile::{
    AlertAttestation, AlertReconciliationOutcome, CAP_ALERT_RECONCILE,
    preview_alert_reconciliation, reconcile_alert_operation,
};
use fss_reference::deployment_session::episode::{CloseRequest, close_plan};
use fss_reference::deployment_session::mission::{
    MissionAction, MissionAnswer, MissionError, MissionRequest, execute,
};
use fss_reference::deployment_session::plan::{
    AlertRoute, PlanRecord, planning_context, publish_plan,
};
use fss_reference::deployment_session::{
    HandoffRequest, OpenSessionRequest, OpenedSession, ResumeRequest, open_session,
    prepare_handoff, resume_session,
};
use fss_reference::webhook::WebhookEndpoint;
use fss_reference::{
    ADP_REPLAY_ROW_ID, DeliveryPlan, MockModelScript, MockModelSpec, MockSemanticLabel,
    PrepareAlertParams, ReferenceAlertPlan, ReferenceDeployment, ReferenceEventReceipt,
    ReferenceModelObservation, ReferencePolicyAction, ReferencePolicyDecision, ReplayCx,
    VirtualCameraSpec, execute_mock_model, prepare_reference_alert, run_reference_capture,
};

type TestResult<T = ()> = Result<T, Box<dyn Error>>;
static NEXT: AtomicU64 = AtomicU64::new(0);
const SITE: &str = "site:mission-lifecycle-native-contract";
const PREPARED_AT: i128 = 1_000_000;

fn hex(digest: ContentDigest) -> String {
    digest
        .bytes()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

struct Fixture {
    directory: PathBuf,
    root: PathBuf,
    authority: ContextAuthority,
    cx: ReplayCx,
    decision: ReferencePolicyDecision,
    event: ReferenceEventReceipt,
    opened: OpenedSession,
}

impl Fixture {
    /// The returned deployment keeps the actual sole-writer lock held throughout native calls.
    fn new(label: &str) -> TestResult<(Self, ReferenceDeployment)> {
        let directory = std::env::temp_dir().join(format!(
            "fss-native-mission-{label}-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed),
        ));
        fs::create_dir(&directory)?;
        let root = directory.join("deployment");
        let authority = ContextAuthority::new_root(RootAuthoritySpec {
            trace_id: format!("trace:mission-lifecycle:{label}"),
            operation_id: OperationId::parse(format!("operation:mission-lifecycle:{label}"))?,
            principal: "operator:mission-lifecycle-fixture".to_owned(),
            capabilities: vec![ADP_REPLAY_ROW_ID.to_owned(), CAP_ALERT_RECONCILE.to_owned()],
            deadline: None,
            priority: 10,
            budgets: BudgetVector::builder()
                .bytes(64 * 1024 * 1024)
                .storage_operations(16_384)
                .build()?,
            privacy_scope: "privacy:local-authorized-files".to_owned(),
            retention_scope: "retention:existing-deployment-policy".to_owned(),
            anchor_universe: ContentDigest::sha256(SITE.as_bytes()),
            generation: 1,
        })?;
        let cx = ReplayCx::from_context_authority(&authority, &root)?;
        let mut dep = ReferenceDeployment::open(&root, SITE, &cx)?;
        let mut objects = InMemoryObjectStore::new(ObjectLimits::new(512, 8 * 1024 * 1024));
        let mut captures = DurableReferenceLedger::open(
            directory.join("synthetic-captures.journal"),
            "site:mission-lifecycle-synthetic-captures",
            IncompleteTailPolicy::Reject,
        )?;
        let mut observations = Vec::new();
        for (lane, seed) in [("a", 111), ("b", 222)] {
            let spec = VirtualCameraSpec {
                capture_id: CapsuleId::parse(format!("capture:mission-lifecycle:{lane}"))?,
                sensor_id: SensorId::parse(format!("sensor:mission-lifecycle:{lane}"))?,
                seed,
                packet_count: 2,
                packet_bytes: 32,
                start_ns: 10_000,
                period_ns: 1_000_000,
                uncertainty_ns: 100,
            };
            let capture = run_reference_capture(
                &spec,
                &DeliveryPlan::identity(spec.packet_count)?,
                &mut objects,
                &mut captures,
            )?;
            let model = MockModelSpec::new(
                format!("mock:mission-lifecycle:{lane}:v1"),
                MockModelScript::Fixed {
                    label: MockSemanticLabel::PersonLike,
                    probability: ProbabilityInterval::new(0.99, 1.0)?,
                },
            )?;
            let result = execute_mock_model(&model, &capture, &mut objects)?;
            observations.push(ReferenceModelObservation::new(
                result,
                format!("power:mission-lifecycle:{lane}"),
                CaptureInterval::new(TimestampNs(10_000), TimestampNs(20_000))?,
            )?);
        }
        let decision = dep.evaluate_policy(
            EventId::parse("event:mission-lifecycle-synthetic")?,
            observations,
            &cx,
        )?;
        assert_eq!(decision.action, ReferencePolicyAction::PrepareAlert);
        for digest in &decision.event.model_receipts {
            assert_eq!(dep.stage_payload(objects.read_verified(*digest)?)?, *digest);
        }
        let event = dep.publish_event(&decision, &cx)?;
        let opened = open_session(&root, &Self::request("principal:mission-lifecycle")?)?;
        Ok((
            Self {
                directory,
                root,
                authority,
                cx,
                decision,
                event,
                opened,
            },
            dep,
        ))
    }

    fn request(principal: &str) -> TestResult<OpenSessionRequest> {
        Ok(OpenSessionRequest {
            mission: "Retain uncertainty while following this synthetic delivery workflow.".to_owned(),
            objective: "Establish the selected operation's retained delivery outcome; physical activity stays unassessed.".to_owned(),
            principal: PrincipalId::parse(principal)?,
            view: AgentView::Brief,
            token_budget: 100_000,
        })
    }

    fn effect_time(&self) -> i128 {
        PREPARED_AT.max(self.opened.orientation.capsule().created_at.0 + 1000)
    }

    /// Same frozen operation and approval encodings as AOP-007's real alert preview.
    fn plan(&self, dep: &mut ReferenceDeployment, lane: &str) -> TestResult<PlanRecord> {
        let endpoint = WebhookEndpoint::new(
            "127.0.0.1:18080".parse()?,
            &format!("/synthetic-{lane}"),
            ContentDigest::sha256(b"explicit synthetic route approval; never dispatched"),
        )?;
        let mut identity = CanonicalEncoder::new();
        identity.text("fss.cli_alert_operation.v1");
        identity.digest(self.event.event_revision_digest);
        identity.digest(endpoint.digest());
        let key = hex(ContentDigest::sha256(&identity.finish()));
        let (_, ledger) = dep.effects_and_ledger();
        let preview = prepare_reference_alert(
            PrepareAlertParams {
                decision: &self.decision,
                event_receipt: &self.event,
                authority: ledger,
                operation_id: OperationId::parse(format!("operation:alert:{key}"))?,
                idempotency_key: IdempotencyKey::parse(format!("idempotency:alert:{key}"))?,
                obligation_id: ObligationId::parse(format!("obligation:alert:{key}"))?,
                channel: endpoint.channel().to_owned(),
                now: TimestampNs(self.effect_time()),
            },
            &mut EffectJournal::new(),
        )?;
        let mut approval = CanonicalEncoder::new();
        approval.text("fss.cli_alert_plan_approval.v1");
        preview.intent.encode_canonical(&mut approval);
        preview.obligation_id.encode_canonical(&mut approval);
        approval.text(&preview.channel);
        approval.digest(preview.event_root);
        approval.digest(preview.event_revision_digest);
        approval.digest(endpoint.digest());
        approval.text(self.opened.session.principal_id.as_str());
        let plan_approval = ContentDigest::sha256(&approval.finish());
        let control_plan = format!("synthetic custody rendering for route {lane}");
        Ok(PlanRecord {
            plan_id: PlanRecord::identity(
                &self.opened.session.session_id,
                &self.opened.orientation.anchor_token,
                plan_approval,
            ),
            session_id: self.opened.session.session_id.clone(),
            mission_id: self.opened.session.mission_id.clone(),
            principal: self.opened.session.principal_id.clone(),
            anchor_token: self.opened.orientation.anchor_token.clone(),
            intent: "alert".to_owned(),
            event_id: self.decision.event.event_id.as_str().to_owned(),
            event_revision: self.event.event_revision_digest,
            route: AlertRoute {
                relay: endpoint.peer().to_string(),
                path: endpoint.target().to_owned(),
                plaintext_approval: endpoint.plaintext_approval(),
                deadline_ms: 5000,
            },
            operation_id: preview.intent.operation_id.as_str().to_owned(),
            obligation_id: preview.obligation_id.as_str().to_owned(),
            plan_approval,
            control_plan_digest: ContentDigest::sha256(control_plan.as_bytes()),
            case: None,
            created_at: self.opened.orientation.capsule().created_at,
        })
    }

    fn publish(&self, plan: &PlanRecord) -> TestResult {
        let lane = plan
            .route
            .path
            .strip_prefix("/synthetic-")
            .ok_or("fixture route")?;
        publish_plan(
            &self.root,
            plan,
            format!("synthetic custody rendering for route {lane}").as_bytes(),
        )?;
        Ok(())
    }

    fn prepare(
        &self,
        dep: &mut ReferenceDeployment,
        plan: &PlanRecord,
    ) -> TestResult<ReferenceAlertPlan> {
        let endpoint = WebhookEndpoint::new(
            plan.route.relay.parse()?,
            &plan.route.path,
            plan.route.plaintext_approval,
        )?;
        let key = plan
            .operation_id
            .strip_prefix("operation:alert:")
            .ok_or("fixture operation")?;
        let (effects, ledger) = dep.effects_and_ledger();
        Ok(effects.prepare_alert(PrepareAlertParams {
            decision: &self.decision,
            event_receipt: &self.event,
            authority: ledger,
            operation_id: OperationId::parse(&plan.operation_id)?,
            idempotency_key: IdempotencyKey::parse(format!("idempotency:alert:{key}"))?,
            obligation_id: ObligationId::parse(&plan.obligation_id)?,
            channel: endpoint.channel().to_owned(),
            now: TimestampNs(self.effect_time()),
        })?)
    }

    fn act(&self, action: MissionAction) -> TestResult<MissionAnswer> {
        Ok(execute(
            &self.root,
            &MissionRequest {
                session_id: self.opened.session.session_id.clone(),
                principal: self.opened.session.principal_id.clone(),
                action,
            },
        )?)
    }

    fn adopt(&self, plan: &PlanRecord) -> TestResult<MissionAnswer> {
        self.act(MissionAction::Adopt {
            plan_id: plan.plan_id.clone(),
            decision_deadline: TimestampNs(self.opened.orientation.capsule().created_at.0 + 1),
        })
    }

    fn assess(&self, plan: &PlanRecord, expected: ContentDigest) -> TestResult<MissionAnswer> {
        self.act(MissionAction::Assess {
            plan_id: plan.plan_id.clone(),
            expected,
        })
    }

    fn indeterminate(&self, dep: &mut ReferenceDeployment, plan: &PlanRecord) -> TestResult {
        let prepared = self.prepare(dep, plan)?;
        let effects = dep.effects_mut();
        effects.transition(
            &prepared.intent.operation_id,
            EffectState::Committed,
            TimestampNs(self.effect_time() + 1),
            None,
            None,
        )?;
        effects.transition(
            &prepared.intent.operation_id,
            EffectState::AdapterAccepted,
            TimestampNs(self.effect_time() + 2),
            None,
            None,
        )?;
        effects.mark_indeterminate(
            &prepared.intent.operation_id,
            TimestampNs(self.effect_time() + 3),
            "synthetic_ack_unknown",
        )?;
        Ok(())
    }

    fn reconcile(
        &self,
        dep: &mut ReferenceDeployment,
        plan: &PlanRecord,
        delivered: bool,
    ) -> TestResult {
        let operation = OperationId::parse(&plan.operation_id)?;
        let attestation = AlertAttestation {
            outcome: if delivered {
                AlertReconciliationOutcome::Delivered
            } else {
                AlertReconciliationOutcome::NotDelivered
            },
            evidence: ContentDigest::sha256(b"explicit synthetic recipient observation"),
            statement: "Synthetic test observation, not an actual provider or physical outcome."
                .to_owned(),
        };
        let preview =
            preview_alert_reconciliation(dep, &operation, &attestation, &self.authority, &self.cx)?;
        let result = reconcile_alert_operation(
            dep,
            &operation,
            &attestation,
            preview.approval_digest(),
            TimestampNs(self.effect_time() + 4),
            &self.authority,
            &self.cx,
        )?;
        assert_eq!(
            result.operation.state,
            if delivered {
                EffectState::Verified
            } else {
                EffectState::Failed
            }
        );
        assert_eq!(
            result.operation.result_digest,
            result.obligation.proof_digest
        );
        Ok(())
    }

    fn advance_evidence_clock(&self, dep: &mut ReferenceDeployment) -> TestResult {
        let payload = dep.stage_payload(b"explicit synthetic clock-advance metadata")?;
        dep.append_batch(
            BatchId::parse("batch:mission-lifecycle:clock-advance")?,
            vec![EvidenceDelta {
                delta_id: "delta:mission-lifecycle:clock-advance".to_owned(),
                family: "decode_receipt".to_owned(),
                object_id: ObjectId::parse("object:mission-lifecycle:clock-advance")?,
                prior_generation: None,
                new_generation: 1,
                validity: CaptureInterval::new(
                    TimestampNs(0),
                    TimestampNs(self.effect_time() + 10),
                )?,
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

    fn close(&self, plan: &PlanRecord) -> TestResult {
        let closed = close_plan(
            &self.root,
            &CloseRequest {
                session_id: self.opened.session.session_id.clone(),
                principal: self.opened.session.principal_id.clone(),
                plan_id: plan.plan_id.clone(),
            },
            &|episode| {
                format!(
                    "synthetic episode custody rendering: {}",
                    episode.episode_id
                )
            },
        )?;
        assert_eq!(closed.episode.record.plan_id, plan.plan_id);
        Ok(())
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.directory);
    }
}

fn authority_bytes(dep: &mut ReferenceDeployment) -> TestResult<(Vec<u8>, Vec<u8>)> {
    let (effects, ledger) = dep.effects_and_ledger();
    Ok((fs::read(effects.path())?, fs::read(ledger.path())?))
}

/// The executable profile is protected context, while the requested prose remains literal
/// context and explicitly unassessed. A terminal execution receipt must not erase that boundary.
fn protected_objective(
    fixture: &Fixture,
    answer: &MissionAnswer,
    state: Option<MissionLifecycleState>,
) -> TestResult {
    let criterion = answer.revision.criterion();
    let oriented = &answer.orientation;
    let objective = &oriented.objective;
    assert_eq!(
        criterion.mission_record_digest,
        fixture.opened.mission.digest()
    );
    assert_eq!(
        objective.source_request_digest,
        criterion.digest().to_text()
    );
    assert_eq!(
        objective.objective_id,
        oriented.capsule().frame.objective_id
    );
    assert!(objective.desired_outcome.contains(&criterion.plan_id));
    assert!(!objective.success_predicates.is_empty());
    assert!(!objective.failure_predicates.is_empty());
    assert!(!objective.stop_conditions.is_empty());
    let success = objective.success_predicates.join("\n");
    assert!(success.contains(criterion.operation_id.as_str()));
    assert!(success.contains(criterion.obligation_id.as_str()));
    assert!(success.contains("proof"));
    assert!(success.contains("episode"));
    assert!(success.contains("closure"));
    assert!(objective.stop_conditions.iter().any(|condition| {
        condition.contains(&criterion.decision_deadline.0.to_string())
            && condition.contains("neither cancels")
    }));
    assert!(
        objective
            .terminal_proof
            .contains(&format!("fss://proof/{}", criterion.digest()))
    );
    assert!(
        objective
            .terminal_proof
            .contains(&format!("fss://proof/{}", criterion.plan_root))
    );
    assert_eq!(oriented.capsule().mission_state, state);
    let summary = oriented
        .publication
        .context_pack
        .items
        .iter()
        .find(|item| item.item_id == "context:frame:summary")
        .ok_or("protected mission profile summary")?;
    for required in [
        fixture.opened.mission.mission.as_str(),
        fixture.opened.mission.objective.as_str(),
        fss_reference::agent_session::mission::MissionPlanCriterion::PROFILE,
        criterion.plan_id.as_str(),
        criterion.operation_id.as_str(),
        criterion.obligation_id.as_str(),
    ] {
        assert!(
            summary.content.contains(required),
            "protected summary lost {required}"
        );
    }
    assert!(summary.content.contains(&criterion.digest().to_text()));
    assert!(
        summary
            .content
            .contains(&answer.revision.digest().to_text())
    );
    assert!(
        summary
            .content
            .contains("Physical truth and prose completion remain unassessed.")
    );
    assert!(oriented.publication.context_pack.items.iter().any(|item|
        item.kind == "unknown" && item.content.contains("completion is unassessed")));
    assert!(
        oriented
            .publication
            .compression_receipt
            .critical_preservation
            .is_lossless()
    );
    let original = oriented
        .capsule()
        .frame
        .knowledge_cells
        .iter()
        .find(|cell| cell.claim_id() == "claim:session:requested-mission")
        .ok_or("original mission provenance")?;
    assert_eq!(
        original.evidence_digests(),
        vec![fixture.opened.mission.digest()]
    );
    Ok(())
}

fn same_objective_criteria(before: &MissionAnswer, after: &MissionAnswer) {
    let before = &before.orientation.objective;
    let after = &after.orientation.objective;
    assert_eq!(before.objective_id, after.objective_id);
    assert_eq!(before.source_request_digest, after.source_request_digest);
    assert_eq!(before.desired_outcome, after.desired_outcome);
    assert_eq!(before.success_predicates, after.success_predicates);
    assert_eq!(before.failure_predicates, after.failure_predicates);
    assert_eq!(before.stop_conditions, after.stop_conditions);
    assert_eq!(before.terminal_proof, after.terminal_proof);
}

#[test]
fn unprepared_assessment_and_cold_exact_predecessor_retry_preserve_every_effect_byte() -> TestResult
{
    let (f, mut dep) = Fixture::new("cold-retry")?;
    let plan = f.plan(&mut dep, "selected")?;
    f.publish(&plan)?;
    let before = authority_bytes(&mut dep)?;
    assert_eq!(
        f.opened.orientation.objective.desired_outcome,
        f.opened.mission.objective
    );
    assert_eq!(
        f.opened.orientation.objective.source_request_digest,
        f.opened.mission.digest().to_text()
    );
    assert!(f.opened.orientation.objective.success_predicates.is_empty());
    assert!(f.opened.orientation.objective.failure_predicates.is_empty());
    assert!(f.opened.orientation.objective.stop_conditions.is_empty());
    assert!(f.opened.orientation.objective.terminal_proof.is_empty());
    let frozen = planning_context(
        &f.root,
        &f.opened.session.principal_id,
        &f.opened.session.session_id,
        None,
    )?;
    let enrolled = f.adopt(&plan)?;
    protected_objective(&f, &enrolled, Some(MissionLifecycleState::AwaitingEvidence))?;
    let after_enrollment = planning_context(
        &f.root,
        &f.opened.session.principal_id,
        &f.opened.session.session_id,
        None,
    )?;
    // A plan's original compilation witness stays unchanged when that same plan is enrolled.
    // Current executable mission criteria belong to mission/session views, not this old DAG.
    assert_eq!(
        frozen.orientation.objective,
        after_enrollment.orientation.objective
    );
    assert_eq!(
        frozen.orientation.capsule().decision_fingerprint()?,
        after_enrollment
            .orientation
            .capsule()
            .decision_fingerprint()?
    );
    assert_eq!(
        after_enrollment.orientation.objective.source_request_digest,
        f.opened.mission.digest().to_text()
    );
    assert!(
        after_enrollment
            .orientation
            .objective
            .success_predicates
            .is_empty()
    );
    assert!(enrolled.committed);
    assert_eq!(
        enrolled.revision.state(),
        MissionLifecycleState::AwaitingEvidence
    );
    assert!(enrolled.revision.assessment().is_none());
    assert_eq!(
        enrolled.revision.criterion().mission_record_digest,
        f.opened.mission.digest()
    );
    let assessed = f.assess(&plan, enrolled.revision.digest())?;
    protected_objective(&f, &assessed, Some(MissionLifecycleState::AwaitingEvidence))?;
    same_objective_criteria(&enrolled, &assessed);
    assert!(assessed.committed);
    assert_eq!(
        assessed.revision.state(),
        MissionLifecycleState::AwaitingEvidence
    );
    assert!(!assessed.revision.deadline_reached());
    assert!(
        assessed
            .revision
            .assessment()
            .ok_or("assessment")?
            .operation
            .is_none()
    );
    assert_eq!(before, authority_bytes(&mut dep)?);
    drop(dep);
    let mut reopened = ReferenceDeployment::open(&f.root, SITE, &f.cx)?;
    let retry = f.assess(&plan, enrolled.revision.digest())?;
    assert!(!retry.committed);
    assert_eq!(retry.revision, assessed.revision);
    assert_eq!(retry.request_digest, assessed.request_digest);
    assert_eq!(retry.journal_root, assessed.journal_root);
    assert_eq!(before, authority_bytes(&mut reopened)?);
    let adopted_again = f.adopt(&plan)?;
    assert!(!adopted_again.committed);
    assert_eq!(adopted_again.revision, assessed.revision);
    // A later evidence observation advances the live session's clock, while this session's
    // retained projection still uses its earlier anchor and unchanged mission assessment.
    // Inventory admission must use the live clock, not replay an old timestamp into it.
    f.advance_evidence_clock(&mut reopened)?;
    prepare_handoff(
        &f.root,
        &HandoffRequest {
            session_id: f.opened.session.session_id.clone(),
            principal: f.opened.session.principal_id.clone(),
            note: None,
        },
    )?
    .publish(&[])?;
    Ok(())
}

#[test]
fn uncertain_dispatched_effect_stays_reconciling_after_explicit_decision_deadline() -> TestResult {
    let (f, mut dep) = Fixture::new("indeterminate")?;
    let plan = f.plan(&mut dep, "selected")?;
    f.publish(&plan)?;
    let enrolled = f.adopt(&plan)?;
    f.indeterminate(&mut dep, &plan)?;
    // Effect timestamps alone do not advance the evidence clock. Retain an explicit later
    // evidence interval before asserting that the deadline has actually passed.
    f.advance_evidence_clock(&mut dep)?;
    let before = authority_bytes(&mut dep)?;
    let assessed = f.assess(&plan, enrolled.revision.digest())?;
    protected_objective(&f, &assessed, Some(MissionLifecycleState::Reconciling))?;
    assert_eq!(assessed.orientation.view, AgentView::Brief);
    assert!(assessed.orientation.target_tokens <= u64::from(AgentView::Brief.maximum_tokens()));
    assert!(
        assessed.orientation.publication.context_pack.token_count
            <= assessed.orientation.target_tokens
    );
    assert_eq!(
        assessed.revision.state(),
        MissionLifecycleState::Reconciling
    );
    assert!(assessed.revision.deadline_reached());
    assert!(!assessed.revision.state().is_terminal());
    let facts = assessed.revision.assessment().ok_or("assessment")?;
    assert!(facts.operation.as_ref().ok_or("operation")?.dispatched);
    assert!(facts.episode.is_none());
    assert_eq!(before, authority_bytes(&mut dep)?);
    assert!(!f.assess(&plan, enrolled.revision.digest())?.committed);
    Ok(())
}

#[test]
fn real_receipt_and_obligation_require_episode_and_clear_owned_work_before_terminal() -> TestResult
{
    for (delivered, expected_state) in [
        (true, MissionLifecycleState::Resolved),
        (false, MissionLifecycleState::Failed),
    ] {
        let (f, mut dep) = Fixture::new(if delivered { "delivered" } else { "failed" })?;
        let selected = f.plan(&mut dep, "selected")?;
        let other = f.plan(&mut dep, "other")?;
        f.publish(&selected)?;
        f.publish(&other)?;
        let enrolled = f.adopt(&selected)?;
        f.indeterminate(&mut dep, &selected)?;
        f.reconcile(&mut dep, &selected, delivered)?;
        let without_episode = f.assess(&selected, enrolled.revision.digest())?;
        assert_eq!(
            without_episode.revision.state(),
            MissionLifecycleState::AwaitingEvidence
        );
        assert!(
            without_episode
                .revision
                .assessment()
                .ok_or("assessment")?
                .episode
                .is_none()
        );
        f.close(&selected)?;
        let blocked = f.assess(&selected, without_episode.revision.digest())?;
        assert_eq!(
            blocked.revision.state(),
            MissionLifecycleState::AwaitingEvidence
        );
        assert_eq!(
            blocked
                .revision
                .assessment()
                .ok_or("assessment")?
                .closure
                .unsettled_plans,
            1
        );
        f.close(&other)?;
        let before = authority_bytes(&mut dep)?;
        let terminal = f.assess(&selected, blocked.revision.digest())?;
        protected_objective(&f, &terminal, Some(expected_state))?;
        same_objective_criteria(&enrolled, &terminal);
        assert_eq!(terminal.revision.state(), expected_state);
        let facts = terminal.revision.assessment().ok_or("assessment")?;
        assert_eq!(facts.closure.unsettled_plans, 0);
        assert!(facts.episode.is_some());
        assert_eq!(
            facts.operation.as_ref().ok_or("operation")?.result_digest,
            facts.obligation.as_ref().ok_or("obligation")?.proof_digest
        );
        assert_eq!(
            terminal.orientation.capsule().mission_state,
            Some(expected_state)
        );
        assert_eq!(before, authority_bytes(&mut dep)?);
        drop(dep);
        let mut reopened = ReferenceDeployment::open(&f.root, SITE, &f.cx)?;
        let retry = f.assess(&selected, blocked.revision.digest())?;
        assert!(!retry.committed);
        assert_eq!(retry.revision, terminal.revision);
        assert_eq!(retry.journal_root, terminal.journal_root);
        assert_eq!(before, authority_bytes(&mut reopened)?);
    }
    Ok(())
}

#[test]
fn broken_other_plan_custody_refuses_instead_of_disappearing_from_closure() -> TestResult {
    let (f, mut dep) = Fixture::new("broken-closure")?;
    let selected = f.plan(&mut dep, "selected")?;
    let other = f.plan(&mut dep, "other")?;
    f.publish(&selected)?;
    f.publish(&other)?;
    let enrolled = f.adopt(&selected)?;
    f.indeterminate(&mut dep, &selected)?;
    f.reconcile(&mut dep, &selected, true)?;
    f.close(&selected)?;
    let blocked = f.assess(&selected, enrolled.revision.digest())?;
    assert_eq!(
        blocked
            .revision
            .assessment()
            .ok_or("assessment")?
            .closure
            .unsettled_plans,
        1
    );
    let path = f
        .root
        .join("agent/publications/spool/objects")
        .join(hex(other.control_plan_digest));
    assert!(path.is_file());
    fs::write(&path, b"deliberately damaged synthetic plan child")?;
    let before = authority_bytes(&mut dep)?;
    let refusal = execute(
        &f.root,
        &MissionRequest {
            session_id: f.opened.session.session_id.clone(),
            principal: f.opened.session.principal_id.clone(),
            action: MissionAction::Assess {
                plan_id: selected.plan_id.clone(),
                expected: blocked.revision.digest(),
            },
        },
    );
    assert!(
        matches!(refusal, Err(MissionError::InvalidProof)),
        "{refusal:?}"
    );
    assert_eq!(before, authority_bytes(&mut dep)?);
    Ok(())
}

#[test]
fn terminal_receipt_stays_immutable_but_new_owned_work_invalidates_current_projection() -> TestResult
{
    let (f, mut dep) = Fixture::new("historical-terminal")?;
    let selected = f.plan(&mut dep, "selected")?;
    let future = f.plan(&mut dep, "later")?;
    f.publish(&selected)?;
    let enrolled = f.adopt(&selected)?;
    f.indeterminate(&mut dep, &selected)?;
    f.reconcile(&mut dep, &selected, true)?;
    f.close(&selected)?;
    let terminal = f.assess(&selected, enrolled.revision.digest())?;
    protected_objective(&f, &terminal, Some(MissionLifecycleState::Resolved))?;
    same_objective_criteria(&enrolled, &terminal);
    assert_eq!(terminal.revision.state(), MissionLifecycleState::Resolved);
    assert_eq!(
        terminal.orientation.capsule().mission_state,
        Some(MissionLifecycleState::Resolved)
    );
    f.publish(&future)?;
    let same_anchor = dep.current_anchor().clone();
    let before = authority_bytes(&mut dep)?;
    let stale = f.assess(&selected, terminal.revision.digest())?;
    protected_objective(&f, &stale, None)?;
    same_objective_criteria(&terminal, &stale);
    assert!(!stale.committed);
    assert_eq!(stale.revision, terminal.revision);
    assert_eq!(stale.orientation.capsule().anchor, same_anchor);
    assert_eq!(stale.orientation.capsule().mission_state, None);
    assert_eq!(before, authority_bytes(&mut dep)?);
    Ok(())
}

#[test]
fn exact_adoption_after_handoff_rebase_keeps_original_criterion_and_mission() -> TestResult {
    let (f, mut dep) = Fixture::new("adoption-rebase")?;
    let plan = f.plan(&mut dep, "selected")?;
    f.publish(&plan)?;
    let enrolled = f.adopt(&plan)?;
    let handoff = prepare_handoff(
        &f.root,
        &HandoffRequest {
            session_id: f.opened.session.session_id.clone(),
            principal: f.opened.session.principal_id.clone(),
            note: Some("Synthetic mission adoption must retain its first criterion.".to_owned()),
        },
    )?
    .publish(&[])?;
    f.indeterminate(&mut dep, &plan)?;
    f.reconcile(&mut dep, &plan, true)?;
    let resumed = resume_session(
        &f.root,
        &ResumeRequest {
            handoff_id: handoff.record.capsule.handoff_id,
            principal: f.opened.session.principal_id.clone(),
        },
    )?;
    assert!(resumed.anchor_moved);
    let retry = f.adopt(&plan)?;
    assert!(!retry.committed);
    assert_eq!(retry.revision, enrolled.revision);
    assert_eq!(
        retry.revision.criterion().baseline_anchor,
        f.opened.session.current_anchor
    );
    assert_eq!(retry.session.current_anchor, resumed.session.current_anchor);
    assert_eq!(
        retry.revision.criterion().mission_record_digest,
        f.opened.mission.digest()
    );
    Ok(())
}

#[test]
fn another_principal_cannot_enroll_a_retained_foreign_plan() -> TestResult {
    let (f, mut dep) = Fixture::new("foreign")?;
    let plan = f.plan(&mut dep, "selected")?;
    f.publish(&plan)?;
    let other = open_session(
        &f.root,
        &Fixture::request("principal:foreign-mission-owner")?,
    )?;
    let before = authority_bytes(&mut dep)?;
    let refusal = execute(
        &f.root,
        &MissionRequest {
            session_id: other.session.session_id,
            principal: other.session.principal_id,
            action: MissionAction::Adopt {
                plan_id: plan.plan_id,
                decision_deadline: TimestampNs(f.opened.orientation.capsule().created_at.0 + 1),
            },
        },
    );
    assert!(matches!(
        refusal,
        Err(MissionError::Session(
            fss_reference::deployment_session::DeploymentSessionError::PlanUnknown
        ))
    ));
    assert_eq!(before, authority_bytes(&mut dep)?);
    Ok(())
}

#[test]
fn proof_bound_cancellation_is_terminal_and_old_effect_prefix_stays_historical() -> TestResult {
    let (f, mut dep) = Fixture::new("cancelled-historical")?;
    let selected = f.plan(&mut dep, "selected")?;
    let other = f.plan(&mut dep, "other")?;
    f.publish(&selected)?;
    f.publish(&other)?;
    let enrolled = f.adopt(&selected)?;
    let initial = f.assess(&selected, enrolled.revision.digest())?;
    let old_anchor = dep.current_anchor().clone();
    let prepared = f.prepare(&mut dep, &selected)?;
    dep.effects_mut().cancel(
        &prepared.intent.operation_id,
        TimestampNs(f.effect_time() + 1),
        ContentDigest::sha256(b"explicit synthetic cancellation request"),
        Some("owner withdrew synthetic delivery".to_owned()),
    )?;
    // Neither a cancellation nor a root-last episode advances the ledger anchor. The
    // historical session view predates these effect records, so close must show stale
    // mission metadata instead of comparing its absent old receipt with a newer episode.
    f.close(&selected)?;
    f.close(&other)?;
    assert_eq!(dep.current_anchor(), &old_anchor);
    let before = authority_bytes(&mut dep)?;
    let cancelled = f.assess(&selected, initial.revision.digest())?;
    protected_objective(&f, &cancelled, Some(MissionLifecycleState::Cancelled))?;
    same_objective_criteria(&enrolled, &cancelled);
    assert_eq!(cancelled.revision.state(), MissionLifecycleState::Cancelled);
    assert_eq!(
        cancelled.orientation.capsule().mission_state,
        Some(MissionLifecycleState::Cancelled)
    );
    assert!(
        !cancelled
            .revision
            .assessment()
            .ok_or("assessment")?
            .operation
            .as_ref()
            .ok_or("operation")?
            .dispatched
    );
    let old_view = prepare_handoff(&f.root, &HandoffRequest {
        session_id: f.opened.session.session_id.clone(),
        principal: f.opened.session.principal_id.clone(),
        note: Some("Preserve the retained cancellation without laundering it into an older effect prefix.".to_owned()),
    })?;
    assert_eq!(old_view.orientation.capsule().mission_state, None);
    old_view.publish(&[])?;
    assert_eq!(before, authority_bytes(&mut dep)?);
    Ok(())
}

#[test]
fn retained_effect_prefix_refuses_truncation_and_equal_or_larger_divergent_history() -> TestResult {
    for replacement in ["empty", "equal", "longer"] {
        let (f, mut dep) = Fixture::new(&format!("prefix-{replacement}"))?;
        let selected = f.plan(&mut dep, "selected")?;
        let unrelated = f.plan(&mut dep, "replacement")?;
        let extra = f.plan(&mut dep, "extra")?;
        f.publish(&selected)?;
        let effect_path = dep.effects().path().to_path_buf();
        let original_prefix = fs::read(&effect_path)?;
        let enrolled = f.adopt(&selected)?;
        f.indeterminate(&mut dep, &selected)?;
        let assessed = f.assess(&selected, enrolled.revision.digest())?;
        assert_eq!(
            assessed.revision.state(),
            MissionLifecycleState::Reconciling
        );
        let retained = assessed.revision.assessment().ok_or("assessment")?.clone();
        assert!(retained.effect_record_count > 0);
        drop(dep);

        // Deliberately simulate out-of-band loss or replacement of an otherwise valid
        // committed journal prefix. Reopen through the real owner, then write any replacement
        // operations through its normal durable APIs; no malformed record is manufactured.
        fs::write(&effect_path, &original_prefix)?;
        let mut reopened = ReferenceDeployment::open(&f.root, SITE, &f.cx)?;
        if replacement != "empty" {
            f.indeterminate(&mut reopened, &unrelated)?;
        }
        if replacement == "longer" {
            f.prepare(&mut reopened, &extra)?;
        }
        let history = fss_reference::agent_orient::DeploymentHistory::read(
            &f.root,
            &fss_reference::agent_orient::OrientLimits::default(),
        )?;
        let snapshot = history.snapshot_at(history.head())?;
        let count = snapshot.position.effect_records.unwrap_or(0);
        match replacement {
            "empty" => assert!(count < retained.effect_record_count),
            "equal" => assert_eq!(count, retained.effect_record_count),
            "longer" => assert!(count > retained.effect_record_count),
            _ => return Err("unknown fixture replacement".into()),
        }
        assert_eq!(snapshot.anchor, retained.anchor);
        assert_ne!(snapshot.effect_journal_root, retained.effect_journal_root);
        let before = authority_bytes(&mut reopened)?;
        let refusal = execute(
            &f.root,
            &MissionRequest {
                session_id: f.opened.session.session_id.clone(),
                principal: f.opened.session.principal_id.clone(),
                action: MissionAction::Assess {
                    plan_id: selected.plan_id.clone(),
                    expected: assessed.revision.digest(),
                },
            },
        );
        assert!(
            matches!(refusal, Err(MissionError::InvalidProof)),
            "{refusal:?}"
        );
        assert_eq!(before, authority_bytes(&mut reopened)?);
    }
    Ok(())
}
