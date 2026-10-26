#![forbid(unsafe_code)]
//! Durable delivery, disconnect/restart and explicit contiguous ACKs over real deployment files.
//! Effects are explicitly synthetic journal fixtures; no provider or device is contacted.

use std::error::Error;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

use fss_core::{
    AgentView, BatchId, BudgetVector, CaptureInterval, ContentDigest, ContextAuthority,
    EffectIntent, EffectState, EventId, EvidenceDelta, IdempotencyKey, MeaningfulDeltaClass,
    ObjectId, ObligationId, OperationId, Plane, PrincipalId, RootAuthoritySpec, TimestampNs,
};
use fss_reference::agent_follow::replay::{
    ReplayBinding, ReplayBoundary, ReplayControl, ReplayDenial, ReplayError, follow_replay_step_for,
};
use fss_reference::agent_follow::{AnchorToken, FollowRequest, history_anchor_token};
use fss_reference::agent_orient::{
    DeploymentHistory, OrientLimits, OrientMissionBrief, OrientMissionProgress,
    OrientSessionBinding,
};
use fss_reference::agent_session::checkpoint::journal::follow::DurableFollowError;
use fss_reference::agent_session::checkpoint::journal::{
    DurableSessionLimits, DurableSessionStore, SessionRecoveryState, inspect_session_bytes,
};
use fss_reference::agent_session::mission::MissionPlanCriterion;
use fss_reference::agent_session::work_claims::WorkClaimLimits;
use fss_reference::agent_session::workspace::{WorkspaceWrite, WorkspaceWriteMode};
use fss_reference::deployment_session::follow::{
    FollowSessionBinding, FollowSessionBoundary, FollowSessionControl, FollowSessionDelivery,
    FollowSessionError, FollowSessionRequest, follow_session,
};
use fss_reference::deployment_session::{
    DeploymentSessionError, OpenSessionRequest, OpenedSession, open_session,
};
use fss_reference::{ADP_REPLAY_ROW_ID, ReferenceDeployment, ReplayCx, ReplayIoAuthority};

type TestResult<T = ()> = Result<T, Box<dyn Error>>;
const SITE: &str = "site:follow-session-contract";

struct Fixture {
    root: PathBuf,
    cx: ReplayCx,
    commits: u64,
    opened: OpenedSession,
}

impl Fixture {
    fn new(tag: &str) -> TestResult<Self> {
        let root =
            std::env::temp_dir().join(format!("fss-follow-session-{tag}-{}", std::process::id()));
        if root.exists() {
            fs::remove_dir_all(&root)?;
        }
        let authority = ContextAuthority::new_root(RootAuthoritySpec {
            trace_id: format!("trace:follow-session:{tag}"),
            operation_id: OperationId::parse(format!("operation:follow-session:{tag}"))?,
            principal: "operator:follow-session-fixture".to_owned(),
            capabilities: vec![ADP_REPLAY_ROW_ID.to_owned()],
            deadline: None,
            priority: 10,
            budgets: BudgetVector::ZERO,
            privacy_scope: "privacy:internal".to_owned(),
            retention_scope: "retention:ephemeral".to_owned(),
            anchor_universe: ContentDigest::sha256(b"explicit follow session fixture"),
            generation: 1,
        })?;
        let cx = ReplayCx::new(ReplayIoAuthority::from_context_authority(
            &authority,
            root.with_extension("cx"),
        )?);
        drop(ReferenceDeployment::open(&root, SITE, &cx)?);
        let opened = open_session(
            &root,
            &OpenSessionRequest {
                mission: "Observe every retained deployment transition".to_owned(),
                objective: "Preserve uncertainty and explicit delivery acknowledgement".to_owned(),
                principal: PrincipalId::parse("principal:follow-session")?,
                view: AgentView::Brief,
                token_budget: 100_000,
            },
        )?;
        Ok(Self {
            root,
            cx,
            commits: 0,
            opened,
        })
    }

    fn append(&mut self) -> TestResult {
        self.commits += 1;
        let index = self.commits;
        let mut deployment = ReferenceDeployment::open(&self.root, SITE, &self.cx)?;
        let payload = deployment.stage_payload(format!("synthetic metadata {index}").as_bytes())?;
        deployment.append_batch(
            BatchId::parse(format!("batch:follow-session:{index}"))?,
            vec![EvidenceDelta {
                delta_id: format!("delta:follow-session:{index}"),
                family: "decode_receipt".to_owned(),
                object_id: ObjectId::parse(format!("object:follow-session:{index}"))?,
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

    fn request(&self, page_size: u32) -> TestResult<FollowSessionRequest> {
        Ok(FollowSessionRequest {
            session_id: self.opened.session.session_id.clone(),
            subscription_id: "deployment-watch".to_owned(),
            since: AnchorToken::parse(&self.opened.orientation.anchor_token)
                .ok_or("opening token")?,
            view: AgentView::Brief,
            max_entries: page_size,
            acknowledge: None,
        })
    }

    fn follow(&self, request: &FollowSessionRequest) -> TestResult<FollowSessionDelivery> {
        let mut control = Control::new(&self.root, request, &self.opened);
        Ok(follow_session(
            &self.root,
            &self.opened.session.principal_id,
            request,
            &OrientLimits::default(),
            &mut control,
        )?)
    }

    fn inspect(&self) -> TestResult<SessionRecoveryState> {
        Ok(inspect_session_bytes(
            &fs::read(self.root.join("agent/sessions/journal.fssj"))?,
            DurableSessionLimits::default(),
            WorkClaimLimits::default(),
        )?)
    }

    fn prepare(&self) -> TestResult<OperationId> {
        let operation = OperationId::parse("operation:follow-session:uncertain")?;
        let mut deployment = ReferenceDeployment::open(&self.root, SITE, &self.cx)?;
        deployment.effects_mut().prepare(
            EffectIntent {
                operation_id: operation.clone(),
                idempotency_key: IdempotencyKey::parse("idempotency:follow-session:uncertain")?,
                effect_class: "fixture.observe".to_owned(),
                request_digest: ContentDigest::sha256(b"synthetic observation request"),
                precondition_digest: ContentDigest::sha256(b"synthetic precondition"),
            },
            ObligationId::parse("obligation:follow-session:uncertain")?,
            "synthetic observation verified",
            TimestampNs(100),
        )?;
        Ok(operation)
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
        let _ = fs::remove_dir_all(self.root.with_extension("cx"));
    }
}

struct Control<'a> {
    root: PathBuf,
    request: FollowSessionRequest,
    opened: OpenedSession,
    deny: Option<FollowSessionBoundary>,
    boundaries: Vec<FollowSessionBoundary>,
    before_revalidate: Option<Box<dyn FnMut() -> TestResult + 'a>>,
}

impl<'a> Control<'a> {
    fn new(root: &Path, request: &FollowSessionRequest, opened: &OpenedSession) -> Self {
        Self {
            root: root.to_path_buf(),
            request: request.clone(),
            opened: opened.clone(),
            deny: None,
            boundaries: Vec::new(),
            before_revalidate: None,
        }
    }
}

impl ReplayControl for Control<'_> {
    fn admit(&mut self, binding: &ReplayBinding, _: ReplayBoundary) -> Result<(), ReplayDenial> {
        if !binding.objects_root().starts_with(&self.root)
            || binding.request().principal != self.opened.session.principal_id
            || binding.request().view != self.request.view
            || binding.request().max_entries != self.request.max_entries
            || binding.session().is_none_or(|session| {
                session.session_id != self.opened.session.session_id
                    || session.mission_id != self.opened.session.mission_id
            })
        {
            return Err(ReplayDenial::Unauthorized);
        }
        Ok(())
    }
}

impl FollowSessionControl for Control<'_> {
    fn admit_session(
        &mut self,
        binding: &FollowSessionBinding<'_>,
        boundary: FollowSessionBoundary,
    ) -> Result<(), ReplayDenial> {
        if binding.root() != self.root
            || binding.principal() != &self.opened.session.principal_id
            || binding.request() != &self.request
        {
            return Err(ReplayDenial::Unauthorized);
        }
        self.boundaries.push(boundary);
        if self.deny == Some(boundary) {
            return Err(ReplayDenial::Cancelled);
        }
        if boundary == FollowSessionBoundary::RevalidateHistory
            && let Some(mut mutate) = self.before_revalidate.take()
        {
            mutate().map_err(|_| ReplayDenial::Unavailable)?;
        }
        Ok(())
    }
}

#[test]
fn disconnect_replays_exact_pending_page_and_lost_ack_does_not_consume_its_successor() -> TestResult
{
    let mut fixture = Fixture::new("restart")?;
    let mut request = fixture.request(64)?;
    for _ in 0..3 {
        fixture.append()?;
    }
    let first = fixture.follow(&request)?;
    assert_eq!(first.result_anchor.position().commit_sequence, 1);
    assert_eq!(first.horizon_anchor.position().commit_sequence, 3);
    assert_eq!(
        first.follow.delta.session_id,
        fixture.opened.session.session_id
    );
    assert!(!first.replayed);
    let retained = fixture.inspect()?;
    assert_eq!(retained.follows.len(), 1);
    assert_eq!(
        retained.follows[0].acknowledged_anchor(),
        request.since.as_str()
    );
    assert_eq!(
        retained.follows[0].pending().ok_or("pending")?.receipt(),
        first.delivery_receipt
    );
    let repeated = fixture.follow(&request)?;
    assert!(repeated.replayed);
    assert_eq!(repeated.delivery_receipt, first.delivery_receipt);
    assert_eq!(repeated.follow, first.follow);
    assert_eq!(repeated.journal_root, first.journal_root);

    // A later head cannot move the frozen window being acknowledged.
    fixture.append()?;
    request.acknowledge = Some(first.delivery_receipt);
    let second = fixture.follow(&request)?;
    assert_eq!(second.since_anchor, first.result_anchor);
    assert_eq!(second.result_anchor.position().commit_sequence, 2);
    assert_eq!(second.horizon_anchor, first.horizon_anchor);
    assert_eq!(second.acknowledged, Some(first.delivery_receipt));
    let lost_ack_retry = fixture.follow(&request)?;
    assert!(lost_ack_retry.replayed);
    assert_eq!(lost_ack_retry.delivery_receipt, second.delivery_receipt);
    assert_eq!(lost_ack_retry.follow, second.follow);
    assert_eq!(lost_ack_retry.journal_root, second.journal_root);
    request.acknowledge = Some(second.delivery_receipt);
    let third = fixture.follow(&request)?;
    assert_eq!(third.result_anchor.position().commit_sequence, 3);
    assert!(third.horizon_reached);
    assert_eq!(third.horizon_anchor, first.horizon_anchor);
    Ok(())
}

#[test]
fn paging_keeps_transition_and_complete_class_header_until_every_item_is_explicitly_acked()
-> TestResult {
    let mut fixture = Fixture::new("pages")?;
    let mut request = fixture.request(1)?;
    fixture.append()?;
    fixture.append()?;
    let mut delivery = fixture.follow(&request)?;
    let complete = delivery
        .follow
        .items
        .iter()
        .map(|item| item.digest())
        .collect::<Vec<_>>();
    assert!(
        complete.len() > 1,
        "fixture must require more than one page"
    );
    let classes = delivery.follow.delta.classes.clone();
    let result = delivery.result_anchor.clone();
    let mut seen = Vec::new();
    for _ in 0..128 {
        assert_eq!(delivery.follow.delta.classes, classes);
        assert_eq!(delivery.result_anchor, result);
        assert_eq!(delivery.since_anchor, request.since);
        seen.extend(delivery.follow.page_items.iter().map(|item| item.digest()));
        assert_eq!(
            fixture.inspect()?.follows[0].acknowledged_anchor(),
            request.since.as_str()
        );
        let final_page = delivery.follow.page.next_cursor.is_none();
        request.acknowledge = Some(delivery.delivery_receipt);
        delivery = fixture.follow(&request)?;
        if final_page {
            assert_eq!(delivery.since_anchor, result);
            assert_eq!(delivery.result_anchor.position().commit_sequence, 2);
            assert_eq!(seen, complete);
            assert_eq!(
                fixture.inspect()?.follows[0].acknowledged_anchor(),
                result.as_str()
            );
            return Ok(());
        }
    }
    Err("bounded fixture pages failed to terminate".into())
}

#[test]
fn wrong_receipt_and_changed_registration_cannot_advance_or_replace_pending_delivery() -> TestResult
{
    let mut fixture = Fixture::new("wrong-ack")?;
    fixture.append()?;
    let request = fixture.request(64)?;
    let first = fixture.follow(&request)?;
    let before = fixture.inspect()?;
    let mut wrong = request.clone();
    wrong.acknowledge = Some(ContentDigest::sha256(b"receipt from a different delivery"));
    let mut changed_page = request.clone();
    changed_page.max_entries = 1;
    let mut changed_view = request.clone();
    changed_view.view = AgentView::Pulse;
    let mut changed_start = request.clone();
    changed_start.since = first.result_anchor.clone();
    for input in [wrong, changed_page, changed_view, changed_start] {
        let mut control = Control::new(&fixture.root, &input, &fixture.opened);
        let failure = follow_session(
            &fixture.root,
            &fixture.opened.session.principal_id,
            &input,
            &OrientLimits::default(),
            &mut control,
        )
        .err()
        .ok_or("wrong identity must refuse")?;
        assert!(matches!(
            failure.error,
            FollowSessionError::Store(DurableFollowError::Conflict)
        ));
        assert!(failure.acknowledged.is_none());
        assert_eq!(fixture.inspect()?, before);
    }
    assert_eq!(
        fixture.follow(&request)?.delivery_receipt,
        first.delivery_receipt
    );
    Ok(())
}

#[test]
fn cancelled_release_retains_delivery_and_failed_successor_reports_committed_ack() -> TestResult {
    let mut fixture = Fixture::new("release")?;
    fixture.append()?;
    fixture.append()?;
    let mut request = fixture.request(64)?;
    let mut control = Control::new(&fixture.root, &request, &fixture.opened);
    control.deny = Some(FollowSessionBoundary::Deliver);
    let failure = follow_session(
        &fixture.root,
        &fixture.opened.session.principal_id,
        &request,
        &OrientLimits::default(),
        &mut control,
    )
    .err()
    .ok_or("release cancellation")?;
    assert!(failure.journal_may_have_changed);
    assert!(failure.acknowledged.is_none());
    let pending = fixture.inspect()?.follows[0]
        .pending()
        .ok_or("durable pending")?
        .receipt();
    let first = fixture.follow(&request)?;
    assert!(first.replayed);
    assert_eq!(first.delivery_receipt, pending);
    request.acknowledge = Some(pending);
    let mut control = Control::new(&fixture.root, &request, &fixture.opened);
    control.deny = Some(FollowSessionBoundary::Deliver);
    let failure = follow_session(
        &fixture.root,
        &fixture.opened.session.principal_id,
        &request,
        &OrientLimits::default(),
        &mut control,
    )
    .err()
    .ok_or("successor release cancellation")?;
    assert_eq!(failure.acknowledged, Some(pending));
    assert_eq!(failure.since_anchor, Some(first.result_anchor));
    let successor = fixture.follow(&request)?;
    assert!(successor.replayed);
    assert_eq!(successor.result_anchor.position().commit_sequence, 2);
    assert_ne!(successor.delivery_receipt, pending);
    Ok(())
}

#[test]
fn oversized_limits_and_cancelled_read_refuse_before_any_journal_io() -> TestResult {
    let fixture = Fixture::new("pre-io")?;
    let request = fixture.request(64)?;
    let before = fixture.inspect()?;
    let mut control = Control::new(&fixture.root, &request, &fixture.opened);
    let limits = OrientLimits {
        max_layout_bytes: usize::MAX,
        ..OrientLimits::default()
    };
    let failure = follow_session(
        &fixture.root,
        &fixture.opened.session.principal_id,
        &request,
        &limits,
        &mut control,
    )
    .err()
    .ok_or("oversized native limit")?;
    assert!(matches!(
        failure.error,
        FollowSessionError::Replay(ReplayError::InvalidBounds)
    ));
    assert!(failure.head.is_none());
    assert!(!failure.journal_may_have_changed);
    assert!(control.boundaries.is_empty());
    control.deny = Some(FollowSessionBoundary::ReadHistory);
    let failure = follow_session(
        &fixture.root,
        &fixture.opened.session.principal_id,
        &request,
        &OrientLimits::default(),
        &mut control,
    )
    .err()
    .ok_or("cancelled initial read")?;
    assert!(!failure.journal_may_have_changed);
    assert_eq!(fixture.inspect()?, before);
    Ok(())
}

#[test]
fn current_history_change_during_ack_reconstruction_does_not_consume_pending() -> TestResult {
    let mut fixture = Fixture::new("ack-race")?;
    fixture.append()?;
    fixture.append()?;
    let mut request = fixture.request(64)?;
    let first = fixture.follow(&request)?;
    let retained = fixture.inspect()?.follows;
    request.acknowledge = Some(first.delivery_receipt);
    let root = fixture.root.clone();
    let principal = fixture.opened.session.principal_id.clone();
    let mut control = Control::new(&root, &request, &fixture.opened);
    control.before_revalidate = Some(Box::new(|| fixture.append()));
    let failure = follow_session(
        &root,
        &principal,
        &request,
        &OrientLimits::default(),
        &mut control,
    )
    .err()
    .ok_or("concurrent history append")?;
    drop(control);
    assert!(matches!(failure.error, FollowSessionError::ChangedDelivery));
    assert!(failure.acknowledged.is_none());
    assert_eq!(fixture.inspect()?.follows, retained);
    assert_eq!(
        fixture
            .follow(&request)?
            .result_anchor
            .position()
            .commit_sequence,
        2
    );
    Ok(())
}

#[test]
fn effect_uncertainty_survives_disconnect_until_a_separately_delivered_verification() -> TestResult
{
    let fixture = Fixture::new("effect-order")?;
    let mut request = fixture.request(64)?;
    let operation = fixture.prepare()?;
    let witness = ContentDigest::sha256(b"explicit fixture terminal observation");
    {
        let mut deployment = ReferenceDeployment::open(&fixture.root, SITE, &fixture.cx)?;
        deployment.effects_mut().transition(
            &operation,
            EffectState::Committed,
            TimestampNs(101),
            None,
            None,
        )?;
        deployment.effects_mut().mark_indeterminate(
            &operation,
            TimestampNs(102),
            "synthetic lost ACK",
        )?;
        deployment.effects_mut().transition(
            &operation,
            EffectState::Observed,
            TimestampNs(103),
            Some(witness),
            None,
        )?;
        deployment
            .effects_mut()
            .reconcile_verified(&operation, witness, TimestampNs(104))?;
    }
    let mut uncertainty = false;
    let mut closed = false;
    let mut prior = request.since.clone();
    for _ in 0..8 {
        let delivery = fixture.follow(&request)?;
        assert_eq!(delivery.since_anchor, prior);
        assert_eq!(delivery.result_anchor.position().commit_sequence, 0);
        assert!(delivery.follow.page.next_cursor.is_none());
        if delivery
            .follow
            .result
            .indeterminate_effects
            .contains(&operation)
        {
            uncertainty = true;
            assert!(
                delivery
                    .follow
                    .delta
                    .classes
                    .contains(&MeaningfulDeltaClass::EffectUncertainty)
            );
        } else if uncertainty {
            closed = true;
        }
        let retry = fixture.follow(&request)?;
        assert_eq!(retry.delivery_receipt, delivery.delivery_receipt);
        assert_eq!(retry.follow, delivery.follow);
        if delivery.horizon_reached {
            assert!(uncertainty && closed);
            assert!(delivery.follow.result.open_obligations.is_empty());
            return Ok(());
        }
        request.acknowledge = Some(delivery.delivery_receipt);
        prior = delivery.result_anchor;
    }
    Err("bounded fixture effect horizon was not reached".into())
}

#[test]
fn committed_ack_without_successor_cannot_restate_a_changed_previously_acknowledged_basis()
-> TestResult {
    let mut fixture = Fixture::new("ack-only-custody")?;
    fixture.append()?;
    fixture.append()?;
    let mut request = fixture.request(64)?;
    let first = fixture.follow(&request)?;
    request.acknowledge = Some(first.delivery_receipt);
    let mut control = Control::new(&fixture.root, &request, &fixture.opened);
    control.deny = Some(FollowSessionBoundary::PublishDelivery);
    let failure = follow_session(
        &fixture.root,
        &fixture.opened.session.principal_id,
        &request,
        &OrientLimits::default(),
        &mut control,
    )
    .err()
    .ok_or("successor publication cancellation")?;
    assert_eq!(failure.acknowledged, Some(first.delivery_receipt));
    let retained = fixture.inspect()?.follows;
    assert_eq!(
        retained[0].acknowledged_anchor(),
        first.result_anchor.as_str()
    );
    assert!(retained[0].acknowledged_fingerprint().is_some());
    assert!(retained[0].pending().is_none());

    // Tear the effect journal, leaving canonical ledger authority writable. A torn ledger is
    // correctly refused before the session writer opens, so it cannot exercise this later
    // acknowledged-fingerprint guard. Both journals use the same native record header.
    let original = fs::read(fixture.root.join("ledger/journal.fssj"))?;
    let effects = fixture.root.join("effects/journal.fssj");
    let mut writer = fs::OpenOptions::new().append(true).open(&effects)?;
    writer.write_all(&original[..4])?;
    writer.sync_all()?;
    drop(writer);
    let history = DeploymentHistory::read(&fixture.root, &OrientLimits::default())?;
    assert_eq!(
        history_anchor_token(&history, history.head()).ok_or("unchanged committed head")?,
        first.horizon_anchor
    );
    let mut control = Control::new(&fixture.root, &request, &fixture.opened);
    let failure = follow_session(
        &fixture.root,
        &fixture.opened.session.principal_id,
        &request,
        &OrientLimits::default(),
        &mut control,
    )
    .err()
    .ok_or("changed acknowledged basis must resnapshot")?;
    assert!(
        matches!(failure.error, FollowSessionError::ChangedDelivery),
        "unexpected acknowledged-basis refusal: {:?}",
        failure.error
    );
    assert_eq!(failure.acknowledged, Some(first.delivery_receipt));
    assert!(failure.journal_may_have_changed);
    assert!(
        control
            .boundaries
            .contains(&FollowSessionBoundary::Acknowledge)
    );
    assert!(
        !control
            .boundaries
            .contains(&FollowSessionBoundary::PublishDelivery)
    );
    assert_eq!(fixture.inspect()?.follows, retained);
    Ok(())
}

#[test]
fn torn_authority_ledger_refuses_before_reconfirming_an_already_committed_ack() -> TestResult {
    let mut fixture = Fixture::new("ack-only-authority")?;
    fixture.append()?;
    fixture.append()?;
    let mut request = fixture.request(64)?;
    let first = fixture.follow(&request)?;
    request.acknowledge = Some(first.delivery_receipt);
    let mut control = Control::new(&fixture.root, &request, &fixture.opened);
    control.deny = Some(FollowSessionBoundary::PublishDelivery);
    let failure = follow_session(
        &fixture.root,
        &fixture.opened.session.principal_id,
        &request,
        &OrientLimits::default(),
        &mut control,
    )
    .err()
    .ok_or("successor publication cancellation")?;
    assert_eq!(failure.acknowledged, Some(first.delivery_receipt));
    let retained = fixture.inspect()?;
    assert_eq!(
        retained.follows[0].last_acknowledged(),
        Some(first.delivery_receipt)
    );
    assert!(retained.follows[0].pending().is_none());
    let journal = fixture.root.join("agent/sessions/journal.fssj");
    let journal_before = fs::read(&journal)?;

    let ledger = fixture.root.join("ledger/journal.fssj");
    let original = fs::read(&ledger)?;
    let mut writer = fs::OpenOptions::new().append(true).open(&ledger)?;
    writer.write_all(&original[..4])?;
    writer.sync_all()?;
    drop(writer);
    let mut control = Control::new(&fixture.root, &request, &fixture.opened);
    let failure = follow_session(
        &fixture.root,
        &fixture.opened.session.principal_id,
        &request,
        &OrientLimits::default(),
        &mut control,
    )
    .err()
    .ok_or("canonical authority requires recovery")?;
    assert!(
        matches!(
            &failure.error,
            FollowSessionError::Session(DeploymentSessionError::StoreInvalid(reason))
                if reason == "deployment authority requires recovery"
        ),
        "unexpected authority refusal: {:?}",
        failure.error
    );
    // This invocation cannot attest the historical ACK: it never admitted the live session.
    // Inspection still proves the earlier committed ACK and the absence of a successor.
    assert!(failure.acknowledged.is_none());
    assert!(failure.since_anchor.is_none());
    assert_eq!(
        control.boundaries,
        [
            FollowSessionBoundary::ReadHistory,
            FollowSessionBoundary::OpenJournal,
        ]
    );
    assert_eq!(fs::read(&journal)?, journal_before);
    assert_eq!(fixture.inspect()?, retained);
    Ok(())
}

#[test]
fn ambiguous_journals_and_nonreplayable_workspace_semantics_require_explicit_resnapshot()
-> TestResult {
    let mut ambiguous = Fixture::new("ambiguous")?;
    let request = ambiguous.request(64)?;
    ambiguous.append()?;
    ambiguous.prepare()?;
    let mut control = Control::new(&ambiguous.root, &request, &ambiguous.opened);
    let failure = follow_session(
        &ambiguous.root,
        &ambiguous.opened.session.principal_id,
        &request,
        &OrientLimits::default(),
        &mut control,
    )
    .err()
    .ok_or("unproved journal order")?;
    assert!(matches!(
        failure.error,
        FollowSessionError::Replay(ReplayError::AmbiguousOrder)
    ));
    assert_eq!(failure.since_anchor, Some(request.since.clone()));
    let retained = ambiguous.inspect()?;
    assert_eq!(
        retained.follows[0].acknowledged_anchor(),
        request.since.as_str()
    );
    assert!(retained.follows[0].pending().is_none());

    let mut fixture = Fixture::new("semantic-drift")?;
    fixture.append()?;
    let mut request = fixture.request(64)?;
    let delivered = fixture.follow(&request)?;
    let before = fixture.inspect()?.follows;
    let mut store = DurableSessionStore::open_existing_with_coordination(
        fixture.root.join("agent/sessions/journal.fssj"),
        delivered.journal_root,
        DurableSessionLimits::default(),
        WorkClaimLimits::default(),
    )?;
    let mut capsule = fixture.opened.revision.capsule().clone();
    capsule.revision += 1;
    capsule
        .unknowns
        .push("A new unresolved mission obligation".to_owned());
    store.publish_workspace(
        &fixture.opened.session.principal_id,
        WorkspaceWrite {
            expected_head: Some(fixture.opened.revision.digest()),
            capsule,
            mode: WorkspaceWriteMode::Advance,
        },
        TimestampNs(10_000),
    )?;
    fs::write(
        fixture.root.join("agent/sessions/ROOT"),
        format!("{}\n", store.committed_root().to_text()),
    )?;
    drop(store);
    request.acknowledge = Some(delivered.delivery_receipt);
    let mut control = Control::new(&fixture.root, &request, &fixture.opened);
    let failure = follow_session(
        &fixture.root,
        &fixture.opened.session.principal_id,
        &request,
        &OrientLimits::default(),
        &mut control,
    )
    .err()
    .ok_or("unreplayed mission history")?;
    assert!(matches!(
        failure.error,
        FollowSessionError::Replay(ReplayError::UnsupportedSessionFacets)
    ));
    assert!(failure.acknowledged.is_none());
    assert_eq!(fixture.inspect()?.follows, before);
    let history = DeploymentHistory::read(&fixture.root, &OrientLimits::default())?;
    assert_eq!(
        history_anchor_token(&history, history.head()),
        Some(delivered.result_anchor)
    );
    Ok(())
}

#[test]
fn retained_mission_progress_refuses_replay_before_ack_or_new_subscription() -> TestResult {
    let mut fixture = Fixture::new("mission-progress")?;
    fixture.append()?;
    let mut request = fixture.request(64)?;
    let delivered = fixture.follow(&request)?;
    let mut store = DurableSessionStore::open_existing_with_coordination(
        fixture.root.join("agent/sessions/journal.fssj"),
        delivered.journal_root,
        DurableSessionLimits::default(),
        WorkClaimLimits::default(),
    )?;
    // Explicit synthetic owner metadata isolates the agent-journal axis. It is not an actual
    // retained native plan or evidence that an operation occurred. Follow must refuse even
    // though there is no plan publication for its pre-existing publication scan to detect.
    let revision = store.register_mission_plan(
        &fixture.opened.session.principal_id,
        MissionPlanCriterion {
            session_id: fixture.opened.session.session_id.clone(),
            mission_id: fixture.opened.session.mission_id.clone(),
            principal: fixture.opened.session.principal_id.clone(),
            mission_record_digest: fixture.opened.mission.digest(),
            plan_id: "plan:follow:synthetic-mission".to_owned(),
            plan_record_digest: ContentDigest::sha256(b"synthetic mission plan metadata"),
            plan_root: ContentDigest::sha256(b"synthetic mission plan publication"),
            control_plan_digest: ContentDigest::sha256(b"synthetic mission plan rendering"),
            operation_id: OperationId::parse("operation:follow:synthetic-mission")?,
            obligation_id: ObligationId::parse("obligation:follow:synthetic-mission")?,
            event_id: EventId::parse("event:follow:synthetic-mission")?,
            event_revision: ContentDigest::sha256(b"synthetic mission event revision"),
            contract_basis: fixture.opened.orientation.capsule().contract_basis.clone(),
            baseline_anchor: fixture.opened.session.current_anchor.clone(),
            decision_deadline: TimestampNs(10_001),
        },
        TimestampNs(10_000),
    )?;
    fs::write(
        fixture.root.join("agent/sessions/ROOT"),
        format!("{}\n", store.committed_root().to_text()),
    )?;
    drop(store);

    // A supplied current or historical mission head cannot be applied to both evidence
    // endpoints by the pure replay API. Refusal precedes even its first snapshot admission.
    struct NoReplay;
    impl ReplayControl for NoReplay {
        fn admit(&mut self, _: &ReplayBinding, _: ReplayBoundary) -> Result<(), ReplayDenial> {
            Err(ReplayDenial::Unavailable)
        }
    }
    let history = DeploymentHistory::read(&fixture.root, &OrientLimits::default())?;
    for current in [false, true] {
        let binding = OrientSessionBinding {
            session_id: fixture.opened.session.session_id.clone(),
            mission_id: fixture.opened.session.mission_id.clone(),
            mission: Some(OrientMissionBrief {
                mission_id: fixture.opened.session.mission_id.clone(),
                session_id: fixture.opened.session.session_id.clone(),
                principal: fixture.opened.session.principal_id.clone(),
                site_lineage: SITE.to_owned(),
                mission: fixture.opened.mission.mission.clone(),
                objective: fixture.opened.mission.objective.clone(),
                record_digest: fixture.opened.mission.digest(),
            }),
            mission_progress: Some(OrientMissionProgress {
                revision: revision.clone(),
                current,
            }),
            cases: Vec::new(),
            plans: Vec::new(),
            claims: Vec::new(),
            findings: Vec::new(),
            supervisions: None,
            trauma_warnings: None,
        };
        let refusal = follow_replay_step_for(
            &history,
            &request.since,
            &delivered.result_anchor,
            &FollowRequest {
                view: request.view,
                principal: fixture.opened.session.principal_id.clone(),
                max_entries: request.max_entries,
                continuation: None,
            },
            Some(&binding),
            &mut NoReplay,
        );
        assert!(matches!(
            refusal,
            Err(ReplayError::UnsupportedSessionFacets)
        ));
    }

    let retained = fixture.inspect()?;
    let conserved_paths = [
        "agent/sessions/journal.fssj",
        "agent/sessions/ROOT",
        "ledger/journal.fssj",
        "effects/journal.fssj",
    ];
    let before = conserved_paths
        .iter()
        .map(|path| fs::read(fixture.root.join(path)))
        .collect::<Result<Vec<_>, _>>()?;
    request.acknowledge = Some(delivered.delivery_receipt);
    for retry in 0..3 {
        if retry == 2 {
            request.subscription_id = "new-after-mission-enrollment".to_owned();
            request.acknowledge = None;
        }
        let mut control = Control::new(&fixture.root, &request, &fixture.opened);
        let failure = follow_session(
            &fixture.root,
            &fixture.opened.session.principal_id,
            &request,
            &OrientLimits::default(),
            &mut control,
        )
        .err()
        .ok_or("retained mission history must require explicit resnapshot")?;
        assert!(matches!(
            failure.error,
            FollowSessionError::Replay(ReplayError::UnsupportedSessionFacets)
        ));
        assert!(failure.acknowledged.is_none());
        assert_eq!(
            control.boundaries,
            [
                FollowSessionBoundary::ReadHistory,
                FollowSessionBoundary::OpenJournal,
                FollowSessionBoundary::ReadSubscription,
            ],
        );
        assert_eq!(fixture.inspect()?, retained);
        for (path, expected) in conserved_paths.iter().zip(&before) {
            assert_eq!(&fs::read(fixture.root.join(path))?, expected);
        }
    }
    Ok(())
}
