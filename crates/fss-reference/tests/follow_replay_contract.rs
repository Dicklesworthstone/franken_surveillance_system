#![forbid(unsafe_code)]
//! Exact ordered follow replay over real committed deployment files. All effects below are
//! explicitly synthetic journal fixtures; no provider or physical device is contacted.

use std::error::Error;
use std::fs;
use std::path::PathBuf;

use fss_core::{
    AgentView, BatchId, BudgetVector, CaptureInterval, ContentDigest, ContextAuthority,
    EffectIntent, EffectState, EvidenceDelta, IdempotencyKey, KnowledgeState, MeaningfulDeltaClass,
    MissionId, ObjectId, ObligationId, OperationId, Plane, PrincipalId, RootAuthoritySpec,
    SessionId, TimestampNs,
};
use fss_reference::agent_follow::replay::{
    ReplayAxis, ReplayBinding, ReplayBoundary, ReplayControl, ReplayDenial, ReplayError,
    follow_replay_step, follow_replay_step_for,
};
use fss_reference::agent_follow::{
    AnchorToken, FollowError, FollowRequest, follow_deployment, snapshot_anchor_token,
};
use fss_reference::agent_orient::{
    DeploymentHistory, OrientCaseBrief, OrientClaimBrief, OrientFindingBrief, OrientLimits,
    OrientPlanBrief, OrientSessionBinding,
};
use fss_reference::{ADP_REPLAY_ROW_ID, ReferenceDeployment, ReplayCx, ReplayIoAuthority};

type TestResult<T = ()> = Result<T, Box<dyn Error>>;
const SITE: &str = "site:follow-replay-contract";

struct Fixture {
    root: PathBuf,
    cx: ReplayCx,
    commits: u64,
}

impl Fixture {
    fn new(tag: &str) -> TestResult<Self> {
        let root =
            std::env::temp_dir().join(format!("fss-follow-replay-{tag}-{}", std::process::id()));
        if root.exists() {
            fs::remove_dir_all(&root)?;
        }
        let authority = ContextAuthority::new_root(RootAuthoritySpec {
            trace_id: format!("trace:follow-replay:{tag}"),
            operation_id: OperationId::parse(format!("operation:follow-replay:{tag}"))?,
            principal: "operator:follow-replay-fixture".to_owned(),
            capabilities: vec![ADP_REPLAY_ROW_ID.to_owned()],
            deadline: None,
            priority: 10,
            budgets: BudgetVector::ZERO,
            privacy_scope: "privacy:internal".to_owned(),
            retention_scope: "retention:ephemeral".to_owned(),
            anchor_universe: ContentDigest::sha256(b"explicit follow replay fixture"),
            generation: 1,
        })?;
        let cx = ReplayCx::new(ReplayIoAuthority::from_context_authority(
            &authority,
            root.with_extension("cx"),
        )?);
        drop(ReferenceDeployment::open(&root, SITE, &cx)?);
        Ok(Self {
            root,
            cx,
            commits: 0,
        })
    }

    fn append(&mut self) -> TestResult {
        self.commits += 1;
        let index = self.commits;
        let mut deployment = ReferenceDeployment::open(&self.root, SITE, &self.cx)?;
        let payload =
            deployment.stage_payload(format!("explicit fixture metadata {index}").as_bytes())?;
        deployment.append_batch(
            BatchId::parse(format!("batch:follow-replay:{index}"))?,
            vec![EvidenceDelta {
                delta_id: format!("delta:follow-replay:{index}"),
                family: "decode_receipt".to_owned(),
                object_id: ObjectId::parse(format!("object:follow-replay:{index}"))?,
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

    fn history(&self) -> TestResult<DeploymentHistory> {
        Ok(DeploymentHistory::read(
            &self.root,
            &OrientLimits::default(),
        )?)
    }

    fn token(&self) -> TestResult<AnchorToken> {
        let history = self.history()?;
        let snapshot = history.snapshot_at(history.head())?;
        AnchorToken::parse(&snapshot_anchor_token(&snapshot))
            .ok_or_else(|| "invalid fixture token".into())
    }

    fn prepare(&self, suffix: &str) -> TestResult<OperationId> {
        let mut deployment = ReferenceDeployment::open(&self.root, SITE, &self.cx)?;
        let operation_id = OperationId::parse(format!("operation:follow-replay:{suffix}"))?;
        deployment.effects_mut().prepare(
            EffectIntent {
                operation_id: operation_id.clone(),
                idempotency_key: IdempotencyKey::parse(format!(
                    "idempotency:follow-replay:{suffix}"
                ))?,
                effect_class: "fixture.observe".to_owned(),
                request_digest: ContentDigest::sha256(b"synthetic observation request"),
                precondition_digest: ContentDigest::sha256(b"synthetic fixture precondition"),
            },
            ObligationId::parse(format!("obligation:follow-replay:{suffix}"))?,
            "synthetic fixture terminal observation verified",
            TimestampNs(100),
        )?;
        Ok(operation_id)
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
        let _ = fs::remove_dir_all(self.root.with_extension("cx"));
    }
}

#[derive(Default)]
struct Control {
    binding: Option<ReplayBinding>,
    boundaries: Vec<ReplayBoundary>,
    deny_at: Option<ReplayBoundary>,
}

impl ReplayControl for Control {
    fn admit(
        &mut self,
        binding: &ReplayBinding,
        boundary: ReplayBoundary,
    ) -> Result<(), ReplayDenial> {
        if let Some(expected) = &self.binding {
            if binding != expected {
                return Err(ReplayDenial::Unauthorized);
            }
        } else {
            self.binding = Some(binding.clone());
        }
        self.boundaries.push(boundary);
        if self.deny_at == Some(boundary) {
            Err(ReplayDenial::Cancelled)
        } else {
            Ok(())
        }
    }
}

fn request(page_size: u32) -> TestResult<FollowRequest> {
    Ok(FollowRequest {
        view: AgentView::Brief,
        principal: PrincipalId::parse("principal:follow-replay")?,
        max_entries: page_size,
        continuation: None,
    })
}

#[test]
fn ledger_replay_delivers_every_commit_and_keeps_a_frozen_horizon_after_appends() -> TestResult {
    let mut fixture = Fixture::new("ledger")?;
    let start = fixture.token()?;
    for _ in 0..3 {
        fixture.append()?;
    }
    let horizon = fixture.token()?;
    let first_history = fixture.history()?;
    let first = follow_replay_step(
        &first_history,
        &start,
        &horizon,
        &request(64)?,
        &mut Control::default(),
    )?;
    assert_eq!(first.result_anchor.position().commit_sequence, 1);
    assert!(!first.horizon_reached);
    // Both journals subsequently advance. The previously frozen ledger-only range remains exact.
    fixture.append()?;
    fixture.prepare("later")?;
    let later_history = fixture.history()?;
    let repeated = follow_replay_step(
        &later_history,
        &start,
        &horizon,
        &request(64)?,
        &mut Control::default(),
    )?;
    assert_eq!(first.page_digest(), repeated.page_digest());
    assert_eq!(first.follow.delta, repeated.follow.delta);
    let mut since = start;
    for expected in 1..=3 {
        let mut control = Control::default();
        let step = follow_replay_step(
            &later_history,
            &since,
            &horizon,
            &request(64)?,
            &mut control,
        )?;
        assert_eq!(step.axis, ReplayAxis::Ledger);
        assert_eq!(step.result_anchor.position().commit_sequence, expected);
        assert_eq!(step.horizon_reached, expected == 3);
        assert_eq!(step.follow.basis.anchor_token, since.as_str());
        assert_eq!(step.follow.result.anchor_token, step.result_anchor.as_str());
        assert_eq!(
            control.boundaries,
            vec![
                ReplayBoundary::BasisSnapshot,
                ReplayBoundary::ResultSnapshot,
                ReplayBoundary::Project,
                ReplayBoundary::Deliver
            ]
        );
        let binding = control.binding.ok_or("control binding missing")?;
        assert_eq!(binding.since(), &since);
        assert_eq!(binding.horizon(), &horizon);
        assert_eq!(binding.read_limits(), OrientLimits::default());
        assert!(binding.objects_root().starts_with(&fixture.root));
        since = step.result_anchor;
    }
    assert_eq!(since, horizon);
    assert_ne!(since, fixture.token()?);
    Ok(())
}

#[test]
fn intermediate_effect_uncertainty_survives_a_later_verified_outcome() -> TestResult {
    let mut fixture = Fixture::new("effects")?;
    fixture.append()?;
    let start = fixture.token()?;
    let operation = fixture.prepare("uncertain")?;
    let witness = ContentDigest::sha256(b"explicit synthetic terminal observation");
    let terminal_receipt;
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
            "fixture lost acknowledgement",
        )?;
        deployment.effects_mut().transition(
            &operation,
            EffectState::Observed,
            TimestampNs(103),
            Some(witness),
            None,
        )?;
        terminal_receipt = deployment
            .effects_mut()
            .reconcile_verified(&operation, witness, TimestampNs(104))?
            .receipt_digest();
    }
    let horizon = fixture.token()?;
    let history = fixture.history()?;
    let endpoint = follow_deployment(&history, &start, &request(64)?)?;
    assert!(endpoint.result.indeterminate_effects.is_empty());
    let mut since = start;
    let mut uncertainty_seen = false;
    let mut uncertainty_closed = false;
    let mut count = 0;
    while since != horizon {
        count += 1;
        assert!(
            count <= 6,
            "one creation plus five effect records are the finite range"
        );
        let step = follow_replay_step(
            &history,
            &since,
            &horizon,
            &request(64)?,
            &mut Control::default(),
        )?;
        assert_eq!(step.axis, ReplayAxis::Effects);
        assert_eq!(
            step.result_anchor.position().commit_sequence,
            since.position().commit_sequence
        );
        if step
            .follow
            .result
            .indeterminate_effects
            .contains(&operation)
        {
            uncertainty_seen = true;
            assert!(
                step.follow
                    .delta
                    .classes
                    .contains(&MeaningfulDeltaClass::EffectUncertainty)
            );
            assert!(!step.follow.delta.effect_uncertainty_changes.is_empty());
        }
        if uncertainty_seen && step.follow.result.indeterminate_effects.is_empty() {
            uncertainty_closed = true;
        }
        if step.horizon_reached {
            assert!(step.follow.result.open_obligations.is_empty());
            let terminal = step
                .follow
                .result
                .capsule()
                .frame
                .knowledge_cells
                .iter()
                .find(|cell| cell.claim_id() == format!("claim:effect:{operation}:local-state"))
                .ok_or("terminal effect claim omitted")?;
            assert_eq!(terminal.knowledge_state(), KnowledgeState::Known);
            assert!(terminal.evidence_digests().contains(&terminal_receipt));
            assert!(step.follow.result.proof_roots().contains(&terminal_receipt));
        }
        // The existing classifier's stronger lineage proof bar is not weakened by replay.
        assert!(
            !step
                .follow
                .delta
                .classes
                .contains(&MeaningfulDeltaClass::TerminalTransition)
        );
        assert!(step.follow.page.next_cursor.is_none());
        since = step.result_anchor;
    }
    assert!(
        uncertainty_seen,
        "endpoint-only comparison must not hide the intermediate lost ACK"
    );
    assert!(
        uncertainty_closed,
        "the subsequent verified observation remains a separate transition"
    );
    Ok(())
}

#[test]
fn simultaneous_journal_advances_and_rewinds_refuse_before_hydration() -> TestResult {
    let mut fixture = Fixture::new("ambiguous")?;
    let start = fixture.token()?;
    fixture.append()?;
    fixture.prepare("parallel")?;
    let horizon = fixture.token()?;
    let history = fixture.history()?;
    let mut control = Control::default();
    assert!(matches!(
        follow_replay_step(&history, &start, &horizon, &request(64)?, &mut control),
        Err(ReplayError::AmbiguousOrder)
    ));
    assert!(control.boundaries.is_empty());
    assert!(matches!(
        follow_replay_step(&history, &horizon, &start, &request(64)?, &mut control),
        Err(ReplayError::ReversedRange)
    ));
    assert!(control.boundaries.is_empty());
    Ok(())
}

#[test]
fn exact_item_continuations_do_not_advance_or_skip_the_transition() -> TestResult {
    let mut fixture = Fixture::new("pages")?;
    let since = fixture.token()?;
    fixture.append()?;
    fixture.append()?;
    let horizon = fixture.token()?;
    let history = fixture.history()?;
    let whole = follow_replay_step(
        &history,
        &since,
        &horizon,
        &request(64)?,
        &mut Control::default(),
    )?;
    assert!(
        whole.follow.items.len() > 1,
        "fixture needs several protected/changed items"
    );
    let mut paged_request = request(1)?;
    let mut seen = Vec::new();
    let mut page_digests = std::collections::BTreeSet::new();
    loop {
        let step = follow_replay_step(
            &history,
            &since,
            &horizon,
            &paged_request,
            &mut Control::default(),
        )?;
        assert_eq!(step.result_anchor, whole.result_anchor);
        assert!(page_digests.insert(step.page_digest().to_text()));
        seen.extend(step.follow.page_items.iter().map(|item| item.digest()));
        match step.follow.page.next_cursor {
            Some(next) => paged_request.continuation = Some(next.token().to_owned()),
            None => break,
        }
    }
    assert_eq!(
        seen,
        whole
            .follow
            .items
            .iter()
            .map(|item| item.digest())
            .collect::<Vec<_>>()
    );
    let mut wrong = request(2)?;
    wrong.continuation = paged_request.continuation;
    assert!(matches!(
        follow_replay_step(&history, &since, &horizon, &wrong, &mut Control::default()),
        Err(ReplayError::Follow(FollowError::Continuation(_)))
    ));
    Ok(())
}

#[test]
fn every_owned_boundary_can_cancel_without_releasing_or_advancing_a_page() -> TestResult {
    let mut fixture = Fixture::new("cancel")?;
    let since = fixture.token()?;
    fixture.append()?;
    let horizon = fixture.token()?;
    let history = fixture.history()?;
    for (index, boundary) in [
        ReplayBoundary::BasisSnapshot,
        ReplayBoundary::ResultSnapshot,
        ReplayBoundary::Project,
        ReplayBoundary::Deliver,
    ]
    .into_iter()
    .enumerate()
    {
        let mut control = Control {
            deny_at: Some(boundary),
            ..Control::default()
        };
        assert!(matches!(
            follow_replay_step(&history, &since, &horizon, &request(64)?, &mut control),
            Err(ReplayError::Denied(ReplayDenial::Cancelled))
        ));
        assert_eq!(control.boundaries.len(), index + 1);
        assert_eq!(control.boundaries.last(), Some(&boundary));
    }
    assert_eq!(fixture.token()?, horizon);
    assert!(
        !fixture.root.join("agent").exists(),
        "replay owns no session writes"
    );
    Ok(())
}

#[test]
fn full_token_request_and_horizon_identities_are_revalidated() -> TestResult {
    let mut fixture = Fixture::new("identity")?;
    let since = fixture.token()?;
    fixture.append()?;
    let horizon = fixture.token()?;
    fixture.append()?;
    let later = fixture.token()?;
    let history = fixture.history()?;
    let original = follow_replay_step(
        &history,
        &since,
        &horizon,
        &request(64)?,
        &mut Control::default(),
    )?;
    let wider = follow_replay_step(
        &history,
        &since,
        &later,
        &request(64)?,
        &mut Control::default(),
    )?;
    assert_eq!(original.result_anchor, wider.result_anchor);
    assert_ne!(original.page_digest(), wider.page_digest());
    let mut other = request(64)?;
    other.principal = PrincipalId::parse("principal:follow-replay-other")?;
    let other_page =
        follow_replay_step(&history, &since, &horizon, &other, &mut Control::default())?;
    assert_ne!(original.page_digest(), other_page.page_digest());
    let mut tampered = horizon.as_str().to_owned();
    let last = tampered.pop().ok_or("token empty")?;
    tampered.push(if last == '0' { '1' } else { '0' });
    let tampered = AnchorToken::parse(&tampered).ok_or("canonical tamper parses")?;
    let mut control = Control::default();
    assert!(matches!(
        follow_replay_step(&history, &since, &tampered, &request(64)?, &mut control),
        Err(ReplayError::Follow(FollowError::Anchor(_)))
    ));
    assert!(control.boundaries.is_empty());
    let mut invalid = request(64)?;
    invalid.max_entries = 0;
    assert!(matches!(
        follow_replay_step(&history, &since, &horizon, &invalid, &mut control),
        Err(ReplayError::InvalidBounds)
    ));
    assert!(control.boundaries.is_empty());
    Ok(())
}

#[test]
fn caught_up_replay_preserves_existing_protected_gaps_and_silence_rules() -> TestResult {
    let fixture = Fixture::new("caught-up")?;
    let horizon = fixture.token()?;
    let history = fixture.history()?;
    let step = follow_replay_step(
        &history,
        &horizon,
        &horizon,
        &request(64)?,
        &mut Control::default(),
    )?;
    assert_eq!(step.axis, ReplayAxis::CaughtUp);
    assert_eq!(step.since, step.result_anchor);
    assert!(step.horizon_reached);
    assert!(
        step.follow
            .delta
            .classes
            .contains(&MeaningfulDeltaClass::CoverageLoss)
    );
    assert!(step.follow.delta.silence_certificate.is_none());
    Ok(())
}

fn session_binding() -> TestResult<OrientSessionBinding> {
    Ok(OrientSessionBinding {
        session_id: SessionId::parse("session:follow-replay:durable")?,
        mission_id: MissionId::parse("mission:follow-replay:durable")?,
        mission: None,
        mission_progress: None,
        cases: Vec::new(),
        plans: Vec::new(),
        claims: Vec::new(),
        findings: Vec::new(),
        supervisions: None,
        trauma_warnings: None,
        captured_learning: None,
    })
}

#[test]
fn durable_identity_is_bound_before_native_effect_sealing_and_classification() -> TestResult {
    let mut fixture = Fixture::new("session-identity")?;
    fixture.append()?;
    fixture.prepare("bound")?;
    let since = fixture.token()?;
    fixture.append()?;
    let horizon = fixture.token()?;
    let history = fixture.history()?;
    let binding = session_binding()?;
    let mut control = Control::default();
    let bound = follow_replay_step_for(
        &history,
        &since,
        &horizon,
        &request(64)?,
        Some(&binding),
        &mut control,
    )?;
    for orientation in [&bound.follow.basis, &bound.follow.result] {
        assert_eq!(orientation.capsule().session_id, binding.session_id);
        assert_eq!(orientation.capsule().mission_id, binding.mission_id);
        assert!(orientation.publication.situation.is_sealed());
        orientation.publication.verify()?;
    }
    assert_eq!(bound.follow.delta.session_id, binding.session_id);
    assert_eq!(bound.follow.stream.session_id, binding.session_id);
    assert_eq!(
        control.binding.as_ref().and_then(ReplayBinding::session),
        Some(&binding)
    );
    let unbound = follow_replay_step(
        &history,
        &since,
        &horizon,
        &request(64)?,
        &mut Control::default(),
    )?;
    let explicit_none = follow_replay_step_for(
        &history,
        &since,
        &horizon,
        &request(64)?,
        None,
        &mut Control::default(),
    )?;
    assert_eq!(unbound, explicit_none);
    assert_ne!(bound.page_digest(), unbound.page_digest());
    Ok(())
}

#[test]
fn unsupported_mission_facets_refuse_instead_of_disappearing_from_replay() -> TestResult {
    let fixture = Fixture::new("session-facets")?;
    let token = fixture.token()?;
    let history = fixture.history()?;
    for kind in 0..6 {
        let mut binding = session_binding()?;
        match kind {
            0 => binding.cases.push(OrientCaseBrief {
                case_id: "case:replay:active".to_owned(),
                state: "active".to_owned(),
                revision: 1,
                live_hypotheses: vec!["hypothesis:must-not-disappear".to_owned()],
                rebase_required: true,
            }),
            1 => binding.plans.push(OrientPlanBrief {
                plan_id: "plan:replay:active".to_owned(),
                operation_id: "operation:replay:pending".to_owned(),
                state: Some("indeterminate".to_owned()),
            }),
            2 => binding.claims.push(OrientClaimBrief {
                claim_id: "claim:replay:active".to_owned(),
                case_id: "case:replay:active".to_owned(),
                state: "claimed".to_owned(),
                owner_session: binding.session_id.as_str().to_owned(),
                expires_at: TimestampNs(100),
                lease_live: true,
                held_here: true,
            }),
            3 => binding.findings.push(OrientFindingBrief {
                finding_id: "finding:replay:active".to_owned(),
                case_id: "case:replay:active".to_owned(),
                disputed_by: vec!["finding:replay:contradicting".to_owned()],
            }),
            4 => {
                // Current advisory state has no historical session replay witness. Refuse
                // before reading either snapshot, rather than applying it to both endpoints.
                binding.trauma_warnings = Some(vec![
                    fss_reference::deployment_session::trauma_guard::AntiPatternWarning {
                        warning_id: "trauma-guard:replay:current".to_owned(),
                        target_json: "{\"id\":\"event:replay\",\"kind\":\"event\"}".to_owned(),
                        cause_class: fss_core::AttributionCauseClass::Execution,
                        negative_count: 2,
                        half_life_ns: 86_400_000_000_000,
                        decay_weight_ppm: 2_000_000,
                        cited_record_ids: vec![
                            "feedback:one".to_owned(),
                            "feedback:two".to_owned(),
                        ],
                        cited_evidence_digests: vec![ContentDigest::sha256(b"historical feedback")],
                        active_policy_mutation: false,
                    },
                ]);
            }
            _ => {
                // Captures may arrive without an evidence/effect advance. The two-axis cursor
                // cannot prove when they existed, even when its evidence endpoints are equal.
                let root = ContentDigest::sha256(b"retained learning");
                binding.captured_learning =
                    Some(vec![fss_reference::agent_orient::OrientLearningBrief {
                        experience_id: "experience:replay:current".to_owned(),
                        proposal_id: "learning:replay:current".to_owned(),
                        source_episode_id: "episode:replay:terminal".to_owned(),
                        class: fss_core::LearningClass::PolicyReviewCandidate,
                        publication_root: root,
                        experience_digest: root,
                        proposal_digest: root,
                        episode_root: root,
                        feedback_root: root,
                        plan_root: root,
                        review_after: TimestampNs(10),
                        expires_at: TimestampNs(20),
                        review_due: false,
                        expired: false,
                        missing_evidence: vec!["Efficacy remains unvalidated.".to_owned()],
                    }]);
            }
        }
        let mut control = Control::default();
        assert!(matches!(
            follow_replay_step_for(
                &history,
                &token,
                &token,
                &request(64)?,
                Some(&binding),
                &mut control
            ),
            Err(ReplayError::UnsupportedSessionFacets)
        ));
        assert!(control.boundaries.is_empty());
    }
    Ok(())
}
