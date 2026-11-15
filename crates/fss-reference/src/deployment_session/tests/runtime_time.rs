#![forbid(unsafe_code)]
//! Runtime authority drives durable admission while the evidence position stays quiet.

use std::cell::Cell;

use super::*;
use crate::agent_session::SessionRefresh;
use crate::agent_session::checkpoint::journal::{
    DurableSessionLimits, RetainedSessionState, inspect_session_bytes,
};
use crate::agent_session::work_claims::WorkClaimLimits;
use crate::deployment_session::{
    SessionContext, SessionJournal, SessionTimeAuthority, SessionTimeError,
    orient::{OrientSessionRequest, orient_session},
};

const START: i128 = 1_800_000_000_000_000_000;

struct Clock {
    root: PathBuf,
    now: Cell<Result<TimestampNs, SessionTimeError>>,
}

impl Clock {
    fn new(root: &Path, now: i128) -> Self {
        Self {
            root: root.to_owned(),
            now: Cell::new(Ok(TimestampNs(now))),
        }
    }

    fn context(&self) -> SessionContext<'_> {
        SessionContext::runtime(&self.root, self)
    }

    fn set(&self, now: i128) {
        self.now.set(Ok(TimestampNs(now)));
    }
}

impl SessionTimeAuthority for Clock {
    fn observe(&self, root: &Path, actor: &PrincipalId) -> Result<TimestampNs, SessionTimeError> {
        if root != self.root || actor.as_str() != "principal:session-unit" {
            return Err(SessionTimeError::Denied);
        }
        self.now.get()
    }
}

fn retained(root: &Path) -> TestResult<RetainedSessionState> {
    let state = inspect_session_bytes(
        &journal_bytes(root)?,
        DurableSessionLimits::default(),
        WorkClaimLimits::default(),
    )?;
    assert_eq!(state.sessions.len(), 1);
    Ok(state.sessions[0].clone())
}

fn orient_request(session: &fss_core::SessionId) -> TestResult<OrientSessionRequest> {
    Ok(OrientSessionRequest {
        session_id: session.clone(),
        principal: principal()?,
        view: AgentView::Brief,
        budget_tokens: None,
    })
}

#[test]
fn quiet_runtime_session_expires_at_its_exact_boundary_and_cold_reopen_cannot_revive_it()
-> TestResult {
    let fixture = Fixture::new("runtime-quiet-expiry", SITE)?;
    let authority = fixture.authority_digests()?;
    let clock = Clock::new(&fixture.root, START);
    let opened = open_session(clock.context(), &open_request()?)?;
    assert_eq!(opened.session.created_at_ns, START);
    let request = orient_request(&opened.session.session_id)?;
    clock.set(opened.session.expires_at_ns - 1);
    let oriented = orient_session(clock.context(), &request)?;
    assert_eq!(oriented.revision, opened.revision);
    assert_eq!(
        oriented.orientation.anchor_token,
        opened.orientation.anchor_token
    );
    assert_eq!(
        retained(&fixture.root)?.last_observed_at.0,
        opened.session.expires_at_ns - 1
    );

    clock.set(opened.session.expires_at_ns);
    assert!(matches!(
        orient_session(clock.context(), &request),
        Err(DeploymentSessionError::SessionUnknown)
    ));
    let expired = retained(&fixture.root)?;
    assert!(expired.closed);
    assert_eq!(expired.last_observed_at.0, opened.session.expires_at_ns);
    let cold_clock = Clock::new(&fixture.root, START + 1);
    assert!(matches!(
        open_session(cold_clock.context(), &open_request()?),
        Err(DeploymentSessionError::SessionUnknown)
    ));
    assert_eq!(retained(&fixture.root)?, expired);
    assert_eq!(fixture.authority_digests()?, authority);
    Ok(())
}

#[test]
fn refusal_after_live_admission_preserves_the_watermark_across_a_cold_owner() -> TestResult {
    let fixture = Fixture::new("runtime-denied-watermark", SITE)?;
    let clock = Clock::new(&fixture.root, START);
    let opened = open_session(clock.context(), &open_request()?)?;
    let mut capabilities = opened.session.capabilities.clone();
    assert!(capabilities.remove("CAP-AGENT-SITUATION-READ-001"));
    let mut journal = SessionJournal::open(&fixture.root)?;
    journal.store.refresh(
        &principal()?,
        &opened.session.session_id,
        SessionRefresh {
            expected_session_digest: opened.session.session_digest(),
            current_anchor: opened.session.current_anchor.clone(),
            capabilities,
            privacy_scope: opened.session.privacy_scope.clone(),
        },
        TimestampNs(START),
    )?;
    journal.commit_pin()?;
    drop(journal);

    clock.set(START + 10_000);
    let request = orient_request(&opened.session.session_id)?;
    assert!(matches!(
        orient_session(clock.context(), &request),
        Err(DeploymentSessionError::SessionStale(_))
    ));
    let admitted = retained(&fixture.root)?;
    assert_eq!(admitted.last_observed_at, TimestampNs(START + 10_000));
    assert!(!admitted.closed);
    let cold_clock = Clock::new(&fixture.root, START + 9_999);
    assert!(matches!(
        orient_session(cold_clock.context(), &request),
        Err(DeploymentSessionError::SessionStale(_))
    ));
    assert_eq!(retained(&fixture.root)?, admitted);
    Ok(())
}

#[test]
fn later_open_retries_retain_the_original_lease_workspace_mission_and_narrowed_grants() -> TestResult
{
    let fixture = Fixture::new("runtime-opening-retry", SITE)?;
    let clock = Clock::new(&fixture.root, START);
    let request = open_request()?;
    let opened = open_session(clock.context(), &request)?;
    let mut capabilities = opened.session.capabilities.clone();
    assert!(capabilities.remove("CAP-AGENT-FEEDBACK-001"));
    let mut journal = SessionJournal::open(&fixture.root)?;
    let narrowed = journal.store.refresh(
        &principal()?,
        &opened.session.session_id,
        SessionRefresh {
            expected_session_digest: opened.session.session_digest(),
            current_anchor: opened.session.current_anchor.clone(),
            capabilities,
            privacy_scope: opened.session.privacy_scope.clone(),
        },
        TimestampNs(START),
    )?;
    journal.commit_pin()?;
    drop(journal);
    let before = retained(&fixture.root)?;
    clock.set(START + 50_000);
    let retry = open_session(clock.context(), &request)?;
    assert_eq!(retry.session, narrowed);
    assert_eq!(retry.mission, opened.mission);
    assert_eq!(retry.mission_root, opened.mission_root);
    assert_eq!(retry.revision, opened.revision);
    assert_eq!(retry.session.created_at_ns, START);
    assert_eq!(retry.session.expires_at_ns, opened.session.expires_at_ns);
    let after = retained(&fixture.root)?;
    assert_eq!(after.opening_digest, before.opening_digest);
    assert_eq!(after.spent_tokens, before.spent_tokens);
    assert_eq!(after.last_observed_at, TimestampNs(START + 50_000));
    relative_opening_retries_keep_deadlines_and_progress()?;
    Ok(())
}

fn relative_opening_retries_keep_deadlines_and_progress() -> TestResult {
    use crate::agent_session::checkpoint::journal::coordination::investigations::{
        InvestigationChange, InvestigationError,
    };
    use crate::deployment_session::claims::{
        ClaimAction, ClaimChange, ClaimRequest, ClaimWork, work_claim,
    };
    use crate::deployment_session::feedback::{FeedbackRequest, FeedbackTarget, publish_feedback};
    use crate::deployment_session::investigation::{
        CaseAction, CaseDeadline, CaseDraft, InvestigateRequest, investigate,
    };

    let fixture = Fixture::new("runtime-relative-openings", SITE)?;
    let clock = Clock::new(&fixture.root, START);
    let mut request = open_request()?;
    request.token_budget = 64_000;
    let opened = open_session(clock.context(), &request)?;
    let session = &opened.session.session_id;

    let mut draft = CaseDraft {
        case_id: "case:runtime-retry".into(),
        question: "Which explanation fits the retained observation?".into(),
        decision_informed: "Whether another observation is needed".into(),
        hypotheses: ["first", "alternative"]
            .into_iter()
            .map(|id| fss_core::CaseHypothesis {
                hypothesis_id: format!("hypothesis:{id}"),
                description: format!("Consider {id}"),
                epistemic_state: fss_core::KnowledgeState::Unknown,
                predictions: vec![
                    "An independent observation distinguishes the alternatives".into(),
                ],
                evidence: Vec::new(),
                contradictions: Vec::new(),
            })
            .collect(),
        knowns: Vec::new(),
        unknowns: Vec::new(),
        discriminators: Vec::new(),
        probes: Vec::new(),
        stop_rules: vec!["Preserve uncertainty".into()],
        deadline: CaseDeadline::After(60_000_000_000),
    };
    let open = |draft: &CaseDraft| InvestigateRequest {
        session_id: session.clone(),
        principal: principal().expect("constant test principal"),
        action: CaseAction::Open(Box::new(draft.clone())),
    };
    clock.set(START + 60_000);
    let first = investigate(clock.context(), &open(&draft))?
        .revision
        .ok_or("first case revision")?;
    clock.set(START + 70_000);
    let active = investigate(
        clock.context(),
        &InvestigateRequest {
            session_id: session.clone(),
            principal: principal()?,
            action: CaseAction::Change {
                case_id: draft.case_id.clone(),
                expected: first.digest(),
                change: InvestigationChange::Activate,
            },
        },
    )?
    .revision
    .ok_or("active case revision")?;
    clock.set(START + 80_000);
    assert_eq!(
        investigate(clock.context(), &open(&draft))?.revision,
        Some(active.clone())
    );
    assert_eq!(
        active.record().decision_deadline_ns,
        START + 60_000 + 60_000_000_000
    );
    draft.deadline = CaseDeadline::After(60_000_000_001);
    assert!(matches!(
        investigate(clock.context(), &open(&draft)),
        Err(DeploymentSessionError::CaseRefused(
            InvestigationError::Conflict
        ))
    ));

    let acquire = |lease_ms| ClaimRequest {
        session_id: session.clone(),
        principal: principal().expect("constant test principal"),
        action: ClaimAction::Acquire {
            case_id: draft.case_id.clone(),
            work: ClaimWork::Case,
            lease_ms,
            dependencies: std::collections::BTreeSet::new(),
        },
    };
    clock.set(START + 100_000);
    let first = work_claim(clock.context(), &acquire(300_000))?
        .claim
        .ok_or("first claim revision")?;
    clock.set(START + 200_000);
    let active = work_claim(
        clock.context(),
        &ClaimRequest {
            session_id: session.clone(),
            principal: principal()?,
            action: ClaimAction::Change {
                claim_id: first.claim().claim_id.clone(),
                expected: first.digest(),
                change: ClaimChange::Activate,
            },
        },
    )?
    .claim
    .ok_or("active claim revision")?;
    clock.set(START + 300_000);
    assert_eq!(
        work_claim(clock.context(), &acquire(300_000))?.claim,
        Some(active.clone())
    );
    assert_eq!(active.claim().expires_at_ns, first.claim().expires_at_ns);
    assert!(matches!(
        work_claim(clock.context(), &acquire(299_999)),
        Err(DeploymentSessionError::ClaimRefused(
            crate::agent_session::work_claims::WorkClaimError::Conflict
        ))
    ));

    let mut feedback = FeedbackRequest {
        session_id: session.clone(),
        principal: principal()?,
        target: FeedbackTarget::Case(draft.case_id.clone()),
        kind: fss_core::FeedbackProposalKind::Correction,
        statement: "Keep the competing explanation open for review".into(),
        supporting: vec![ContentDigest::sha256(b"runtime feedback supporting handle")],
        contradicting: Vec::new(),
        disposition: fss_core::RequestedDisposition::OpenCase,
    };
    clock.set(START + 400_000);
    let first = publish_feedback(clock.context(), &feedback)?;
    assert_eq!(first.proposal.created_at_ns, START + 400_000);
    assert!(first.case_refusal.is_none(), "{:?}", first.case_refusal);
    let first_case = first.case.ok_or("feedback review case")?;
    assert_eq!(
        first_case.opening.decision_deadline_ns,
        START + 400_000 + crate::deployment_session::feedback::case::CASE_REVIEW_LIFETIME_NS
    );
    clock.set(START + 500_000);
    let retry = publish_feedback(clock.context(), &feedback)?;
    assert_eq!(retry.proposal, first.proposal);
    assert_eq!(retry.root, first.root);
    assert!(retry.case_refusal.is_none(), "{:?}", retry.case_refusal);
    let retry_case = retry.case.ok_or("retained feedback case")?;
    assert_eq!(retry_case.opening, first_case.opening);
    assert_eq!(retry_case.revision, first_case.revision);
    let state = inspect_session_bytes(
        &journal_bytes(&fixture.root)?,
        DurableSessionLimits::default(),
        WorkClaimLimits::default(),
    )?;
    assert_eq!(
        state.cases.len(),
        2,
        "feedback retry must not create another case"
    );
    feedback
        .statement
        .push_str(" after another independent review");
    let changed = publish_feedback(clock.context(), &feedback)?;
    assert_ne!(changed.root, first.root);
    assert_eq!(changed.proposal.created_at_ns, START + 500_000);
    Ok(())
}

#[test]
fn cold_interrupted_open_completes_under_later_runtime_time_without_renewing_the_lease()
-> TestResult {
    let fixture = Fixture::new("runtime-interrupted-opening", SITE)?;
    let clock = Clock::new(&fixture.root, START);
    let request = open_request()?;
    let original = open_session(clock.context(), &request)?;
    super::opening_retry::interrupt_before_first_workspace(&fixture.root)?;
    let cold_clock = Clock::new(&fixture.root, START + 1_000);
    let recovered = open_session(cold_clock.context(), &request)?;
    assert_eq!(recovered.session, original.session);
    assert_eq!(recovered.mission, original.mission);
    assert_eq!(recovered.mission_root, original.mission_root);
    assert_eq!(recovered.revision, original.revision);
    assert_eq!(
        retained(&fixture.root)?.last_observed_at,
        TimestampNs(START + 1_000)
    );
    Ok(())
}

#[test]
fn explicit_clock_refusal_or_invalid_time_never_falls_back_to_evidence() -> TestResult {
    for (tag, result, expected) in [
        (
            "denied",
            Err(SessionTimeError::Denied),
            SessionTimeError::Denied,
        ),
        (
            "cancelled",
            Err(SessionTimeError::Cancelled),
            SessionTimeError::Cancelled,
        ),
        (
            "uncertain",
            Err(SessionTimeError::Uncertain),
            SessionTimeError::Uncertain,
        ),
        ("negative", Ok(TimestampNs(-1)), SessionTimeError::Uncertain),
    ] {
        let fixture = Fixture::new(&format!("runtime-clock-{tag}"), SITE)?;
        let clock = Clock::new(&fixture.root, START);
        clock.now.set(result);
        assert!(
            matches!(open_session(clock.context(), &open_request()?), Err(DeploymentSessionError::Time(error)) if error == expected)
        );
        assert!(!fixture.root.join(SESSIONS_RELPATH).exists());
        assert!(!fixture.root.join(PUBLICATIONS_RELPATH).exists());
    }
    Ok(())
}

#[test]
fn runtime_handoff_requires_fresh_publication_admission_and_resume_expires_source_session()
-> TestResult {
    let fixture = Fixture::new("runtime-handoff", SITE)?;
    let clock = Clock::new(&fixture.root, START);
    let opened = open_session(clock.context(), &open_request()?)?;
    let request = handoff_request(&opened.session.session_id, "runtime handoff")?;
    let prepared = prepare_handoff(clock.context(), &request)?;
    assert!(matches!(
        prepared.publish(&[]),
        Err(DeploymentSessionError::Time(SessionTimeError::Denied))
    ));
    let prepared = prepare_handoff(clock.context(), &request)?;
    clock.set(START + 1_000);
    let published = prepared.publish_with_time(&[], &clock)?;
    let resumed = resume_session(
        clock.context(),
        &resume_request(&published.record.capsule.handoff_id)?,
    )?;
    assert_eq!(resumed.session.created_at_ns, START);
    assert_eq!(resumed.session.expires_at_ns, opened.session.expires_at_ns);
    clock.set(opened.session.expires_at_ns);
    assert!(matches!(
        resume_session(
            clock.context(),
            &resume_request(&published.record.capsule.handoff_id)?
        ),
        Err(DeploymentSessionError::HandoffInvalid(_))
    ));
    assert!(retained(&fixture.root)?.closed);
    Ok(())
}

#[test]
fn a_prepared_handoff_cannot_be_published_after_its_session_expires() -> TestResult {
    let fixture = Fixture::new("runtime-prepared-expiry", SITE)?;
    let clock = Clock::new(&fixture.root, START);
    let opened = open_session(clock.context(), &open_request()?)?;
    let prepared = prepare_handoff(
        clock.context(),
        &handoff_request(&opened.session.session_id, "delay")?,
    )?;
    let slot = HandoffRecord::slot(&prepared.record.capsule.handoff_id)?;
    clock.set(opened.session.expires_at_ns);
    assert!(matches!(
        prepared.publish_with_time(&[], &clock),
        Err(DeploymentSessionError::SessionUnknown)
    ));
    assert!(crate::deployment_session::read_published(&fixture.root, &slot)?.is_none());
    assert!(retained(&fixture.root)?.closed);
    Ok(())
}

fn cancellation_authority() -> TestResult<ContextAuthority> {
    Ok(ContextAuthority::new_root(RootAuthoritySpec {
        trace_id: "trace:runtime-session-cancel".into(),
        operation_id: OperationId::parse("operation:runtime-session-cancel")?,
        principal: principal()?.as_str().to_owned(),
        capabilities: vec![crate::deployment_session::cancellation::CAP_SESSION_CANCEL.into()],
        deadline: None,
        priority: 10,
        budgets: BudgetVector::default(),
        privacy_scope: "privacy:local-authorized-files".into(),
        retention_scope: "retention:existing-deployment-policy".into(),
        anchor_universe: ContentDigest::sha256(SITE.as_bytes()),
        generation: 1,
    })?)
}

#[test]
fn live_cancellation_approval_survives_elapsed_time_but_cannot_extend_expiry() -> TestResult {
    use crate::deployment_session::cancellation::{
        SessionCancellationError, SessionCancellationOutcome, cancel_session,
    };
    for expires in [false, true] {
        let fixture = Fixture::new(
            if expires {
                "runtime-cancel-expiry"
            } else {
                "runtime-cancel-later"
            },
            SITE,
        )?;
        let clock = Clock::new(&fixture.root, START);
        let opened = open_session(clock.context(), &open_request()?)?;
        let authority = cancellation_authority()?;
        clock.set(START + 1_000);
        let preview = cancel_session(
            clock.context(),
            &opened.session.session_id,
            &authority,
            None,
        )?;
        assert_eq!(preview.outcome, SessionCancellationOutcome::Proposed);
        assert_eq!(preview.plan.observed_at, TimestampNs(START + 1_000));
        let approval = preview.plan.approval_digest()?;
        clock.set(if expires {
            opened.session.expires_at_ns
        } else {
            START + 2_000
        });
        let outcome = cancel_session(
            clock.context(),
            &opened.session.session_id,
            &authority,
            Some(approval),
        );
        if expires {
            assert!(matches!(
                outcome,
                Err(SessionCancellationError::Session(
                    DeploymentSessionError::SessionUnknown
                ))
            ));
            let expired = retained(&fixture.root)?;
            assert!(expired.closed);
            assert_eq!(expired.last_observed_at.0, opened.session.expires_at_ns);
        } else {
            let cancelled = outcome?;
            assert_eq!(cancelled.outcome, SessionCancellationOutcome::Cancelled);
            assert_eq!(cancelled.plan, preview.plan);
            assert!(retained(&fixture.root)?.closed);
            let cold_clock = Clock::new(&fixture.root, START + 3_000);
            let retry = cancel_session(
                cold_clock.context(),
                &opened.session.session_id,
                &authority,
                Some(approval),
            )?;
            assert_eq!(retry.outcome, SessionCancellationOutcome::AlreadyCancelled);
            assert_eq!(retry.receipt, cancelled.receipt);
        }
    }
    Ok(())
}
