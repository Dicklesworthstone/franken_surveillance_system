#![forbid(unsafe_code)]
//! Runtime time advances on a quiet deployment without changing native evidence custody.

use std::cell::Cell;

use super::*;
use fss_core::{CaseHypothesis, KnowledgeState, TimestampNs};
use fss_reference::agent_session::checkpoint::journal::coordination::investigations::{
    InvestigationChange, InvestigationError, ProbeCitationTarget,
};
use fss_reference::deployment_session::investigation::{
    CaseAction, CaseDeadline, CaseDraft, InvestigateRequest, investigate,
};
use fss_reference::deployment_session::probe::case::{
    charge_linked_probe_delivery, commit_probe_case, preflight_probe_case,
};
use fss_reference::deployment_session::probe::{
    ProbeRequest, admit_probe, admit_probe_continuation,
};
use fss_reference::deployment_session::supervision::supervise_existing_session_at;
use fss_reference::deployment_session::{
    DeploymentSessionError, SESSION_LEASE_NS, SessionContext, SessionTimeAuthority,
    SessionTimeError,
};

const START: i128 = 1_700_000_000_000_000_000;

struct Clock {
    now: Cell<i128>,
    next: Cell<Option<i128>>,
}

impl Clock {
    fn at(now: i128) -> Self {
        Self {
            now: Cell::new(now),
            next: Cell::new(None),
        }
    }
}

impl SessionTimeAuthority for Clock {
    fn observe(&self, _: &Path, _: &PrincipalId) -> Result<TimestampNs, SessionTimeError> {
        let now = self.now.get();
        if let Some(next) = self.next.take() {
            self.now.set(next);
        }
        Ok(TimestampNs(now))
    }
}

fn runtime_fixture(tag: &str, clock: &Clock) -> TestResult<Fixture> {
    let mut fixture = Fixture::new(tag)?;
    fixture
        .request
        .objective
        .push_str(" under the explicit runtime clock");
    fixture.opened = open_session(
        SessionContext::runtime(&fixture.root, clock),
        &fixture.request,
    )?;
    fixture.registration.session_id = fixture.opened.session.session_id.clone();
    assert_eq!(fixture.opened.session.created_at_ns, START);
    assert_eq!(
        fixture.opened.session.expires_at_ns,
        START + SESSION_LEASE_NS
    );
    Ok(fixture)
}

fn action(
    fixture: &Fixture,
    clock: &Clock,
    action: SupervisionAction,
) -> Result<SupervisionSessionDelivery, Box<SupervisionSessionFailure>> {
    let request = SupervisionSessionRequest {
        registration: fixture.registration.clone(),
        expected_authority_root: fixture.opened.session.current_anchor.state_root,
        action,
    };
    supervise_session(
        SessionContext::runtime(&fixture.root, clock),
        &fixture.opened.session.principal_id,
        &request,
        &OrientLimits::default(),
        &mut SyntheticEvaluator {
            root: &fixture.root,
            source: &fixture.source,
            principal: &fixture.opened.session.principal_id,
            registration: &fixture.registration,
        },
    )
}

fn retained_session(
    fixture: &Fixture,
) -> TestResult<fss_reference::agent_session::checkpoint::journal::RetainedSessionState> {
    let recovered = inspect_session_bytes(
        &fs::read(fixture.root.join("agent/sessions/journal.fssj"))?,
        DurableSessionLimits::default(),
        WorkClaimLimits::default(),
    )?;
    assert_eq!(
        fs::read_to_string(fixture.root.join("agent/sessions/ROOT"))?.trim(),
        recovered.inspection.root.to_text(),
    );
    recovered
        .sessions
        .into_iter()
        .find(|entry| entry.session.session_id == fixture.opened.session.session_id)
        .ok_or_else(|| "retained runtime session missing".into())
}

fn probe(fixture: &Fixture) -> ProbeRequest {
    ProbeRequest {
        session_id: fixture.opened.session.session_id.clone(),
        principal: fixture.opened.session.principal_id.clone(),
        subscription_id: SUBSCRIPTION.to_owned(),
        expected_authority_root: fixture.opened.session.current_anchor.state_root,
        view: AgentView::Case,
        action: SupervisionAction::Poll,
    }
}

#[test]
fn runtime_native_case_link_preserves_adjacency_and_charges_fresh_time() -> TestResult {
    native_case_link("runtime-case-link", false)
}

#[test]
fn runtime_case_deadline_is_rechecked_after_native_work_before_exact_linkage() -> TestResult {
    native_case_link("runtime-case-deadline", true)
}

#[allow(clippy::expect_used)]
fn native_case_link(tag: &str, expire_before_link: bool) -> TestResult {
    let clock = Clock::at(START);
    let fixture = runtime_fixture(tag, &clock)?;
    let sources = fixture.authority_and_sources()?;
    clock.now.set(START + 1);
    let configured = action(
        &fixture,
        &clock,
        SupervisionAction::ConfigureSchedule { total_windows: 1 },
    )?;
    let draft = CaseDraft {
        case_id: "case:runtime-clock".into(),
        question: "Does the retained synthetic report support the selected hypothesis?".into(),
        decision_informed: "Whether to collect another independent observation".into(),
        hypotheses: ["hypothesis:configured", "hypothesis:alternative"]
            .into_iter()
            .map(|id| CaseHypothesis {
                hypothesis_id: id.into(),
                description: format!("Consider {id}"),
                epistemic_state: KnowledgeState::Unknown,
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
        probes: vec![SUBSCRIPTION.into()],
        stop_rules: vec!["Preserve uncertainty".into()],
        deadline: CaseDeadline::After(if expire_before_link {
            4
        } else {
            3_600_000_000_000
        }),
    };
    let mut request = InvestigateRequest {
        session_id: fixture.opened.session.session_id.clone(),
        principal: fixture.opened.session.principal_id.clone(),
        action: CaseAction::Open(Box::new(draft)),
    };
    clock.now.set(START + 2);
    let opened = investigate(SessionContext::runtime(&fixture.root, &clock), &request)?;
    request.action = CaseAction::Change {
        case_id: "case:runtime-clock".into(),
        expected: opened.revision.ok_or("opened case")?.digest(),
        change: InvestigationChange::Activate,
    };
    clock.now.set(START + 3);
    let active = investigate(SessionContext::runtime(&fixture.root, &clock), &request)?;
    let target = ProbeCitationTarget {
        case_id: "case:runtime-clock".into(),
        expected: active.revision.ok_or("active case")?.digest(),
        hypothesis: "hypothesis:configured".into(),
        contradicts: false,
    };
    let request = probe(&fixture);
    clock.now.set(START + 4);
    let admission = preflight_probe_case(
        SessionContext::runtime(&fixture.root, &clock),
        &request,
        &target,
        configured.subscription.digest(),
        &fixture.registration,
        &target.hypothesis,
    )?;
    clock.now.set(START + 5);
    let guarded = supervise_existing_session_at(
        SessionContext::runtime(&fixture.root, &clock),
        &request.principal,
        &SupervisionSessionRequest {
            registration: fixture.registration.clone(),
            expected_authority_root: request.expected_authority_root,
            action: SupervisionAction::Poll,
        },
        configured.subscription.digest(),
        &OrientLimits::default(),
        &mut SyntheticEvaluator {
            root: &fixture.root,
            source: &fixture.source,
            principal: &request.principal,
            registration: &fixture.registration,
        },
    )?;
    assert_eq!(guarded.delivery().head.observed_at, TimestampNs(START + 5));
    clock.now.set(START + 6);
    let linked = commit_probe_case(
        SessionContext::runtime(&fixture.root, &clock),
        &admission,
        &guarded,
    );
    if expire_before_link {
        let failed = linked.expect_err("case expires after native work, before linkage");
        assert!(matches!(
            failed.error,
            DeploymentSessionError::CaseRefused(InvestigationError::DeadlineElapsed)
        ));
        assert!(failed.committed.is_none());
        let retained = retained_session(&fixture)?;
        assert_eq!(retained.last_observed_at, TimestampNs(START + 6));
        assert!(!retained.closed);
        assert_eq!(fixture.retained()?.attempts_reserved(), 1);
        assert!(fixture.retained()?.pending().is_some());
        clock.now.set(START + 5);
        assert!(
            commit_probe_case(
                SessionContext::runtime(&fixture.root, &clock),
                &admission,
                &guarded,
            )
            .is_err()
        );
        assert_eq!(fixture.authority_and_sources()?, sources);
        return Ok(());
    }
    let linked = linked.map_err(|error| error.error)?;
    let before = fs::read(fixture.root.join("agent/sessions/journal.fssj"))?;
    clock.now.set(START + 7);
    let context = admit_probe_continuation(
        SessionContext::runtime(&fixture.root, &clock),
        &request,
        linked.journal_root(),
    )?;
    assert_eq!(context.oriented.journal_root, linked.journal_root());
    assert_eq!(
        before,
        fs::read(fixture.root.join("agent/sessions/journal.fssj"))?
    );
    let spent = retained_session(&fixture)?.spent_tokens;
    clock.now.set(START + 8);
    let charge = charge_linked_probe_delivery(
        SessionContext::runtime(&fixture.root, &clock),
        &request,
        &context,
        guarded.delivery(),
        &linked,
        1,
    )?;
    let retained = retained_session(&fixture)?;
    assert_eq!(retained.spent_tokens, spent + 1);
    assert_eq!(retained.last_observed_at, TimestampNs(START + 8));
    assert_eq!(
        charge.remaining_tokens + retained.spent_tokens,
        fixture.request.token_budget
    );
    assert!(!retained.closed);
    clock.now.set(START + 9);
    let retried = open_session(
        SessionContext::runtime(&fixture.root, &clock),
        &fixture.request,
    )?;
    assert_eq!(retried.session, fixture.opened.session);
    assert_eq!(
        retained_session(&fixture)?.spent_tokens,
        retained.spent_tokens
    );
    assert_eq!(fixture.authority_and_sources()?, sources);
    Ok(())
}

#[test]
fn exact_runtime_expiry_refuses_before_native_work_and_cannot_reopen() -> TestResult {
    let clock = Clock::at(START);
    let fixture = runtime_fixture("runtime-expiry", &clock)?;
    action(
        &fixture,
        &clock,
        SupervisionAction::ConfigureSchedule { total_windows: 1 },
    )?;
    clock.now.set(fixture.opened.session.expires_at_ns);
    let failed = action(&fixture, &clock, SupervisionAction::Poll).expect_err("expired admission");
    assert_eq!(failed.attempts_reserved, 0);
    assert!(retained_session(&fixture)?.closed);
    assert_eq!(fixture.retained()?.attempts_reserved(), 0);
    clock.now.set(START);
    assert!(action(&fixture, &clock, SupervisionAction::Poll).is_err());
    assert!(retained_session(&fixture)?.closed);
    Ok(())
}

#[test]
fn expiry_during_native_work_keeps_spent_attempt_and_withholds_delivery() -> TestResult {
    let clock = Clock::at(START);
    let fixture = runtime_fixture("runtime-late-expiry", &clock)?;
    action(
        &fixture,
        &clock,
        SupervisionAction::ConfigureSchedule { total_windows: 1 },
    )?;
    clock.next.set(Some(fixture.opened.session.expires_at_ns));
    let failed = action(&fixture, &clock, SupervisionAction::Poll).expect_err("expired release");
    assert_eq!(failed.attempts_reserved, 1);
    assert_eq!(fixture.retained()?.attempts_reserved(), 1);
    assert!(fixture.retained()?.pending().is_some());
    assert!(retained_session(&fixture)?.closed);
    Ok(())
}

#[test]
fn expired_sealed_projection_persists_tombstone_without_another_native_attempt() -> TestResult {
    let clock = Clock::at(START);
    let fixture = runtime_fixture("runtime-projection-expiry", &clock)?;
    action(
        &fixture,
        &clock,
        SupervisionAction::ConfigureSchedule { total_windows: 1 },
    )?;
    let delivery = action(&fixture, &clock, SupervisionAction::Poll)?;
    clock.now.set(fixture.opened.session.expires_at_ns);
    assert!(
        admit_probe_continuation(
            SessionContext::runtime(&fixture.root, &clock),
            &probe(&fixture),
            delivery.journal_root,
        )
        .is_err()
    );
    assert!(retained_session(&fixture)?.closed);
    assert_eq!(fixture.retained()?.attempts_reserved(), 1);
    Ok(())
}

#[test]
fn runtime_reads_recover_verified_pin_extensions_and_expire_before_projection_release() -> TestResult
{
    let clock = Clock::at(START);
    let fixture = runtime_fixture("runtime-read-pin-extension", &clock)?;
    let configured = action(
        &fixture,
        &clock,
        SupervisionAction::ConfigureSchedule { total_windows: 1 },
    )?;
    clock.now.set(START + 1);
    let delivery = action(&fixture, &clock, SupervisionAction::Poll)?;
    let pin = fixture.root.join("agent/sessions/ROOT");
    // Simulate a durable complete native append whose ROOT replacement was interrupted.
    fs::write(&pin, format!("{}\n", configured.journal_root.to_text()))?;
    let context = admit_probe(
        SessionContext::runtime(&fixture.root, &clock),
        &probe(&fixture),
    )?;
    assert_eq!(context.oriented.journal_root, delivery.journal_root);
    assert_eq!(
        retained_session(&fixture)?.last_observed_at,
        TimestampNs(START + 1)
    );
    // A sealed read likewise verifies the full extension, and a deadline crossed while it
    // compiles the private projection is pinned before anything can be returned to transport.
    fs::write(&pin, format!("{}\n", configured.journal_root.to_text()))?;
    clock.now.set(START + 3);
    clock.next.set(Some(fixture.opened.session.expires_at_ns));
    assert!(
        admit_probe_continuation(
            SessionContext::runtime(&fixture.root, &clock),
            &probe(&fixture),
            context.oriented.journal_root,
        )
        .is_err()
    );
    assert!(retained_session(&fixture)?.closed);
    assert_eq!(fixture.retained()?.attempts_reserved(), 1);
    Ok(())
}
