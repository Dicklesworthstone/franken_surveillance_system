#![forbid(unsafe_code)]
//! Native state comparison uses real durable sessions; the retained source adapter is synthetic.

use super::*;
use fss_core::DigestAlgorithm;
use fss_reference::agent_session::checkpoint::journal::supervision::DurableSupervisionError;
use fss_reference::deployment_session::supervision::{
    GuardedSupervisionDelivery, supervise_existing_session_at,
};

struct GuardControl<'a> {
    fixture: &'a Fixture,
    adapter: SyntheticEvaluator<'a>,
    boundaries: Vec<SupervisionSessionBoundary>,
    evaluations: usize,
    validations: usize,
    before_lock: Option<SupervisionAction>,
    changed_bytes: Option<Vec<u8>>,
    deny: Option<SupervisionSessionBoundary>,
}

impl<'a> GuardControl<'a> {
    fn new(fixture: &'a Fixture) -> Self {
        Self {
            fixture,
            adapter: SyntheticEvaluator {
                root: &fixture.root,
                source: &fixture.source,
                principal: &fixture.opened.session.principal_id,
                registration: &fixture.registration,
            },
            boundaries: Vec::new(),
            evaluations: 0,
            validations: 0,
            before_lock: None,
            changed_bytes: None,
            deny: None,
        }
    }

    fn run(
        &mut self,
        expected: ContentDigest,
        action: SupervisionAction,
    ) -> Result<GuardedSupervisionDelivery, Box<SupervisionSessionFailure>> {
        let fixture = self.fixture;
        supervise_existing_session_at(
            &fixture.root,
            &fixture.opened.session.principal_id,
            &SupervisionSessionRequest {
                registration: fixture.registration.clone(),
                expected_authority_root: fixture.opened.session.current_anchor.state_root,
                action,
            },
            expected,
            &OrientLimits {
                max_journal_bytes: 32 * 1024 * 1024,
                ..OrientLimits::default()
            },
            self,
        )
    }

    fn no_native_work(&self) {
        assert_eq!(self.evaluations, 0);
        assert_eq!(self.validations, 0);
        assert!(
            !self
                .boundaries
                .contains(&SupervisionSessionBoundary::ReserveRead)
        );
    }
}

impl SupervisionSessionControl for GuardControl<'_> {
    fn admit_session(
        &mut self,
        binding: &SupervisionSessionBinding<'_>,
        boundary: SupervisionSessionBoundary,
    ) -> Result<(), SupervisionAdapterError> {
        self.adapter.admit_session(binding, boundary)?;
        self.boundaries.push(boundary);
        if self.deny == Some(boundary) {
            return Err(SupervisionAdapterError {
                identity: "fixture:guard-cancelled",
                reason: "explicit native boundary refusal".to_owned(),
            });
        }
        if boundary == SupervisionSessionBoundary::OpenJournal
            && let Some(action) = self.before_lock.take()
        {
            // Simulate another admitted command after external preflight, before this
            // operation can acquire the journal. Its work must not be repeated afterward.
            self.fixture
                .action(action)
                .map_err(|_| SyntheticEvaluator::refused())?;
            self.changed_bytes =
                Some(journal_bytes(self.fixture).map_err(|_| SyntheticEvaluator::refused())?);
        }
        Ok(())
    }
}

impl SupervisionEvaluator for GuardControl<'_> {
    fn evaluate(
        &mut self,
        binding: &SupervisionSessionBinding<'_>,
        anchor: &LedgerAnchor,
    ) -> Result<SupervisionEvaluation, SupervisionAdapterError> {
        self.evaluations += 1;
        self.adapter.evaluate(binding, anchor)
    }

    fn revalidate(
        &mut self,
        binding: &SupervisionSessionBinding<'_>,
        anchor: &LedgerAnchor,
        pending: &PendingSupervisionDelivery,
    ) -> Result<SupervisionValidation, SupervisionAdapterError> {
        self.validations += 1;
        self.adapter.revalidate(binding, anchor, pending)
    }
}

fn journal_bytes(fixture: &Fixture) -> TestResult<Vec<u8>> {
    Ok(fs::read(fixture.root.join("agent/sessions/journal.fssj"))?)
}

fn conflict(failure: &SupervisionSessionFailure) {
    assert!(matches!(
        failure.error,
        SupervisionSessionError::Store(DurableSupervisionError::Conflict)
    ));
    assert!(failure.acknowledged.is_none());
    assert!(failure.discarded.is_none());
    assert!(failure.advanced.is_none());
}

#[test]
fn exact_guard_preserves_fresh_then_explicit_cold_pending_delivery() -> TestResult {
    let fixture = Fixture::new("guarded-cold")?;
    fixture.action(SupervisionAction::ConfigureSchedule { total_windows: 2 })?;
    let initial = fixture.retained()?;
    let protected = fixture.authority_and_sources()?;
    let mut fresh = GuardControl::new(&fixture);
    let fresh = fresh.run(initial.digest(), SupervisionAction::Poll)?;
    assert_eq!(fresh.expected_subscription_state(), initial.digest());
    assert!(matches!(
        fresh.delivery().outcome,
        SupervisionSessionOutcome::Report {
            replayed: false,
            ..
        }
    ));
    let returned = fresh.into_delivery();
    assert_eq!(returned.subscription.attempts_reserved(), 1);
    let pending = returned
        .subscription
        .pending()
        .ok_or("native pending")?
        .clone();
    let exact = fixture.retained()?;
    let bytes = journal_bytes(&fixture)?;
    let mut stale = GuardControl::new(&fixture);
    conflict(
        &*stale
            .run(initial.digest(), SupervisionAction::Poll)
            .err()
            .ok_or("old state reused")?,
    );
    stale.no_native_work();
    assert_eq!(journal_bytes(&fixture)?, bytes);
    let mut replay = GuardControl::new(&fixture);
    let replayed = replay.run(exact.digest(), SupervisionAction::Poll)?;
    assert_eq!(replayed.expected_subscription_state(), exact.digest());
    assert_eq!(replay.evaluations, 0);
    assert_eq!(replay.validations, 1);
    assert!(matches!(
        replayed.delivery().outcome,
        SupervisionSessionOutcome::Report { replayed: true, .. }
    ));
    assert_eq!(replayed.delivery().subscription.attempts_reserved(), 2);
    assert_eq!(replayed.delivery().subscription.pending(), Some(&pending));
    assert!(
        replayed
            .delivery()
            .subscription
            .last_acknowledged()
            .is_none()
    );
    assert_eq!(fixture.authority_and_sources()?, protected);
    Ok(())
}

#[test]
fn change_after_preflight_is_checked_under_native_lock_before_reservation() -> TestResult {
    let fixture = Fixture::new("guarded-race")?;
    fixture.action(SupervisionAction::ConfigureSchedule { total_windows: 2 })?;
    let expected = fixture.retained()?.digest();
    let mut control = GuardControl::new(&fixture);
    control.before_lock = Some(SupervisionAction::Poll);
    let refused = control
        .run(expected, SupervisionAction::Poll)
        .err()
        .ok_or("stale preflight")?;
    conflict(&refused);
    control.no_native_work();
    assert_eq!(refused.attempts_reserved, 1);
    assert_eq!(fixture.retained()?.attempts_reserved(), 1);
    assert!(fixture.retained()?.pending().is_some());
    assert_eq!(Some(journal_bytes(&fixture)?), control.changed_bytes);
    Ok(())
}

#[test]
fn lost_final_delivery_cannot_repeat_source_work_under_original_expectation() -> TestResult {
    let fixture = Fixture::new("guarded-lost-output")?;
    fixture.action(SupervisionAction::ConfigureSchedule { total_windows: 2 })?;
    let expected = fixture.retained()?.digest();
    let mut interrupted = GuardControl::new(&fixture);
    interrupted.deny = Some(SupervisionSessionBoundary::Deliver);
    let refused = interrupted
        .run(expected, SupervisionAction::Poll)
        .err()
        .ok_or("late refusal")?;
    assert!(matches!(refused.error, SupervisionSessionError::Denied(_)));
    assert_eq!(refused.attempts_reserved, 1);
    assert_eq!(interrupted.evaluations, 1);
    let persisted = fixture.retained()?;
    assert!(persisted.pending().is_some());
    let bytes = journal_bytes(&fixture)?;
    let mut retry = GuardControl::new(&fixture);
    conflict(
        &*retry
            .run(expected, SupervisionAction::Poll)
            .err()
            .ok_or("lost output blind retry")?,
    );
    retry.no_native_work();
    assert_eq!(fixture.retained()?.digest(), persisted.digest());
    assert_eq!(journal_bytes(&fixture)?, bytes);
    Ok(())
}

#[test]
fn state_guard_precedes_terminal_actions_and_never_reopens_resolved_work() -> TestResult {
    let fixture = Fixture::new("guarded-terminal")?;
    fixture.action(SupervisionAction::ConfigureSchedule { total_windows: 2 })?;
    let report = fixture.action(SupervisionAction::Poll)?;
    let old = report.subscription.digest();
    let receipt = report.subscription.pending().ok_or("pending")?.receipt();
    fixture.action(SupervisionAction::Discard(receipt))?;
    let terminal = fixture.retained()?;
    let bytes = journal_bytes(&fixture)?;
    for action in [
        SupervisionAction::Poll,
        SupervisionAction::Acknowledge(receipt),
        SupervisionAction::Discard(receipt),
        SupervisionAction::Advance {
            target_count: 2,
            after_receipt: receipt,
        },
    ] {
        let mut control = GuardControl::new(&fixture);
        conflict(
            &*control
                .run(old, action)
                .err()
                .ok_or("stale terminal state")?,
        );
        control.no_native_work();
        assert_eq!(fixture.retained()?.digest(), terminal.digest());
        assert_eq!(journal_bytes(&fixture)?, bytes);
    }
    Ok(())
}

#[test]
fn invalid_or_absent_expectation_never_registers_or_admits_source_work() -> TestResult {
    let fixture = Fixture::new("guarded-absent")?;
    let bytes = journal_bytes(&fixture)?;
    for expected in [
        ContentDigest::new(DigestAlgorithm::Sha256, [0; 32]),
        ContentDigest::new(DigestAlgorithm::Blake3, [1; 32]),
    ] {
        let mut control = GuardControl::new(&fixture);
        let refused = control
            .run(expected, SupervisionAction::Poll)
            .err()
            .ok_or("invalid state pin")?;
        assert!(matches!(
            refused.error,
            SupervisionSessionError::InvalidRequest
        ));
        assert!(control.boundaries.is_empty());
        assert_eq!(journal_bytes(&fixture)?, bytes);
    }
    let mut control = GuardControl::new(&fixture);
    assert!(
        control
            .run(
                ContentDigest::sha256(b"absent state"),
                SupervisionAction::Poll
            )
            .is_err()
    );
    control.no_native_work();
    assert!(fixture.retained().is_err());
    assert_eq!(journal_bytes(&fixture)?, bytes);
    Ok(())
}
